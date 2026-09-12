package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// EnvelopeTTL is how long an undelivered sealed blob may sit in RAM.
	// After this, it is discarded forever. There is no disk archive and no
	// second-chance queue. Choose days, not forever: 48 hours is long enough
	// for a phone to come back online, short enough that a seized process
	// does not hold a week of mail.
	EnvelopeTTL    = 48 * time.Hour
	MaxBlobBytes   = 64 << 10
	MaxPending     = 500
)

type Mailbox struct {
	ID        string `json:"id"`
	TokenHash []byte `json:"tokenHash"`
	CreatedAt int64  `json:"createdAt"`
}

type Envelope struct {
	ID        string `json:"id"`
	Dest      string `json:"dest"`
	Blob      []byte `json:"-"` // never serialized to the mailbox file
	Bytes     int    `json:"bytes"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
}

type Event struct {
	At       int64  `json:"at"`
	Kind     string `json:"kind"`
	Bytes    int    `json:"bytes,omitempty"`
	DestHint string `json:"destHint,omitempty"`
	BlobHead string `json:"blobHead,omitempty"`
}

// snapshot is the only thing written to disk: mailbox capability IDs and
// token hashes. Ciphertext is omitted on purpose.
type snapshot struct {
	Mailboxes map[string]Mailbox `json:"mailboxes"`
}

type Store struct {
	mu        sync.Mutex
	path      string
	mailboxes map[string]Mailbox
	envelopes map[string]Envelope
	events    []Event
	started   time.Time
}

func Open(path string) (*Store, error) {
	s := &Store{
		path:      path,
		mailboxes: map[string]Mailbox{},
		envelopes: map[string]Envelope{},
		started:   time.Now(),
	}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var snap snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, err
	}
	if snap.Mailboxes != nil {
		s.mailboxes = snap.Mailboxes
	}
	// Older builds wrote envelopes into this file. Drop that archive on load
	// and rewrite so ciphertext does not remain on disk.
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(snapshot{Mailboxes: s.mailboxes}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) PutMailbox(id string, tokenHash []byte) error {
	if len(id) != 32 {
		return fmt.Errorf("mailbox id must be 16 bytes hex")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.mailboxes[id]; ok {
		if subtleEq(existing.TokenHash, tokenHash) {
			return nil
		}
		return fmt.Errorf("mailbox already registered")
	}
	s.mailboxes[id] = Mailbox{ID: id, TokenHash: append([]byte(nil), tokenHash...), CreatedAt: time.Now().Unix()}
	s.noteLocked(Event{At: time.Now().Unix(), Kind: "mailbox"})
	return s.persistLocked()
}

func (s *Store) Auth(id string, tokenHash []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	mb, ok := s.mailboxes[id]
	if !ok {
		return false
	}
	return subtleEq(mb.TokenHash, tokenHash)
}

func (s *Store) Drop(dest string, blob []byte) (*Envelope, error) {
	return s.dropAt(dest, blob, time.Now())
}

func (s *Store) dropAt(dest string, blob []byte, now time.Time) (*Envelope, error) {
	if len(blob) == 0 || len(blob) > MaxBlobBytes {
		return nil, fmt.Errorf("invalid envelope size")
	}
	if len(dest) != 32 {
		return nil, fmt.Errorf("invalid destination")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	pending := 0
	for _, e := range s.envelopes {
		if e.Dest == dest {
			pending++
		}
	}
	if pending >= MaxPending {
		return nil, fmt.Errorf("mailbox full")
	}
	id := newID()
	env := Envelope{
		ID:        id,
		Dest:      dest,
		Blob:      append([]byte(nil), blob...),
		Bytes:     len(blob),
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(EnvelopeTTL).Unix(),
	}
	s.envelopes[id] = env
	s.noteLocked(Event{
		At:       env.CreatedAt,
		Kind:     "drop",
		Bytes:    env.Bytes,
		DestHint: hint(dest),
		BlobHead: hex.EncodeToString(blob[:min(12, len(blob))]),
	})
	// Ciphertext stays in RAM only. Do not persist the blob.
	return &env, nil
}

func (s *Store) Inbox(dest string) []Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(time.Now())
	var out []Envelope
	for _, e := range s.envelopes {
		if e.Dest == dest {
			cp := e
			cp.Blob = append([]byte(nil), e.Blob...)
			out = append(out, cp)
		}
	}
	return out
}

// Ack deletes envelopes immediately after the recipient device confirms it
// has the payload. This is successful delivery. Nothing remains on the relay.
func (s *Store) Ack(dest string, ids []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, id := range ids {
		e, ok := s.envelopes[id]
		if !ok || e.Dest != dest {
			continue
		}
		delete(s.envelopes, id)
		n++
	}
	if n > 0 {
		s.noteLocked(Event{At: time.Now().Unix(), Kind: "delivered", Bytes: n})
	}
	return n
}

func (s *Store) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gcLocked(time.Now())
}

type Transparency struct {
	Name              string         `json:"name"`
	Version           string         `json:"version"`
	UptimeSeconds     int64          `json:"uptimeSeconds"`
	Mailboxes         int            `json:"mailboxes"`
	PendingEnvelopes  int            `json:"pendingEnvelopes"`
	PlaintextBodies   int            `json:"plaintextBodies"`
	DecryptionKeys    int            `json:"decryptionKeys"`
	CiphertextOnDisk  int            `json:"ciphertextOnDisk"`
	TTLHours          int            `json:"ttlHours"`
	Retention         string         `json:"retention"`
	SizeHistogram     map[string]int `json:"sizeHistogram"`
	Recent            []Event        `json:"recent"`
	Honest            Honest         `json:"whatThisServerCanSee"`
}

type Honest struct {
	Can    []string `json:"can"`
	Cannot []string `json:"cannot"`
}

func (s *Store) Transparency() Transparency {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(time.Now())
	hist := map[string]int{"<128": 0, "128-255": 0, "256-511": 0, "512-1023": 0, ">=1024": 0}
	for _, e := range s.envelopes {
		switch {
		case e.Bytes < 128:
			hist["<128"]++
		case e.Bytes < 256:
			hist["128-255"]++
		case e.Bytes < 512:
			hist["256-511"]++
		case e.Bytes < 1024:
			hist["512-1023"]++
		default:
			hist[">=1024"]++
		}
	}
	recent := append([]Event(nil), s.events...)
	return Transparency{
		Name:             "faraday-relay",
		Version:          "1",
		UptimeSeconds:    int64(time.Since(s.started).Seconds()),
		Mailboxes:        len(s.mailboxes),
		PendingEnvelopes: len(s.envelopes),
		PlaintextBodies:  0,
		DecryptionKeys:   0,
		CiphertextOnDisk: 0,
		TTLHours:         int(EnvelopeTTL.Hours()),
		Retention:        "Sealed blobs live in process memory only. They are deleted the moment the recipient device acknowledges fetch, or discarded after 48 hours if nobody collects them. A process restart drops any still-pending blobs. The on-disk file holds mailbox capability IDs and token hashes — never ciphertext.",
		SizeHistogram:    hist,
		Recent:           recent,
		Honest: Honest{
			Can: []string{
				"That an opaque blob is currently waiting in RAM for a mailbox",
				"The size of each pending blob (padded on the client)",
				"The destination mailbox identifier (a random capability, not a name)",
				"The source IP of the TCP connection that dropped or fetched mail",
				"Approximate online presence while a client holds a WebSocket",
			},
			Cannot: []string{
				"Message plaintext",
				"Sender identity (sealed envelope)",
				"Display names, recovery phrases, or contact lists",
				"Decryption keys or ratchet state",
				"A long-term archive of ciphertext — delivered and expired blobs are gone",
				"Whether two mailboxes belong to the same person",
			},
		},
	}
}

func (s *Store) gcLocked(now time.Time) int {
	n := 0
	cut := now.Add(-EnvelopeTTL).Unix()
	for id, e := range s.envelopes {
		if e.CreatedAt < cut {
			delete(s.envelopes, id)
			n++
		}
	}
	if n > 0 {
		s.noteLocked(Event{At: now.Unix(), Kind: "expired", Bytes: n})
	}
	return n
}

func (s *Store) noteLocked(e Event) {
	s.events = append(s.events, e)
	if len(s.events) > 40 {
		s.events = s.events[len(s.events)-40:]
	}
}

func hint(dest string) string {
	if len(dest) < 4 {
		return "••"
	}
	return "••" + dest[len(dest)-4:]
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func subtleEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
