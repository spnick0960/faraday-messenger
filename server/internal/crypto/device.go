package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// ChatPayload is the inner plaintext (never stored on the relay).
type ChatPayload struct {
	V    int    `json:"v"`
	T    string `json:"t"`
	ID   string `json:"id"`
	TS   int64  `json:"ts"`
	Body string `json:"body"`
	Card *Card  `json:"card,omitempty"`
}

type Card struct {
	MB   string `json:"mb"`
	IK   []byte `json:"ik"`
	IKS  []byte `json:"iks"`
	SPK  []byte `json:"spk"`
	Sig  []byte `json:"sig"`
	Name string `json:"name,omitempty"`
}

func (id *Identity) Card() *Card {
	b := id.PublicBundle()
	return &Card{
		MB:   id.MailboxHex(),
		IK:   b.IKX,
		IKS:  b.IKS,
		SPK:  b.SPK,
		Sig:  b.SPKSig,
		Name: id.DisplayName,
	}
}

// EncryptTo produces a sealed envelope for peer. If session is nil, a new
// X3DH+Double Ratchet session is started and returned.
func EncryptTo(self *Identity, peer *PublicBundle, session *Session, body string) (blob []byte, next *Session, payload *ChatPayload, err error) {
	if err := peer.Verify(); err != nil {
		return nil, nil, nil, err
	}
	prekey := false
	if session == nil {
		eka, err := generateDH()
		if err != nil {
			return nil, nil, nil, err
		}
		sk, err := x3dhInitiatorSecret(self.IKX, eka, peer.IKX, peer.SPK)
		if err != nil {
			return nil, nil, nil, err
		}
		session, err = InitAlice(sk, peer.SPK, peer.IKX, self.IKX.PublicKey().Bytes(), peer.Mailbox)
		if err != nil {
			return nil, nil, nil, err
		}
		session.eka = eka
		prekey = true
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, nil, nil, err
	}
	payload = &ChatPayload{
		V:    1,
		T:    "txt",
		ID:   fmt.Sprintf("%x", idBytes),
		TS:   time.Now().Unix(),
		Body: body,
	}
	if prekey {
		payload.Card = self.Card()
	}
	pt, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, nil, err
	}
	hdr, ct, err := session.Encrypt(pt)
	if err != nil {
		return nil, nil, nil, err
	}

	inner := encodeInner(self, session, prekey, hdr, ct)
	aad := append([]byte(InfoSeal), peer.Mailbox[:]...)
	blob, err = SealTo(peer.IKX, aad, inner)
	if err != nil {
		return nil, nil, nil, err
	}
	session.eka = nil
	return blob, session, payload, nil
}

func DecryptFrom(self *Identity, sessions map[string]*Session, blob []byte) (*ChatPayload, *PublicBundle, *Session, error) {
	aad := append([]byte(InfoSeal), self.Mailbox[:]...)
	inner, err := OpenSealed(self.IKX, aad, blob)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open seal: %w", err)
	}
	msg, err := decodeInner(inner)
	if err != nil {
		return nil, nil, nil, err
	}

	key := hexKey(msg.senderIK)
	sess := sessions[key]

	if msg.prekey {
		if sess == nil {
			sk, err := x3dhResponderSecret(self.IKX, self.SPK, msg.senderIK, msg.eka)
			if err != nil {
				return nil, nil, nil, err
			}
			var peerMB [16]byte
			sess = InitBob(sk, self.SPK, msg.senderIK, self.IKX.PublicKey().Bytes(), peerMB)
		}
	}
	if sess == nil {
		return nil, nil, nil, fmt.Errorf("no session for sender and not a prekey message")
	}

	pt, err := sess.Decrypt(msg.header, msg.ciphertext)
	if err != nil {
		return nil, nil, nil, err
	}
	var payload ChatPayload
	if err := json.Unmarshal(pt, &payload); err != nil {
		return nil, nil, nil, fmt.Errorf("payload: %w", err)
	}

	var peer *PublicBundle
	if payload.Card != nil {
		mb, err := parseMailbox(payload.Card.MB)
		if err != nil {
			return nil, nil, nil, err
		}
		peer = &PublicBundle{
			Mailbox:     mb,
			IKX:         payload.Card.IK,
			IKS:         payload.Card.IKS,
			SPK:         payload.Card.SPK,
			SPKSig:      payload.Card.Sig,
			SPKID:       SPKID,
			DisplayName: payload.Card.Name,
		}
		if err := peer.Verify(); err != nil {
			return nil, nil, nil, err
		}
		if !bytesEq(peer.IKX, msg.senderIK) {
			return nil, nil, nil, fmt.Errorf("card identity does not match sender")
		}
		sess.PeerMB = mb
		sess.PeerIK = append([]byte(nil), peer.IKX...)
	}
	return &payload, peer, sess, nil
}

type innerMsg struct {
	prekey      bool
	senderIK    []byte
	eka         []byte
	header      []byte
	ciphertext  []byte
}

func encodeInner(self *Identity, sess *Session, prekey bool, hdr, ct []byte) []byte {
	flag := FlagRatchetOnly
	if prekey {
		flag = FlagPrekey
	}
	out := []byte{InnerVersion, flag}
	out = append(out, self.IKX.PublicKey().Bytes()...)
	if prekey {
		out = append(out, sess.eka.PublicKey().Bytes()...)
		spkID := make([]byte, 2)
		binary.BigEndian.PutUint16(spkID, SPKID)
		out = append(out, spkID...)
	}
	out = append(out, hdr...)
	out = append(out, ct...)
	return out
}

func decodeInner(b []byte) (*innerMsg, error) {
	if len(b) < 2+32+40+16 {
		return nil, fmt.Errorf("inner: short")
	}
	if b[0] != InnerVersion {
		return nil, fmt.Errorf("inner: version")
	}
	m := &innerMsg{prekey: b[1] == FlagPrekey, senderIK: append([]byte(nil), b[2:34]...)}
	o := 34
	if m.prekey {
		if len(b) < o+32+2+40+16 {
			return nil, fmt.Errorf("inner: short prekey")
		}
		m.eka = append([]byte(nil), b[o:o+32]...)
		o += 32 + 2 // skip eka + spk id
	}
	m.header = append([]byte(nil), b[o:o+40]...)
	m.ciphertext = append([]byte(nil), b[o+40:]...)
	return m, nil
}

func hexKey(ik []byte) string {
	return fmt.Sprintf("%x", ik)
}

func parseMailbox(hexMB string) ([16]byte, error) {
	var out [16]byte
	b, err := hex.DecodeString(hexMB)
	if err != nil || len(b) != 16 {
		return out, fmt.Errorf("mailbox hex")
	}
	copy(out[:], b)
	return out, nil
}
