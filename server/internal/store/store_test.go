package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCiphertextNeverHitsDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.json")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("this must not be archived")
	if _, err := st.Drop("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", secret); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		// Drop must not even require a file write for envelopes. Mailbox file
		// may not exist yet if we never registered.
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		raw = nil
	}
	if bytes.Contains(raw, secret) || bytes.Contains(raw, []byte("this must")) {
		t.Fatal("ciphertext written to disk")
	}
	if bytes.Contains(raw, []byte("\"blob\"")) {
		t.Fatal("envelope blob field present on disk")
	}
	if n := len(st.Inbox("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); n != 1 {
		t.Fatalf("ram inbox %d", n)
	}
}

func TestAckDeletesImmediately(t *testing.T) {
	st, _ := Open("")
	dest := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	env, err := st.Drop(dest, []byte("sealed-blob-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Inbox(dest)) != 1 {
		t.Fatal("expected pending")
	}
	if n := st.Ack(dest, []string{env.ID}); n != 1 {
		t.Fatalf("ack %d", n)
	}
	if len(st.Inbox(dest)) != 0 {
		t.Fatal("blob still held after successful delivery")
	}
	if st.Transparency().PendingEnvelopes != 0 {
		t.Fatal("transparency still lists pending ciphertext")
	}
}

func TestTTLDiscardsUncollected(t *testing.T) {
	st, _ := Open("")
	dest := "cccccccccccccccccccccccccccccccc"
	old := time.Now().Add(-EnvelopeTTL - time.Hour)
	if _, err := st.dropAt(dest, []byte("stale-blob"), old); err != nil {
		t.Fatal(err)
	}
	if n := st.Sweep(); n != 1 {
		t.Fatalf("expired %d", n)
	}
	if len(st.Inbox(dest)) != 0 {
		t.Fatal("expired blob still in RAM")
	}
}

func TestOldDiskArchiveIsStripped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.json")
	legacy := []byte(`{"mailboxes":{},"envelopes":{"x":{"id":"x","dest":"dd","blob":"c2VjcmV0LWFyY2hpdmU=","bytes":14}}}`)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rewritten, []byte("blob")) || bytes.Contains(rewritten, []byte("envelopes")) || bytes.Contains(rewritten, []byte("c2VjcmV0")) {
		t.Fatalf("legacy ciphertext archive survived load: %s", rewritten)
	}
	if st.Transparency().CiphertextOnDisk != 0 {
		t.Fatal("claimed disk ciphertext")
	}
	var snap map[string]any
	if err := json.Unmarshal(rewritten, &snap); err != nil {
		t.Fatal(err)
	}
	if _, ok := snap["envelopes"]; ok {
		t.Fatal("envelopes key still on disk")
	}
}

func TestMailboxFileHasNoEnvelopeKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.json")
	st, _ := Open(path)
	sum := make([]byte, 32)
	if err := st.PutMailbox("dddddddddddddddddddddddddddddddd", sum); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Drop("dddddddddddddddddddddddddddddddd", bytes.Repeat([]byte{0x01}, 40)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("envelopes")) || bytes.Contains(raw, []byte("blob")) {
		t.Fatalf("mailbox file leaked envelope fields: %s", raw)
	}
}
