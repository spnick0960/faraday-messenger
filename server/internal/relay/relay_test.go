package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fcrypto "faraday/internal/crypto"
	"faraday/internal/store"
)

func TestTwoDevicesThroughRelay(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st, "").Handler())
	defer srv.Close()

	alice, _ := fcrypto.GenerateIdentity("Alice")
	bob, _ := fcrypto.GenerateIdentity("Bob")
	secret := "the operator cannot read this sentence"

	ac := NewClient(srv.URL)
	bc := NewClient(srv.URL)
	if err := ac.Register(alice.MailboxHex(), alice.AuthHex()); err != nil {
		t.Fatal(err)
	}
	if err := bc.Register(bob.MailboxHex(), bob.AuthHex()); err != nil {
		t.Fatal(err)
	}

	blob, sessA, _, err := fcrypto.EncryptTo(alice, bob.PublicBundle(), nil, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ac.Drop(bob.MailboxHex(), blob); err != nil {
		t.Fatal(err)
	}

	// Persistence honesty: store snapshot must not contain the body.
	tr := st.Transparency()
	if tr.PlaintextBodies != 0 || tr.DecryptionKeys != 0 {
		t.Fatal("store claims to hold plaintext")
	}
	raw, _ := json.Marshal(st.Inbox(bob.MailboxHex()))
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("plaintext present in store inbox serialization")
	}

	items, err := bc.Inbox()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("inbox %d", len(items))
	}
	enc, err := DecodeBlob(items[0].Blob)
	if err != nil {
		t.Fatal(err)
	}
	got, peer, sessB, err := fcrypto.DecryptFrom(bob, map[string]*fcrypto.Session{}, enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != secret || peer.DisplayName != "Alice" {
		t.Fatalf("%q / %+v", got.Body, peer)
	}
	if err := bc.Ack([]string{items[0].ID}); err != nil {
		t.Fatal(err)
	}

	blob, _, _, err = fcrypto.EncryptTo(bob, alice.PublicBundle(), sessB, "reply-ok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bc.Drop(alice.MailboxHex(), blob); err != nil {
		t.Fatal(err)
	}
	items, err = ac.Inbox()
	if err != nil {
		t.Fatal(err)
	}
	enc, _ = DecodeBlob(items[0].Blob)
	got, _, _, err = fcrypto.DecryptFrom(alice, map[string]*fcrypto.Session{
		hexOf(bob): sessA,
	}, enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != "reply-ok" {
		t.Fatal(got.Body)
	}
	if err := ac.Ack([]string{items[0].ID}); err != nil {
		t.Fatal(err)
	}
	if st.Transparency().PendingEnvelopes != 0 {
		t.Fatal("relay still holding ciphertext after both deliveries")
	}

	res, err := http.Get(srv.URL + "/v1/transparency")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var view map[string]any
	if err := json.NewDecoder(res.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	dump, _ := json.Marshal(view)
	if bytes.Contains(dump, []byte(secret)) {
		t.Fatal("transparency leaked plaintext")
	}
	if view["ciphertextOnDisk"] != float64(0) {
		t.Fatalf("ciphertextOnDisk %+v", view["ciphertextOnDisk"])
	}
	if view["ttlHours"] != float64(48) {
		t.Fatalf("ttlHours %+v", view["ttlHours"])
	}
}

// HTTP inbox fetch is the iOS client's fallback when the WebSocket is down.
// A drop must be visible on the next GET /v1/inbox without any WS subscriber.
func TestInboxHTTPPollWithoutWebsocket(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st, "").Handler())
	defer srv.Close()

	alice, _ := fcrypto.GenerateIdentity("Alice")
	bob, _ := fcrypto.GenerateIdentity("Bob")
	ac := NewClient(srv.URL)
	bc := NewClient(srv.URL)
	if err := ac.Register(alice.MailboxHex(), alice.AuthHex()); err != nil {
		t.Fatal(err)
	}
	if err := bc.Register(bob.MailboxHex(), bob.AuthHex()); err != nil {
		t.Fatal(err)
	}

	empty, err := bc.Inbox()
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected empty inbox, got %d", len(empty))
	}

	const body = "poll-path-only"
	blob, _, _, err := fcrypto.EncryptTo(alice, bob.PublicBundle(), nil, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ac.Drop(bob.MailboxHex(), blob); err != nil {
		t.Fatal(err)
	}

	// First poll after drop — same GET the iOS 1.5s loop uses.
	items, err := bc.Inbox()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("poll after drop: %d", len(items))
	}
	enc, err := DecodeBlob(items[0].Blob)
	if err != nil {
		t.Fatal(err)
	}
	got, _, _, err := fcrypto.DecryptFrom(bob, map[string]*fcrypto.Session{}, enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != body {
		t.Fatalf("decrypted %q", got.Body)
	}
	if bytes.Contains(enc, []byte(body)) {
		t.Fatal("plaintext present in relay blob")
	}
	if err := bc.Ack([]string{items[0].ID}); err != nil {
		t.Fatal(err)
	}

	cleared, err := bc.Inbox()
	if err != nil {
		t.Fatal(err)
	}
	if len(cleared) != 0 {
		t.Fatalf("inbox after ack %d", len(cleared))
	}
	if st.Transparency().PendingEnvelopes != 0 || st.Transparency().PlaintextBodies != 0 {
		t.Fatal("relay still holding envelope or plaintext after ack")
	}
}

func TestReadReceiptIsOpaqueOnRelay(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st, "").Handler())
	defer srv.Close()

	alice, _ := fcrypto.GenerateIdentity("Alice")
	bob, _ := fcrypto.GenerateIdentity("Bob")
	ac := NewClient(srv.URL)
	bc := NewClient(srv.URL)
	if err := ac.Register(alice.MailboxHex(), alice.AuthHex()); err != nil {
		t.Fatal(err)
	}
	if err := bc.Register(bob.MailboxHex(), bob.AuthHex()); err != nil {
		t.Fatal(err)
	}

	blob, sessA, txt, err := fcrypto.EncryptTo(alice, bob.PublicBundle(), nil, "visible only on devices")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ac.Drop(bob.MailboxHex(), blob); err != nil {
		t.Fatal(err)
	}
	items, err := bc.Inbox()
	if err != nil || len(items) != 1 {
		t.Fatalf("bob inbox %v %d", err, len(items))
	}
	enc, _ := DecodeBlob(items[0].Blob)
	got, _, sessB, err := fcrypto.DecryptFrom(bob, map[string]*fcrypto.Session{}, enc)
	if err != nil {
		t.Fatal(err)
	}
	if err := bc.Ack([]string{items[0].ID}); err != nil {
		t.Fatal(err)
	}

	receipt, _, rec, err := fcrypto.EncryptReadReceipt(bob, alice.PublicBundle(), sessB, got.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.T != "read" {
		t.Fatal(rec.T)
	}
	if _, err := bc.Drop(alice.MailboxHex(), receipt); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(st.Inbox(alice.MailboxHex()))
	if bytes.Contains(raw, []byte("read")) || bytes.Contains(raw, []byte(txt.ID)) || bytes.Contains(raw, []byte("visible only on devices")) {
		t.Fatal("receipt plaintext present in relay inbox")
	}
	items, err = ac.Inbox()
	if err != nil || len(items) != 1 {
		t.Fatalf("alice inbox %v %d", err, len(items))
	}
	enc, _ = DecodeBlob(items[0].Blob)
	got, _, _, err = fcrypto.DecryptFrom(alice, map[string]*fcrypto.Session{hexOf(bob): sessA}, enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.T != "read" || got.Upto != txt.ID {
		t.Fatalf("alice receipt %+v", got)
	}
	if st.Transparency().PlaintextBodies != 0 {
		t.Fatal("relay claims plaintext")
	}
}

func TestDropDoesNotRequireSenderAuth(t *testing.T) {
	st, _ := store.Open("")
	srv := httptest.NewServer(New(st, "").Handler())
	defer srv.Close()
	bob, _ := fcrypto.GenerateIdentity("Bob")
	bc := NewClient(srv.URL)
	if err := bc.Register(bob.MailboxHex(), bob.AuthHex()); err != nil {
		t.Fatal(err)
	}
	// Anonymous drop — no Authorization header.
	body := `{"to":"` + bob.MailboxHex() + `","blob":"AAAA"}`
	res, err := http.Post(srv.URL+"/v1/drop", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusAccepted && res.StatusCode != http.StatusBadRequest {
		// AAAA is invalid size after decode — 3 bytes is fine actually
		t.Fatalf("status %d", res.StatusCode)
	}
}

func hexOf(id *fcrypto.Identity) string {
	return fmt.Sprintf("%x", id.IKX.PublicKey().Bytes())
}
