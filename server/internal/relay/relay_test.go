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
