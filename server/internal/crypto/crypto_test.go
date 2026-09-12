package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMnemonicRoundTrip(t *testing.T) {
	id, err := GenerateIdentity("Ada")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := IdentityFromMnemonic(id.Mnemonic, "Ada")
	if err != nil {
		t.Fatal(err)
	}
	if id.MailboxHex() != id2.MailboxHex() {
		t.Fatalf("mailbox mismatch")
	}
	if !bytesEq(id.IKX.PublicKey().Bytes(), id2.IKX.PublicKey().Bytes()) {
		t.Fatalf("identity key mismatch after restore")
	}
	if _, err := IdentityFromMnemonic("not a real phrase at all", ""); err == nil {
		t.Fatal("expected invalid mnemonic to fail")
	}
}

func TestInviteVerify(t *testing.T) {
	id, err := GenerateIdentity("Ada")
	if err != nil {
		t.Fatal(err)
	}
	s, err := EncodeInvite(id.PublicBundle())
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodeInvite(s)
	if err != nil {
		t.Fatal(err)
	}
	if b.DisplayName != "Ada" || b.Mailbox != id.Mailbox {
		t.Fatalf("invite fields: %+v", b)
	}
	// Tamper a byte in the identity key (signature covers the prekey; Verify
	// still binds IKS, and DecodeInvite rejects a bad signature on the SPK).
	badBundle := id.PublicBundle()
	badBundle.SPK[0] ^= 0xff
	if err := badBundle.Verify(); err == nil {
		t.Fatal("tampered signed prekey should fail")
	}
}

func TestX3DHAgreement(t *testing.T) {
	alice, _ := GenerateIdentity("Alice")
	bob, _ := GenerateIdentity("Bob")
	eka, err := generateDH()
	if err != nil {
		t.Fatal(err)
	}
	skA, err := x3dhInitiatorSecret(alice.IKX, eka, bob.IKX.PublicKey().Bytes(), bob.SPK.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	skB, err := x3dhResponderSecret(bob.IKX, bob.SPK, alice.IKX.PublicKey().Bytes(), eka.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEq(skA, skB) {
		t.Fatalf("X3DH mismatch\nA %x\nB %x", skA, skB)
	}
}

func TestDoubleRatchetConversation(t *testing.T) {
	alice, _ := GenerateIdentity("Alice")
	bob, _ := GenerateIdentity("Bob")
	// Alice -> Bob (prekey)
	blob, sessA, p1, err := EncryptTo(alice, bob.PublicBundle(), nil, "hello bob")
	if err != nil {
		t.Fatal(err)
	}
	if p1.Body != "hello bob" || p1.Card == nil {
		t.Fatalf("payload: %+v", p1)
	}
	sessionsB := map[string]*Session{}
	got, peer, sessB, err := DecryptFrom(bob, sessionsB, blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != "hello bob" {
		t.Fatalf("got %q", got.Body)
	}
	if peer == nil || peer.DisplayName != "Alice" {
		t.Fatalf("missing card")
	}
	sessionsB[hexKey(peer.IKX)] = sessB

	// Bob -> Alice
	blob, sessB, _, err = EncryptTo(bob, alice.PublicBundle(), sessB, "hello alice")
	if err != nil {
		t.Fatal(err)
	}
	sessionsA := map[string]*Session{hexKey(bob.IKX.PublicKey().Bytes()): sessA}
	got, _, sessA, err = DecryptFrom(alice, sessionsA, blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != "hello alice" {
		t.Fatalf("got %q", got.Body)
	}

	// More turns + out-of-order
	var queued [][]byte
	for i, msg := range []string{"m1", "m2", "m3"} {
		var p *ChatPayload
		blob, sessA, p, err = EncryptTo(alice, bob.PublicBundle(), sessA, msg)
		if err != nil {
			t.Fatal(err)
		}
		_ = p
		if i == 1 {
			queued = append(queued, blob)
			continue
		}
		got, _, sessB, err = DecryptFrom(bob, map[string]*Session{hexKey(alice.IKX.PublicKey().Bytes()): sessB}, blob)
		if err != nil {
			t.Fatal(err)
		}
		if got.Body != msg {
			t.Fatalf("got %q want %q", got.Body, msg)
		}
	}
	// deliver skipped m2
	got, _, sessB, err = DecryptFrom(bob, map[string]*Session{hexKey(alice.IKX.PublicKey().Bytes()): sessB}, queued[0])
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != "m2" {
		t.Fatalf("skipped got %q", got.Body)
	}

	// Blob must not contain plaintext
	if bytes.Contains(blob, []byte("hello")) || bytes.Contains(blob, []byte("alice")) {
		t.Fatal("plaintext leaked into sealed blob")
	}
}

func TestSealHidesSender(t *testing.T) {
	alice, _ := GenerateIdentity("Alice")
	bob, _ := GenerateIdentity("Bob")
	blob, _, _, err := EncryptTo(alice, bob.PublicBundle(), nil, "secret line")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, alice.IKX.PublicKey().Bytes()) {
		t.Fatal("sender identity key visible in sealed blob")
	}
	if bytes.Contains(blob, []byte("secret line")) {
		t.Fatal("plaintext visible in sealed blob")
	}
	if bytes.Contains(blob, []byte(alice.MailboxHex())) {
		t.Fatal("sender mailbox visible in sealed blob")
	}
}

func TestSessionExportImport(t *testing.T) {
	alice, _ := GenerateIdentity("A")
	bob, _ := GenerateIdentity("B")
	blob, sessA, _, err := EncryptTo(alice, bob.PublicBundle(), nil, "ping")
	if err != nil {
		t.Fatal(err)
	}
	st, err := sessA.Export()
	if err != nil {
		t.Fatal(err)
	}
	sessA2, err := ImportSession(st)
	if err != nil {
		t.Fatal(err)
	}
	_, _, sessB, err := DecryptFrom(bob, map[string]*Session{}, blob)
	if err != nil {
		t.Fatal(err)
	}
	blob, _, _, err = EncryptTo(bob, alice.PublicBundle(), sessB, "pong")
	if err != nil {
		t.Fatal(err)
	}
	got, _, _, err := DecryptFrom(alice, map[string]*Session{hexKey(bob.IKX.PublicKey().Bytes()): sessA2}, blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != "pong" {
		t.Fatal(got.Body)
	}
}

func TestWriteVectors(t *testing.T) {
	// Deterministic-ish documentation vectors from a generated pair.
	// Not fixed-seed (X25519 generation + HKDF of random mnemonic). Written so
	// the Swift client can pin the invite format and AEAD layout.
	alice, err := GenerateIdentity("Alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateIdentity("Bob")
	if err != nil {
		t.Fatal(err)
	}
	invite, err := EncodeInvite(alice.PublicBundle())
	if err != nil {
		t.Fatal(err)
	}
	blob, _, payload, err := EncryptTo(alice, bob.PublicBundle(), nil, "vector-body")
	if err != nil {
		t.Fatal(err)
	}
	vec := map[string]any{
		"protocol":     ProtocolName,
		"invite":       invite,
		"aliceMailbox": alice.MailboxHex(),
		"bobMailbox":   bob.MailboxHex(),
		"blobHex":      hex.EncodeToString(blob),
		"blobLen":      len(blob),
		"payloadId":    payload.ID,
		"algorithms": map[string]string{
			"agreement": "X3DH (Signal spec, no OPK)",
			"ratchet":   "Double Ratchet (Signal spec)",
			"seal":      "DHKEM(X25519)+HKDF-SHA256+AES-256-GCM (RFC 9180 style)",
			"identity":  "X25519 + Ed25519 from BIP-39 seed",
		},
	}
	raw, _ := json.MarshalIndent(vec, "", "  ")
	out := filepath.Join("..", "..", "..", "testdata", "vectors.json")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPaddingRoundTrip(t *testing.T) {
	for _, s := range []string{"", "x", "hello", string(bytes.Repeat([]byte("n"), 200))} {
		p := padToBucket([]byte(s))
		got, err := unpad(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != s {
			t.Fatalf("%q -> %q", s, got)
		}
	}
}
