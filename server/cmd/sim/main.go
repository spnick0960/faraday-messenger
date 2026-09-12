package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	fcrypto "faraday/internal/crypto"
	"faraday/internal/relay"
)

func main() {
	base := flag.String("relay", env("FARADAY_URL", "http://127.0.0.1:43147"), "relay base URL")
	flag.Parse()

	alice, err := fcrypto.GenerateIdentity("Alice")
	must(err)
	bob, err := fcrypto.GenerateIdentity("Bob")
	must(err)

	ac := relay.NewClient(*base)
	bc := relay.NewClient(*base)
	must(ac.Register(alice.MailboxHex(), alice.AuthHex()))
	must(bc.Register(bob.MailboxHex(), bob.AuthHex()))

	invite, err := fcrypto.EncodeInvite(bob.PublicBundle())
	must(err)
	fmt.Println("=== Faraday E2E simulation ===")
	fmt.Println("Alice invite is never sent to the server. Bob's invite (peer-to-peer):")
	fmt.Println(" ", invite[:min(72, len(invite))]+"…")

	blob, sessA, p1, err := fcrypto.EncryptTo(alice, bob.PublicBundle(), nil, "keys never leave this device")
	must(err)
	fmt.Printf("\nAlice sealed %d bytes (inner body %q). Dropping anonymously.\n", len(blob), p1.Body)
	id, err := ac.Drop(bob.MailboxHex(), blob)
	must(err)
	fmt.Println("relay assigned envelope", id, "(no sender field)")

	items, err := bc.Inbox()
	must(err)
	if len(items) == 0 {
		log.Fatal("bob inbox empty")
	}
	raw, err := relay.DecodeBlob(items[0].Blob)
	must(err)
	got, peer, sessB, err := fcrypto.DecryptFrom(bob, map[string]*fcrypto.Session{}, raw)
	must(err)
	fmt.Printf("Bob decrypted locally: %q from %s\n", got.Body, peer.DisplayName)
	must(bc.Ack([]string{items[0].ID}))

	blob, _, p2, err := fcrypto.EncryptTo(bob, alice.PublicBundle(), sessB, "and the operator cannot read this either")
	must(err)
	_, err = bc.Drop(alice.MailboxHex(), blob)
	must(err)
	_ = sessA
	items, err = ac.Inbox()
	must(err)
	raw, err = relay.DecodeBlob(items[0].Blob)
	must(err)
	got, _, _, err = fcrypto.DecryptFrom(alice, map[string]*fcrypto.Session{
		fmt.Sprintf("%x", bob.IKX.PublicKey().Bytes()): sessA,
	}, raw)
	must(err)
	fmt.Printf("Alice decrypted locally: %q\n", got.Body)
	must(ac.Ack([]string{items[0].ID}))

	if strings.Contains(base64.StdEncoding.EncodeToString(blob), p2.Body) {
		log.Fatal("plaintext appeared in blob encoding")
	}
	fmt.Println("\nBoth devices acked. Relay must now hold zero pending envelopes.")
	fmt.Println("Server-visible fields while pending: dest mailbox, blob size, timestamp (RAM only).")
	fmt.Println("After delivery: the blob is gone. Messages live only on the two devices.")
	fmt.Println("OK")
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func init() { _ = time.Now }
