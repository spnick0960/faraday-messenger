package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Identity is a device-local long-term key set. Private halves never go
// to the relay. Mailbox and auth token are capability identifiers, not names.
type Identity struct {
	Mnemonic   string
	IKX        *ecdh.PrivateKey // X25519 identity (DH)
	IKS        ed25519.PrivateKey
	SPK        *ecdh.PrivateKey // signed prekey, derived for restore-stability
	Mailbox    [16]byte
	AuthToken  [32]byte
	DisplayName string
}

type PublicBundle struct {
	Mailbox     [16]byte
	IKX         []byte // 32
	IKS         []byte // 32
	SPK         []byte // 32
	SPKSig      []byte // 64
	SPKID       uint16
	DisplayName string
}

func GenerateIdentity(displayName string) (*Identity, error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}
	mnemonic, err := EntropyToMnemonic(entropy)
	if err != nil {
		return nil, err
	}
	return IdentityFromMnemonic(mnemonic, displayName)
}

func IdentityFromMnemonic(mnemonic, displayName string) (*Identity, error) {
	seed, err := MnemonicToSeed(mnemonic)
	if err != nil {
		return nil, err
	}
	ikxBytes, err := hkdfSHA256(seed, []byte(InfoRoot), []byte(InfoIKX), 32)
	if err != nil {
		return nil, err
	}
	iksBytes, err := hkdfSHA256(seed, []byte(InfoRoot), []byte(InfoIKS), 32)
	if err != nil {
		return nil, err
	}
	spkBytes, err := hkdfSHA256(seed, []byte(InfoRoot), []byte(InfoSPKPriv), 32)
	if err != nil {
		return nil, err
	}
	mb, err := hkdfSHA256(seed, []byte(InfoRoot), []byte(InfoMailbox), 16)
	if err != nil {
		return nil, err
	}
	auth, err := hkdfSHA256(seed, []byte(InfoRoot), []byte(InfoAuth), 32)
	if err != nil {
		return nil, err
	}

	curve := ecdh.X25519()
	ikx, err := curve.NewPrivateKey(ikxBytes)
	if err != nil {
		return nil, fmt.Errorf("ikx: %w", err)
	}
	spk, err := curve.NewPrivateKey(spkBytes)
	if err != nil {
		return nil, fmt.Errorf("spk: %w", err)
	}
	iks := ed25519.NewKeyFromSeed(iksBytes)

	id := &Identity{
		Mnemonic:    mnemonic,
		IKX:         ikx,
		IKS:         iks,
		SPK:         spk,
		DisplayName: displayName,
	}
	copy(id.Mailbox[:], mb)
	copy(id.AuthToken[:], auth)
	return id, nil
}

func (id *Identity) PublicBundle() *PublicBundle {
	spkID := make([]byte, 2)
	binary.BigEndian.PutUint16(spkID, SPKID)
	msg := append([]byte(InfoSPK), id.SPK.PublicKey().Bytes()...)
	msg = append(msg, spkID...)
	sig := ed25519.Sign(id.IKS, msg)

	b := &PublicBundle{
		Mailbox:     id.Mailbox,
		IKX:         id.IKX.PublicKey().Bytes(),
		IKS:         id.IKS.Public().(ed25519.PublicKey),
		SPK:         id.SPK.PublicKey().Bytes(),
		SPKSig:      sig,
		SPKID:       SPKID,
		DisplayName: id.DisplayName,
	}
	return b
}

func (b *PublicBundle) Verify() error {
	if len(b.IKX) != 32 || len(b.IKS) != ed25519.PublicKeySize || len(b.SPK) != 32 || len(b.SPKSig) != ed25519.SignatureSize {
		return fmt.Errorf("bundle: unexpected key lengths")
	}
	spkID := make([]byte, 2)
	binary.BigEndian.PutUint16(spkID, b.SPKID)
	msg := append([]byte(InfoSPK), b.SPK...)
	msg = append(msg, spkID...)
	if !ed25519.Verify(ed25519.PublicKey(b.IKS), msg, b.SPKSig) {
		return fmt.Errorf("bundle: signed prekey signature rejected")
	}
	return nil
}

func (id *Identity) MailboxHex() string { return hex.EncodeToString(id.Mailbox[:]) }
func (id *Identity) AuthHex() string    { return hex.EncodeToString(id.AuthToken[:]) }

func (id *Identity) Fingerprint() string {
	h := sha256.Sum256(id.IKX.PublicKey().Bytes())
	return hex.EncodeToString(h[:8])
}

func (b *PublicBundle) Fingerprint() string {
	h := sha256.Sum256(b.IKX)
	return hex.EncodeToString(h[:8])
}

func (id *Identity) AuthTokenHash() []byte {
	sum := sha256.Sum256(id.AuthToken[:])
	return sum[:]
}

func HashAuthToken(token []byte) []byte {
	sum := sha256.Sum256(token)
	return sum[:]
}
