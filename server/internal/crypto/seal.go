package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// SealTo wraps plaintext in a single-shot anonymous DH envelope for
// recipientIK (X25519 public). This is DHKEM(X25519, HKDF-SHA256) + AES-256-GCM
// in the style of RFC 9180 HPKE Base mode. The relay sees only dest mailbox +
// this blob — not the sender identity, not the inner Signal headers.
func SealTo(recipientIK, aad, plaintext []byte) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(recipientIK)
	if err != nil {
		return nil, err
	}
	zz, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	enc := eph.PublicKey().Bytes()
	shared, err := kemShared(zz, enc, recipientIK)
	if err != nil {
		return nil, err
	}
	key, nonce, err := sealKeys(shared, aad)
	if err != nil {
		return nil, err
	}
	ct, err := sealAESGCM(key, nonce, aad, plaintext)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+32+len(ct))
	out = append(out, SealVersion)
	out = append(out, enc...)
	out = append(out, ct...)
	return out, nil
}

func OpenSealed(recipientIKPriv *ecdh.PrivateKey, aad, blob []byte) ([]byte, error) {
	if len(blob) < 1+32+16 {
		return nil, fmt.Errorf("seal: short")
	}
	if blob[0] != SealVersion {
		return nil, fmt.Errorf("seal: unsupported version")
	}
	enc := blob[1:33]
	ct := blob[33:]
	ephPub, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, err
	}
	zz, err := recipientIKPriv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	shared, err := kemShared(zz, enc, recipientIKPriv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	key, nonce, err := sealKeys(shared, aad)
	if err != nil {
		return nil, err
	}
	return openAESGCM(key, nonce, aad, ct)
}

func kemShared(zz, enc, pkR []byte) ([]byte, error) {
	// RFC 9180 DHKEM ExtractAndExpand: IKM = DH, kem_context = enc || pkR
	ctx := append(append([]byte(nil), enc...), pkR...)
	return hkdfSHA256(zz, zeros32, append([]byte(InfoDHKEM), ctx...), 32)
}

func sealKeys(shared, aad []byte) (key, nonce []byte, err error) {
	info := append([]byte(InfoSeal), aad...)
	okm, err := hkdfSHA256(shared, zeros32, info, 44)
	if err != nil {
		return nil, nil, err
	}
	return okm[:32], okm[32:], nil
}
