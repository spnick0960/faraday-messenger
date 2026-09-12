package crypto

import (
	"crypto/ecdh"
	"fmt"
)

// x3dhInitiatorSecret implements Signal X3DH §3.3 without a one-time prekey:
//
//	DH1 = DH(IKa, SPKb)
//	DH2 = DH(EKa, IKb)
//	DH3 = DH(EKa, SPKb)
//	SK  = HKDF(F || DH1 || DH2 || DH3)
func x3dhInitiatorSecret(ika, eka *ecdh.PrivateKey, ikb, spkb []byte) ([]byte, error) {
	curve := ecdh.X25519()
	ikbPub, err := curve.NewPublicKey(ikb)
	if err != nil {
		return nil, fmt.Errorf("x3dh: ikb: %w", err)
	}
	spkbPub, err := curve.NewPublicKey(spkb)
	if err != nil {
		return nil, fmt.Errorf("x3dh: spkb: %w", err)
	}
	dh1, err := ika.ECDH(spkbPub)
	if err != nil {
		return nil, err
	}
	dh2, err := eka.ECDH(ikbPub)
	if err != nil {
		return nil, err
	}
	dh3, err := eka.ECDH(spkbPub)
	if err != nil {
		return nil, err
	}
	return x3dhKDF(dh1, dh2, dh3)
}

// x3dhResponderSecret is the Bob-side of the same three DHs.
func x3dhResponderSecret(ikb, spkb *ecdh.PrivateKey, ika, eka []byte) ([]byte, error) {
	curve := ecdh.X25519()
	ikaPub, err := curve.NewPublicKey(ika)
	if err != nil {
		return nil, fmt.Errorf("x3dh: ika: %w", err)
	}
	ekaPub, err := curve.NewPublicKey(eka)
	if err != nil {
		return nil, fmt.Errorf("x3dh: eka: %w", err)
	}
	dh1, err := spkb.ECDH(ikaPub)
	if err != nil {
		return nil, err
	}
	dh2, err := ikb.ECDH(ekaPub)
	if err != nil {
		return nil, err
	}
	dh3, err := spkb.ECDH(ekaPub)
	if err != nil {
		return nil, err
	}
	return x3dhKDF(dh1, dh2, dh3)
}

func x3dhKDF(dh1, dh2, dh3 []byte) ([]byte, error) {
	ikm := make([]byte, 0, 32+32*3)
	ikm = append(ikm, x3dhF...)
	ikm = append(ikm, dh1...)
	ikm = append(ikm, dh2...)
	ikm = append(ikm, dh3...)
	return hkdfSHA256(ikm, zeros32, []byte(InfoX3DH), 32)
}

func associatedData(initiatorIK, responderIK []byte) []byte {
	ad := make([]byte, 0, 64)
	ad = append(ad, initiatorIK...)
	ad = append(ad, responderIK...)
	return ad
}
