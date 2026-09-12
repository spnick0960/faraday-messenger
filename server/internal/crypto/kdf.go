package crypto

import "crypto/hmac"
import "crypto/sha256"

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(data)
	return m.Sum(nil)
}

// kdfRK is the Double Ratchet root KDF (spec §5.2): HKDF with the current
// root key as salt and the DH output as IKM.
func kdfRK(rk, dhOut []byte) (newRK, ck []byte, err error) {
	okm, err := hkdfSHA256(dhOut, rk, []byte(InfoDR), 64)
	if err != nil {
		return nil, nil, err
	}
	return okm[:32], okm[32:], nil
}

// kdfCK is the Double Ratchet chain KDF (spec §5.2): HMAC-SHA256 with
// constant labels 0x01 (message key) and 0x02 (next chain key).
func kdfCK(ck []byte) (mk, nextCK []byte) {
	return hmacSHA256(ck, []byte{0x01}), hmacSHA256(ck, []byte{0x02})
}

func deriveMessageKey(mk []byte) (key, nonce []byte, err error) {
	okm, err := hkdfSHA256(mk, zeros32, []byte(InfoMsg), 44)
	if err != nil {
		return nil, nil, err
	}
	return okm[:32], okm[32:], nil
}
