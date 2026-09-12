package crypto

import (
	"crypto/hmac"
	"crypto/sha512"
	"hash"
)

// pbkdf2SHA512 is PBKDF2-HMAC-SHA512 (RFC 8018), used by BIP-39.
func pbkdf2SHA512(password, salt []byte, iter, keyLen int) []byte {
	return pbkdf2(sha512.New, password, salt, iter, keyLen)
}

func pbkdf2(h func() hash.Hash, password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	block := make([]byte, 4)
	for i := 1; i <= numBlocks; i++ {
		block[0] = byte(i >> 24)
		block[1] = byte(i >> 16)
		block[2] = byte(i >> 8)
		block[3] = byte(i)
		prf.Reset()
		prf.Write(salt)
		prf.Write(block)
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for j := 1; j < iter; j++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
