package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// hkdfSHA256 is HKDF-SHA256 (RFC 5869). Extract then Expand.
func hkdfSHA256(ikm, salt, info []byte, n int) ([]byte, error) {
	if n <= 0 || n > 255*sha256.Size {
		return nil, fmt.Errorf("hkdf: invalid length %d", n)
	}
	if salt == nil || len(salt) == 0 {
		salt = zeros32
	}
	prk := hmacSHA256(salt, ikm)
	return hkdfExpand(prk, info, n)
}

func hkdfExpand(prk, info []byte, n int) ([]byte, error) {
	var (
		t    []byte
		out  []byte
		prev []byte
	)
	for i := 1; len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		_, _ = m.Write(prev)
		_, _ = m.Write(info)
		_, _ = m.Write([]byte{byte(i)})
		t = m.Sum(t[:0])
		out = append(out, t...)
		prev = append(prev[:0], t...)
	}
	return out[:n], nil
}
