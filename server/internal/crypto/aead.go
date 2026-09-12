package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func sealAESGCM(key, nonce, aad, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("aes-gcm: bad nonce size %d", len(nonce))
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func openAESGCM(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("aes-gcm: bad nonce size %d", len(nonce))
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// padToBucket appends 0x80 + zero padding so the AEAD plaintext lands in a
// fixed size bucket. This reduces (does not eliminate) length side channels.
func padToBucket(pt []byte) []byte {
	buckets := []int{64, 128, 256, 512, 1024, 2048, 4096, 8192}
	need := len(pt) + 1
	target := buckets[len(buckets)-1]
	for _, b := range buckets {
		if b >= need {
			target = b
			break
		}
	}
	if need > target {
		// oversized: pad to next 1 KiB
		target = ((need + 1023) / 1024) * 1024
	}
	out := make([]byte, target)
	copy(out, pt)
	out[len(pt)] = 0x80
	return out
}

func unpad(pt []byte) ([]byte, error) {
	for i := len(pt) - 1; i >= 0; i-- {
		if pt[i] == 0x00 {
			continue
		}
		if pt[i] == 0x80 {
			return pt[:i], nil
		}
		return nil, fmt.Errorf("padding: corrupt")
	}
	return nil, fmt.Errorf("padding: empty")
}
