package crypto

import (
	"bufio"
	"crypto/sha256"
	"embed"
	"fmt"
	"strings"
)

//go:embed bip39-english.txt
var bip39FS embed.FS

var bip39Words []string
var bip39Index map[string]int

func init() {
	f, err := bip39FS.Open("bip39-english.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	bip39Index = make(map[string]int, 2048)
	for sc.Scan() {
		w := strings.TrimSpace(sc.Text())
		if w == "" {
			continue
		}
		bip39Index[w] = len(bip39Words)
		bip39Words = append(bip39Words, w)
	}
	if len(bip39Words) != 2048 {
		panic(fmt.Sprintf("bip39 wordlist: got %d words", len(bip39Words)))
	}
}

// EntropyToMnemonic encodes 256-bit entropy as a BIP-39 24-word phrase.
func EntropyToMnemonic(entropy []byte) (string, error) {
	if len(entropy) != 32 {
		return "", fmt.Errorf("bip39: need 32 bytes of entropy, got %d", len(entropy))
	}
	cs := sha256.Sum256(entropy)
	bits := make([]byte, 0, 32+1)
	bits = append(bits, entropy...)
	bits = append(bits, cs[0]) // 8 checksum bits for 256-bit entropy

	words := make([]string, 24)
	for i := 0; i < 24; i++ {
		idx := elevenBits(bits, i*11)
		words[i] = bip39Words[idx]
	}
	return strings.Join(words, " "), nil
}

func elevenBits(data []byte, bitOffset int) int {
	var v int
	for i := 0; i < 11; i++ {
		byteI := (bitOffset + i) / 8
		bitI := 7 - ((bitOffset + i) % 8)
		v <<= 1
		if data[byteI]&(1<<bitI) != 0 {
			v |= 1
		}
	}
	return v
}

func MnemonicToSeed(mnemonic string) ([]byte, error) {
	words, err := NormalizeMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	if err := ValidateMnemonic(words); err != nil {
		return nil, err
	}
	// BIP-39 seed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048, 64)
	return pbkdf2SHA512([]byte(strings.Join(words, " ")), []byte("mnemonic"), 2048, 64), nil
}

func NormalizeMnemonic(mnemonic string) ([]string, error) {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(mnemonic)))
	if len(fields) != 24 {
		return nil, fmt.Errorf("recovery phrase must be 24 words (got %d)", len(fields))
	}
	return fields, nil
}

func ValidateMnemonic(words []string) error {
	if len(words) != 24 {
		return fmt.Errorf("recovery phrase must be 24 words")
	}
	var bitBuf []byte
	var acc, nbits int
	for _, w := range words {
		idx, ok := bip39Index[w]
		if !ok {
			return fmt.Errorf("unknown recovery word %q", w)
		}
		acc = (acc << 11) | idx
		nbits += 11
		for nbits >= 8 {
			nbits -= 8
			bitBuf = append(bitBuf, byte(acc>>nbits))
			acc &= (1 << nbits) - 1
		}
	}
	if len(bitBuf) != 33 {
		return fmt.Errorf("bip39: unexpected bit length")
	}
	entropy := bitBuf[:32]
	cs := sha256.Sum256(entropy)
	if bitBuf[32] != cs[0] {
		return fmt.Errorf("recovery phrase checksum failed — a word is wrong")
	}
	return nil
}

func Wordlist() []string { return bip39Words }
