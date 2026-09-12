package crypto

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

const invitePrefix = "faraday:i1."

// EncodeInvite packs a public bundle into a QR / pasteable invite string.
// Keys travel peer-to-peer; the relay never hosts a directory.
func EncodeInvite(b *PublicBundle) (string, error) {
	if err := b.Verify(); err != nil {
		return "", err
	}
	name := []byte(b.DisplayName)
	if len(name) > 64 {
		name = name[:64]
	}
	raw := make([]byte, 0, 1+16+32+32+32+64+2+1+len(name))
	raw = append(raw, 1)
	raw = append(raw, b.Mailbox[:]...)
	raw = append(raw, b.IKX...)
	raw = append(raw, b.IKS...)
	raw = append(raw, b.SPK...)
	raw = append(raw, b.SPKSig...)
	spkID := make([]byte, 2)
	binary.BigEndian.PutUint16(spkID, b.SPKID)
	raw = append(raw, spkID...)
	raw = append(raw, byte(len(name)))
	raw = append(raw, name...)
	return invitePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func DecodeInvite(s string) (*PublicBundle, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, invitePrefix) {
		return nil, fmt.Errorf("invite: not a Faraday invite")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, invitePrefix))
	if err != nil {
		return nil, fmt.Errorf("invite: corrupt")
	}
	if len(raw) < 1+16+32+32+32+64+2+1 {
		return nil, fmt.Errorf("invite: short")
	}
	if raw[0] != 1 {
		return nil, fmt.Errorf("invite: unsupported version")
	}
	o := 1
	var mb [16]byte
	copy(mb[:], raw[o:o+16])
	o += 16
	b := &PublicBundle{
		Mailbox: mb,
		IKX:     append([]byte(nil), raw[o:o+32]...),
	}
	o += 32
	b.IKS = append([]byte(nil), raw[o:o+32]...)
	o += 32
	b.SPK = append([]byte(nil), raw[o:o+32]...)
	o += 32
	b.SPKSig = append([]byte(nil), raw[o:o+64]...)
	o += 64
	b.SPKID = binary.BigEndian.Uint16(raw[o : o+2])
	o += 2
	nlen := int(raw[o])
	o++
	if nlen > 0 {
		if o+nlen > len(raw) {
			return nil, fmt.Errorf("invite: name truncated")
		}
		b.DisplayName = string(raw[o : o+nlen])
	}
	if err := b.Verify(); err != nil {
		return nil, err
	}
	return b, nil
}
