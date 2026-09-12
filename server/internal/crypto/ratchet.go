package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type skippedKey struct {
	DH string
	N  uint32
	MK []byte
}

// Session is one Double Ratchet session with a peer (spec §3).
type Session struct {
	// Role: "init" if we started the conversation, "resp" otherwise.
	// AD is IKa || IKb (initiator identity || responder identity).
	Role   string
	PeerIK []byte
	PeerMB [16]byte

	DHs *ecdh.PrivateKey
	DHr []byte // 32, may be nil before first receive on responder

	RK  []byte
	CKs []byte // may be nil
	CKr []byte // may be nil
	Ns  uint32
	Nr  uint32
	PN  uint32

	AD          []byte
	Skipped     []skippedKey
	Established bool
	eka         *ecdh.PrivateKey // X3DH ephemeral, initiator first message only
}

type SessionState struct {
	Role        string   `json:"role"`
	PeerIK      []byte   `json:"peerIK"`
	PeerMB      []byte   `json:"peerMB"`
	DHsPriv     []byte   `json:"dhs"`
	DHrPub      []byte   `json:"dhr,omitempty"`
	RK          []byte   `json:"rk"`
	CKs         []byte   `json:"cks,omitempty"`
	CKr         []byte   `json:"ckr,omitempty"`
	Ns          uint32   `json:"ns"`
	Nr          uint32   `json:"nr"`
	PN          uint32   `json:"pn"`
	AD          []byte   `json:"ad"`
	Established bool     `json:"ok"`
	Skipped     []skippedKey `json:"skipped,omitempty"`
}

func generateDH() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func dh(priv *ecdh.PrivateKey, pubBytes []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

// InitAlice is Double Ratchet init for the X3DH initiator (spec §3.3).
func InitAlice(sk, bobSPK, bobIK, aliceIK []byte, bobMB [16]byte) (*Session, error) {
	dhs, err := generateDH()
	if err != nil {
		return nil, err
	}
	secret, err := dh(dhs, bobSPK)
	if err != nil {
		return nil, err
	}
	rk, cks, err := kdfRK(sk, secret)
	if err != nil {
		return nil, err
	}
	return &Session{
		Role:        "init",
		PeerIK:      append([]byte(nil), bobIK...),
		PeerMB:      bobMB,
		DHs:         dhs,
		DHr:         append([]byte(nil), bobSPK...),
		RK:          rk,
		CKs:         cks,
		AD:          associatedData(aliceIK, bobIK),
		Established: true,
	}, nil
}

// InitBob is Double Ratchet init for the X3DH responder (spec §3.3).
func InitBob(sk []byte, bobSPK *ecdh.PrivateKey, aliceIK, bobIK []byte, aliceMB [16]byte) *Session {
	return &Session{
		Role:        "resp",
		PeerIK:      append([]byte(nil), aliceIK...),
		PeerMB:      aliceMB,
		DHs:         bobSPK,
		RK:          append([]byte(nil), sk...),
		AD:          associatedData(aliceIK, bobIK),
		Established: true,
	}
}

type ratchetHeader struct {
	DH []byte
	PN uint32
	N  uint32
}

func encodeHeader(h ratchetHeader) []byte {
	out := make([]byte, 32+4+4)
	copy(out[:32], h.DH)
	binary.BigEndian.PutUint32(out[32:36], h.PN)
	binary.BigEndian.PutUint32(out[36:40], h.N)
	return out
}

func decodeHeader(b []byte) (ratchetHeader, error) {
	if len(b) < 40 {
		return ratchetHeader{}, fmt.Errorf("header: short")
	}
	return ratchetHeader{
		DH: append([]byte(nil), b[:32]...),
		PN: binary.BigEndian.Uint32(b[32:36]),
		N:  binary.BigEndian.Uint32(b[36:40]),
	}, nil
}

func (s *Session) Encrypt(plaintext []byte) (header, ciphertext []byte, err error) {
	if s.CKs == nil {
		return nil, nil, fmt.Errorf("ratchet: no sending chain")
	}
	var mk []byte
	mk, s.CKs = kdfCK(s.CKs)
	h := ratchetHeader{DH: s.DHs.PublicKey().Bytes(), PN: s.PN, N: s.Ns}
	hdr := encodeHeader(h)
	key, nonce, err := deriveMessageKey(mk)
	if err != nil {
		return nil, nil, err
	}
	aad := append(append([]byte(nil), s.AD...), hdr...)
	ct, err := sealAESGCM(key, nonce, aad, padToBucket(plaintext))
	if err != nil {
		return nil, nil, err
	}
	s.Ns++
	return hdr, ct, nil
}

func (s *Session) Decrypt(header, ciphertext []byte) ([]byte, error) {
	h, err := decodeHeader(header)
	if err != nil {
		return nil, err
	}
	if pt, ok := s.trySkipped(h, header, ciphertext); ok {
		return pt, nil
	}
	if s.DHr == nil || !bytesEq(s.DHr, h.DH) {
		if err := s.skipMessageKeys(h.PN); err != nil {
			return nil, err
		}
		if err := s.dhRatchet(h); err != nil {
			return nil, err
		}
	}
	if err := s.skipMessageKeys(h.N); err != nil {
		return nil, err
	}
	if s.CKr == nil {
		return nil, fmt.Errorf("ratchet: no receiving chain")
	}
	var mk []byte
	mk, s.CKr = kdfCK(s.CKr)
	s.Nr++
	return openWithMK(mk, s.AD, header, ciphertext)
}

func (s *Session) trySkipped(h ratchetHeader, header, ct []byte) ([]byte, bool) {
	want := hex.EncodeToString(h.DH)
	for i, sk := range s.Skipped {
		if sk.DH == want && sk.N == h.N {
			s.Skipped = append(s.Skipped[:i], s.Skipped[i+1:]...)
			pt, err := openWithMK(sk.MK, s.AD, header, ct)
			if err != nil {
				return nil, false
			}
			return pt, true
		}
	}
	return nil, false
}

func (s *Session) skipMessageKeys(until uint32) error {
	if s.CKr == nil {
		return nil
	}
	if until < s.Nr {
		return nil
	}
	if until-s.Nr > MaxSkip {
		return fmt.Errorf("ratchet: too many skipped keys")
	}
	dhHex := hex.EncodeToString(s.DHr)
	for s.Nr < until {
		var mk []byte
		mk, s.CKr = kdfCK(s.CKr)
		s.Skipped = append(s.Skipped, skippedKey{DH: dhHex, N: s.Nr, MK: mk})
		s.Nr++
	}
	if len(s.Skipped) > MaxSkip {
		s.Skipped = s.Skipped[len(s.Skipped)-MaxSkip:]
	}
	return nil
}

func (s *Session) dhRatchet(h ratchetHeader) error {
	s.PN = s.Ns
	s.Ns = 0
	s.Nr = 0
	s.DHr = append([]byte(nil), h.DH...)
	secret, err := dh(s.DHs, s.DHr)
	if err != nil {
		return err
	}
	s.RK, s.CKr, err = kdfRK(s.RK, secret)
	if err != nil {
		return err
	}
	s.DHs, err = generateDH()
	if err != nil {
		return err
	}
	secret, err = dh(s.DHs, s.DHr)
	if err != nil {
		return err
	}
	s.RK, s.CKs, err = kdfRK(s.RK, secret)
	return err
}

func openWithMK(mk, ad, header, ct []byte) ([]byte, error) {
	key, nonce, err := deriveMessageKey(mk)
	if err != nil {
		return nil, err
	}
	aad := append(append([]byte(nil), ad...), header...)
	pt, err := openAESGCM(key, nonce, aad, ct)
	if err != nil {
		return nil, err
	}
	return unpad(pt)
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func (s *Session) Export() (*SessionState, error) {
	st := &SessionState{
		Role:        s.Role,
		PeerIK:      append([]byte(nil), s.PeerIK...),
		PeerMB:      s.PeerMB[:],
		DHsPriv:     s.DHs.Bytes(),
		DHrPub:      append([]byte(nil), s.DHr...),
		RK:          append([]byte(nil), s.RK...),
		CKs:         append([]byte(nil), s.CKs...),
		CKr:         append([]byte(nil), s.CKr...),
		Ns:          s.Ns,
		Nr:          s.Nr,
		PN:          s.PN,
		AD:          append([]byte(nil), s.AD...),
		Established: s.Established,
		Skipped:     s.Skipped,
	}
	return st, nil
}

func ImportSession(st *SessionState) (*Session, error) {
	dhs, err := ecdh.X25519().NewPrivateKey(st.DHsPriv)
	if err != nil {
		return nil, err
	}
	var mb [16]byte
	copy(mb[:], st.PeerMB)
	return &Session{
		Role:        st.Role,
		PeerIK:      st.PeerIK,
		PeerMB:      mb,
		DHs:         dhs,
		DHr:         st.DHrPub,
		RK:          st.RK,
		CKs:         st.CKs,
		CKr:         st.CKr,
		Ns:          st.Ns,
		Nr:          st.Nr,
		PN:          st.PN,
		AD:          st.AD,
		Established: st.Established,
		Skipped:     st.Skipped,
	}, nil
}
