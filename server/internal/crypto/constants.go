package crypto

// Faraday-v1 implements published specifications — it does not invent a new
// ratcheting scheme:
//
//   • X3DH key agreement     https://signal.org/docs/specifications/x3dh/
//   • Double Ratchet         https://signal.org/docs/specifications/doubleratchet/
//   • DHKEM(X25519)+HKDF+GCM in the style of RFC 9180 HPKE (Base mode) for
//     the outer sealed envelope (hides sender identity from the relay)
//   • BIP-39 recovery phrases https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
//
// Primitives are the same ones those specs call for:
//   DH     = X25519
//   Hash   = SHA-256
//   KDF    = HKDF-SHA256 / HMAC-SHA256
//   Sign   = Ed25519
//   AEAD   = AES-256-GCM
const (
	ProtocolName = "Faraday-v1"

	InfoRoot     = "Faraday-v1"
	InfoX3DH     = "Faraday-v1/x3dh"
	InfoDHKEM    = "Faraday-v1/dhkem"
	InfoSeal     = "Faraday-v1/seal"
	InfoDR       = "Faraday-v1/dr"
	InfoMsg      = "Faraday-v1/msg"
	InfoSPK      = "Faraday-v1/spk"
	InfoIKX      = "ik-x25519"
	InfoIKS      = "ik-ed25519"
	InfoSPKPriv  = "spk-x25519-1"
	InfoMailbox  = "mailbox"
	InfoAuth     = "mailbox-auth"

	SPKID = uint16(1)

	MaxSkip          = 64
	MaxEnvelopeBytes = 64 << 10
	SealVersion      = byte(0x01)
	InnerVersion     = byte(0x01)

	FlagRatchetOnly = byte(0x00)
	FlagPrekey      = byte(0x01)
)

var (
	// X3DH IKM prefix for X25519 (Signal X3DH §2.2).
	x3dhF = bytesRepeat(0xFF, 32)
	zeros32 = make([]byte, 32)
)

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
