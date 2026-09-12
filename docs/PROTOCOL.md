# Faraday-v1 protocol

This is an implementation of published specifications, not a homemade ratchet.

| Layer | Spec | Primitives |
| --- | --- | --- |
| Recovery | [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) | PBKDF2-HMAC-SHA512, 24 words, 256-bit entropy |
| Identity | derived from BIP-39 seed | X25519 (DH) + Ed25519 (sign) via HKDF-SHA256 |
| Session setup | [Signal X3DH](https://signal.org/docs/specifications/x3dh/) (no one-time prekey) | 3× X25519, HKDF-SHA256 |
| Conversation | [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) | DH ratchet + HMAC chain, AES-256-GCM |
| Sealed envelope | [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) HPKE-style Base mode | DHKEM(X25519), HKDF-SHA256, AES-256-GCM |

There is no `libsignal` binary in this repository. The iOS client uses Apple CryptoKit. The Go package is a reference implementation used by `cmd/sim` and unit tests.

## Identity derivation

```
seed      = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048, 64)
ikx       = HKDF-SHA256(seed, salt="Faraday-v1", info="ik-x25519", 32)
iks       = HKDF-SHA256(seed, salt="Faraday-v1", info="ik-ed25519", 32)
spk       = HKDF-SHA256(seed, salt="Faraday-v1", info="spk-x25519-1", 32)
mailbox   = HKDF-SHA256(seed, salt="Faraday-v1", info="mailbox", 16)
authToken = HKDF-SHA256(seed, salt="Faraday-v1", info="mailbox-auth", 32)
spkSig    = Ed25519.Sign(iks, "Faraday-v1/spk" || spk_pub || uint16be(1))
```

Mailbox and auth token are capabilities, not names. The relay stores `SHA-256(authToken)` only.

## Invite (peer-to-peer, never uploaded)

```
faraday:i1.<base64url( version || mailbox || ikx || iks || spk || spkSig || spkID || name )>
```

The signed prekey signature is checked before a session starts. Display name is unsigned cosmetic data.

## Envelope on the wire

`POST /v1/drop` body:

```json
{ "to": "<32 hex mailbox>", "blob": "<standard base64>" }
```

No sender field. The blob is:

```
0x01 || eph_x25519_pub(32) || AES-256-GCM(inner)
```

AAD and HPKE info bind the destination mailbox so a blob cannot be replayed onto another mailbox.

Inner (after the recipient opens the seal):

```
version || flags || sender_ikx
[if prekey: eka || spk_id]
DoubleRatchet header (dh_pub || pn || n)
AES-256-GCM(padded JSON payload)
```

The JSON payload is `{v,t,id,ts,body,card?,upto?}`. First `txt` messages include a `card` so the recipient can reply without a second QR scan.

| `t` | Meaning | Fields | UI |
| --- | --- | --- | --- |
| `txt` | 1:1 chat text | `body` is the message | shown as a bubble |
| `read` | 1:1 read receipt | `body` is empty; `upto` is the last **peer** message id the sender has displayed | never a chat row; advances the peer’s local read watermark |

A `read` payload travels on the same Double Ratchet + sealed envelope as `txt`. The relay sees another opaque blob (size / dest mailbox / time only). Receipts are not sent until a session already exists. This MVP is 1:1 only; group read state is a follow-up.

## Session reset (1:1 auto-heal)

If a sealed blob cannot be opened with the current Double Ratchet state (reinstall, desync, leftover RAM after a relay flush):

1. The device **acks** the envelope so it cannot jam `GET /v1/inbox`.
2. It deletes the local session for that sender (when `sender_ikx` is readable after the outer seal). Old ciphertext is unrecoverable.
3. The next **outbound** `txt` to that contact is a new X3DH prekey using the **stored** invite bundle — the peer does not paste an invite again.
4. A recipient that still has a stale session accepts a new prekey from the same `sender_ikx` and replaces the ratchet.

The relay still sees only another opaque blob. Contacts and history on disk are not deleted.

Plaintext is padded to 64 / 128 / 256 / 512 / 1024 / 2048 / 4096 / 8192 bytes before AEAD.

## Relay API

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| PUT | `/v1/mailbox` | token in body (hashed at rest) | register capability |
| POST | `/v1/drop` | **none** (sealed sender) | enqueue opaque blob |
| GET | `/v1/inbox` | mailbox + bearer token | list pending blobs |
| POST | `/v1/ack` | mailbox + bearer token | delete delivered blobs immediately |
| WS | `/v1/ws` | first frame `auth` | live deliver / send / ack |
| GET | `/v1/transparency` | none | operator-visible metadata only |
| GET | `/v1/health` | none | liveness |

**Retention:** sealed blobs are held in RAM only. `POST /v1/ack` (or the WebSocket `ack` op) deletes them immediately after the device has persisted the message locally. Undelivered blobs are discarded after **48 hours**, or sooner if the process restarts. They are never written to the mailbox file. Default logs do not print blobs, tokens, or full mailbox IDs.
