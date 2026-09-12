# Faraday

An iOS messenger whose product is privacy: **the operator of the relay cannot read your messages**.

No phone number. No email. No address-book upload. No analytics SDK. Keys are created on the device, stored in the iOS Keychain (`AfterFirstUnlockThisDeviceOnly` — not iCloud-synced), and backed up only by a BIP-39 24-word phrase that Faraday never transmits.

This repository is a working vertical slice: a SwiftUI client (iOS 17+) and a small Go ciphertext relay. **The iOS app UI is Traditional Chinese (zh-TW / 繁體中文).** Protocol docs stay in English.

## What you get

- Onboarding that generates a local identity and recovery phrase (or restores one). Opaque mailbox IDs only — never a phone or email.
- 1:1 text chat using **Signal X3DH + Double Ratchet**, wrapped in a **sealed envelope** so the relay does not see the sender.
- Contact discovery by QR / pasteable invite. Nothing is uploaded from your address book.
- An **ephemeral** relay: sealed blobs sit in RAM until the recipient device fetches and acks them, then they are deleted immediately. Nothing is archived on disk.
- A transparency dashboard that shows *exactly* what the server can see.

Group chat, attachments, voice, stories, and push notifications are out of scope for this pass.

## Threat model

**Designed against:** a curious relay operator, a leaked relay disk (which holds mailbox IDs only), and a network observer who can see that two IPs exchanged padded blobs.

**Not designed against:** a compromised or unlocked iPhone, malware on the device, or a contact who screenshots the chat. We also do not claim post-quantum confidentiality (no PQXDH yet).

### The server CAN see

- That mailbox `X` currently has a sealed blob waiting **in RAM**, its padded size, and when it arrived
- The TCP/IP address that dropped or fetched mail
- Coarse presence while a client holds a WebSocket

### The server CANNOT see

- Message plaintext
- Display names (they travel inside ciphertext)
- Recovery phrases or private keys
- Contact lists
- Who sent a given envelope (sealed sender)
- Ratchet / session state
- A long-term ciphertext archive (delivered and expired blobs are gone; they were never written to disk)

Invite links are **capabilities**. Anyone who has yours can start a conversation with you. They still cannot read your other chats.

## Ephemeral relay policy

The server is a **mailbox, not a store**. After a message is delivered, it lives only on the two user devices.

| Stage | What the relay holds | Where |
| --- | --- | --- |
| Just sent, recipient offline | Sealed blob + dest mailbox + time + size | Process memory only |
| Recipient fetched and acked | Nothing | Deleted immediately |
| Recipient never comes online | Nothing after **48 hours** | Discarded; no retry |
| Relay process restarts | Nothing pending | RAM queue is gone |

If the recipient never opens Faraday within 48 hours, the sealed blob is permanently gone from the network. The sender still has the outgoing message on their own phone. Faraday will not reconstruct it from the server, because the server was never allowed to keep it.

The on-disk file (`data/relay.json`) stores mailbox capability IDs and token hashes so a restart can still authenticate devices. It does **not** store envelopes. An older build that wrote blobs into that file is stripped on startup.

### Local notifications vs APNs

While the process is alive, Faraday can receive via WebSocket (reconnects after a drop) plus HTTP inbox polling every ~1.5s. A new message for a conversation you are **not** looking at posts a **local** `UNUserNotificationCenter` banner on this device only:

- Title: the contact display name already stored on the device
- Body: the fixed line `你有一則新訊息` — **never** the message plaintext
- No APNs, no Firebase, no payload sent to any push server

**Still missing (killed-app push):** if iOS suspends or kills Faraday, polling and the socket stop. Sealed blobs wait in relay RAM for up to 48 hours. Waking a killed app needs APNs. The only acceptable APNs payload later is a silent data-only ping or the same generic “new message” line — no body, mailbox, or ciphertext. Apple would still learn that this device got a ping at time T. That is why APNs is still off.

## Cryptography (auditable, not invented)

| Piece | What we use |
| --- | --- |
| Session setup | [Signal X3DH](https://signal.org/docs/specifications/x3dh/) (no one-time prekey in the MVP) |
| Message ratchet | [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) |
| Sealed envelope | DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM, [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) HPKE Base style |
| Identity | X25519 + Ed25519 derived from a [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) seed |
| Libraries | Apple **CryptoKit** (iOS), Go `crypto/*` (reference + tests). No Firebase, Mixpanel, Crashlytics, or other analytics. |

This is an implementation of those specs, **not** a vendored `libsignal` binary, and it has **not** been independently audited. See [docs/PROTOCOL.md](docs/PROTOCOL.md).

Secure Enclave does not support X25519. DH identity keys are Keychain-protected, not enclave-bound. That limitation is honest, not hidden.

## Repository layout

```
ios/Faraday/          SwiftUI client (open Faraday.xcodeproj)
server/               Go relay, reference crypto, two-device simulator
docs/PROTOCOL.md      Wire format and algorithms
testdata/             BIP-39 wordlist + generated vectors
```

## Run the relay (Linux / macOS)

Requires Go 1.22+.

```bash
cd server
go test ./...
go run ./cmd/relay -addr 127.0.0.1:43147 -data data/relay.json -web web
```

Open [http://127.0.0.1:43147/](http://127.0.0.1:43147/) — that page is the operator view. It will show mailbox counts and ciphertext prefixes. It cannot show plaintext; the process does not have the keys.

Prove two devices through the same relay:

```bash
cd server
go run ./cmd/sim -relay http://127.0.0.1:43147
```

You should see Alice and Bob decrypt locally, and the dashboard update with sealed blobs only.

Bind `0.0.0.0:43147` if iPhones on your LAN need to reach this machine:

```bash
FARADAY_ADDR=0.0.0.0:43147 go run ./cmd/relay -addr 0.0.0.0:43147 -data data/relay.json -web web
```

## Deploy (Render)

The relay is Render-ready. `server/Dockerfile` is a multi-stage build of `./cmd/relay` plus the `web/` dashboard. In a container it listens on `0.0.0.0:$PORT` (default `43147`). Local `go run` still binds `127.0.0.1:43147` unless you set `PORT` or `FARADAY_ADDR`.

1. Push this repo and [create a Blueprint](https://render.com/docs/blueprint-spec) from root `render.yaml`, or create a **Web Service** with Docker context `server/` and Dockerfile `server/Dockerfile`.
2. Health check: `GET /v1/health`.
3. In the iOS app Settings, set the relay URL to `https://<your-service>.onrender.com` (no trailing path).

Render injects `PORT`. The service is ephemeral: mailbox IDs may live in `/tmp`; sealed blobs stay in RAM and vanish on deploy or restart, same as the 48-hour TTL policy.

## Open the iOS app in Xcode

You need a Mac with Xcode 15+ (iOS 17 SDK). This Cloud environment cannot compile SwiftUI. The running app’s chrome (welcome, inbox, chat, settings, invites) is Traditional Chinese.

1. Open `ios/Faraday/Faraday.xcodeproj`.
2. Select the **Faraday** scheme, an iPhone 17 / iOS 17+ simulator.
3. Signing: choose your Team under the Faraday target (bundle id `app.faraday.messenger`).
4. Run.

### Two simulators exchanging messages

1. Keep the relay running on the Mac (`127.0.0.1:43147`).
2. Xcode → **Product → Destination → Manage Run Destinations** and boot two simulators (or `xcrun simctl boot`).
3. Run Faraday on the first simulator. Create an identity. Write down the phrase.
4. Run Faraday on the second simulator (Xcode can target the other destination; each simulator has its own Keychain).
5. On device A: **QR** → **Copy invite string**.
6. On device B: **+** → paste the invite → **Add contact**.
7. Send a text from B. A decrypts it on-device. B’s first sealed message includes A’s reply path, so A can answer without a second scan.
8. In Settings, confirm the relay URL is `http://127.0.0.1:43147`.

On a physical device, set the relay URL to `http://<your-mac-lan-ip>:43147`.

Simulator QR scanning is not available; paste the invite. A real device can scan the QR.

## Known limitations (intentionally documented)

- **No APNs / killed-app push.** Local banners work while Faraday can still poll or hold a WebSocket. See the APNs note above. A future silent ping would still leak “this device got mail at T” to Apple.
- **Restore does not bring back history.** The phrase restores keys and mailbox. Ratchet sessions and local messages stay on the old device. Previous contacts may need to invite you again.
- **No post-quantum.** Classic X3DH, not PQXDH.
- **Metadata remains.** IPs, times, padded sizes, mailbox IDs. Sealed sender hides *who* wrote to a mailbox, not *that* the mailbox received mail.
- **Invite is a capability.** Treat it like a secret.
- **Unaudited implementation** of the Signal specs. Do not use this build for high-risk threat models without review.
- **No attachments.** Text only.
- **1:1 read receipts only.** Opening a thread seals a `t: "read"` payload (`upto` = last peer message id). Group receipts are a follow-up. The relay sees another opaque blob.
- **Background iOS networking is unreliable** without push. If the app is suspended, a sealed blob waits in RAM for up to 48 hours. After that it is gone, even if the recipient later comes online.

## Privacy defaults

- Tracking: `NSPrivacyTracking = false`. No collected data types declared.
- No third-party SDKs.
- Relay logs omit bodies, tokens, and full mailbox IDs.
- Default UI copy states what is and is not collected. There is no “optional analytics” toggle because there is no analytics.

## License

You own this project. Add a license before you publish it if you want others to run or audit it.
