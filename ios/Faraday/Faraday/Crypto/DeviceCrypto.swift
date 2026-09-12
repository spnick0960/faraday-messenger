import CryptoKit
import Foundation

enum FaradayPayloadType {
    static let txt = "txt"
    static let read = "read"
}

struct ChatPayload: Codable, Equatable {
    var v: Int
    var t: String
    var id: String
    var ts: Int64
    var body: String
    var card: ContactCard?
    /// Last peer message id the sender has displayed. Set when `t == "read"`.
    var upto: String?
}

struct ContactCard: Codable, Equatable {
    var mb: String
    var ik: Data
    var iks: Data
    var spk: Data
    var sig: Data
    var name: String?
}

enum DeviceCrypto {
    static func encrypt(
        self id: FaradayIdentity,
        peer: PublicBundle,
        session: RatchetSession?,
        body: String,
        kind: String = FaradayPayloadType.txt,
        upto: String? = nil
    ) throws -> (blob: Data, session: RatchetSession, payload: ChatPayload) {
        try peer.verify()
        if kind == FaradayPayloadType.read, session == nil {
            throw FaradayCryptoError.session
        }
        var sess = session
        var prekey = false
        if sess == nil {
            let eka = Curve25519.KeyAgreement.PrivateKey()
            let sk = try X3DH.initiatorSecret(ika: id.ikx, eka: eka, ikb: peer.ikx, spkb: peer.spk)
            let created = try RatchetSession.alice(
                sk: sk,
                bobSPK: peer.spk,
                bobIK: peer.ikx,
                aliceIK: id.ikx.publicKey.rawRepresentation,
                bobMB: peer.mailbox
            )
            created.eka = eka
            sess = created
            prekey = true
        }
        guard let session = sess else { throw FaradayCryptoError.session }
        var idBytes = Data(count: 16)
        _ = idBytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        var payload = ChatPayload(
            v: 1,
            t: kind,
            id: idBytes.hex,
            ts: Int64(Date().timeIntervalSince1970),
            body: body,
            card: prekey ? id.card() : nil,
            upto: upto
        )
        let pt = try JSONEncoder().encode(payload)
        let enc = try session.encrypt(pt)
        let inner = encodeInner(self: id, session: session, prekey: prekey, header: enc.header, ciphertext: enc.ciphertext)
        var aad = Data(FaradayKDF.infoSeal.utf8)
        aad.append(peer.mailbox)
        let blob = try SealedEnvelope.seal(to: peer.ikx, aad: aad, plaintext: inner)
        session.eka = nil
        return (blob, session, payload)
    }

    static func decrypt(
        self id: FaradayIdentity,
        sessions: [String: RatchetSession],
        blob: Data
    ) throws -> (payload: ChatPayload, peer: PublicBundle?, session: RatchetSession) {
        var aad = Data(FaradayKDF.infoSeal.utf8)
        aad.append(id.mailbox)
        let inner = try SealedEnvelope.open(recipientIK: id.ikx, aad: aad, blob: blob)
        let msg = try decodeInner(inner)
        let key = msg.senderIK.hex
        var session = sessions[key]
        var pt: Data
        if let existing = session {
            do {
                pt = try existing.decrypt(header: msg.header, ciphertext: msg.ciphertext)
            } catch {
                // Stale ratchet after reinstall / desync: accept a new X3DH prekey
                // from the same sender without deleting the contact.
                guard msg.prekey else { throw FaradayCryptoError.session }
                session = try bobSession(self: id, senderIK: msg.senderIK, eka: msg.eka)
                pt = try session!.decrypt(header: msg.header, ciphertext: msg.ciphertext)
            }
        } else if msg.prekey {
            session = try bobSession(self: id, senderIK: msg.senderIK, eka: msg.eka)
            pt = try session!.decrypt(header: msg.header, ciphertext: msg.ciphertext)
        } else {
            throw FaradayCryptoError.session
        }
        guard let session else { throw FaradayCryptoError.session }
        let payload = try JSONDecoder().decode(ChatPayload.self, from: pt)
        var peer: PublicBundle?
        if let card = payload.card, let mb = Data.fromHex(card.mb) {
            let bundle = PublicBundle(
                mailbox: mb,
                ikx: card.ik,
                iks: card.iks,
                spk: card.spk,
                spkSig: card.sig,
                spkID: FaradayKDF.spkID,
                displayName: card.name ?? ""
            )
            try bundle.verify()
            guard bundle.ikx == msg.senderIK else { throw FaradayCryptoError.signature }
            session.peerMB = mb
            session.peerIK = bundle.ikx
            peer = bundle
        }
        return (payload, peer, session)
    }

    /// Sender identity from the sealed inner header — available even when the ratchet cannot open.
    static func peekSenderIK(self id: FaradayIdentity, blob: Data) -> String? {
        var aad = Data(FaradayKDF.infoSeal.utf8)
        aad.append(id.mailbox)
        guard let inner = try? SealedEnvelope.open(recipientIK: id.ikx, aad: aad, blob: blob),
              let msg = try? decodeInner(inner) else { return nil }
        return msg.senderIK.hex
    }

    private static func bobSession(
        self id: FaradayIdentity,
        senderIK: Data,
        eka: Data
    ) throws -> RatchetSession {
        let sk = try X3DH.responderSecret(ikb: id.ikx, spkb: id.spk, ika: senderIK, eka: eka)
        return RatchetSession.bob(
            sk: sk,
            bobSPK: id.spk,
            aliceIK: senderIK,
            bobIK: id.ikx.publicKey.rawRepresentation,
            aliceMB: Data(count: 16)
        )
    }

    private static func encodeInner(
        self id: FaradayIdentity,
        session: RatchetSession,
        prekey: Bool,
        header: Data,
        ciphertext: Data
    ) -> Data {
        var out = Data([FaradayKDF.innerVersion, prekey ? FaradayKDF.flagPrekey : 0])
        out.append(id.ikx.publicKey.rawRepresentation)
        if prekey, let eka = session.eka {
            out.append(eka.publicKey.rawRepresentation)
            var spkID = Data(count: 2)
            spkID.withUnsafeMutableBytes { $0.storeBytes(of: FaradayKDF.spkID.bigEndian, as: UInt16.self) }
            out.append(spkID)
        }
        out.append(header)
        out.append(ciphertext)
        return out
    }

    private static func decodeInner(_ data: Data) throws -> (prekey: Bool, senderIK: Data, eka: Data, header: Data, ciphertext: Data) {
        guard data.count >= 2 + 32 + 40 + 16 else { throw FaradayCryptoError.inner }
        guard data[0] == FaradayKDF.innerVersion else { throw FaradayCryptoError.inner }
        let prekey = data[1] == FaradayKDF.flagPrekey
        let senderIK = data.subdata(in: 2..<34)
        var o = 34
        var eka = Data()
        if prekey {
            guard data.count >= o + 32 + 2 + 40 + 16 else { throw FaradayCryptoError.inner }
            eka = data.subdata(in: o..<(o + 32))
            o += 34
        }
        let header = data.subdata(in: o..<(o + 40))
        let ct = data.suffix(from: o + 40)
        return (prekey, senderIK, eka, header, Data(ct))
    }
}
