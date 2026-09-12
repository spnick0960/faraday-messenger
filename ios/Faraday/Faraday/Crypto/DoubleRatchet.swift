import CryptoKit
import Foundation

struct SkippedKey: Codable, Equatable {
    var dh: String
    var n: UInt32
    var mk: Data
}

struct SessionState: Codable {
    var role: String
    var peerIK: Data
    var peerMB: Data
    var dhs: Data
    var dhr: Data?
    var rk: Data
    var cks: Data?
    var ckr: Data?
    var ns: UInt32
    var nr: UInt32
    var pn: UInt32
    var ad: Data
    var ok: Bool
    var skipped: [SkippedKey]
}

final class RatchetSession {
    var role: String
    var peerIK: Data
    var peerMB: Data
    var dhs: Curve25519.KeyAgreement.PrivateKey
    var dhr: Data?
    var rk: Data
    var cks: Data?
    var ckr: Data?
    var ns: UInt32 = 0
    var nr: UInt32 = 0
    var pn: UInt32 = 0
    var ad: Data
    var established = true
    var skipped: [SkippedKey] = []
    var eka: Curve25519.KeyAgreement.PrivateKey?

    init(
        role: String,
        peerIK: Data,
        peerMB: Data,
        dhs: Curve25519.KeyAgreement.PrivateKey,
        dhr: Data?,
        rk: Data,
        cks: Data?,
        ckr: Data?,
        ad: Data
    ) {
        self.role = role
        self.peerIK = peerIK
        self.peerMB = peerMB
        self.dhs = dhs
        self.dhr = dhr
        self.rk = rk
        self.cks = cks
        self.ckr = ckr
        self.ad = ad
    }

    static func alice(sk: Data, bobSPK: Data, bobIK: Data, aliceIK: Data, bobMB: Data) throws -> RatchetSession {
        let dhs = Curve25519.KeyAgreement.PrivateKey()
        let secret = try dhs.sharedSecretFromKeyAgreement(
            with: try Curve25519.KeyAgreement.PublicKey(rawRepresentation: bobSPK)
        ).data
        let (rk, cks) = try FaradayKDF.kdfRK(rk: sk, dhOut: secret)
        return RatchetSession(
            role: "init",
            peerIK: bobIK,
            peerMB: bobMB,
            dhs: dhs,
            dhr: bobSPK,
            rk: rk,
            cks: cks,
            ckr: nil,
            ad: X3DH.associatedData(initiatorIK: aliceIK, responderIK: bobIK)
        )
    }

    static func bob(sk: Data, bobSPK: Curve25519.KeyAgreement.PrivateKey, aliceIK: Data, bobIK: Data, aliceMB: Data) -> RatchetSession {
        RatchetSession(
            role: "resp",
            peerIK: aliceIK,
            peerMB: aliceMB,
            dhs: bobSPK,
            dhr: nil,
            rk: sk,
            cks: nil,
            ckr: nil,
            ad: X3DH.associatedData(initiatorIK: aliceIK, responderIK: bobIK)
        )
    }

    func encrypt(_ plaintext: Data) throws -> (header: Data, ciphertext: Data) {
        guard var ck = cks else { throw FaradayCryptoError.session }
        let pair = FaradayKDF.kdfCK(ck: ck)
        ck = pair.ck
        cks = ck
        let header = encodeHeader(dh: dhs.publicKey.rawRepresentation, pn: pn, n: ns)
        let keys = try FaradayKDF.messageKey(pair.mk)
        var aad = ad
        aad.append(header)
        let ct = try FaradayAEAD.seal(key: keys.key, nonce: keys.nonce, aad: aad, plaintext: FaradayPad.pad(plaintext))
        ns += 1
        return (header, ct)
    }

    func decrypt(header: Data, ciphertext: Data) throws -> Data {
        let h = try decodeHeader(header)
        if let pt = trySkipped(h, header: header, ciphertext: ciphertext) {
            return pt
        }
        if dhr == nil || dhr != h.dh {
            try skip(until: h.pn)
            try dhRatchet(h)
        }
        try skip(until: h.n)
        guard var ck = ckr else { throw FaradayCryptoError.session }
        let pair = FaradayKDF.kdfCK(ck: ck)
        ck = pair.ck
        ckr = ck
        nr += 1
        return try open(mk: pair.mk, header: header, ciphertext: ciphertext)
    }

    private func trySkipped(_ h: (dh: Data, pn: UInt32, n: UInt32), header: Data, ciphertext: Data) -> Data? {
        let want = h.dh.hex
        if let idx = skipped.firstIndex(where: { $0.dh == want && $0.n == h.n }) {
            let mk = skipped[idx].mk
            skipped.remove(at: idx)
            return try? open(mk: mk, header: header, ciphertext: ciphertext)
        }
        return nil
    }

    private func skip(until: UInt32) throws {
        guard ckr != nil else { return }
        if until < nr { return }
        if until &- nr > UInt32(FaradayKDF.maxSkip) { throw FaradayCryptoError.session }
        let dhHex = (dhr ?? Data()).hex
        while nr < until {
            let pair = FaradayKDF.kdfCK(ck: ckr!)
            ckr = pair.ck
            skipped.append(SkippedKey(dh: dhHex, n: nr, mk: pair.mk))
            nr += 1
        }
        if skipped.count > FaradayKDF.maxSkip {
            skipped = Array(skipped.suffix(FaradayKDF.maxSkip))
        }
    }

    private func dhRatchet(_ h: (dh: Data, pn: UInt32, n: UInt32)) throws {
        pn = ns
        ns = 0
        nr = 0
        dhr = h.dh
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: h.dh)
        var secret = try dhs.sharedSecretFromKeyAgreement(with: pub).data
        var next = try FaradayKDF.kdfRK(rk: rk, dhOut: secret)
        rk = next.rk
        ckr = next.ck
        dhs = Curve25519.KeyAgreement.PrivateKey()
        secret = try dhs.sharedSecretFromKeyAgreement(with: pub).data
        next = try FaradayKDF.kdfRK(rk: rk, dhOut: secret)
        rk = next.rk
        cks = next.ck
    }

    private func open(mk: Data, header: Data, ciphertext: Data) throws -> Data {
        let keys = try FaradayKDF.messageKey(mk)
        var aad = ad
        aad.append(header)
        let pt = try FaradayAEAD.open(key: keys.key, nonce: keys.nonce, aad: aad, ciphertext: ciphertext)
        return try FaradayPad.unpad(pt)
    }

    func exportState() -> SessionState {
        SessionState(
            role: role,
            peerIK: peerIK,
            peerMB: peerMB,
            dhs: dhs.rawRepresentation,
            dhr: dhr,
            rk: rk,
            cks: cks,
            ckr: ckr,
            ns: ns,
            nr: nr,
            pn: pn,
            ad: ad,
            ok: established,
            skipped: skipped
        )
    }

    static func importState(_ st: SessionState) throws -> RatchetSession {
        let s = RatchetSession(
            role: st.role,
            peerIK: st.peerIK,
            peerMB: st.peerMB,
            dhs: try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: st.dhs),
            dhr: st.dhr,
            rk: st.rk,
            cks: st.cks,
            ckr: st.ckr,
            ad: st.ad
        )
        s.ns = st.ns
        s.nr = st.nr
        s.pn = st.pn
        s.established = st.ok
        s.skipped = st.skipped
        return s
    }
}

func encodeHeader(dh: Data, pn: UInt32, n: UInt32) -> Data {
    var out = dh
    var pnBE = pn.bigEndian
    var nBE = n.bigEndian
    out.append(Data(bytes: &pnBE, count: 4))
    out.append(Data(bytes: &nBE, count: 4))
    return out
}

func decodeHeader(_ data: Data) throws -> (dh: Data, pn: UInt32, n: UInt32) {
    guard data.count >= 40 else { throw FaradayCryptoError.short }
    return (Data(data.prefix(32)), u32be(data, 32), u32be(data, 36))
}

func u32be(_ data: Data, _ offset: Int) -> UInt32 {
    (UInt32(data[offset]) << 24) | (UInt32(data[offset + 1]) << 16) | (UInt32(data[offset + 2]) << 8) | UInt32(data[offset + 3])
}
