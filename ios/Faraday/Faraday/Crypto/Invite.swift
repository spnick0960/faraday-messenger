import Foundation

enum FaradayInvite {
    static let prefix = "faraday:i1."

    static func encode(_ b: PublicBundle) throws -> String {
        try b.verify()
        var name = Data(b.displayName.utf8)
        if name.count > 64 { name = name.prefix(64) }
        var raw = Data([1])
        raw.append(b.mailbox)
        raw.append(b.ikx)
        raw.append(b.iks)
        raw.append(b.spk)
        raw.append(b.spkSig)
        var spkID = Data(count: 2)
        spkID.withUnsafeMutableBytes { $0.storeBytes(of: b.spkID.bigEndian, as: UInt16.self) }
        raw.append(spkID)
        raw.append(UInt8(name.count))
        raw.append(name)
        return prefix + raw.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ string: String) throws -> PublicBundle {
        let s = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.hasPrefix(prefix) else { throw FaradayCryptoError.invite }
        let b64 = String(s.dropFirst(prefix.count))
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        var padded = b64
        while padded.count % 4 != 0 { padded.append("=") }
        guard let raw = Data(base64Encoded: padded), raw.count >= 1 + 16 + 32 + 32 + 32 + 64 + 2 + 1 else {
            throw FaradayCryptoError.invite
        }
        guard raw[0] == 1 else { throw FaradayCryptoError.invite }
        var o = 1
        let mailbox = raw.subdata(in: o..<(o + 16)); o += 16
        let ikx = raw.subdata(in: o..<(o + 32)); o += 32
        let iks = raw.subdata(in: o..<(o + 32)); o += 32
        let spk = raw.subdata(in: o..<(o + 32)); o += 32
        let sig = raw.subdata(in: o..<(o + 64)); o += 64
        let id = (UInt16(raw[o]) << 8) | UInt16(raw[o + 1])
        o += 2
        let nlen = Int(raw[o]); o += 1
        var name = ""
        if nlen > 0 {
            guard o + nlen <= raw.count else { throw FaradayCryptoError.invite }
            name = String(data: raw.subdata(in: o..<(o + nlen)), encoding: .utf8) ?? ""
        }
        let bundle = PublicBundle(mailbox: mailbox, ikx: ikx, iks: iks, spk: spk, spkSig: sig, spkID: id, displayName: name)
        try bundle.verify()
        return bundle
    }
}
