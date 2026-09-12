import CryptoKit
import Foundation

enum FaradayKDF {
    static let protocolName = "Faraday-v1"
    static let infoRoot = "Faraday-v1"
    static let infoX3DH = "Faraday-v1/x3dh"
    static let infoDHKEM = "Faraday-v1/dhkem"
    static let infoSeal = "Faraday-v1/seal"
    static let infoDR = "Faraday-v1/dr"
    static let infoMsg = "Faraday-v1/msg"
    static let infoSPK = "Faraday-v1/spk"
    static let infoIKX = "ik-x25519"
    static let infoIKS = "ik-ed25519"
    static let infoSPKPriv = "spk-x25519-1"
    static let infoMailbox = "mailbox"
    static let infoAuth = "mailbox-auth"
    static let spkID: UInt16 = 1
    static let maxSkip = 64
    static let sealVersion: UInt8 = 0x01
    static let innerVersion: UInt8 = 0x01
    static let flagPrekey: UInt8 = 0x01
    static let zeros32 = Data(repeating: 0, count: 32)
    static let x3dhF = Data(repeating: 0xFF, count: 32)

    static func hmacSHA256(key: Data, data: Data) -> Data {
        let code = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
        return Data(code)
    }

    /// HKDF-SHA256 (RFC 5869) — same construction as the Go relay tests.
    static func hkdf(ikm: Data, salt: Data?, info: Data, length: Int) throws -> Data {
        let salt = (salt?.isEmpty == false) ? salt! : zeros32
        let prk = hmacSHA256(key: salt, data: ikm)
        var out = Data()
        var prev = Data()
        var counter: UInt8 = 1
        while out.count < length {
            var block = Data()
            block.append(prev)
            block.append(info)
            block.append(counter)
            prev = hmacSHA256(key: prk, data: block)
            out.append(prev)
            counter += 1
        }
        return out.prefix(length)
    }

    static func kdfRK(rk: Data, dhOut: Data) throws -> (rk: Data, ck: Data) {
        let okm = try hkdf(ikm: dhOut, salt: rk, info: Data(infoDR.utf8), length: 64)
        return (okm.prefix(32), okm.suffix(32))
    }

    static func kdfCK(ck: Data) -> (mk: Data, ck: Data) {
        (hmacSHA256(key: ck, data: Data([0x01])), hmacSHA256(key: ck, data: Data([0x02])))
    }

    static func messageKey(_ mk: Data) throws -> (key: Data, nonce: Data) {
        let okm = try hkdf(ikm: mk, salt: zeros32, info: Data(infoMsg.utf8), length: 44)
        return (okm.prefix(32), okm.suffix(12))
    }
}

enum FaradayPad {
    static func pad(_ pt: Data) -> Data {
        let buckets = [64, 128, 256, 512, 1024, 2048, 4096, 8192]
        let need = pt.count + 1
        var target = buckets.last!
        for b in buckets where b >= need {
            target = b
            break
        }
        if need > target {
            target = ((need + 1023) / 1024) * 1024
        }
        var out = Data(count: target)
        out.replaceSubrange(0..<pt.count, with: pt)
        out[pt.count] = 0x80
        return out
    }

    static func unpad(_ pt: Data) throws -> Data {
        var i = pt.count - 1
        while i >= 0 {
            if pt[i] == 0x00 {
                i -= 1
                continue
            }
            if pt[i] == 0x80 {
                return pt.prefix(i)
            }
            throw FaradayCryptoError.padding
        }
        throw FaradayCryptoError.padding
    }
}

enum FaradayAEAD {
    static func seal(key: Data, nonce: Data, aad: Data, plaintext: Data) throws -> Data {
        let box = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: key),
            nonce: try AES.GCM.Nonce(data: nonce),
            authenticating: aad
        )
        return box.ciphertext + box.tag
    }

    static func open(key: Data, nonce: Data, aad: Data, ciphertext: Data) throws -> Data {
        guard ciphertext.count >= 16 else { throw FaradayCryptoError.short }
        let ct = ciphertext.dropLast(16)
        let tag = ciphertext.suffix(16)
        let box = try AES.GCM.SealedBox(
            nonce: try AES.GCM.Nonce(data: nonce),
            ciphertext: ct,
            tag: Data(tag)
        )
        return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
    }
}

enum FaradayCryptoError: Error, LocalizedError {
    case short, padding, invite, signature, seal, session, inner, wordlist, phrase

    var errorDescription: String? {
        switch self {
        case .short: return "加密資料不完整。"
        case .padding: return "訊息填充已損毀。"
        case .invite: return "這不是有效的 Faraday 邀請。"
        case .signature: return "邀請簽章驗證失敗。"
        case .seal: return "無法開啟封裝信封。"
        case .session: return "沒有與這位寄件者的會話。"
        case .inner: return "內部訊息格式不正確。"
        case .wordlist: return "App 缺少復原詞庫。"
        case .phrase: return "復原助記詞無效。"
        }
    }
}
