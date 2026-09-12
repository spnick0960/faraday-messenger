import CryptoKit
import Foundation

enum SealedEnvelope {
    static func seal(to recipientIK: Data, aad: Data, plaintext: Data) throws -> Data {
        let eph = Curve25519.KeyAgreement.PrivateKey()
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientIK)
        let zz = try eph.sharedSecretFromKeyAgreement(with: pub).data
        let enc = eph.publicKey.rawRepresentation
        let shared = try kemShared(zz: zz, enc: enc, pkR: recipientIK)
        let keys = try sealKeys(shared: shared, aad: aad)
        let ct = try FaradayAEAD.seal(key: keys.key, nonce: keys.nonce, aad: aad, plaintext: plaintext)
        var out = Data([FaradayKDF.sealVersion])
        out.append(enc)
        out.append(ct)
        return out
    }

    static func open(recipientIK: Curve25519.KeyAgreement.PrivateKey, aad: Data, blob: Data) throws -> Data {
        guard blob.count >= 1 + 32 + 16, blob[0] == FaradayKDF.sealVersion else {
            throw FaradayCryptoError.seal
        }
        let enc = blob.subdata(in: 1..<33)
        let ct = blob.suffix(from: 33)
        let ephPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: enc)
        let zz = try recipientIK.sharedSecretFromKeyAgreement(with: ephPub).data
        let shared = try kemShared(zz: zz, enc: enc, pkR: recipientIK.publicKey.rawRepresentation)
        let keys = try sealKeys(shared: shared, aad: aad)
        return try FaradayAEAD.open(key: keys.key, nonce: keys.nonce, aad: aad, ciphertext: Data(ct))
    }

    private static func kemShared(zz: Data, enc: Data, pkR: Data) throws -> Data {
        var info = Data(FaradayKDF.infoDHKEM.utf8)
        info.append(enc)
        info.append(pkR)
        return try FaradayKDF.hkdf(ikm: zz, salt: FaradayKDF.zeros32, info: info, length: 32)
    }

    private static func sealKeys(shared: Data, aad: Data) throws -> (key: Data, nonce: Data) {
        var info = Data(FaradayKDF.infoSeal.utf8)
        info.append(aad)
        let okm = try FaradayKDF.hkdf(ikm: shared, salt: FaradayKDF.zeros32, info: info, length: 44)
        return (okm.prefix(32), okm.suffix(12))
    }
}
