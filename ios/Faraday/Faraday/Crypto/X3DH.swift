import CryptoKit
import Foundation

enum X3DH {
    static func initiatorSecret(
        ika: Curve25519.KeyAgreement.PrivateKey,
        eka: Curve25519.KeyAgreement.PrivateKey,
        ikb: Data,
        spkb: Data
    ) throws -> Data {
        let ikbPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ikb)
        let spkbPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: spkb)
        let dh1 = try ika.sharedSecretFromKeyAgreement(with: spkbPub).data
        let dh2 = try eka.sharedSecretFromKeyAgreement(with: ikbPub).data
        let dh3 = try eka.sharedSecretFromKeyAgreement(with: spkbPub).data
        return try kdf(dh1, dh2, dh3)
    }

    static func responderSecret(
        ikb: Curve25519.KeyAgreement.PrivateKey,
        spkb: Curve25519.KeyAgreement.PrivateKey,
        ika: Data,
        eka: Data
    ) throws -> Data {
        let ikaPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ika)
        let ekaPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: eka)
        let dh1 = try spkb.sharedSecretFromKeyAgreement(with: ikaPub).data
        let dh2 = try ikb.sharedSecretFromKeyAgreement(with: ekaPub).data
        let dh3 = try spkb.sharedSecretFromKeyAgreement(with: ekaPub).data
        return try kdf(dh1, dh2, dh3)
    }

    private static func kdf(_ dh1: Data, _ dh2: Data, _ dh3: Data) throws -> Data {
        var ikm = FaradayKDF.x3dhF
        ikm.append(dh1)
        ikm.append(dh2)
        ikm.append(dh3)
        return try FaradayKDF.hkdf(ikm: ikm, salt: FaradayKDF.zeros32, info: Data(FaradayKDF.infoX3DH.utf8), length: 32)
    }

    static func associatedData(initiatorIK: Data, responderIK: Data) -> Data {
        var ad = initiatorIK
        ad.append(responderIK)
        return ad
    }
}

extension SharedSecret {
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
}
