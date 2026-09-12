import CryptoKit
import Foundation

struct PublicBundle: Equatable {
    var mailbox: Data
    var ikx: Data
    var iks: Data
    var spk: Data
    var spkSig: Data
    var spkID: UInt16
    var displayName: String

    func verify() throws {
        guard mailbox.count == 16, ikx.count == 32, iks.count == 32, spk.count == 32, spkSig.count == 64 else {
            throw FaradayCryptoError.invite
        }
        var msg = Data(FaradayKDF.infoSPK.utf8)
        msg.append(spk)
        var spkIDBytes = Data(count: 2)
        spkIDBytes.withUnsafeMutableBytes { $0.storeBytes(of: spkID.bigEndian, as: UInt16.self) }
        msg.append(spkIDBytes)
        let pub = try Curve25519.Signing.PublicKey(rawRepresentation: iks)
        guard pub.isValidSignature(spkSig, for: msg) else {
            throw FaradayCryptoError.signature
        }
    }

    var mailboxHex: String { mailbox.hex }
    var fingerprint: String {
        let hex = SHA256.hash(data: ikx).map { String(format: "%02x", $0) }.joined()
        return String(hex.prefix(16))
    }
}

struct FaradayIdentity {
    var mnemonic: String
    var ikx: Curve25519.KeyAgreement.PrivateKey
    var iks: Curve25519.Signing.PrivateKey
    var spk: Curve25519.KeyAgreement.PrivateKey
    var mailbox: Data
    var authToken: Data
    var displayName: String

    var mailboxHex: String { mailbox.hex }
    var authHex: String { authToken.hex }
    var fingerprint: String { publicBundle.fingerprint }

    static func generate(displayName: String) throws -> FaradayIdentity {
        var entropy = Data(count: 32)
        _ = entropy.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        return try from(mnemonic: try BIP39.mnemonic(fromEntropy: entropy), displayName: displayName)
    }

    static func from(mnemonic: String, displayName: String) throws -> FaradayIdentity {
        let seed = try BIP39.seed(fromMnemonic: mnemonic)
        let salt = Data(FaradayKDF.infoRoot.utf8)
        let ikxB = try FaradayKDF.hkdf(ikm: seed, salt: salt, info: Data(FaradayKDF.infoIKX.utf8), length: 32)
        let iksB = try FaradayKDF.hkdf(ikm: seed, salt: salt, info: Data(FaradayKDF.infoIKS.utf8), length: 32)
        let spkB = try FaradayKDF.hkdf(ikm: seed, salt: salt, info: Data(FaradayKDF.infoSPKPriv.utf8), length: 32)
        let mb = try FaradayKDF.hkdf(ikm: seed, salt: salt, info: Data(FaradayKDF.infoMailbox.utf8), length: 16)
        let auth = try FaradayKDF.hkdf(ikm: seed, salt: salt, info: Data(FaradayKDF.infoAuth.utf8), length: 32)
        return FaradayIdentity(
            mnemonic: mnemonic,
            ikx: try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ikxB),
            iks: try Curve25519.Signing.PrivateKey(rawRepresentation: iksB),
            spk: try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: spkB),
            mailbox: mb,
            authToken: auth,
            displayName: displayName
        )
    }

    var publicBundle: PublicBundle {
        var msg = Data(FaradayKDF.infoSPK.utf8)
        msg.append(spk.publicKey.rawRepresentation)
        var spkIDBytes = Data(count: 2)
        spkIDBytes.withUnsafeMutableBytes { $0.storeBytes(of: FaradayKDF.spkID.bigEndian, as: UInt16.self) }
        msg.append(spkIDBytes)
        let sig = iks.signature(for: msg)
        return PublicBundle(
            mailbox: mailbox,
            ikx: ikx.publicKey.rawRepresentation,
            iks: iks.publicKey.rawRepresentation,
            spk: spk.publicKey.rawRepresentation,
            spkSig: sig,
            spkID: FaradayKDF.spkID,
            displayName: displayName
        )
    }

    func card() -> ContactCard {
        let b = publicBundle
        return ContactCard(mb: mailboxHex, ik: b.ikx, iks: b.iks, spk: b.spk, sig: b.spkSig, name: displayName)
    }
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }

    static func fromHex(_ hex: String) -> Data? {
        var hex = hex
        if hex.count % 2 != 0 { return nil }
        var data = Data()
        while !hex.isEmpty {
            let pair = hex.prefix(2)
            hex.removeFirst(2)
            guard let b = UInt8(pair, radix: 16) else { return nil }
            data.append(b)
        }
        return data
    }
}
