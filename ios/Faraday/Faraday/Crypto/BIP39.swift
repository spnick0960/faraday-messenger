import CommonCrypto
import CryptoKit
import Foundation

enum BIP39 {
    static func wordlist() throws -> [String] {
        guard let url = Bundle.main.url(forResource: "bip39-english", withExtension: "txt") else {
            throw FaradayCryptoError.wordlist
        }
        let text = try String(contentsOf: url, encoding: .utf8)
        let words = text.split(whereSeparator: \.isNewline).map(String.init)
        guard words.count == 2048 else { throw FaradayCryptoError.wordlist }
        return words
    }

    static func mnemonic(fromEntropy entropy: Data) throws -> String {
        guard entropy.count == 32 else { throw FaradayCryptoError.phrase }
        let words = try wordlist()
        let hash = SHA256.hash(data: entropy)
        var bits = entropy
        bits.append(hash[0])
        var out: [String] = []
        for i in 0..<24 {
            out.append(words[elevenBits(bits, offset: i * 11)])
        }
        return out.joined(separator: " ")
    }

    static func seed(fromMnemonic mnemonic: String) throws -> Data {
        let words = try normalize(mnemonic)
        try validate(words)
        return pbkdf2SHA512(password: Data(words.joined(separator: " ").utf8), salt: Data("mnemonic".utf8))
    }

    static func normalize(_ mnemonic: String) throws -> [String] {
        let words = mnemonic.lowercased().split(whereSeparator: \.isWhitespace).map(String.init)
        guard words.count == 24 else { throw FaradayCryptoError.phrase }
        return words
    }

    static func validate(_ words: [String]) throws {
        let list = try wordlist()
        let index = Dictionary(uniqueKeysWithValues: list.enumerated().map { ($1, $0) })
        var acc = 0
        var nbits = 0
        var buf = Data()
        for w in words {
            guard let idx = index[w] else { throw FaradayCryptoError.phrase }
            acc = (acc << 11) | idx
            nbits += 11
            while nbits >= 8 {
                nbits -= 8
                buf.append(UInt8((acc >> nbits) & 0xFF))
                acc &= (1 << nbits) - 1
            }
        }
        guard buf.count == 33 else { throw FaradayCryptoError.phrase }
        let entropy = buf.prefix(32)
        let cs = SHA256.hash(data: entropy)
        guard buf[32] == cs[0] else { throw FaradayCryptoError.phrase }
    }

    private static func elevenBits(_ data: Data, offset: Int) -> Int {
        var v = 0
        for i in 0..<11 {
            let byteI = (offset + i) / 8
            let bitI = 7 - ((offset + i) % 8)
            v <<= 1
            if data[byteI] & (1 << bitI) != 0 { v |= 1 }
        }
        return v
    }

    private static func pbkdf2SHA512(password: Data, salt: Data) -> Data {
        var out = Data(count: 64)
        out.withUnsafeMutableBytes { outBuf in
            password.withUnsafeBytes { passBuf in
                salt.withUnsafeBytes { saltBuf in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passBuf.baseAddress?.assumingMemoryBound(to: CChar.self),
                        password.count,
                        saltBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                        2048,
                        outBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        64
                    )
                }
            }
        }
        return out
    }
}
