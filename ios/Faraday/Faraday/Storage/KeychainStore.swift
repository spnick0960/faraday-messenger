import Foundation
import Security

enum KeychainStore {
    static let service = "app.faraday.messenger"

    static func save(_ data: Data, account: String) throws {
        try delete(account)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw FaradayStoreError.keychain(status)
        }
    }

    static func load(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        guard status == errSecSuccess else { return nil }
        return out as? Data
    }

    static func delete(_ account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw FaradayStoreError.keychain(status)
        }
    }

    static func wipeIdentity() throws {
        try delete("mnemonic")
        try delete("displayName")
    }
}

enum FaradayStoreError: Error, LocalizedError {
    case keychain(OSStatus)
    case disk

    var errorDescription: String? {
        switch self {
        case .keychain(let s): return "鑰匙圈錯誤（\(s)）。"
        case .disk: return "無法寫入本機狀態。"
        }
    }
}
