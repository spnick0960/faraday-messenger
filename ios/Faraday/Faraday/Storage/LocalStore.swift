import Foundation

final class LocalStore {
    private let dir: URL
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init() throws {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        dir = base.appendingPathComponent("Faraday", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: dir.path)
        encoder.outputFormatting = [.sortedKeys]
        decoder.dateDecodingStrategy = .iso8601
        encoder.dateEncodingStrategy = .iso8601
    }

    var contacts: [Contact] {
        get { read("contacts.json") ?? [] }
        set { write(newValue, to: "contacts.json") }
    }

    var conversations: [Conversation] {
        get { read("conversations.json") ?? [] }
        set { write(newValue, to: "conversations.json") }
    }

    func messages(in conversationID: String) -> [LocalMessage] {
        read("messages-\(conversationID).json") ?? []
    }

    func save(messages: [LocalMessage], in conversationID: String) {
        write(messages, to: "messages-\(conversationID).json")
    }

    func session(for identityHex: String) -> SessionState? {
        read("session-\(identityHex).json")
    }

    func save(session: SessionState, for identityHex: String) {
        write(session, to: "session-\(identityHex).json")
    }

    func wipe() {
        try? FileManager.default.removeItem(at: dir)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    private func read<T: Decodable>(_ name: String) -> T? {
        let url = dir.appendingPathComponent(name)
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? decoder.decode(T.self, from: data)
    }

    private func write<T: Encodable>(_ value: T, to name: String) {
        let url = dir.appendingPathComponent(name)
        guard let data = try? encoder.encode(value) else { return }
        try? data.write(to: url, options: [.atomic, .completeFileProtection])
    }
}
