import Foundation

struct Contact: Identifiable, Codable, Hashable {
    var id: String { identityHex }
    var identityHex: String
    var mailboxHex: String
    var displayName: String
    var bundle: PublicBundleRecord
    var addedAt: Date
}

struct PublicBundleRecord: Codable, Hashable {
    var mailbox: Data
    var ikx: Data
    var iks: Data
    var spk: Data
    var spkSig: Data
    var spkID: UInt16
    var displayName: String

    func bundle() -> PublicBundle {
        PublicBundle(mailbox: mailbox, ikx: ikx, iks: iks, spk: spk, spkSig: spkSig, spkID: spkID, displayName: displayName)
    }

    static func from(_ b: PublicBundle) -> PublicBundleRecord {
        PublicBundleRecord(mailbox: b.mailbox, ikx: b.ikx, iks: b.iks, spk: b.spk, spkSig: b.spkSig, spkID: b.spkID, displayName: b.displayName)
    }
}

struct Conversation: Identifiable, Codable, Hashable {
    var id: String
    var contactID: String
    var updatedAt: Date
    var lastPreview: String
    var unreadCount: Int

    init(id: String, contactID: String, updatedAt: Date, lastPreview: String, unreadCount: Int = 0) {
        self.id = id
        self.contactID = contactID
        self.updatedAt = updatedAt
        self.lastPreview = lastPreview
        self.unreadCount = unreadCount
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        contactID = try c.decode(String.self, forKey: .contactID)
        updatedAt = try c.decode(Date.self, forKey: .updatedAt)
        lastPreview = try c.decode(String.self, forKey: .lastPreview)
        unreadCount = try c.decodeIfPresent(Int.self, forKey: .unreadCount) ?? 0
    }
}

struct LocalMessage: Identifiable, Codable, Hashable {
    var id: String
    var conversationID: String
    var outgoing: Bool
    var body: String
    var sentAt: Date
    var status: Status

    enum Status: String, Codable { case sending, sent, failed, received, read }
}

struct AppError: Identifiable {
    var id = UUID()
    var message: String
}
