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
}

struct LocalMessage: Identifiable, Codable, Hashable {
    var id: String
    var conversationID: String
    var outgoing: Bool
    var body: String
    var sentAt: Date
    var status: Status

    enum Status: String, Codable { case sending, sent, failed, received }
}

struct AppError: Identifiable {
    var id = UUID()
    var message: String
}
