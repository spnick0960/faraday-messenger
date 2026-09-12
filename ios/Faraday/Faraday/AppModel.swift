import Foundation
import Observation

@Observable
@MainActor
final class AppModel {
    var identity: FaradayIdentity?
    var contacts: [Contact] = []
    var conversations: [Conversation] = []
    var relayURLString: String
    var isOnline = false
    var isBusy = false
    var lastError: AppError?
    var pendingPhrase: String?
    var showNotificationRationale = false
    /// Set when the user taps a local notification; InboxView consumes it to push the thread.
    var pendingOpenConversationID: String?

    /// Bumped whenever file-backed messages change so thread views re-render immediately.
    private(set) var messageEpoch = 0

    private var store: LocalStore?
    private var relay: RelayClient
    private var sessions: [String: RatchetSession] = [:]
    private var seenEnvelopeIDs = Set<String>()
    private var inboxPollTask: Task<Void, Never>?
    private var openConversationID: String?
    private var isSceneActive = true
    private let notificationDelegate = FaradayNotificationDelegate()

    init() {
        let saved = UserDefaults.standard.string(forKey: "relayURL") ?? "http://127.0.0.1:43147"
        relayURLString = saved
        relay = RelayClient(baseURL: URL(string: saved) ?? URL(string: "http://127.0.0.1:43147")!)
        store = try? LocalStore()
        if let mnemonic = KeychainStore.load(account: "mnemonic"),
           let phrase = String(data: mnemonic, encoding: .utf8) {
            let name = KeychainStore.load(account: "displayName").flatMap { String(data: $0, encoding: .utf8) } ?? ""
            identity = try? FaradayIdentity.from(mnemonic: phrase, displayName: name)
        }
        contacts = store?.contacts ?? []
        conversations = store?.conversations ?? []
        loadSessions()
        notificationDelegate.bind(self)
        LocalNotifier.setBadge(totalUnread)
    }

    var totalUnread: Int {
        conversations.reduce(0) { $0 + $1.unreadCount }
    }

    func isViewing(conversationID: String) -> Bool {
        isSceneActive && openConversationID == conversationID
    }

    var hasIdentity: Bool { identity != nil }

    func generatePhrase() throws -> String {
        var entropy = Data(count: 32)
        _ = entropy.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let phrase = try BIP39.mnemonic(fromEntropy: entropy)
        pendingPhrase = phrase
        return phrase
    }

    func finishOnboarding(displayName: String) async {
        guard let phrase = pendingPhrase else { return }
        await commitIdentity(mnemonic: phrase, displayName: displayName)
        pendingPhrase = nil
    }

    func restore(mnemonic: String, displayName: String) async {
        await commitIdentity(mnemonic: mnemonic, displayName: displayName)
    }

    private func commitIdentity(mnemonic: String, displayName: String) async {
        isBusy = true
        defer { isBusy = false }
        do {
            let id = try FaradayIdentity.from(mnemonic: mnemonic, displayName: displayName)
            try KeychainStore.save(Data(mnemonic.utf8), account: "mnemonic")
            try KeychainStore.save(Data(displayName.utf8), account: "displayName")
            identity = id
            try await relay.register(mailbox: id.mailboxHex, token: id.authHex)
            await connect()
        } catch {
            lastError = AppError(message: error.localizedDescription)
        }
    }

    func updateRelayURL(_ raw: String) async {
        relayURLString = raw
        UserDefaults.standard.set(raw, forKey: "relayURL")
        if let url = URL(string: raw) {
            await relay.setBase(url)
            await connect()
        }
    }

    func connect() async {
        guard let id = identity else { return }
        do {
            try await relay.register(mailbox: id.mailboxHex, token: id.authHex)
            await relay.connect(mailbox: id.mailboxHex, token: id.authHex) { [weak self] env in
                Task { @MainActor in
                    await self?.handle(envelope: env)
                }
            }
            isOnline = true
            startInboxPolling()
            await refreshInbox(reportError: false)
            await considerNotificationPermission()
        } catch {
            isOnline = false
            lastError = AppError(message: error.localizedDescription)
            // HTTP register failed — still poll so a later relay recovery is picked up.
            startInboxPolling()
            await considerNotificationPermission()
        }
    }

    func considerNotificationPermission() async {
        guard identity != nil else { return }
        let explainedKey = "didExplainLocalNotifications"
        let status = await LocalNotifier.authorizationStatus()
        if status == .notDetermined, !UserDefaults.standard.bool(forKey: explainedKey) {
            UserDefaults.standard.set(true, forKey: explainedKey)
            showNotificationRationale = true
            return
        }
        if status == .notDetermined {
            await LocalNotifier.requestPermission()
        }
    }

    func requestNotificationPermission() async {
        await LocalNotifier.requestPermission()
    }

    func setSceneActive(_ active: Bool) {
        isSceneActive = active
        if active, let id = openConversationID {
            clearUnread(conversationID: id)
        }
    }

    func openThread(_ conversation: Conversation) {
        openConversationID = conversation.id
        clearUnread(conversationID: conversation.id)
    }

    func closeThread(_ conversation: Conversation) {
        if openConversationID == conversation.id {
            openConversationID = nil
        }
    }

    func openFromNotification(conversationID: String) {
        pendingOpenConversationID = conversationID
        openConversationID = conversationID
        clearUnread(conversationID: conversationID)
    }

    func consumePendingOpen() {
        pendingOpenConversationID = nil
    }

    func conversation(id: String) -> Conversation? {
        conversations.first { $0.id == id }
    }

    func refreshInbox() async {
        await refreshInbox(reportError: true)
    }

    private func refreshInbox(reportError: Bool) async {
        guard let id = identity else { return }
        do {
            let items = try await relay.inbox(mailbox: id.mailboxHex, token: id.authHex)
            isOnline = true
            for item in items {
                await handle(envelope: item)
            }
        } catch {
            isOnline = false
            if reportError {
                lastError = AppError(message: error.localizedDescription)
            }
            // Register is idempotent. Retry so a relay that was down at launch
            // can start accepting inbox fetches without a manual refresh.
            try? await relay.register(mailbox: id.mailboxHex, token: id.authHex)
        }
    }

    private func startInboxPolling() {
        inboxPollTask?.cancel()
        inboxPollTask = Task { [weak self] in
            await self?.inboxPollLoop()
        }
    }

    private func inboxPollLoop() async {
        // HTTP inbox is the reliable path when the Cloudflare WS tunnel drops.
        // Keep this under a couple of seconds so pending envelopes do not sit forever.
        while !Task.isCancelled {
            do {
                try await Task.sleep(for: .seconds(1.5))
            } catch {
                return
            }
            guard !Task.isCancelled else { return }
            await refreshInbox(reportError: false)
        }
    }

    private func stopInboxPolling() {
        inboxPollTask?.cancel()
        inboxPollTask = nil
    }

    func addContact(fromInvite string: String) throws -> Contact {
        let bundle = try FaradayInvite.decode(string)
        let contact = upsert(bundle: bundle)
        return contact
    }

    func myInvite() throws -> String {
        guard let id = identity else { throw FaradayCryptoError.session }
        return try FaradayInvite.encode(id.publicBundle)
    }

    func send(to contact: Contact, body: String) async {
        guard let id = identity else { return }
        let trimmed = body.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let conversation = upsertConversation(contactID: contact.identityHex, preview: trimmed)
        let local = LocalMessage(
            id: UUID().uuidString,
            conversationID: conversation.id,
            outgoing: true,
            body: trimmed,
            sentAt: Date(),
            status: .sending
        )
        append(local)
        // Yield so SwiftUI can paint the optimistic bubble before crypto blocks the main actor.
        await Task.yield()
        do {
            let existing = sessions[contact.identityHex]
            let result = try DeviceCrypto.encrypt(
                self: id,
                peer: contact.bundle.bundle(),
                session: existing,
                body: trimmed
            )
            sessions[contact.identityHex] = result.session
            persistSession(result.session, key: contact.identityHex)
            try await relay.drop(to: contact.mailboxHex, blob: result.blob)
            update(messageID: local.id, conversationID: conversation.id) { $0.status = .sent }
        } catch {
            update(messageID: local.id, conversationID: conversation.id) { $0.status = .failed }
            lastError = AppError(message: error.localizedDescription)
        }
    }

    func messages(for conversation: Conversation) -> [LocalMessage] {
        _ = messageEpoch
        return store?.messages(in: conversation.id) ?? []
    }

    func contact(for conversation: Conversation) -> Contact? {
        contacts.first { $0.identityHex == conversation.contactID }
    }

    func destroyIdentity() async {
        stopInboxPolling()
        await relay.disconnect()
        LocalNotifier.clearAll()
        try? KeychainStore.wipeIdentity()
        store?.wipe()
        identity = nil
        contacts = []
        conversations = []
        sessions = [:]
        seenEnvelopeIDs = []
        pendingPhrase = nil
        pendingOpenConversationID = nil
        openConversationID = nil
        showNotificationRationale = false
    }

    private func handle(envelope: InboxEnvelope) async {
        guard let id = identity else { return }
        if seenEnvelopeIDs.contains(envelope.id) {
            // Already on this device — tell the relay to drop the RAM copy.
            try? await relay.ack(mailbox: id.mailboxHex, token: id.authHex, ids: [envelope.id])
            return
        }
        seenEnvelopeIDs.insert(envelope.id)
        guard let blob = Data(base64Encoded: envelope.blob) else { return }
        do {
            let result = try DeviceCrypto.decrypt(self: id, sessions: sessions, blob: blob)
            let peerBundle = result.peer ?? inferredBundle(from: result.session)
            guard let peerBundle else {
                lastError = AppError(message: "已解密來自未知寄件者的訊息，仍留在中繼站。")
                seenEnvelopeIDs.remove(envelope.id)
                return
            }
            let contact = upsert(bundle: peerBundle)
            sessions[contact.identityHex] = result.session
            persistSession(result.session, key: contact.identityHex)
            let conversation = upsertConversation(contactID: contact.identityHex, preview: result.payload.body)
            let msg = LocalMessage(
                id: result.payload.id,
                conversationID: conversation.id,
                outgoing: false,
                body: result.payload.body,
                sentAt: Date(timeIntervalSince1970: TimeInterval(result.payload.ts)),
                status: .received
            )
            let wasNew = append(msg)
            if wasNew, !isViewing(conversationID: conversation.id) {
                incrementUnread(conversationID: conversation.id)
                LocalNotifier.postNewMessage(
                    conversationID: conversation.id,
                    senderName: contact.displayName
                )
            }
            // Successful delivery: persist locally first, then delete on the relay.
            try? await relay.ack(mailbox: id.mailboxHex, token: id.authHex, ids: [envelope.id])
        } catch {
            seenEnvelopeIDs.remove(envelope.id)
            lastError = AppError(message: "無法解密封裝。已留在中繼站以便重試。")
        }
    }

    private func inferredBundle(from session: RatchetSession) -> PublicBundle? {
        contacts.first { $0.identityHex == session.peerIK.hex }?.bundle.bundle()
    }

    @discardableResult
    private func upsert(bundle: PublicBundle) -> Contact {
        let hex = bundle.ikx.hex
        if let idx = contacts.firstIndex(where: { $0.identityHex == hex }) {
            contacts[idx].displayName = bundle.displayName.isEmpty ? contacts[idx].displayName : bundle.displayName
            contacts[idx].mailboxHex = bundle.mailboxHex
            contacts[idx].bundle = .from(bundle)
            store?.contacts = contacts
            return contacts[idx]
        }
        let contact = Contact(
            identityHex: hex,
            mailboxHex: bundle.mailboxHex,
            displayName: bundle.displayName.isEmpty ? "聯絡人 · \(bundle.mailboxHex.suffix(4))" : bundle.displayName,
            bundle: .from(bundle),
            addedAt: Date()
        )
        contacts.insert(contact, at: 0)
        store?.contacts = contacts
        _ = upsertConversation(contactID: hex, preview: "已接受邀請。訊息只留在這台裝置。")
        return contact
    }

    @discardableResult
    private func upsertConversation(contactID: String, preview: String) -> Conversation {
        if let idx = conversations.firstIndex(where: { $0.contactID == contactID }) {
            conversations[idx].updatedAt = Date()
            conversations[idx].lastPreview = preview
            conversations.sort { $0.updatedAt > $1.updatedAt }
            persistConversationList()
            return conversations[idx]
        }
        let c = Conversation(id: contactID, contactID: contactID, updatedAt: Date(), lastPreview: preview)
        conversations.insert(c, at: 0)
        persistConversationList()
        return c
    }

    @discardableResult
    private func append(_ message: LocalMessage) -> Bool {
        var list = store?.messages(in: message.conversationID) ?? []
        if list.contains(where: { $0.id == message.id }) { return false }
        list.append(message)
        store?.save(messages: list, in: message.conversationID)
        objectNotify()
        return true
    }

    private func incrementUnread(conversationID: String) {
        guard let idx = conversations.firstIndex(where: { $0.id == conversationID }) else { return }
        conversations[idx].unreadCount += 1
        persistConversationList()
    }

    private func clearUnread(conversationID: String) {
        LocalNotifier.clearThread(conversationID)
        guard let idx = conversations.firstIndex(where: { $0.id == conversationID }) else { return }
        guard conversations[idx].unreadCount != 0 else { return }
        conversations[idx].unreadCount = 0
        persistConversationList()
    }

    private func persistConversationList() {
        store?.conversations = conversations
        LocalNotifier.setBadge(totalUnread)
    }

    private func update(messageID: String, conversationID: String, mutate: (inout LocalMessage) -> Void) {
        var list = store?.messages(in: conversationID) ?? []
        if let idx = list.firstIndex(where: { $0.id == messageID }) {
            mutate(&list[idx])
            store?.save(messages: list, in: conversationID)
            objectNotify()
        }
    }

    private func persistSession(_ session: RatchetSession, key: String) {
        store?.save(session: session.exportState(), for: key)
    }

    private func loadSessions() {
        for contact in contacts {
            if let st = store?.session(for: contact.identityHex),
               let sess = try? RatchetSession.importState(st) {
                sessions[contact.identityHex] = sess
            }
        }
    }

    private func objectNotify() {
        // File-backed messages are not stored on an @Observable property.
        // Bump an epoch so thread views that call messages(for:) re-render immediately.
        messageEpoch += 1
        conversations = conversations
    }
}
