import Foundation
import UserNotifications

/// Device-local banners only. Never talks to APNs or the relay.
enum LocalNotifier {
    static let conversationKey = "conversationID"
    static let genericBody = "你有一則新訊息"

    static func authorizationStatus() async -> UNAuthorizationStatus {
        await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
    }

    static func requestPermission() async {
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()
        guard settings.authorizationStatus == .notDetermined else { return }
        _ = try? await center.requestAuthorization(options: [.alert, .sound, .badge])
    }

    /// Title is the on-device display name. Body is a fixed line — never the message plaintext.
    static func postNewMessage(conversationID: String, senderName: String) {
        let content = UNMutableNotificationContent()
        content.title = senderName
        content.body = genericBody
        content.sound = .default
        content.userInfo = [conversationKey: conversationID]
        content.threadIdentifier = conversationID
        let request = UNNotificationRequest(identifier: conversationID, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    static func clearThread(_ conversationID: String) {
        let center = UNUserNotificationCenter.current()
        center.removeDeliveredNotifications(withIdentifiers: [conversationID])
        center.removePendingNotificationRequests(withIdentifiers: [conversationID])
    }

    static func setBadge(_ count: Int) {
        Task {
            try? await UNUserNotificationCenter.current().setBadgeCount(count)
        }
    }

    static func clearAll() {
        let center = UNUserNotificationCenter.current()
        center.removeAllDeliveredNotifications()
        center.removeAllPendingNotificationRequests()
        setBadge(0)
    }
}

@MainActor
final class FaradayNotificationDelegate: NSObject, UNUserNotificationCenterDelegate {
    weak var model: AppModel?

    func bind(_ model: AppModel) {
        self.model = model
        UNUserNotificationCenter.current().delegate = self
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        let id = notification.request.content.userInfo[LocalNotifier.conversationKey] as? String
        if let id, model?.isViewing(conversationID: id) == true {
            return []
        }
        return [.banner, .sound, .badge, .list]
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse
    ) async {
        guard let id = response.notification.request.content.userInfo[LocalNotifier.conversationKey] as? String else {
            return
        }
        model?.openFromNotification(conversationID: id)
    }
}
