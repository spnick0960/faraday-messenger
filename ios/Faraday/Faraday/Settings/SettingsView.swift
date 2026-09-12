import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var relay: String = ""
    @State private var confirmDestroy = false

    var body: some View {
        List {
            Section {
                if let id = model.identity {
                    LabeledContent("指紋", value: id.fingerprint)
                    LabeledContent("信箱", value: "••\(id.mailboxHex.suffix(4))")
                    LabeledContent("名稱", value: id.displayName.isEmpty ? "未設定" : id.displayName)
                }
                Text("金鑰存在 iOS 鑰匙圈，屬性為「首次解鎖後、僅限本機」。不會同步到 iCloud。安全隔離區不支援 X25519，因此身分交換金鑰受鑰匙圈保護，並非隔離區綁定。")
                    .font(.footnote)
                    .foregroundStyle(FaradayTheme.muted)
            } header: {
                Text("身分")
            }

            Section {
                TextField("中繼站網址", text: $relay)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                Button("儲存中繼站網址") {
                    Task { await model.updateRelayURL(relay) }
                }
                Text("預設是本機 Faraday 中繼站。該主機的操作者看得到信箱 ID、時間、大小與 IP，看不到訊息本文。")
                    .font(.footnote)
                    .foregroundStyle(FaradayTheme.muted)
            } header: {
                Text("中繼站")
            }

            Section {
                NavigationLink("伺服器看得到／看不到什麼") {
                    ThreatModelView()
                }
            }

            Section {
                Text("若本機棘輪與對方不同步，無法解密的封裝會被取走並丟棄，該聯絡人的會話會清掉。請再傳一則訊息：會用你已存的邀請公鑰重新做 X3DH，不必刪除聯絡人或再貼邀請。舊密文無法復原。中繼站仍然只看得到密文。")
                    .font(.footnote)
                    .foregroundStyle(FaradayTheme.muted)
            } header: {
                Text("會話重設")
            }

            Section {
                Text("打開一對一對話時，Faraday 會再封裝一筆已讀回條給對方。中繼站只看得到另一個密文。群組已讀尚未實作。")
                    .font(.footnote)
                    .foregroundStyle(FaradayTheme.muted)
            } header: {
                Text("已讀回條")
            }

            Section {
                Text("本機通知只在這台裝置上顯示。標題是你已儲存的聯絡人名稱，內容固定為「你有一則新訊息」，不會把訊息本文交給 Apple 或中繼站。App 被系統完全殺掉之後就收不到通知——那需要 APNs，目前尚未接上。")
                    .font(.footnote)
                    .foregroundStyle(FaradayTheme.muted)
            } header: {
                Text("本機通知")
            }

            Section {
                Button("銷毀這台裝置上的身分", role: .destructive) {
                    confirmDestroy = true
                }
            } footer: {
                Text("會刪除鑰匙圈中的金鑰與本機紀錄。助記詞是唯一回來的方法。中繼站上等待的封裝密文只存在記憶體，若 48 小時內沒人取走就會消失。")
            }
        }
        .scrollContentBackground(.hidden)
        .faradayScreen()
        .navigationTitle("設定")
        .onAppear { relay = model.relayURLString }
        .confirmationDialog("要銷毀這個身分嗎？", isPresented: $confirmDestroy, titleVisibility: .visible) {
            Button("銷毀身分", role: .destructive) {
                Task { await model.destroyIdentity() }
            }
        } message: {
            Text("沒有助記詞就無法復原。這台裝置上的聊天紀錄會被清除。")
        }
    }
}
