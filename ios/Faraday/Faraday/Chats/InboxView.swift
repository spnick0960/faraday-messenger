import SwiftUI

struct InboxView: View {
    @Environment(AppModel.self) private var model
    @State private var path: [Conversation] = []

    var body: some View {
        NavigationStack(path: $path) {
            Group {
                if model.conversations.isEmpty {
                    empty
                } else {
                    List(model.conversations) { convo in
                        NavigationLink(value: convo) {
                            row(convo)
                        }
                        .listRowBackground(FaradayTheme.surface)
                    }
                    .listStyle(.plain)
                    .scrollContentBackground(.hidden)
                }
            }
            .faradayScreen()
            .navigationTitle("Faraday")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Circle()
                        .fill(model.isOnline ? FaradayTheme.good : FaradayTheme.muted)
                        .frame(width: 8, height: 8)
                        .accessibilityLabel(model.isOnline ? "已連上中繼站" : "中繼站離線")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink {
                        MyInviteView()
                    } label: {
                        Image(systemName: "qrcode")
                    }
                    .tint(FaradayTheme.brass)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink {
                        AddContactView()
                    } label: {
                        Image(systemName: "plus")
                    }
                    .tint(FaradayTheme.brass)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink {
                        SettingsView()
                    } label: {
                        Image(systemName: "gearshape")
                    }
                    .tint(FaradayTheme.brass)
                }
            }
            .navigationDestination(for: Conversation.self) { convo in
                ThreadView(conversation: convo)
            }
            .refreshable { await model.refreshInbox() }
        }
        .task { await model.connect() }
        .onChange(of: model.pendingOpenConversationID) { _, id in
            openPending(id)
        }
        .onChange(of: model.conversations) { _, _ in
            openPending(model.pendingOpenConversationID)
        }
        .alert("本機通知", isPresented: Binding(
            get: { model.showNotificationRationale },
            set: { model.showNotificationRationale = $0 }
        )) {
            Button("允許通知") {
                Task { await model.requestNotificationPermission() }
            }
            Button("稍後", role: .cancel) {}
        } message: {
            Text("有新訊息且你不在該對話時，Faraday 會在這台裝置顯示通知。標題是聯絡人名稱，內容固定為「你有一則新訊息」。訊息本文不會送給 Apple 或中繼站。")
        }
    }

    private func openPending(_ id: String?) {
        guard let id, let convo = model.conversation(id: id) else { return }
        path = [convo]
        model.consumePendingOpen()
    }

    private var empty: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.rectangle.stack")
                .font(.system(size: 44))
                .foregroundStyle(FaradayTheme.brass)
            Text("還沒有對話")
                .font(.title3.weight(.medium))
            Text("用你的 QR Code 邀請對方。Faraday 不會讀通訊錄。對方取走訊息後，內容只留在你們兩台裝置上，不會留在中繼站。")
                .multilineTextAlignment(.center)
                .foregroundStyle(FaradayTheme.muted)
                .padding(.horizontal, 28)
            NavigationLink("顯示我的邀請") { MyInviteView() }
                .buttonStyle(FaradayButtonStyle())
                .padding(.horizontal, 24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func row(_ convo: Conversation) -> some View {
        let contact = model.contact(for: convo)
        let unread = convo.unreadCount
        return HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(contact?.displayName ?? "未知")
                        .font(.headline)
                        .fontWeight(unread > 0 ? .semibold : .regular)
                    Spacer()
                    Text(convo.updatedAt, style: .time)
                        .font(.caption)
                        .foregroundStyle(FaradayTheme.muted)
                }
                Text(convo.lastPreview)
                    .font(.subheadline)
                    .foregroundStyle(FaradayTheme.muted)
                    .lineLimit(1)
            }
            if unread > 0 {
                Text(unread > 99 ? "99+" : "\(unread)")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(FaradayTheme.bg)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3)
                    .background(FaradayTheme.bad)
                    .clipShape(Capsule())
                    .accessibilityLabel("\(unread) 則未讀")
            }
        }
        .padding(.vertical, 4)
    }
}
