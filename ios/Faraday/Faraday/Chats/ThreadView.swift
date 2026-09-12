import SwiftUI

struct ThreadView: View {
    @Environment(AppModel.self) private var model
    let conversation: Conversation
    @State private var draft = ""

    var contact: Contact? { model.contact(for: conversation) }
    var messages: [LocalMessage] { model.messages(for: conversation) }

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 10) {
                        Text("端對端加密。中繼站只在記憶體暫存封裝密文，這台裝置取走後就會刪除。")
                            .font(.caption)
                            .foregroundStyle(FaradayTheme.muted)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                        ForEach(messages) { msg in
                            bubble(msg)
                                .id(msg.id)
                        }
                    }
                    .padding(16)
                }
                .onChange(of: messages.count) { _, _ in
                    if let last = messages.last { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
            composer
        }
        .faradayScreen()
        .navigationTitle(contact?.displayName ?? "對話")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { model.openThread(conversation) }
        .onDisappear { model.closeThread(conversation) }
    }

    private func bubble(_ msg: LocalMessage) -> some View {
        HStack {
            if msg.outgoing { Spacer(minLength: 48) }
            VStack(alignment: msg.outgoing ? .trailing : .leading, spacing: 4) {
                Text(msg.body)
                    .padding(12)
                    .background(msg.outgoing ? FaradayTheme.brass : FaradayTheme.elevated)
                    .foregroundStyle(msg.outgoing ? FaradayTheme.bg : FaradayTheme.text)
                    .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                if msg.id == model.readWatermarkID(for: conversation) {
                    readChip
                } else {
                    Text(statusLine(msg))
                        .font(.caption2)
                        .foregroundStyle(FaradayTheme.muted)
                }
            }
            if !msg.outgoing { Spacer(minLength: 48) }
        }
    }

    /// Brass watermark on the last outgoing message the peer has opened — not a grey per-bubble 已讀.
    private var readChip: some View {
        HStack(spacing: 3) {
            Image(systemName: "checkmark")
            Image(systemName: "checkmark")
                .padding(.leading, -6)
            Text("已讀")
        }
        .font(.caption2.weight(.semibold))
        .foregroundStyle(FaradayTheme.brass)
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(FaradayTheme.brass.opacity(0.14))
        .overlay(
            Capsule().stroke(FaradayTheme.brass.opacity(0.5), lineWidth: 1)
        )
        .clipShape(Capsule())
        .accessibilityLabel("對方已讀")
    }

    private func statusLine(_ msg: LocalMessage) -> String {
        switch msg.status {
        case .sending: return "加密中…"
        case .sent: return "已封裝並送出"
        case .failed: return "無法連上中繼站"
        case .received: return msg.sentAt.formatted(date: .omitted, time: .shortened)
        case .read: return msg.sentAt.formatted(date: .omitted, time: .shortened)
        }
    }

    private var composer: some View {
        HStack(spacing: 10) {
            TextField("訊息", text: $draft, axis: .vertical)
                .lineLimit(1...5)
                .padding(12)
                .background(FaradayTheme.surface)
                .clipShape(RoundedRectangle(cornerRadius: 16))
            Button {
                let text = draft
                draft = ""
                if let contact {
                    Task { await model.send(to: contact, body: text) }
                }
            } label: {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.system(size: 32))
                    .foregroundStyle(FaradayTheme.brass)
            }
            .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || contact == nil)
        }
        .padding(12)
        .background(FaradayTheme.bg)
    }
}
