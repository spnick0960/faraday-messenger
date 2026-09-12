import SwiftUI

struct RecoveryPhraseView: View {
    let phrase: String
    @State private var revealed = false

    var words: [String] { phrase.split(separator: " ").map(String.init) }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("請把這 24 個詞抄下來。")
                .font(.title2.weight(.medium))
            Text("這是復原金鑰的唯一方法。Faraday 看不到這些詞，也不會進 iCloud 備份。")
                .foregroundStyle(FaradayTheme.muted)

            ScrollView {
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                    ForEach(Array(words.enumerated()), id: \.offset) { i, w in
                        HStack(spacing: 6) {
                            Text("\(i + 1).")
                                .foregroundStyle(FaradayTheme.muted)
                                .font(.caption.monospaced())
                            Text(revealed ? w : "••••")
                                .font(.callout.monospaced())
                            Spacer(minLength: 0)
                        }
                        .padding(8)
                        .background(FaradayTheme.surface)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }
            }

            Toggle("顯示詞彙", isOn: $revealed)
                .tint(FaradayTheme.brass)
            NavigationLink("我已經抄好了") {
                ConfirmPhraseView(phrase: phrase)
            }
            .buttonStyle(FaradayButtonStyle())
        }
        .padding(24)
        .faradayScreen()
        .navigationTitle("復原助記詞")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct ConfirmPhraseView: View {
    let phrase: String
    @State private var checks: [Int] = []
    @State private var answers: [String] = ["", "", ""]
    @State private var error: String?

    var words: [String] { phrase.split(separator: " ").map(String.init) }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("確認其中三個詞")
                .font(.title2.weight(.medium))
            Text("確認助記詞已寫在紙上，而不只留在螢幕上。")
                .foregroundStyle(FaradayTheme.muted)
            ForEach(Array(checks.enumerated()), id: \.offset) { i, idx in
                VStack(alignment: .leading, spacing: 6) {
                    Text("第 \(idx + 1) 個詞")
                        .font(.caption)
                        .foregroundStyle(FaradayTheme.muted)
                    TextField("請輸入", text: $answers[i])
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .padding(12)
                        .background(FaradayTheme.surface)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                }
            }
            if let error { Text(error).foregroundStyle(FaradayTheme.bad) }
            NavigationLink("繼續") {
                DisplayNameView(mode: .create)
            }
            .buttonStyle(FaradayButtonStyle())
            .disabled(!matches)
            .opacity(matches ? 1 : 0.5)
            Spacer()
        }
        .padding(24)
        .faradayScreen()
        .onAppear {
            if checks.isEmpty {
                checks = Array(0..<24).shuffled().prefix(3).sorted()
            }
        }
    }

    private var matches: Bool {
        zip(checks, answers).allSatisfy { words[$0].lowercased() == $1.lowercased().trimmingCharacters(in: .whitespaces) }
    }
}

struct DisplayNameView: View {
    enum Mode { case create, restore }
    var mode: Mode
    var mnemonic: String = ""
    @Environment(AppModel.self) private var model
    @State private var name = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("聯絡人要怎麼稱呼你？")
                .font(.title2.weight(.medium))
            Text("只會出現在邀請裡，而且在密文中。中繼站不會存這個名字。")
                .foregroundStyle(FaradayTheme.muted)
            TextField("顯示名稱（選填）", text: $name)
                .padding(12)
                .background(FaradayTheme.surface)
                .clipShape(RoundedRectangle(cornerRadius: 10))
            Button(model.isBusy ? "正在產生金鑰…" : "完成") {
                Task {
                    if mode == .restore {
                        await model.restore(mnemonic: mnemonic, displayName: name)
                    } else {
                        await model.finishOnboarding(displayName: name)
                    }
                }
            }
            .buttonStyle(FaradayButtonStyle())
            .disabled(model.isBusy)
            Spacer()
        }
        .padding(24)
        .faradayScreen()
        .navigationTitle("名稱")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct RestoreView: View {
    @State private var phrase = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("還原身分")
                .font(.title2.weight(.medium))
            Text("貼上你的 24 詞助記詞。其他裝置上的聊天紀錄與會話狀態不會回來，只會還原金鑰與信箱。")
                .foregroundStyle(FaradayTheme.muted)
            TextEditor(text: $phrase)
                .scrollContentBackground(.hidden)
                .frame(minHeight: 160)
                .padding(8)
                .background(FaradayTheme.surface)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            if let error { Text(error).foregroundStyle(FaradayTheme.bad) }
            if valid {
                NavigationLink("繼續") {
                    DisplayNameView(mode: .restore, mnemonic: phrase)
                }
                .buttonStyle(FaradayButtonStyle())
            } else {
                Button("繼續") {
                    error = "助記詞檢查碼不符。必須是原本的 24 個詞。"
                }
                .buttonStyle(FaradayButtonStyle())
            }
            Spacer()
        }
        .padding(24)
        .faradayScreen()
    }

    private var valid: Bool {
        (try? BIP39.seed(fromMnemonic: phrase)) != nil
    }
}
