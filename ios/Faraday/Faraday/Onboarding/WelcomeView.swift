import SwiftUI

struct WelcomeView: View {
    @Environment(AppModel.self) private var model
    @State private var path = NavigationPath()

    var body: some View {
        NavigationStack(path: $path) {
            VStack(alignment: .leading, spacing: 0) {
                Spacer()
                Text("FARADAY")
                    .font(.system(size: 13, weight: .semibold, design: .monospaced))
                    .tracking(3)
                    .foregroundStyle(FaradayTheme.brass)
                Text("伺服器讀不到的訊息。")
                    .font(.system(size: 34, weight: .medium))
                    .padding(.top, 12)
                    .padding(.bottom, 28)

                fact("不需要電話號碼、電子郵件或帳號。")
                fact("金鑰在這台裝置上產生，也只留在這裡。")
                fact("中繼站只看得到封裝密文，而且對方取走後就會刪除。")

                Spacer()
                Button("建立私密身分") {
                    if let phrase = try? model.generatePhrase() {
                        path.append(phrase)
                    }
                }
                .buttonStyle(FaradayButtonStyle())
                Button("用復原助記詞還原") { path.append("restore") }
                    .buttonStyle(FaradayButtonStyle(prominent: false))
                    .padding(.top, 10)
                Text("Faraday 不會回傳使用資料。這個 App 沒有分析 SDK。")
                    .font(.footnote)
                    .foregroundStyle(FaradayTheme.muted)
                    .padding(.top, 18)
            }
            .padding(24)
            .faradayScreen()
            .navigationDestination(for: String.self) { value in
                if value == "restore" {
                    RestoreView()
                } else {
                    RecoveryPhraseView(phrase: value)
                }
            }
        }
    }

    private func fact(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "lock.fill")
                .foregroundStyle(FaradayTheme.brass)
                .frame(width: 18)
            Text(text)
                .foregroundStyle(FaradayTheme.muted)
        }
        .padding(.bottom, 12)
    }
}
