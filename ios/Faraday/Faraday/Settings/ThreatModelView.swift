import SwiftUI

struct ThreatModelView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                block(
                    title: "我們防的是誰",
                    body: "好奇的中繼站操作者、日後被拷走的中繼站磁碟，以及能看見兩個 IP 交換了特定大小封包的網路觀察者。我們不宣稱能防被入侵或未上鎖的 iPhone、裝置上的惡意軟體，或能脅迫你聊天對象的國家級對手。"
                )
                block(
                    title: "伺服器看不到",
                    body: "訊息明文。顯示名稱（走在密文裡）。復原助記詞。私鑰。聯絡人清單。封裝信封的寄件者。棘輪狀態。長期郵件封存——已送達的密文會立刻刪除，未送達的也從不寫進磁碟。"
                )
                block(
                    title: "伺服器仍看得到",
                    body: "信箱 X 目前是否有一筆密文在記憶體等待、其填充後大小、以及到達時間。投下或取走郵件的 TCP/IP 位址。用戶端是否握著 WebSocket（粗略在線）。送達或超過 48 小時 TTL 之後，連這筆等待中的密文都會消失。"
                )
                block(
                    title: "離線保留期限（TTL）",
                    body: "若收件人一直不開啟 Faraday，封裝密文會在 48 小時後丟棄。這段期間也不寫進磁碟。寄件者自己的裝置上仍留有該則訊息。逾期後伺服器不會重試。中繼站重啟也會清掉仍在等待的內容。"
                )
                block(
                    title: "密碼學，不是自創方案",
                    body: "採用 Signal 公布的 X3DH 與 Double Ratchet。外層封裝使用 DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM，風格依 RFC 9180 HPKE Base。身分金鑰是由 BIP-39 的 24 詞助記詞衍生的 X25519 + Ed25519。函式庫為 Apple CryptoKit 與系統鑰匙圈。此 MVP 沒有 libsignal 二進位——這是依規格實作，且尚未經過稽核。"
                )
                block(
                    title: "推播通知（未使用）",
                    body: "這個 MVP 不會連 APNs。未來若加靜音或僅顯示「新訊息」的推播，Apple 仍會知道這台裝置在某個時間點上線並收到 ping，也會洩漏時間資訊。推播絕不可帶明文、寄件者或信箱 ID。帶預覽文字的可見橫幅與本威脅模型不相容。"
                )
                block(
                    title: "刻意不做的事",
                    body: "推播、電話／電子郵件身分、上傳通訊錄、分析、崩潰回報、群組、附件、語音與個人檔案。"
                )
                block(
                    title: "誠實的限制",
                    body: "還原助記詞只恢復金鑰與信箱，不會帶回聊天紀錄或進行中的棘輪會話——先前的聯絡人可能要再邀請你一次。尚無後量子（PQXDH）。若 Faraday 關閉，封裝密文會在中繼站記憶體等待 48 小時後丟棄。邀請連結是能力憑證：拿到的人就能傳訊給你。"
                )
            }
            .padding(24)
        }
        .faradayScreen()
        .navigationTitle("威脅模型")
    }

    private func block(title: String, body: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline).foregroundStyle(FaradayTheme.brass)
            Text(body).foregroundStyle(FaradayTheme.muted)
        }
    }
}
