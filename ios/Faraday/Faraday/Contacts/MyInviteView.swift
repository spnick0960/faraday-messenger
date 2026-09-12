import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

struct MyInviteView: View {
    @Environment(AppModel.self) private var model
    @State private var invite = ""
    @State private var copied = false

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                Text("拿到這組邀請的人可以開始跟你對話，但仍讀不到你其他聊天。中繼站看不到這份邀請。")
                    .foregroundStyle(FaradayTheme.muted)
                    .multilineTextAlignment(.center)
                if let img = QRCode.image(from: invite) {
                    Image(uiImage: img)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 240, height: 240)
                        .padding(16)
                        .background(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 20))
                }
                if let id = model.identity {
                    LabeledContent("信箱", value: "••\(id.mailboxHex.suffix(4))")
                    LabeledContent("指紋", value: id.fingerprint)
                }
                ShareLink(item: invite) {
                    Label("分享邀請", systemImage: "square.and.arrow.up")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(FaradayButtonStyle())
                Button(copied ? "已複製" : "複製邀請字串") {
                    UIPasteboard.general.string = invite
                    copied = true
                }
                .buttonStyle(FaradayButtonStyle(prominent: false))
            }
            .padding(24)
        }
        .faradayScreen()
        .navigationTitle("你的邀請")
        .task {
            invite = (try? model.myInvite()) ?? ""
        }
    }
}

enum QRCode {
    static func image(from string: String) -> UIImage? {
        guard !string.isEmpty else { return nil }
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        let context = CIContext()
        guard let cg = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}
