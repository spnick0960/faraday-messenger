import AVFoundation
import SwiftUI

struct AddContactView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var pasted = ""
    @State private var error: String?
    @State private var addedName: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("加入聯絡人")
                    .font(.title2.weight(.medium))
                Text("貼上邀請或掃描 QR Code。Faraday 不讀通訊錄，也不會在伺服器上做聯絡人探索。")
                    .foregroundStyle(FaradayTheme.muted)

                #if !targetEnvironment(simulator)
                QRScanner { code in
                    pasted = code
                    add()
                }
                .frame(height: 240)
                .clipShape(RoundedRectangle(cornerRadius: 16))
                #else
                Text("模擬器：請貼上邀請字串。真機才能用相機掃描。")
                    .font(.footnote)
                    .foregroundStyle(FaradayTheme.muted)
                #endif

                TextField("faraday:i1.…", text: $pasted, axis: .vertical)
                    .lineLimit(3...6)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .padding(12)
                    .background(FaradayTheme.surface)
                    .clipShape(RoundedRectangle(cornerRadius: 12))

                if let error { Text(error).foregroundStyle(FaradayTheme.bad) }
                if let addedName {
                    Text("已加入\(addedName)。可從收件匣開始傳訊。")
                        .foregroundStyle(FaradayTheme.good)
                }

                Button("加入") { add() }
                    .buttonStyle(FaradayButtonStyle())
            }
            .padding(24)
        }
        .faradayScreen()
        .navigationTitle("新聯絡人")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func add() {
        do {
            let contact = try model.addContact(fromInvite: pasted)
            addedName = contact.displayName
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }
}

#if !targetEnvironment(simulator)
struct QRScanner: UIViewRepresentable {
    var onCode: (String) -> Void

    func makeUIView(context: Context) -> ScannerView {
        let v = ScannerView()
        v.onCode = onCode
        return v
    }

    func updateUIView(_ uiView: ScannerView, context: Context) {
        uiView.onCode = onCode
    }
}

final class ScannerView: UIView, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    private let session = AVCaptureSession()
    private var started = false

    override func didMoveToWindow() {
        super.didMoveToWindow()
        guard window != nil, !started else { return }
        started = true
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device) else { return }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = bounds
        preview.autoresizingMask = [.layerWidthSizable, .layerHeightSizable]
        layer.addSublayer(preview)
        DispatchQueue.global(qos: .userInitiated).async { self.session.startRunning() }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let value = obj.stringValue,
              value.hasPrefix("faraday:") else { return }
        onCode?(value)
    }
}
#endif
