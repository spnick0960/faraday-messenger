import SwiftUI

@main
struct FaradayApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .preferredColorScheme(.dark)
        }
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Group {
            if model.hasIdentity {
                InboxView()
            } else {
                WelcomeView()
            }
        }
        .faradayScreen()
        .alert(item: Binding(
            get: { model.lastError },
            set: { model.lastError = $0 }
        )) { err in
            Alert(title: Text("發生錯誤"), message: Text(err.message), dismissButton: .default(Text("確定")))
        }
        .onAppear { model.setSceneActive(scenePhase == .active) }
        .onChange(of: scenePhase) { _, phase in
            model.setSceneActive(phase == .active)
            if phase == .active, model.hasIdentity {
                Task { await model.connect() }
            }
        }
    }
}
