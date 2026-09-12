import SwiftUI

enum FaradayTheme {
    static let bg = Color(red: 0.047, green: 0.055, blue: 0.071)
    static let surface = Color(red: 0.086, green: 0.102, blue: 0.133)
    static let elevated = Color(red: 0.118, green: 0.141, blue: 0.184)
    static let text = Color(red: 0.910, green: 0.902, blue: 0.882)
    static let muted = Color(red: 0.545, green: 0.569, blue: 0.533)
    static let brass = Color(red: 0.769, green: 0.647, blue: 0.455)
    static let good = Color(red: 0.490, green: 0.608, blue: 0.463)
    static let bad = Color(red: 0.831, green: 0.416, blue: 0.416)
}

struct FaradayButtonStyle: ButtonStyle {
    var prominent = true
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background(prominent ? FaradayTheme.brass : FaradayTheme.elevated)
            .foregroundStyle(prominent ? FaradayTheme.bg : FaradayTheme.text)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            .opacity(configuration.isPressed ? 0.85 : 1)
    }
}

extension View {
    func faradayScreen() -> some View {
        self
            .foregroundStyle(FaradayTheme.text)
            .background(FaradayTheme.bg.ignoresSafeArea())
    }
}
