import SwiftUI

extension Color {
    init(hex: UInt32, opacity: Double = 1) {
        self.init(.sRGB,
                  red: Double((hex >> 16) & 0xFF) / 255,
                  green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255,
                  opacity: opacity)
    }
}

/// Agamemnon's midnight theme.
enum Theme {
    static let midnight = Color(hex: 0x050916)
    static let midnightHigh = Color(hex: 0x0A1230)
    static let sidebar = Color(hex: 0x060B1D)
    static let card = Color(hex: 0x0D1632)
    static let cardRaised = Color(hex: 0x111C3E)
    static let stroke = Color(hex: 0x1C2B57)
    static let navy = Color(hex: 0x1B3474)
    static let navyHover = Color(hex: 0x24438F)
    static let navyPressed = Color(hex: 0x142858)
    static let accent = Color(hex: 0x5B93FF)
    static let gold = Color(hex: 0xD8B26A)
    static let text = Color.white
    static let textSecondary = Color(hex: 0x93A2C9)
    static let textTertiary = Color(hex: 0x5D6C94)
    static let success = Color(hex: 0x3DDC97)
    static let warning = Color(hex: 0xFFB547)
    static let danger = Color(hex: 0xFF5C7A)

    static let background = LinearGradient(colors: [midnightHigh, midnight],
                                            startPoint: .top, endPoint: .bottom)

    static func color(for level: ThreatLevel) -> Color {
        switch level {
        case .malicious: return danger
        case .suspicious: return warning
        case .test: return accent
        }
    }
}

// MARK: - Buttons

struct NavyButtonStyle: ButtonStyle {
    enum Kind { case primary, secondary, destructive }
    var kind: Kind = .primary
    var compact = false

    func makeBody(configuration: Configuration) -> some View {
        NavyButtonBody(configuration: configuration, kind: kind, compact: compact)
    }

    private struct NavyButtonBody: View {
        let configuration: ButtonStyleConfiguration
        let kind: Kind
        let compact: Bool
        @State private var hovering = false
        @Environment(\.isEnabled) private var isEnabled

        var body: some View {
            let shape = RoundedRectangle(cornerRadius: compact ? 9 : 11, style: .continuous)
            let label = configuration.label
                .font(.system(size: compact ? 12 : 13, weight: .semibold))
                .foregroundStyle(foreground)
                .padding(.horizontal, compact ? 12 : 16)
                .padding(.vertical, compact ? 6 : 9)

            Group {
                if #available(macOS 26.0, *) {
                    // Liquid Glass: navy-tinted for primary buttons, clear glass otherwise.
                    label
                        .glassEffect(glass, in: shape)
                        .scaleEffect(configuration.isPressed ? 0.97 : 1)
                } else {
                    label
                        .background(shape.fill(fill))
                        .overlay(shape.strokeBorder(border, lineWidth: 1))
                }
            }
            .opacity(isEnabled ? 1 : 0.45)
            .contentShape(shape)
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: hovering)
            .animation(.spring(response: 0.25, dampingFraction: 0.7), value: configuration.isPressed)
        }

        @available(macOS 26.0, *)
        private var glass: Glass {
            switch kind {
            case .primary:
                return Glass.regular.tint(hovering ? Theme.navyHover : Theme.navy).interactive()
            case .secondary:
                return Glass.regular.interactive()
            case .destructive:
                return Glass.regular.tint(Theme.danger.opacity(0.18)).interactive()
            }
        }

        private var foreground: Color {
            switch kind {
            case .primary: return .white
            case .secondary: return Theme.text
            case .destructive: return Theme.danger
            }
        }

        private var fill: Color {
            switch kind {
            case .primary:
                if configuration.isPressed { return Theme.navyPressed }
                return hovering ? Theme.navyHover : Theme.navy
            case .secondary, .destructive:
                if configuration.isPressed { return Theme.cardRaised.opacity(0.6) }
                return hovering ? Theme.cardRaised : Theme.card
            }
        }

        private var border: Color {
            switch kind {
            case .primary: return Color.white.opacity(0.10)
            case .secondary: return Theme.stroke
            case .destructive: return Theme.danger.opacity(0.35)
            }
        }
    }
}

extension ButtonStyle where Self == NavyButtonStyle {
    static var navy: NavyButtonStyle { NavyButtonStyle() }
    static var navySecondary: NavyButtonStyle { NavyButtonStyle(kind: .secondary) }
    static var navyDestructive: NavyButtonStyle { NavyButtonStyle(kind: .destructive) }
    static var navyCompact: NavyButtonStyle { NavyButtonStyle(kind: .secondary, compact: true) }
}

// MARK: - Building blocks

struct Card<Content: View>: View {
    var padding: CGFloat = 18
    var tint: Color? = nil
    @ViewBuilder var content: () -> Content

    var body: some View {
        content()
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .liquidGlass(RoundedRectangle(cornerRadius: 18, style: .continuous), tint: tint)
    }
}

// MARK: - Liquid Glass

extension View {
    /// Liquid Glass on macOS 26 and later; a frosted navy panel on older macOS.
    @ViewBuilder
    func liquidGlass<S: Shape>(_ shape: S, tint: Color? = nil, interactive: Bool = false) -> some View {
        if #available(macOS 26.0, *) {
            self.glassEffect(Theme.glass(tint: tint, interactive: interactive), in: shape)
        } else {
            self
                .background(shape.fill(Theme.card.opacity(0.72)))
                .background(shape.fill(.ultraThinMaterial))
                .overlay(shape.stroke(Theme.stroke, lineWidth: 1))
        }
    }

    /// Groups nearby glass shapes so they blend and morph together (macOS 26+).
    @ViewBuilder
    func glassGroup(spacing: CGFloat = 16) -> some View {
        if #available(macOS 26.0, *) {
            GlassEffectContainer(spacing: spacing) { self }
        } else {
            self
        }
    }
}

extension Theme {
    @available(macOS 26.0, *)
    static func glass(tint: Color?, interactive: Bool) -> Glass {
        var glass = Glass.regular
        if let tint { glass = glass.tint(tint) }
        if interactive { glass = glass.interactive() }
        return glass
    }
}

/// Soft midnight glows behind the content, so the glass has something to refract.
struct AuroraBackground: View {
    var body: some View {
        ZStack {
            Theme.background
            Circle()
                .fill(Theme.navyHover.opacity(0.55))
                .frame(width: 520, height: 520)
                .blur(radius: 140)
                .offset(x: -260, y: -240)
            Circle()
                .fill(Theme.accent.opacity(0.22))
                .frame(width: 420, height: 420)
                .blur(radius: 150)
                .offset(x: 320, y: 60)
            Circle()
                .fill(Theme.gold.opacity(0.10))
                .frame(width: 380, height: 380)
                .blur(radius: 160)
                .offset(x: -40, y: 380)
        }
        .ignoresSafeArea()
        .allowsHitTesting(false)
    }
}

struct PageHeader: View {
    let title: String
    let subtitle: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.system(size: 26, weight: .bold))
                .foregroundStyle(Theme.text)
            Text(subtitle)
                .font(.system(size: 13))
                .foregroundStyle(Theme.textSecondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct SectionTitle: View {
    let text: String
    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 11, weight: .semibold))
            .tracking(0.8)
            .foregroundStyle(Theme.textTertiary)
    }
}

struct StatusPill: View {
    let text: String
    let color: Color

    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 7, height: 7)
            Text(text)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(color)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 4)
        .background(Capsule().fill(color.opacity(0.12)))
    }
}

struct IconBadge: View {
    let symbol: String
    var color: Color = Theme.accent
    var size: CGFloat = 34

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size * 0.45, weight: .semibold))
            .foregroundStyle(color)
            .frame(width: size, height: size)
            .background(
                RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                    .fill(color.opacity(0.14))
            )
    }
}

/// A row with a title, description and a trailing control.
struct SettingRow<Trailing: View>: View {
    let symbol: String
    let title: String
    let detail: String
    var color: Color = Theme.accent
    @ViewBuilder var trailing: () -> Trailing

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            IconBadge(symbol: symbol, color: color)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Theme.text)
                Text(detail)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            trailing()
        }
    }
}

struct Notice: View {
    let symbol: String
    let text: String
    var color: Color = Theme.warning

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol).foregroundStyle(color)
            Text(text)
                .font(.system(size: 12))
                .foregroundStyle(Theme.text.opacity(0.9))
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(12)
        .liquidGlass(RoundedRectangle(cornerRadius: 12, style: .continuous), tint: color.opacity(0.14))
    }
}

/// Page container: scrollable, padded, on the midnight background.
struct Page<Content: View>: View {
    @ViewBuilder var content: () -> Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                content()
            }
            .padding(28)
            .frame(maxWidth: 980, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .scrollContentBackground(.hidden)
    }
}

extension Date {
    var relative: String {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(for: self, relativeTo: Date())
    }
}

extension Int64 {
    var fileSize: String { ByteCountFormatter.string(fromByteCount: self, countStyle: .file) }
}
