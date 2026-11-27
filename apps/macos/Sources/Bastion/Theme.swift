import SwiftUI
import BastionCore

/// User-chosen look: colour mode, accent palette and density. Stored in `settings.json` through
/// `SettingsModel` (raw values are the core's option ids) and applied at the window root, so every view reads it through `.tint`, the colour scheme and
/// `\.density`.
@MainActor @Observable
final class AppearanceSettings {
    enum Mode: String, CaseIterable, Identifiable {
        case system, light, dark, highContrast = "high-contrast"
        var id: String { rawValue }
        var label: String {
            switch self {
            case .system: "System"
            case .light: "Light"
            case .dark: "Dark"
            case .highContrast: "High contrast"
            }
        }
    }

    enum Accent: String, CaseIterable, Identifiable {
        case electric, cyan, violet, emerald, amber, rose
        var id: String { rawValue }
        var label: String {
            switch self {
            case .electric: "Electric blue"
            case .cyan: "Cyan"
            case .violet: "Violet"
            case .emerald: "Emerald"
            case .amber: "Amber"
            case .rose: "Rose"
            }
        }
        var color: Color {
            switch self {
            case .electric: Color(red: 0.18, green: 0.42, blue: 1.00)
            case .cyan: Color(red: 0.00, green: 0.66, blue: 0.82)
            case .violet: Color(red: 0.49, green: 0.36, blue: 1.00)
            case .emerald: Color(red: 0.06, green: 0.65, blue: 0.45)
            case .amber: Color(red: 0.90, green: 0.58, blue: 0.04)
            case .rose: Color(red: 0.93, green: 0.25, blue: 0.37)
            }
        }
    }

    enum Density: String, CaseIterable, Identifiable {
        case compact, comfortable, spacious
        var id: String { rawValue }
        var label: String { rawValue.capitalized }
        /// Vertical padding added to sidebar and editor rows.
        var rowPadding: CGFloat {
            switch self {
            case .compact: 0
            case .comfortable: 1
            case .spacious: DS.Space.xxs
            }
        }
        var controlSize: ControlSize {
            switch self {
            case .compact: .small
            case .comfortable: .regular
            case .spacious: .large
            }
        }
    }

    private let settings: SettingsModel

    init(settings: SettingsModel) {
        self.settings = settings
    }

    var mode: Mode {
        get { Mode(rawValue: settings.value("appearance.mode")) ?? .system }
        set { settings.set("appearance.mode", newValue.rawValue) }
    }
    var accent: Accent {
        get { Accent(rawValue: settings.value("appearance.accent")) ?? .electric }
        set { settings.set("appearance.accent", newValue.rawValue) }
    }
    var density: Density {
        get { Density(rawValue: settings.value("appearance.density")) ?? .comfortable }
        set { settings.set("appearance.density", newValue.rawValue) }
    }
    static let matchAppTheme = TerminalThemeChoice.matchApp
    static func terminalThemeId(_ value: String, appIsDark: Bool) -> String { TerminalThemeChoice.id(value, appIsDark: appIsDark) }

    /// App-wide terminal theme setting (`termthemes`: `match-app`, bundled or `custom-…`); connections may override it.
    var terminalTheme: String {
        get { settings.value("terminal.theme") }
        set { settings.set("terminal.theme", newValue) }
    }
    /// Terminal text size in points (`terminal.font-size`).
    var terminalFontSize: CGFloat { CGFloat(Int(settings.value("terminal.font-size")) ?? 13) }
    /// App-wide terminal font (`terminal.font-family`, `-size`, `terminal.ligatures`); folders and
    /// connections may override each part.
    var terminalFont: TerminalFontView {
        TerminalFontView(family: TerminalFonts.family(settings.value("terminal.font-family")), size: UInt32(terminalFontSize),
                         ligatures: settings.value("terminal.ligatures") == "true")
    }

    var colorScheme: ColorScheme? {
        switch mode {
        case .system: nil
        case .light: .light
        case .dark, .highContrast: .dark
        }
    }

    /// AppKit appearance, so sheets, menus and the title bar follow the chosen mode too.
    var nsAppearance: NSAppearance? {
        switch mode {
        case .system: nil
        case .light: NSAppearance(named: .aqua)
        case .dark: NSAppearance(named: .darkAqua)
        case .highContrast: NSAppearance(named: .accessibilityHighContrastDarkAqua)
        }
    }
}

private struct DensityKey: EnvironmentKey {
    static let defaultValue = AppearanceSettings.Density.comfortable
}

extension EnvironmentValues {
    var density: AppearanceSettings.Density {
        get { self[DensityKey.self] }
        set { self[DensityKey.self] = newValue }
    }
}

/// Applies the appearance settings to a window's content.
struct ThemedRoot: ViewModifier {
    let settings: AppearanceSettings

    func body(content: Content) -> some View {
        RenderCount.hit("WindowRoot")
        return content
            .tint(settings.accent.color)
            .preferredColorScheme(settings.colorScheme)
            .environment(\.density, settings.density)
            .controlSize(settings.density.controlSize)
            .onAppear { NSApp.appearance = settings.nsAppearance }
            .onChange(of: settings.mode) { NSApp.appearance = settings.nsAppearance }
    }
}

/// Small status tag: tinted text on a faint fill of the same hue, never colour alone.
struct Badge: View {
    let text: String
    var color: Color = .secondary

    var body: some View {
        Text(text)
            .font(DS.Font.caption2.weight(.medium))
            .foregroundStyle(color)
            .padding(.horizontal, DS.Space.xxs + 1)
            .padding(.vertical, 1)
            .background(color.opacity(0.14), in: RoundedRectangle(cornerRadius: 3))
            .fixedSize()
    }
}

/// Appearance page (Settings window, and a sheet for scripted snapshots).
struct AppearanceView: View {
    @Environment(AppearanceSettings.self) private var settings
    @Environment(ThemesModel.self) private var themes

    var body: some View {
        @Bindable var settings = settings
        Form {
            Picker("Mode", selection: $settings.mode) {
                ForEach(AppearanceSettings.Mode.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
            LabeledContent("Accent") {
                HStack(spacing: DS.Space.xs) {
                    ForEach(AppearanceSettings.Accent.allCases) { accent in
                        Button { settings.accent = accent } label: {
                            Circle()
                                .fill(accent.color)
                                .frame(width: DS.Size.swatch, height: DS.Size.swatch)
                                .overlay {
                                    if settings.accent == accent {
                                        Circle().strokeBorder(.primary, lineWidth: 2).padding(-3)
                                    }
                                }
                        }
                        .buttonStyle(.plain)
                        .help(accent.label)
                        .accessibilityLabel(accent.label)
                        .accessibilityAddTraits(settings.accent == accent ? .isSelected : [])
                    }
                }
            }
            Picker("Density", selection: $settings.density) {
                ForEach(AppearanceSettings.Density.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
            Picker("Terminal colours", selection: $settings.terminalTheme) {
                Text("Match app theme").tag(AppearanceSettings.matchAppTheme)
                ForEach(themes.items, id: \.id) { Text($0.name).tag($0.id) }
            }
            Text("Saved automatically and applied to every window.")
                .font(DS.Font.caption).foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
        .frame(width: DS.Size.settingsWidth)
    }
}
