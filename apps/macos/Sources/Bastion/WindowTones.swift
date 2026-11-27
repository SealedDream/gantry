import AppKit
import SwiftUI
import BastionCore

/// UI-06: the window's sidebar, tab strip and toolbar take tones from the active tab's terminal theme when
/// `appearance.window-follows-terminal` is on. The colours come from the core (`window_tones`), so every app
/// derives the same ones; `nil` means the stock colours.
struct ChromeTones: Equatable {
    let sidebar: Color
    let tabStrip: Color
    let toolbar: Color
    let activeTab: Color
    let separator: Color
    let text: Color
    let secondaryText: Color
    /// `0xRRGGBB` per surface, for the UI driver.
    let raw: WindowTonesView
    let nsSidebar: NSColor
    let nsText: NSColor
    let isDark: Bool
    /// The accent reaches 3:1 on every surface; otherwise selection is drawn in `text`.
    let accentUsable: Bool
    var colorScheme: ColorScheme { isDark ? .dark : .light }
    var appearance: NSAppearance? { NSAppearance(named: isDark ? .darkAqua : .aqua) }

    init(_ t: WindowTonesView, accentUsable: Bool) {
        sidebar = Self.color(t.sidebar)
        tabStrip = Self.color(t.tabStrip)
        toolbar = Self.color(t.toolbar)
        activeTab = Self.color(t.activeTab)
        separator = Self.color(t.separator)
        text = Self.color(t.text)
        secondaryText = Self.color(t.secondaryText)
        raw = t
        nsSidebar = Self.nsColor(t.sidebar)
        nsText = Self.nsColor(t.text)
        isDark = t.isDark
        self.accentUsable = accentUsable
    }

    static func nsColor(_ rgb: UInt32) -> NSColor {
        NSColor(srgbRed: CGFloat(rgb >> 16 & 0xff) / 255, green: CGFloat(rgb >> 8 & 0xff) / 255, blue: CGFloat(rgb & 0xff) / 255, alpha: 1)
    }
    static func color(_ rgb: UInt32) -> Color { Color(nsColor: nsColor(rgb)) }

    /// Tones for a theme, or nil when the setting is off or the tab has no terminal theme.
    static func resolve(enabled: Bool, theme: TerminalThemeView?, accent: Color, increasedContrast: Bool) -> ChromeTones? {
        guard enabled, let theme else { return nil }
        let view = windowTones(background: theme.background, foreground: theme.foreground, increasedContrast: increasedContrast)
        let a = NSColor(accent).usingColorSpace(.sRGB) ?? .systemBlue
        let rgb = UInt32((a.redComponent * 255).rounded()) << 16 | UInt32((a.greenComponent * 255).rounded()) << 8 | UInt32((a.blueComponent * 255).rounded())
        return ChromeTones(view, accentUsable: windowTonesAccentUsable(accent: rgb, tones: view))
    }
}

/// Paints a surface in its tone and switches the subtree to the tone's light or dark look, so system text
/// colours (label, secondary label) stay readable on it. Stock look when tones are off.
struct ChromeSurface: ViewModifier {
    let tone: KeyPath<ChromeTones, Color>
    @Environment(\.chromeTones) private var tones

    func body(content: Content) -> some View {
        if let tones {
            content
                .background(tones[keyPath: tone])
                .environment(\.colorScheme, tones.colorScheme)
        } else {
            content
        }
    }
}

/// For views hosted outside the window's environment (the toolbar's tab strip): tones from the window's sessions.
struct ChromeTonesFromSessions: ViewModifier {
    @Environment(SessionsModel.self) private var sessions
    func body(content: Content) -> some View {
        if let t = sessions.chromeTones {
            content.environment(\.chromeTones, t).environment(\.colorScheme, t.colorScheme)
        } else {
            content
        }
    }
}

private struct ChromeTonesKey: EnvironmentKey {
    static let defaultValue: ChromeTones? = nil
}

extension EnvironmentValues {
    var chromeTones: ChromeTones? {
        get { self[ChromeTonesKey.self] }
        set { self[ChromeTonesKey.self] = newValue }
    }
}

/// Resolves the window's tones from its selected tab and publishes them to the window's views; paints the toolbar.
/// Changes only when the selected tab, its theme, the setting or the contrast mode change: no per-frame work.
struct ChromeTonesProvider: ViewModifier {
    /// A torn-off window: its own selected tab and id. Nil: the main window (selected tab, Home).
    var window: (id: UUID, tab: TerminalTab)? = nil
    @Environment(AppearanceSettings.self) private var appearance
    @Environment(ThemesModel.self) private var themes
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @Environment(SettingsModel.self) private var appSettings
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var contrast

    static let setting = "appearance.window-follows-terminal"
    /// UI tests stand in for System Settings › Accessibility › Increase Contrast (a system setting they must not change).
    private static let testIncreasedContrast = TestHooks.isScripted && ProcessInfo.processInfo.environment["BASTION_TEST_INCREASE_CONTRAST"] == "1"

    private var tones: ChromeTones? {
        // Off: nothing to resolve, and the selected tab's theme is not read, so a tab opening or
        // changing does not re-run the window's chrome (MAC-FIRST-SHELL).
        guard appSettings.value(Self.setting) == "true" else { return nil }
        return ChromeTones.resolve(enabled: true, theme: activeTheme,
                            accent: appearance.accent.color, increasedContrast: contrast == .increased || Self.testIncreasedContrast)
    }

    /// The selected tab's theme as the terminal shows it (`TerminalView.applyTheme`); nil for non-terminal tabs.
    private var activeTheme: TerminalThemeView? {
        let candidate = window.map(\.tab) ?? (sessions.homeShown ? nil : sessions.selectedTab)
        guard let tab = candidate, case .terminal = tab.content else { return nil }
        _ = themes.revision
        _ = model.revision
        let own = tab.connectionId.flatMap { id in (try? model.library?.terminalTheme(connectionId: id)) ?? nil }
        let id = own ?? AppearanceSettings.terminalThemeId(appearance.terminalTheme, appIsDark: colorScheme == .dark)
        return themes.theme(id) ?? themes.theme("bastion-dark")
    }

    private func publish(_ t: ChromeTones?) {
        if let window {
            if TestHooks.isScripted { DriverEvents.windowChromeTones[window.id] = t }
            return
        }
        if sessions.chromeTones != t { sessions.chromeTones = t }
        if TestHooks.isScripted { DriverEvents.chromeTones = t }
    }

    func body(content: Content) -> some View {
        let t = tones
        content
            .environment(\.chromeTones, t)
            .toolbarBackground(t?.toolbar ?? .clear, for: .windowToolbar)
            .toolbarBackground(t == nil ? .automatic : .visible, for: .windowToolbar)
            // Only the title bar takes the tones' light or dark look; `.toolbarColorScheme` switched the whole window's
            // appearance, which turned Match app theme (and every page) dark in a light app.
            .background(TitlebarAppearance(appearance: t?.appearance))
            .onAppear { publish(t) }
            .onChange(of: t) { _, new in publish(new) }
    }
}


/// Sets the title bar container's appearance (nil = the window's own), so the toolbar's controls read on the toolbar tone
/// while the window content, sheets and menus keep the app's appearance.
private struct TitlebarAppearance: NSViewRepresentable {
    let appearance: NSAppearance?
    func makeNSView(context: Context) -> NSView { NSView(frame: .zero) }
    func updateNSView(_ view: NSView, context: Context) {
        let apply = { [appearance] in
            guard let container = view.window?.standardWindowButton(.closeButton)?.superview?.superview else { return }
            if container.appearance != appearance { container.appearance = appearance }
        }
        if view.window == nil { DispatchQueue.main.async(execute: apply) } else { apply() }
    }
}
