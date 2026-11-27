import AppKit

/// Applies Settings › General › Window at launch to the main window once it is on screen, and fills the fixed size
/// from the current window (Use current size). The size rules are in WindowLaunch.swift.
@MainActor
enum WindowLaunchApplier {
    private static var applied = false

    /// From the main window's onAppear: once per launch, after SwiftUI has restored the remembered frame.
    static func applyOnce(settings: SettingsModel) {
        guard !applied else { return }
        applied = true
        DispatchQueue.main.async { apply(settings: settings) }
    }

    private static func mainWindow() -> NSWindow? {
        NSApp.windows.first { $0.contentView?.firstSubview(of: KeyOutlineView.self) != nil }
            ?? NSApp.windows.first { $0.isVisible && $0.canBecomeMain }
    }

    private static func apply(settings: SettingsModel) {
        guard let window = mainWindow() else { return }
        let main = (NSScreen.main ?? NSScreen.screens.first)?.visibleFrame ?? window.frame
        let visible = WindowLaunch.visibleArea(for: window.frame, screens: NSScreen.screens.map(\.visibleFrame), main: main)
        switch WindowLaunch.Mode(rawValue: settings.value(WindowLaunch.settingId)) ?? .remember {
        case .remember:
            window.setFrame(WindowLaunch.clamp(window.frame, to: visible), display: true)
        case .fixed:
            let width = CGFloat(Int(settings.value(WindowLaunch.widthId)) ?? 1280)
            let height = CGFloat(Int(settings.value(WindowLaunch.heightId)) ?? 800)
            window.setFrame(WindowLaunch.centred(width: width, height: height, in: visible), display: true)
        case .maximized:
            window.setFrame(visible, display: true)
        case .fullScreen:
            if !window.styleMask.contains(.fullScreen) { window.toggleFullScreen(nil) }
        }
    }

    /// Settings › General › Use current size.
    static func useCurrentSize(settings: SettingsModel) {
        guard let window = mainWindow(), !window.styleMask.contains(.fullScreen) else { return }
        settings.set(WindowLaunch.widthId, String(Int(window.frame.width.rounded())))
        settings.set(WindowLaunch.heightId, String(Int(window.frame.height.rounded())))
    }
}
