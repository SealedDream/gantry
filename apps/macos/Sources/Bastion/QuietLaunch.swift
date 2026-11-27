import AppKit

/// UI-driver runs (`BASTION_UI_SCRIPT`, or `BASTION_UI_QUIET=1`) are quiet: the app runs with the accessory activation policy
/// (no Dock icon, no menu bar takeover), never activates itself or steals focus, and never beeps.
/// The driver sends its events straight to the windows, so nothing needs the app to be active.
/// `BASTION_UI_FOREGROUND=1` restores the normal behaviour for a script that must be watched.
enum QuietLaunch {
    static let isOn: Bool = {
        return (TestHooks.isScripted || TestHooks.env("BASTION_UI_QUIET") == "1") && TestHooks.env("BASTION_UI_FOREGROUND") == nil
    }()

    /// The activation policy to start with: accessory while quiet, else regular.
    static var policy: NSApplication.ActivationPolicy { isOn ? .accessory : .regular }

    /// `NSApp.activate()` unless quiet.
    @MainActor static func activate() {
        guard !isOn else { return }
        NSApp.activate()
    }

    /// `NSSound.beep()` unless quiet.
    static func beep() {
        guard !isOn else { return }
        NSSound.beep()
    }
}
