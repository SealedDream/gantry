import Foundation
import BastionCore

/// `settings.json` next to the library (so `BASTION_LIBRARY` test runs never touch the user's
/// settings). Definitions, validation and search come from the core; this model caches values for
/// SwiftUI and reports rejected values instead of swallowing them.
@MainActor @Observable
final class SettingsModel {
    /// Pages and commands this frontend provides for the core's `link` settings.
    /// `check-updates` only when the build has an update channel (it also gates the launch check).
    static let handledLinks = ["defaults:ssh", "defaults:rdp", "defaults:vnc", "defaults:web", "ssh-sources", "ssh-import",
                               "credential-manager", "vaultwarden", "lock-credentials", "workspace-manager", "keyboard-shortcuts", "terminal-themes", "window-launch", "window-current-size", "library-auto-hide", "full-screen-dock", "tab-groups", "vertical-tabs", "tab-previews", "header-style",
                               // UI-06: window colours follow the terminal theme (`WindowTones.swift`).
                               "window-tones",
                               // LOG-ERRCODES: Detailed logging (`DetailedLog.swift`).
                               "detailed-log",
                               // Terminal features this frontend implements (`settings.rs` `terminal-*`).
                               "terminal-font-family", "terminal-ligatures", "terminal-cursor-style", "terminal-bell", "terminal-program-notifications",
                               "terminal-scrollback", "terminal-copy-on-select", "terminal-confirm-close", "terminal-session-bar",
                               // `SecretPasteboard` clears a copied password after this setting's time (A3-S1).
                               "secret-clipboard-lifetime",
                               // Touch ID before the vault opens (`Credentials.confirmOpen`) and for the library key (`LibraryKey`).
                               "vault-open-confirm", "touch-id-library-unlock",
                               // Delete goes to Recently Deleted for this long (B10, `RecentlyDeleted`).
                               "restore-deleted",
                               // Settings → Security → Allow Telnet, with the confirm-once (B7).
                               "allow-telnet",
                               // Remembered logins expire after this many minutes (SEC-03, `RememberedLoginStore`).
                               "session-login-reuse",
                               // Session log folder, time stamps, retention and redaction (LOG-CORE-02, `startPlannedLog`).
                               "session-log-v2"]
        + (updateChannelConfigured() ? ["check-updates"] : [])

    let definitions: [SettingDefView] = settingDefinitions(handledLinks: handledLinks)
    let categories: [SettingCategoryView] = settingCategories(handledLinks: handledLinks)
    private(set) var values: [String: String] = [:]
    var error: String?
    /// Search to show when the Settings window opens next (palette: jump to one setting).
    var pendingQuery: String?
    /// Category to show when the Settings window opens next (palette: Keyboard Shortcuts).
    var pendingCategory: String?
    /// Settings link target presented as a sheet on the Settings window (`SettingsSheet`).
    var pendingSheet: String?
    private let file: SettingsFile?
    /// The settings file the core reads Allow Telnet from (`connectTelnet`).
    var coreFile: SettingsFile? { file }

    static var path: URL { LibraryModel.dataDir.appendingPathComponent("settings.json") }

    init() {
        do {
            let f = try SettingsFile.open(path: Self.path.path)
            file = f
            if f.isNew(), let problem = Self.importLegacyPreferences(into: f) { error = problem }
        } catch {
            file = nil
            self.error = "Settings could not be read and are not being saved: \(error)"
        }
        reload()
        TelnetPolicy.settings = self
    }

    func value(_ id: String) -> String {
        values[id] ?? definitions.first { $0.id == id }?.defaultValue ?? ""
    }

    /// Validated and saved by the core; on rejection the old value stays and `error` says why.
    @discardableResult
    func set(_ id: String, _ value: String) -> Bool {
        guard let file else { return false }
        do {
            try file.set(id: id, value: value)
            values[id] = try file.get(id: id)
            if id == DetailedLog.settingId { DetailedLog.changed(self) }
            return true
        } catch {
            self.error = error.userMessage
            return false
        }
    }

    func definitions(in category: String) -> [SettingDefView] { definitions.filter { $0.category == category } }

    func search(_ query: String) -> [SettingDefView] {
        let ids = Set(searchSettings(query: query, handledLinks: Self.handledLinks))
        return definitions.filter { ids.contains($0.id) }
    }

    private func reload() {
        guard let file else { return }
        values = Dictionary(uniqueKeysWithValues: definitions.filter { $0.kind != "link" }.compactMap { d in
            (try? file.get(id: d.id)).map { (d.id, $0) }
        })
    }

    /// Before settings.json, appearance lived in UserDefaults. Import it once into the real
    /// library's settings only; a test library starts from defaults.
    private static func importLegacyPreferences(into file: SettingsFile) -> String? {
        guard TestHooks.libraryOverride == nil else { return nil }
        let d = UserDefaults.standard
        var legacy: [String: String] = [:]
        if let m = d.string(forKey: "appearance.mode") { legacy["appearance.mode"] = m == "highContrast" ? "high-contrast" : m }
        for (key, id) in [("appearance.accent", "appearance.accent"), ("appearance.density", "appearance.density"),
                          ("appearance.terminalTheme", "terminal.theme")] {
            if let v = d.string(forKey: key) { legacy[id] = v }
        }
        guard !legacy.isEmpty else { return nil }
        do { try file.setMany(values: legacy) } catch { return "Earlier appearance preferences were not imported: \(error)" }
        return nil
    }
}
