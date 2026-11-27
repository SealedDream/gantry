import Foundation

/// The Plugins page's wording (PLUG-06a part 1), free of the core so it is unit-tested alone
/// (`tests/plugins-text-test.sh`).
enum PluginsText {
    static func policyBanner(error: String?, disabled: Bool, officialOnly: Bool, forbidUnverified: Bool, listedOnly: Bool) -> String? {
        if let error { return "Managed policy unreadable, plugins off: \(error)" }
        if disabled { return "Plugins are turned off by policy" }
        if officialOnly { return "Policy: Official plugins only" }
        if forbidUnverified { return "Policy: unverified plugins forbidden" }
        if listedOnly { return "Policy: listed plugins only" }
        return nil
    }

    static func badge(_ tier: String) -> String {
        switch tier {
        case "official": return "Official"
        case "external": return "External"
        default: return "Unverified"
        }
    }

    static func catalogueText(_ outcome: String?) -> String {
        guard let outcome else { return "Catalogue not checked yet" }
        switch outcome {
        case "accepted": return "Catalogue up to date"
        case "expired": return "Catalogue expired: revocation status unknown"
        case "clock-wrong": return "Catalogue checked; this Mac's clock looks wrong"
        default:
            if outcome.hasPrefix("unreachable") { return "Catalogue unreachable; nothing changed" }
            if outcome.hasPrefix("refused") { return "Catalogue refused; nothing changed" }
            return "Catalogue: \(outcome)"
        }
    }

    static func installText(_ kind: String, file: String) -> String {
        switch kind {
        case "installed": return "Installed \(file)"
        case "updated": return "Updated from \(file)"
        case "restored": return "Restored the previous version"
        case "unchanged": return "Already installed"
        default: return "\(kind): \(file)"
        }
    }

    /// Why a plugin view stopped (PLUG-06a part 2), from the core's `ended` reason.
    static func ended(_ reason: String) -> String {
        switch reason {
        case "cancel", "tab-closed": return "Plugin stopped"
        case "limit": return "Plugin stopped: over its memory or time limit"
        case "hang": return "Plugin stopped: not responding"
        case "crash": return "Plugin stopped: it crashed"
        case "document-locked", "credentials-locked-policy": return "Plugin stopped: credentials locked"
        case "revoked": return "Plugin stopped: revoked"
        case "policy": return "Plugin stopped: policy changed"
        case "turned-off": return "Plugin stopped: turned off"
        case "removed": return "Plugin stopped: removed"
        case "safe-mode": return "Plugin stopped: Safe mode"
        default: return "Plugin stopped (\(reason))"
        }
    }

    /// The prompt before an Unverified plugin runs (no stored setting yet; asked on each open).
    static let unverifiedRun = "Unverified plugin: no known publisher signature. It runs in the plugin sandbox."
}
