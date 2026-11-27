import Foundation

/// AppKit saves window frames ("NSWindow Frame <name>") and split-view layouts ("NSSplitView Subview Frames
/// <name>") in user defaults. Builds whose scenes had no id let SwiftUI name them after the whole view type,
/// which changed with each build, so keys piled up: 1,122 window keys and 2,250 split keys of about 1.7 KB
/// each on a test Mac (2026-11-16). Every divider or frame save reads the defaults and walks them all; New
/// Connection at screen size took about 490 ms there, about 100 ms without them. Every scene now has an id
/// (`main`, `session`, `credentials`, Settings), so no current window uses a generated name: they are all
/// removed at launch, before any window reads the defaults. Foundation only, so tests/autosave-keys builds it.
enum AutosaveKeys {
    static let windowPrefix = "NSWindow Frame ", splitPrefix = "NSSplitView Subview Frames "
    /// SwiftUI's type-derived names. Hand-written names (`main-AppWindow-1`, `credentials`) keep their keys.
    static let generated = "SwiftUI."

    /// Keys to remove: window or split-view keys with a generated name.
    static func staleKeys(in keys: some Sequence<String>) -> [String] {
        keys.filter { $0.hasPrefix(windowPrefix + generated) || $0.hasPrefix(splitPrefix + generated) }.sorted()
    }

    /// Removes the stale keys from `domain` (the app's own by default). Key by key through CFPreferences: a
    /// batch removal (CFPreferencesSetMultiple, setPersistentDomain) did not persist, and once windows observe
    /// the defaults each UserDefaults removal walks the whole domain (minutes for 3,000 keys). Without stale
    /// keys this is one key-list read. Returns how many were removed.
    @discardableResult
    static func removeStale(domain: String = Bundle.main.bundleIdentifier ?? ProcessInfo.processInfo.processName) -> Int {
        let app = domain as CFString
        let keys = (CFPreferencesCopyKeyList(app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost) as? [String]) ?? []
        let stale = staleKeys(in: keys)
        guard !stale.isEmpty else { return 0 }
        for key in stale { CFPreferencesSetValue(key as CFString, nil, app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost) }
        CFPreferencesSynchronize(app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost)
        return stale.count
    }
}
