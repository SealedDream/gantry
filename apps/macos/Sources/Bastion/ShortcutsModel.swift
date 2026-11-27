import SwiftUI
import BastionCore

/// Keyboard shortcuts from the core (`shortcuts.json` next to the library). The core owns the
/// commands, defaults and conflict rules and stores chords in a neutral form (`primary+shift+p`);
/// this model turns them into AppKit key equivalents and ⌘-style text, and records new ones.
@MainActor @Observable
final class ShortcutsModel {
    static let platform = "macos"

    private(set) var items: [ShortcutView] = []
    /// Commands left unbound because an earlier command has the same chord (hand-edited file).
    private(set) var shadowed: Set<String> = []
    /// Why shortcuts.json could not be read (shown once in the main window).
    var error: String?
    /// Why the last change was refused (shown on the Keyboard page until the next change).
    private(set) var rejection: String?
    /// A recorder is waiting for keys (the UI driver checks this before typing).
    var isRecording = false
    /// The user's file; nil when it could not be read, and then nothing is saved.
    private let file: ShortcutsFile?
    /// What is listed: the user's file, or the defaults when it is damaged.
    private let source: ShortcutsFile?

    static var path: URL { LibraryModel.dataDir.appendingPathComponent("shortcuts.json") }

    init() {
        do {
            file = try ShortcutsFile.open(path: Self.path.path)
            source = file
        } catch {
            file = nil
            // A path that does not exist opens as the defaults; it is never written.
            source = try? ShortcutsFile.open(path: FileManager.default.temporaryDirectory.appendingPathComponent("bastion-default-shortcuts-\(UUID()).json").path)
            self.error = "Keyboard shortcuts could not be read; the defaults are in use and changes are not saved: \(error.userMessage)"
        }
        reload()
    }

    /// The menu key equivalent for a command, or nil when it has none.
    func key(_ id: String) -> KeyboardShortcut? {
        guard !shadowed.contains(id), let chord = item(id)?.chord else { return nil }
        return Chords.keyboardShortcut(chord)
    }

    /// `⇧⌘P` for a command, or "" when it has none.
    func display(_ id: String) -> String {
        guard !shadowed.contains(id), let chord = item(id)?.chord else { return "" }
        return Chords.display(chord)
    }

    /// Tooltip text with the shortcut appended when there is one: "New folder (⇧⌘N)".
    func help(_ text: String, _ id: String) -> String {
        let keys = display(id)
        return keys.isEmpty ? text : "\(text) (\(keys))"
    }

    func item(_ id: String) -> ShortcutView? { items.first { $0.id == id } }

    func conflict(for id: String, chord: String) -> ShortcutConflict? {
        try? source?.conflict(id: id, chord: chord, platform: Self.platform)
    }

    enum Outcome { case saved, refused, taken(ShortcutConflict) }

    /// A recorded chord for `id`: saved, refused with the reason in `rejection` (worded here in
    /// ⌘ notation, never the core's neutral form), or taken by another command (ask first).
    func record(_ id: String, chord: String) -> Outcome {
        let keys = Chords.display(chord)
        let (mods, key) = Chords.parts(chord)
        if mods.isDisjoint(with: ["primary", "ctrl", "alt"]) && !key.hasPrefix("f") {
            rejection = "\(keys) needs ⌘, ⌃ or ⌥."
            return .refused
        }
        switch conflict(for: id, chord: chord) {
        case let c? where c.commandId == nil:
            rejection = "\(keys) is reserved for \(c.label)."
            return .refused
        case let c?:
            return .taken(c)
        case nil:
            return set(id, chord: chord) ? .saved : .refused
        }
    }

    /// Saved by the core; on rejection nothing changes and `rejection` says why.
    @discardableResult
    func set(_ id: String, chord: String?, replace: Bool = false) -> Bool {
        change { try $0.set(id: id, chord: chord, platform: Self.platform, replace: replace) }
    }

    func reset(_ id: String) { change { try $0.reset(id: id) } }
    func resetAll() { change { try $0.resetAll() } }

    /// Commands matching the query by label, group or keywords (core) or by the displayed keys.
    func search(_ query: String) -> [ShortcutView] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return items }
        let ids = Set(searchShortcuts(query: q))
        let keys = q.uppercased().replacingOccurrences(of: " ", with: "")
        return items.filter { ids.contains($0.id) || display($0.id).contains(keys) && !display($0.id).isEmpty }
    }

    @discardableResult
    private func change(_ body: (ShortcutsFile) throws -> Void) -> Bool {
        guard let file else {
            rejection = "Not saved: shortcuts.json could not be read."
            return false
        }
        do {
            try body(file)
            rejection = nil
            reload()
            return true
        } catch {
            rejection = error.userMessage
            return false
        }
    }

    private func reload() {
        items = (try? source?.list(platform: Self.platform)) ?? []
        shadowed = Set((try? source?.shadowed(platform: Self.platform)) ?? [])
    }
}

// MARK: Chords ⇄ AppKit

/// The core's neutral chords (`primary+shift+p`) as AppKit key equivalents and ⌘-style text.
enum Chords {
    private static let namedKeys: [String: (key: KeyEquivalent, glyph: String)] = [
        "return": (.return, "↩"), "tab": (.tab, "⇥"), "escape": (.escape, "⎋"), "space": (.space, "Space"),
        "delete": (.delete, "⌫"), "up": (.upArrow, "↑"), "down": (.downArrow, "↓"), "left": (.leftArrow, "←"),
        "right": (.rightArrow, "→"), "home": (.home, "↖"), "end": (.end, "↘"), "pageup": (.pageUp, "⇞"), "pagedown": (.pageDown, "⇟"),
    ]

    static func parts(_ chord: String) -> (mods: Set<String>, key: String) {
        // The key is everything after the last `+` (the core never stores `+` as a key).
        guard let plus = chord.lastIndex(of: "+") else { return ([], chord) }
        return (Set(chord[..<plus].split(separator: "+").map(String.init)), String(chord[chord.index(after: plus)...]))
    }

    private static func functionKey(_ key: String) -> Int? {
        guard key.hasPrefix("f"), let n = Int(key.dropFirst()), (1...12).contains(n) else { return nil }
        return n
    }

    static func keyboardShortcut(_ chord: String) -> KeyboardShortcut? {
        let (mods, key) = parts(chord)
        let equivalent: KeyEquivalent
        if let named = namedKeys[key] {
            equivalent = named.key
        } else if let n = functionKey(key), let scalar = UnicodeScalar(NSF1FunctionKey + n - 1) {
            equivalent = KeyEquivalent(Character(scalar))
        } else if key.count == 1, let c = key.first {
            equivalent = KeyEquivalent(c)
        } else {
            return nil
        }
        var modifiers: EventModifiers = []
        if mods.contains("primary") { modifiers.insert(.command) }
        if mods.contains("ctrl") { modifiers.insert(.control) }
        if mods.contains("alt") { modifiers.insert(.option) }
        if mods.contains("shift") { modifiers.insert(.shift) }
        return KeyboardShortcut(equivalent, modifiers: modifiers)
    }

    /// An `NSMenuItem` key equivalent and modifier mask for a chord.
    static func menuKey(_ chord: String) -> (String, NSEvent.ModifierFlags) {
        let (mods, key) = parts(chord)
        let named: [String: Int] = [
            "return": 0x0D, "tab": 0x09, "escape": 0x1B, "space": 0x20, "delete": 0x08,
            "up": NSUpArrowFunctionKey, "down": NSDownArrowFunctionKey, "left": NSLeftArrowFunctionKey, "right": NSRightArrowFunctionKey,
            "home": NSHomeFunctionKey, "end": NSEndFunctionKey, "pageup": NSPageUpFunctionKey, "pagedown": NSPageDownFunctionKey,
        ]
        let code = named[key] ?? functionKey(key).map { NSF1FunctionKey + $0 - 1 }
        let equivalent = code.flatMap(UnicodeScalar.init).map { String(Character($0)) } ?? key
        var mask: NSEvent.ModifierFlags = []
        if mods.contains("primary") { mask.insert(.command) }
        if mods.contains("ctrl") { mask.insert(.control) }
        if mods.contains("alt") { mask.insert(.option) }
        if mods.contains("shift") { mask.insert(.shift) }
        return (equivalent, mask)
    }

    /// macOS notation, modifiers in the system order: ⌃⌥⇧⌘.
    static func display(_ chord: String) -> String {
        let (mods, key) = parts(chord)
        let glyphs = [("ctrl", "⌃"), ("alt", "⌥"), ("shift", "⇧"), ("primary", "⌘")].filter { mods.contains($0.0) }.map(\.1).joined()
        let keyText = namedKeys[key]?.glyph ?? functionKey(key).map { "F\($0)" } ?? key.uppercased()
        return glyphs + keyText
    }

    private static let keyCodes: [UInt16: String] = [
        36: "return", 76: "return", 48: "tab", 53: "escape", 49: "space", 51: "delete", 123: "left", 124: "right",
        125: "down", 126: "up", 115: "home", 119: "end", 116: "pageup", 121: "pagedown",
        122: "f1", 120: "f2", 99: "f3", 118: "f4", 96: "f5", 97: "f6", 98: "f7", 100: "f8", 101: "f9", 109: "f10", 103: "f11", 111: "f12",
    ]

    /// The neutral chord for a key press, or nil for a key the core does not accept. The key is
    /// read without modifiers, so ⇧⌘1 records `1`, not `!`, on any layout.
    @MainActor static func chord(from event: NSEvent) -> String? {
        let key: String
        if let named = keyCodes[event.keyCode] {
            key = named
        } else if let c = event.characters(byApplyingModifiers: [])?.lowercased(), c.count == 1 {
            key = c
        } else {
            return nil
        }
        let flags = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
        let mods = [(NSEvent.ModifierFlags.command, "primary"), (.control, "ctrl"), (.option, "alt"), (.shift, "shift")]
            .filter { flags.contains($0.0) }.map(\.1)
        return (mods + [key]).joined(separator: "+")
    }
}
