import AppKit

/// Decides whether a key press goes to the RDP server as typed text (Unicode) or as a scancode.
enum RdpKeyText {
    enum Kind: Equatable { case text(String), deadKey, scancode }

    static let capsLock: UInt16 = 0x39
    /// The left-hand key for each modifier, pressed when the server lacks a modifier held here.
    static let leftModifier: [(NSEvent.ModifierFlags, UInt16)] = [
        (.shift, 0x38), (.control, 0x3B), (.option, 0x3A), (.command, 0x37),
    ]
    /// Keys that type whitespace or control characters but must stay keys (Return, Tab, Space,
    /// Delete, Escape, keypad Enter), so shortcuts and auto-repeat behave as on a PC keyboard.
    private static let alwaysScancode: Set<UInt16> = [0x24, 0x30, 0x31, 0x33, 0x35, 0x4C, 0x75]

    static func classify(characters: String?, flags: NSEvent.ModifierFlags, keyCode: UInt16) -> Kind {
        if alwaysScancode.contains(keyCode) || flags.contains(.control) || flags.contains(.command) {
            return .scancode
        }
        guard let characters else { return .scancode }
        // An empty string is a dead key (Option-E, Option-U …): the next key carries the accent.
        if characters.isEmpty { return flags.contains(.option) ? .deadKey : .scancode }
        let printable = characters.unicodeScalars.allSatisfy { scalar in
            scalar.value >= 0x20 && scalar.value != 0x7F && !(0xF700...0xF8FF).contains(scalar.value)
        }
        return printable ? .text(characters) : .scancode
    }
}
