// Prints, for a Mac input source, the character each key types with no modifier, Shift, Option and
// Shift+Option (what NSEvent.characters gives the RDP view): `swift mac-layout-table.swift com.apple.keylayout.British`.
// Lines are `<keycode-hex> <modifier> <utf8-hex>`; dead keys and non-printing results are left out.
import Carbon

let id = CommandLine.arguments.dropFirst().first ?? "com.apple.keylayout.US"
let filter = [kTISPropertyInputSourceID as String: id] as CFDictionary
guard let list = TISCreateInputSourceList(filter, true)?.takeRetainedValue() as? [TISInputSource], let source = list.first,
      let raw = TISGetInputSourceProperty(source, kTISPropertyUnicodeKeyLayoutData) else {
    FileHandle.standardError.write("no layout \(id)\n".data(using: .utf8)!); exit(1)
}
let data = Unmanaged<CFData>.fromOpaque(raw).takeUnretainedValue() as Data
// The keys the RDP view types as text: letters, digits, punctuation, ISO § key and the keypad.
let codes: [UInt16] = Array(0x00...0x32).filter { ![0x24, 0x30, 0x31].contains($0) } + [0x41, 0x43, 0x45, 0x4B, 0x4E, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5B, 0x5C]
let mods: [(String, UInt32)] = [("none", 0), ("shift", UInt32(shiftKey >> 8)), ("option", UInt32(optionKey >> 8)), ("shift-option", UInt32((shiftKey | optionKey) >> 8))]
data.withUnsafeBytes { buf in
    let layout = buf.baseAddress!.assumingMemoryBound(to: UCKeyboardLayout.self)
    for code in codes {
        for (name, m) in mods {
            var dead: UInt32 = 0
            var chars = [UniChar](repeating: 0, count: 8)
            var n = 0
            UCKeyTranslate(layout, code, UInt16(kUCKeyActionDown), m, UInt32(LMGetKbdType()), OptionBits(kUCKeyTranslateNoDeadKeysBit), &dead, 8, &n, &chars)
            let s = String(utf16CodeUnits: chars, count: n)
            guard dead == 0, !s.isEmpty, s.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F && !(0xF700...0xF8FF).contains($0.value) }) else { continue }
            print(String(format: "%02x", code), name, s.utf8.map { String(format: "%02x", $0) }.joined())
        }
    }
}
