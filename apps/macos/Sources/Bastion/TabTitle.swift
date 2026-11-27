import Foundation

/// A terminal program's title (OSC 0/2) as an unsaved tab's name. The title is text any program in
/// the session (or a server it reaches) can set, so it is cleaned before the tab strip, the sidebar
/// and the window title show it.
enum TabTitle {
    /// Longest name shown; the strip shrinks wider titles anyway, and a long one only hides others.
    static let maxLength = 60

    /// Control characters, bidi controls and zero-width characters removed, trimmed, capped at
    /// `maxLength` characters (the last one an ellipsis). Nil when nothing readable is left.
    static func sanitized(_ title: String?) -> String? {
        guard let title else { return nil }
        let kept = title.unicodeScalars.filter { !isHidden($0) }
        let text = String(String.UnicodeScalarView(kept)).trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return nil }
        guard text.count > maxLength else { return text }
        return String(text.prefix(maxLength - 1)) + "…"
    }

    /// The name a tab shows: a saved connection keeps its own name; an unsaved terminal (local
    /// shell, quick connect) follows its program's title and falls back to `name` when it is unset.
    static func display(name: String, program: String?, isSaved: Bool) -> String {
        guard !isSaved, let program = marked(program) else { return name }
        return program
    }

    /// SEC-7: marks a name a terminal program set, so it never passes as a Bastion label.
    static let programMark = "\u{203A} "

    /// A program title as a tab shows it: sanitized, leading symbols (a fake bell, dot or mark)
    /// dropped, then `programMark` in front. Nil when nothing readable is left.
    static func marked(_ title: String?) -> String? {
        guard let clean = sanitized(title) else { return nil }
        let body = String(clean.drop { c in c.isWhitespace || c.unicodeScalars.contains { isLeadSymbol($0) } })
        return body.isEmpty ? nil : programMark + body
    }

    /// SEC-7: heading and body of a program (OSC 9/777) notification. The heading always names
    /// the tab's own source (connection or shell) and says it came from the terminal.
    static func programNotice(source: String, title: String, body: String) -> (title: String, body: String) {
        let t = sanitized(title) ?? "", b = sanitized(body) ?? ""
        let text = t.isEmpty ? b : (b.isEmpty || b == t ? t : t + ": " + b)
        return (source + " \u{00B7} terminal", text)
    }

    private static func isLeadSymbol(_ s: Unicode.Scalar) -> Bool {
        if s.value == 0x203A || s.value == 0xFE0F { return true }
        switch s.properties.generalCategory {
        case .otherSymbol, .mathSymbol, .modifierSymbol, .initialPunctuation, .finalPunctuation: return true
        default: return false
        }
    }

    private static func isHidden(_ s: Unicode.Scalar) -> Bool {
        switch s.value {
        case 0x00...0x1F, 0x7F...0x9F: true                       // C0, DEL, C1
        case 0x200B...0x200F, 0x202A...0x202E, 0x2060...0x2069, 0xFEFF: true  // zero-width, bidi
        default: false
        }
    }
}
