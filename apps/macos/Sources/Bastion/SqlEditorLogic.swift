import Foundation

/// PLUG-06c (Native Mac): the code editor's decisions that need no AppKit and no core, so the
/// unit test (`tests/sql-editor-logic-test.sh`) compiles this file alone. Offsets are UTF-16
/// units, as `NSString` and the core's `utf16_*` spans count.
enum SqlEditorLogic {
    /// What a token kind is drawn as; the view maps a role to a system colour (light and dark).
    enum Role: Equatable { case keyword, string, number, comment, type, function, parameter, error, plain }

    static func role(_ kind: String) -> Role {
        switch kind {
        case "keyword": .keyword
        case "string": .string
        case "number": .number
        case "comment": .comment
        case "type": .type
        case "function": .function
        case "parameter": .parameter
        case "error": .error
        default: .plain // identifier, quoted-identifier, operator, punctuation, text, unknown
        }
    }

    /// UTF-16 offset where each line starts (`\n` separated); always at least one line.
    static func lineStarts(_ s: NSString) -> [Int] {
        var starts = [0]
        let n = s.length
        guard n > 0 else { return starts }
        var buf = [unichar](repeating: 0, count: n)
        s.getCharacters(&buf, range: NSRange(location: 0, length: n))
        for i in 0..<n where buf[i] == 0x0A { starts.append(i + 1) }
        return starts
    }

    /// Index of the line holding UTF-16 offset `at` (binary search over `starts`).
    static func line(of at: Int, in starts: [Int]) -> Int {
        var lo = 0, hi = starts.count - 1
        while lo < hi {
            let mid = (lo + hi + 1) / 2
            if starts[mid] <= at { lo = mid } else { hi = mid - 1 }
        }
        return lo
    }

    /// The end states after an edit: the old list with the edited lines' entries replaced by
    /// placeholders, so its count equals the new line count. `first...lastNew` are the edited lines
    /// in the new text; `delta` the change in line count.
    static func splice(_ states: [String], first: Int, lastNew: Int, delta: Int, placeholder: String = "\u{1}") -> [String] {
        let lastOld = lastNew - delta
        guard first <= states.count, first <= lastNew else { return states }
        let head = Array(states[..<min(first, states.count)])
        let tail = lastOld + 1 < states.count ? Array(states[(lastOld + 1)...]) : []
        return head + Array(repeating: placeholder, count: lastNew - first + 1) + tail
    }

    /// Re-colours from line `first` down: always through `mustReach`, then until a line's new end
    /// state equals the one it had. `tokenize(line, stateBefore)` colours one line and returns its
    /// end state. Returns the new states and the last line coloured.
    static func recolour(states: [String], first: Int, mustReach: Int, tokenize: (Int, String) -> String) -> (states: [String], last: Int) {
        var out = states
        var i = first
        var last = first
        while i < out.count {
            let before = i == 0 ? "" : out[i - 1]
            let end = tokenize(i, before)
            let unchanged = out[i] == end
            out[i] = end
            last = i
            if i >= mustReach && unchanged { break }
            i += 1
        }
        return (out, last)
    }

    /// The text after a completion replaces `start..<start+length` with `insert`, and the caret.
    static func applyCompletion(_ text: String, start: Int, length: Int, insert: String) -> (text: String, caret: Int) {
        let ns = text as NSString
        let s = max(0, min(start, ns.length)), l = max(0, min(length, ns.length - s))
        return (ns.replacingCharacters(in: NSRange(location: s, length: l), with: insert), s + (insert as NSString).length)
    }

    /// The popup's selection after an arrow key; stays inside the list, no wrap.
    static func move(_ index: Int, by step: Int, count: Int) -> Int {
        guard count > 0 else { return 0 }
        return max(0, min(count - 1, index + step))
    }

    /// Ask the plugin again only when the word being completed starts somewhere new; while the
    /// user types on in the same word the last answer is re-ranked in the app.
    static func needsNewAsk(previousStart: Int?, start: Int) -> Bool { previousStart != start }

    /// Whether a typed string should open completions on its own (a letter, digit, `_` or `.`).
    static func triggersCompletion(_ typed: String) -> Bool {
        guard typed.count == 1, let c = typed.unicodeScalars.first else { return false }
        return CharacterSet.alphanumerics.contains(c) || c == "_" || c == "."
    }

    /// What ⌘↩ runs: the selection when there is one, else the whole text.
    static func runText(_ text: String, selection: NSRange) -> String {
        let ns = text as NSString
        guard selection.length > 0, NSMaxRange(selection) <= ns.length else { return text }
        return ns.substring(with: selection)
    }

    /// ⌘/: comments the lines touched by `selection` with `-- `, or removes it when every
    /// non-empty one already starts with `--`. Returns the new text and the range of those lines.
    static func toggleComment(_ text: String, selection: NSRange) -> (text: String, lines: NSRange) {
        let ns = text as NSString
        let sel = NSRange(location: min(selection.location, ns.length), length: max(0, min(selection.length, ns.length - min(selection.location, ns.length))))
        var range = ns.lineRange(for: sel)
        // A selection ending at a line's start does not take that line.
        if sel.length > 0, NSMaxRange(sel) > 0, NSMaxRange(sel) < NSMaxRange(range),
           ns.character(at: NSMaxRange(sel) - 1) == 0x0A {
            range = ns.lineRange(for: NSRange(location: sel.location, length: sel.length - 1))
        }
        let block = ns.substring(with: range)
        let hasBreak = block.hasSuffix("\n")
        var lines = block.components(separatedBy: "\n")
        if hasBreak { lines.removeLast() }
        let filled = lines.filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        let uncomment = !filled.isEmpty && filled.allSatisfy { $0.trimmingCharacters(in: .whitespaces).hasPrefix("--") }
        let changed = lines.map { line -> String in
            if uncomment {
                guard let r = line.range(of: "--") else { return line }
                var rest = line[r.upperBound...]
                if rest.hasPrefix(" ") { rest = rest.dropFirst() }
                return String(line[..<r.lowerBound]) + rest
            }
            return line.trimmingCharacters(in: .whitespaces).isEmpty ? line : "-- " + line
        }
        let newBlock = changed.joined(separator: "\n") + (hasBreak ? "\n" : "")
        let out = ns.replacingCharacters(in: range, with: newBlock)
        return (out, NSRange(location: range.location, length: (newBlock as NSString).length))
    }
}
