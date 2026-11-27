import Foundation

// Transcript viewer (LOG-NATIVE-01 item 4, Native Mac): reads a session log in pages, splits it
// into lines, strips terminal control sequences, finds the time column and searches. Foundation
// only, so `tests/transcript-test.sh` builds it without the app. Read-only: nothing writes the file.

/// One line of a transcript. `time` is the leading timestamp when the line has one.
struct TranscriptLine: Identifiable, Equatable, Sendable {
    let id: Int // 0-based line number
    let time: String?
    let text: String

    /// The line as shown: with or without its time column.
    func display(showTimes: Bool) -> String {
        guard showTimes, let time else { return text }
        return time + "  " + text
    }
}

enum TranscriptText {
    /// Bytes read per page. A 60 MB log arrives in 60 pages; the window stays responsive between them.
    static let pageBytes = 1 << 20

    /// The agreed window title: "<connection> — <started>".
    static func title(connection: String, started: Date) -> String {
        "\(connection) — \(started.formatted(date: .abbreviated, time: .shortened))"
    }

    /// Reads `url` page by page, calling `page` with the new lines of each. Stops when `page`
    /// returns false (the viewer closed). Throws when the file cannot be opened or read.
    static func read(_ url: URL, pageBytes: Int = pageBytes, page: ([TranscriptLine]) -> Bool) throws {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var carry = Data()
        var next = 0
        while true {
            let chunk = try handle.read(upToCount: pageBytes) ?? Data()
            let atEnd = chunk.isEmpty
            carry.append(chunk)
            var body = carry
            if atEnd {
                carry = Data()
            } else if let cut = carry.lastIndex(of: 0x0A) {
                body = carry[carry.startIndex...cut]
                carry = Data(carry[carry.index(after: cut)...])
            } else {
                continue // no full line yet
            }
            let lines = split(body, firstNumber: next)
            next += lines.count
            if !lines.isEmpty, !page(lines) { return }
            if atEnd { return }
        }
    }

    /// Splits bytes into lines (invalid UTF-8 is replaced, not dropped).
    static func split(_ data: Data, firstNumber: Int) -> [TranscriptLine] {
        let text = String(decoding: data, as: UTF8.self)
        // By scalar, not Character: "\r\n" is one Character and would not split on "\n".
        var parts = text.components(separatedBy: "\n")
        if parts.last == "" { parts.removeLast() }
        return parts.enumerated().map { i, raw in
            let clean = strip(raw)
            let (time, rest) = splitTime(clean)
            return TranscriptLine(id: firstNumber + i, time: time, text: rest)
        }
    }

    /// Removes terminal control sequences (CSI, OSC, other ESC pairs), carriage returns and
    /// other control characters except tab.
    static func strip(_ s: String) -> String {
        guard s.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) else { return s }
        var out = String.UnicodeScalarView()
        var it = s.unicodeScalars.makeIterator()
        while let c = it.next() {
            if c == "\u{1B}" {
                guard let n = it.next() else { break }
                if n == "[" { // CSI: parameters, then a final byte 0x40–0x7E
                    while let p = it.next(), !(0x40...0x7E).contains(p.value) {}
                } else if n == "]" { // OSC: ends with BEL or ESC \
                    while let p = it.next() {
                        if p == "\u{07}" { break }
                        if p == "\u{1B}" { _ = it.next(); break }
                    }
                } // other ESC x pairs: both dropped
                continue
            }
            if c == "\t" || c.value >= 0x20 && c.value != 0x7F { out.append(c) }
        }
        return String(out)
    }

    private static let timePattern = try! NSRegularExpression(
        pattern: #"^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\]?[ \t]"#)

    /// A leading ISO 8601 or `[hh:mm:ss]` timestamp and the rest of the line.
    static func splitTime(_ line: String) -> (String?, String) {
        let ns = line as NSString
        guard let m = timePattern.firstMatch(in: line, range: NSRange(location: 0, length: min(ns.length, 48))) else { return (nil, line) }
        return (ns.substring(with: m.range(at: 1)), ns.substring(from: m.range.length))
    }

    /// Whether the transcript has a time column worth a toggle.
    static func hasTimes(_ lines: [TranscriptLine]) -> Bool {
        lines.prefix(200).contains { $0.time != nil }
    }

    /// Line numbers containing `query` (case-insensitive), in order.
    static func find(_ query: String, in lines: [TranscriptLine]) -> [Int] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return [] }
        return lines.compactMap { $0.text.localizedCaseInsensitiveContains(q) || ($0.time?.contains(q) ?? false) ? $0.id : nil }
    }

    /// Where Find Next (or Previous) lands from `current`, wrapping round.
    static func step(_ hits: [Int], from current: Int?, forward: Bool) -> Int? {
        guard !hits.isEmpty else { return nil }
        guard let current else { return forward ? hits.first : hits.last }
        if forward { return hits.first { $0 > current } ?? hits.first }
        return hits.last { $0 < current } ?? hits.last
    }

    /// Text for Copy: the chosen lines, or all lines when none are chosen.
    static func copyText(_ lines: [TranscriptLine], selected: Set<Int>, showTimes: Bool) -> String {
        let picked = selected.isEmpty ? lines : lines.filter { selected.contains($0.id) }
        return picked.map { $0.display(showTimes: showTimes) }.joined(separator: "\n")
    }
}
