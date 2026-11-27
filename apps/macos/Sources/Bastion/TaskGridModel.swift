import Foundation

/// Results grid for Tasks (design A): one row per host, rows with the same output folded into a
/// group, a line diff of two rows and a labelled copy. Pure Foundation so the unit test can build
/// it without the app.
enum GridStatus: Equatable {
    case waiting, running, ok, failed
}

struct TaskGridRow: Identifiable, Equatable {
    /// The connection id.
    let id: String
    let host: String
    /// Core state: `waiting`, `starting`, `running`, `done`, `failed` or `cancelled`.
    var state: String
    var exit: Int?
    var stdout = ""
    var stderr = ""
    var error: String?
    var millis: UInt64 = 0

    var status: GridStatus {
        switch state {
        case "waiting", "starting": .waiting
        case "running": .running
        case "done": exit == 0 ? .ok : .failed
        default: .failed
        }
    }

    var isFinished: Bool { status == .ok || status == .failed }

    /// Everything the host printed, stderr after stdout, then the error.
    var output: String {
        [stdout, stderr, error ?? ""].filter { !$0.isEmpty }
            .map { $0.hasSuffix("\n") ? String($0.dropLast()) : $0 }.joined(separator: "\n")
    }

    /// The line shown in the grid: the last non-empty line, or the first one of an error.
    var summary: String {
        if let error, !error.isEmpty { return TaskGrid.firstLine(error) }
        if status == .failed, stdout.isEmpty, !stderr.isEmpty { return TaskGrid.firstLine(stderr) }
        return TaskGrid.lastLine(output)
    }

    var isTruncated: Bool { output.contains(TaskGrid.truncatedMarker) }
}

/// Rows whose finished output is the same.
struct GridGroup: Identifiable, Equatable {
    let rows: [TaskGridRow]
    var id: String { rows.map(\.id).joined(separator: ",") }
    var first: TaskGridRow { rows[0] }
    var isGroup: Bool { rows.count > 1 }
    var title: String { isGroup ? "\(rows.count) hosts" : first.host }
}

enum DiffLine: Equatable {
    case same(String), left(String), right(String)
}

enum TaskGrid {
    /// What the core appends when it cut a host's output (`multiexec::capture`).
    static let truncatedMarker = "[output truncated by Gantry]"
    /// Lines per side compared at most; beyond that the rest is shown as changed.
    static let maxDiffLines = 2000

    static func firstLine(_ s: String) -> String {
        s.split(whereSeparator: \.isNewline).first.map(String.init)?.trimmingCharacters(in: .whitespaces) ?? ""
    }

    static func lastLine(_ s: String) -> String {
        s.split(whereSeparator: \.isNewline).last { !$0.allSatisfy(\.isWhitespace) }.map(String.init)?.trimmingCharacters(in: .whitespaces) ?? ""
    }

    /// Finished rows with the same status, exit code and output share a group; rows still running
    /// stay alone. Order follows the first row of each group.
    static func groups(_ rows: [TaskGridRow]) -> [GridGroup] {
        var order: [String] = []
        var byKey: [String: [TaskGridRow]] = [:]
        for r in rows {
            let key = r.isFinished ? "\(r.status)|\(r.exit.map(String.init) ?? "-")|\(r.output)" : "live|\(r.id)"
            if byKey[key] == nil { order.append(key) }
            byKey[key, default: []].append(r)
        }
        return order.compactMap { byKey[$0].map(GridGroup.init) }
    }

    /// Line diff (longest common subsequence) of two outputs.
    static func diff(_ a: String, _ b: String) -> [DiffLine] {
        let l = lines(a), r = lines(b)
        let lc = Array(l.prefix(maxDiffLines)), rc = Array(r.prefix(maxDiffLines))
        let n = lc.count, m = rc.count
        var t = Array(repeating: Array(repeating: 0, count: m + 1), count: n + 1)
        for i in stride(from: n - 1, through: 0, by: -1) {
            for j in stride(from: m - 1, through: 0, by: -1) {
                t[i][j] = lc[i] == rc[j] ? t[i + 1][j + 1] + 1 : max(t[i + 1][j], t[i][j + 1])
            }
        }
        var out: [DiffLine] = []
        var i = 0, j = 0
        while i < n && j < m {
            if lc[i] == rc[j] { out.append(.same(lc[i])); i += 1; j += 1 }
            else if t[i + 1][j] >= t[i][j + 1] { out.append(.left(lc[i])); i += 1 }
            else { out.append(.right(rc[j])); j += 1 }
        }
        out += lc[i...].map(DiffLine.left) + rc[j...].map(DiffLine.right)
        out += l.dropFirst(maxDiffLines).map(DiffLine.left) + r.dropFirst(maxDiffLines).map(DiffLine.right)
        return out
    }

    private static func lines(_ s: String) -> [String] {
        var ls = s.components(separatedBy: "\n")
        if ls.last == "" { ls.removeLast() }
        return ls
    }

    /// Every host's output under a header line, for the clipboard.
    static func labelled(_ rows: [TaskGridRow]) -> String {
        rows.map { r in
            let exit = r.exit.map { "exit \($0)" } ?? r.state
            return "== \(r.host) (\(exit), \(duration(r.millis))) ==\n\(r.output)"
        }
        .joined(separator: "\n\n")
    }

    static func duration(_ millis: UInt64) -> String {
        if millis < 1000 { return "\(millis) ms" }
        if millis < 60_000 { return String(format: "%.1f s", Double(millis) / 1000) }
        return "\(millis / 60_000) m \(millis / 1000 % 60) s"
    }

    /// A row still running after `limit` seconds: offer the terminal instead of waiting on it.
    static func isOvertime(_ row: TaskGridRow, runningFor seconds: TimeInterval, limit: TimeInterval) -> Bool {
        !row.isFinished && seconds >= limit
    }

    /// "3 ok · 1 failed", for a task card's last result.
    static func tally(_ rows: [TaskGridRow]) -> String {
        let ok = rows.filter { $0.status == .ok }.count
        let failed = rows.filter { $0.status == .failed }.count
        let busy = rows.count - ok - failed
        return [ok > 0 ? "\(ok) ok" : nil, failed > 0 ? "\(failed) failed" : nil, busy > 0 ? "\(busy) running" : nil]
            .compactMap { $0 }.joined(separator: " · ")
    }
}
