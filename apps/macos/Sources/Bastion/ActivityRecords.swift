import Foundation

// Activity log (LOG-NATIVE-01, Native Mac): the session history rows the core returns from
// `activity_query_json`, the filter sent to it, and the text the page shows and exports.
// Foundation only, so `tests/activity-test.sh` builds it without the app.

/// One session as `activity_query_json` returns it (camelCase fields of the core's SessionSummary).
struct ActivityRecord: Decodable, Identifiable, Equatable {
    let sessionId: String
    let connectionId: String
    let connectionName: String
    let protocolName: String
    let host: String
    let port: Int?
    let username: String?
    let startedAt: UInt64
    let open: Bool
    let durationMs: UInt64?
    let endReason: String?
    let reconnects: Int?
    let transcriptPath: String?

    var id: String { sessionId }

    enum CodingKeys: String, CodingKey {
        case sessionId, connectionId, connectionName, host, port, username, startedAt, open
        case durationMs, endReason, reconnects, transcriptPath
        case protocolName = "protocol"
    }

    var startDate: Date { Date(timeIntervalSince1970: TimeInterval(startedAt) / 1000) }
    var isOk: Bool { !open && ActivityRecord.okReasons.contains(endReason ?? "") }
    var isFailed: Bool { !open && !isOk }

    /// The core's `EndReason::is_ok`.
    static let okReasons: Set<String> = ["closed_by_user", "remote_closed", "app_quit"]

    /// Short result text for the Result column.
    var resultText: String {
        if open { return "Open" }
        switch endReason {
        case "closed_by_user": return "Closed"
        case "remote_closed": return "Closed by host"
        case "network_lost": return "Network lost"
        case "auth_failed": return "Sign-in failed"
        case "host_key": return "Host key rejected"
        case "timeout": return "Timed out"
        case "app_quit": return "App quit"
        case "app_crashed": return "App stopped"
        case "failed": return "Failed"
        default: return "Unknown"
        }
    }

    var target: String { port.map { "\(host):\($0)" } ?? host }

    var durationText: String { durationMs.map(ActivityRecord.duration) ?? (open ? "—" : "") }

    /// "45 s", "12 min", "3 h 05 min".
    static func duration(_ ms: UInt64) -> String {
        let s = ms / 1000
        if s < 60 { return "\(s) s" }
        if s < 3600 { return "\(s / 60) min" }
        return String(format: "%d h %02d min", s / 3600, (s % 3600) / 60)
    }

    /// Free-text search over the visible text columns.
    func matches(_ text: String) -> Bool {
        let t = text.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty else { return true }
        return [connectionName, protocolName, target, username ?? "", resultText].contains { $0.localizedCaseInsensitiveContains(t) }
    }
}

/// The page's filters. Date, protocol, user and result go to the core; free text is applied here.
struct ActivityFilter: Equatable {
    enum Range: String, CaseIterable, Identifiable {
        case all = "All time", day = "Last 24 hours", week = "Last 7 days", month = "Last 30 days"
        var id: String { rawValue }
        var seconds: TimeInterval? {
            switch self {
            case .all: nil
            case .day: 86_400
            case .week: 7 * 86_400
            case .month: 30 * 86_400
            }
        }
    }

    enum Result: String, CaseIterable, Identifiable {
        case all = "Any result", ok = "OK", failed = "Failed", open = "Open"
        var id: String { rawValue }
        var core: String? {
            switch self {
            case .all: nil
            case .ok: "ok"
            case .failed: "failed"
            case .open: "open"
            }
        }
    }

    /// Protocols the core records (`SessionStart.protocol`); empty means all.
    static let protocols = ["ssh", "sftp", "scp", "ftps", "rdp", "vnc", "telnet", "serial", "local"]

    /// History of one connection or one folder (with its subfolders); nil is every session.
    enum Scope: Equatable {
        case connection(id: String, name: String)
        case folder(id: String, name: String)
        var title: String {
            switch self {
            case .connection(_, let n): "History of \(n)"
            case .folder(_, let n): "History of \(n) and subfolders"
            }
        }
    }

    var scope: Scope?
    var range: Range = .all
    var protocolName = ""
    var user = ""
    var result: Result = .all
    var text = ""

    /// The JSON for `activity_query_json`. Only set fields are sent.
    func coreJSON(now: Date = Date()) -> String {
        var object: [String: Any] = [:]
        switch scope {
        case .connection(let id, _): object["connection"] = id
        case .folder(let id, _): object["folder"] = id
        case nil: break
        }
        if let s = range.seconds { object["from"] = UInt64((now.timeIntervalSince1970 - s) * 1000) }
        if !protocolName.isEmpty { object["protocol"] = protocolName }
        let u = user.trimmingCharacters(in: .whitespaces)
        if !u.isEmpty { object["user"] = u }
        if let r = result.core { object["result"] = r }
        let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data("{}".utf8)
        return String(decoding: data, as: UTF8.self)
    }
}

enum ActivityExport {
    static let columns = ["Started", "Connection", "Protocol", "Host", "User", "Duration", "Result"]

    static func fields(_ r: ActivityRecord) -> [String] {
        [iso(r.startDate), r.connectionName, r.protocolName, r.target, r.username ?? "", r.durationText, r.resultText]
    }

    /// CSV of exactly the rows shown (RFC 4180 quoting). Cells that a spreadsheet would run as a
    /// formula are prefixed with an apostrophe.
    static func csv(_ rows: [ActivityRecord]) -> String {
        ([columns] + rows.map(fields)).map { $0.map(cell).joined(separator: ",") }.joined(separator: "\r\n") + "\r\n"
    }

    /// JSON of exactly the rows shown, with the same columns as the CSV.
    static func json(_ rows: [ActivityRecord]) -> String {
        let objects = rows.map { Dictionary(uniqueKeysWithValues: zip(columns, fields($0))) }
        let data = (try? JSONSerialization.data(withJSONObject: objects, options: [.prettyPrinted, .sortedKeys])) ?? Data("[]".utf8)
        return String(decoding: data, as: UTF8.self)
    }

    static func cell(_ s: String) -> String {
        var v = s
        if let first = v.first, "=+-@\t\r".contains(first) { v = "'" + v }
        guard v.contains(where: { ",\"\r\n".contains($0) }) else { return v }
        return "\"" + v.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }

    static func iso(_ d: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.string(from: d)
    }

    static func decode(_ json: String) throws -> [ActivityRecord] {
        try JSONDecoder().decode([ActivityRecord].self, from: Data(json.utf8))
    }
}
