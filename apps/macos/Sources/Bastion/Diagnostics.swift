import Foundation

// Help ▸ Export Diagnostics… (LOG-NATIVE-01 item 7, Native Mac) and the app's own small log.
// Foundation only, so `tests/diagnostics-test.sh` builds it without the app. The zip holds no host
// name, user name, password or key: settings keep only true/false and numbers, the library gives
// counts only, and the logs have the home folder and account name replaced. It stays local.

/// The app's own log: info, warn and error lines in `bastion.log` next to the library, capped at
/// `maxBytes` with one older file kept. Callers never pass secrets, host names or user names.
enum AppLog {
    enum Level: String { case debug = "DEBUG", info = "INFO", warn = "WARN", error = "ERROR" }

    /// Detailed logging (LOG-ERRCODES): debug lines are written only while this is on.
    nonisolated(unsafe) static var detailed = false
    /// Cleans every debug and error line (the app sets the core's `logRedact`). Identity in the
    /// Foundation-only test build.
    nonisolated(unsafe) static var redactor: (String) -> String = { $0 }

    static let maxBytes = 512 * 1024
    nonisolated(unsafe) static var url: URL?
    private static let lock = NSLock()

    static func info(_ message: String) { write(.info, message) }
    static func warn(_ message: String) { write(.warn, message) }
    static func error(_ message: String) { write(.error, message) }
    /// Only with Detailed logging on. Never pass secrets or keystrokes; the line is redacted too.
    static func debug(_ message: @autoclosure () -> String) {
        guard detailed else { return }
        write(.debug, redactor(message()))
    }
    /// An error shown to the user, with its support code, redacted.
    static func failure(code: String, _ message: String) { write(.error, "\(code) \(redactor(message))") }

    static func write(_ level: Level, _ message: String, now: Date = Date()) {
        guard let url else { return }
        let line = "\(ISO8601DateFormatter().string(from: now)) \(level.rawValue) \(message.replacingOccurrences(of: "\n", with: " "))\n"
        lock.lock(); defer { lock.unlock() }
        let fm = FileManager.default
        if let size = (try? fm.attributesOfItem(atPath: url.path))?[.size] as? Int, size + line.utf8.count > maxBytes {
            let old = url.appendingPathExtension("1")
            try? fm.removeItem(at: old)
            try? fm.moveItem(at: url, to: old)
        }
        if let handle = try? FileHandle(forWritingTo: url) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: Data(line.utf8))
        } else {
            try? Data(line.utf8).write(to: url)
        }
    }
}

/// Library counts for the summary. No names.
struct DiagnosticsCounts: Equatable {
    var folders = 0
    var connections = 0
    var byProtocol: [String: Int] = [:]
}

enum DiagnosticsBundle {
    /// What the save dialog says is inside.
    static let contents = "app and macOS version, the app's log, the last crash report, settings without secrets or names, and library counts (no names)"

    /// Settings with every text value replaced: only true/false, numbers and the keys stay.
    static func redactSettings(_ data: Data) -> String {
        guard let obj = try? JSONSerialization.jsonObject(with: data) else { return "{}\n" }
        let clean = redact(obj)
        guard let out = try? JSONSerialization.data(withJSONObject: clean, options: [.prettyPrinted, .sortedKeys]) else { return "{}\n" }
        return String(decoding: out, as: UTF8.self) + "\n"
    }

    private static func redact(_ v: Any) -> Any {
        switch v {
        case let d as [String: Any]: return d.mapValues(redact)
        case let a as [Any]: return a.map(redact)
        case let n as NSNumber: return n // also true/false
        case let s as String: return s.isEmpty ? "" : "(set)"
        default: return NSNull()
        }
    }

    /// Replaces the home folder and the account name in a log.
    static func scrub(_ text: String, home: String, user: String) -> String {
        var out = text
        if !home.isEmpty { out = out.replacingOccurrences(of: home, with: "~") }
        if user.count >= 2 { out = out.replacingOccurrences(of: user, with: "(user)", options: .caseInsensitive) }
        return out
    }

    static func summary(version: String, build: String, os: String, counts: DiagnosticsCounts, created: Date, detailedLog: Bool = false) -> String {
        var lines = [
            "Gantry diagnostics",
            "Created: \(ISO8601DateFormatter().string(from: created))",
            "App version: \(version) (\(build))",
            "macOS: \(os)",
            "Folders: \(counts.folders)",
            "Connections: \(counts.connections)",
            "Detailed logging: \(detailedLog ? "on" : "off")",
        ]
        lines += counts.byProtocol.keys.sorted().map { "  \($0): \(counts.byProtocol[$0] ?? 0)" }
        return lines.joined(separator: "\n") + "\n"
    }

    /// The newest Bastion crash report in `dir`, if any.
    static func latestCrash(in dir: URL) -> URL? {
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.contentModificationDateKey])) ?? []
        return files
            .filter { $0.lastPathComponent.hasPrefix("Gantry") || $0.lastPathComponent.hasPrefix("Bastion") && ["ips", "crash"].contains($0.pathExtension) }
            .max { date($0) < date($1) }
    }

    private static func date(_ url: URL) -> Date {
        (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
    }

    struct Inputs {
        var summary: String
        var settings: URL
        var logs: [URL] // the app log and its older file
        var crash: URL?
        var home: String
        var user: String
    }

    /// Writes the bundle's files into `folder` (which must exist).
    static func stage(_ inputs: Inputs, into folder: URL) throws {
        func put(_ name: String, _ text: String) throws {
            try text.write(to: folder.appendingPathComponent(name), atomically: true, encoding: .utf8)
        }
        try put("summary.txt", inputs.summary)
        try put("settings.json", redactSettings((try? Data(contentsOf: inputs.settings)) ?? Data("{}".utf8)))
        for log in inputs.logs {
            guard let text = try? String(contentsOf: log, encoding: .utf8) else { continue }
            try put(log.lastPathComponent, scrub(text, home: inputs.home, user: inputs.user))
        }
        if let crash = inputs.crash, let data = try? Data(contentsOf: crash) {
            try put("last-crash." + crash.pathExtension, scrub(String(decoding: data, as: UTF8.self), home: inputs.home, user: inputs.user))
        }
    }

    /// Stages the bundle and zips it to `zip` with `ditto` (offline, part of macOS).
    static func write(_ inputs: Inputs, to zip: URL) throws {
        let fm = FileManager.default
        let work = fm.temporaryDirectory.appendingPathComponent("bastion-diagnostics-\(UUID().uuidString)")
        let folder = work.appendingPathComponent("Gantry diagnostics")
        try fm.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: work) }
        try stage(inputs, into: folder)
        try? fm.removeItem(at: zip)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        p.arguments = ["-c", "-k", "--keepParent", folder.path, zip.path]
        try p.run()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else {
            throw NSError(domain: "Diagnostics", code: Int(p.terminationStatus), userInfo: [NSLocalizedDescriptionKey: "The zip could not be written (ditto \(p.terminationStatus))"])
        }
    }
}
