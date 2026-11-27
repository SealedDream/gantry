import Foundation

/// Session log files on disk (LOG-CORE-02): the core plans where each connection's logs go
/// (`session_log_plan`); this lists those folders, filters and exports. Foundation only, so the
/// unit test builds it alone (`tests/session-logs-test.sh`).
struct SessionLogFile: Identifiable, Hashable {
    let url: URL
    let connection: String
    let modified: Date
    let bytes: Int64
    var id: String { url.path }
    var name: String { url.lastPathComponent }
}

enum SessionLogFiles {
    /// The first line of every v2 session log (`sessionlog::LOG_MAGIC`).
    static let magic = "# Gantry session log"
    /// Content search reads at most this much of each file.
    static let searchLimit = 8 * 1024 * 1024

    /// Log files (`.log`, rotated `.log.N`) directly in each folder, newest first. `folders` maps a
    /// folder to the connection name shown for its files. Missing folders give nothing.
    static func list(_ folders: [URL: String]) -> [SessionLogFile] {
        let fm = FileManager.default
        let keys: [URLResourceKey] = [.contentModificationDateKey, .fileSizeKey, .isRegularFileKey]
        var out: [SessionLogFile] = []
        for (dir, connection) in folders {
            guard let items = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles]) else { continue }
            for url in items where isLogName(url.lastPathComponent) {
                guard let v = try? url.resourceValues(forKeys: Set(keys)), v.isRegularFile == true else { continue }
                out.append(SessionLogFile(url: url, connection: connection, modified: v.contentModificationDate ?? .distantPast, bytes: Int64(v.fileSize ?? 0)))
            }
        }
        return out.sorted { $0.modified == $1.modified ? $0.name > $1.name : $0.modified > $1.modified }
    }

    static func isLogName(_ name: String) -> Bool {
        if name.hasSuffix(".log") { return true }
        guard let r = name.range(of: ".log.", options: .backwards) else { return false }
        let tail = name[r.upperBound...]
        return !tail.isEmpty && tail.allSatisfy(\.isNumber)
    }

    /// Files whose name or connection contains `query` (case-insensitive); with `content`, also
    /// files whose text contains it. Empty query: all.
    static func filter(_ files: [SessionLogFile], query: String, content: Bool) -> [SessionLogFile] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return files }
        return files.filter { f in
            f.name.localizedCaseInsensitiveContains(q) || f.connection.localizedCaseInsensitiveContains(q)
                || (content && contains(f.url, q))
        }
    }

    static func contains(_ url: URL, _ text: String) -> Bool {
        guard let h = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? h.close() }
        let data = (try? h.read(upToCount: searchLimit)) ?? Data()
        return String(decoding: data, as: UTF8.self).localizedCaseInsensitiveContains(text)
    }

    /// Copy `files` into `folder`, never overwriting: a taken name gets ` 2`, ` 3` … Copies are
    /// owner-only like the originals. Returns the copies made.
    static func export(_ files: [SessionLogFile], to folder: URL) throws -> [URL] {
        let fm = FileManager.default
        var made: [URL] = []
        for f in files {
            let dest = freeName(f.url.lastPathComponent, in: folder)
            try fm.copyItem(at: f.url, to: dest)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: dest.path)
            made.append(dest)
        }
        return made
    }

    /// The roots retention runs on at start: the default `session-logs` folder, plus the
    /// Settings log folder when one is set (empty root: the core's default in `dataDir`).
    static func purgeRoots(settingFolder: String) -> [String] {
        let custom = settingFolder.trimmingCharacters(in: .whitespacesAndNewlines)
        return custom.isEmpty ? [""] : ["", custom]
    }

    static func freeName(_ name: String, in folder: URL) -> URL {
        let fm = FileManager.default
        var url = folder.appendingPathComponent(name)
        let ext = (name as NSString).pathExtension
        let stem = (name as NSString).deletingPathExtension
        var n = 2
        while fm.fileExists(atPath: url.path) {
            url = folder.appendingPathComponent(ext.isEmpty ? "\(stem) \(n)" : "\(stem) \(n).\(ext)")
            n += 1
        }
        return url
    }
}
