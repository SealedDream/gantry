#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for the transcript viewer and the diagnostics export (LOG-NATIVE-01 items 4
/// and 7). Files go in the test library's folder only; values are synthetic.
extension Driver {
    /// Handles one of these steps; false when `cmd` is not one.
    func transcriptStep(_ cmd: String, _ arg: String) async -> Bool {
        switch cmd {
        case "transcript-seed": transcriptSeed(Int(arg) ?? 1000)
        case "transcript-open": await transcriptOpen()
        case "transcript-find": await transcriptFind(arg)
        case "transcript-times": transcriptTimes(arg != "off")
        case "diag-export": await diagExport()
        default: return false
        }
        return true
    }

    private var transcriptFile: URL { LibraryModel.dataDir.appendingPathComponent("transcripts/web-01.log") }

    /// `transcript-seed <n>`: n timestamped lines with colour codes; line 4242 (if n allows) holds
    /// "needle-line", the line Find must reach.
    private func transcriptSeed(_ n: Int) {
        let fm = FileManager.default
        try? fm.createDirectory(at: transcriptFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        var out = ""
        out.reserveCapacity(n * 64)
        for i in 0..<n {
            let s = String(format: "%02d:%02d:%02d", (i / 3600) % 24, (i / 60) % 60, i % 60)
            out += "[\(s)] \u{1B}[32muser@web-01\u{1B}[0m:~$ " + (i == 4242 ? "echo needle-line" : "ls -la /var/log/item-\(i)") + "\r\n"
        }
        do { try out.write(to: transcriptFile, atomically: true, encoding: .utf8) } catch { return write("FAIL transcript-seed: \(error)") }
        let size = (try? fm.attributesOfItem(atPath: transcriptFile.path))?[.size] as? Int ?? 0
        write("TRANSCRIPT-SEED lines=\(n) bytes=\(size)")
    }

    /// Opens the viewer through the router; reports the time to the first page and to the end.
    private func transcriptOpen() async {
        guard let sv = UIDriver.services else { return write("FAIL transcript-open") }
        let start = Date()
        sv.router.open("transcript:" + transcriptFile.path)
        var first: Double?
        for _ in 0..<600 {
            try? await Task.sleep(nanoseconds: 50_000_000)
            guard let m = TranscriptDriverHook.model else { continue }
            if first == nil, !m.lines.isEmpty { first = Date().timeIntervalSince(start) }
            if !m.loading, !m.lines.isEmpty { break }
        }
        guard let m = TranscriptDriverHook.model else { return write("FAIL transcript-open: no viewer") }
        let all = Date().timeIntervalSince(start)
        write(String(format: "TRANSCRIPT-OPEN lines=%d times=%@ first=%.0fms all=%.0fms sheet=%@", m.lines.count, m.hasTimes ? "yes" : "no",
                     (first ?? -1) * 1000, all * 1000, window?.attachedSheet != nil ? "shown" : "none"))
    }

    private func transcriptFind(_ text: String) async {
        guard let m = TranscriptDriverHook.model else { return write("FAIL transcript-find") }
        m.find(text)
        await settle(0.3)
        let line = m.current.flatMap { c in m.lines.first { $0.id == c } }
        write("TRANSCRIPT-FIND \(text) hits=\(m.hits.count) line=\(m.current.map { $0 + 1 } ?? 0) text=\(line?.text ?? "")")
    }

    private func transcriptTimes(_ on: Bool) {
        guard let m = TranscriptDriverHook.model else { return write("FAIL transcript-times") }
        m.showTimes = on
        let first = m.textView?.string.split(separator: "\n").first.map(String.init) ?? ""
        write("TRANSCRIPT-TIMES \(on ? "on" : "off") first=\(first)")
    }

    /// Writes the diagnostics zip into the test folder, unpacks it and searches every file for the
    /// library's host names, user names and connection names and the account name. Prints counts
    /// only, never the values.
    private func diagExport() async {
        let zip = LibraryModel.dataDir.appendingPathComponent("diag-test.zip")
        let tree = commands.model.tree
        let problem: String? = await withCheckedContinuation { c in DiagnosticsExport.write(tree, to: zip) { c.resume(returning: $0) } }
        if let problem { return write("FAIL diag-export: \(problem)") }
        let out = FileManager.default.temporaryDirectory.appendingPathComponent("diag-check-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: out); try? FileManager.default.removeItem(at: zip) }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        p.arguments = ["-x", "-k", zip.path, out.path]
        do { try p.run(); p.waitUntilExit() } catch { return write("FAIL diag-export unzip") }
        let files = FileManager.default.enumerator(at: out, includingPropertiesForKeys: nil)?.compactMap { $0 as? URL }.filter { !$0.hasDirectoryPath } ?? []
        let text = files.compactMap { try? String(contentsOf: $0, encoding: .utf8) }.joined(separator: "\n")
        var values: Set<String> = [NSUserName()]
        func walk(_ f: FolderView) {
            for c in f.connections { values.insert(c.host); values.insert(c.name); if let u = c.username { values.insert(u) } }
            values.insert(f.name); f.folders.forEach(walk)
        }
        if let tree { walk(tree) }
        let checked = values.filter { $0.count >= 3 }
        let leaks = checked.filter { text.localizedCaseInsensitiveContains($0) }.count
        let names = files.map(\.lastPathComponent).sorted().joined(separator: ",")
        write("DIAG-EXPORT files=\(names) checked=\(checked.count) leaks=\(leaks)")
    }
}
#endif
