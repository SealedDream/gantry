#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for the Audit Log page (LOG-NATIVE-01). Records come from the core's own audit
/// writer; the tamper step edits only the test profile's `audit.jsonl`, never a user's.
extension Driver {
    /// Handles one of these steps; false when `cmd` is not one.
    func auditStep(_ cmd: String, _ arg: String) async -> Bool {
        switch cmd {
        case "audit-seed": auditSeed(Int(arg) ?? 10)
        case "audit-tamper": auditTamper(Int(arg) ?? 1)
        case "audit-status": await auditStatus()
        default: return false
        }
        return true
    }

    private var auditFile: URL { LibraryModel.dataDir.appendingPathComponent("audit.jsonl") }

    /// `audit-seed <n>`: n "document.open" failures through the core (paths that do not exist).
    private func auditSeed(_ n: Int) {
        let dir = LibraryModel.dataDir.path
        for i in 0..<n { _ = try? BastionDocument.reopen(path: "/nonexistent/audit-seed-\(i).bastion", dataDir: dir) }
        let lines = (try? String(contentsOf: auditFile, encoding: .utf8))?.split(separator: "\n").count ?? 0
        write("AUDIT-SEED \(n) lines=\(lines)")
    }

    /// `audit-tamper <n>`: change one character inside record n (1-based) of the test profile's log.
    private func auditTamper(_ n: Int) {
        guard ProcessInfo.processInfo.environment["BASTION_UI_SCRIPT"] != nil, ProcessInfo.processInfo.environment["BASTION_LIBRARY"] != nil,
              var lines = (try? String(contentsOf: auditFile, encoding: .utf8))?.components(separatedBy: "\n"),
              n >= 1, n <= lines.count, let r = lines[n - 1].range(of: "audit-seed-") else { return write("FAIL audit-tamper \(n)") }
        lines[n - 1].replaceSubrange(r, with: "audit-SEED-")
        do { try lines.joined(separator: "\n").write(to: auditFile, atomically: true, encoding: .utf8) } catch { return write("FAIL audit-tamper: \(error)") }
        write("AUDIT-TAMPER \(n)")
    }

    /// The status the page shows, from the same core call.
    private func auditStatus() async {
        let dir = LibraryModel.dataDir.path
        guard let v = try? AuditVerify.decode(auditVerifyJson(dataDir: dir)) else { return write("FAIL audit-status") }
        let shown = window?.attachedSheet != nil
        write("AUDIT-STATUS \(v.text) records=\(v.records) sheet=\(shown)")
    }
}
#endif
