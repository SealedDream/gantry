#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for the Activity page (LOG-NATIVE-01). Records go through the core's own
/// `activity_begin` / `activity_end`, into the test profile's data folder; synthetic values only.
extension Driver {
    /// Handles one of these steps; false when `cmd` is not one.
    func activityStep(_ cmd: String, _ arg: String) async -> Bool {
        switch cmd {
        case "activity-seed": activitySeed(Int(arg) ?? 20)
        case "activity-rows": await activityRows()
        case "activity-seed-conn": activitySeedConnection(arg)
        case "activity-button": await activityButton(arg)
        case "activity-last": await activityLast(arg)
        case "activity-session-log-seed": sessionLogSeed(arg)
        case "activity-session-log-purge": await sessionLogPurge()
        default: return false
        }
        return true
    }

    /// `activity-seed <n>`: n ended sessions over the protocols, results and a long name, plus one open.
    private func activitySeed(_ n: Int) {
        let dir = LibraryModel.dataDir.path
        let protocols = ["ssh", "rdp", "sftp", "vnc", "ftps"]
        let reasons = ["closed_by_user", "auth_failed", "network_lost", "remote_closed", "timeout"]
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        var made = 0
        for i in 0...n {
            let name = i == 1 ? "a-connection-with-a-rather-long-name-for-the-fit-check-\(i)" : "lab-host-\(i)"
            let start: [String: Any] = [
                "connectionId": UUID().uuidString.lowercased(), "connectionName": name, "folderPath": [],
                "protocol": protocols[i % protocols.count], "host": "10.0.0.\(i % 250 + 1)", "port": 22,
                "username": "tester", "route": [], "loginSource": "own", "startedAt": now - UInt64(i) * 3_600_000,
                "app": "native-mac", "appVersion": "test", "deviceName": "test-device",
            ]
            guard let s = try? JSONSerialization.data(withJSONObject: start),
                  let id = try? activityBegin(dataDir: dir, startJson: String(decoding: s, as: UTF8.self)) else { continue }
            made += 1
            if i == 0 { continue } // one session stays open
            let end = #"{"endReason":"\#(reasons[i % reasons.count])","connectedAt":\#(now - UInt64(i) * 3_600_000 + 500),"endedAt":\#(now - UInt64(i) * 3_600_000 + UInt64(i) * 61_000)}"#
            _ = try? activityEnd(dataDir: dir, sessionId: id, endJson: end)
        }
        write("ACTIVITY-SEED \(made)")
    }

    /// `activity-seed-conn <name>`: the packet's three sessions for that library connection, with its
    /// real folder path: one failed sign-in, one closed by the user, one dropped link.
    private func activitySeedConnection(_ name: String) {
        guard let root = commands.model.tree, let (c, path) = Self.find(name, in: root, path: []) else { return write("FAIL activity-seed-conn: no connection \(name)") }
        let dir = LibraryModel.dataDir.path
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        var made = 0
        for (i, reason) in ["auth_failed", "closed_by_user", "network_lost"].enumerated() {
            let startedAt = now - UInt64(3 - i) * 600_000
            let start: [String: Any] = [
                "connectionId": c.id, "connectionName": c.name, "folderPath": path.map { ["id": $0.id, "name": $0.name] },
                "protocol": c.protocol, "host": c.host, "username": "tester", "route": [], "loginSource": "own",
                "startedAt": startedAt, "app": "native-mac", "appVersion": "test", "deviceName": "test-device",
            ]
            guard let s = try? JSONSerialization.data(withJSONObject: start),
                  let id = try? activityBegin(dataDir: dir, startJson: String(decoding: s, as: UTF8.self)) else { continue }
            let connected = reason == "auth_failed" ? "" : #","connectedAt":\#(startedAt + 400)"#
            let end = #"{"endReason":"\#(reason)"\#(connected),"endedAt":\#(startedAt + UInt64(i + 1) * 90_000)}"#
            if (try? activityEnd(dataDir: dir, sessionId: id, endJson: end)) != nil { made += 1 }
        }
        write("ACTIVITY-SEED-CONN \(name) \(made) folders=\(path.map(\.name).joined(separator: "/"))")
    }

    /// `activity-session-log-seed <name>`: three synthetic session logs in the folder the core plans for that
    /// connection (LOG-CORE-02), one of them rotated. No real output, nothing sensitive.
    private func sessionLogSeed(_ arg: String) {
        // `<name>|old`: also one log 40 days old, for the retention check.
        let parts = arg.split(separator: "|").map(String.init)
        let name = parts.first ?? ""
        guard let root = commands.model.tree, let (c, _) = Self.find(name, in: root, path: []),
              let library = commands.model.library,
              let plan = try? library.sessionLogPlan(connectionId: c.id, dataDir: LibraryModel.dataDir.path, app: "native-mac", version: "test", utcOffsetMinutes: 0)
        else { return write("FAIL session-log-seed: no plan for \(name)") }
        let dir = URL(fileURLWithPath: plan.path).deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            for (i, file) in ["2026-11-20_09-00-00_tester.log", "2026-11-19_10-00-00_tester.log", "2026-11-19_10-00-00_tester.log.1"].enumerated() {
                let url = dir.appendingPathComponent(file)
                try (plan.header + "uptime\n 09:00:0\(i) up 3 days\n").write(to: url, atomically: true, encoding: .utf8)
                try FileManager.default.setAttributes([.posixPermissions: 0o600, .modificationDate: Date().addingTimeInterval(Double(-i) * 3600)], ofItemAtPath: url.path)
            }
            if parts.dropFirst().first == "old" {
                let url = dir.appendingPathComponent("2026-10-01_08-00-00_tester.log")
                try (plan.header + "old\n").write(to: url, atomically: true, encoding: .utf8)
                try FileManager.default.setAttributes([.posixPermissions: 0o600, .modificationDate: Date().addingTimeInterval(-40 * 86_400)], ofItemAtPath: url.path)
            }
            write("SESSION-LOG-SEED \(name) dir=\(dir.path)")
        } catch {
            write("FAIL session-log-seed: \(error)")
        }
    }

    /// `activity-session-log-purge`: the launch-time retention (`SessionLogPurge.purge`), now.
    private func sessionLogPurge() async {
        let library = commands.model.library
        let folder = UIDriver.services?.settings.value("logging.session-log-folder") ?? ""
        let dataDir = LibraryModel.dataDir.path
        let n = await Task.detached { SessionLogPurge.purge(library: library, settingFolder: folder, dataDir: dataDir) }.value
        write("SESSION-LOG-PURGE deleted=\(n)")
    }

    /// The connection and the folders above it (outermost first, without the library root).
    private static func find(_ name: String, in f: FolderView, path: [FolderView]) -> (ConnectionView, [FolderView])? {
        if let c = f.connections.first(where: { $0.name == name }) { return (c, path) }
        for sub in f.folders { if let hit = find(name, in: sub, path: path + [sub]) { return hit } }
        return nil
    }

    /// `activity-button <title>`: click a main-window button ("Show All…", "History…").
    private func activityButton(_ title: String) async {
        if let b = window?.contentView?.allSubviews(of: NSButton.self).first(where: { $0.title == title && $0.isEnabled }) {
            b.performClick(nil)
        } else if let action = DriverButtons.actions[title] {
            // SwiftUI buttons in a scroll view are not NSButtons; the view registers the action.
            action()
        } else {
            return write("FAIL activity-button \(title)")
        }
        await settle(0.8)
        write("ACTIVITY-BUTTON \(title) sheet=\(window?.attachedSheet != nil)")
    }

    /// `activity-last <connection name>`: the newest Activity record for that connection, as the core
    /// stores it (LOG-RDP-01). Waits up to 5 s, since the app writes off the main thread.
    private func activityLast(_ name: String) async {
        let dir = LibraryModel.dataDir.path
        for _ in 0..<25 {
            let json = await Task.detached { (try? activityQueryJson(dataDir: dir, filterJson: "{}", offset: 0, limit: 500)) ?? "[]" }.value
            let rows = (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [[String: Any]] ?? []
            if let r = rows.filter({ $0["connectionName"] as? String == name }).max(by: { ($0["startedAt"] as? Int ?? 0) < ($1["startedAt"] as? Int ?? 0) }),
               r["open"] as? Bool == false {
                let path = (r["folderPath"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }.joined(separator: "/")
                return write("ACTIVITY-LAST \(name) protocol=\(r["protocol"] ?? "") host=\(r["host"] ?? "") login=\(r["loginSource"] ?? "") app=\(r["app"] ?? "") folders=\(path) connected=\(r["connectedAt"] != nil) reason=\(r["endReason"] ?? "")")
            }
            await settle(0.2)
        }
        write("FAIL activity-last \(name): no ended record")
    }

    /// Rows in the Activity sheet's table.
    private func activityRows() async {
        await settle(0.5)
        guard let table = attachedDialog?.views(of: NSTableView.self).first else { return write("FAIL activity-rows: no table") }
        write("ACTIVITY-ROWS \(table.numberOfRows)")
    }
}
/// Actions of SwiftUI buttons the driver cannot reach as NSButtons, by title (test builds only).
@MainActor enum DriverButtons {
    static var actions: [String: () -> Void] = [:]
}
#endif
