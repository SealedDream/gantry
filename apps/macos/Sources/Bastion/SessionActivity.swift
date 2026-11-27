import Foundation
import os
import BastionCore

// Records RDP, VNC and web tabs in the Activity log (LOG-RDP-01). Every write runs off the main
// thread, and a failed write never blocks or ends a session (it is logged). Sessions still open
// when the app ends are closed by the core's close_orphans at the next launch.

/// One recorded tab: the pending begin and when it connected.
struct TabActivity: Sendable {
    let begun: Task<String?, Never>
    let connectedAt: UInt64
}

@MainActor enum SessionActivity {
    nonisolated private static let log = Logger(subsystem: "Gantry", category: "activity")

    private static var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "dev"
    }

    private static func startJSON(_ start: SessionActivityStart, at now: UInt64) -> String {
        start.json(startedAt: now, appVersion: appVersion, deviceName: Host.current().localizedName ?? "Mac")
    }

    /// A tab opened on a live RDP/VNC desktop or web page: record its start, connected now.
    static func begin(_ start: SessionActivityStart) -> TabActivity {
        let now = SessionActivityStart.nowMs()
        let json = startJSON(start, at: now)
        let dir = LibraryModel.dataDir.path
        let task = Task.detached(priority: .utility) { () -> String? in
            do { return try activityBegin(dataDir: dir, startJson: json) } catch {
                log.error("activity begin failed: \(String(describing: error), privacy: .public)")
                return nil
            }
        }
        return TabActivity(begun: task, connectedAt: now)
    }

    static func end(_ activity: TabActivity, reason: String) {
        let json = SessionActivityStart.endJSON(connectedAt: activity.connectedAt, endedAt: SessionActivityStart.nowMs(), reason: reason)
        let dir = LibraryModel.dataDir.path
        Task.detached(priority: .utility) {
            guard let id = await activity.begun.value else { return }
            do { try activityEnd(dataDir: dir, sessionId: id, endJson: json) } catch {
                log.error("activity end failed: \(String(describing: error), privacy: .public)")
            }
        }
    }

    /// An RDP or VNC connect that failed before a tab opened: one record that never connected.
    static func recordFailed(_ start: SessionActivityStart, reason: String) {
        let now = SessionActivityStart.nowMs()
        let json = startJSON(start, at: now)
        let end = SessionActivityStart.endJSON(connectedAt: nil, endedAt: now, reason: reason)
        let dir = LibraryModel.dataDir.path
        Task.detached(priority: .utility) {
            do { try activityEnd(dataDir: dir, sessionId: try activityBegin(dataDir: dir, startJson: json), endJson: end) } catch {
                log.error("activity record failed: \(String(describing: error), privacy: .public)")
            }
        }
    }
}

extension LibraryModel {
    /// The activity start for a saved RDP, VNC or web connection; nil for others and for
    /// connections not in this library (quick connect).
    func activityStart(connectionId: String) -> SessionActivityStart? {
        guard let c = connection(id: connectionId), SessionActivityStart.isAppRecorded(c.protocol),
              let root = tree, let path = Self.folderPath(to: connectionId, in: root, path: []) else { return nil }
        return SessionActivityStart(connectionId: c.id, connectionName: c.name,
                                    folderPath: path.map { .init(id: $0.id, name: $0.name) },
                                    protocolName: c.protocol, host: c.host, port: c.port.map(Int.init),
                                    ownUsername: c.username, inheritedUsername: c.effectiveUsername)
    }

    /// The folders above a connection, outermost first, without the library root.
    private static func folderPath(to id: String, in f: FolderView, path: [FolderView]) -> [FolderView]? {
        if f.connections.contains(where: { $0.id == id }) { return path }
        for sub in f.folders { if let hit = folderPath(to: id, in: sub, path: path + [sub]) { return hit } }
        return nil
    }
}
