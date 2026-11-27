import AppKit
import BastionCore

/// What the Tasks results grid opens: one host's terminal, or every host's with input broadcast.
extension Commands {
    /// Open (or show) a terminal on `connectionId`, signing in as a normal connect does.
    func openTaskHost(_ connectionId: String) {
        if let live = sessions.liveTab(for: connectionId) { sessions.selected = live.id; return }
        guard let c = model.connection(id: connectionId) else { return }
        requestConnect(c, Self.mode(for: c))
    }

    /// Open a terminal on every host, then broadcast input to all of them once they are open
    /// (the existing Broadcast Input; stop it from the Session menu).
    func openTaskHostsBroadcast(_ ids: [String]) {
        ids.forEach(openTaskHost)
        Task { @MainActor in
            for _ in 0..<Self.broadcastWaitSteps {
                let open = ids.compactMap { sessions.liveTab(for: $0) }
                if open.count == ids.count { break }
                try? await Task.sleep(for: .milliseconds(500))
            }
            let open = Set(ids.compactMap { sessions.liveTab(for: $0)?.id })
            if open.count > 1 { sessions.startBroadcast(open) }
        }
    }

    /// Half-seconds to wait for the terminals before broadcasting to those that opened.
    private static let broadcastWaitSteps = 60
}
