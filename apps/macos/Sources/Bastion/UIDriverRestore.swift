#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for tabs restored after a crash (A2-W26, decision D15).
/// `restore-tabs [= <rows>]` every tab as `name:mode:state:panes`, joined by ` | `, the selected one
///   with `*`. `state` is `waiting` (restored, not connected), `live` or `ended`; `panes` is the
///   number of panes the tab has, or will have once a waiting tab connects.
/// `restore-bar [= connected|connecting|disconnected]` what the session title bar says for the selected tab
/// `restore-connect` presses Connect on the waiting tab that is showing
/// `restore-connections [= <n>]` connections the test proxy has accepted since it started
///   (`reconnect-proxy.py <count file>`; the file is named by BASTION_UI_PROXY_COUNT)
/// `restore-close [= closed, asked 0]` the close button of the selected tab, and how often it asked first
/// `restore-look [= light|dark]` the appearance the main window is drawn in now (a capture or a fit
///   check named "light" proves nothing unless this says light at that moment)
/// `restore-queue [= idle|busy]` whether a connect is queued, asking or on its way.
extension Driver {
    func restoreStep(_ cmd: String, _ arg: String) async {
        guard let sv = UIDriver.services else { return write("FAIL \(cmd): no services") }
        let want = arg.hasPrefix("= ") ? String(arg.dropFirst(2)) : nil
        func report(_ name: String, _ got: String) { write("\(want == nil || want == got ? "" : "FAIL ")\(name) \(got)") }
        switch cmd {
        case "restore-tabs":
            let s = sv.sessions
            let rows = s.tabs.map { t -> String in
                let state = t.isWaiting ? "waiting" : t.ended ? "ended" : "live"
                let panes = t.isWaiting ? max(1, t.restoredLayout.filter { $0 == "leaf" }.count) : max(1, t.panes.count)
                return "\(t.name):\(t.mode.rawValue):\(state):\(panes)\(t.id == s.selected ? "*" : "")"
            }
            report("RESTORE-TABS", rows.isEmpty ? "none" : rows.joined(separator: " | "))
        case "restore-bar":
            report("RESTORE-BAR", sv.sessions.selectedTab.map { SessionLinkState.of($0).rawValue } ?? "none")
        case "restore-connect":
            guard let tab = sv.sessions.selectedTab, tab.isWaiting else { return write("FAIL restore-connect: the selected tab is not waiting") }
            NotificationCenter.default.post(name: DriverEvents.pressButton, object: "restore-connect")
            await settle(0.6)
            write("RESTORE-CONNECT \(tab.name)")
        case "restore-connections":
            guard let file = ProcessInfo.processInfo.environment["BASTION_UI_PROXY_COUNT"],
                  let text = try? String(contentsOfFile: file, encoding: .utf8) else {
                return write("FAIL restore-connections: BASTION_UI_PROXY_COUNT names no readable file")
            }
            report("RESTORE-CONNECTIONS", text.trimmingCharacters(in: .whitespacesAndNewlines))
        case "restore-close":
            // The tab's close button on the selected tab; a waiting tab has no session to ask about.
            guard let tab = sv.sessions.selectedTab else { return write("FAIL restore-close: no tab") }
            let asked = sv.sessions.closeConfirmations
            sv.sessions.requestClose(tab)
            await settle(0.5)
            let closed = !sv.sessions.tabs.contains { $0.id == tab.id }
            report("RESTORE-CLOSE", "\(closed ? "closed" : "still open"), asked \(sv.sessions.closeConfirmations - asked)")
        case "restore-look":
            // What the main window is really drawn in, whatever was asked for.
            let look = window?.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? "dark" : "light"
            report("RESTORE-LOOK", look)
        case "restore-queue":
            report("RESTORE-QUEUE", commands.isConnectPending ? "busy" : "idle")
        default:
            write("FAIL \(cmd): unknown")
        }
    }
}
#endif
