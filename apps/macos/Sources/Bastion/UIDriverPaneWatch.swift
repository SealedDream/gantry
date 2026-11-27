#if BASTION_TEST_HOOKS
import AppKit

/// `pane-watch start` / `pane-watch stop`: samples every 100 ms whether the session pane stays in
/// front: a tab selected in the main window and the start page never shown (MAC-RECONNECT-PANE).
/// Disconnect and Reconnect used to close the tab, so the start page showed for 1-2 s.
@MainActor
enum PaneWatch {
    static let interval: Duration = .milliseconds(100)
    static var task: Task<Void, Never>?
    static var samples = 0
    static var startPage = 0
    static var noSelection = 0
}

extension Driver {
    func paneWatchStep(_ arg: String) async {
        guard let sv = UIDriver.services else { return write("FAIL pane-watch: no services") }
        switch arg {
        case "start":
            PaneWatch.task?.cancel()
            PaneWatch.samples = 0; PaneWatch.startPage = 0; PaneWatch.noSelection = 0
            PaneWatch.task = Task { @MainActor in
                while !Task.isCancelled {
                    let s = sv.sessions
                    PaneWatch.samples += 1
                    if s.mainTabs.isEmpty { PaneWatch.startPage += 1 }
                    if s.selectedTab == nil { PaneWatch.noSelection += 1 }
                    try? await Task.sleep(for: PaneWatch.interval)
                }
            }
            write("PANE-WATCH started")
        case "stop":
            PaneWatch.task?.cancel()
            PaneWatch.task = nil
            let bad = PaneWatch.samples == 0 || PaneWatch.startPage > 0 || PaneWatch.noSelection > 0
            write("\(bad ? "FAIL " : "")PANE-WATCH samples=\(PaneWatch.samples) startPage=\(PaneWatch.startPage) noSelection=\(PaneWatch.noSelection)")
        default:
            write("FAIL pane-watch \(arg): start or stop")
        }
    }
}
#endif
