import AppKit
import BastionCore

/// CLOSE-01: ⌘Q (or any `NSApp.terminate`) asks first while a session is live and
/// `terminal.confirm-close` is on. The rules are in `QuitDecision.swift`; this file counts what
/// is live from the state the tabs, transfer queues and task runs already expose, and shows the alert.
@MainActor
final class QuitConfirm {
    static let shared = QuitConfirm()

    /// Set by the app at launch.
    weak var sessions: SessionsModel?
    /// `terminal.confirm-close`: read when asked, so a change applies at once.
    var isEnabled: () -> Bool = { true }

    /// Set by `terminateWithoutAsking` for the quit it starts.
    private var isSelfDriven = false
    /// UI driver: the answer for the next question (true = Quit); used once.
    var armedAnswer: Bool?
    /// UI driver: called with a log line whenever the question was asked or answered.
    var onAsked: ((String) -> Void)?
    /// Questions asked so far (UI driver).
    private(set) var asked = 0

    /// Quit for the app's own reasons (update restart, start-up probe, snapshot runner, locked
    /// Personal): never asks.
    static func terminateWithoutAsking() {
        shared.isSelfDriven = true
        NSApp.terminate(nil)
    }

    /// Live sessions: terminal panes whose shell or SSH link is alive, RDP and VNC desktops that
    /// have not closed, open web tabs, task tabs still running, hosts still running in the
    /// Run On sheet, and files still copying or queued in a transfer queue.
    var liveSessions: Int {
        let tabs = (sessions?.tabs ?? []).map(Self.live(in:)).reduce(0, +)
        let sheetTasks = TaskRunOnSheet.current.filter { !$0.isFinished }.count
        return tabs + sheetTasks + TransferQueueRunner.runningTransfers
    }

    private static func live(in tab: TerminalTab) -> Int {
        switch tab.content {
        case .terminal: tab.panes.filter { !$0.ended }.count
        case .rdp, .vnc: tab.desktopCloseReason == nil ? 1 : 0
        case .web: 1
        case .task(let run): run.isFinished() ? 0 : 1
        // A files tab counts through its transfer queue; a system view is a read-only list; a
        // restored tab still waiting (D15) has sent nothing to its host.
        case .files, .system, .waiting, .plugin: 0
        }
    }

    /// What ⌘Q would do for a user right now (UI driver: checks the rule without quitting).
    var preview: QuitDecision {
        QuitQuestion.decide(QuitRequest(isSettingOn: isEnabled(), liveSessions: liveSessions, isSelfDriven: false,
                                        isScripted: false, armedAnswer: nil))
    }

    /// The app delegate's answer to `applicationShouldTerminate`.
    func shouldTerminate() -> NSApplication.TerminateReply {
        let live = liveSessions
        let request = QuitRequest(isSettingOn: isEnabled(), liveSessions: live, isSelfDriven: isSelfDriven,
                                  isScripted: TestHooks.isScripted, armedAnswer: armedAnswer)
        // One quit per flag and per armed answer: a cancelled quit must not skip the next question.
        isSelfDriven = false
        armedAnswer = nil
        switch QuitQuestion.decide(request) {
        case .quit:
            return .terminateNow
        case .answered(let quits):
            asked += 1
            onAsked?("QUIT-ASKED n=\(asked) live=\(live) answer=\(quits ? "quit" : "cancel")")
            return quits ? .terminateNow : .terminateCancel
        case .ask:
            asked += 1
            return Self.runAlert(liveSessions: live) ? .terminateNow : .terminateCancel
        }
    }

    /// Buttons in the Mac's order: Quit is added first, which AppKit draws as the trailing (right)
    /// button, with Cancel to its left. Unlike the tab and pane close alerts,
    /// Return answers Cancel here: a stray Return must not disconnect every session. Quit
    /// answers ⌘Q and a click.
    static func alert(liveSessions: Int) -> NSAlert {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = QuitQuestion.title
        alert.informativeText = QuitQuestion.text(liveSessions: liveSessions)
        let quit = alert.addButton(withTitle: QuitQuestion.quitButton)
        quit.keyEquivalent = QuitQuestion.quitKey
        quit.keyEquivalentModifierMask = .command
        alert.addButton(withTitle: QuitQuestion.cancelButton).keyEquivalent = QuitQuestion.cancelKey
        return alert
    }

    /// Shows the alert; true = Quit. Cancel's key is Return, so Esc is mapped to Cancel here.
    private static func runAlert(liveSessions: Int) -> Bool {
        let escapeKeyCode: UInt16 = 53
        let alert = alert(liveSessions: liveSessions)
        let monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            guard event.keyCode == escapeKeyCode, event.window === alert.window, alert.buttons.count == 2 else { return event }
            alert.buttons[1].performClick(nil)
            return nil
        }
        defer { monitor.map(NSEvent.removeMonitor) }
        return alert.runModalInFront() == .alertFirstButtonReturn
    }
}
