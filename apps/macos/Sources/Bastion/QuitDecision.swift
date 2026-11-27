import Foundation

/// What the quit question is decided from (CLOSE-01). Foundation only, so
/// `uitests/quit-decision-test.sh` compiles this file on its own.
struct QuitRequest: Equatable, Sendable {
    /// `terminal.confirm-close`.
    let isSettingOn: Bool
    /// Live terminals, desktops and web tabs, plus running transfers and tasks.
    let liveSessions: Int
    /// The app quits itself: updater, start-up probe, snapshot runner, locked Personal.
    let isSelfDriven: Bool
    /// A UI-driver run (`BASTION_UI_SCRIPT`).
    let isScripted: Bool
    /// The answer a UI-driver script armed for the next question (true = Quit); nil = none.
    let armedAnswer: Bool?
}

enum QuitDecision: Equatable, Sendable {
    /// Quit at once, no question.
    case quit
    /// Show the alert.
    case ask
    /// The question counts as asked and the script's answer stands in for the alert (true = Quit).
    case answered(Bool)
}

/// The rules and wording of "quit while sessions are open".
enum QuitQuestion {
    static let title = "Quit Gantry?"
    static let quitButton = "Quit"
    static let cancelButton = "Cancel"
    /// Return answers Cancel (coordinator ruling, 2026-11-13: a stray Return must not disconnect
    /// every session; the same on all four apps). Esc answers Cancel too.
    static let cancelKey = "\r"
    /// Quit keeps a key of its own: ⌘Q again.
    static let quitKey = "q"

    static func text(liveSessions: Int) -> String {
        liveSessions == 1
            ? "1 session is still open. Quitting disconnects it."
            : "\(liveSessions) sessions are still open. Quitting disconnects them."
    }

    static func decide(_ request: QuitRequest) -> QuitDecision {
        guard !request.isSelfDriven, request.isSettingOn, request.liveSessions > 0 else { return .quit }
        if let answer = request.armedAnswer { return .answered(answer) }
        // A driver run never blocks on an alert nobody is there to answer.
        return request.isScripted ? .quit : .ask
    }
}
