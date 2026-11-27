#if BASTION_TEST_HOOKS
import AppKit

/// UI driver steps for the quit question (CLOSE-01), printed as text so they also check a run
/// with no captures. A plain `quit` never asks (driver runs skip the alert); these steps arm an
/// answer first, so the question is exercised without an alert nobody can click.
extension Driver {
    /// Handles one of these steps; false when `cmd` is not one.
    func quitStep(_ cmd: String, _ arg: String) async -> Bool {
        let quit = QuitConfirm.shared
        quit.onAsked = { [weak self] line in
            self?.write(line)
            self?.flush(wait: true)
        }
        switch cmd {
        case "quit-live":
            // `quit-live [<count>]`: sessions the question would count; with a count, it must match.
            let live = quit.liveSessions
            let isWrong = !arg.isEmpty && Int(arg) != live
            write("\(isWrong ? "FAIL " : "")QUIT-LIVE sessions=\(live) setting=\(quit.isEnabled() ? "on" : "off") asked=\(quit.asked)\(isWrong ? " want=\(arg)" : "")")
        case "quit-would":
            // `quit-would ask|quit`: what ⌘Q would do for a user now, without quitting.
            let got = quit.preview == .ask ? "ask" : "quit"
            write("\(got == arg ? "" : "FAIL ")QUIT-WOULD \(got) live=\(quit.liveSessions) want=\(arg)")
        case "quit-cancel":
            // `quit-cancel [key]`: quit (terminate, or the real ⌘Q menu shortcut with `key`), answer
            // Cancel. The question must have been asked once and every tab must still be there.
            guard let sessions = UIDriver.services?.sessions else { write("FAIL quit-cancel: no services"); return true }
            let (askedBefore, tabsBefore, liveBefore) = (quit.asked, sessions.tabs.count, quit.liveSessions)
            quit.armedAnswer = false
            if arg == "key" { appKey("cmd+q") } else { NSApp.terminate(nil) }
            await settle(0.6)
            let isRight = quit.asked == askedBefore + 1 && sessions.tabs.count == tabsBefore && quit.liveSessions == liveBefore
            quit.armedAnswer = nil
            write("\(isRight ? "" : "FAIL ")QUIT-CANCEL \(arg.isEmpty ? "terminate" : arg) asked=\(quit.asked - askedBefore) tabs=\(sessions.tabs.count)/\(tabsBefore) live=\(quit.liveSessions)/\(liveBefore)")
        case "quit-confirm":
            // Quit and answer Quit: logs QUIT-ASKED, then ends the run like `quit`.
            guard quit.preview == .ask else { write("FAIL quit-confirm: no question would be asked (live=\(quit.liveSessions))"); return true }
            quit.armedAnswer = true
            await step("quit")
        case "quit-fit":
            // `quit-fit light|dark|system`: the alert's fit in that appearance; `system` leaves the
            // alert exactly as the app builds it for a user (it follows the app's appearance).
            guard arg == "system" || Self.quitAppearance(arg) != nil else { write("FAIL quit-fit: need light, dark or system"); return true }
            await quitFit(Self.quitAppearance(arg), named: arg)
        case "quit-capture":
            // `quit-capture <name> light|dark`: a picture of the alert for 3 sessions, on screen but
            // not modal, written to `<name>.png` in the run's output folder.
            let parts = arg.split(separator: " ").map(String.init)
            guard parts.count == 2, let appearance = Self.quitAppearance(parts[1]) else { write("FAIL quit-capture: need a name and light or dark"); return true }
            let alert = QuitConfirm.alert(liveSessions: 3)
            alert.window.appearance = appearance
            alert.layout()
            alert.window.center()
            alert.window.orderFrontRegardless()
            await settle(0.4)
            let shown = alert.window.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? "dark" : "light"
            write("\(shown == parts[1] ? "" : "FAIL ")QUIT-CAPTURE \(parts[0]) appearance=\(shown) want=\(parts[1])")
            // The app takes the picture itself and logs CAPTURE once the file is written (MAC-CAPTURE-01).
            await capture(alert.window, parts[0])
            alert.window.orderOut(nil)
        default: return false
        }
        return true
    }

    /// The appearance a quit step names. It is set on the alert itself: the app's theme resets
    /// `NSApp.appearance` whenever a themed window or sheet appears (`ThemedRoot`), so the run's
    /// `appearance` step does not last until an alert is made.
    private static func quitAppearance(_ name: String) -> NSAppearance? {
        switch name {
        case "light": NSAppearance(named: .aqua)
        case "dark": NSAppearance(named: .darkAqua)
        default: nil
        }
    }

    /// Layout fit of the alert for 1, 3 and 1000 sessions: wording, both buttons inside the alert,
    /// no overlap, hit targets, Return on Cancel and ⌘Q on Quit, and the shared fit rules.
    private func quitFit(_ appearance: NSAppearance?, named name: String) async {
        let minimumHitTarget: CGFloat = 24
        for count in [1, 3, 1000] {
            let alert = QuitConfirm.alert(liveSessions: count)
            if let appearance { alert.window.appearance = appearance }
            alert.layout()
            // On screen (not modal, not key) so the shared fit rules see a visible window, and
            // measured only once its layout has settled, as a user sees it. Buttons are measured
            // by their alignment rectangles (what is drawn), not by frames that include padding.
            alert.window.orderFrontRegardless()
            // `first`: the buttons as they are the moment the alert is put on screen, to show
            // whether a size seen later was there from the start.
            let first = alert.buttons.map { "\(Int($0.frame.width))x\(Int($0.frame.height))" }.joined(separator: "/")
            alert.window.layoutIfNeeded()
            await settle(0.3)
            guard let content = alert.window.contentView else { write("FAIL QUIT-FIT sessions=\(count): no content view"); continue }
            content.layoutSubtreeIfNeeded()
            let bounds = content.bounds.insetBy(dx: -1, dy: -1)
            let buttons = alert.buttons.map { button in
                (button.superview ?? content).convert(button.alignmentRect(forFrame: button.frame), to: content)
            }
            let shown = alert.window.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? "dark" : "light"
            let labels = content.allSubviews(of: NSTextField.self).filter { !$0.stringValue.isEmpty }
            let isClipped = labels.contains { label in
                let needed = label.cell?.cellSize(forBounds: NSRect(x: 0, y: 0, width: label.frame.width, height: .greatestFiniteMagnitude)) ?? .zero
                return needed.height > label.frame.height + 1 || !bounds.contains(label.convert(label.bounds, to: content))
            }
            let texts = labels.map(\.stringValue)
            let isWorded = texts.contains(QuitQuestion.title) && texts.contains(QuitQuestion.text(liveSessions: count))
                && alert.buttons.map(\.title) == [QuitQuestion.quitButton, QuitQuestion.cancelButton]
            let isInside = buttons.count == 2 && buttons.allSatisfy { bounds.contains($0) }
            let isOverlapping = buttons.count == 2 && buttons[0].intersects(buttons[1])
            // The Mac's order: the first button added (Quit) is the trailing one, Cancel is before it.
            let isOrdered = buttons.count == 2 && (buttons[0].minX > buttons[1].minX || buttons[0].minY < buttons[1].minY)
            let isTouchable = buttons.allSatisfy { $0.height >= minimumHitTarget && $0.width >= minimumHitTarget }
            // Return is Cancel, never Quit; Quit answers ⌘Q. Once an alert is on screen AppKit keeps
            // Return as the window's default button cell and clears that button's key equivalent.
            let defaultTitle = (alert.window.defaultButtonCell as? NSButtonCell)?.title
            let returnButton = defaultTitle ?? alert.buttons.first { $0.keyEquivalent == QuitQuestion.cancelKey }?.title
            let hasKeys = returnButton == QuitQuestion.cancelButton
                && alert.buttons.first?.keyEquivalent == QuitQuestion.quitKey
                && alert.buttons.first?.keyEquivalentModifierMask == .command
            let problems = fitProblems(in: alert.window)
            let isGood = (name == "system" || shown == name) && isWorded && isInside && !isOverlapping && isOrdered && isTouchable && hasKeys && !isClipped && problems.isEmpty
            write("\(isGood ? "" : "FAIL ")QUIT-FIT sessions=\(count) appearance=\(shown) window=\(Int(content.bounds.width))x\(Int(content.bounds.height)) buttons=\(buttons.map { "\(Int($0.width))x\(Int($0.height))" }.joined(separator: "/")) first=\(first) wording=\(isWorded) inside=\(isInside) overlap=\(isOverlapping) order=\(isOrdered) hit=\(isTouchable) keys=\(hasKeys) return=\(returnButton ?? "none") clipped=\(isClipped) fit=\(problems.isEmpty ? "ok" : problems.joined(separator: "; "))")
            alert.window.orderOut(nil)
        }
    }
}
#endif
