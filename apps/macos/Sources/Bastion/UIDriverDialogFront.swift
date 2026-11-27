#if BASTION_TEST_HOOKS
import AppKit

/// UI driver steps for MAC-DIALOG-RESTORE: `dialog-front sheet|modal|none`.
/// `sheet` and `modal` minimise the main window, then show a sheet on it or an app-modal alert;
/// the window must come back on screen with the dialog. `none` shows a sheet on a window that is not
/// minimised: nothing may be restored.
extension Driver {
    func dialogFrontStep(_ cmd: String, _ arg: String) async -> Bool {
        guard cmd == "dialog-front" else { return false }
        guard let main = window else { write("FAIL dialog-front: no main window"); return true }
        let before = DialogFront.restored
        if arg != "none" {
            main.miniaturize(nil)
            for _ in 0..<20 where !main.isMiniaturized { await settle(0.1) }
            guard main.isMiniaturized else { write("FAIL dialog-front \(arg): window did not minimise"); return true }
        }
        let alert = NSAlert()
        alert.messageText = "Dialog front test"
        alert.addButton(withTitle: "OK")
        switch arg {
        case "sheet", "none":
            alert.beginSheetModal(for: main) { _ in }
            await settle(1.0)
            let dialogShown = main.attachedSheet?.isVisible == true
            check(arg, main, dialogShown, before)
            main.endSheet(alert.window)
        case "modal":
            // runModal blocks this step; a common-modes timer checks inside the modal loop and ends it.
            let timer = Timer(timeInterval: 1.0, repeats: false) { _ in
                MainActor.assumeIsolated {
                    let shown = NSApp.modalWindow === alert.window && alert.window.isVisible
                    self.check("modal", main, shown, before)
                    NSApp.stopModal()
                }
            }
            RunLoop.main.add(timer, forMode: .common)
            _ = alert.runModalInFront()
        default:
            write("FAIL dialog-front: need sheet, modal or none")
        }
        await settle(0.3)
        return true
    }

    private func check(_ kind: String, _ main: NSWindow, _ dialogShown: Bool, _ before: Int) {
        let onScreen = main.isVisible && !main.isMiniaturized
        let restores = DialogFront.restored - before
        // AppKit itself brings a window back for `beginSheet` before the sheet notification, so a
        // sheet may count 0 restores; the modal alert has no such help and must count 1.
        let wantRestores: ClosedRange<Int> = switch kind { case "none": 0...0; case "modal": 1...1; default: 0...1 }
        let isRight = onScreen && dialogShown && wantRestores.contains(restores)
        write("\(isRight ? "" : "FAIL ")DIALOG-FRONT \(kind) onScreen=\(onScreen) dialog=\(dialogShown) restores=\(restores)")
    }
}
#endif
