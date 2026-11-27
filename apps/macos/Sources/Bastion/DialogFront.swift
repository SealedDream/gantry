import AppKit

/// MAC-DIALOG-RESTORE (parity with Windows WIN-DIALOG-RESTORE): a sheet or an app-modal alert shown
/// while its window is minimised brings that window back from the Dock, so the user sees the
/// question. Nothing happens when no window is minimised, so it never takes focus in other cases.
/// Activation is only a request (macOS decides); quiet driver runs never activate. When the
/// request is refused the Dock icon bounces once.
@MainActor
enum DialogFront {
    private static var observers: [NSObjectProtocol] = []
    /// Restores done so far (UI driver).
    private(set) static var restored = 0

    /// Called once at launch. App-modal alerts go through `NSAlert.runModalInFront()` instead: no
    /// notification names an alert that `runModal` puts up, and the event loop may not turn over.
    static func install() {
        guard observers.isEmpty else { return }
        let center = NotificationCenter.default
        // Sheets: SwiftUI `.sheet`/`.alert` on a window and `NSAlert.beginSheetModal` all post this.
        observers.append(center.addObserver(forName: NSWindow.willBeginSheetNotification, object: nil, queue: .main) { note in
            let window = note.object as? NSWindow
            MainActor.assumeIsolated { bringForward(window) }
        })
    }

    /// The window an app-modal alert belongs to: the first minimised titled window that is not a
    /// panel (`canBecomeMain` is false while a window is in the Dock, so it cannot be the test).
    static func minimisedMainWindow() -> NSWindow? {
        NSApp.windows.first { $0.isMiniaturized && !($0 is NSPanel) && $0.styleMask.contains(.titled) }
    }

    /// Restores `window` when it is minimised; otherwise does nothing.
    static func bringForward(_ window: NSWindow?) {
        guard let window, window.isMiniaturized else { return }
        restored += 1
        window.deminiaturize(nil)
        guard !QuietLaunch.isOn else { return }
        window.makeKeyAndOrderFront(nil)
        if !NSApp.isActive {
            NSApp.activate()
            NSApp.requestUserAttention(.informationalRequest)
        }
    }
}

extension NSAlert {
    /// `runModal` for the app's alerts (the quit question, unlock, document prompts): brings a
    /// minimised main window back first, so the alert is not left alone over an empty desktop.
    @MainActor
    func runModalInFront() -> NSApplication.ModalResponse {
        DialogFront.bringForward(DialogFront.minimisedMainWindow())
        return runModal()
    }
}
