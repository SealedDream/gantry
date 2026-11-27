import AppKit
import SwiftUI

// Owner round 2, item 2: a click outside a transient sheet (the command palette, read-only lists)
// closes it, as a popover does. Forms that hold unsaved edits keep the macOS sheet rule (a click
// outside does nothing) so a stray click never throws work away.

extension View {
    /// Dismisses this sheet on a mouse-down in the window it is attached to.
    func closesOnOutsideClick() -> some View { modifier(OutsideClickDismiss()) }
}

private struct OutsideClickDismiss: ViewModifier {
    @Environment(\.dismiss) private var dismiss
    func body(content: Content) -> some View {
        content.background(OutsideClickMonitor { dismiss() })
    }
}

/// Watches mouse-downs while its sheet window is up; one in the sheet's parent window dismisses.
private struct OutsideClickMonitor: NSViewRepresentable {
    let onOutside: () -> Void
    func makeNSView(context: Context) -> MonitorView { MonitorView(onOutside: onOutside) }
    func updateNSView(_ view: MonitorView, context: Context) { view.onOutside = onOutside }

    final class MonitorView: NSView {
        var onOutside: () -> Void
        private var monitor: Any?
        init(onOutside: @escaping () -> Void) { self.onOutside = onOutside; super.init(frame: .zero) }
        required init?(coder: NSCoder) { fatalError("not used") }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let monitor { NSEvent.removeMonitor(monitor); self.monitor = nil }
            guard window != nil else { return }
            monitor = NSEvent.addLocalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] event in
                guard let self, let sheet = self.window, let parent = sheet.sheetParent,
                      event.window === parent else { return event }
                self.onOutside()
                return nil
            }
        }
    }
}
