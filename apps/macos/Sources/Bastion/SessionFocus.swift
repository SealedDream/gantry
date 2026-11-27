import AppKit
import SwiftUI
import WebKit

/// Reports whether keyboard focus is in a session (terminal, remote desktop, web page) of the
/// window this view is in, for the `tree.auto-hide` setting. Watches the window's first responder.
struct SessionFocusObserver: NSViewRepresentable {
    let changed: (Bool) -> Void

    func makeNSView(context: Context) -> ObserverView { ObserverView(changed: changed) }
    func updateNSView(_ view: ObserverView, context: Context) { view.changed = changed }

    final class ObserverView: NSView {
        var changed: (Bool) -> Void
        private var observation: NSKeyValueObservation?

        init(changed: @escaping (Bool) -> Void) {
            self.changed = changed
            super.init(frame: .zero)
        }
        required init?(coder: NSCoder) { nil }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            // AppKit reports first-responder changes on the main thread.
            observation = window?.observe(\.firstResponder, options: [.initial, .new]) { [weak self] window, _ in
                let focused = Self.isSession(window.firstResponder)
                MainActor.assumeIsolated { self?.changed(focused) }
            }
        }

        static func isSession(_ responder: NSResponder?) -> Bool {
            var view = responder as? NSView
            while let v = view {
                if v is TerminalNSView || v is RemoteDesktopCanvas || v is WKWebView { return true }
                view = v.superview
            }
            return false
        }
    }
}
