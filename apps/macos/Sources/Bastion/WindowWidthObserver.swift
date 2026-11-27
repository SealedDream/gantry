import AppKit
import SwiftUI

/// Reports the hosting window's content width as it resizes (MAC-INSPECTOR-FIT).
/// The window, not the SwiftUI content: when the split view's column minimums exceed the window,
/// the content grows past it, so a geometry reader inside it never sees the window as narrow.
struct WindowWidthObserver: NSViewRepresentable {
    let onChange: (CGFloat) -> Void

    func makeNSView(context: Context) -> ObserverView { ObserverView(onChange: onChange) }
    func updateNSView(_ view: ObserverView, context: Context) { view.onChange = onChange }

    final class ObserverView: NSView {
        var onChange: (CGFloat) -> Void
        private var token: NSObjectProtocol?

        init(onChange: @escaping (CGFloat) -> Void) {
            self.onChange = onChange
            super.init(frame: .zero)
        }

        required init?(coder: NSCoder) { nil }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let token { NotificationCenter.default.removeObserver(token) }
            token = nil
            guard let window else { return }
            token = NotificationCenter.default.addObserver(forName: NSWindow.didResizeNotification, object: window, queue: .main) { [weak self, weak window] _ in
                guard let window else { return }
                MainActor.assumeIsolated { self?.onChange(window.contentLayoutRect.width) }
            }
            let now = window.contentLayoutRect.width
            DispatchQueue.main.async { [weak self] in self?.onChange(now) }
        }
    }
}
