import AppKit
import SwiftUI

/// Driver-only: quiet (accessory) test runs cannot own a full-screen Space, so `fullscreen sim`
/// makes the window chrome behave as in full screen (overlay inspector) without one.
@MainActor @Observable
final class FullScreenSimulation {
    static let shared = FullScreenSimulation()
    var isOn = false
}

/// Reports whether the hosting window is in full screen (enter/exit notifications, plus the
/// state when the view first joins a window).
struct FullScreenObserver: NSViewRepresentable {
    let onChange: (Bool) -> Void

    func makeNSView(context: Context) -> ObserverView { ObserverView(onChange: onChange) }
    func updateNSView(_ view: ObserverView, context: Context) { view.onChange = onChange }

    final class ObserverView: NSView {
        var onChange: (Bool) -> Void
        private var tokens: [NSObjectProtocol] = []

        init(onChange: @escaping (Bool) -> Void) {
            self.onChange = onChange
            super.init(frame: .zero)
        }

        required init?(coder: NSCoder) { nil }

        /// Full screen keeps the toolbar on screen; only the menu bar and Dock hide. With the
        /// default auto-hiding toolbar, a pointer at the top edge slid the toolbar down over the
        /// session's own header row (address, Reconnect, pin) instead of pushing it down (owner
        /// 2026-11-20, 13:51). Safari offers the same as "Always Show Toolbar in Full Screen".
        @MainActor static func keepToolbarShown() {
            let wanted: NSApplication.PresentationOptions = [.fullScreen, .autoHideMenuBar, .autoHideDock]
            if NSApp.presentationOptions != wanted { NSApp.presentationOptions = wanted }
        }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            tokens.forEach(NotificationCenter.default.removeObserver)
            tokens = []
            guard let window else { return }
            let center = NotificationCenter.default
            for (name, on) in [(NSWindow.didEnterFullScreenNotification, true), (NSWindow.willExitFullScreenNotification, false)] {
                tokens.append(center.addObserver(forName: name, object: window, queue: .main) { [weak self] _ in
                    if on { MainActor.assumeIsolated { Self.keepToolbarShown() } }
                    self?.onChange(on)
                })
            }
            let now = window.styleMask.contains(.fullScreen)
            DispatchQueue.main.async { [weak self] in
                if now { Self.keepToolbarShown() }
                self?.onChange(now)
            }
        }
    }
}

/// The inspector drawn over the sessions in full screen: same width as the column, a divider on
/// its leading edge, the window background behind it. The content underneath keeps its size.
struct InspectorOverlay<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        HStack(spacing: 0) {
            Divider()
            content.frame(maxHeight: .infinity, alignment: .top)
        }
        .frame(width: DS.Size.inspectorIdeal)
        .frame(maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
        .accessibilityIdentifier("inspector-overlay")
    }
}
