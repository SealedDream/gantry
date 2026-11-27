import SwiftUI

/// The toolbar's tab strip in its own `NSHostingView`. Placed straight in a `ToolbarItem`, every
/// change the strip shows (above all the selected tab) went through SwiftUI's toolbar bridge, which
/// rebuilt the window's NSToolbar items each time (`ToolbarBridge.makeStorage`, re-added item views):
/// a tab switch took ~140 ms, 9 ms without the strip (budget 50 ms). In its own hosting view the
/// strip updates in its own view graph and the toolbar only sees a size change.
struct HostedTabStrip: NSViewRepresentable {
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @Environment(Commands.self) private var commands
    @Environment(SettingsModel.self) private var settings
    @Environment(AppearanceSettings.self) private var appearance
    @Environment(CredentialsModel.self) private var credentials
    @Environment(VaultwardenModel.self) private var vaultwarden
    @Environment(AppRouter.self) private var router
    @Environment(WorkspaceModel.self) private var workspaces
    @Environment(ShortcutsModel.self) private var shortcuts

    func makeNSView(context: Context) -> StripHost {
        let host = StripHost(rootView: root)
        // The toolbar sizes the item from the strip's own fixed width and height.
        host.sizingOptions = [.intrinsicContentSize, .minSize]
        // The toolbar may squeeze the strip down to its minimum (‹ › and +) when the bar has less
        // room than the strip asks for, as on a full-screen top-edge hover; at full resistance it
        // moved the inspector toggle into the » menu instead (owner round 3, item 16).
        host.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        // Bounded: each re-measure asks for less, so a strip that does not fit cannot rebuild the toolbar forever.
        host.remeasure = { [sessions, settings] in
            sessions.stripStillInOverflow(ideal: SessionTabStrip.width(forArea: sessions.sessionAreaWidth, sessions: sessions, settings: settings),
                                          minimum: SessionTabStrip.minWidth)
        }
        StripHost.current = host
        StripHost.installMenuMonitor()
        return host
    }

    func updateNSView(_ host: StripHost, context: Context) {
        host.rootView = root
    }

    /// The strip's hosting view. Its width follows the session area through its intrinsic size, with
    /// no new toolbar identity per width step (MAC-LIBRARY-SLIDE). That works while the item is in
    /// the bar. When the window narrows, the toolbar lays out before the strip has its new width, so
    /// the strip (and the inspector toggle after it) moves into the » menu; there the view is out of
    /// the window, its size changes never reach NSToolbar, and the items stayed in the menu
    /// (MAC-TOOLBAR-OVERFLOW). So a strip in the menu gets a new toolbar identity once, after its
    /// width has settled, and NSToolbar measures it afresh. Only then: a rebuild per width step
    /// was the post-slide stall.
    final class StripHost: NSHostingView<AnyView> {
        /// The main window's strip; a strip that is replaced or closed is never re-measured.
        @MainActor static weak var current: StripHost?
        var remeasure: (() -> Void)?
        private var wasInWindow = false

        /// Waits for the session area width to settle (`SessionsModel.sessionAreaResized`, 150 ms).
        private static let settle: Duration = .milliseconds(250)

        /// The tab anchor (`TabMenuAnchor`) under a right-click or control-click in this strip.
        func anchor(for event: NSEvent) -> TabMenuAnchor.AnchorView? {
            guard event.window === window else { return nil }
            return TabMenuAnchor.AnchorView.under(event.locationInWindow, in: self)
        }

        /// Right-click over a tab opens the tab's menu (over a group chip, its editor). Caught before
        /// window dispatch: in the toolbar, AppKit's item viewer takes the right-click for its own
        /// "Icon and Text / Icon Only" menu, and neither SwiftUI's `.contextMenu` nor this view ever
        /// saw it (owner round 4, item 5). One monitor for the app; other events pass untouched.
        @MainActor static func installMenuMonitor() {
            guard monitor == nil else { return }
            monitor = NSEvent.addLocalMonitorForEvents(matching: [.rightMouseDown, .leftMouseDown]) { event in
                guard event.type == .rightMouseDown || event.modifierFlags.contains(.control),
                      let host = current, let anchor = host.anchor(for: event) else { return event }
                // After this event returns: a menu opened inside the monitor did not start tracking.
                let at = host.convert(event.locationInWindow, from: nil)
                DispatchQueue.main.async {
                    if let menu = anchor.makeMenu?() { menu.popUp(positioning: nil, at: at, in: host) } else { anchor.action?() }
                }
                return nil
            }
        }
        @MainActor private static var monitor: Any?

        /// In the » menu: once shown in the bar and now out of the window.
        var isInOverflow: Bool { wasInWindow && window == nil }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard window == nil else { wasInWindow = true; return }
            guard wasInWindow else { return }
            Task { @MainActor [weak self] in
                try? await Task.sleep(for: Self.settle)
                guard let self, Self.current === self, self.isInOverflow else { return }
                self.remeasure?()
            }
        }
    }

    private var root: AnyView {
        AnyView(SessionTabStrip()
            .uiZoomRoot()
            .environment(model)
            .environment(sessions)
            .environment(commands)
            .environment(settings)
            .environment(appearance)
            .environment(credentials)
            .environment(vaultwarden)
            .environment(router)
            .environment(workspaces)
            .environment(shortcuts)
            .modifier(ThemedRoot(settings: appearance))
            .modifier(ChromeTonesFromSessions()))
    }
}
