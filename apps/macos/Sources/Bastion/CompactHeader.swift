import AppKit
import Combine
import SwiftUI

// HEADER-A (owner, 2026-11-14, option A "Compact"): one title-bar row. Traffic lights; the
// library switcher across the sidebar's width (its trailing edge on the sidebar's divider);
// then the tab group button, the tabs and +; the inspector toggle at the trailing end.
// Settings › Appearance › Header style switches back to Classic (`LibraryToolbar`,
// `SessionToolbar`), which is kept unchanged.

/// The `appearance.header-style` setting (core `settings.rs`); anything but "classic" is Compact.
enum HeaderStyle {
    static let settingKey = "appearance.header-style"
    @MainActor static func isCompact(_ settings: SettingsModel) -> Bool { settings.value(settingKey) != "classic" }
}

struct CompactToolbar: ToolbarContent {
    let sessions: SessionsModel

    var body: some ToolbarContent {
        // The switcher sits in the library column's own toolbar (`CompactSidebarHeader`); AppKit
        // keeps that item at the leading edge while the column is hidden, where it is an icon.
        // One group, as on main: the strip's width budget (`SessionTabStrip.compactNeighbours`) is
        // measured for it. Split into two items, the extra item spacing pushed the library picker
        // and the inspector toggle into the » menu (owner round 2). Flat: no glass capsule.
        ToolbarItemGroup(placement: .navigation) {
            OpenSessionsMenu()
            HostedTabStrip().id(sessions.stripIdentity)
        }
        .flatToolbarItem()
    }
}

/// "Personal ▾": the open libraries (Personal and documents) and Show/Hide Library. As wide as
/// the sidebar less the room left of it (traffic lights); an icon button while the sidebar is hidden.
struct LibrarySwitcher: View {
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @Environment(AppRouter.self) private var router
    let libraryShown: Bool
    /// Narrower by this much after the item landed in » (`OverflowRemeasure`): the bar had less
    /// room than measured, as on the full-screen reveal, so it shrinks rather than stay in ».
    var squeeze: CGFloat = 0
    static let squeezeStep: CGFloat = 24
    /// Window x of this item's leading edge, read once it is placed.
    @State private var originX: CGFloat?

    /// Gap between the switcher's trailing edge and the sidebar's divider.
    private static let dividerGap: CGFloat = 8
    private static let minWidth: CGFloat = 96

    /// The leading x the switcher has with the traffic lights shown, kept from the last windowed
    /// measure. Full screen hides the lights until the pointer reaches the top edge; then they come
    /// back in front of the switcher without any notification. Sized from the lights-hidden origin,
    /// the switcher no longer fitted the column on that reveal: AppKit moved it into the » menu and
    /// the tabs shifted over it (owner round 2, item 16). Always sizing for the lights avoids that.
    @MainActor static var originWithLights: CGFloat = 0
    /// Test hooks (`switcher-slack`): the picker asks for this much more than the column has.
    @MainActor static var testSlack: CGFloat = 0

    private var width: CGFloat {
        guard let originX else { return Self.minWidth }
        let origin = max(originX, Self.originWithLights)
        return max(Self.minWidth, sessions.sidebarWidth - origin - Self.dividerGap + Self.testSlack - squeeze)
    }

    var body: some View {
        let _ = RenderCount.hit("LibrarySwitcher")
        // A Button, not a Menu: a toolbar Menu sizes to its own label and ignores the frame.
        Button(action: showMenu) {
            if libraryShown {
                HStack(spacing: DS.Space.xxs) {
                    Image(systemName: model.activeDocumentId == nil ? "person.crop.circle" : "doc.text")
                    Text(model.activeName).lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 0)
                    Image(systemName: "chevron.down").font(DS.Font.caption2.weight(.semibold)).foregroundStyle(.secondary)
                }
                .padding(.horizontal, DS.Space.xs)
                // Flexible down to the minimum: when the bar has less room than measured (the
                // full-screen top-edge reveal brings the traffic lights back in front of it), the
                // toolbar shrinks the picker instead of moving it and the inspector toggle into »
                // (owner round 4, item 16).
                .frame(minWidth: Self.minWidth, idealWidth: width, maxWidth: width, minHeight: DS.Size.minHitTarget,
                       maxHeight: DS.Size.minHitTarget, alignment: .leading)
                .contentShape(Rectangle())
            } else {
                Image(systemName: "sidebar.left").iconHitTarget()
            }
        }
        .buttonStyle(.borderless)
        .foregroundStyle(.primary)
        .help("Switch library")
        .accessibilityLabel("Library: \(model.activeName)")
        .accessibilityIdentifier("library-switcher")
        .background(DriverFrame(name: "library-switcher"))
        .background(WindowOriginReader { x, fullScreen in
            if !fullScreen { Self.originWithLights = x }
            else if Self.originWithLights == 0, let lights = Self.trafficLightsTrailingX() { Self.originWithLights = max(x, lights) }
            if originX != x { originX = x }
        })
        // MAC-FULLSCREEN: full screen has no traffic lights, so the origin (and width) there is
        // larger room than the window has. Kept after leaving, the item no longer fits, AppKit moves
        // it to the overflow menu, and an item off the bar never reports its origin again. Start
        // from the minimum width on every transition and measure again.
        .onReceive(Self.fullScreenTransitions) { _ in originX = nil }
    }
}

extension LibrarySwitcher {
    static let fullScreenTransitions = NotificationCenter.default.publisher(for: NSWindow.willEnterFullScreenNotification)
        .merge(with: NotificationCenter.default.publisher(for: NSWindow.didEnterFullScreenNotification),
               NotificationCenter.default.publisher(for: NSWindow.willExitFullScreenNotification),
               NotificationCenter.default.publisher(for: NSWindow.didExitFullScreenNotification))

    /// Launched straight into full screen there is no windowed measure yet: the zoom button's
    /// trailing edge (the lights exist, hidden, in full screen) plus the gap AppKit leaves after it.
    @MainActor static func trafficLightsTrailingX() -> CGFloat? {
        guard let window = NSApp.windows.first(where: { $0.styleMask.contains(.fullScreen) }),
              let zoom = window.standardWindowButton(.zoomButton) else { return nil }
        return zoom.convert(zoom.bounds, to: nil).maxX.rounded() + DS.Space.s
    }

    /// The open libraries and Show/Hide Library, built on click.
    func showMenu() {
        let menu = NSMenu()
        let personal = ClosureMenuItem(title: model.personalName) { [model] in model.select(nil) }
        personal.state = model.activeDocumentId == nil ? .on : .off
        menu.addItem(personal)
        for d in model.documents {
            let item = ClosureMenuItem(title: d.info.name) { [model] in model.select(d.id) }
            item.state = model.activeDocumentId == d.id ? .on : .off
            menu.addItem(item)
        }
        menu.addItem(.separator())
        menu.addItem(ClosureMenuItem(title: libraryShown ? "Hide Library" : "Show Library") { [router] in router.open("toggle-library") })
        menu.popUp(positioning: nil, at: NSEvent.mouseLocation, in: nil)
    }
}

/// Reports the window x of the view's leading edge after layout.
private struct WindowOriginReader: NSViewRepresentable {
    let report: (CGFloat, Bool) -> Void
    func makeNSView(context: Context) -> OriginView { OriginView(report: report) }
    func updateNSView(_ view: OriginView, context: Context) { view.report = report }

    final class OriginView: NSView {
        var report: (CGFloat, Bool) -> Void
        init(report: @escaping (CGFloat, Bool) -> Void) { self.report = report; super.init(frame: .zero) }
        required init?(coder: NSCoder) { fatalError("not used") }
        override func viewDidMoveToWindow() { super.viewDidMoveToWindow(); send() }
        override func setFrameOrigin(_ p: NSPoint) { super.setFrameOrigin(p); send() }
        override func setFrameSize(_ s: NSSize) { super.setFrameSize(s); send() }
        override func layout() { super.layout(); send() }
        /// After this run loop turn, when the toolbar has placed the item.
        private func send() {
            DispatchQueue.main.async { [weak self] in
                guard let self, let window = self.window else { return }
                // In full screen the toolbar lives in its own window; ask the content window.
                let fullScreen = window.styleMask.contains(.fullScreen) || NSApp.windows.contains { $0.styleMask.contains(.fullScreen) && $0.isVisible }
                self.report(self.convert(self.bounds, to: nil).minX.rounded(), fullScreen)
            }
        }
    }
}

/// Compact, on the library column: the switcher in the column's toolbar section (so it spans the
/// sidebar and follows a resize), and no system sidebar button (the switcher shows and hides the library).
struct CompactSidebarHeader: ViewModifier {
    let compact: Bool
    @State private var remeasures = 0
    private static let maxRemeasures = 8
    @Environment(SessionsModel.self) private var sessions
    @Environment(Commands.self) private var commands
    @Environment(SettingsModel.self) private var settings
    private var shown: Bool { commands.tree.libraryShown(autoHide: settings.value("tree.auto-hide") == "true") }
    private var switcher: some View {
        // A new identity per 4 pt of sidebar width: NSToolbar keeps an item's first measured size.
        // And one each time it lands in »: off the bar it never reports a new size, so it
        // stayed there with the inspector toggle (owner round 4, item 16).
        LibrarySwitcher(libraryShown: shown, squeeze: CGFloat(remeasures) * LibrarySwitcher.squeezeStep)
            // Bounded: at the minimum width a picker still in » stays there rather than rebuild forever.
            .background(OverflowRemeasure { if remeasures < Self.maxRemeasures { remeasures += 1 } })
            .id("\(shown)-\(Int(sessions.sidebarWidth / 4))-\(remeasures)")
    }

    func body(content: Content) -> some View {
        // One modifier chain either way: a branch would give the column a new identity on a style switch.
        content
            .toolbar(removing: compact ? .sidebarToggle : nil)
            // A new sidebar width measures from the full width again.
            .onChange(of: Int(sessions.sidebarWidth / 4)) { _, _ in remeasures = 0 }
            .toolbar {
                // No library switcher on the start window: nothing of the library before a document is open.
                if compact && DocumentGate.shared.isOpen {
                    // UI-06: on the toolbar tone the shared glass pill drew light under light-on-dark text; tones on
                    // drop it, so the switcher sits on the tone like the tabs.
                    if sessions.chromeTones != nil {
                        ToolbarItem(placement: .automatic) { switcher }.flatToolbarItem()
                    } else {
                        ToolbarItem(placement: .automatic) { switcher }
                    }
                }
            }
    }
}

/// Records the view's window frame for the UI driver; nothing outside a scripted test run.
struct DriverFrame: NSViewRepresentable {
    let name: String
    func makeNSView(context: Context) -> FrameView { FrameView(name: name) }
    func updateNSView(_ view: FrameView, context: Context) {}

    final class FrameView: NSView {
        let name: String
        init(name: String) { self.name = name; super.init(frame: .zero) }
        required init?(coder: NSCoder) { fatalError("not used") }
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard TestHooks.isScripted else { return }
            // Gone from the window: forget it, or every closed tab's "strip-tab-<id>" stayed (MAC-MEMORY).
            guard window != nil else {
                if DriverEvents.headerViews[name].map({ $0.view == nil || $0.view === self }) ?? false { DriverEvents.headerViews[name] = nil }
                return
            }
            DriverEvents.headerViews[name] = WeakView(self)
        }
    }
}

/// Calls `remeasure` once the toolbar item holding it has been moved into the » menu (its view
/// left the window) and the layout has settled: a new identity makes NSToolbar measure it afresh.
struct OverflowRemeasure: NSViewRepresentable {
    let remeasure: () -> Void
    func makeNSView(context: Context) -> WatchView { WatchView(remeasure: remeasure) }
    func updateNSView(_ view: WatchView, context: Context) { view.remeasure = remeasure }

    final class WatchView: NSView {
        var remeasure: () -> Void
        private var wasInWindow = false
        /// As the strip (`HostedTabStrip.StripHost`): after the session area width settles.
        private static let settle: Duration = .milliseconds(250)
        init(remeasure: @escaping () -> Void) { self.remeasure = remeasure; super.init(frame: .zero) }
        required init?(coder: NSCoder) { nil }
        override func hitTest(_ point: NSPoint) -> NSView? { nil }
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard window == nil else { wasInWindow = true; return }
            guard wasInWindow else { return }
            Task { @MainActor [weak self] in
                try? await Task.sleep(for: Self.settle)
                guard let self, self.window == nil, self.wasInWindow else { return }
                self.wasInWindow = false
                self.remeasure()
            }
        }
    }
}
