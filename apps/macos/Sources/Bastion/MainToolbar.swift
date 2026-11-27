import AppKit
import SwiftUI
import BastionCore

// The toolbar is split by column, as in Finder and Xcode: what changes the library sits over the
// sidebar, what acts on sessions over the session canvas. The window title is hidden (the
// workspace menu names the current context), so the canvas segment holds its items at the
// default window size instead of pushing them into the overflow menu.

/// Leading edge, beside the library toggle: open sessions and +. In the root toolbar, not the
/// sidebar column's: items leaving with the column made NSToolbar rebuild and re-lay out mid-slide,
/// so hiding the library stuttered while the inspector slid smoothly (owner feedback 4, 2026-11-07).
/// Everything that used to sit in the "More" menu lives in the menu bar (owner feedback 12).
struct LibraryToolbar: ToolbarContent {
    let addMenu: AddMenuState
    let commands: Commands
    let sel: LibrarySelection
    let shortcuts: ShortcutsModel

    var body: some ToolbarContent {
        let _ = RenderCount.hit("LibraryToolbar")
        // Read when an add action runs, so the toolbar does not re-render per selection.
        let folder = { [sel, commands] in sel.id.flatMap { commands.model.folder(id: $0) != nil ? $0 : nil } }
        ToolbarItemGroup(placement: .navigation) {
            // Owner 2026-11-05 (c): open sessions on the far left, beside the sidebar toggle.
            OpenSessionsMenu()
            AddToolbarButton(state: addMenu, help: shortcuts.help("Add a connection or folder", "add"),
                             addFolder: { [commands] in commands.run("new-subfolder", on: folder()) },
                             addConnection: { [commands] in
                                 if $0 == AddMenu.fromTemplate { commands.newFromTemplate = ParentTarget(id: folder()) }
                                 else { commands.addConnection = ParentTarget(id: folder(), protocolName: $0) } })
        }
    }
}

/// Whether the + popover shows. An object, not a binding: the toolbar's inputs must stay the same
/// value from one window update to the next (`MainWindowToolbar`), and a binding's captured value
/// changes with every open and close.
@MainActor @Observable
final class AddMenuState {
    var showing = false
}

/// +: an AppKit button with an NSPopover built once and kept. The SwiftUI `.popover` on a toolbar
/// Button rebuilt the toolbar group and the whole AddMenu per click (owner feedback 9).
struct AddToolbarButton: NSViewRepresentable {
    let state: AddMenuState
    let help: String
    let addFolder: () -> Void
    let addConnection: (String) -> Void

    func makeNSView(context: Context) -> AddPopoverButton {
        let button = AddPopoverButton(addFolder: addFolder, addConnection: addConnection)
        button.toolTip = help
        button.onShownChange = { [state] shown in if state.showing != shown { state.showing = shown } }
        button.follow(state)
        return button
    }
    func updateNSView(_ button: AddPopoverButton, context: Context) {}
    func sizeThatFits(_ proposal: ProposedViewSize, nsView: AddPopoverButton, context: Context) -> CGSize? { nsView.fittingSize }
}

@MainActor
final class AddPopoverButton: NSButton, NSPopoverDelegate {
    var onShownChange: ((Bool) -> Void)?
    private let popover = NSPopover()

    init(addFolder: @escaping () -> Void, addConnection: @escaping (String) -> Void) {
        super.init(frame: .zero)
        bezelStyle = .toolbar
        image = NSImage(systemSymbolName: "plus", accessibilityDescription: "Add")
        imagePosition = .imageOnly
        setAccessibilityLabel("Add")
        target = self
        action = #selector(toggle)
        popover.behavior = .transient
        popover.delegate = self
        let close: () -> Void = { [weak popover] in popover?.performClose(nil) }
        let host = NSHostingController(rootView: AnyView(
            AddMenu(addFolder: addFolder, addConnection: addConnection, close: close).uiZoomRoot()))
        host.sizingOptions = [.preferredContentSize]
        popover.contentViewController = host
        // Build the menu's views after launch, off the click path.
        DispatchQueue.main.async { host.view.layoutSubtreeIfNeeded() }
    }

    /// Delay after the button appears before the hidden first show (OF-B3: the first open cost
    /// 106-114 ms of popover window creation, material and SwiftUI first layout).
    private static let prewarmDelay: TimeInterval = 1.2
    private var prewarming = false
    private var prewarmed = false

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window != nil, followed?.showing == true, !popover.isShown { setShown(true) }
        guard window != nil, !prewarmed else { return }
        prewarmed = true
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.prewarmDelay) { [weak self] in self?.prewarm() }
    }

    /// Shows this popover once, unseen, anchored to a transparent offscreen window, then closes it.
    private func prewarm() {
        guard !popover.isShown else { return }
        let anchorWindow = PrewarmWindow(contentRect: NSRect(x: -20_000, y: -20_000, width: 40, height: 40),
                                         styleMask: [.borderless], backing: .buffered, defer: false)
        anchorWindow.ignoresMouseEvents = true
        anchorWindow.collectionBehavior = [.transient, .ignoresCycle]
        let anchor = NSView(frame: anchorWindow.contentLayoutRect)
        anchorWindow.contentView = anchor
        let key = NSApp.keyWindow
        anchorWindow.orderBack(nil)
        prewarming = true
        let animates = popover.animates
        popover.animates = false
        popover.show(relativeTo: anchor.bounds, of: anchor, preferredEdge: .maxY)
        popover.contentViewController?.view.window?.displayIfNeeded()
        popover.close()
        popover.animates = animates
        prewarming = false
        anchorWindow.orderOut(nil)
        key?.makeKey()
    }

    func popoverWillShow(_ notification: Notification) {
        // Unseen while prewarming: the popover window keeps its alpha until shown for real.
        popover.contentViewController?.view.window?.alphaValue = prewarming ? 0 : 1
    }
    required init?(coder: NSCoder) { fatalError("not used") }

    #if BASTION_TEST_HOOKS
    /// The popover is shown until its close has finished (`popoverDidClose`), about 0.6 s after its
    /// window has faded out; a click before that toggles it closed again (of-b-perf, 2026-11-26).
    var isPopoverShown: Bool { popover.isShown }
    #endif

    @objc private func toggle() { setShown(!popover.isShown) }

    /// Shows or closes the popover whenever `state` changes (the Add route, a scripted sheet); the
    /// button observes it itself, so the toolbar item never updates for it.
    func follow(_ state: AddMenuState) {
        followed = state
        let shown = withObservationTracking { state.showing } onChange: { [weak self] in
            Task { @MainActor in self?.follow(state) }
        }
        setShown(shown)
    }

    /// The state followed; a show asked for before the button was in a window happens once it is.
    private weak var followed: AddMenuState?

    func setShown(_ shown: Bool) {
        if shown == popover.isShown { return }
        if shown {
            guard window != nil else { return }
            popover.show(relativeTo: bounds, of: self, preferredEdge: .maxY)
        } else {
            popover.performClose(nil)
        }
        onShownChange?(popover.isShown)
    }

    func popoverDidClose(_ notification: Notification) {
        popover.contentViewController?.view.window?.alphaValue = 1
        if !prewarming { onShownChange?(false) }
    }
}

/// Over the session canvas: the tab strip on the leading edge, filling the width; actions on
/// the trailing edge. Shortcuts live in the menu bar (`AppMenus`); tooltips name them.
struct SessionToolbar: ToolbarContent {
    let sel: LibrarySelection
    let commands: Commands
    let sessions: SessionsModel
    let router: AppRouter
    let shortcuts: ShortcutsModel

    var body: some ToolbarContent {
        let _ = RenderCount.hit("SessionToolbar")
        // Tabs beside the traffic lights: the window has no separate tab row. The item is always
        // there (no width without tabs): created for a burst of 40+ tabs, as a workspace opens
        // them, NSToolbar measured it before layout and hid the strip in the » menu.
        // Its own hosting view (no toolbar rebuild per tab switch). Its width follows the session
        // area through the hosting view's intrinsic size; no new identity per width step: that
        // rebuilt the toolbar 150 ms after every panel slide, the ~90 ms post-slide stall
        // (MAC-LIBRARY-SLIDE). The width no longer depends on whether tabs are open (nm-22).
        ToolbarItem(placement: .navigation) { HostedTabStrip().id(sessions.stripIdentity) }
            // Flat tabs straight on the bar (owner 2026-11-17): no glass capsule around the strip.
            .flatToolbarItem()
        // Everything else sits on the trailing edge (owner UX spec 2026-11-04 §4): the tabs take the
        // width between the library toggle and these items. Workspaces live in the library
        // sidebar's header, the File and Window menus and the palette (`WorkspaceMenuItems`).
        ToolbarItemGroup(placement: .primaryAction) {
            FindToolbarButton(sessions: sessions, shortcuts: shortcuts)
            // The route opens the popover (`ContentView.open`), as ⌘L and the menu do.
            ToolbarSymbolButton(symbol: "bolt", label: "Quick Connect", help: shortcuts.help("Quick Connect to an address", "quick-connect")) { [router] in
                router.open("quick-connect")
            }
            connectionMenu
            SplitToolbarMenu(sessions: sessions, router: router, shortcuts: shortcuts)
        }
    }

    /// Click runs the selection's default action (⌘↩); the arrow lists every registry action.
    /// AppKit, observing the selection itself: as a SwiftUI Menu reading `sel.id` in this body,
    /// every library click rebuilt the toolbar group (nm-22: the 280 ms first-select stall).
    private var connectionMenu: some View {
        ConnectToolbarControl(sel: sel, commands: commands, help: shortcuts.help("Default action for the selection", "default-action") + "; the arrow lists every action")
    }
}

// Find and Split enable only while the selected tab has a terminal. They are AppKit controls
// that observe that one fact themselves: as SwiftUI views their disabled state changing (the
// first terminal opening, the last closing) made SwiftUI rebuild the toolbar group (nm-22).
struct FindToolbarButton: NSViewRepresentable {
    let sessions: SessionsModel
    let shortcuts: ShortcutsModel

    func makeNSView(context: Context) -> ClosureToolbarButton {
        let button = ClosureToolbarButton(symbol: "magnifyingglass", label: "Find") { [sessions] in
            // Only with a terminal: a click elsewhere left search on, and the next terminal's first
            // click then turned it off (owner point 30).
            guard sessions.selectedTab?.terminal != nil else { return }
            sessions.searching ? sessions.endSearch() : (sessions.searching = true)
        }
        button.toolTip = shortcuts.help("Find in terminal", "find")
        TerminalEnabled.track(sessions) { [weak button] in button?.allowed = $0 }
        return button
    }
    func updateNSView(_ view: ClosureToolbarButton, context: Context) {}
    func sizeThatFits(_ proposal: ProposedViewSize, nsView: ClosureToolbarButton, context: Context) -> CGSize? { nsView.fittingSize }
}

/// A toolbar button that runs an action: AppKit, like Find and Split. As a SwiftUI `Button` with a
/// system image, SwiftUI made the item's overflow-menu entry again on every toolbar tile, loading
/// the symbol image from the asset catalog each time (MAC-STALLS profile: about 50 ms of symbol
/// loads over one perf run, in the library slides and the first tabs).
struct ToolbarSymbolButton: NSViewRepresentable {
    let symbol: String
    let label: String
    let help: String
    let run: () -> Void

    func makeNSView(context: Context) -> ClosureToolbarButton {
        let button = ClosureToolbarButton(symbol: symbol, label: label, run: run)
        button.toolTip = help
        return button
    }
    func updateNSView(_ view: ClosureToolbarButton, context: Context) {}
    func sizeThatFits(_ proposal: ProposedViewSize, nsView: ClosureToolbarButton, context: Context) -> CGSize? { nsView.fittingSize }
}

struct SplitToolbarMenu: NSViewRepresentable {
    let sessions: SessionsModel
    let router: AppRouter
    let shortcuts: ShortcutsModel

    func makeNSView(context: Context) -> SplitSegments {
        let control = SplitSegments(router: router)
        control.toolTip = "Split the terminal: " + shortcuts.help("right", "split-right") + " or " + shortcuts.help("down", "split-down")
        TerminalEnabled.track(sessions) { [weak control] in control?.allowed = $0 }
        return control
    }
    func updateNSView(_ view: SplitSegments, context: Context) {}
    func sizeThatFits(_ proposal: ProposedViewSize, nsView: SplitSegments, context: Context) -> CGSize? { nsView.fittingSize }
}

struct ConnectToolbarControl: NSViewRepresentable {
    let sel: LibrarySelection
    let commands: Commands
    let help: String

    func makeNSView(context: Context) -> NSSegmentedControl {
        let control = ConnectSegments(sel: sel, commands: commands)
        control.toolTip = help
        return control
    }
    func updateNSView(_ view: NSSegmentedControl, context: Context) {}
    func sizeThatFits(_ proposal: ProposedViewSize, nsView: NSSegmentedControl, context: Context) -> CGSize? { nsView.fittingSize }
}

/// Connect: the icon runs the default action; the arrow builds the action menu on click.
final class ConnectSegments: NSSegmentedControl {
    private let sel: LibrarySelection
    private let commands: Commands
    init(sel: LibrarySelection, commands: Commands) {
        self.sel = sel
        self.commands = commands
        super.init(frame: .zero)
        segmentCount = 2
        trackingMode = .momentary
        segmentStyle = .separated
        setImage(NSImage(systemSymbolName: "play", accessibilityDescription: "Connect"), forSegment: 0)
        setImage(NSImage(systemSymbolName: "chevron.down", accessibilityDescription: "Connect options"), forSegment: 1)
        setWidth(28, forSegment: 0)
        setWidth(14, forSegment: 1)
        setAccessibilityLabel("Connect")
        target = self
        action = #selector(clicked)
        track()
    }
    required init?(coder: NSCoder) { fatalError("not used") }

    private func track() {
        let on = withObservationTracking { sel.id != nil } onChange: { [weak self] in
            Task { @MainActor in self?.track() }
        }
        allowed = on
    }

    /// NSToolbar validation enables an item's control by itself; this keeps it off while not allowed.
    var allowed = true { didSet { super.isEnabled = allowed } }
    override var isEnabled: Bool {
        get { super.isEnabled }
        set { super.isEnabled = newValue && allowed }
    }

    @objc private func clicked() {
        guard allowed, let id = sel.id else { return }
        if selectedSegment == 0 { return commands.performDefault(on: id) }
        let menu = NSMenu()
        ActionMenuBuilder.fill(menu, items: commands.menu(for: id), submenu: { [commands] in commands.submenu(for: $0, on: id) }) { [commands] in commands.perform($0, on: id) }
        menu.popUp(positioning: nil, at: NSPoint(x: width(forSegment: 0), y: bounds.height + 4), in: self)
    }
}

/// Calls `apply` with whether the selected tab has a terminal, now and whenever that changes.
@MainActor
enum TerminalEnabled {
    static func track(_ sessions: SessionsModel, _ apply: @escaping @MainActor @Sendable (Bool) -> Void) {
        let on = withObservationTracking { sessions.selectedTab?.terminal != nil } onChange: {
            Task { @MainActor in track(sessions, apply) }
        }
        apply(on)
    }
}

final class ClosureToolbarButton: NSButton {
    private let run: () -> Void
    init(symbol: String, label: String, run: @escaping () -> Void) {
        self.run = run
        super.init(frame: .zero)
        bezelStyle = .toolbar
        // Not NSButton's default "Button": the item is known by its label (header-layout finds the
        // inspector toggle by it).
        title = ""
        image = NSImage(systemSymbolName: symbol, accessibilityDescription: label)
        imagePosition = .imageOnly
        setAccessibilityLabel(label)
        target = self
        action = #selector(fire)
    }
    required init?(coder: NSCoder) { fatalError("not used") }
    @objc private func fire() { run() }

    /// NSToolbar validation enables an item's control by itself; this keeps it off while not allowed.
    var allowed = true { didSet { super.isEnabled = allowed } }
    override var isEnabled: Bool {
        get { super.isEnabled }
        set { super.isEnabled = newValue && allowed }
    }
}

/// Split: the icon splits right; the arrow segment lists Split Right and Split Down.
final class SplitSegments: NSSegmentedControl {
    private let router: AppRouter
    init(router: AppRouter) {
        self.router = router
        super.init(frame: .zero)
        segmentCount = 2
        trackingMode = .momentary
        segmentStyle = .separated
        setImage(NSImage(systemSymbolName: "rectangle.split.2x1", accessibilityDescription: "Split"), forSegment: 0)
        setImage(NSImage(systemSymbolName: "chevron.down", accessibilityDescription: "Split options"), forSegment: 1)
        setWidth(28, forSegment: 0)
        setWidth(14, forSegment: 1)
        let menu = NSMenu()
        menu.addItem(ClosureMenuItem(title: "Split Right") { [router] in router.open("split-right") })
        menu.addItem(ClosureMenuItem(title: "Split Down") { [router] in router.open("split-down") })
        setMenu(menu, forSegment: 1)
        setShowsMenuIndicator(false, forSegment: 1)
        setAccessibilityLabel("Split")
        target = self
        action = #selector(clicked)
    }
    required init?(coder: NSCoder) { fatalError("not used") }
    /// NSToolbar validation enables an item's control by itself; this keeps it off while not allowed.
    var allowed = true { didSet { super.isEnabled = allowed } }
    override var isEnabled: Bool {
        get { super.isEnabled }
        set { super.isEnabled = newValue && allowed }
    }

    @objc private func clicked() {
        guard allowed else { return }
        if selectedSegment == 0 { router.open("split-right") }
        else if let menu = menu(forSegment: 1) { menu.popUp(positioning: nil, at: NSPoint(x: width(forSegment: 0), y: bounds.height + 4), in: self) }
    }
}

/// The inspector toggle, flush with the window's right edge (owner 2026-11-23): a trailing titlebar
/// accessory, not a toolbar item, because the toolbar leaves a trailing margin of its own (44 pt
/// measured). In the root window (not the inspector's), so the inspector hiding as a tab opens does
/// not change the toolbar (nm-24). Settings is Bastion › Settings…, ⌘,.
struct InspectorAccessoryInstaller: NSViewRepresentable {
    let router: AppRouter
    let shortcuts: ShortcutsModel

    func makeNSView(context: Context) -> InstallerView { InstallerView(router: router, help: shortcuts.help("Show or hide the inspector", "toggle-inspector")) }
    func updateNSView(_ view: InstallerView, context: Context) {}

    /// Adds the accessory once, when the view reaches its window.
    final class InstallerView: NSView {
        static let identifier = NSUserInterfaceItemIdentifier("inspector-toggle-accessory")
        private let router: AppRouter
        private let help: String
        init(router: AppRouter, help: String) {
            self.router = router
            self.help = help
            super.init(frame: .zero)
        }
        required init?(coder: NSCoder) { fatalError("not used") }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard let window, !window.titlebarAccessoryViewControllers.contains(where: { $0.view.identifier == Self.identifier }) else { return }
            let button = ClosureToolbarButton(symbol: "sidebar.right", label: "Inspector") { [router] in router.open("toggle-inspector") }
            button.toolTip = help
            // A titlebar accessory takes its size from the view's frame, not from Auto Layout.
            let natural = button.cell?.cellSize(forBounds: NSRect(x: 0, y: 0, width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)) ?? button.fittingSize
            let size = NSSize(width: max(natural.width, button.fittingSize.width), height: max(natural.height, button.fittingSize.height))
            let height = DS.Size.minHitTarget + 4
            let holder = NSView(frame: NSRect(x: 0, y: 0, width: size.width + Self.edgeInset, height: height))
            holder.identifier = Self.identifier
            button.frame = NSRect(x: 0, y: (height - size.height) / 2, width: size.width, height: size.height)
            button.autoresizingMask = [.maxXMargin, .minYMargin, .maxYMargin]
            holder.addSubview(button)
            let accessory = NSTitlebarAccessoryViewController()
            accessory.view = holder
            accessory.layoutAttribute = .trailing
            window.addTitlebarAccessoryViewController(accessory)
        }
        /// Space between the button and the window's right edge.
        static let edgeInset: CGFloat = 12
    }
}

/// The window's toolbar, in its own modifier. Its inputs are references that stay the same from one
/// window update to the next, so a re-run of `ContentView.body` (a library toggle, a tab opening)
/// no longer re-evaluates the toolbar content. Each re-evaluation made SwiftUI's toolbar bridge build
/// every item again (`ToolbarBridge.makeStorage`), and NSToolbar then re-tiled and made each item's
/// overflow-menu entry again (MAC-STALLS profile: about 13 ms of rebuild and 20–50 ms of tiling per
/// library toggle).
struct MainWindowToolbar: ViewModifier {
    let sel: LibrarySelection
    let addMenu: AddMenuState
    @Environment(SessionsModel.self) private var sessions
    @Environment(Commands.self) private var commands
    @Environment(SettingsModel.self) private var settings
    @Environment(AppRouter.self) private var router
    @Environment(ShortcutsModel.self) private var shortcuts
    @ObservedObject private var launch = LaunchGate.shared

    func body(content: Content) -> some View {
        let _ = RenderCount.hit("MainWindowToolbar")
        let ready = launch.isOpen && DocumentGate.shared.isOpen
        // Built after the first frame (LaunchGate): the toolbar bridge dominated launch time.
        content.background(InspectorAccessoryInstaller(router: router, shortcuts: shortcuts)).toolbar {
            if ready && HeaderStyle.isCompact(settings) {
                CompactToolbar(sessions: sessions)
            } else if ready {
                LibraryToolbar(addMenu: addMenu, commands: commands, sel: sel, shortcuts: shortcuts)
                SessionToolbar(sel: sel, commands: commands, sessions: sessions, router: router, shortcuts: shortcuts)
            }
        }
    }
}

/// Hide the "Gantry" title on macOS 15+, where the workspace menu carries the context; macOS
/// 14 keeps it (and may overflow sooner at small widths).
struct HiddenWindowTitle: ViewModifier {
    func body(content: Content) -> some View {
        if #available(macOS 15, *) { content.toolbar(removing: .title) } else { content }
    }
}

/// "▣ N ▾": every open tab (torn-off ones too), and New Local Shell. An AppKit button that keeps
/// its own count up to date (Observation, outside SwiftUI) and builds its menu on click: when the
/// SwiftUI label or menu read the tabs, every tab open, close or rename made SwiftUI rebuild the
/// toolbar item group (nm-22: most of tab-close time and the 240 ms local-shell stall).
struct OpenSessionsMenu: NSViewRepresentable {
    @Environment(SessionsModel.self) private var sessions

    func makeNSView(context: Context) -> SessionsCountButton { SessionsCountButton(sessions: sessions) }
    func updateNSView(_ view: SessionsCountButton, context: Context) {}
    /// At least the "999" width from the first measure: NSToolbar keeps an item's first size.
    func sizeThatFits(_ proposal: ProposedViewSize, nsView: SessionsCountButton, context: Context) -> CGSize? {
        let size = nsView.fittingSize
        return CGSize(width: max(size.width, SessionsCountButton.widest), height: size.height)
    }
}

@MainActor
final class SessionsCountButton: NSButton {
    private let sessions: SessionsModel

    init(sessions: SessionsModel) {
        self.sessions = sessions
        super.init(frame: .zero)
        bezelStyle = .toolbar
        image = NSImage(systemSymbolName: "macwindow.on.rectangle", accessibilityDescription: nil)
        // Icon only (owner 2026-11-17): the count is in the tooltip and the menu.
        imagePosition = .imageOnly
        // Same-width digits, and the size reported only when it really changes: a new width made
        // SwiftUI rebuild this whole toolbar group (nm-23: part of the first local-shell stall).
        font = .monospacedDigitSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        target = self
        action = #selector(showMenu)
        track()
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        // Test hooks: a plain AppKit tool tip, the control for `tip-hover`.
        if TestHooks.isScripted, window != nil { DriverEvents.headerViews["open-sessions-button"] = WeakView(self) }
    }

    private var reportedSize: NSSize?

    /// Content size, never narrower than with "999": NSToolbar keeps an item's first measured
    /// size, so a width taken at "3" cut "33" (needs 61 pt, had 56). Digits are same-width, so
    /// every count up to 999 fits and the size does not change while tabs open and close.
    override var intrinsicContentSize: NSSize {
        let size = super.intrinsicContentSize
        return NSSize(width: max(size.width, Self.widest), height: size.height)
    }

    /// The width of this button's cell showing "999" (what the title needs, not the toolbar bezel's
    /// smaller intrinsic size): a probe button with the same bezel, image and font.
    static let widest: CGFloat = {
        let probe = NSButton(title: "", target: nil, action: nil)
        probe.bezelStyle = .toolbar
        probe.image = NSImage(systemSymbolName: "macwindow.on.rectangle", accessibilityDescription: nil)
        probe.imagePosition = .imageOnly
        probe.font = .monospacedDigitSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        let huge = NSRect(x: 0, y: 0, width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        return ceil(max(probe.intrinsicContentSize.width, probe.cell?.cellSize(forBounds: huge).width ?? 0))
    }()

    override func invalidateIntrinsicContentSize() {
        let size = intrinsicContentSize
        guard size != reportedSize else { return }
        reportedSize = size
        super.invalidateIntrinsicContentSize()
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    /// Re-reads the count whenever it changes; nothing else is observed.
    private func track() {
        let count = withObservationTracking { sessions.tabCount } onChange: { [weak self] in
            Task { @MainActor in self?.track() }
        }
        let help = count == 1 ? "1 open session" : "\(count) open sessions"
        toolTip = help
        setAccessibilityLabel(help)
    }

    @objc private func showMenu() {
        let menu = NSMenu()
        for tab in sessions.tabs {
            let item = ClosureMenuItem(title: tab.title) { [sessions] in sessions.selected = tab.id }
            item.image = NSImage(systemSymbolName: tab.symbol, accessibilityDescription: nil)
            item.state = tab.id == sessions.selected ? .on : .off
            menu.addItem(item)
        }
        if !sessions.tabs.isEmpty { menu.addItem(.separator()) }
        menu.addItem(ClosureMenuItem(title: "New Local Shell") { [sessions] in sessions.openLocal() })
        menu.popUp(positioning: nil, at: NSPoint(x: 0, y: bounds.height + 4), in: self)
    }
}

extension ToolbarContent {
    /// macOS 26+: no shared Liquid Glass background behind the item; earlier systems draw none.
    @ToolbarContentBuilder func flatToolbarItem() -> some ToolbarContent {
        if #available(macOS 26, *) { sharedBackgroundVisibility(.hidden) } else { self }
    }
}
