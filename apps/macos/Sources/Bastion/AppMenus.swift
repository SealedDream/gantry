import AppKit
import Combine
import SwiftUI
import BastionCore

/// Menu bar commands: the discoverable home of the app's keyboard shortcuts. Each item routes
/// through `AppRouter` to the main window (`ContentView.open`), the same path the palette and
/// Settings links use, so there is one handler per command. Key equivalents come from the core's
/// shortcut list (Settings › Keyboard); an item's router target is its shortcut id. Items carry
/// no `.disabled` state: AppKit checks key equivalents against the state from when the menu was
/// last built, so a stale "disabled" would swallow the shortcut. Each handler ignores what does
/// not apply.
///
/// Menu bar content follows `ObservableObject` changes only, so `MenuState` republishes the
/// keys and the workspace list; and SwiftUI never changes an existing item's key equivalent,
/// so `MenuKeys.apply` sets changed ones on the AppKit items.
///
/// The command items fill in once the main window's first frame is on screen (`MenuState.launched`,
/// speed wave 3): building about 70 SwiftUI menu items took ~50 ms of warm start before the window
/// could appear. The menus themselves exist from the start; only their contents wait one frame.
struct AppMenus: SwiftUI.Commands {
    let router: AppRouter
    @ObservedObject var state: MenuState

    /// Menu item titles by command id, per menu, in menu order (also how `MenuKeys.apply` finds
    /// the AppKit items).
    static let file = [("New Connection…", "add"), ("New Folder…", "new-folder"), ("Quick Connect…", "quick-connect"),
                       ("New Local Shell", "local-shell"),
                       ("Import Connections…", "import-connections"), ("Import KeePass File…", "import-keepass"), ("Export Library…", "export-library"), ("Export to ssh_config…", "export-ssh-config"), ("Export Ansible Inventory…", "export-ansible-inventory"), ("Run Ansible…", "run-ansible")]
    static let view = [("Filter Connections", "focus-search"), ("Command Palette…", "palette"), ("Show or Hide Library", "toggle-library"), ("Show or Hide Inspector", "toggle-inspector"), ("Show or Hide File Panel", "toggle-files-panel")]
    static let session = [("Connect", "default-action"), ("Split Right", "split-right"), ("Split Down", "split-down"),
                          ("Snippets…", "snippets"), ("Tasks…", "tasks-page"), ("Run Command on Hosts…", "run-on-hosts"), ("Broadcast Input…", "broadcast"), ("Start or Stop Session Log", "toggle-session-log")]
    static let focusPane = [("Left", "focus-pane-left"), ("Right", "focus-pane-right"), ("Above", "focus-pane-up"),
                            ("Below", "focus-pane-down"), ("Next Pane", "next-pane"), ("Previous Pane", "previous-pane")]
    static let tabs = [("Show Tab Overview", "tab-overview"), ("Show All Tabs", "all-tabs"), ("Show Next Tab", "next-tab"), ("Show Previous Tab", "previous-tab"),
                       ("Show Next Tab (Alternate)", "next-tab-alt"), ("Show Previous Tab (Alternate)", "previous-tab-alt")]
    /// ⌘1…⌘9 go to the first nine tabs; the menu lists only the tabs that exist, by name (owner round 2, item 12).
    static let numberedTabs = 9
    static let terminal = [("Find…", "find"), ("Find Next", "find-next"), ("Find Previous", "find-previous"),
                           ("Bigger Text", "zoom-in"), ("Smaller Text", "zoom-out"), ("Actual Size", "zoom-reset"),
                           ("Clear Scrollback", "clear-scrollback"), ("Previous Prompt", "previous-prompt"), ("Next Prompt", "next-prompt"), ("Send Interrupt (Ctrl+C)", "send-break"), ("Close Pane", "close-pane")]
    static let workspace = [("Save Current Layout…", "save-workspace")]
    /// Tools: the app's pages that left the sidebar (owner 2026-11-21), the same names and order as on Windows,
    /// then the credential and security tools that used to sit in View (MAC-MENUBAR).
    static let tools = [("Activity", "activity"), ("Audit Log", "audit-log"), ("Plugins…", "plugins"), ("Tunnel Manager", "tunnel-manager"), ("Manage Workspaces…", "workspace-manager"),
                       ("Credential Manager", "credential-manager"), ("Gateway Manager", "gateway-manager"), ("Host Certificate Authorities", "host-cas"), ("SSH Agent", "ssh-agent"), ("Password Generator…", "password-generator"),
                       ("Recently Deleted…", "recently-deleted"), ("Host Status", "host-status"), ("Triggers…", "triggers"),
                       ("Lock Credentials", "lock-credentials"), ("Personal Master Password…", "personal-master-password")]

    var body: some SwiftUI.Commands {
        let _ = RenderCount.hit("AppMenus")
        let keys = state.keys
        let launched = state.launched
        // Bastion menu: what the toolbar's » "More" menu held (owner feedback 12, 2026-11-07).
        CommandGroup(after: .appInfo) {
            if updateChannelConfigured() {
                Button("Check for Updates…") { router.open("check-updates") }
            }
        }
        CommandGroup(after: .appSettings) {
            if launched {
                Menu("Default Settings") {
                    ForEach(defaultSettingTypes, id: \.protocolName) { type in
                        Button("\(type.label)…") { router.open("defaults:\(type.protocolName)") }
                    }
                }
            }
        }
        // The About panel names the product in full (owner 2026-11-23: "Gantry Terminal").
        CommandGroup(replacing: .appInfo) {
            Button("About Gantry Terminal") {
                NSApp.orderFrontStandardAboutPanel(options: [.applicationName: "Gantry Terminal"])
            }
        }
        // Replaces New Window: Gantry works in one window, and ⌘N adds to the library.
        CommandGroup(replacing: .newItem) {
            if launched {
                items(Self.file[0..<2], keys)
                Divider()
                items(Self.file[2..<3], keys)
                Divider()
                items(Self.file[3..<4], keys)
                Divider()
                items(Self.file[4...], keys)
                Button("Import SSH Config…") { router.open("ssh-import") }
                Button("SSH Config Sources…") { router.open("ssh-sources") }
                Divider()
                // Workspaces: File and Window menus (and the sidebar header), not a menu of their own.
                Menu("Workspaces") { workspaceItems(keys) }
            }
        }
        // Replaces Show Sidebar so the library toggle (⌃⌘S) persists and respects auto-hide.
        CommandGroup(replacing: .sidebar) {
            if launched {
                items(Self.view[0..<2], keys)
                Divider()
                items(Self.view[2...], keys)
                Divider()
                Button("Expand All Folders") { router.open("expand-all") }
                Button("Collapse All Folders") { router.open("collapse-all") }
                Divider()
                // Fixed keys (reserved in the core's shortcut list); `UIZoom.handle` also takes ⌘= and the keypad.
                // They zoom the session only; the app's UI size lives in Settings › General.
                Button("Zoom In Session") { UIZoom.shared.terminalZoom?(1) }.keyboardShortcut("+", modifiers: .command)
                Button("Zoom Out Session") { UIZoom.shared.terminalZoom?(-1) }.keyboardShortcut("-", modifiers: .command)
                Button("Actual Size Session") { UIZoom.shared.terminalZoom?(nil) }.keyboardShortcut("0", modifiers: .command)
            }
        }
        CommandGroup(after: .help) {
            Button("Export Diagnostics…") { router.open("export-diagnostics") }
        }
        CommandMenu("Session") {
            if launched {
                // Fixed key, as Finder's Home (owner round 2, item 6).
                Button("Home") { router.open("home") }.keyboardShortcut("h", modifiers: [.command, .shift])
                Divider()
                items(Self.session[0..<1], keys)
                Divider()
                items(Self.session[1..<3], keys)
                Menu("Focus Pane") {
                    items(Self.focusPane[0..<4], keys)
                    Divider()
                    items(Self.focusPane[4...], keys)
                }
                Divider()
                items(Self.session[3...], keys)
                Divider()
                items(Self.tabs[...], keys)
                // Then the open tabs by name, ⌘1…⌘9: AppKit items (`SessionMenuTabs`).
            }
        }
        CommandMenu("Tools") {
            if launched {
                items(Self.tools[0..<2], keys)
                Divider()
                items(Self.tools[2..<5], keys)
                Divider()
                items(Self.tools[5..<10], keys)
                Divider()
                items(Self.tools[10...], keys)
            }
        }
        CommandMenu("Terminal") {
            if launched {
                items(Self.terminal[0..<3], keys)
                Divider()
                items(Self.terminal[3..<6], keys)
                Divider()
                items(Self.terminal[6...], keys)
            }
        }
        // Workspaces: File and Window menus (and the sidebar header), not a menu of their own.
        CommandGroup(before: .windowList) {
            if launched {
                Menu("Workspaces") { workspaceItems(keys) }
                Divider()
            }
        }
    }

    @ViewBuilder
    private func workspaceItems(_ keys: MenuKeys) -> some View {
        items(Self.workspace[...], keys)
        if !state.workspaces.isEmpty {
            Divider()
            ForEach(state.workspaces, id: \.id) { ws in
                Button(ws.name) { router.open("workspace:\(ws.id)") }
            }
        }
    }

    private func items(_ entries: ArraySlice<(String, String)>, _ keys: MenuKeys) -> some View {
        ForEach(Array(entries), id: \.1) { title, target in
            Button(title) { router.open(target) }.keyboardShortcut(keys.key(target)).help(Self.tips[target] ?? "")
        }
    }

    /// Menu item tool tips where the title alone is unclear (owner round 2, item 13).
    static let tips = [
        "send-break": "Sends Ctrl+C to the program in the focused terminal",
        "clear-scrollback": "Deletes the lines above the screen; the screen stays",
    ]
}

/// What the menu bar shows from the `@Observable` models, republished as an `ObservableObject`
/// (see `AppMenus`). Tracking re-arms after every change.
@MainActor
final class MenuState: ObservableObject {
    @Published private(set) var keys: MenuKeys
    @Published private(set) var workspaces: [WorkspaceView]
    /// False until the main window's first frame is on screen (`LaunchGate`); the menus fill in then.
    @Published private(set) var launched = false
    private var gateWatch: AnyCancellable?
    /// Names of the first nine tabs in the main window, for the Session menu (`SessionMenuTabs`).
    private var tabTitles: [String] = []
    private let shortcuts: ShortcutsModel
    private let sessions: SessionsModel
    private let router: AppRouter
    private let workspaceModel: WorkspaceModel

    init(shortcuts: ShortcutsModel, workspaces: WorkspaceModel, sessions: SessionsModel, router: AppRouter) {
        self.shortcuts = shortcuts
        self.sessions = sessions
        self.router = router
        workspaceModel = workspaces
        keys = MenuKeys(shortcuts)
        self.workspaces = workspaces.items
        track()
        gateWatch = LaunchGate.shared.$isOpen.first { $0 }.sink { [weak self] _ in
            guard let self else { return }
            launched = true
            // After SwiftUI has made the items: changed chords, full screen item and the tab items.
            let (k, t) = (keys, tabTitles)
            DispatchQueue.main.async { [router] in
                MenuState.materialize()
                k.apply()
                FullScreenMenu.ensure()
                SessionMenuTabs.update(titles: t, keys: k, open: router.open)
            }
        }
    }

    /// SwiftUI copies changed `Commands` content into the AppKit menus only when a menu is about
    /// to open or the app becomes active. An app launched inactive (a test run, or opened from
    /// Terminal behind another app) kept its menus empty, so key equivalents such as ⌘↩ and ⌘D did
    /// nothing until the user clicked the menu bar. Asking each menu's delegate for its update, as
    /// opening it would, fills the items in at once.
    static func materialize() {
        for item in NSApp.mainMenu?.items ?? [] {
            guard let menu = item.submenu else { continue }
            menu.delegate?.menuNeedsUpdate?(menu)
        }
    }

    private func track() {
        withObservationTracking {
            let k = MenuKeys(shortcuts)
            let w = workspaceModel.items
            let keysChanged = k != keys
            if keysChanged {
                keys = k
                // After SwiftUI's own menu update for this change.
                DispatchQueue.main.async { k.apply(); FullScreenMenu.ensure() }
            }
            if w != workspaces { workspaces = w }
            let t = sessions.mainTabs.prefix(AppMenus.numberedTabs).map(\.shownName)
            if t != tabTitles || keysChanged {
                tabTitles = t
                DispatchQueue.main.async { [router] in SessionMenuTabs.update(titles: t, keys: k, open: router.open) }
            }
        } onChange: { [weak self] in
            Task { @MainActor in self?.track() }
        }
    }
}

/// Key equivalents by command id, as a value (see `AppMenus`).
struct MenuKeys: Equatable {
    let chords: [String: String]

    @MainActor init(_ model: ShortcutsModel) {
        chords = Dictionary(uniqueKeysWithValues: model.items.compactMap { item in
            model.shadowed.contains(item.id) ? nil : item.chord.map { (item.id, $0) }
        })
    }

    func key(_ id: String) -> KeyboardShortcut? { chords[id].flatMap(Chords.keyboardShortcut) }

    /// Set every command item's key equivalent in the AppKit menu bar to the current chord (or
    /// none), found by menu and title as `AppMenus` declares them.
    @MainActor func apply() {
        guard let bar = NSApp.mainMenu else { return }
        func menu(_ title: String) -> NSMenu? { bar.items.first { $0.title == title }?.submenu }
        let session = menu("Session")
        let targets: [(NSMenu?, [(String, String)])] = [
            (menu("File"), AppMenus.file), (menu("View"), AppMenus.view), (session, AppMenus.session + AppMenus.tabs),
            (session?.items.first { $0.title == "Focus Pane" }?.submenu, AppMenus.focusPane), (menu("File")?.items.first { $0.title == "Workspaces" }?.submenu, AppMenus.workspace),
            (menu("Window")?.items.first { $0.title == "Workspaces" }?.submenu, AppMenus.workspace),
            (menu("Terminal"), AppMenus.terminal), (menu("Tools"), AppMenus.tools),
        ]
        for (menu, entries) in targets {
            for (title, id) in entries {
                guard let item = menu?.items.first(where: { $0.title == title }) else { continue }
                let key = chords[id].map(Chords.menuKey) ?? ("", [])
                item.keyEquivalent = key.0
                item.keyEquivalentModifierMask = key.1
            }
        }
    }
}
