import AppKit
import SwiftUI
import BastionCore

/// The one place macOS handles registry actions (`actions.rs`). Menus, the inspector and keyboard
/// shortcuts all ask the core which actions apply and come here to run them; `handled` is exactly
/// the set of ids `run` implements, so the core never offers an action without a handler.
@MainActor @Observable
final class Commands {
    static let handled: [String] = [
        "connect", "connect-new-tab", "full-screen", "reconnect", "disconnect", "open-sftp", "connect-as", "reconnect-as",
        "copy-ssh-command", "copy-hostname", "copy-username", "copy-address",
        "new-connection", "new-subfolder", "connect-all", "disconnect-all", "reconnect-all", "expand-all", "collapse-all", "sort",
        "rename", "duplicate", "save-as-template", "move", "toggle-favorite", "add-to-workspace", "properties", "delete",
    ]

    let model: LibraryModel
    let sessions: SessionsModel
    let tree: TreeStateModel
    let settings: SettingsModel
    let workspaces: WorkspaceModel
    /// B15 dynamic folders: generated rows, the edit and trust sheets (`DynamicFolders.swift`).
    let dynamic: DynamicFoldersModel
    /// Plugin trees under their entries in the library (plugin API 1.3, `PluginSidebar.swift`).
    let pluginSidebar = PluginSidebarModel()

    /// Presentation requests the window turns into sheets.
    var connectRequest: ConnectRequest?
    /// Waiting for a host to wake before its connect sheet (`Wake.swift`).
    var waking: WakeRequest?
    /// Context menu › Wake sent its packet.
    var wakeNotice: String?
    /// Connects waiting for the current sheet to close (opening a workspace), then the tab to
    /// select once they are done.
    @ObservationIgnored private var queue: [ConnectRequest] = []
    /// Saved logins, for connects that open without the sheet (`DirectConnect`).
    @ObservationIgnored var credentials: CredentialsModel?
    /// A saved-login connect is running without a sheet; the queue waits for it.
    @ObservationIgnored private var directing = false
    /// The request `connectDirectly` is working on.
    @ObservationIgnored private var directed: ConnectRequest?
    @ObservationIgnored private var selectAfterQueue: (connectionId: String, mode: ConnectMode)?
    var addConnection: ParentTarget?
    /// A manager dialog open as a panel in the main window (`InWindowPanel.swift`).
    var panel: WindowPanel?
    /// Text the sidebar's "Search or connect" field hands to Quick Connect when nothing in the tree matches.
    var quickConnectPrefill: String?
    var editing: EditorTarget?
    /// Page the next property editor opens on (the connection page's login line asks for `credentials`).
    var editorStartPage: String?
    var moving: MoveRequest?
    /// Save as Template… and New from Template… (`Templates.swift`).
    var savingTemplate: TemplateSaveRequest?
    var newFromTemplate: ParentTarget?
    /// The Templates list (UI driver; users reach it from New from Template).
    var showingTemplates = false
    /// Task editor (new when the id is empty) and a connection's attached tasks (`Tasks.swift`).
    var editingTask: TaskEditRequest?
    /// What the Export, Import report and KeePass import panels show; set before `panel` opens them,
    /// read once as the panel builds (not observed).
    @ObservationIgnored var exportRequest: ExportSheet.Request?
    @ObservationIgnored var importReport: ImportReport?
    /// A plugin entry waiting for its gateway sign-in (PLUG-08).
    var pluginGateway: PluginGatewayRequest?
    @ObservationIgnored var keepassRequest: KeePassImportSheet.Request?
    func showImportReport(_ report: ImportReport) { importReport = report; panel = .importReport }
    /// Task › Run on… (folder or picked hosts).
    var runOnTask: TaskRunOnRequest?
    var taskHooks: ParentTarget?
    /// Before-connect hook tasks the connect is waiting for (`HookGateBar`).
    var hookGates: [HookGateState] = []
    /// Connections opened by a Connect All run, with the run's batch for their after-connect hooks.
    @ObservationIgnored var hookBatches: [String: HookBatch] = [:]
    /// Work to do once a connection's terminal is up (Ansible control host), dropped after its deadline.
    @ObservationIgnored var afterConnect: [String: (deadline: Date, run: @MainActor (TerminalTab) -> Void)] = [:]
    /// Name dialog for a new workspace holding one connection (Add to Workspace › New Workspace…).
    var namingWorkspace: NameRequest?
    /// A folder just made by New Folder: the tree fades its row in as it starts the rename.
    var insertedFolder: String?
    /// Set to a node id to start inline rename in the tree.
    var renaming: String?
    /// Set after a delete so the window can clear its selection.
    var deleted: String?
    /// Selects a node in the library (a folder row on the folder dashboard). The main window sets
    /// it; a call is one selection write, where an observed request plus its reset re-ran the
    /// whole window twice per open.
    @ObservationIgnored var selectNode: ((String) -> Void)?
    /// Connect All's last plan, as shown to the user (UI driver).
    @ObservationIgnored var lastBulkSummary: BulkConnectSummary?
    /// UI driver: receives Connect All's requests instead of the connect queue.
    @ObservationIgnored var bulkRecorder: (([ConnectRequest]) -> Void)?
    /// Where Copy actions write; the UI test driver swaps in a private pasteboard.
    @ObservationIgnored var pasteboard: NSPasteboard = .general

    init(model: LibraryModel, sessions: SessionsModel, tree: TreeStateModel, settings: SettingsModel, workspaces: WorkspaceModel) {
        self.model = model
        self.sessions = sessions
        self.tree = tree
        self.settings = settings
        self.workspaces = workspaces
        dynamic = DynamicFoldersModel(model: model, sessions: sessions)
        dynamic.expand = { [weak tree] id in tree?.setExpanded(id, true) }
        sessions.onConnected = { [weak self] id in
            guard let self else { return }
            self.runAfterConnect(id)
            self.runHooks("after_connect", for: id, batch: self.hookBatches.removeValue(forKey: id))
        }
        sessions.onDisconnected = { [weak self] id in self?.runHooks("after_disconnect", for: id) }
        sessions.activityStart = { [weak model] id in model?.activityStart(connectionId: id) }
    }

    /// Entries of a registry item's submenu; empty for items without one. Add to Workspace lists
    /// the saved workspaces (those already holding the connection are checked and disabled), then
    /// New Workspace….
    func submenu(for item: MenuItemView, on id: String?) -> [MenuChoice] {
        guard item.id == "add-to-workspace", let c = id.flatMap(model.connection(id:)) else { return [] }
        let saved = workspaces.items.map { ws in
            let member = ws.tabs.contains { $0.connectionId == c.id && $0.mode == ConnectMode.terminal.rawValue }
            return MenuChoice(title: ws.name, checked: member, enabled: !member) { [weak self] in
                self?.workspaces.add(connectionId: c.id, to: ws.id)
            }
        }
        let new = MenuChoice(title: "New Workspace…", separatorBefore: !saved.isEmpty) { [weak self] in
            self?.namingWorkspace = .create(c)
        }
        return saved + [new]
    }

    /// Menu for a node (`nil` = the library root), filtered to what this app handles.
    func menu(for id: String?) -> [MenuItemView] {
        guard let library = model.library else { return [] }
        return (try? library.menu(id: id, sessions: sessions.snapshot, handled: Self.handled)) ?? []
    }

    /// Run a menu entry, asking first when the core says it needs confirmation.
    func perform(_ item: MenuItemView, on id: String?) {
        guard item.enabled else { return }
        guard let question = item.confirm else { return run(item.id, on: id) }
        let alert = NSAlert()
        alert.messageText = question
        alert.informativeText = id.flatMap { model.connection(id: $0)?.name ?? model.folder(id: $0)?.name } ?? ""
        alert.alertStyle = item.destructive ? .warning : .informational
        let ok = alert.addButton(withTitle: item.label.replacingOccurrences(of: "…", with: ""))
        ok.hasDestructiveAction = item.destructive
        alert.addButton(withTitle: "Cancel").keyEquivalent = "\u{1b}"
        if let window = NSApp.keyWindow ?? NSApp.mainWindow ?? NSApp.windows.first(where: { $0.isVisible && $0.canBecomeMain }) {
            alert.beginSheetModal(for: window) { [weak self] response in
                if response == .alertFirstButtonReturn { self?.run(item.id, on: id) }
            }
        } else if alert.runModalInFront() == .alertFirstButtonReturn {
            run(item.id, on: id)
        }
    }

    /// The default action (double-click, Return, inspector primary) for a node.
    func performDefault(on id: String) {
        if settings.value("tree.double-click") == "properties", model.connection(id: id) != nil {
            return run("properties", on: id)
        }
        if openPluginEntry(id) { return }
        if let primary = menu(for: id).first(where: \.primary) { perform(primary, on: id) }
    }

    /// The user expanded a plugin entry whose type has a library tree: open its sidebar session.
    func openPluginSidebar(_ c: ConnectionView) {
        guard let type = PluginEntries.type(of: c), type.sidebarTree, let library = model.library else { return }
        pluginSidebar.expand(entry: c, type: type, library: library, credentials: credentials, sessions: sessions)
    }

    /// A plugin entry an installed plugin opens: its view in a tab. False for every other node.
    @discardableResult
    func openPluginEntry(_ id: String) -> Bool {
        guard let c = model.connection(id: id), let type = PluginEntries.type(of: c), let library = model.library else { return false }
        PluginViewWindow.show(entry: c, type: type, library: library, credentials: credentials)
        return true
    }

    func run(_ action: String, on id: String?) {
        let connection = id.flatMap(model.connection(id:))
        switch action {
        case "connect":
            guard let c = connection else { return }
            guard let open = sessions.tabs(for: c.id).first(where: { !$0.ended }) else { return requestConnect(c, Self.mode(for: c)) }
            // A tab that has waited since a crash connects now: the user asked (decision D15).
            if open.isWaiting { connectRestored(open) } else { sessions.selected = open.id }
        case "connect-new-tab": connection.map { requestConnect($0, Self.mode(for: $0)) }
        case "open-sftp": connection.map { requestConnect($0, .files) }
        case let a where a.hasPrefix(ConnectionTool.actionPrefix):
            guard let c = connection, let tool = ConnectionTool(rawValue: String(a.dropFirst(ConnectionTool.actionPrefix.count))) else { return }
            openTool(tool, on: c)
        case "reconnect":
            guard let c = connection else { return }
            // The title bar's Reconnect on a tab that waits since a crash: connect it in its place.
            if let waiting = sessions.selectedTab, waiting.isWaiting, waiting.connectionId == c.id { return connectRestored(waiting) }
            // A terminal tab is replaced in place once the new session is open: closing it first
            // showed the start page until the new tab came (MAC-RECONNECT-PANE).
            let open = sessions.tabs(for: c.id)
            if let tab = open.first(where: { $0.id == sessions.selected }) ?? open.first, tab.root != nil, c.protocol == "ssh" {
                open.filter { $0.id != tab.id }.forEach(sessions.close)
                return connectInPlace(tab, c)
            }
            sessions.disconnect([c.id])
            requestConnect(c, Self.mode(for: c))
        // One-off login: the sheet asks for a user and secret; the current tab is replaced only
        // once the new login succeeds, so a wrong password never costs the open session.
        case "connect-as": connection.map { connectAs($0, replacing: nil) }
        case "reconnect-as":
            guard let c = connection else { return }
            let tab = sessions.tabs(for: c.id).first { $0.id == sessions.selected } ?? sessions.tabs(for: c.id).first { !$0.ended }
            connectAs(c, replacing: tab?.id)
        case "disconnect": connection.map { sessions.disconnect([$0.id]) }
        case "full-screen":
            guard let c = connection, let tab = sessions.tabs(for: c.id).first(where: { !$0.ended }) else { return }
            sessions.selected = tab.id
            NSApp.keyWindow?.toggleFullScreen(nil)
        case "copy-ssh-command": copy { try $0.sshCommand(id: id ?? "") }
        case "copy-hostname": copy { _ in connection?.host ?? "" }
        case "copy-username": copy { try $0.effectiveUsername(id: id ?? "") ?? "" }
        case "copy-address": copy { try $0.address(id: id ?? "") }
        case "new-connection": addConnection = ParentTarget(id: id)
        case "new-subfolder": addFolderInline(parent: id)
        case "connect-all": connectAll(under: id)
        case "disconnect-all": sessions.disconnect(connectionIdsBelow(id))
        case "reconnect-all": reconnectAll(under: id)
        case "expand-all": tree.setSubtree(id, expanded: true, library: model.library)
        case "collapse-all": tree.setSubtree(id, expanded: false, library: model.library)
        case "sort": model.mutate { try $0.sortFolder(id: id, recursive: false) }
        case "rename": renaming = id
        case "duplicate": model.mutate { _ = try $0.duplicateNode(id: id ?? "") }
        case "move": id.map { moving = MoveRequest(id: $0) }
        case "save-as-template": connection.map { savingTemplate = TemplateSaveRequest(id: $0.id, name: $0.name) }
        case "add-to-workspace":
            // Without a submenu (palette, keyboard): name a new workspace for it.
            connection.map { namingWorkspace = .create($0) }
        case "toggle-favorite":
            guard let c = connection else { return }
            model.mutate { try $0.setFavorite(id: c.id, favorite: !c.favorite) }
        case "properties":
            tree.revealInspector()
            if let c = connection {
                editing = .connection(id: c.id, name: c.name, protocolName: c.protocol)
            } else if let id, let f = model.folder(id: id) {
                editing = .folder(id: f.id, name: f.name)
            }
        case "delete":
            // B10: to Recently Deleted (or for good when the keep time is Off); ⌘Z puts it back.
            guard let id else { return }
            let days = RecentlyDeleted.retentionDays(settings)
            model.patch { _ = try $0.trashNode(id: id, now: RecentlyDeleted.now(), retentionDays: days); return [id] }
            deleted = id
            if days > 0, let undo = Self.undoWindow?.undoManager {
                undo.registerUndo(withTarget: self) { commands in
                    MainActor.assumeIsolated {
                        // Restored or purged since (the Recently Deleted window): nothing to undo.
                        guard commands.model.library?.deletedItems().contains(where: { $0.id == id }) == true else { return }
                        RecentlyDeleted.restore(id, model: commands.model)
                        commands.deleted = nil
                        commands.selectNode?(id)
                    }
                }
                undo.setActionName("Delete")
            }
        default:
            assertionFailure("no handler for \(action)")
        }
    }

    /// The window whose undo stack takes a library edit. The Delete confirmation runs its action while
    /// its own sheet is still the key window: registering there put ⌘Z's undo on the sheet, which
    /// closes right after, so Edit › Undo had nothing (b10-restore, 2026-11-26). The main window comes
    /// first (a sheet or alert panel never becomes main), then a sheet's parent.
    static var undoWindow: NSWindow? {
        NSApp.mainWindow ?? NSApp.keyWindow.map { $0.sheetParent ?? $0 }
            ?? NSApp.windows.first(where: { $0.isVisible && $0.canBecomeMain })
    }

    /// New Folder as in Finder (owner 2026-11-15): a folder with a free default name appears in
    /// `parent` (nil = the library root), selected and in inline rename. Return saves the name,
    /// Escape keeps the default. No sheet. ⌘Z removes it again.
    func addFolderInline(parent: String?) {
        let siblings = (parent.flatMap(model.folder(id:)) ?? model.tree)?.folders.map(\.name) ?? []
        let name = Self.freeFolderName(taken: siblings)
        if let parent { tree.setExpanded(parent, true) }
        var created: String?
        model.patch { lib in
            let id = try lib.addFolder(parent: parent, name: name)
            created = id
            return [id]
        }
        guard let id = created else { return }
        if let undo = Self.undoWindow?.undoManager {
            undo.registerUndo(withTarget: self) { commands in
                MainActor.assumeIsolated {
                    guard commands.model.folder(id: id) != nil else { return }
                    commands.model.patch { try $0.remove(id: id); return [id] }
                }
            }
            undo.setActionName("New Folder")
        }
        insertedFolder = id
        renaming = id
    }

    /// "New Folder", then "New Folder 2", "New Folder 3"…: the first not used in the parent (any case).
    nonisolated static func freeFolderName(taken: [String]) -> String {
        let used = Set(taken.map { $0.lowercased() })
        let base = "New Folder"
        if !used.contains(base.lowercased()) { return base }
        var n = 2
        while used.contains("\(base) \(n)".lowercased()) { n += 1 }
        return "\(base) \(n)"
    }

    /// Open a connection: web pages open a tab directly, everything else goes through its connect sheet.
    /// SFTP, SCP and FTPS connections open a files tab; everything else a terminal or desktop.
    static func mode(for c: ConnectionView) -> ConnectMode { ConnectRoute.mode(forProtocol: c.protocol) }

    /// Connect as… / Reconnect as… (`replacing` = the tab to swap for the new session).
    func connectAs(_ c: ConnectionView, replacing: UUID?) {
        enqueue([ConnectRequest(connection: c, mode: .terminal, connectAs: true, replacing: replacing)], select: nil)
    }

    /// A tab's right-click asked for Connect as… (`sessions.connectAsRequest`).
    func connectAs(connectionId: String, replacing: UUID?) {
        guard let c = model.connection(id: connectionId) else { return }
        connectAs(c, replacing: replacing)
    }

    /// Services, Processes or Event Log of an SSH connection, in a new tab (owner feedback 11).
    func openTool(_ tool: ConnectionTool, on c: ConnectionView) {
        guard ConnectionTool.applies(to: c) else { return }
        enqueue([ConnectRequest(connection: c, mode: .system, systemView: tool.rawValue)], select: nil)
    }

    /// How `requestConnect` opens `c` in `mode` (`ConnectRoute.of`).
    func route(_ c: ConnectionView, _ mode: ConnectMode, library: Library?) -> ConnectRoute {
        let usesMosh = library.map { MoshTransport.uses(c, library: $0) } ?? false
        return ConnectRoute.of(protocol: c.protocol, mode: mode, usesMosh: usesMosh)
    }

    func requestConnect(_ c: ConnectionView, _ mode: ConnectMode, library: Library? = nil, batch: HookBatch? = nil) {
        // Every connect path (toolbar, menus, Return, batches) opens a plugin entry as its default
        // action does: the plugin's view in a tab. A plugin type is never a protocol to connect.
        if library == nil, openPluginEntry(c.id) { return }
        // Before-connect tasks run first and the connect waits for them (`gateBeforeConnect`).
        // A connect with an explicit library is an internal one that already passed the gate.
        guard library == nil else { return openConnect(c, mode, library: library) }
        if let batch { hookBatches[c.id] = batch } else { hookBatches[c.id] = nil }
        gateBeforeConnect(c.id, batch: batch) { [weak self] in self?.openConnect(c, mode, library: nil) }
    }

    private func openConnect(_ c: ConnectionView, _ mode: ConnectMode, library: Library?) {
        let lib = library ?? model.library
        switch (route(c, mode, library: lib), lib) {
        case (.local, let lib?): return sessions.openLocal(connection: c, library: lib)
        case (.mosh, let lib?): return sessions.openMosh(connection: c, library: lib)
        case (.telnet, let lib?): return openTelnet(c, library: lib)
        case (.unsupported, _): return sessions.refuseUnsupported(connection: c)
        default: break
        }
        enqueue([ConnectRequest(connection: c, mode: mode, library: library)], select: nil)
    }

    /// A tab restored after a crash connects when the user asks (decision D15): the normal
    /// connect, so a saved login needs no sheet, and the new session takes the waiting tab's place.
    func connectRestored(_ tab: TerminalTab) {
        guard tab.isWaiting, let id = tab.connectionId, let c = model.connection(id: id) else { return }
        connectInPlace(tab, c)
    }

    /// Connect `c` and swap the new session in for `tab` (`SessionsModel.replace`): the tab stays
    /// on screen until then, so the session area never empties.
    private func connectInPlace(_ tab: TerminalTab, _ c: ConnectionView) {
        sessions.selected = tab.id
        // A second press while the first connect is still on its way must not open a second session.
        guard !pendingRequests.contains(where: { $0.replacing == tab.id }) else { return }
        let request = ConnectRequest(connection: c, mode: tab.mode, replacing: tab.id)
        gateBeforeConnect(c.id) { [weak self] in self?.enqueue([request], select: nil) }
    }

    /// Every connect request that is queued, asking in a sheet, waiting for a wake or on its way.
    private var pendingRequests: [ConnectRequest] { queue + [connectRequest, waking?.request, directed].compactMap { $0 } }
    /// Nothing is queued or connecting (UI driver: after a crash the queue must stay empty).
    var isConnectPending: Bool { !pendingRequests.isEmpty }

    /// Connect several tabs one after another (each with its own sheet), then select `select`.
    func enqueue(_ requests: [ConnectRequest], select: (connectionId: String, mode: ConnectMode)?) {
        queue += requests
        if select != nil { selectAfterQueue = select }
        advance()
    }

    /// A woken request goes back to the front of the queue.
    func enqueueFront(_ r: ConnectRequest) {
        queue.insert(r, at: 0)
        advance()
    }

    func resumeQueue() { advance() }

    /// The connect sheet closed (connected or cancelled): present the next one.
    func connectSheetClosed() {
        connectRequest = nil
        // Let the closing sheet finish before presenting the next one.
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(350))
            advance()
        }
    }

    private func advance() {
        guard connectRequest == nil, waking == nil, !directing else { return }
        while let next = queue.first {
            queue.removeFirst()
            if let plan = wakePlanBeforeConnect(next) { return waking = WakeRequest(request: next, plan: plan) }
            // The core enforces the managed policy again on every connect; this stops early with its reason.
            do { try policyCheckProtocol(protocol: next.connection.protocol) } catch {
                sessions.error = "\(next.connection.name): \(error)"
                continue
            }
            // Connect All's needs-login connections always ask in the sheet (`askLogin`).
            if !next.askLogin, let credentials, DirectConnect.eligible(next, credentials: credentials) { return connectDirectly(next, credentials: credentials) }
            guard next.connection.protocol == "web", !hasGateway(next.connection) else { return connectRequest = next }
            openWeb(next.connection)
        }
        if let target = selectAfterQueue {
            selectAfterQueue = nil
            sessions.selected = sessions.tabs.last { $0.connectionId == target.connectionId && $0.mode == target.mode }?.id ?? sessions.selected
        }
    }

    /// Saved login: the handshake starts now, with no sheet; the sheet shows only if it must ask.
    private func connectDirectly(_ r: ConnectRequest, credentials: CredentialsModel) {
        directing = true
        directed = r
        Task { @MainActor in
            let outcome = await DirectConnect.attempt(r, model: model, sessions: sessions, credentials: credentials)
            directing = false
            directed = nil
            if case .needsSheet(let retry, let failure) = outcome {
                var shown = r
                shown.autoConnect = retry
                shown.failure = failure
                connectRequest = shown
            } else {
                advance()
            }
        }
    }

    /// A web connection with a gateway (or a broken gateway reference) opens a sign-in sheet first.
    private func hasGateway(_ c: ConnectionView) -> Bool {
        do { return try model.library?.gatewayRoute(connectionId: c.id) != nil } catch { return true }
    }

    private func openWeb(_ c: ConnectionView) {
        // A tab that opens records its first load's outcome itself (WebPage.onFirstResult).
        if let failure = openWebTab(c) { sessions.error = failure; sessions.recordOutcome(c.id, user: nil, failure: failure) }
    }

    /// Opens the web tab; returns the reason when it cannot (that is the footer's "Last result").
    private func openWebTab(_ c: ConnectionView) -> String? {
        guard let url = WebTarget.url(host: c.host, port: c.port) else {
            return "\(c.name): only http and https addresses can be opened."
        }
        // A web tunnel never falls back to a direct load: a deleted tunnel or one not running is an error.
        let plan: WebTunnelPlanView?
        do { plan = try model.library?.webTunnelPlan(connectionId: c.id, dataDir: WebTunnels.dataDir.path) } catch {
            return "\(c.name): \(error)"
        }
        guard let plan else { sessions.add(TerminalTab(name: c.name, content: .web(url), connectionId: c.id)); return nil }
        guard sessions.runningTunnels[plan.tunnelId] != nil else {
            return "\(c.name) opens through the tunnel “\(plan.tunnelName)”. Start it in the Tunnel Manager first."
        }
        let tab: TerminalTab
        if let proxy = plan.proxyUrl {
            tab = TerminalTab(name: c.name, content: .web(url), connectionId: c.id)
            tab.webTunnel = (URL(string: proxy)?.port.flatMap(UInt16.init(exactly:)), plan.tunnelId)
        } else if let address = plan.forwardAddress, let forwarded = WebTunnels.url(url, through: address) {
            tab = TerminalTab(name: c.name, content: .web(forwarded), connectionId: c.id)
            tab.webTunnel = (nil, plan.tunnelId)
        } else {
            return "\(c.name): the tunnel “\(plan.tunnelName)” has no usable address."
        }
        sessions.add(tab)
        return nil
    }

    private func copy(_ value: (Library) throws -> String) {
        guard let library = model.library else { return }
        do {
            let text = try value(library)
            pasteboard.clearContents()
            pasteboard.setString(text, forType: .string)
        } catch {
            model.error = "\(error)"
        }
    }
}

struct MoveRequest: Identifiable {
    let id: String
}

/// One connect sheet to show. `library` is set for a Quick Connect target (an unsaved library);
/// `layout` is the split tree to rebuild after a workspace's terminal tab connects.
struct ConnectRequest {
    let connection: ConnectionView
    let mode: ConnectMode
    var library: Library? = nil
    var layout: [String] = []
    var tunnelId: String? = nil
    /// `.system` mode on an SSH connection: `services`, `processes` or `eventlog` (its child tools).
    var systemView: String? = nil
    /// Connect as…: ask for a one-off user and secret instead of the saved login.
    var connectAs = false
    /// Reconnect as…: the tab the new session replaces once it is connected.
    var replacing: UUID? = nil
    /// Files mode into the docked file panel of this SSH tab instead of a new tab.
    var filePanelFor: UUID? = nil
    /// Already woken (or the user chose Connect Now): skip "Wake before connect".
    var woken = false
    /// The sheet may try the saved login itself; false after a direct attempt failed with it.
    var autoConnect = true
    /// Why the direct connect failed, shown in the sheet (RDP).
    var failure: String? = nil
    /// Connect All opened this connection, which has no login of its own: only the sheet may
    /// sign in, and only with what the user picks there (never a saved login without asking).
    var askLogin = false
}

/// One entry of a registry item's submenu (`Commands.submenu`).
struct MenuChoice {
    let title: String
    var checked = false
    var enabled = true
    var separatorBefore = false
    let run: @MainActor () -> Void
}

/// Registry menu entries as SwiftUI menu content (inspector overflow), with dividers between
/// sections; items with choices become submenus.
struct ActionMenuItems: View {
    let items: [MenuItemView]
    var submenu: (MenuItemView) -> [MenuChoice] = { _ in [] }
    let perform: (MenuItemView) -> Void

    var body: some View {
        ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
            if index > 0, items[index - 1].section != item.section { Divider() }
            let choices = submenu(item)
            if choices.isEmpty {
                Button(role: item.destructive ? .destructive : nil) { perform(item) } label: {
                    Label(item.label, systemImage: Icons.actionSymbols[item.glyph] ?? "circle")
                }
                .disabled(!item.enabled)
                .help(item.disabledReason ?? "")
            } else {
                Menu {
                    ForEach(Array(choices.enumerated()), id: \.offset) { _, choice in
                        if choice.separatorBefore { Divider() }
                        Toggle(choice.title, isOn: Binding(get: { choice.checked }, set: { _ in choice.run() }))
                            .disabled(!choice.enabled)
                    }
                } label: {
                    Label(item.label, systemImage: Icons.actionSymbols[item.glyph] ?? "circle")
                }
                .disabled(!item.enabled)
            }
        }
    }
}

/// Registry menu entries as an AppKit menu (tree context menu).
enum ActionMenuBuilder {
    @MainActor static func fill(_ menu: NSMenu, items: [MenuItemView], submenu: (MenuItemView) -> [MenuChoice] = { _ in [] },
                                perform: @escaping (MenuItemView) -> Void) {
        menu.removeAllItems()
        for (index, item) in items.enumerated() {
            if index > 0, items[index - 1].section != item.section { menu.addItem(.separator()) }
            let entry = ClosureMenuItem(title: item.label) { perform(item) }
            entry.isEnabled = item.enabled
            entry.toolTip = item.disabledReason
            entry.image = NSImage(systemSymbolName: Icons.actionSymbols[item.glyph] ?? "circle", accessibilityDescription: nil)
            if item.primary {
                entry.attributedTitle = NSAttributedString(string: item.label, attributes: [.font: NSFont.boldSystemFont(ofSize: NSFont.systemFontSize)])
            }
            let choices = submenu(item)
            if !choices.isEmpty {
                let sub = NSMenu(title: item.label)
                for choice in choices {
                    if choice.separatorBefore { sub.addItem(.separator()) }
                    let row = ClosureMenuItem(title: choice.title, handler: choice.run)
                    row.state = choice.checked ? .on : .off
                    row.isEnabled = choice.enabled
                    sub.addItem(row)
                }
                entry.submenu = sub
            }
            menu.addItem(entry)
        }
    }
}

/// An NSMenuItem that runs a closure.
final class ClosureMenuItem: NSMenuItem {
    private let handler: () -> Void

    init(title: String, handler: @escaping () -> Void) {
        self.handler = handler
        super.init(title: title, action: #selector(fire), keyEquivalent: "")
        target = self
    }

    required init(coder: NSCoder) { fatalError("not used") }

    @objc private func fire() { handler() }
}
