import AppKit
import SwiftUI
import BastionCore
import BastionRdp

/// What a tab shows: a terminal (local or SSH), an SFTP file browser an RDP or VNC desktop, or a web page.
enum SessionContent: Sendable {
    case terminal(Terminal)
    case files(FilesBrowser)
    case rdp(RdpSession)
    case vnc(VncViewer)
    case web(URL)
    /// Read-only Services, Processes or Event Log view (`SystemViews.swift`).
    case system(SystemView)
    /// A task's output (`Tasks.swift`).
    case task(TaskRun)
    /// A plugin's view (`PluginViewWindow.swift`, PLUG-06c).
    case plugin(PluginViewModel)
    /// Restored after a crash and not connected yet (decision D15): nothing is sent to the host
    /// until the user connects the tab. Holds how it reopens (terminal or files).
    case waiting(ConnectMode)
}

/// One open tab. A terminal tab holds a split tree of panes; a files tab holds its browser.
@MainActor @Observable
final class TerminalTab: Identifiable {
    let id = UUID()
    let name: String
    /// Set by Rename Tab (owner round 2, item 4) for the tab's life; nil shows the automatic name.
    var customName: String?
    /// What the strip shows: the user's name for the tab, else the connection or shell name.
    var stripName: String { customName ?? name }
    let content: SessionContent
    /// Library connection this tab was opened from; nil for local shells.
    let connectionId: String?
    /// Nil for a files tab.
    private(set) var root: PaneNode?
    var focusedPane: UUID?
    /// ⌘+ / ⌘−: points added to every pane's font size in this tab; never saved.
    var zoom = 0
    static let zoomRange: ClosedRange<Int> = 6...48
    /// Set once an RDP or VNC session has closed; nil while it runs (and for other tabs).
    var desktopCloseReason: String? { didSet { if desktopCloseReason != nil { endActivity("remote_closed") } } }
    /// The Activity log record of an RDP, VNC or web tab (`SessionActivity.swift`); nil once ended.
    @ObservationIgnored private var activity: TabActivity?
    /// The loopback forward or SOCKS proxy through the connection's gateway; closed with the tab.
    var gatewayRoute: GatewayRoute?
    /// Web tab through a saved SOCKS tunnel: its loopback port, and the tunnel id that names the
    /// tab's own website data store (cookies stay per tunnel).
    var webTunnel: (port: UInt16?, id: String)?
    /// Id of the tab group (`SessionsModel.groups`) this tab is in.
    var group: String?
    /// Dragged out of a folder group: auto-grouping leaves it alone.
    var detached = false
    /// The protected document this tab was opened from (nil = Personal), stamped once in `add`.
    /// Its lock covers the tab in whichever window it is shown, even after the main window
    /// switches document (Codex M04).
    var documentId: String?
    /// Pinned: a small icon-only tab at the leading end of the strip, outside any group.
    var pinned = false
    /// TERM-MARKS: new output while the tab was in the background; cleared when it is shown.
    var unread = false
    /// TERM-MARKS: "Command failed, exit 3 (40 s)" for a long command that ended in the background.
    var notice: String?
    /// SFTP browser shown in the docked file panel beside this SSH tab (`FilePanel.swift`).
    var filePanel: FilesBrowser?
    /// A waiting tab's split tree from before the crash: saved again while it waits, rebuilt
    /// once it connects.
    var restoredLayout: [String] = []
    /// Restored after a crash, not connected yet (`SessionContent.waiting`).
    var isWaiting: Bool { if case .waiting = content { true } else { false } }

    init(name: String, content: SessionContent, connectionId: String? = nil) {
        self.name = name
        self.content = content
        self.connectionId = connectionId
        if case .terminal(let t) = content {
            let pane = TerminalPane(terminal: t)
            root = .leaf(pane)
            focusedPane = pane.id
        }
    }

    convenience init(name: String, terminal: Terminal) {
        self.init(name: name, content: .terminal(terminal))
    }

    var panes: [TerminalPane] { root?.leaves ?? [] }
    private var focused: TerminalPane? { panes.first { $0.id == focusedPane } ?? panes.first }

    /// The focused pane's terminal (search, scripted input).
    var terminal: Terminal? { focused?.terminal }
    var remoteTitle: String? { focused?.remoteTitle }
    var ended: Bool { desktopCloseReason != nil || (!panes.isEmpty && panes.allSatisfy(\.ended)) }
    /// Bumped when logging starts or stops, so the tab redraws its indicator.
    var logChanged = 0
    var isLogging: Bool { _ = logChanged; return panes.contains { $0.terminal.isLogging() } }

    /// The tab's name as shown: a saved connection's own name; an unsaved terminal (local shell,
    /// quick connect) follows its program's title, cleaned (`TabTitle`), so after `ssh host` it
    /// names the server (owner 2026-11-17).
    var shownName: String { customName ?? TabTitle.display(name: name, program: remoteTitle, isSaved: connectionId != nil) }

    var title: String {
        let name = shownName
        if isWaiting { return "\(name) (not connected)" }
        if ended { return "\(name) (ended)" }
        if let status = panes.lazy.compactMap(\.linkStatus).first { return "\(name) (\(status))" }
        return name
    }

    /// The strip shows this as a dot instead of words in the title (owner 2026-11-16).
    enum LinkDot {
        case online, reconnecting, offline

        /// Core theme token (`theme.rs`), light and dark.
        var token: String {
            switch self {
            case .online: "status.connected"
            case .reconnecting: "status.connecting"
            case .offline: "status.failed"
            }
        }
    }

    /// The tab's link state; nil for a local shell, which has no link.
    var linkDot: LinkDot? {
        if ended || isWaiting { return .offline }
        if let status = panes.lazy.compactMap(\.linkStatus).first {
            return status == "Connection lost" ? .offline : .reconnecting
        }
        return connectionId == nil ? nil : .online
    }

    /// The words the dot stands for: its tooltip and accessibility text.
    var linkText: String? {
        if isWaiting { return "Not connected" }
        if ended { return "Ended" }
        if let status = panes.lazy.compactMap(\.linkStatus).first { return status }
        return linkDot == nil ? nil : "Connected"
    }

    func split(with pane: TerminalPane, axis: SplitAxis, ratio: CGFloat = 0.5) {
        guard let root, let target = focused?.id else { return }
        self.root = root.splitting(target, with: pane, axis: axis, ratio: ratio)
        focusedPane = pane.id
    }

    /// Closes the focused pane; focus moves to the pane before it. Returns false if it was the last.
    func closeFocusedPane() -> Bool {
        guard let root, let pane = focused, panes.count > 1 else { return false }
        let index = panes.firstIndex { $0.id == pane.id } ?? 0
        pane.terminal.close()
        self.root = root.removing(pane.id)
        focusedPane = panes[max(0, index - 1)].id
        return true
    }

    /// How a workspace reopens this tab.
    var mode: ConnectMode {
        if case .waiting(let mode) = content { return mode }
        if case .files = content { return .files }
        if case .system = content { return .system }
        return .terminal
    }

    /// The split tree for a workspace (`PaneNode.layoutSteps`); empty for one pane.
    var layoutSteps: [String] { isWaiting ? restoredLayout : panes.count > 1 ? root?.layoutSteps ?? [] : [] }

    var symbol: String {
        switch content {
        case .terminal: "terminal"
        case .files: "folder"
        case .rdp, .vnc: "display"
        case .web: "globe"
        case .system(let s): s.view() == "processes" ? "cpu" : s.view() == "services" ? "gearshape.2" : "list.bullet.rectangle"
        case .task: "bolt.horizontal"
        case .plugin: "puzzlepiece.extension"
        case .waiting(let mode): mode == .files ? "folder" : "terminal"
        }
    }

    /// Record this tab in the Activity log, once (RDP, VNC and web tabs of saved connections).
    func beginActivity(_ start: SessionActivityStart?) {
        guard activity == nil, let start else { return }
        switch content {
        case .rdp, .vnc, .web: activity = SessionActivity.begin(start)
        default: return
        }
    }

    /// Record the end once; later calls do nothing.
    func endActivity(_ reason: String) {
        guard let a = activity else { return }
        activity = nil
        SessionActivity.end(a, reason: reason)
    }

    func closeAll() {
        endActivity("closed_by_user")
        panes.forEach { $0.terminal.close() }
        if case .rdp(let session) = content { session.close() }
        if case .vnc(let viewer) = content { viewer.close() }
        if case .system(let s) = content { Task.detached { s.close() } }
        if case .task(let run) = content { run.cancel() }
        if case .plugin(let m) = content { PluginViewWindow.closed(m) }
        gatewayRoute?.close()
    }

    /// Moves focus to the neighbouring pane; does nothing at the tab's edge.
    func focusNeighbour(_ direction: PaneDirection) {
        guard let root, let id = focused?.id, let next = root.neighbour(of: id, direction) else { return }
        focusedPane = next.id
    }

    /// Moves focus to the next (or previous) pane in reading order, wrapping around.
    func cycleFocus(forward: Bool) {
        let all = panes
        guard all.count > 1, let i = all.firstIndex(where: { $0.id == focused?.id }) else { return }
        focusedPane = all[(i + (forward ? 1 : all.count - 1)) % all.count].id
    }
}

/// Open sessions plus the core `SessionManager` (broker, known_hosts, audit) behind them.
@MainActor @Observable
final class SessionsModel {
    /// UI-06: this window's tones from the selected tab's terminal theme (`ChromeTonesProvider`); nil = stock colours.
    /// Read by the tab strip, which the toolbar hosts outside the window's SwiftUI environment.
    var chromeTones: ChromeTones?
    private(set) var tabs: [TerminalTab] = [] {
        didSet {
            if tabs.count > oldValue.count { tabOpened?() }
            if tabCount != tabs.count { tabCount = tabs.count }
        }
    }
    /// A tab was added. Called as it is added, so what follows from it (the inspector stepping aside)
    /// changes in the same SwiftUI update as the new tab, not in a second pass (speed wave 3).
    @ObservationIgnored var tabOpened: (() -> Void)?
    /// `tabs.count`, observed on its own so views that only show the count (the toolbar's
    /// sessions menu) don't re-render on every tab rename or reorder.
    private(set) var tabCount = 0
    /// Tab groups in strip order (`TabStrip.swift`); tabs name theirs in `TerminalTab.group`.
    private(set) var groups: [StripGroup] = []
    /// Folder auto-grouping over the current library (core `tab_strip_auto_group`); set by the app.
    @ObservationIgnored var autoGroup: ((String) -> String?)?
    /// Workspace groups waiting for their tabs to reconnect: connection id → group ids, in order.
    @ObservationIgnored var pendingGroups: [String: [String]] = [:]
    @ObservationIgnored var pendingGroupDefs: [StripGroup] = []
    /// B12: restored tabs' windows waiting for their tabs, in plan order: connection id → window
    /// (nil: the main window). Filled by `SessionRestore.begin`, used by `placeRestored`.
    @ObservationIgnored var pendingWindows: [String: [UUID?]] = [:]
    /// Each restored window's saved frame (screen coordinates) and front tab key, until it opens.
    @ObservationIgnored var pendingWindowFrames: [UUID: NSRect] = [:]
    @ObservationIgnored var pendingWindowFronts: [UUID: String] = [:]
    /// A restored window's front tab once it is back, so later tabs do not take the front.
    @ObservationIgnored var restoredFronts: [UUID: UUID] = [:]
    var selected: UUID? {
        // A tab torn off into its own window is never the main window's selection: picking it
        // (All Tabs, the toolbar menu) brings its window forward instead.
        didSet {
            if selected != oldValue { viewChanged?() }
            // Only when set: an equal write still invalidates every view that reads it.
            if homeShown { homeShown = false }
            // Picking a tab (even the selected one) returns from a connection page to the service.
            if connectionPage != nil { connectionPage = nil }
            if folderPage != nil { folderPage = nil }
            // TERM-MARKS: the tab is seen; its unread dot and command notice go.
            if let tab = selectedTab, tab.unread || tab.notice != nil { tab.unread = false; tab.notice = nil }
            guard let id = selected, let window = windowed[id] else { return }
            windowSelected[window] = id
            focusTabWindow?(window)
            selected = oldValue.flatMap { windowed[$0] == nil ? $0 : nil } ?? mainTabs.last?.id
        }
    }
    /// The connection whose page covers the session area (owner feedback 6, 2026-11-07): set by
    /// clicking a connection in the library, cleared by picking a tab. The inspector shows only here.
    var connectionPage: String? { didSet { if connectionPage != oldValue { viewChanged?() } } }
    /// The view on screen changed (tab, connection page or picked Recent row). Called as it changes, so
    /// what depends on it (the inspector's per-view choice) changes in the same SwiftUI update.
    @ObservationIgnored var viewChanged: (() -> Void)?
    /// The folder whose dashboard covers the session area (DASH-01): set by selecting a folder or
    /// the library root, cleared by picking a tab, like `connectionPage`.
    var folderPage: String?
    /// The folder the session area's dashboard is built for, hidden, before the first folder is
    /// selected (`FolderDashboardPrewarm`): the first select then only changes its folder.
    var folderPageWarm: String?
    /// The Recent Sessions row single-clicked on the start page (owner feedback 8): the inspector
    /// shows for it; nil (the default) keeps the start page full width.
    var startPick: String? { didSet { if startPick != oldValue { viewChanged?() } } }
    /// Tabs dragged out of the strip into their own window (`TabWindows.swift`).
    /// Tab id → the id of the window it was moved to (one window can hold several tabs).
    var windowed: [UUID: UUID] = [:]
    /// Each torn-off window's selected tab, by window id.
    var windowSelected: [UUID: UUID] = [:]
    /// Bumped when a torn-off window ends a move or resize, so the open-session set saves its frame.
    var windowFramesVersion = 0
    /// Tabs still in the main window's strip and session area.
    var mainTabs: [TerminalTab] { tabs.filter { windowed[$0.id] == nil } }
    /// The first session of `connectionId` that has not ended, if any (owner feedback 18).
    func liveTab(for connectionId: String) -> TerminalTab? { tabs(for: connectionId).first { !$0.ended } }
    /// Set by the main window: opens / brings forward a torn-off window by its id.
    @ObservationIgnored var openTabWindow: ((UUID) -> Void)?
    @ObservationIgnored var focusTabWindow: ((UUID) -> Void)?
    /// Set by the main window: the active document's id, and whether a document is locked now.
    @ObservationIgnored var currentDocumentId: (() -> String?)?
    @ObservationIgnored var documentLocked: ((String) -> Bool)?
    /// The tab's own document is locked: its content is covered and takes no input.
    func isDocumentLocked(_ tab: TerminalTab) -> Bool {
        guard let id = tab.documentId else { return false }
        return documentLocked?(id) ?? false
    }
    /// Home (⇧⌘H, Session menu, the strip's house button): the Start page in front of the open
    /// tabs, which stay open (owner round 2, item 6). Picking any tab leaves it.
    var homeShown = false
    /// The tab whose Rename field is open on it (`TabRenameField`).
    var renamingTab: UUID?
    /// The All Tabs list (⇧⌘A, Session menu, the strip's ⌄ button).
    var showingAllTabs = false
    /// The tab group whose editor popover (name, colour) is open on its chip.
    var editingGroup: String?
    /// Width of the session area, which the toolbar's tab strip sits above (`SessionTabStrip`).
    var sessionAreaWidth: CGFloat = 600
    @ObservationIgnored private var areaWidthSettle: Task<Void, Never>?
    /// A shrink of at least this much in one report is a window jump, not a drag.
    static let abruptShrink: CGFloat = 48
    /// The strip (a toolbar item) re-measures only once the width has settled: per-8 pt updates
    /// through a library slide rebuilt the toolbar every few frames (owner feedback 4, 2026-11-07).
    func sessionAreaResized(_ width: CGFloat) {
        // An abrupt shrink (zoom back, leave full screen: the window jumps) takes effect at once, as the library
        // opening does (`libraryWillShow`). Left to settle 150 ms, the strip kept its old, wider size, the trailing
        // items no longer fitted, and NSToolbar flashed its » menu until the width caught up. NSToolbar keeps an
        // item's first measured size, so the strip needs its new identity (`stripRoomChanged`), not a changed
        // intrinsic size. Slow drags stay debounced: a new identity per 8 pt step rebuilt the toolbar all along.
        if sessionAreaWidth - width >= Self.abruptShrink {
            areaWidthSettle?.cancel()
            if sessionAreaWidth != width { sessionAreaWidth = width; stripRoomChanged() }
            return
        }
        areaWidthSettle?.cancel()
        areaWidthSettle = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .milliseconds(150))
            guard !Task.isCancelled, let self, self.sessionAreaWidth != width else { return }
            self.sessionAreaWidth = width
            self.stripRoomChanged()
        }
    }
    /// The toolbar tab strip's identity: bumped only while the strip sits in the toolbar's » menu,
    /// so NSToolbar measures it afresh (`HostedTabStrip.StripHost`, MAC-TOOLBAR-OVERFLOW).
    var stripIdentity = 0
    /// How much less than its room the strip asks for, after it was measured again and still landed
    /// in the » menu: the bar had less room than the estimate (`SessionTabStrip.neighbours`). Without
    /// it every re-measure gave the same width, the strip went straight back into », and the toolbar
    /// was rebuilt about four times a second for as long as the app ran (MAC-IDLE-01: ~28 % idle CPU,
    /// ~70 MB/h of AppKit KVO dependency records). Zero again whenever the room changes.
    var stripSqueeze: CGFloat = 0
    /// The strip's room changed: a strip in the » menu never sees its new width, so re-measure it.
    func stripRoomChanged() {
        if stripSqueeze != 0 { stripSqueeze = 0 }
        if HostedTabStrip.StripHost.current?.isInOverflow == true { stripIdentity += 1 }
    }
    /// The strip was measured afresh and is still in the » menu at the same room: ask for less
    /// (24, 48, 96 … pt), so it converges in a few steps. At its minimum width it stays in » rather
    /// than rebuild the toolbar forever. Returns whether a new measure was started.
    @discardableResult
    func stripStillInOverflow(ideal: CGFloat, minimum: CGFloat) -> Bool {
        guard ideal - stripSqueeze > minimum else { return false }
        stripSqueeze = stripSqueeze == 0 ? Self.stripSqueezeStep : stripSqueeze * 2
        stripIdentity += 1
        return true
    }
    static let stripSqueezeStep: CGFloat = 24
    /// The library is opening: the session area loses the column's width, so the strip takes its
    /// final width now. Left to settle 150 ms after the slide, the strip kept its old width through
    /// the slide, the trailing items no longer fitted, and NSToolbar moved them into its ">>" menu
    /// on every frame of the open (MAC-LIBRARY-OPEN-OVERFLOW). Growing (the library closing) still
    /// waits for the width to settle: a strip narrower than the room never overflows.
    func libraryWillShow(sidebar: CGFloat) {
        areaWidthSettle?.cancel()
        let target = max(0, sessionAreaWidth - sidebar)
        if sessionAreaWidth != target { sessionAreaWidth = target; stripRoomChanged() }
    }
    /// Width of the library column; the Compact header's library switcher spans it (`CompactHeader`).
    var sidebarWidth: CGFloat = DS.Size.sidebarIdeal
    @ObservationIgnored private var sidebarWidthSettle: Task<Void, Never>?
    /// Settles like `sessionAreaResized`: the switcher is a toolbar item and re-measures per change.
    func sidebarResized(_ width: CGFloat) {
        sidebarWidthSettle?.cancel()
        sidebarWidthSettle = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .milliseconds(150))
            guard !Task.isCancelled, let self, self.sidebarWidth != width else { return }
            self.sidebarWidth = width
        }
    }
    /// Compact header with the library hidden: room the traffic lights and the switcher icon take
    /// in front of the tab group button, over the session area (`ContentView`).
    var compactLeading: CGFloat = 0
    var error: String?
    /// Bumped when connection history is written, so the inspector footer reloads.
    var historyRevision = 0
    /// Called with the connection id when a connection's tab opens (runs its after-connect tasks).
    @ObservationIgnored var onConnected: ((String) -> Void)?
    /// B5: once per session end (tab closed, or the link lost for good). Not on app quit.
    @ObservationIgnored var onDisconnected: ((String) -> Void)?
    @ObservationIgnored private var disconnectFired: Set<UUID> = []

    /// A session ended: run its after-disconnect hooks once. A tab still waiting since a crash
    /// never connected, so it has none.
    func sessionEnded(_ tab: TerminalTab) {
        guard let id = tab.connectionId, !tab.isWaiting, disconnectFired.insert(tab.id).inserted else { return }
        onDisconnected?(id)
    }

    /// The Activity log start for a saved RDP, VNC or web connection (`LibraryModel.activityStart`).
    @ObservationIgnored var activityStart: ((String) -> SessionActivityStart?)?

    /// An RDP or VNC connect that failed before its tab opened. Web failures are reported after
    /// the tab opened, so its own record ends when the tab closes.
    private func recordFailedDesktop(_ id: String) {
        guard let start = activityStart?(id), start.protocolName == "rdp" || start.protocolName == "vnc" else { return }
        SessionActivity.recordFailed(start, reason: "failed")
    }
    /// Internal so feature files (gateway routes, tunnels) can extend the model; views never call it.
    let manager: SessionManager?
    /// Started tunnels by definition id (Tunnel Manager).
    var runningTunnels: [String: RunningTunnel] = [:]
    /// Tabs whose input is shared (broadcast); empty when not broadcasting.
    private(set) var broadcastTargets: Set<UUID> = []
    private let group = BroadcastGroup()
    /// Opt-in session logs go here (owner-only).
    private let logDir: URL
    /// Tells the core when the network path changes so reconnecting tabs replace their link.
    let networkWatch = NetworkWatch()
    /// Set by the app: whether a library connection opts in to session logging.
    var wantsLog: (String) -> Bool = { _ in false }
    /// Set by the app: starts the core-planned session log of a saved connection (LOG-CORE-02);
    /// returns the file. Nil: the unplanned log below.
    @ObservationIgnored var startPlannedLog: ((Terminal, String) throws -> String)?

    init(dataDir: URL) {
        manager = try? SessionManager(dataDir: dataDir.path)
        logDir = dataDir.appendingPathComponent("session-logs", isDirectory: true)
        // Supervised SSH terminals with automatic reconnect pause before sleep and resume on wake.
        let center = NSWorkspace.shared.notificationCenter
        center.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.manager?.systemWillSleep() }
        }
        center.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.manager?.systemDidWake() }
        }
        networkWatch.onChange = { [weak self] in self?.manager?.networkChanged() }
        networkWatch.start()
        TermEventsRuntime.shared.sessions = self
    }

    /// Forks the PTY off the main thread (nm-24: the spawn was ~9 ms of the first-open stall). One
    /// serial queue, so a burst of shells opens its tabs in order.
    func openLocal() {
        let plan = LocalShellAgent.plan()
        Self.spawnQueue.async {
            let result = Result { try LocalShellAgent.terminal(plan, cols: 80, rows: 24) }
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    switch result {
                    case .success(let t): LocalShellActivity.markLocal(t); self.add(TerminalTab(name: "Local Shell", terminal: t))
                    case .failure(let e): self.error = "Could not start a local shell: \(e)"
                    }
                }
            }
        }
    }

    private static let spawnQueue = DispatchQueue(label: "bastion.local-shell-spawn", qos: .userInitiated)

    /// A saved local terminal connection: its shell, arguments and start folder from the core.
    func openLocal(connection: ConnectionView, library: Library) {
        do {
            let t = try Terminal.localConnection(library: library, connectionId: connection.id, cols: 80, rows: 24)
            LocalShellActivity.markLocal(t)
            add(TerminalTab(name: connection.name, content: .terminal(t), connectionId: connection.id))
        } catch {
            self.error = "Could not start \(connection.name): \(errorText(error))"
        }
    }

    func add(_ tab: TerminalTab) {
        if tab.documentId == nil { tab.documentId = currentDocumentId?() }
        if let id = tab.connectionId, var queue = pendingGroups[id], !queue.isEmpty {
            let gid = queue.removeFirst()
            pendingGroups[id] = queue
            if let def = pendingGroupDefs.first(where: { $0.id == gid }) {
                tab.group = gid
                if !groups.contains(where: { $0.id == gid }) { groups.append(def) }
            }
        }
        tabs.append(tab)
        if let id = tab.connectionId { tab.beginActivity(activityStart?(id)) }
        regroup()
        selected = tab.id
        if let id = tab.connectionId { onConnected?(id) }
        if let id = tab.connectionId, wantsLog(id), let t = tab.terminal { startLog(t, label: tab.name, connectionId: id) }
        placeRestored(tab)
    }

    /// A multi-host exec run over this manager's broker and known_hosts (not started yet).
    func multiExec(library: Library, ids: [String], command: String, concurrency: UInt32, username: String, login: SshLogin, productionAck: Bool) throws -> MultiExec {
        guard let manager else { throw FfiError.Failed(message: "The session manager could not start.", code: "other") }
        return try MultiExec(manager: manager, library: library, connectionIds: ids, command: command, concurrency: concurrency,
                             username: username, login: login, productionAck: productionAck)
    }

    // MARK: Session logs, broadcast, snippets

    /// The core's defaults (`sessionlog::DEFAULT_MAX_BYTES`, `DEFAULT_KEEP`); escape codes are stripped, as on Windows (LOG-01).
    private static let logMaxBytes: UInt64 = 10 * 1024 * 1024
    private static let logKeep: UInt32 = 5

    /// A saved connection's log goes where the core plans it (folder path, header, settings);
    /// a tab without a connection keeps the flat `session-logs` file.
    private func startLog(_ t: Terminal, label: String, connectionId: String?) {
        if let connectionId, let plan = startPlannedLog {
            do { _ = try plan(t, connectionId) } catch { self.error = "The session log could not be started: \(errorText(error))" }
            return
        }
        do { _ = try t.startLogWith(dir: logDir.path, label: label, maxBytes: Self.logMaxBytes, keep: Self.logKeep, stripAnsi: true) } catch { self.error = "The session log could not be started: \(errorText(error))" }
    }

    /// Session › Start/Stop Session Log for the focused pane.
    func toggleLog() {
        guard let tab = selectedTab, let t = tab.terminal else { return }
        if t.isLogging() { _ = try? t.finishLog(reason: "stopped") } else { startLog(t, label: tab.name, connectionId: tab.connectionId) }
        tab.logChanged += 1
    }

    func startBroadcast(_ ids: Set<UUID>) {
        broadcastTargets = ids
        group.setMembers(terminals: tabs.filter { ids.contains($0.id) }.compactMap(\.terminal))
    }

    func stopBroadcast() {
        broadcastTargets = []
        group.setMembers(terminals: [])
    }

    /// Mirror input typed in a broadcast member to the other members.
    func broadcast(_ bytes: [UInt8], from source: Terminal) {
        guard !broadcastTargets.isEmpty, tabs.contains(where: { broadcastTargets.contains($0.id) && $0.terminal === source }) else { return }
        _ = try? group.send(bytes: Data(bytes), source: source)
    }

    /// A snippet: to the focused terminal, and to the other members while broadcasting. One line
    /// is typed (so Return runs it); several lines go as a paste followed by Return, after the
    /// sheet's confirmation.
    /// The focused terminal, then every other broadcast member: where a snippet goes.
    var snippetTargets: [Terminal] {
        guard let focused = selectedTab?.terminal else { return [] }
        return [focused] + tabs.filter { broadcastTargets.contains($0.id) && $0.terminal !== focused }.compactMap(\.terminal)
    }

    func sendToFocused(_ text: String) {
        guard let t = selectedTab?.terminal else { return }
        let lines = text.trimmingCharacters(in: .newlines)
        if lines.contains(where: \.isNewline) {
            try? t.paste(text: lines)
            try? t.write(bytes: Data("\r".utf8))
        } else {
            try? t.write(bytes: Data((lines + "\r").utf8))
        }
        broadcast(Array(lines.utf8) + [13], from: t)
    }

    /// A tab restored after a crash (decision D15): back in its place, not connected. Nothing has
    /// connected, so there is no recent-session entry, no session log and no request to any host.
    @discardableResult
    func addWaiting(connection c: ConnectionView, mode: ConnectMode, layout: [String]) -> TerminalTab {
        let tab = TerminalTab(name: mode == .files ? "\(c.name) — Files" : c.name, content: .waiting(mode), connectionId: c.id)
        tab.restoredLayout = layout
        tab.documentId = currentDocumentId?()
        tabs.append(tab)
        regroup()
        if selected == nil { selected = tab.id }
        placeRestored(tab)
        return tab
    }

    /// Add a reconnected workspace tab and rebuild its split panes: each extra pane is another
    /// shell on the same connection (no new login), as ⌘D would open it.
    func add(_ tab: TerminalTab, layout: [String]) {
        add(tab)
        guard !layout.isEmpty, let first = tab.panes.first else { return }
        Task { await rebuild(LayoutCursor(layout), at: first, in: tab) }
    }

    private func rebuild(_ cursor: LayoutCursor, at pane: TerminalPane, in tab: TerminalTab) async {
        // `right:0.620`: axis and the first side's share (an even split when absent).
        guard let step = cursor.next()?.split(separator: ":"), let axis = step.first.flatMap({ SplitAxis(rawValue: String($0)) }) else { return }
        let ratio = step.count > 1 ? Double(step[1]).map { CGFloat($0) } ?? 0.5 : 0.5
        let source = pane.terminal
        do {
            let terminal = try await Task.detached { try source.openSibling(cols: 80, rows: 24) }.value
            if LocalShellActivity.isLocal(source) { LocalShellActivity.markLocal(terminal) }
            let sibling = TerminalPane(terminal: terminal)
            tab.focusedPane = pane.id
            tab.split(with: sibling, axis: axis, ratio: ratio)
            await rebuild(cursor, at: pane, in: tab)
            await rebuild(cursor, at: sibling, in: tab)
        } catch {
            self.error = "Could not restore a split pane: \(error)"
        }
    }

    var selectedTab: TerminalTab? { tabs.first { $0.id == selected } }

    /// ⇧⌘] / ⇧⌘[: the next or previous tab, wrapping around.
    /// Pin or unpin a tab. Pinned tabs leave their group and sit first, in pin order.
    func setPinned(_ tab: TerminalTab, _ pinned: Bool) {
        guard tab.pinned != pinned else { return }
        if pinned, tab.group != nil { groupOp(["op": "removeFromGroup", "tab": tab.id.uuidString]) }
        tab.pinned = pinned
        tab.detached = pinned || tab.detached
        let to = tabs.filter { $0.pinned && $0.id != tab.id }.count
        groupOp(["op": "move", "tab": tab.id.uuidString, "to": to])
    }

    func selectNeighbourTab(forward: Bool) {
        let tabs = mainTabs
        guard tabs.count > 1, let i = tabs.firstIndex(where: { $0.id == selected }) else { return }
        selected = tabs[(i + (forward ? 1 : tabs.count - 1)) % tabs.count].id
    }

    /// A connection whose ended desktop tab asked to reconnect; the window runs the
    /// `reconnect` command for it (close the tab, then the connect sheet again).
    var reconnectRequest: String?
    /// A tab's right-click asked for Connect as… (new tab) or Reconnect as… (`replacing` set).
    var connectAsRequest: ConnectAsRequest?

    /// Connections with a connect in flight (SSH and SFTP; set by `connect`).
    var connecting: Set<String> = []

    /// Real per-connection state from the open tabs, for menus and status indicators.
    var snapshot: SessionSnapshot {
        let linked = tabs.filter { $0.connectionId != nil }
        return SessionSnapshot(connected: linked.filter { !$0.ended && !$0.isWaiting }.compactMap(\.connectionId),
                               connecting: Array(connecting),
                               failed: linked.filter(\.ended).compactMap(\.connectionId))
    }

    func tabs(for connectionId: String) -> [TerminalTab] {
        tabs.filter { $0.connectionId == connectionId }
    }

    /// Disconnect, Disconnect All: end every session opened from one of `connectionIds`. A terminal
    /// tab stays, disconnected, with its Reconnect button; closing it emptied the session area and
    /// showed the start page (MAC-RECONNECT-PANE). Other tabs (desktops, files, web) close.
    func disconnect(_ connectionIds: Set<String>) {
        for tab in tabs where tab.connectionId.map(connectionIds.contains) ?? false {
            if tab.root != nil { tab.closeAll() } else { close(tab) }
        }
    }

    /// Splits the selected tab's focused pane. An SSH pane gets a second shell on the same
    /// connection (no new login); a local pane gets a new local shell. Opening the channel can
    /// block on the network, so it runs off the main thread.
    func split(_ axis: SplitAxis) async {
        guard let tab = selectedTab, let source = tab.terminal else { return }
        do {
            let terminal = try await Task.detached { try source.openSibling(cols: 80, rows: 24) }.value
            if LocalShellActivity.isLocal(source) { LocalShellActivity.markLocal(terminal) }
            tab.split(with: TerminalPane(terminal: terminal), axis: axis)
        } catch {
            self.error = "Could not open a new pane: \(error)"
        }
    }

    /// ⌘W: the focused pane, or the whole tab when it has one pane (or is a files tab). Asks
    /// first when `terminal.confirm-close` is on and the pane's session is still running.
    func closeFocused() {
        guard let tab = selectedTab else { return }
        if tab.panes.count > 1, let pane = tab.panes.first(where: { $0.id == tab.focusedPane }) {
            guard confirmClose([pane], what: "this pane") else { return }
            _ = tab.closeFocusedPane()
        } else {
            requestClose(tab)
        }
    }

    /// The tab's close button and ⌘W on its last pane: asks first like `closeFocused`.
    func requestClose(_ tab: TerminalTab) {
        guard confirmClose(tab.panes, what: "“\(tab.name)”") else { return }
        close(tab)
    }

    /// `terminal.confirm-close`: read when asked, so a change applies at once.
    var confirmCloseEnabled: () -> Bool = { true }
    /// Answer the UI driver gives instead of showing the alert (nil shows it).
    var scriptedCloseAnswer: Bool?
    /// Close confirmations asked so far (UI driver).
    private(set) var closeConfirmations = 0

    /// Whether to close: true at once when nothing is running or confirmation is off. A pane
    /// counts as running while its SSH link is alive, or while a program runs in its local shell
    /// (owner round 2, item 14: an idle local shell closes without asking; `LocalShellActivity`).
    private func confirmClose(_ panes: [TerminalPane], what: String) -> Bool {
        let live = panes.filter { !$0.ended }
        let shellBusy = live.contains { LocalShellActivity.isLocal($0.terminal) } && LocalShellActivity.anyShellBusy()
        let running = live.filter { !LocalShellActivity.isLocal($0.terminal) || shellBusy }
        guard confirmCloseEnabled(), !running.isEmpty else { return true }
        closeConfirmations += 1
        if let answer = scriptedCloseAnswer { return answer }
        let alert = NSAlert()
        alert.messageText = "Close \(what)?"
        alert.informativeText = running.count == 1 ? "Its session is still running and will be ended." : "\(running.count) sessions are still running and will be ended."
        alert.addButton(withTitle: "Close")
        alert.addButton(withTitle: "Cancel")
        return alert.runModalInFront() == .alertFirstButtonReturn
    }

    // MARK: Find (⌘F, ⌘G, ⇧⌘G)

    /// Whether the find bar shows, its query (shared by Find Next and Find Previous) and options.
    var searching = false
    var searchQuery = ""
    var searchStatus: String?
    /// Match case (⌥⌘C) and Regular expression (⌥⌘R); plain text, case ignored by default.
    var searchMatchCase = false
    var searchRegex = false

    /// Next (`forward`, newer) or previous match of the query in the focused terminal; the status
    /// reads "3 of 12", "No matches" or why the expression is invalid.
    func find(forward: Bool) {
        guard let terminal = selectedTab?.terminal else { return }
        guard !searchQuery.isEmpty else { searching = true; searchStatus = nil; return }
        do {
            searchStatus = Self.findStatus(try terminal.find(query: searchQuery, forward: forward, matchCase: searchMatchCase, regex: searchRegex))
        } catch {
            searchStatus = "Invalid expression"
        }
    }

    /// Search again from the newest match (the query or an option changed).
    func refind() {
        selectedTab?.terminal?.clearSearch()
        if searchQuery.isEmpty { searchStatus = nil } else { find(forward: false) }
    }

    static func findStatus(_ r: FindResultView) -> String {
        if r.total == 0 { return "No matches" }
        if r.capped { return r.index > 0 ? "\(r.index) of \(r.total)+" : "\(r.total)+ matches" }
        return "\(r.index) of \(r.total)"
    }

    func endSearch() {
        selectedTab?.terminal?.clearSearch()
        searching = false
        searchStatus = nil
    }

    // MARK: Terminal commands

    /// ⌘+ ⌘− ⌘0 on the selected tab (per tab, not saved).
    func zoom(_ step: Int?) {
        guard let tab = selectedTab, tab.root != nil else { return }
        tab.zoom = step.map { tab.zoom + $0 } ?? 0
    }

    /// Send Break: an interrupt (ETX, as Ctrl+C) to the focused terminal. Holding the shortcut
    /// repeats it like holding Ctrl+C.
    func sendBreak() {
        guard let t = selectedTab?.terminal else { return }
        try? t.write(bytes: Data([0x03]))
        broadcast([0x03], from: t)
    }

    /// Reconnect as…: the new session takes the old tab's place, then the old one closes.
    func replace(_ oldId: UUID, with tab: TerminalTab) {
        guard let i = tabs.firstIndex(where: { $0.id == oldId }) else { return add(tab) }
        let old = tabs[i]
        tab.group = old.group
        tab.detached = old.detached
        tab.pinned = old.pinned
        if tab.documentId == nil { tab.documentId = old.documentId }
        tabs[i] = tab
        if let id = tab.connectionId { tab.beginActivity(activityStart?(id)) }
        // Reconnect keeps the earlier session's text above the new prompt.
        if let was = old.panes.first?.terminal, let now = tab.panes.first?.terminal { now.carryOver(old: was) }
        old.closeAll()
        selected = tab.id
        // A tab that waited since a crash has now connected: its first connect, with its splits.
        if old.isWaiting {
            if let id = tab.connectionId { onConnected?(id) }
            if !old.restoredLayout.isEmpty, let first = tab.panes.first {
                Task { await rebuild(LayoutCursor(old.restoredLayout), at: first, in: tab) }
            }
        }
        if let id = tab.connectionId, wantsLog(id), let t = tab.terminal { startLog(t, label: tab.name, connectionId: id) }
    }

    func close(_ tab: TerminalTab) {
        sessionEnded(tab)
        disconnectFired.remove(tab.id)
        // The log footer says why it ended (LOG-CORE-02); a log that is not running returns nil.
        for pane in tab.panes { _ = try? pane.terminal.finishLog(reason: "closed") }
        tab.closeFilePanel()
        tab.closeAll()
        tabs.removeAll { $0.id == tab.id }
        if let window = windowed.removeValue(forKey: tab.id), windowSelected[window] == tab.id {
            windowSelected[window] = tabs.last { windowed[$0.id] == window }?.id
        }
        if selected == tab.id { selected = mainTabs.last?.id }
        regroup()
    }

    /// Take a strip from the core: tab order, each tab's group and the groups themselves. Tabs
    /// the core listed as closed (Close Group) are closed here.
    func adopt(_ strip: StripState, closing closed: [String] = []) {
        let byId = Dictionary(uniqueKeysWithValues: tabs.map { ($0.id, $0) })
        let gone = Set(closed.compactMap(UUID.init(uuidString:)))
        var order: [TerminalTab] = []
        // Every tab open runs this (`regroup`), mostly with nothing changed. Written only when changed:
        // an equal write still invalidates every view that reads it (MAC-FIRST-SHELL).
        for t in strip.tabs {
            guard let id = UUID(uuidString: t.id), let tab = byId[id], !gone.contains(id) else { continue }
            if tab.group != t.group { tab.group = t.group }
            if tab.detached != (t.detached ?? false) { tab.detached = t.detached ?? false }
            order.append(tab)
        }
        // Anything the strip did not mention stays, at the end.
        order += tabs.filter { tab in !gone.contains(tab.id) && !order.contains { $0 === tab } }
        tabs.filter { gone.contains($0.id) }.forEach { sessionEnded($0); disconnectFired.remove($0.id); $0.closeAll() }
        if !order.elementsEqual(tabs, by: ===) { tabs = order }
        if groups != strip.groups { groups = strip.groups }
        if let s = selected, gone.contains(s) { selected = tabs.last?.id }
    }

    /// The vault that `.vault` logins read from (opened by `CredentialsModel`).
    func useVault(_ vault: CredentialVault) {
        manager?.setVault(vault: vault)
    }

    /// The Vaultwarden session that `.vaultwarden` logins read from.
    func useVaultwarden(_ session: VaultwardenSession) {
        manager?.setVaultwarden(session: session)
    }

    func lockCredentials() {
        do { try manager?.lockCredentials() } catch { self.error = "\(error)" }
    }

    enum ConnectResult: Sendable {
        case connected(SessionContent)
        /// `hop` is nil for the target itself, else the jump host's `host:port`.
        case unknownHost(hop: String?, fingerprint: String)
        /// The server asked for a second factor (or the code was wrong).
        case needsCode
        case tunnel(RunningTunnel)
        /// No common algorithm; `names` are the weak ones "Allow for this host" may enable (empty: none can).
        case weakAlgorithms(message: String, kind: String, names: [String])
        case failed(String)
    }

    /// Jump hosts of a connection in connect order; empty when direct or not resolvable yet.
    func jumpHosts(library: Library, connectionId: String) -> [JumpHostView] {
        (try? manager?.jumpHosts(library: library, connectionId: connectionId)) ?? []
    }

    /// Runs the blocking connect off the main thread.
    /// `jumpTrust` holds fingerprints the user verified for jump hosts and `jumpLogins` their own
    /// logins (both keyed `host:port`); a hop without a login uses the target's.
    func connect(library: Library, connectionId: String, username: String, login: SshLogin, trust: String?,
                 jumpTrust: [String: String] = [:], jumpLogins: [String: SshLogin] = [:],
                 mode: ConnectMode = .terminal, tunnelId: String? = nil, systemView: String? = nil) async -> ConnectResult {
        guard let manager else { return .failed("The session manager could not start.") }
        connecting.insert(connectionId)
        defer { connecting.remove(connectionId) }
        let result = await Task.detached { () -> ConnectResult in
            do {
                switch mode {
                case .terminal:
                    return .connected(.terminal(try manager.connectSsh(library: library, connectionId: connectionId, username: username,
                                                                       login: login, trustFingerprint: trust, jumpTrust: jumpTrust,
                                                                       jumpLogins: jumpLogins, cols: 80, rows: 24)))
                case .files:
                    return .connected(.files(try manager.connectSftp(library: library, connectionId: connectionId, username: username,
                                                                     login: login, trustFingerprint: trust, jumpTrust: jumpTrust,
                                                                     jumpLogins: jumpLogins)))
                case .system:
                    return .connected(.system(try SystemView.openView(manager: manager, library: library, connectionId: connectionId, view: systemView, username: username,
                                                                  login: login, trustFingerprint: trust)))
                case .tunnel:
                    return .tunnel(try manager.startTunnel(library: library, tunnelId: tunnelId ?? "", username: username, login: login,
                                                           trustFingerprint: trust, jumpTrust: jumpTrust, jumpLogins: jumpLogins))
                }
            } catch FfiError.HostKeyUnknown(let fingerprint) {
                return .unknownHost(hop: nil, fingerprint: fingerprint)
            } catch FfiError.JumpHostKeyUnknown(let hop, let fingerprint) {
                return .unknownHost(hop: hop, fingerprint: fingerprint)
            } catch FfiError.NeedsConfiguration(let missing) {
                return .failed("This host needs your values for \(missing.map { "<\($0)>" }.joined(separator: ", ")). Set them under SSH Config Sources or Personal Overrides.")
            } catch FfiError.NoCommonAlgorithm(let message, let kind, _, let weakAllowable) {
                return .weakAlgorithms(message: message, kind: kind, names: weakAllowable)
            } catch FfiError.TwoFactorRequired {
                return .needsCode
            } catch FfiError.AuthFailed {
                return .failed("Authentication failed. Check the username and credentials.")
            } catch {
                return .failed(error.userMessage)
            }
        }.value
        recordHistory(connectionId, username: username, result: result)
        return result
    }

    /// Feeds the inspector footer ("Last connected" / "Last result"); prompts are not outcomes.
    private func recordHistory(_ id: String, username: String, result: ConnectResult) {
        switch result {
        case .connected, .tunnel: recordOutcome(id, user: username, failure: nil)
        case .failed(let message), .weakAlgorithms(let message, _, _): recordOutcome(id, user: username, failure: message)
        case .unknownHost, .needsCode: return
        }
    }

    /// One connect outcome for the inspector footer; `failure` nil means it connected.
    func recordOutcome(_ id: String, user: String?, failure: String?) {
        let dir = LibraryModel.stateDir
        do {
            if let failure {
                recordFailedDesktop(id)
                try recordConnectionFailure(dataDir: dir, connectionId: id, error: failure)
            } else {
                try recordConnectionSuccess(dataDir: dir, connectionId: id, user: user.flatMap { $0.isEmpty ? nil : $0 })
            }
            historyRevision += 1
        } catch {
            self.error = "Could not save connection history: \(error)"
        }
    }
}


/// Tab strip plus the selected terminal.
struct SessionTabsView: View {
    @Environment(SessionsModel.self) private var sessions
    @Environment(SettingsModel.self) private var settings
    @Environment(Commands.self) private var commands
    @Environment(AppRouter.self) private var router
    @Environment(ShortcutsModel.self) private var shortcuts
    /// The last folder shown: the dashboard stays built for it, hidden, while a tab or a
    /// connection page is in front.
    @State private var keptFolder: String?

    private var selectedTerminal: Terminal? { sessions.selectedTab?.terminal }

    // The canvas stays mounted while there are no tabs, with the start page over it: swapping
    // one for the other made the first local shell and the last tab close lay out the whole
    // session area from scratch (nm-22: a 250–400 ms stall and a 170 ms close).
    var body: some View {
        let _ = RenderCount.hit("SessionArea")
        let empty = sessions.mainTabs.isEmpty
        let home = empty || sessions.homeShown
        let covered = home || sessions.connectionPage != nil || sessions.folderPage != nil
        let folderShown = sessions.folderPage != nil && sessions.connectionPage == nil
        ZStack {
            // One dashboard, kept mounted (hidden when not in front): building it on the first folder
            // select was a 55–63 ms stall (perf budgets, 5,000 connections); a select now only
            // changes its folder, as every later select did.
            // At the bottom, under a plain blocker, so hiding it never changes its hit testing: a hit-test
            // flip on a subtree with AppKit views re-parents them (key-view loop, table re-tile), about
            // 20 ms of every tab opened over a folder page (MAC-FIRST-SHELL).
            if let id = sessions.folderPage ?? keptFolder ?? sessions.folderPageWarm {
                FolderDashboard(folderId: id, isShown: folderShown).equatable()
                    .opacity(folderShown ? 1 : 0)
                    .disabled(!folderShown)
                    .accessibilityHidden(!folderShown)
            }
            Color.clear.contentShape(Rectangle()).allowsHitTesting(!folderShown)
            canvas
                .opacity(covered ? 0 : 1)
                .allowsHitTesting(!covered)
                .disabled(covered)
                .accessibilityHidden(covered)
            // Not under a folder page: there it was hidden but still held Return (Quick Connect).
            if home && sessions.folderPage == nil { StartPage().background(.background) }
            if let id = sessions.connectionPage, let c = commands.model.connection(id: id) {
                ConnectionPage(connection: c)
            }
        }
        .onChange(of: sessions.folderPage) { _, id in if let id { keptFolder = id } }
    }

    private var canvas: some View {
            VStack(spacing: 0) {
                BroadcastBanner()
                // All Tabs hangs from the top of the session area, not the strip's ⌄ button:
                // a narrow window moves the strip into the toolbar's » menu, and ⇧⌘A must still work.
                AllTabsAnchor()
                    .frame(maxWidth: .infinity)
                    .background(SizeReporter { sessions.sessionAreaResized($0.width) })
                // The tabs live in the toolbar beside the traffic lights (`SessionTabStrip`), or
                // down the side with the Vertical tabs setting (`VerticalTabList`).
                PaneShortcuts()
                if sessions.searching, selectedTerminal != nil {
                    TerminalSearchBar()
                    Divider()
                }
                if let tab = sessions.selectedTab, let id = tab.connectionId, let c = commands.model.connection(id: id) {
                    SessionTitleBar(tab: tab, connection: c)
                }
                HStack(spacing: 0) {
                if settings.value("tabs.vertical") == "true" {
                    VerticalTabList().frame(width: DS.Size.verticalTabs)
                    Divider()
                }
                FilePanelHost(tab: sessions.selectedTab) {
                ZStack {
                    // Every tab stays mounted so its view keeps its size and timer; only one is visible.
                    ForEach(sessions.mainTabs) { tab in
                        // Under a connection page the selected tab is not active: a terminal there
                        // must not take the keyboard from the library (QA F2: Return was lost).
                        TabContentView(tab: tab, isActive: tab.id == sessions.selected && sessions.connectionPage == nil && sessions.folderPage == nil)
                        .opacity(tab.id == sessions.selected ? 1 : 0)
                        .allowsHitTesting(tab.id == sessions.selected)
                        // Hidden terminals release their drawn layer contents (TerminalNSView.isShown).
                        .environment(\.tabShown, tab.id == sessions.selected)
                    }
                }
                }
                }
            }
    }
}

/// Invisible button that owns ⌘W while sessions are open: it closes the focused pane (then the
/// tab) before it can close the window. Pane focus moves from the Session menu (configurable).
private struct PaneShortcuts: View {
    @Environment(SessionsModel.self) private var sessions

    var body: some View {
        Group {
            Button("Close Pane") { sessions.closeFocused() }.keyboardShortcut("w")
        }
        .frame(width: 0, height: 0)
        .opacity(0)
        .accessibilityHidden(true)
    }
}

/// Search in the selected terminal's screen and scrollback, as you type. Return finds the previous
/// (older) match, Shift-Return the next one; ⌥⌘C and ⌥⌘R toggle Match case and Regular expression;
/// closing clears the highlight.
private struct TerminalSearchBar: View {
    @Environment(SessionsModel.self) private var sessions
    @FocusState private var focused: Bool

    var body: some View {
        @Bindable var sessions = sessions
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("Find", text: $sessions.searchQuery)
                .textFieldStyle(.plain)
                .focused($focused)
                .accessibilityLabel("Find in terminal")
                .onSubmit { sessions.find(forward: NSEvent.modifierFlags.contains(.shift)) }
                .onChange(of: sessions.searchQuery) { sessions.refind() }
            Toggle(isOn: $sessions.searchMatchCase) { Text("Aa").font(.system(.body, design: .monospaced)).iconHitTarget() }
                .toggleStyle(.button)
                .iconTip("Match case (⌥⌘C)")
                .accessibilityLabel("Match case")
                .keyboardShortcut("c", modifiers: [.command, .option])
                .onChange(of: sessions.searchMatchCase) { sessions.refind() }
            Toggle(isOn: $sessions.searchRegex) { Text(".*").font(.system(.body, design: .monospaced)).iconHitTarget() }
                .toggleStyle(.button)
                .iconTip("Regular expression (⌥⌘R)")
                .accessibilityLabel("Regular expression")
                .keyboardShortcut("r", modifiers: [.command, .option])
                .onChange(of: sessions.searchRegex) { sessions.refind() }
            if let status = sessions.searchStatus {
                Text(status).font(DS.Font.caption).foregroundStyle(.secondary).monospacedDigit().lineLimit(1).fixedSize()
            }
            Button("Previous", systemImage: "chevron.up") { sessions.find(forward: false) }.iconHitTarget()
            Button("Next", systemImage: "chevron.down") { sessions.find(forward: true) }.iconHitTarget()
            Button("Close", systemImage: "xmark") { sessions.endSearch() }
                .iconHitTarget()
                .keyboardShortcut(.cancelAction)
                .iconTip("Close")
        }
        .labelStyle(.iconHitTarget)
        .buttonStyle(.borderless)
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(.bar)
        .onAppear { focused = true }
    }
}

struct ConnectAsRequest: Equatable {
    let connectionId: String
    let replacing: UUID?
}

struct TabButton: View {
    @Environment(SessionsModel.self) private var sessions
    /// UI-06: the window's tones (a torn-off window has its own); the main strip also reads them from `sessions`.
    @Environment(\.chromeTones) private var envTones
    let tab: TerminalTab
    let isSelected: Bool
    let select: () -> Void
    let close: () -> Void
    /// Fixed width in the shrinking strip; nil sizes to the title (vertical list).
    var width: CGFloat? = nil
    /// Icon-only (pinned tab).
    var compact = false
    @State private var hovering = false

    /// Room for the icon, the title and padding, between Tabby-like bounds: short titles stay
    /// compact, long ones truncate. Measured with the system font the label uses.
    /// The widest a tab may be so `widths` fit in `room`: nil (no cap) when they fit as they are;
    /// otherwise the level where the widest are cut down evenly, never below `floor` (owner 2026-11-16).
    static func shareCap(_ widths: [CGFloat], room: CGFloat, floor: CGFloat) -> CGFloat? {
        guard widths.reduce(0, +) > room + 0.5 else { return nil }
        var left = room
        let sorted = widths.sorted()
        for (i, w) in sorted.enumerated() {
            let share = left / CGFloat(sorted.count - i)
            if w > share { return max(floor, share.rounded(.down)) }
            left -= w
        }
        return nil
    }

    static func contentWidth(_ title: String, dot: Bool = false) -> CGFloat {
        // The label's own size: body text times the UI zoom (`DS.Font.body`). Measured at a fixed
        // 13 pt, every name was cut short at any zoom above Actual Size.
        let size = DS.Font.points(.body) * DS.Font.zoom
        let text = ceil((title as NSString).size(withAttributes: [.font: NSFont.systemFont(ofSize: size)]).width)
        // Leading padding, icon, gap, dot, the name, the trailing inset that holds the ✕, and a
        // little slack so the name never truncates by a rounding pixel. Every gap is counted: an
        // uncounted one cut names.
        return max(Self.padding + 16 + 6 + (dot ? TabLinkDot.size + 6 : 0) + text + Self.closeInset + 4, DS.Size.tabContentMin)
    }

    /// The strip's measure of a tab: its name, plus the dot when it has one.
    static func contentWidth(_ tab: TerminalTab) -> CGFloat {
        // The logging mark (caption symbol) and its spacing, when the session is being logged.
        contentWidth(tab.stripName, dot: tab.linkDot != nil) + (tab.isLogging ? DS.Font.points(.caption) * DS.Font.zoom + 8 : 0)
    }

    static let padding: CGFloat = 10
    /// Room on the right for the ✕ (16 pt) with 4 pt either side: it sits in the tab's trailing
    /// inset, not in the content row, so it costs 14 pt more than plain padding, not 28.
    static let closeInset: CGFloat = 24

    /// "name, status" for VoiceOver; the dot itself is hidden from it.
    private var accessibilityText: String {
        let marks = tab.notice ?? (tab.unread ? "unread output" : nil)
        return ([tab.stripName, tab.linkText, marks].compactMap { $0 }).joined(separator: ", ")
    }

    private var hostPaint: HostColors.Paint? { HostColors.shared.paint(for: tab.connectionId) }
    /// The close button shows on the selected tab and under the pointer, always on the right
    /// (owner 2026-11-17); its slot is kept so the name does not move.
    private var showsClose: Bool { !compact && (isSelected || hovering) }

    var body: some View {
        let _ = RenderCount.hit("TabButton")
        HStack(spacing: 6) {
            ZStack {
                Image(systemName: tab.ended ? "bolt.horizontal.circle" : tab.symbol)
                    .foregroundStyle(tab.ended || tab.isWaiting ? .secondary : .primary)
                    // TERM-MARKS: a small badge on the icon, so the tab keeps its width.
                    .overlay(alignment: .topTrailing) {
                        if tab.unread || tab.notice != nil {
                            Circle().fill(tab.notice?.hasPrefix("Command failed") == true ? Color.red : Color.accentColor)
                                .frame(width: 6, height: 6).offset(x: 3, y: -2).accessibilityHidden(true)
                        }
                    }
            }
            .frame(width: 16)
            if !compact { TabLabel(tab: tab, isSelected: isSelected) }
        }
        .padding(.leading, compact ? 0 : Self.padding)
        .padding(.trailing, compact ? 0 : Self.closeInset)
        .frame(width: compact ? DS.Size.pinnedTab : width, height: 26, alignment: compact ? .center : .leading)
        .overlay(alignment: .trailing) {
            if showsClose {
                Button(action: close) { Image(systemName: "xmark").font(DS.Font.caption2.weight(.semibold)) }
                    .buttonStyle(TabCloseButtonStyle())
                    .help("Close Tab")
                    .padding(.trailing, 4)
            }
        }
        // Tabby: flat tabs. Only a faint fill on the selected tab and under the pointer.
        .background(background, in: RoundedRectangle(cornerRadius: 5))
        .overlay(alignment: .leading) {
            // Per-host colour (`host_color`, e.g. production): a thin bar on the leading edge.
            if let p = hostPaint {
                RoundedRectangle(cornerRadius: 1).fill(Color(nsColor: p.accent)).frame(width: 2).padding(.vertical, 6)
            }
        }
        .overlay(alignment: .bottom) {
            // Chrome: a line in the group colour under every tab of a group, so the run reads as
            // one; the selected tab outside a group gets a thin accent line.
            if isSelected || groupTint != nil {
                Rectangle().fill(groupTint ?? Color.accentColor)
                    .frame(height: 2)
                    .padding(.horizontal, groupTint == nil ? 6 : 0)
            }
        }
        .overlay { MiddleClickCatcher(action: close) }
        // Its own AppKit menu: in the toolbar a SwiftUI `.contextMenu` never opened and the
        // toolbar's "Icon and Text" menu showed instead (owner round 4, item 5).
        .background { TabMenuAnchor { [sessions] in TabMenu.build(tab: tab, sessions: sessions, close: close) } }
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .onTapGesture(perform: select)
        // Simultaneous, so a single click still selects at once (no wait for a second click).
        .simultaneousGesture(TapGesture(count: 2).onEnded { sessions.renamingTab = tab.id })
        .popover(isPresented: Binding(get: { sessions.renamingTab == tab.id }, set: { if !$0 { sessions.renamingTab = nil } })) {
            TabRenameField(tab: tab)
        }
        .help(tab.desktopCloseReason.map { "\(tab.stripName): \($0)" } ?? tab.customName ?? TabTitle.sanitized(tab.remoteTitle) ?? tab.name)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityText)
        .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : .isButton)
        .accessibilityAction(named: "Close Tab", close)
    }

    /// The tab's group colour, if it is in a group.
    private var groupTint: Color? { tab.group.flatMap(sessions.group).map { StripGroup.tint($0.color) } }

    /// Selected: a faint neutral fill. Hover: fainter still. Both follow light and dark.
    private var background: Color {
        if isSelected, let tones = envTones ?? sessions.chromeTones { return tones.activeTab }
        if isSelected { return Color.primary.opacity(0.07) }
        return hovering ? Color.primary.opacity(0.04) : .clear
    }
}

/// A strip tab's dot, name and logging mark (its own view keeps TabButton's body type-checkable).
private struct TabLabel: View {
    let tab: TerminalTab
    let isSelected: Bool

    var body: some View {
        if let dot = tab.linkDot { TabLinkDot(dot: dot, text: tab.linkText ?? "") }
        Text(tab.stripName).lineLimit(1).truncationMode(.tail)
            .foregroundStyle(isSelected ? .primary : .secondary)
        // No Spacer here: in the tab's HStack a Spacer takes 6 pt the width measure does not count.
        if tab.isLogging {
            Image(systemName: "record.circle").foregroundStyle(.red).font(DS.Font.caption).help("Session output is being logged")
        }
    }
}

/// The tab's link state as a small dot: green online, amber reconnecting, red offline. The words are
/// in its tooltip and the tab's accessibility label. Static: no animation, nothing per byte.
struct TabLinkDot: View {
    static let size: CGFloat = 7
    let dot: TerminalTab.LinkDot
    let text: String

    var body: some View {
        Circle()
            .fill(Color(nsColor: Icons.dynamicColor(dot.token)))
            .frame(width: Self.size, height: Self.size)
            .help(text)
            .accessibilityHidden(true)
    }
}

/// The tab's ✕: a small circle that lights up under the pointer.
private struct TabCloseButtonStyle: ButtonStyle {
    @State private var hovering = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .frame(width: 16, height: 16)
            .background(Color.primary.opacity(configuration.isPressed ? 0.2 : hovering ? 0.1 : 0), in: Circle())
            .contentShape(Circle())
            .onHover { hovering = $0 }
    }
}

/// Middle-click closes the tab (Safari, Chrome, iTerm2). Transparent to every other event.
private struct MiddleClickCatcher: NSViewRepresentable {
    let action: () -> Void

    func makeNSView(context: Context) -> CatcherView { CatcherView(action: action) }
    func updateNSView(_ view: CatcherView, context: Context) { view.action = action }

    final class CatcherView: NSView {
        var action: () -> Void
        init(action: @escaping () -> Void) { self.action = action; super.init(frame: .zero) }
        required init?(coder: NSCoder) { nil }

        override func hitTest(_ point: NSPoint) -> NSView? {
            guard let e = NSApp.currentEvent, e.type == .otherMouseDown || e.type == .otherMouseUp, e.buttonNumber == 2 else { return nil }
            return super.hitTest(point)
        }

        override func otherMouseUp(with event: NSEvent) {
            if event.buttonNumber == 2, bounds.contains(convert(event.locationInWindow, from: nil)) { action() }
        }
    }
}

/// Collects the username and credential for one SSH connect. Secrets live only in this sheet's
/// state until they are handed to the core broker.
struct ConnectSheet: View {
    let connection: ConnectionView
    let mode: ConnectMode
    /// A Quick Connect target's unsaved library; nil for library connections.
    var quickLibrary: Library? = nil
    /// Workspace split tree to rebuild once connected.
    var layout: [String] = []
    /// With `mode == .tunnel`: the saved tunnel to start.
    var tunnelId: String? = nil
    var systemView: String? = nil
    /// Connect as… / Reconnect as…: start blank with recent usernames for this host as
    /// suggestions (never secrets), and offer to save the login to the vault (off by default).
    var connectAs = false
    /// Reconnect as…: the tab the new session replaces once connected.
    var replacing: UUID? = nil
    /// With `mode == .files`: the SSH tab whose file panel shows the browser (no new tab).
    var filePanelFor: UUID? = nil
    /// False when a direct connect already tried the saved login and it failed: show the form.
    var autoConnectAllowed = true
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @Environment(CredentialsModel.self) private var credentials
    @Environment(VaultwardenModel.self) private var vaultwarden
    @Environment(\.dismiss) private var dismiss
    @State private var username = ""
    @State private var credentialId: String?
    @State private var vaultwardenItem: String?
    @State private var providerRef = ""
    @State private var method = Method.password
    @State private var password = ""
    @State private var keyPath = ""
    @State private var passphrase = ""
    @State private var busy = false
    @State private var error: String?
    @State private var pendingKey: Fingerprint?
    @State private var weakOffer: WeakOffer?
    @State private var targetTrust: String?
    @State private var jumpTrust: [String: String] = [:]
    @State private var hops: [JumpHostView] = []
    @State private var separateHopLogins = false
    @State private var hopPasswords: [String: String] = [:]
    /// Shown once the server asked for a second factor; the code is sent with the password once.
    @State private var needsCode = false
    @State private var code = ""
    /// The connection's inline secret, when it has one (`CredentialVault.inlineFor`).
    @State private var inlineSecret: InlineCredentialView?
    /// Asked before an inline secret is used on a Production host.
    @State private var confirmingInline = false
    @State private var recentUsers: [String] = []
    @State private var saveToVault = false
    /// The login this connection used last in this run (Reconnect, Recent sessions).
    @State private var reusedLogin: SshLogin?
    /// Saved properties connect at once; the form shows only when something is missing or the
    /// attempt failed (owner feedback 2026-11-07 #2).
    @State private var autoConnectTried = false
    /// The saved-login attempt is running: a small "Reconnecting…" card covers the sign-in steps
    /// (owner feedback 2026-11-07 #17). Cleared when it fails, so the form shows what went wrong.
    @State private var autoConnecting = false
    /// Saved logins the core offers this connection, best first (`LoginResolver`).
    @State private var offers: [LoginOffer] = []
    /// The selected vault login is the connection's own, inherited or inline: no question needed.
    @State private var autoLogin = false
    /// "Use this login for <connection> from now on", for a login that is not the connection's own.
    @State private var keepLogin = false
    /// The credential this sheet added to the connection's logins for the connect in progress.
    /// It stays only when that connect succeeds; a failed or cancelled attempt removes it again.
    @State private var addedLogin: String?

    static let width: CGFloat = 584

    enum Method: String, CaseIterable { case vault = "Vault", vaultwarden = "Vaultwarden", provider = "Provider", password = "Password", key = "Key File", agent = "Agent" }

    var body: some View {
        Form {
            LabeledContent("Host", value: "\(connection.host):\(connection.port.map(String.init) ?? "22")")
            if connectAs {
                HStack {
                    TextField("User", text: $username)
                    if !recentUsers.isEmpty {
                        Menu("Recent") {
                            ForEach(recentUsers, id: \.self) { u in Button(u) { username = u } }
                        }
                        .fixedSize()
                        .help("Usernames used for this host before")
                    }
                }
            } else {
                TextField("User", text: $username)
            }
            Picker("Authentication", selection: $method) {
                ForEach(Method.allCases, id: \.self) { Text($0.rawValue) }
            }
            // A pop-up: five segments in the SDK 27 style need 594 pt and the sheet has 524
            // (a1-logins-fit, 2026-11-16).
            .pickerStyle(.menu)
            if method == .vault {
                Picker("Credential", selection: Binding(get: { credentialId }, set: { pickCredential($0) })) {
                    Text("Choose…").tag(String?.none)
                    if let inlineSecret {
                        Text("This connection’s own \(inlineSecret.kind == "ssh-key" ? "key" : "password") (\(inlineSecret.username))").tag(Optional(connection.id))
                    }
                    // The core's list, each with where it comes from: the only saved logins the
                    // core lets this connection use. Any other saved credential first joins the
                    // connection's logins, on Connect (A1-CORE-01-FU2).
                    if !offers.isEmpty {
                        Section("Logins for this connection") {
                            ForEach(offers) { Text($0.label).tag(Optional($0.credentialId)) }
                        }
                    }
                    // Connect as… is a one-off login: it never adds to the connection, so it
                    // lists only what the core already lets this connection use.
                    if !connectAs, !otherCredentials.isEmpty {
                        Section("Add to this connection") {
                            ForEach(otherCredentials, id: \.id) { Text("\($0.name) (\($0.username))").tag(Optional($0.id)) }
                        }
                    }
                }
                if addsLogin {
                    Text("Connect adds this credential to the logins of \(connection.name).")
                        .font(DS.Font.caption).foregroundStyle(.secondary)
                }
                if connectAs, offers.isEmpty, inlineSecret == nil {
                    Text("No saved login is set for \(connection.name). Add one in Properties › Credentials, or type a password.")
                        .font(DS.Font.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                if canKeepLogin {
                    Toggle("Use this login for \(connection.name) from now on", isOn: $keepLogin)
                        .lineLimit(1).truncationMode(.middle)
                        .help("Add it to this connection’s logins, so the next connect does not ask.")
                }
            } else if method == .vaultwarden {
                if vaultwarden.isUnlocked {
                    Picker("Item", selection: $vaultwardenItem) {
                        Text("Choose…").tag(String?.none)
                        ForEach(vaultwarden.items, id: \.id) { Text("\($0.name) (\($0.username ?? "no user"))").tag(Optional($0.id)) }
                    }
                } else {
                    Text("Vaultwarden is locked. Unlock it in More → Credentials… (Vaultwarden).").foregroundStyle(.secondary)
                }
            } else if method == .provider {
                ProviderLoginFields(reference: $providerRef)
            } else if method == .password {
                SecureField("Password", text: $password).onSubmit(submit)
                if needsCode {
                    TextField("Verification code", text: $code, prompt: Text("From your authenticator"))
                        .onSubmit(submit)
                    Text("The server asks for a second factor. The code is used for this sign-in only.")
                        .font(DS.Font.caption).foregroundStyle(.secondary)
                }
            } else if method == .agent {
                Text(ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"] == nil
                     ? "No SSH agent is running for this session (SSH_AUTH_SOCK is not set)."
                     : "Keys from your SSH agent are offered in turn; they never enter Gantry.")
                    .foregroundStyle(.secondary)
            } else {
                HStack {
                    TextField("Private key", text: $keyPath)
                    Button("Choose…", action: chooseKey)
                }
                SecureField("Passphrase (if the key is encrypted)", text: $passphrase).onSubmit(submit)
            }
            if !hops.isEmpty {
                Section("Jump hosts") {
                    Toggle("Use a different password for jump hosts", isOn: $separateHopLogins)
                    if separateHopLogins {
                        ForEach(hops, id: \.key) { hop in
                            SecureField("\(hop.username)@\(hop.key)", text: Binding(
                                get: { hopPasswords[hop.key] ?? "" },
                                set: { hopPasswords[hop.key] = $0 }))
                        }
                    }
                }
            }
            if connectAs, method == .password || method == .key {
                Toggle("Save to vault", isOn: $saveToVault)
                    .help("Keep this login as a credential in the vault. Off: the secret is used for this session only.")
            }
            if let error { CodedError(area: "SSH", message: error) }
            if let weakOffer {
                HStack {
                    Text("Weak: \(weakOffer.names.joined(separator: ", "))").font(DS.Font.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Allow for This Host") { Task { await allowWeakAndRetry(weakOffer) } }.disabled(busy)
                }
            }
        }
        .formStyle(.grouped)
        // The sheet follows the form's height (a code field or jump-host logins may appear after
        // presentation); a grouped form would otherwise scroll inside the first height.
        .scrollDisabled(true)
        .fixedSize(horizontal: false, vertical: true)
        // Wide enough for the six authentication segments without truncating "Vaultwarden" (layout fit).
        .frame(width: ConnectSheet.width)
        .disabled(busy)
        .overlay { if autoConnecting { ReconnectingCard(name: connection.name, reconnect: reusedLogin != nil) { dismiss() } } }
        // The UI driver cannot reach SwiftUI Form buttons (the in-process accessibility tree is
        // built only for an assistive client), so `top-button` asks the visible button by name.
        .onReceive(NotificationCenter.default.publisher(for: DriverEvents.pressButton)) { note in
            if note.object as? String == "Allow for This Host", let weakOffer, !busy {
                Task { await allowWeakAndRetry(weakOffer) }
            }
            driverLoginStep(note.object as? String ?? "")
        }
        .onChange(of: method) { _, m in
            guard m == .vault else { return }
            Task {
                await credentials.openInBackground(sessions: sessions)
                if offers.isEmpty { await loadOffers() }
            }
        }
        .onChange(of: loginState, initial: true) { _, state in LoginResolver.sheetState = state }
        .onChange(of: sheetDetail, initial: true) { _, d in LoginResolver.sheetDetail = d }
        // Closed before the connect succeeded (Cancel, or an unknown host key declined).
        .onDisappear { removeAddedLogin() }
        .onAppear {
            if let lib = library { hops = sessions.jumpHosts(library: lib, connectionId: connection.id) }
            // Only a connection with an assigned credential needs the vault (a Keychain read) now;
            // otherwise it opens when the user picks Vault.
            if connectAs {
                method = .password
                recentUsers = (try? recentUsernames(dataDir: LibraryModel.dataDir.path, host: connection.host, port: connection.port)) ?? []
                return
            }
            vaultwardenItem = connection.vaultwardenItem
            if autoConnectAllowed, let last = usableLastLogin {
                username = last.username
                reusedLogin = last.login
                autoConnect()
                return
            }
            // The connection's own secret, or a login the core lets it use without asking.
            let saved = quickLibrary == nil && (connection.inlineCredential != nil
                || LoginResolver.mayAutoConnect(connection, credentials: credentials, passwordsOnly: false))
            method = saved ? .vault : vaultwardenItem != nil ? .vaultwarden : .password
            // A saved login connects behind the "Reconnecting…" card from the first frame; the form
            // shows only if the attempt cannot start or fails (owner points 23 and 26).
            autoConnecting = saved && autoConnectAllowed
            // Off the main thread: the Keychain read, and Touch ID when the setting asks for it.
            // The vault opens only for a connection that sets a login, or when opening cannot prompt.
            Task {
                await loadOffers()
                guard let vault = credentials.vault else { autoConnecting = false; return }
                if let inline = try? vault.inlineFor(connectionId: connection.id) {
                    inlineSecret = inline
                    method = .vault
                    credentialId = connection.id
                    autoLogin = true
                    if username.isEmpty { username = inline.username }
                } else if let first = offers.first, first.autoUse || vaultwardenItem == nil {
                    // Its own or inherited login connects at once. One saved for another connection
                    // is selected and labelled, and waits for Connect (owner decision D1).
                    method = .vault
                    credentialId = first.credentialId
                    autoLogin = first.autoUse
                } else if offers.isEmpty, let name = connection.effectiveCredentialName {
                    error = "No single saved credential is called “\(name)”. Choose one below."
                } else if offers.isEmpty, method == .vault {
                    // Vault was chosen before the logins loaded (a stale assignment, or the vault not
                    // open yet), and none applies: an empty picker would leave no way to sign in.
                    method = vaultwardenItem != nil ? .vaultwarden : .password
                }
                autoConnect()
            }
            // Imported hosts show the user after placeholders and overrides, never a raw `<user>`.
            if connection.imported, let lib = model.library,
               let e = (try? model.workflow?.effectiveFor(library: lib, connectionId: connection.id)) ?? nil {
                username = e.unresolved.isEmpty ? (e.user ?? "") : ""
            } else {
                username = connection.effectiveUsername ?? ""
            }
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button(busy ? "Connecting…" : "Connect", action: submit).disabled(!canConnect)
            }
        }
        .alert("Use this connection’s own secret on a Production host?", isPresented: $confirmingInline) {
            Button("Connect") { Task { await connect() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(InlineSecretWarning.text + " \(connection.name) is classified Production.")
        }
        .sheet(item: $pendingKey) { fp in
            HostKeyPrompt(host: fp.hop.map { "jump host \($0)" } ?? connection.host, fingerprint: fp.value,
                          trust: {
                              if let hop = fp.hop { jumpTrust[hop] = fp.value } else { targetTrust = fp.value }
                              pendingKey = nil
                              Task { await connect() }
                          },
                          cancel: { pendingKey = nil })
        }
    }

    private var library: Library? { quickLibrary ?? model.library }

    // MARK: Saved logins (LoginResolver)

    /// Ask the core which saved logins this connection can use. Quick Connect targets have none.
    private func loadOffers() async {
        guard quickLibrary == nil, let lib = model.library else { return }
        offers = await LoginResolver.resolve(connection, library: lib, credentials: credentials, sessions: sessions, passwordsOnly: false)
    }

    /// The login used a moment ago; a vault login confirmed in this run only while still offered.
    private var usableLastLogin: RememberedLogin? {
        guard let last = credentials.lastLogin(for: connection.id) else { return nil }
        guard case .vault(let id) = last.login else { return last }
        if LoginResolver.stillOffered(id, to: connection, credentials: credentials, passwordsOnly: false) { return last }
        credentials.forgetLastLogin(for: connection.id)
        return nil
    }

    private var selectedOffer: LoginOffer? { offers.first { $0.credentialId == credentialId } }
    private var otherCredentials: [CredentialView] {
        credentials.items.filter { item in !offers.contains { $0.credentialId == item.id } }
    }

    /// A login saved for another connection (offered, not its own) can be kept from now on.
    private var canKeepLogin: Bool {
        guard method == .vault, quickLibrary == nil, !connectAs else { return false }
        return selectedOffer.map { !$0.autoUse } ?? false
    }

    /// A saved credential the core does not list for this connection: Connect adds it first.
    private var addsLogin: Bool {
        guard method == .vault, !connectAs, let credentialId, credentialId != connection.id else { return false }
        return selectedOffer == nil
    }

    private func pickCredential(_ id: String?) {
        if id != addedLogin { removeAddedLogin() }
        credentialId = id
        keepLogin = false
    }

    /// The connect this sheet added a login for did not succeed (it failed, or the sheet closed
    /// first): the login leaves the connection again, so a wrong pick is never sent by itself later.
    private func removeAddedLogin() {
        guard let id = addedLogin else { return }
        addedLogin = nil
        guard let vault = credentials.vault else { return }
        if let quickLibrary {
            do { _ = try vault.removeLogin(library: quickLibrary, connectionId: connection.id, credentialId: id) } catch {
                sessions.error = "\(connection.name): the login could not be removed again: \(errorText(error))"
            }
            return
        }
        let connectionId = connection.id
        LoginResolver.change(connectionId, model: model, credentials: credentials) { vault, library in
            _ = try vault.removeLogin(library: library, connectionId: connectionId, credentialId: id)
        }
        Task { await loadOffers() }
    }

    /// The core connects with a saved credential only when the connection's login list has it
    /// (`may_use`). One picked from the rest of the vault joins the connection's own logins
    /// before the connect; false when that fails (the reason is shown).
    private func addPickedLogin() async -> Bool {
        guard addsLogin, reusedLogin == nil, let id = credentialId, let library, let vault = credentials.vault else { return true }
        var failure: String?
        if quickLibrary != nil {
            // A Quick Connect target lives in its own library, which is never saved.
            do { try vault.addLogin(library: library, connectionId: connection.id, credentialId: id) } catch { failure = errorText(error) }
        } else {
            // Changed and saved in one step, and the remembered login makes way for the new list.
            let connectionId = connection.id
            model.mutate { library in
                do { try vault.addLogin(library: library, connectionId: connectionId, credentialId: id) } catch {
                    failure = errorText(error)
                    throw error
                }
            }
            if let saveError = model.error { failure = failure ?? saveError; model.error = nil }
            credentials.forgetLastLogin(for: connection.id)
        }
        if let failure {
            self.error = "This credential could not be added to \(connection.name): \(failure)"
            return false
        }
        addedLogin = id
        if quickLibrary == nil { await loadOffers() }
        return true
    }

    /// For the UI driver's failure lines only: which sign-in step the sheet is on.
    private var sheetDetail: String {
        "method=\(method.rawValue) autoConnecting=\(autoConnecting) reused=\(reusedLogin != nil) offers=\(offers.count) busy=\(busy) error=\(error ?? "-")"
    }

    private var loginState: String {
        LoginResolver.sheetText(offers: offers, selected: method == .vault ? credentialId : nil, keep: canKeepLogin ? keepLogin : nil)
    }

    /// UI driver (`login-pick <label>`, `login-keep on|off`): the same state the controls set.
    private func driverLoginStep(_ step: String) {
        if step.hasPrefix("login-pick:") {
            let want = String(step.dropFirst("login-pick:".count))
            // Connect as… lists only the core's logins: anything else there leaves "Choose…".
            let id = offers.first(where: { $0.label == want || $0.name == want })?.credentialId
                ?? (connectAs ? nil : credentials.items.first(where: { $0.name == want })?.id)
            guard id != nil || connectAs else { return }
            method = .vault
            pickCredential(id)
        } else if step == "login-connect:" {
            Task { await connect() }
        } else if step.hasPrefix("login-keep:") {
            keepLogin = step.hasSuffix(":on") && canKeepLogin
        }
    }

    /// After a Connect as… login succeeded: the username becomes a suggestion for this host, and
    /// the secret goes to the vault only when "Save to vault" is on.
    private func rememberLogin() async {
        do {
            try recordRecentUsername(dataDir: LibraryModel.dataDir.path, host: connection.host, port: connection.port, username: username)
        } catch {
            sessions.error = "The username was not remembered: \(errorText(error))"
        }
        guard saveToVault, method == .password || method == .key else { return }
        let user = username, secret = password, path = keyPath, label = "\(username)@\(connection.host)"
        await credentials.openInBackground(sessions: sessions)
        let key = method == .key ? (try? String(contentsOfFile: (path as NSString).expandingTildeInPath, encoding: .utf8)) : nil
        if method == .key, key == nil { sessions.error = "The key file could not be read, so it was not saved to the vault."; return }
        _ = credentials.mutate { v in
            if let key {
                _ = try v.saveSshKey(id: nil, name: label, folder: nil, username: user, privateKey: key)
            } else {
                _ = try v.savePassword(id: nil, name: label, folder: nil, username: user, password: secret)
            }
        }
    }

    private var canConnect: Bool {
        !(busy || (username.isEmpty && method != .vault && method != .vaultwarden) || (method == .key && keyPath.isEmpty)
          || (method == .vault && credentialId == nil)
          || (method == .password && needsCode && code.trimmingCharacters(in: .whitespaces).isEmpty)
          || (method == .vaultwarden && (vaultwardenItem == nil || !vaultwarden.isUnlocked))
          || (method == .provider && providerRef.isEmpty))
    }

    /// Connect button and Return in a credential field.
    private func submit() {
        guard canConnect else { return }
        if usesInlineSecret, isProduction {
            confirmingInline = true
            return
        }
        Task { await connect() }
    }

    private var usesInlineSecret: Bool { method == .vault && inlineSecret != nil && credentialId == connection.id }

    private var isProduction: Bool {
        guard let lib = library else { return false }
        return (try? lib.propertyValues(id: connection.id))?.first { $0.key == "environment" }?.effective == "production"
    }

    /// Connect without showing a prompt when everything is already known: a saved (inline or
    /// vault) credential, or the login used a moment ago. Once only; a failure shows the form.
    private func autoConnect() {
        guard !autoConnectTried, !connectAs, autoConnectAllowed else { autoConnecting = false; return }
        autoConnectTried = true
        guard reusedLogin != nil || (method == .vault && credentialId != nil && autoLogin),
              canConnect, !(usesInlineSecret && isProduction) else { autoConnecting = false; return }
        autoConnecting = true
        Task {
            await connect()
            autoConnecting = false
        }
    }

    private var login: SshLogin {
        if let reusedLogin { return reusedLogin }
        return switch method {
        case .vault: .vault(credentialId: credentialId ?? "")
        case .vaultwarden: .vaultwarden(itemId: vaultwardenItem ?? "")
        case .provider: .provider(reference: providerRef)
        case .password: needsCode ? .passwordAndCode(password: password, code: code) : .password(password: password)
        case .agent: .agent
        case .key: .keyFile(path: (keyPath as NSString).expandingTildeInPath, passphrase: passphrase.isEmpty ? nil : passphrase)
        }
    }

    /// Only hops with a password typed get their own login; the rest reuse the target's.
    private var hopLogins: [String: SshLogin] {
        guard separateHopLogins else { return [:] }
        return hopPasswords.filter { !$0.value.isEmpty }.mapValues { .password(password: $0) }
    }

    private func chooseKey() {
        let panel = NSOpenPanel()
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        panel.showsHiddenFiles = true
        if panel.runModal() == .OK, let url = panel.url { keyPath = url.path }
    }

    /// Each unknown key (jump hosts first, then the target) gets its own prompt; the attempt is
    /// retried with every fingerprint trusted so far.
    private func connect() async {
        guard let library else { return }
        busy = true
        error = nil
        guard await addPickedLogin() else { busy = false; autoConnecting = false; return }
        let used = login
        let result = await sessions.connect(library: library, connectionId: connection.id, username: username, login: used,
                                            trust: targetTrust, jumpTrust: jumpTrust, jumpLogins: hopLogins, mode: mode, tunnelId: tunnelId, systemView: systemView)
        busy = false
        switch result {
        case .connected(.files(let browser)) where filePanelFor != nil:
            addedLogin = nil
            sessions.tabs.first { $0.id == filePanelFor }?.filePanel = browser
            password = ""
            passphrase = ""
            code = ""
            hopPasswords = [:]
            dismiss()
        case .connected(let content):
            // The connect succeeded with the login this sheet added: it stays, as the caption said.
            addedLogin = nil
            if !connectAs, method != .vault, method != .vaultwarden, method != .provider {
                let kept: SshLogin = if case .passwordAndCode(let p, _) = used { .password(password: p) } else { used }
                credentials.remember(RememberedLogin(username: username, login: kept), for: connection.id)
            } else if canKeepLogin, !keepLogin, reusedLogin == nil {
                // Confirmed for this run only: Reconnect goes straight through, by id (no secret kept here).
                credentials.remember(RememberedLogin(username: username, login: used), for: connection.id)
            }
            let name = mode == .files ? "\(connection.name) — Files" : connectAs ? "\(connection.name) (\(username))" : connection.name
            let tab = TerminalTab(name: name, content: content, connectionId: connection.id)
            if let replacing { sessions.replace(replacing, with: tab) } else { sessions.add(tab, layout: layout) }
            if connectAs { await rememberLogin() } else { await rememberAnswer(used) }
            password = ""
            passphrase = ""
            code = ""
            hopPasswords = [:]
            dismiss()
        case .tunnel(let running):
            addedLogin = nil
            if let tunnelId { sessions.runningTunnels[tunnelId]?.stop(); sessions.runningTunnels[tunnelId] = running }
            password = ""
            dismiss()
        case .needsCode:
            // A second factor is never remembered: the form asks for the code with the password filled.
            if case .password(let p)? = reusedLogin { password = p }
            if reusedLogin != nil { reusedLogin = nil; method = .password }
            error = needsCode ? "The code was not accepted. Enter the current code." : nil
            needsCode = true
            code = ""
        case .unknownHost(let hop, let fp):
            pendingKey = Fingerprint(value: fp, hop: hop)
        case .weakAlgorithms(let message, let kind, let names):
            error = message
            weakOffer = names.isEmpty ? nil : WeakOffer(kind: kind, names: names)
        case .failed(let message):
            error = message
            if reusedLogin != nil { dropReusedLogin() }
            removeAddedLogin()
        }
    }

    /// A sign-in typed or chosen in this sheet is kept for the connection, so the next
    /// double-click, Recent or Reconnect opens directly (owner points 23 and 26). A typed password
    /// or key becomes the connection's own secret (sealed in the vault, like Properties ›
    /// Credentials); a vault login that is not yet the connection's own joins its logins when
    /// "Use this login … from now on" is ticked. Quick Connect targets and a login reused from
    /// this run are not written.
    private func rememberAnswer(_ used: SshLogin) async {
        guard quickLibrary == nil, reusedLogin == nil, model.library != nil else { return }
        if case .vault(let id) = used {
            guard canKeepLogin, keepLogin, id == credentialId else { return }
            LoginResolver.keep(id, for: connection, model: model, credentials: credentials)
            return
        }
        let secret: SavedAnswer
        switch used {
        case .password(let p), .passwordAndCode(let p, _): secret = .password(p)
        case .keyFile(let path, let pass): secret = .key(path: path, passphrase: pass)
        default: return
        }
        if credentials.vaultForSave() == nil { await credentials.openInBackground(sessions: sessions) }
        guard let vault = credentials.vaultForSave() ?? credentials.vault else {
            sessions.error = "\(connection.name): signed in, but saved logins are locked, so this login was not remembered."
            return
        }
        do {
            switch secret {
            case .password(let p):
                try vault.setInlinePassword(connectionId: connection.id, username: username, password: p)
            case .key(let path, let pass):
                let key = try String(contentsOfFile: path, encoding: .utf8)
                try vault.setInlineKey(connectionId: connection.id, username: username, privateKey: key, passphrase: pass)
            }
            try vault.save()
            model.mutate { try $0.setInlineMarker(connectionId: connection.id, kind: secret.kind) }
        } catch {
            sessions.error = "\(connection.name): signed in, but the login was not remembered: \(errorText(error))"
        }
    }

    private enum SavedAnswer {
        case password(String), key(path: String, passphrase: String?)
        var kind: String { if case .password = self { "password" } else { "ssh-key" } }
    }

    /// The remembered login no longer works: forget it and let the form ask.
    private func dropReusedLogin() {
        reusedLogin = nil
        credentials.forgetLastLogin(for: connection.id)
    }

    /// "Allow for this host": the core enables the named weak algorithms on this connection only
    /// (policy may refuse), then the connect is retried.
    private func allowWeakAndRetry(_ offer: WeakOffer) async {
        guard let library else { return }
        do {
            try library.allowWeakAlgorithms(id: connection.id, kind: offer.kind, names: offer.names)
            try library.save()
            if quickLibrary == nil { model.mutate { _ in } }
            weakOffer = nil
            await connect()
        } catch {
            self.error = "Not allowed: \(errorText(error))"
            weakOffer = nil
        }
    }
}

private struct WeakOffer {
    let kind: String
    let names: [String]
}

private struct Fingerprint: Identifiable {
    let value: String
    var hop: String?
    var id: String { value }
}

/// First-contact host key confirmation. Trust is explicit and per fingerprint; a changed key is
/// refused by the core and never reaches this prompt.
struct HostKeyPrompt: View {
    let host: String
    let fingerprint: String
    /// "host key" for SSH, "certificate" for RDP.
    var subject = "host key"
    /// True when a different fingerprint was trusted before for this host.
    var changed = false
    /// The confirming button. Test Connection names its own (SEC-07).
    var trustTitle = "Trust and Connect"
    /// A line under the fingerprint saying what trusting does here; nil for a normal connect.
    var note: String?
    /// Return cancels, so trusting takes a deliberate click (Test Connection). Escape still cancels.
    var cancelOnReturn = false
    let trust: () -> Void
    let cancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(changed ? "Changed \(subject)" : "Unknown \(subject)", systemImage: "exclamationmark.shield").font(DS.Font.headline)
                .foregroundStyle(changed ? .red : .primary)
            Text(changed ? "The \(subject) of \(host) differs from the one you trusted before. This can mean the server was reinstalled, or that someone is intercepting the connection. Compare" : "Gantry has not seen \(host) before. Compare this fingerprint with one you obtained independently (for example from the server's administrator or console) before trusting it.")
                .fixedSize(horizontal: false, vertical: true)
            Text(fingerprint).font(DS.Font.style(.body, design: .monospaced)).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            if let note {
                Text(note).font(DS.Font.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                if cancelOnReturn {
                    Button("Cancel", role: .cancel, action: cancel).keyboardShortcut(.defaultAction).dsPrimaryButton()
                        // A button takes one shortcut: Escape goes to an unseen twin.
                        .background { Button("", action: cancel).keyboardShortcut(.cancelAction).dsSecondaryButton().frame(width: 0, height: 0).opacity(0).accessibilityHidden(true) }
                } else {
                    Button("Cancel", role: .cancel, action: cancel).keyboardShortcut(.cancelAction).dsSecondaryButton()
                }
                Button(trustTitle, action: trust)
            }
        }
        .padding(20)
        .frame(width: 460)
        // UI driver: SwiftUI buttons are not NSButtons it can click (`top-button Trust and Connect`).
        .onReceive(NotificationCenter.default.publisher(for: DriverEvents.pressButton)) { pressed in
            if pressed.object as? String == trustTitle { trust() }
        }
    }
}

/// Reads a pre-order layout (`right:0.5`/`down:0.5`/`leaf`) one step at a time across async rebuilds.
@MainActor
private final class LayoutCursor {
    private var steps: ArraySlice<String>
    init(_ steps: [String]) { self.steps = steps[...] }
    func next() -> String? { steps.popFirst() }
}

/// Over an RDP or VNC tab whose session ended: why, with Reconnect (the connect sheet again,
/// so credentials and the certificate pin are checked as on any connect) and Close.
struct DesktopEndedOverlay: View {
    let tab: TerminalTab
    @Environment(SessionsModel.self) private var sessions

    var body: some View {
        if let reason = tab.desktopCloseReason {
            VStack(spacing: DS.Space.s) {
                Text("Disconnected").font(DS.Font.headline)
                Text(reason).font(DS.Font.caption).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center).frame(maxWidth: 360)
                HStack(spacing: DS.Space.xs) {
                    Button("Close Tab") { sessions.close(tab) }
                    if let id = tab.connectionId {
                        Button("Reconnect") { sessions.reconnectRequest = id }.keyboardShortcut(.defaultAction).dsPrimaryButton()
                    }
                }
            }
            .padding(DS.Space.l)
            .background(RoundedRectangle(cornerRadius: 10).fill(.regularMaterial))
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(.black.opacity(0.35))
        }
    }
}

/// A tab restored after a crash (decision D15): back in its place, connected only when the user
/// asks. The session title bar above it says Disconnected and offers Reconnect, as for an ended
/// session; this says why, and offers the same connect.
struct RestoredTabView: View {
    let tab: TerminalTab
    let isActive: Bool
    @Environment(SessionsModel.self) private var sessions
    @Environment(Commands.self) private var commands

    private var isConnecting: Bool { tab.connectionId.map(sessions.connecting.contains) ?? false }

    var body: some View {
        VStack(spacing: DS.Space.s) {
            Text("Not connected").font(DS.Font.headline)
            Text("Gantry did not quit normally last time. This tab is back where it was. Nothing is sent to the host until you connect.")
                .font(DS.Font.callout).foregroundStyle(.secondary)
                // No `fixedSize` here: it made the text's smallest height the height it has when
                // squeezed to one word per line, and the window's content grew far taller than
                // the window (layout fit, run of 2026-11-13).
                .multilineTextAlignment(.center).frame(maxWidth: 360)
            if isConnecting {
                ProgressView("Connecting…").controlSize(.small)
            } else {
                HStack(spacing: DS.Space.xs) {
                    Button("Close Tab") { sessions.close(tab) }
                    // One default button: only the tab that is showing takes Return.
                    if isActive {
                        Button("Connect") { commands.connectRestored(tab) }.keyboardShortcut(.defaultAction).dsPrimaryButton()
                    } else {
                        Button("Connect") { commands.connectRestored(tab) }
                    }
                }
            }
        }
        .padding(DS.Space.l)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.background)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("restored-tab")
        // The UI driver's `restore-connect` presses Connect on the tab that is showing.
        .onReceive(NotificationCenter.default.publisher(for: DriverEvents.pressButton)) { note in
            if isActive, note.object as? String == "restore-connect" { commands.connectRestored(tab) }
        }
    }
}

/// Covers the connect sheet while a saved login signs in by itself, so the user sees one calm
/// line instead of the form flickering through its steps.
struct ReconnectingCard: View {
    let name: String
    let reconnect: Bool
    let cancel: () -> Void

    var body: some View {
        VStack(spacing: DS.Space.s) {
            ProgressView().controlSize(.small)
            Text(reconnect ? "Reconnecting…" : "Connecting…").font(DS.Font.headline)
            Text(name).font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            Button("Cancel", action: cancel).controlSize(.small)
        }
        .padding(DS.Space.m)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.background)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("reconnecting-card")
    }
}

/// Rename Tab: a field under the tab. Return keeps the name; an empty name brings back the
/// automatic one; Esc leaves it as it was (owner round 2, item 4).
struct TabRenameField: View {
    @Environment(SessionsModel.self) private var sessions
    let tab: TerminalTab
    @State private var text = ""
    @FocusState private var focused: Bool
    private static let width: CGFloat = 220

    var body: some View {
        TextField(tab.name, text: $text)
            .textFieldStyle(.roundedBorder)
            .frame(width: Self.width)
            .focused($focused)
            .onSubmit {
                let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                tab.customName = trimmed.isEmpty ? nil : String(trimmed.prefix(TabTitle.maxLength))
                sessions.renamingTab = nil
            }
            .onExitCommand { sessions.renamingTab = nil }
            .padding(DS.Space.s)
            .help("Empty restores the automatic name")
            .onAppear {
                text = tab.customName ?? tab.shownName
                focused = true
                // The whole name selected, so typing replaces it.
                // The popover's window may not be key (sendAction to nil would reach the main window),
                // so select in this field's own editor once it has focus.
                let name = text
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                    let editor = NSApp.windows.lazy.compactMap { $0.firstResponder as? NSTextView }.first { $0.string == name }
                    editor?.selectAll(nil)
                }
            }
            .accessibilityIdentifier("tab-rename-field")
    }
}
