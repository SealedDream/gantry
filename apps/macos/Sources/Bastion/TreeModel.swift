import Foundation
import BastionCore

/// Persisted view state from the core (`ui-state.json` next to the library): expanded folders
/// and inspector visibility. `version` changes when expansion changes outside
/// the tree view (Expand All), so the outline re-applies it.
@MainActor @Observable
final class TreeStateModel {
    @ObservationIgnored private let store: TreeState
    private(set) var expanded: Set<String>
    private(set) var version = 0
    private(set) var inspectorVisible: Bool
    /// The library panel as the user left it (toggle, menu, shortcut); persisted.
    private(set) var libraryVisible: Bool
    /// Not persisted: a session view has keyboard focus, and the user showed the library while
    /// auto-hide had hidden it (cleared when focus moves).
    private(set) var sessionFocused = false
    private var shownOverAutoHide = false
    var error: String?

    init(dataDir: URL) {
        store = TreeState.open(path: dataDir.appendingPathComponent("ui-state.json").path)
        expanded = Set(store.expanded())
        inspectorVisible = store.inspectorVisible()
        libraryVisible = store.libraryVisible()
    }

    /// Whether the library panel shows now: the user's choice, unless the `tree.auto-hide`
    /// setting hides it while a session has focus.
    func libraryShown(autoHide: Bool) -> Bool { libraryShown(autoHide: autoHide, pinned: shownOverAutoHide) }

    private func libraryShown(autoHide: Bool, pinned: Bool) -> Bool {
        libraryVisible && !(autoHide && sessionFocused && !pinned)
    }

    /// Toggle from the bottom bar, menu or shortcut. While auto-hide has hidden the panel this
    /// shows it for now without changing the saved choice.
    func toggleLibrary(autoHide: Bool) {
        // The library stepped aside for an inspector shown while narrow: showing it again sends
        // the inspector back to its narrow-window state instead (only two columns fit).
        if libraryYieldsToInspector {
            if inspectorOverride == true { inspectorOverride = false } else { inspectorShownWhileNarrow = false }
            return
        }
        // Shown only because the user pinned it over auto-hide: hiding unpins, auto-hide takes over
        // again and the saved choice stays on (owner point 25).
        if shownOverAutoHide && libraryShown(autoHide: autoHide) && !libraryShown(autoHide: autoHide, pinned: false) {
            shownOverAutoHide = false
            return
        }
        if libraryShown(autoHide: autoHide) { return setLibraryVisible(false) }
        if !libraryVisible { setLibraryVisible(true) }
        shownOverAutoHide = !libraryShown(autoHide: autoHide)
    }

    func setLibraryVisible(_ on: Bool) {
        shownOverAutoHide = false
        libraryVisible = on
        // Off the main thread: the save fsyncs, and it ran in the first frame of every library
        // slide (OF-B profile). The core serializes saves under its own lock.
        let store = store
        Self.saveQueue.async { [weak self] in
            do { try store.setLibraryVisible(visible: on) } catch {
                let message = "Could not save the view state: \(error)"
                DispatchQueue.main.async { self?.error = message }
            }
        }
    }

    private static let saveQueue = DispatchQueue(label: "bastion.ui-state-save", qos: .utility)

    func setSessionFocused(_ on: Bool) {
        guard on != sessionFocused else { return }
        sessionFocused = on
        // Only when set: `libraryShown` reads it in the split view and the toolbar, and an equal
        // write re-ran them on every first tab (MAC-FIRST-SHELL).
        if shownOverAutoHide { shownOverAutoHide = false }
    }

    /// Not persisted: set when a session opens, cleared by selecting or clicking a connection
    /// (owner 2026-11-05: the inspector shows when you click a connection).
    var inspectorHiddenBySession = false

    /// A click on a connection row, even the selected one.
    func connectionClicked() { showInspectorAgain(); onConnectionClicked?() }
    /// Set by the main window: a connection row click opens that connection's page.
    @ObservationIgnored var onConnectionClicked: (() -> Void)?

    /// Clears `inspectorHiddenBySession` only when set: an equal write still invalidates every
    /// view that reads it (the whole window), once per click.
    func showInspectorAgain() { if inspectorHiddenBySession { inspectorHiddenBySession = false } }

    /// Not persisted: whether the inspector is on screen now, as a column or the full-screen overlay
    /// (set by ContentView; read by `toggleInspector` and the UI driver).
    var inspectorPresented = false

    /// Not persisted: Properties… or Test Connection opened the inspector over a closed saved choice.
    private(set) var inspectorRevealed = false

    /// Whether the inspector shows now: the one global saved choice, or a temporary reveal.
    var inspectorShown: Bool { inspectorVisible || inspectorRevealed }

    /// The saved choice (toolbar, ⌘⌥I, View menu). Clears any temporary reveal.
    func setInspectorVisible(_ on: Bool) {
        inspectorRevealed = false
        save { try store.setInspectorVisible(visible: on) }
        inspectorVisible = store.inspectorVisible()
    }

    /// Toggle what shows now: closing a temporary reveal leaves the saved choice (closed) alone.
    /// Not persisted: the window is too narrow for library + connection page + inspector, so the
    /// inspector auto-hides (coordinator 2026-11-07, OF-C 600 pt gap). Set by ContentView.
    var tooNarrowForInspector = false
    /// Not persisted: the user brought the inspector back while the window is too narrow.
    var inspectorShownWhileNarrow = false
    /// Hidden only by the window width right now (the toggle then brings it back, unsaved).
    var inspectorHiddenByWidth: Bool { tooNarrowForInspector && !inspectorShownWhileNarrow && inspectorShown }

    /// The inspector is on screen in a window too narrow for all three columns (the user brought
    /// it back with the toggle, or a per-view override shows it): the library column steps aside
    /// for it. The saved library choice is unchanged (MAC-INSPECTOR-FIT).
    var libraryYieldsToInspector: Bool { tooNarrowForInspector && inspectorPresented }

    func setTooNarrow(_ on: Bool) {
        guard on != tooNarrowForInspector else { return }
        tooNarrowForInspector = on
        if !on { inspectorShownWhileNarrow = false }
    }

    /// Not persisted: what the view would show without a click (ContentView sets it). A service
    /// or the bare start page never shows the inspector on its own (owner feedback 6, 8).
    var inspectorContextAllows = true
    /// Not persisted: the toggle's choice for the view on screen, where the context does not show
    /// the inspector by itself; cleared when the tab or page changes (owner point 30).
    var inspectorOverride: Bool?
    /// Not persisted: width the full-screen inspector overlay covers on the session area's trailing
    /// side (0 when it is a column). Set by ContentView, read by the connection page only.
    var inspectorOverlayInset: CGFloat = 0

    func toggleInspector() {
        // On a service or the start page the saved choice alone shows nothing: the click decides
        // for this view (point 30: the button looked dead with a session open).
        if !inspectorContextAllows || inspectorOverride != nil { inspectorOverride = !inspectorPresented; return }
        if inspectorHiddenByWidth { inspectorShownWhileNarrow = true; return }
        if tooNarrowForInspector && inspectorShownWhileNarrow { inspectorShownWhileNarrow = false; return }
        if inspectorRevealed && !inspectorVisible { inspectorRevealed = false; return }
        setInspectorVisible(!inspectorVisible)
    }

    /// Show the inspector for Properties… / Test Connection without changing the saved choice.
    func revealInspector() {
        if !inspectorVisible { inspectorRevealed = true }
    }

    /// Called by the outline when the user expands or collapses one folder.
    func setExpanded(_ id: String, _ on: Bool) {
        guard expanded.contains(id) != on else { return }
        save { try store.setExpanded(id: id, expanded: on) }
        expanded = Set(store.expanded())
    }

    /// `setExpanded` for several folders with one save.
    func setExpanded(_ ids: [String], _ on: Bool) {
        let changed = ids.filter { expanded.contains($0) != on }
        guard !changed.isEmpty else { return }
        save { try store.setExpandedMany(ids: changed, expanded: on) }
        expanded = Set(store.expanded())
    }

    /// Expand or collapse a folder and everything below it (`nil` = whole library).
    func setSubtree(_ id: String?, expanded on: Bool, library: Library?) {
        guard let library else { return }
        save { try store.setSubtreeExpanded(library: library, id: id, expanded: on) }
        expanded = Set(store.expanded())
        version += 1
    }

    /// Forget folders that were deleted.
    func prune(library: Library?) {
        guard let library else { return }
        save { try store.prune(library: library) }
        expanded = Set(store.expanded())
    }

    private func save(_ change: () throws -> Void) {
        do { try change() } catch { self.error = "Could not save the view state: \(error)" }
    }
}

/// One row of the navigation outline. A reference type because NSOutlineView tracks items by identity.
final class OutlineNode {
    enum Kind {
        case group(String)
        case folder(FolderView)
        case connection(ConnectionView)
        /// Application › Tasks.
        case tasks
        /// Application › Triggers: opens the Triggers page.
        case triggers
        case task(TaskView)
        /// Services, Processes or Event Log under an SSH connection (owner feedback 11).
        case tool(ConnectionTool, ConnectionView)
        /// An open tab, under its connection or under Other sessions (UI-05). Never saved.
        case session(SessionRow, parentName: String?)
        /// A row a dynamic folder's last Refresh produced (B15). Never saved.
        case generated(DynamicRow)
        /// A row of a plugin's tree under its entry (plugin API 1.3). Never saved.
        case pluginItem(PluginSidebarRow)
    }

    /// Mutable for session rows only: a title or state change updates the node in place, so the
    /// tree repaints one row instead of replacing it.
    var kind: Kind
    /// Row identity: the library id, `fav:<id>` for a Favorites entry, `group:<name>` for a section.
    let rowId: String
    /// Containing folder id; nil for top-level items and sections.
    let parentId: String?
    var children: [OutlineNode] = []

    init(kind: Kind, rowId: String, parentId: String?) {
        self.kind = kind
        self.rowId = rowId
        self.parentId = parentId
    }

    /// The library object this row stands for (nil for sections).
    var targetId: String? {
        switch kind {
        case .group: nil
        case .folder(let f): f.id
        case .connection(let c): c.id
        case .tasks, .triggers: nil
        case .task(let t): Self.taskPrefix + t.id
        // The connection it opens: selecting a tool row shows that connection's page.
        case .tool(_, let c): c.id
        // Commands that act on "the selected connection" act on the parent connection.
        case .session(let s, _): s.connectionId
        case .generated: nil
        // The entry the tree belongs to: "the selected connection" commands act on it.
        case .pluginItem(let r): r.entryId
        }
    }

    var isFolder: Bool { if case .folder = kind { true } else { false } }
    var isGroup: Bool { if case .group = kind { true } else { false } }
    var isFavoriteMirror: Bool { rowId.hasPrefix("fav:") }
    var isTasksFolder: Bool { if case .tasks = kind { true } else { false } }
    var isTriggers: Bool { if case .triggers = kind { true } else { false } }
    var task: TaskView? { if case .task(let t) = kind { t } else { nil } }
    var tool: (ConnectionTool, ConnectionView)? { if case .tool(let t, let c) = kind { (t, c) } else { nil } }
    var session: SessionRow? { if case .session(let s, _) = kind { s } else { nil } }
    var generated: DynamicRow? { if case .generated(let g) = kind { g } else { nil } }
    var pluginItem: PluginSidebarRow? { if case .pluginItem(let r) = kind { r } else { nil } }
    /// A generated sub-folder: always shown open.
    var isGeneratedGroup: Bool { generated.map { !$0.children.isEmpty } ?? false }
    var isLibraryConnection: Bool { if case .connection = kind { !isFavoriteMirror } else { false } }
    /// Session rows under this node (a library connection's children are only ever sessions).
    var sessionCount: Int { isLibraryConnection ? children.filter { $0.session != nil }.count : 0 }

    static let favoritesGroup = "group:favorites"
    static let libraryGroup = "group:library"
    static let applicationGroup = "group:application"
    static let sessionsGroup = "group:sessions"
    static let tasksFolder = "app:tasks"
    static let triggersRow = "app:triggers"
    /// Prefix of a task row's `targetId`, so it can never be mistaken for a library id.
    static let taskPrefix = "task:"

    /// Sections and rows for `tree`. With a filter, only matching connections and the folders
    /// leading to them remain (a folder whose name matches keeps all its contents).
    static func build(tree: FolderView, filter: String, tasks: [TaskView] = [], sessions: SessionRows = SessionRows(),
                      dynamic: DynamicRows = DynamicRows(), plugin: PluginSidebarRows = PluginSidebarRows()) -> [OutlineNode] {
        let library = OutlineNode(kind: .group("Library"), rowId: libraryGroup, parentId: nil)
        library.children = children(of: tree, parent: nil, filter: filter, sessions: sessions, dynamic: dynamic, plugin: plugin)
        let application = OutlineNode(kind: .group("Application"), rowId: applicationGroup, parentId: nil)
        let folder = OutlineNode(kind: .tasks, rowId: tasksFolder, parentId: nil)
        folder.children = tasks.filter { filter.isEmpty || $0.name.localizedCaseInsensitiveContains(filter) }
            .map { OutlineNode(kind: .task($0), rowId: taskPrefix + $0.id, parentId: tasksFolder) }
        let triggers = OutlineNode(kind: .triggers, rowId: triggersRow, parentId: nil)
        application.children = filter.isEmpty ? [folder, triggers] : [folder]
        var trailing = filter.isEmpty || !folder.children.isEmpty ? [application] : []
        if let other = otherSessions(sessions.other, filter: filter) { trailing.append(other) }
        var favorites: [ConnectionView] = []
        func collect(_ f: FolderView) {
            favorites += f.connections.filter { $0.favorite && matches($0, filter) }
            f.folders.forEach(collect)
        }
        collect(tree)
        guard !favorites.isEmpty else { return [library] + trailing }
        let group = OutlineNode(kind: .group("Favorites"), rowId: favoritesGroup, parentId: nil)
        group.children = favorites.map { OutlineNode(kind: .connection($0), rowId: "fav:\($0.id)", parentId: nil) }
        return [group, library] + trailing
    }

    /// One folder's row and the rows below it, unfiltered (the outline's patch after an edit).
    static func folderNode(_ folder: FolderView, parent: String?, sessions: SessionRows, dynamic: DynamicRows = DynamicRows(),
                           plugin: PluginSidebarRows = PluginSidebarRows()) -> OutlineNode {
        let node = OutlineNode(kind: .folder(folder), rowId: folder.id, parentId: parent)
        node.children = children(of: folder, parent: folder.id, filter: "", sessions: sessions, dynamic: dynamic, plugin: plugin)
        return node
    }

    private static func children(of folder: FolderView, parent: String?, filter: String, sessions: SessionRows,
                                 dynamic: DynamicRows = DynamicRows(), plugin: PluginSidebarRows = PluginSidebarRows()) -> [OutlineNode] {
        let folders: [OutlineNode] = folder.folders.compactMap { sub in
            let keepAll = !filter.isEmpty && sub.name.localizedCaseInsensitiveContains(filter)
            let node = OutlineNode(kind: .folder(sub), rowId: sub.id, parentId: parent)
            node.children = children(of: sub, parent: sub.id, filter: keepAll ? "" : filter, sessions: sessions, dynamic: dynamic, plugin: plugin)
            return filter.isEmpty || keepAll || !node.children.isEmpty ? node : nil
        }
        // Services / Processes / Event Log stay in the right-click menu and on the connection
        // page, not as child rows (owner point 24). Open sessions are the only children.
        let rows: [OutlineNode] = folder.connections.compactMap { c in
            let open = sessions.rows(for: c.id)
            // A matching connection shows all its sessions; a matching session shows with its parent.
            let shown = matches(c, filter) ? open : open.filter { $0.matches(filter) }
            guard matches(c, filter) || !shown.isEmpty else { return nil }
            let node = OutlineNode(kind: .connection(c), rowId: c.id, parentId: parent)
            node.children = sessionNodes(shown, parent: c)
            // A plugin entry with a tree (API 1.3): its rows after the sessions; hidden while a filter is on.
            if filter.isEmpty, plugin.types.contains(c.protocol) {
                node.children += pluginNodes(plugin.rows(for: c.id) ?? [PluginSidebarModel.placeholder(c.id)], parent: c.id)
            }
            return node
        }
        // A dynamic folder's generated rows follow its own; hidden while a filter is on.
        let generated = filter.isEmpty ? generatedNodes(dynamic.rows(for: folder.id), parent: folder.id) : []
        return folders + rows + generated
    }

    static func generatedNodes(_ rows: [DynamicRow], parent: String) -> [OutlineNode] {
        rows.map { r in
            let node = OutlineNode(kind: .generated(r), rowId: r.rowId, parentId: parent)
            node.children = generatedNodes(r.children, parent: r.rowId)
            return node
        }
    }

    static func pluginNodes(_ rows: [PluginSidebarRow], parent: String) -> [OutlineNode] {
        rows.map { r in
            let node = OutlineNode(kind: .pluginItem(r), rowId: r.rowId, parentId: parent)
            node.children = pluginNodes(r.children, parent: r.rowId)
            return node
        }
    }

    /// Session nodes under a library connection, in tab-strip order.
    static func sessionNodes(_ rows: [SessionRow], parent c: ConnectionView) -> [OutlineNode] {
        rows.map { OutlineNode(kind: .session($0, parentName: c.name), rowId: $0.rowId, parentId: c.id) }
    }

    /// The Other sessions section, only while it has rows.
    static func otherSessions(_ rows: [SessionRow], filter: String) -> OutlineNode? {
        let shown = rows.filter { $0.matches(filter) }
        guard !shown.isEmpty else { return nil }
        let group = OutlineNode(kind: .group("Other sessions"), rowId: sessionsGroup, parentId: nil)
        group.children = shown.map { OutlineNode(kind: .session($0, parentName: nil), rowId: $0.rowId, parentId: sessionsGroup) }
        return group
    }

    /// Whether the filter keeps any row: stops at the first hit instead of building the tree.
    static func anyMatch(in folder: FolderView, filter: String) -> Bool {
        let byTag = !FilterKeys.query(filter).tags.isEmpty
        return folder.connections.contains { matches($0, filter) }
            || folder.folders.contains { (!byTag && $0.name.localizedCaseInsensitiveContains(filter)) || anyMatch(in: $0, filter: filter) }
    }

    /// Free text matches name, address, user, group or a tag; each `tag:name` term must be a tag.
    static func matches(_ c: ConnectionView, _ filter: String) -> Bool {
        guard !filter.isEmpty else { return true }
        let q = FilterKeys.query(filter)
        guard q.admits(c.tags) else { return false }
        guard !q.text.isEmpty else { return true }
        if let hit = FilterKeys.matches(c, q.text) { return hit }
        return ([c.name, c.host, c.username ?? "", c.group ?? ""] + c.tags).contains { $0.localizedCaseInsensitiveContains(q.text) }
    }
}

extension FolderView {
    /// Connections anywhere below.
    var connectionCount: Int { connections.count + folders.reduce(0) { $0 + $1.connectionCount } }

    /// Whether `id` names a folder anywhere below this one.
    func containsFolder(_ id: String) -> Bool {
        folders.contains { $0.id == id || $0.containsFolder(id) }
    }
}

/// Lower-cased "name host user group tags" per connection, built once per tree version, so a filter
/// keystroke over 5,000 connections is a byte search each instead of four localized compares.
enum FilterKeys {
    nonisolated(unsafe) private static var version = -1
    nonisolated(unsafe) private static var keys: [String: [UInt8]] = [:]
    nonisolated(unsafe) private static var needle: (filter: String, bytes: [UInt8]) = ("", [])
    nonisolated(unsafe) private static var parsed: (filter: String, query: TagQuery) = ("", TagQuery(tags: [], text: ""))

    /// `filter` split into `tag:` terms and free text, parsed once per keystroke.
    static func query(_ filter: String) -> TagQuery {
        if parsed.filter != filter { parsed = (filter, TagQuery.parse(filter)) }
        return parsed.query
    }

    static func prepare(_ tree: FolderView?, version v: Int) {
        guard v != version else { return }
        version = v
        var k: [String: [UInt8]] = [:]
        func walk(_ f: FolderView) {
            for c in f.connections {
                k[c.id] = Array(([c.name, c.host, c.username ?? "", c.group ?? ""] + c.tags).joined(separator: "\u{0}").lowercased().utf8)
            }
            f.folders.forEach(walk)
        }
        tree.map(walk)
        keys = k
    }

    /// nil when `c` has no key (tree not prepared): the caller falls back to the slow compare.
    static func matches(_ c: ConnectionView, _ filter: String) -> Bool? {
        guard let key = keys[c.id] else { return nil }
        if needle.filter != filter { needle = (filter, Array(filter.lowercased().utf8)) }
        let n = needle.bytes
        guard !n.isEmpty, n.count <= key.count else { return n.isEmpty }
        return key.withUnsafeBytes { k in n.withUnsafeBytes { memmem(k.baseAddress, k.count, $0.baseAddress, $0.count) != nil } }
    }
}
