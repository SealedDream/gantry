import AppKit
import SwiftUI
import BastionCore

/// The navigation tree: a native NSOutlineView (source-list style) so expansion, arrow-key
/// navigation, type-select, multi-selection, drag-and-drop between rows and context menus behave
/// like every other Mac app. Data comes from the core; every change goes back through it.
struct LibraryOutline: NSViewRepresentable {
    let tree: FolderView?
    /// `LibraryModel.treeVersion`: compared instead of the tree (a deep compare of 5,000 rows per update).
    let treeVersion: Int
    var tasks: [TaskView] = []
    let filter: String
    let sessions: SessionSnapshot
    /// Open tabs as rows under their connections (UI-05); applied by diff, never a reload.
    var sessionRows = SessionRows()
    /// Rows the last Refresh of each dynamic folder produced (B15); a change rebuilds the outline.
    var dynamic = DynamicRows()
    /// Plugin trees under their entries (plugin API 1.3); a change rebuilds the outline.
    var plugin = PluginSidebarRows()
    let expansionVersion: Int
    let rowHeight: CGFloat
    let iconSize: CGFloat
    let indent: CGFloat
    /// The user's accent: AppKit draws a selection in the system accent, which SwiftUI's
    /// `.tint` does not reach, so the rows draw it themselves (`AccentRowView`).
    let accent: NSColor
    /// Not a binding: the tree follows the selection through `LibrarySelection.changed`, so a
    /// selection change does not re-run the sidebar's SwiftUI update (MAC-SELECT-SPEED).
    let sel: LibrarySelection
    let commands: Commands

    func makeCoordinator() -> Coordinator { Coordinator(commands: commands) }

    func makeNSView(context: Context) -> NSScrollView {
        let outline = KeyOutlineView()
        let column = NSTableColumn(identifier: .init("name"))
        column.resizingMask = .autoresizingMask
        outline.addTableColumn(column)
        outline.outlineTableColumn = column
        outline.headerView = nil
        // The column already fills the sidebar; re-measuring it on every expand made a filter
        // over 5,000 connections (one expand per folder) cost tens of milliseconds.
        outline.autoresizesOutlineColumn = false
        outline.style = .sourceList
        // Selection is drawn by `AccentRowView` in the user's accent; the source list's own
        // highlight (a system material in the system accent) would cover it.
        outline.selectionHighlightStyle = .none
        outline.allowsMultipleSelection = true
        outline.floatsGroupRows = false
        outline.dataSource = context.coordinator
        outline.delegate = context.coordinator
        outline.target = context.coordinator
        outline.doubleAction = #selector(Coordinator.doubleClicked)
        // A click anywhere on a section header (Favorites, Library) shows or hides it, so AppKit's
        // small Show/Hide button is not the only target.
        outline.action = #selector(Coordinator.clicked)
        outline.registerForDraggedTypes([.bastionNode, .string])
        outline.setDraggingSourceOperationMask(.move, forLocal: true)
        outline.draggingDestinationFeedbackStyle = .sourceList
        outline.coordinator = context.coordinator
        outline.setAccessibilityLabel("Connections")
        let menu = NSMenu()
        menu.delegate = context.coordinator
        outline.menu = menu
        context.coordinator.outline = outline

        let scroll = NSScrollView()
        scroll.documentView = outline
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        let c = context.coordinator
        c.commands = commands
        c.attach(sel)
        guard let outline = c.outline else { return }
        c.iconSize = iconSize
        outline.indentationPerLevel = indent
        if c.accent != accent {
            c.accent = accent
            outline.enumerateAvailableRowViews { row, _ in
                (row as? AccentRowView)?.accent = accent
            }
        }
        if treeVersion != c.treeVersion || tasks != c.tasks || filter != c.filter || expansionVersion != c.expansionVersion || rowHeight != outline.rowHeight
            || dynamic != c.dynamic || plugin != c.plugin {
            // Only the filter changed: patch the outline in place, so the visible row views are kept
            // instead of rebuilt (reloadData purges them all).
            // A library edit (add, rename, delete, move) patches too: a full reload rebuilt every
            // row view, 20–50 ms per edit at 5,000 connections (2026-11-15). `reload` falls back to
            // a full reload when rows change order.
            let filterOnly = rowHeight == outline.rowHeight && c.treeVersion >= 0
            c.tree = tree
            c.treeVersion = treeVersion
            c.tasks = tasks
            c.filter = filter
            c.expansionVersion = expansionVersion
            outline.rowHeight = rowHeight
            c.sessionRows = sessionRows
            c.dynamic = dynamic
            c.plugin = plugin
            if !c.patchRows(version: treeVersion) { c.reload(diff: filterOnly) }
        } else if sessionRows != c.sessionRows {
            c.applySessions(sessionRows)
        }
        if sessions != c.sessions {
            c.sessions = sessions
            c.refreshVisibleRows()
        }
        if let id = commands.renaming {
            commands.renaming = nil
            let inserted = commands.insertedFolder == id
            commands.insertedFolder = nil
            DispatchQueue.main.async { c.beginRename(id, fadeIn: inserted) }
        }
    }

    @MainActor
    final class Coordinator: NSObject, NSOutlineViewDataSource, NSOutlineViewDelegate, NSMenuDelegate, NSTextFieldDelegate {
        var accent: NSColor = .controlAccentColor
        var commands: Commands
        weak var outline: NSOutlineView?
        private weak var sel: LibrarySelection?
        nonisolated(unsafe) private var selObserver: NSObjectProtocol?

        /// Follows `sel`: a selection made elsewhere (palette, dashboard, UI driver) selects and reveals its row.
        func attach(_ new: LibrarySelection) {
            guard sel !== new else { return }
            if let selObserver { NotificationCenter.default.removeObserver(selObserver) }
            sel = new
            selObserver = NotificationCenter.default.addObserver(forName: LibrarySelection.changed, object: new, queue: nil) { [weak self] _ in
                MainActor.assumeIsolated { guard let self else { return }; self.select(self.sel?.current) }
            }
            select(new.current)
        }

        deinit { if let selObserver { NotificationCenter.default.removeObserver(selObserver) } }

        /// Writes the user's choice; `isConnection` is worked out here, as the window's setter did.
        private func choose(_ id: String?) {
            guard let sel, sel.current != id else { return }
            sel.set(id, isConnection: id.flatMap { commands.model.connection(id: $0) } != nil)
        }
        var tree: FolderView?
        var treeVersion = -1
        var lastBuildMs = 0.0
        var lastExpandMs = 0.0
        var lastDataMs = 0.0
        var tasks: [TaskView] = []
        /// The connection a task row runs against: the last connection selected in the tree.
        var lastConnectionId: String?
        var filter = ""
        var sessions = SessionSnapshot(connected: [], connecting: [], failed: [])
        var expansionVersion = -1
        var iconSize: CGFloat = 14
        var sessionRows = SessionRows()
        var dynamic = DynamicRows()
        var plugin = PluginSidebarRows()
        /// Library connections the user collapsed while they had sessions. Not saved; forgotten
        /// when the last session closes (design: "its expanded/collapsed choice is forgotten").
        private var collapsedConnections: Set<String> = []
        /// Library connection rows by id (no Favorites mirrors), rebuilt with the tree.
        private var connectionNodes: [String: OutlineNode] = [:]
        /// Full `reloadData` passes so far, and the last session diff's time (UI driver, A8).
        private(set) var fullReloads = 0
        private(set) var lastSessionMs = 0.0
        private var roots: [OutlineNode] = []
        /// True while expansion or selection is applied programmatically, so it is not written back as user intent.
        private var restoring = false
        private var renamingId: String? { didSet { AutoDock.shared.renaming = renamingId != nil } }

        init(commands: Commands) { self.commands = commands }

        // MARK: Data

        func reload(diff: Bool = false) {
            guard let outline else { return }
            defer { if spareCells.count < Self.spareCellCount { queueSpareRefill() } }
            let selected = sel?.current
            // A Favorites row the user picked stays picked across the rebuild (not its Library twin).
            // So does a session row (its target is its connection, which would win otherwise).
            let selectedMirror = (outline.item(atRow: outline.selectedRow) as? OutlineNode).flatMap { $0.isFavoriteMirror || $0.session != nil ? $0.rowId : nil }
            let tb = CFAbsoluteTimeGetCurrent()
            if !filter.isEmpty { FilterKeys.prepare(tree, version: treeVersion) }
            let built = tree.map { OutlineNode.build(tree: $0, filter: filter, tasks: tasks, sessions: sessionRows, dynamic: dynamic, plugin: plugin) } ?? []
            lastBuildMs = (CFAbsoluteTimeGetCurrent() - tb) * 1000
            restoring = true
            // Folders whose content is the same as last time are skipped whole by the patch (a
            // library edit changes one branch); only when the rows are built from the same
            // filter, sessions and tasks, which also shape a folder's rows.
            let canSkip = filter == builtFilter && sessionRows == builtSessions && tasks == builtTasks && dynamic == builtDynamic && plugin == builtPlugin
            builtFilter = filter; builtSessions = sessionRows; builtTasks = tasks; builtDynamic = dynamic; builtPlugin = plugin
            if diff, Self.sameOrder(old: roots, new: built, canSkip: canSkip) {
                outline.beginUpdates()
                changedRows = []
                skipUnchanged = canSkip
                roots = merge(parent: nil, old: roots, new: built)
                // Same expansion as a rebuild: sections open, then every folder with a filter or
                // the saved state without one. Rows already expanded cost nothing here.
                if filter.isEmpty {
                    for root in roots { outline.expandItem(root) }
                    applyExpansion(roots)
                } else {
                    outline.expandItem(nil, expandChildren: true)
                }
                expandSessionParents(roots)
                outline.endUpdates()
                refreshRowViews(changedRows)
                changedRows = []
                restoring = false
                indexConnections()
                lastDataMs = (CFAbsoluteTimeGetCurrent() - tb) * 1000 - lastBuildMs
                lastExpandMs = 0
                restoreSelection(selected, mirror: selectedMirror)
                return
            }
            roots = built
            fullReloads += 1
            outline.reloadData()
            lastDataMs = (CFAbsoluteTimeGetCurrent() - tb) * 1000 - lastBuildMs
            // One update pass for all expands: without it every expandItem rebuilds the visible
            // row views that reloadData just purged (most of the filter time in the nm-21 profile).
            outline.beginUpdates()
            if filter.isEmpty {
                for root in roots { outline.expandItem(root) }
                applyExpansion(roots)
            } else {
                // A filter shows every match: one recursive expand is linear, a call per folder is quadratic.
                outline.expandItem(nil, expandChildren: true)
            }
            expandSessionParents(roots)
            outline.endUpdates()
            restoring = false
            indexConnections()
            lastExpandMs = (CFAbsoluteTimeGetCurrent() - tb) * 1000 - lastBuildMs
            restoreSelection(selected, mirror: selectedMirror)
        }

        private func restoreSelection(_ selected: String?, mirror selectedMirror: String?) {
            guard let outline else { return }
            if let m = selectedMirror, let node = node(withRowId: m), node.targetId == selected, case let row = outline.row(forItem: node), row >= 0 {
                restoring = true
                outline.selectRowIndexes([row], byExtendingSelection: false)
                restoring = false
            } else {
                select(selected, force: true)
            }
        }

        /// Turns `old` (the children `parent` shows now) into `new` with remove/insert calls, keeping
        /// the node objects (so the row views) of rows in both. A filter result keeps tree order, so
        /// rows in both lists are in the same relative order. Expansion is left to the caller.
        /// Returns the children `parent` now has.
        private func merge(parent: OutlineNode?, old: [OutlineNode], new: [OutlineNode]) -> [OutlineNode] {
            guard let outline else { return new }
            let oldById = Dictionary(old.map { ($0.rowId, $0) }, uniquingKeysWith: { a, _ in a })
            let newIds = Set(new.map(\.rowId))
            let removed = IndexSet(old.indices.filter { !newIds.contains(old[$0].rowId) })
            let kept = old.filter { newIds.contains($0.rowId) }
            let result = new.map { oldById[$0.rowId] ?? $0 }
            let inserted = IndexSet(result.indices.filter { oldById[result[$0].rowId] == nil })
            if !removed.isEmpty {
                setChildren(parent, kept)
                outline.removeItems(at: removed, inParent: parent, withAnimation: [])
            }
            if !inserted.isEmpty {
                setChildren(parent, result)
                outline.insertItems(at: inserted, inParent: parent, withAnimation: [])
            }
            setChildren(parent, result)
            for (node, fresh) in zip(result, new) where node !== fresh {
                // Same folder content: its row and every row below it are unchanged.
                if skipUnchanged, Self.sameFolder(node, fresh) { continue }
                // A kept row takes the fresh content (a new name, count or colour); changed rows on
                // screen are redrawn after the patch.
                if !Self.sameContent(node.kind, fresh.kind) { changedRows.append(node) }
                node.kind = fresh.kind
                node.children = merge(parent: node, old: node.children, new: fresh.children)
            }
            return result
        }

        /// The patch's state: rows whose content changed, and whether unchanged folders are skipped.
        private var changedRows: [OutlineNode] = []
        private var skipUnchanged = false
        /// What the current rows were built from.
        private var builtFilter = ""
        private var builtSessions = SessionRows()
        private var builtTasks: [TaskView] = []
        private var builtDynamic = DynamicRows()
        private var builtPlugin = PluginSidebarRows()

        /// Both rows are the same folder with the same content (folders, connections, names).
        static func sameFolder(_ a: OutlineNode, _ b: OutlineNode) -> Bool {
            guard case let .folder(x) = a.kind, case let .folder(y) = b.kind else { return false }
            return a.children.count == b.children.count && x == y
        }

        /// Whether a row would draw the same.
        static func sameContent(_ a: OutlineNode.Kind, _ b: OutlineNode.Kind) -> Bool {
            switch (a, b) {
            case let (.folder(x), .folder(y)): return x == y
            case let (.connection(x), .connection(y)): return x == y
            case let (.group(x), .group(y)): return x == y
            case (.tasks, .tasks): return true
            case let (.task(x), .task(y)): return x == y
            case let (.generated(x), .generated(y)): return x == y
            case let (.pluginItem(x), .pluginItem(y)): return x == y
            default: return false
            }
        }

        /// True when every list keeps the rows it shares with `new` in the same relative order, so
        /// `merge` can patch it; a sort or a drag reorders rows and needs a full reload.
        static func sameOrder(old: [OutlineNode], new: [OutlineNode], canSkip: Bool = false) -> Bool {
            let newIds = Set(new.map(\.rowId))
            let oldIds = Set(old.map(\.rowId))
            let keptOld = old.filter { newIds.contains($0.rowId) }
            let keptNew = new.filter { oldIds.contains($0.rowId) }
            guard keptOld.map(\.rowId) == keptNew.map(\.rowId) else { return false }
            for (a, b) in zip(keptOld, keptNew) {
                if canSkip, sameFolder(a, b) { continue }
                if !sameOrder(old: a.children, new: b.children, canSkip: canSkip) { return false }
            }
            return true
        }

        /// After a library edit that `LibraryModel.patch` made (New Folder, rename, delete, move of
        /// folders): rebuilds only the edited folders' parent rows, reusing every other row, without
        /// building the whole outline (~10 ms at 5,000 connections) or walking it. False when this
        /// update is anything else; the caller then reloads.
        func patchRows(version: Int) -> Bool {
            guard let outline, let tree, filter.isEmpty, filter == builtFilter, sessionRows == builtSessions, tasks == builtTasks,
                  dynamic.byFolder.isEmpty, builtDynamic.byFolder.isEmpty, plugin == builtPlugin,
                  let patch = commands.model.lastPatch, patch.version == version,
                  let library = roots.first(where: { $0.rowId == OutlineNode.libraryGroup }) else { return false }
            // Parents to rebuild: where each node was and where it is now (a move has both).
            var parents: [String] = []
            for id in patch.ids {
                if let old = node(withRowId: id) {
                    guard old.isFolder, !Self.hasFavorite(old) else { return false }
                    parents.append(old.parentId ?? tree.id)
                }
                guard let now = Self.parentPath(of: id, in: tree) else { continue }
                guard now.isFolder else { return false }
                if let f = now.folder, Self.anyFavorite(f) { return false }
                parents.append(now.path.last?.id ?? tree.id)
            }
            outline.beginUpdates()
            changedRows = []
            skipUnchanged = true
            for parentId in Set(parents) {
                guard let path = parentId == tree.id ? [tree] : Self.folderPath(to: parentId, in: tree).map({ [tree] + $0 }),
                      let folder = path.last else { outline.endUpdates(); return false }
                let parentNode = parentId == tree.id ? library : node(withRowId: parentId)
                guard let parentNode else { outline.endUpdates(); return false }
                // Ancestors (and the parent) show new counts.
                for f in path.dropFirst() {
                    if let n = node(withRowId: f.id) { n.kind = .folder(f); changedRows.append(n) }
                }
                let existing = Dictionary(parentNode.children.map { ($0.rowId, $0) }, uniquingKeysWith: { a, _ in a })
                let edited = Set(patch.ids)
                var fresh: [OutlineNode] = []
                for sub in folder.folders {
                    if !edited.contains(sub.id), let kept = existing[sub.id] { fresh.append(kept) }
                    else { fresh.append(OutlineNode.folderNode(sub, parent: parentId == tree.id ? nil : parentId, sessions: sessionRows, plugin: plugin)) }
                }
                for c in folder.connections {
                    guard let kept = existing[c.id] else { outline.endUpdates(); return false }
                    fresh.append(kept)
                }
                guard Self.sameOrder(old: parentNode.children, new: fresh) else { outline.endUpdates(); return false }
                parentNode.children = merge(parent: parentNode, old: parentNode.children, new: fresh)
                applyExpansion(parentNode.children)
            }
            outline.endUpdates()
            refreshRowViews(changedRows)
            changedRows = []
            restoreSelection(sel?.current, mirror: nil)
            return true
        }

        /// The folders from the root's children down to `id` (inclusive), or nil.
        static func folderPath(to id: String, in f: FolderView) -> [FolderView]? {
            for sub in f.folders {
                if sub.id == id { return [sub] }
                if let rest = folderPath(to: id, in: sub) { return [sub] + rest }
            }
            return nil
        }

        /// Where node `id` sits: the folders above it (below the root) and the node if it is a folder.
        static func parentPath(of id: String, in f: FolderView, above: [FolderView] = []) -> (path: [FolderView], folder: FolderView?, isFolder: Bool)? {
            if let sub = f.folders.first(where: { $0.id == id }) { return (above, sub, true) }
            if f.connections.contains(where: { $0.id == id }) { return (above, nil, false) }
            for sub in f.folders { if let hit = parentPath(of: id, in: sub, above: above + [sub]) { return hit } }
            return nil
        }

        static func anyFavorite(_ f: FolderView) -> Bool {
            f.connections.contains(where: \.favorite) || f.folders.contains(where: anyFavorite)
        }

        static func hasFavorite(_ n: OutlineNode) -> Bool {
            if case let .folder(f) = n.kind { return anyFavorite(f) }
            return false
        }

        /// Redraws the given rows where they are on screen (no rows added or removed).
        private func refreshRowViews(_ nodes: [OutlineNode]) {
            guard let outline, !nodes.isEmpty else { return }
            let visible = outline.rows(in: outline.visibleRect)
            let rows = IndexSet(nodes.map { outline.row(forItem: $0) }.filter { NSLocationInRange($0, visible) })
            guard !rows.isEmpty else { return }
            outline.reloadData(forRowIndexes: rows, columnIndexes: [0])
        }

        /// Redraws the row views on screen from their nodes (no rows added or removed).
        private func refreshVisibleRowViews() {
            guard let outline else { return }
            let visible = outline.rows(in: outline.visibleRect)
            guard visible.length > 0 else { return }
            outline.reloadData(forRowIndexes: IndexSet(integersIn: visible.location..<NSMaxRange(visible)), columnIndexes: [0])
        }

        private func setChildren(_ parent: OutlineNode?, _ children: [OutlineNode]) {
            if let parent { parent.children = children } else { roots = children }
        }

        private func applyExpansion(_ nodes: [OutlineNode]) {
            guard let outline else { return }
            for n in nodes {
                if n.isGroup || n.isGeneratedGroup || !filter.isEmpty || commands.tree.expanded.contains(n.rowId) {
                    if n.isFolder || n.isTasksFolder || n.isGeneratedGroup { outline.expandItem(n) }
                    applyExpansion(n.children)
                } else if n.isFolder {
                    outline.collapseItem(n)
                }
            }
        }

        /// Session state changed: reconfigure the visible rows only, no reload.
        func refreshVisibleRows() {
            guard let outline else { return }
            let range = outline.rows(in: outline.visibleRect)
            for row in range.location..<(range.location + range.length) {
                guard let node = outline.item(atRow: row) as? OutlineNode,
                      let cell = outline.view(atColumn: 0, row: row, makeIfNecessary: false) as? OutlineCell else { continue }
                configure(cell, node)
            }
        }

        private func state(of node: OutlineNode) -> SessionStateLabel? {
            guard node.session == nil else { return nil }
            return node.targetId.flatMap { SessionStateLabel.of($0, in: sessions) }
        }

        /// Sessions hidden under a collapsed connection row (shown as its count).
        private func collapsedSessions(_ node: OutlineNode) -> Int {
            guard let outline, node.sessionCount > 0, !outline.isItemExpanded(node) else { return 0 }
            return node.sessionCount
        }

        private func configure(_ cell: OutlineCell, _ node: OutlineNode) {
            cell.configure(node, state: state(of: node), iconSize: iconSize, collapsedSessions: collapsedSessions(node),
                           connectedInside: connectedInside(node))
        }

        /// UI-01: connected items inside a collapsed folder (shown with its count).
        private func connectedInside(_ node: OutlineNode) -> Int {
            guard let outline, case .folder(let f) = node.kind, !outline.isItemExpanded(node), !sessions.connected.isEmpty else { return 0 }
            let connected = Set(sessions.connected)
            func count(_ f: FolderView) -> Int {
                f.connections.filter { connected.contains($0.id) }.count + f.folders.reduce(0) { $0 + count($1) }
            }
            return count(f)
        }

        /// Repaint one row in place, if it is on screen.
        private func reconfigure(_ node: OutlineNode) {
            guard let outline, case let row = outline.row(forItem: node), row >= 0,
                  let cell = outline.view(atColumn: 0, row: row, makeIfNecessary: false) as? OutlineCell else { return }
            configure(cell, node)
        }

        // MARK: Sessions (UI-05)

        private func indexConnections() {
            var index: [String: OutlineNode] = [:]
            func walk(_ nodes: [OutlineNode]) {
                for n in nodes {
                    if n.isLibraryConnection { index[n.rowId] = n } else { walk(n.children) }
                }
            }
            walk(roots)
            connectionNodes = index
        }

        /// Connections with sessions open expanded unless the user collapsed them.
        private func expandSessionParents(_ nodes: [OutlineNode]) {
            guard let outline else { return }
            for n in nodes {
                if n.isLibraryConnection {
                    // Sessions open the row; a plugin tree only when the user opened it (never on its own).
                    let pluginOpen = commands.pluginSidebar.isOpen(n.rowId)
                    if (n.sessionCount > 0 || pluginOpen) && !collapsedConnections.contains(n.rowId) { outline.expandItem(n) }
                    if pluginOpen { expandPluginRows(n.children) }
                } else {
                    expandSessionParents(n.children)
                }
            }
        }

        /// Plugin rows the user expanded stay expanded across a rebuild.
        private func expandPluginRows(_ nodes: [OutlineNode]) {
            guard let outline else { return }
            for n in nodes {
                guard let r = n.pluginItem, commands.pluginSidebar.isExpanded(r) else { continue }
                outline.expandItem(n)
                expandPluginRows(n.children)
            }
        }

        /// The tab list changed: insert, remove or repaint only the session rows that changed.
        func applySessions(_ new: SessionRows) {
            guard let outline else { return }
            let old = sessionRows
            sessionRows = new
            // A search keeps parents of matching sessions only: the filtered tree decides that.
            guard filter.isEmpty else { return reload(diff: true) }
            let t0 = CFAbsoluteTimeGetCurrent()
            restoring = true
            outline.beginUpdates()
            for id in Set(old.byConnection.keys).union(new.byConnection.keys) where old.rows(for: id) != new.rows(for: id) {
                guard let node = connectionNodes[id], case .connection(let c) = node.kind else { continue }
                var fresh = OutlineNode.sessionNodes(new.rows(for: id), parent: c)
                if plugin.types.contains(c.protocol) {
                    fresh += OutlineNode.pluginNodes(plugin.rows(for: c.id) ?? [PluginSidebarModel.placeholder(c.id)], parent: c.id)
                }
                sync(node, fresh: fresh)
            }
            if old.other != new.other { syncOther(new.other) }
            outline.endUpdates()
            restoring = false
            announceFailures(old: old, new: new)
            lastSessionMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        }

        /// Make `parent`'s session children `fresh`, keeping the row of every tab still open.
        private func sync(_ parent: OutlineNode, fresh: [OutlineNode]) {
            guard let outline else { return }
            let wasEmpty = parent.children.isEmpty
            let keptOrder = parent.children.map(\.rowId).filter(Set(fresh.map(\.rowId)).contains)
            let merged = merge(parent: parent, old: parent.children, new: fresh)
            // The rows merge changed, redrawn here: nothing else empties the list on this path, and
            // it kept every session row of every closed tab (MAC-MEMORY soak, +4.6 KB per tab).
            let changed = changedRows
            changedRows = []
            changed.forEach(reconfigure)
            if keptOrder != merged.map(\.rowId).filter(Set(keptOrder).contains) {
                // Tabs were reordered: this one parent's rows only.
                outline.reloadItem(parent, reloadChildren: true)
            }
            for (node, f) in zip(merged, fresh) where node !== f && node.session != f.session {
                node.kind = f.kind
                reconfigure(node)
            }
            guard parent.isLibraryConnection else { return }
            if wasEmpty != merged.isEmpty {
                // The disclosure arrow comes or goes with the first or last session.
                outline.reloadItem(parent, reloadChildren: false)
                if merged.isEmpty { collapsedConnections.remove(parent.rowId) } else { outline.expandItem(parent) }
            }
            reconfigure(parent)
        }

        private func syncOther(_ rows: [SessionRow]) {
            guard let outline else { return }
            let existing = roots.first { $0.rowId == OutlineNode.sessionsGroup }
            guard let group = OutlineNode.otherSessions(rows, filter: "") else {
                if let existing, let i = roots.firstIndex(where: { $0 === existing }) {
                    roots.remove(at: i)
                    outline.removeItems(at: [i], inParent: nil, withAnimation: [])
                }
                return
            }
            guard let existing else {
                roots.append(group)
                outline.insertItems(at: [roots.count - 1], inParent: nil, withAnimation: [])
                outline.expandItem(group)
                return
            }
            sync(existing, fresh: group.children)
        }

        /// Only ended or failed is announced, once, without moving focus.
        private func announceFailures(old: SessionRows, new: SessionRows) {
            let before = Dictionary((old.byConnection.values.joined() + old.other).map { ($0.tabId, $0.state) }, uniquingKeysWith: { a, _ in a })
            for row in new.byConnection.values.joined() + new.other where row.state == .ended && before[row.tabId].map({ $0 != .ended }) ?? false {
                NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested,
                                     userInfo: [.announcement: "\(row.title) failed", .priority: NSAccessibilityPriorityLevel.high.rawValue])
            }
        }

        func focusSession(_ row: SessionRow) { commands.sessions.focus(tabId: row.tabId) }

        func node(withRowId id: String, in nodes: [OutlineNode]? = nil) -> OutlineNode? {
            for n in nodes ?? roots {
                if n.rowId == id { return n }
                if let hit = node(withRowId: id, in: n.children) { return hit }
            }
            return nil
        }

        func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
            (item as? OutlineNode)?.children.count ?? roots.count
        }

        func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
            (item as? OutlineNode)?.children[index] ?? roots[index]
        }

        func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
            guard let n = item as? OutlineNode else { return false }
            // An empty folder has no disclosure triangle (it can still take drops).
            return n.isGroup || n.isTasksFolder || ((n.isFolder || !n.isFavoriteMirror) && !n.children.isEmpty)
        }

        func outlineView(_ outlineView: NSOutlineView, isGroupItem item: Any) -> Bool {
            (item as? OutlineNode)?.isGroup ?? false
        }

        func outlineView(_ outlineView: NSOutlineView, shouldSelectItem item: Any) -> Bool {
            !((item as? OutlineNode)?.isGroup ?? true)
        }

        func outlineView(_ outlineView: NSOutlineView, rowViewForItem item: Any) -> NSTableRowView? {
            // From AppKit's reuse queue when it has one: a filter keystroke replaces most visible rows.
            let row = outlineView.makeView(withIdentifier: AccentRowView.identifier, owner: nil) as? AccentRowView ?? AccentRowView()
            row.accent = accent
            return row
        }

        /// Cells made ahead, between keystrokes. A filter pass removes and adds its visible rows in one
        /// update, so AppKit's reuse queue is still empty when the new rows ask for cells, and making
        /// each cell was the largest part of `endUpdates` in the A3-P1 profile.
        private var spareCells: [OutlineCell] = []
        private var refillQueued = false
        private static let spareCellCount = 48

        private func takeCell(_ outlineView: NSOutlineView) -> OutlineCell {
            if let reused = outlineView.makeView(withIdentifier: OutlineCell.identifier, owner: nil) as? OutlineCell { return reused }
            queueSpareRefill()
            return spareCells.popLast() ?? OutlineCell()
        }

        private func queueSpareRefill() {
            guard !refillQueued else { return }
            refillQueued = true
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                refillQueued = false
                while spareCells.count < Self.spareCellCount { spareCells.append(OutlineCell()) }
            }
        }

        func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
            guard let node = item as? OutlineNode else { return nil }
            let cell = takeCell(outlineView)
            configure(cell, node)
            cell.textField?.delegate = self
            return cell
        }

        // MARK: Expansion

        func outlineViewItemDidExpand(_ notification: Notification) { persist(notification, expanded: true) }
        func outlineViewItemDidCollapse(_ notification: Notification) { persist(notification, expanded: false) }

        /// Folders expanded or collapsed this runloop turn, saved together: an Option-click
        /// sends one notification per folder in the subtree, and each save writes the state file.
        private var pendingExpansion: [(id: String, expanded: Bool)] = []

        private func persist(_ notification: Notification, expanded: Bool) {
            if let node = notification.userInfo?["NSObject"] as? OutlineNode, let r = node.pluginItem {
                expanded ? commands.pluginSidebar.expand(row: r) : commands.pluginSidebar.collapse(row: r)
                return
            }
            if let node = notification.userInfo?["NSObject"] as? OutlineNode, node.isLibraryConnection, !restoring,
               case .connection(let c) = node.kind, plugin.types.contains(c.protocol) {
                // Expanding a plugin entry with a tree opens its sidebar session; collapsing stops it.
                if expanded { commands.openPluginSidebar(c) } else { commands.pluginSidebar.collapse(entryId: c.id) }
            }
            if let node = notification.userInfo?["NSObject"] as? OutlineNode, node.isLibraryConnection {
                // The count shows only while collapsed. A user's collapse is kept until the last session closes.
                if !restoring, filter.isEmpty {
                    if expanded { collapsedConnections.remove(node.rowId) } else { collapsedConnections.insert(node.rowId) }
                }
                reconfigure(node)
                return
            }
            if let node = notification.userInfo?["NSObject"] as? OutlineNode, node.isFolder { reconfigure(node) }
            guard !restoring, filter.isEmpty, let node = notification.userInfo?["NSObject"] as? OutlineNode, node.isFolder else { return }
            if pendingExpansion.isEmpty {
                DispatchQueue.main.async { [weak self] in self?.flushExpansion() }
            }
            pendingExpansion.append((node.rowId, expanded))
        }

        private func flushExpansion() {
            let changes = pendingExpansion
            pendingExpansion = []
            // Last change per folder wins; then one save per direction.
            let last = Dictionary(changes.map { ($0.id, $0.expanded) }, uniquingKeysWith: { _, new in new })
            for on in [true, false] {
                commands.tree.setExpanded(last.filter { $0.value == on }.map(\.key), on)
            }
        }

        // MARK: Selection

        func outlineViewSelectionDidChange(_ notification: Notification) {
            guard let outline, !restoring else { return }
            let picked = outline.item(atRow: outline.selectedRow) as? OutlineNode
            if picked?.isTriggers == true {
                // A page, not a selection: clear it so a second click opens the page again.
                commands.panel = .triggers
                outline.deselectAll(nil)
                return
            }
            let id = picked?.targetId
            if let id, commands.model.connection(id: id) != nil { lastConnectionId = id }
            choose(id)
        }

        /// Select the Library row for `id` (not a Favorites mirror), expanding its folders to reveal it.
        func select(_ id: String?, force: Bool = false) {
            guard let outline else { return }
            let current = (outline.item(atRow: outline.selectedRow) as? OutlineNode)?.targetId
            guard force || current != id else { return }
            guard let id, let node = node(withRowId: id) else {
                if id == nil, outline.selectedRow >= 0 { outline.deselectAll(nil) }
                return
            }
            var chain: [OutlineNode] = []
            var parent = node.parentId
            while let p = parent, let n = self.node(withRowId: p) {
                chain.insert(n, at: 0)
                parent = n.parentId
            }
            chain.forEach { outline.expandItem($0) }
            let row = outline.row(forItem: node)
            guard row >= 0 else { return }
            restoring = true
            outline.selectRowIndexes([row], byExtendingSelection: false)
            restoring = false
            outline.scrollRowToVisible(row)
        }

        // MARK: Mouse and keyboard

        @objc func clicked() {
            guard let outline = outline, outline.clickedRow >= 0,
                  let n = outline.item(atRow: outline.clickedRow) as? OutlineNode else { return }
            // A click on a connection, even the selected one, shows the inspector a session hid.
            if let s = n.session { return focusSession(s) }
            guard n.isGroup else { commands.tree.connectionClicked(); return }
            if outline.isItemExpanded(n) { outline.animator().collapseItem(n) } else { outline.animator().expandItem(n) }
        }

        @objc func doubleClicked() {
            guard let outline, outline.clickedRow >= 0, let node = outline.item(atRow: outline.clickedRow) as? OutlineNode else { return }
            activate(node)
        }

        /// Return and double-click: folders toggle, connections run their default action.
        func activate(_ node: OutlineNode) {
            guard let outline else { return }
            if node.isFolder {
                let expand = !outline.isItemExpanded(node)
                expand ? outline.expandItem(node) : outline.collapseItem(node)
                // NSOutlineView sends no expand/collapse notification for an empty folder; save it here too.
                if filter.isEmpty { commands.tree.setExpanded(node.rowId, expand) }
            } else if node.isTriggers {
                commands.panel = .triggers
            } else if let s = node.session {
                focusSession(s)
            } else if let (tool, c) = node.tool {
                commands.openTool(tool, on: c)
            } else if let r = node.pluginItem {
                // Double-click: the plugin's `open` item (plugin API 1.3); else the row toggles.
                if let item = r.openItem {
                    commands.pluginSidebar.choose(item, on: r)
                } else if r.expandable {
                    outline.isItemExpanded(node) ? outline.collapseItem(node) : outline.expandItem(node)
                }
            } else if let g = node.generated {
                if node.isGeneratedGroup {
                    outline.isItemExpanded(node) ? outline.collapseItem(node) : outline.expandItem(node)
                } else if let address = g.address {
                    commands.dynamic.quickConnect?(address)
                }
            } else if let task = node.task {
                commands.runTask(task, on: lastConnectionId)
            } else if let id = node.targetId {
                commands.performDefault(on: id)
            }
        }

        func activateSelection() {
            guard let outline, let node = outline.item(atRow: outline.selectedRow) as? OutlineNode else { return }
            activate(node)
        }

        /// ⌘⌫: the registry's Delete for the selected row, with its confirmation.
        func deleteSelection() {
            // A session row's target is its connection: ⌘⌫ must never delete that from here.
            if let outline, (outline.item(atRow: outline.selectedRow) as? OutlineNode)?.session != nil { return QuietLaunch.beep() }
            guard let outline, let id = (outline.item(atRow: outline.selectedRow) as? OutlineNode)?.targetId,
                  let item = commands.menu(for: id).first(where: { $0.id == "delete" }) else { return QuietLaunch.beep() }
            commands.perform(item, on: id)
        }

        // MARK: Context menu

        func menuNeedsUpdate(_ menu: NSMenu) {
            guard let outline = outline as? KeyOutlineView else { return }
            let row = outline.menuRow
            let node = row >= 0 ? outline.item(atRow: row) as? OutlineNode : nil
            if node?.rowId == OutlineNode.favoritesGroup || node?.rowId == OutlineNode.applicationGroup
                || node?.rowId == OutlineNode.sessionsGroup { return menu.removeAllItems() }
            if let s = node?.session {
                menu.removeAllItems()
                menu.addItem(ClosureMenuItem(title: "Go to Tab") { [weak self] in self?.focusSession(s) })
                menu.addItem(ClosureMenuItem(title: "Close Tab") { [commands] in commands.sessions.close(tabId: s.tabId) })
                if let id = s.connectionId {
                    menu.addItem(.separator())
                    menu.addItem(ClosureMenuItem(title: "Reveal Connection") { [weak self] in self?.revealConnection(id) })
                }
                return
            }
            if let r = node?.pluginItem {
                menu.removeAllItems()
                for item in r.menu {
                    menu.addItem(ClosureMenuItem(title: item.title) { [commands] in commands.pluginSidebar.choose(item, on: r) })
                }
                return
            }
            if let g = node?.generated {
                menu.removeAllItems()
                guard let address = g.address else { return }
                menu.addItem(ClosureMenuItem(title: "Quick Connect…") { [commands] in commands.dynamic.quickConnect?(address) })
                menu.addItem(ClosureMenuItem(title: "Copy Address") { [commands] in
                    commands.pasteboard.clearContents()
                    commands.pasteboard.setString(address, forType: .string)
                })
                return
            }
            if let (tool, c) = node?.tool {
                menu.removeAllItems()
                menu.addItem(ClosureMenuItem(title: "Open \(tool.label)") { [commands] in commands.openTool(tool, on: c) })
                return
            }
            if let node, node.isTasksFolder || node.task != nil {
                return TaskMenus.fillTaskMenu(menu, task: node.task, connectionId: lastConnectionId, commands: commands)
            }
            // The Library header and empty space act on the library root.
            let target = node?.targetId
            ActionMenuBuilder.fill(menu, items: commands.menu(for: target), submenu: { [commands] in commands.submenu(for: $0, on: target) }) { [weak self] item in
                self?.commands.perform(item, on: target)
            }
            if let target, commands.model.folder(id: target) != nil {
                menu.addItem(.separator())
                menu.addItem(ClosureMenuItem(title: "Attached Tasks…") { [commands] in commands.taskHooks = ParentTarget(id: target) })
                if let f = commands.model.folder(id: target) { commands.dynamic.appendMenu(menu, folderId: target, folderName: f.name) }
            }
            appendBulkEdit(menu, outline: outline, target: target)
            appendTaskScope(menu, outline: outline, target: target)
            if let target, commands.model.connection(id: target) != nil {
                TaskMenus.appendConnectionItems(menu, connectionId: target, commands: commands)
                if let c = commands.model.connection(id: target), ConnectionTool.applies(to: c) {
                    menu.addItem(.separator())
                    for tool in ConnectionTool.allCases {
                        menu.addItem(ClosureMenuItem(title: "Open \(tool.label)") { [commands] in commands.openTool(tool, on: c) })
                    }
                }
                // Wake-on-LAN: only for hosts with a MAC address set (core `wol_plan`).
                if let c = commands.model.connection(id: target), (try? commands.model.library?.wolPlan(id: target)) != nil {
                    menu.addItem(.separator())
                    menu.addItem(ClosureMenuItem(title: "Wake") { [commands] in commands.wake(c) })
                }
            }
        }

        /// Selected connection ids, in row order (folders and other rows left out).
        func selectedConnectionIds(_ outline: NSOutlineView) -> [String] {
            outline.selectedRowIndexes.compactMap { row in
                guard let id = (outline.item(atRow: row) as? OutlineNode)?.targetId, commands.model.connection(id: id) != nil else { return nil }
                return id
            }
        }

        /// "Edit N Connections…" when the menu's row is one of two or more selected connections (B3-BULK-EDIT).
        /// "Run Task ›" on a folder (every host in it) or on a selection of two or more connections.
        private func appendTaskScope(_ menu: NSMenu, outline: NSOutlineView, target: String?) {
            guard let target else { return }
            let ids = selectedConnectionIds(outline)
            let preset: TaskRunOnChoice
            if commands.model.folder(id: target) != nil {
                preset = TaskRunOnChoice(folderId: target)
            } else if ids.count >= 2, ids.contains(target) {
                preset = TaskRunOnChoice(hostIds: Array(ids))
            } else { return }
            TaskMenus.appendScopeItems(menu, preset: preset, commands: commands)
        }

        private func appendBulkEdit(_ menu: NSMenu, outline: NSOutlineView, target: String?) {
            let ids = selectedConnectionIds(outline)
            guard ids.count >= 2, let target, ids.contains(target), let window = outline.window else { return }
            menu.addItem(.separator())
            menu.addItem(ClosureMenuItem(title: "Edit \(ids.count) Connections…") { [commands] in
                BulkEdit.present(ids: ids, model: commands.model, on: window)
            })
        }

        /// Select the session row's library connection.
        func revealConnection(_ id: String) {
            guard let outline, let node = connectionNodes[id] else { return }
            select(id, force: true)
            let row = outline.row(forItem: node)
            if row >= 0 { outline.selectRowIndexes([row], byExtendingSelection: false) }
        }

        /// ⌘W with a session row selected in the focused tree: close that tab.
        func closeSelectedSession() -> Bool {
            guard let outline, let s = (outline.item(atRow: outline.selectedRow) as? OutlineNode)?.session else { return false }
            commands.sessions.close(tabId: s.tabId)
            return true
        }

        /// Left / Right on a session row or a connection with sessions; false leaves the key to AppKit.
        func sessionArrow(left: Bool) -> Bool {
            guard let outline, let n = outline.item(atRow: outline.selectedRow) as? OutlineNode else { return false }
            if n.session != nil, left, let parent = outline.parent(forItem: n) {
                let row = outline.row(forItem: parent)
                guard row >= 0 else { return false }
                outline.selectRowIndexes([row], byExtendingSelection: false)
                outline.scrollRowToVisible(row)
                return true
            }
            guard n.sessionCount > 0 else { return false }
            if left == outline.isItemExpanded(n) { left ? outline.collapseItem(n) : outline.expandItem(n) }
            return true
        }

        var selectedIsSession: Bool {
            guard let outline else { return false }
            return (outline.item(atRow: outline.selectedRow) as? OutlineNode)?.session != nil
        }

        // MARK: Rename

        /// Row fade-in for a new folder (Reduce Motion: none).
        static let insertFade = 0.18

        func beginRename(_ id: String, fadeIn: Bool = false) {
            guard let outline, let node = node(withRowId: id) else { return }
            select(id, force: true)
            let row = outline.row(forItem: node)
            guard row >= 0, let cell = outline.view(atColumn: 0, row: row, makeIfNecessary: true) as? OutlineCell else { return }
            if fadeIn, !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion,
               let rowView = outline.rowView(atRow: row, makeIfNecessary: false) {
                rowView.alphaValue = 0
                NSAnimationContext.runAnimationGroup { $0.duration = Self.insertFade; rowView.animator().alphaValue = 1 }
            }
            renamingId = id
            cell.beginRename(in: outline.window)
        }

        func controlTextDidEndEditing(_ obj: Notification) {
            guard let field = obj.object as? NSTextField, let id = renamingId else { return }
            renamingId = nil
            field.isEditable = false
            let name = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if name.isEmpty { reload() } else { commands.model.patch { try $0.rename(id: id, name: name); return [id] } }
            outline?.window?.makeFirstResponder(outline)
        }

        /// Escape cancels the rename and restores the old name.
        func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
            guard selector == #selector(NSResponder.cancelOperation(_:)), let id = renamingId else { return false }
            renamingId = nil
            (control as? NSTextField)?.abortEditing()
            (control as? NSTextField)?.isEditable = false
            // Only the edited row shows the old name again (redrawing every visible row cost the
            // first New Folder's Escape a gap over 50 ms).
            if let node = node(withRowId: id) { refreshRowViews([node]) } else { refreshVisibleRowViews() }
            outline?.window?.makeFirstResponder(outline)
            return true
        }

        // MARK: Drag and drop

        func outlineView(_ outlineView: NSOutlineView, pasteboardWriterForItem item: Any) -> NSPasteboardWriting? {
            guard let node = item as? OutlineNode, !node.isGroup, !node.isFavoriteMirror, !node.isTasksFolder, node.task == nil, node.tool == nil, node.session == nil, let id = node.targetId else { return nil }
            let p = NSPasteboardItem()
            p.setString(id, forType: .bastionNode)
            return p
        }

        private func draggedIds(_ info: NSDraggingInfo) -> [String] {
            info.draggingPasteboard.pasteboardItems?.compactMap { $0.string(forType: .bastionNode) } ?? []
        }

        /// The folder a drop lands in (`.some(nil)` = library root), or `nil` when the item is no drop zone.
        private func dropFolder(_ item: OutlineNode?) -> String?? {
            guard let item else { return nil }
            switch item.kind {
            case .group: return item.rowId == OutlineNode.libraryGroup ? .some(nil) : nil
            case .folder(let f): return .some(f.id)
            case .connection, .tasks, .triggers, .task, .tool, .session, .generated, .pluginItem: return nil
            }
        }

        /// A credential row dragged from the Credentials section (its id as text): only an id the
        /// open vault knows counts, so text dragged from elsewhere is ignored.
        private func draggedCredential(_ info: NSDraggingInfo) -> String? {
            guard draggedIds(info).isEmpty, let id = info.draggingPasteboard.string(forType: .string),
                  let item = commands.credentials?.tree.first(where: { $0.id == id }), !item.isFolder else { return nil }
            return id
        }

        /// The folder or connection a dropped credential is assigned to.
        private func credentialTarget(_ item: OutlineNode?) -> String? {
            guard let item, !item.isFavoriteMirror else { return nil }
            switch item.kind {
            case .folder, .connection: return item.targetId
            case .group, .tasks, .triggers, .task, .tool, .session, .generated, .pluginItem: return nil
            }
        }

        func outlineView(_ outlineView: NSOutlineView, validateDrop info: NSDraggingInfo, proposedItem item: Any?,
                         proposedChildIndex index: Int) -> NSDragOperation {
            if draggedCredential(info) != nil {
                // Always onto the row itself: a credential is assigned to it, never placed between rows.
                guard credentialTarget(item as? OutlineNode) != nil else { return [] }
                if index != NSOutlineViewDropOnItemIndex { outlineView.setDropItem(item, dropChildIndex: NSOutlineViewDropOnItemIndex) }
                return .link
            }
            var target = item as? OutlineNode
            var index = index
            // Dropping onto a connection means "just before it": retarget to its folder.
            if let t = target, case .connection = t.kind, !t.isFavoriteMirror {
                let parent = t.parentId.flatMap { node(withRowId: $0) } ?? node(withRowId: OutlineNode.libraryGroup)
                index = parent?.children.firstIndex { $0 === t } ?? -1
                target = parent
                outlineView.setDropItem(target, dropChildIndex: index)
            }
            guard let folder = dropFolder(target) else { return [] }
            let ids = draggedIds(info)
            guard !ids.isEmpty else { return [] }
            // A folder can never go into itself or one of its descendants.
            for id in ids {
                if let f = commands.model.folder(id: id), id == folder || (folder.map(f.containsFolder) ?? false) { return [] }
            }
            // Folders are listed before connections: keep the insertion point inside the moved kind's block.
            if index >= 0, let children = target?.children {
                let folderCount = children.prefix { $0.isFolder }.count
                let movingFolders = ids.contains { commands.model.folder(id: $0) != nil }
                let clamped = movingFolders ? min(index, folderCount) : max(index, folderCount)
                if clamped != index { outlineView.setDropItem(target, dropChildIndex: clamped) }
            }
            return .move
        }

        // A drag from the docked library keeps it in until the drop ends.
        func outlineView(_ outlineView: NSOutlineView, draggingSession session: NSDraggingSession, willBeginAt screenPoint: NSPoint, forItems draggedItems: [Any]) {
            AutoDock.shared.dragging = true
        }

        func outlineView(_ outlineView: NSOutlineView, draggingSession session: NSDraggingSession, endedAt screenPoint: NSPoint, operation: NSDragOperation) {
            AutoDock.shared.dragging = false
        }

        func outlineView(_ outlineView: NSOutlineView, acceptDrop info: NSDraggingInfo, item: Any?, childIndex index: Int) -> Bool {
            if let credential = draggedCredential(info) {
                guard let node = credentialTarget(item as? OutlineNode), let credentials = commands.credentials else { return false }
                let model = commands.model
                // After the drop has ended: a folder asks first, and an alert must not run inside the drag.
                DispatchQueue.main.async {
                    if let folder = model.folder(id: node) {
                        let name = credentials.items.first { $0.id == credential }?.name ?? "this credential"
                        guard LoginResolver.confirmFolderLogin(credential: name, folder: folder.name) else { return }
                    }
                    // The folder's or connection's credential, as the Credentials page sets it.
                    LoginResolver.change(node, model: model, credentials: credentials) { vault, library in
                        try vault.assignCredential(library: library, nodeId: node, credentialId: credential)
                    }
                }
                return true
            }
            let target = item as? OutlineNode
            guard let folder = dropFolder(target) else { return false }
            let ids = draggedIds(info)
            // The first row at or after the drop position that is not itself being moved.
            let before = index >= 0 ? (target?.children ?? []).dropFirst(index).first { !ids.contains($0.rowId) }?.targetId : nil
            commands.model.patch(colours: true) { lib in
                for id in ids { try lib.moveNodeBefore(id: id, parent: folder, before: before) }
                return ids
            }
            if let folder { commands.tree.setExpanded(folder, true) }
            if let first = ids.first { choose(first) }
            return true
        }
    }
}

extension NSPasteboard.PasteboardType {
    static let bastionNode = NSPasteboard.PasteboardType("dev.bastion.node")
}

/// NSOutlineView already gives arrows, ←/→ to collapse and expand (⌥ for all descendants) and
/// type-select. On top: Return opens (folders toggle) and ⌘⌫ deletes, as in Finder.
final class KeyOutlineView: NSOutlineView {
    weak var coordinator: LibraryOutline.Coordinator?
    /// Row the last context menu was opened on (-1 = empty space).
    private(set) var menuRow = -1
    private var claimedLaunchFocus = false

    /// The library has the keyboard when its window opens, as in the Classic header: the Compact
    /// header's "Search or connect" field came first in the key loop and took it, so ↓ and Return
    /// at launch went to the field (HEADER-A regression; p1-web). ⌥⌘F still focuses the field.
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        guard !claimedLaunchFocus, let window else { return }
        claimedLaunchFocus = true
        DispatchQueue.main.async { [weak self, weak window] in
            guard let self, let window, self.window === window else { return }
            let current = window.firstResponder
            if current == nil || current === window || current is NSTextView { window.makeFirstResponder(self) }
        }
    }

    override func keyDown(with event: NSEvent) {
        switch (event.keyCode, event.modifierFlags.intersection([.command, .shift, .option, .control])) {
        case (36, []), (76, []): coordinator?.activateSelection()
        case (51, .command): coordinator?.deleteSelection()
        // UI-05 keyboard: Left on a session row goes to its connection; Left / Right collapse or
        // expand a connection that has sessions.
        case (123, []) where coordinator?.sessionArrow(left: true) == true: break
        case (124, []) where coordinator?.sessionArrow(left: false) == true: break
        // Space on a session row focuses its tab, like Return.
        case (49, []) where coordinator?.selectedIsSession == true: coordinator?.activateSelection()
        default: super.keyDown(with: event)
        }
    }

    /// ⌘W with a session row selected here closes that tab (the menu's ⌘W would close the
    /// selected tab instead).
    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        if window?.firstResponder === self, event.keyCode == 13,
           event.modifierFlags.intersection([.command, .shift, .option, .control]) == .command,
           coordinator?.closeSelectedSession() == true { return true }
        return super.performKeyEquivalent(with: event)
    }

    /// Right-click selects the clicked row first, like Finder, so the menu and inspector agree.
    override func menu(for event: NSEvent) -> NSMenu? {
        let row = self.row(at: convert(event.locationInWindow, from: nil))
        menuRow = row
        if row >= 0, !selectedRowIndexes.contains(row), (item(atRow: row) as? OutlineNode)?.isGroup == false {
            selectRowIndexes([row], byExtendingSelection: false)
        }
        return super.menu(for: event)
    }
}

/// A source-list row whose selection is the user's accent: solid while the tree has focus in the
/// key window, the system's unemphasized fill otherwise (as AppKit does). A source list draws
/// its selection with a system material that ignores any colour, so the outline turns that off
/// and the row fills its own background, keeping the emphasized interior style for legible text.
final class AccentRowView: NSTableRowView {
    static let identifier = NSUserInterfaceItemIdentifier("AccentRowView")

    override init(frame: NSRect) {
        super.init(frame: frame)
        identifier = Self.identifier
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    var accent: NSColor = .controlAccentColor {
        didSet { if isSelected { needsDisplay = true } }
    }

    override var isSelected: Bool {
        didSet { if isSelected != oldValue { needsDisplay = true; applyTextStyle() } }
    }

    override var isEmphasized: Bool {
        didSet { if isEmphasized != oldValue { needsDisplay = true; applyTextStyle() } }
    }

    override func didAddSubview(_ subview: NSView) {
        super.didAddSubview(subview)
        applyTextStyle()
    }

    /// The outline's highlight style is `.none`, so AppKit leaves the cells on `.normal` and a
    /// selected name stayed black on the accent fill in light mode (about 4.5:1, MAC-UI-02). The cells
    /// take the row's style themselves: emphasized turns label colours white, as on a system selection.
    private func applyTextStyle() {
        let style = interiorBackgroundStyle
        for case let cell as NSTableCellView in subviews where cell.backgroundStyle != style { cell.backgroundStyle = style }
    }

    override var interiorBackgroundStyle: NSView.BackgroundStyle {
        isSelected && isEmphasized ? .emphasized : .normal
    }

    /// The accent darkened as far as the emphasized (white) text needs for WCAG AA: raw cyan, emerald,
    /// amber and rose were under 4.5:1 (owner 2026-11-15). `SelectionContrast` has the rule.
    static func readableFill(_ accent: NSColor) -> NSColor {
        guard let c = accent.usingColorSpace(.sRGB) else { return accent }
        let f = SelectionContrast.readableFill(for: .init(r: c.redComponent, g: c.greenComponent, b: c.blueComponent))
        return NSColor(srgbRed: f.r, green: f.g, blue: f.b, alpha: 1)
    }

    override func drawBackground(in dirtyRect: NSRect) {
        super.drawBackground(in: dirtyRect)
        guard isSelected else { return }
        (isEmphasized ? Self.readableFill(accent) : NSColor.unemphasizedSelectedContentBackgroundColor).setFill()
        NSBezierPath(roundedRect: bounds.insetBy(dx: DS.Size.selectionInset, dy: 0), xRadius: DS.Size.selectionRadius, yRadius: DS.Size.selectionRadius).fill()
    }
}
