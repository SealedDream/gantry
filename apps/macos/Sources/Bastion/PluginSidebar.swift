import Foundation
import Combine
import BastionCore

/// One row of a plugin's tree under its entry in the library (plugin API 1.3). Never saved.
struct PluginSidebarRow: Equatable {
    struct MenuEntry: Equatable {
        let id: String
        let title: String
    }
    enum Kind: Equatable {
        /// An item from the plugin.
        case item(key: String, hasChildren: Bool, menu: [MenuEntry])
        /// "Loading…", or the plugin's or the app's words when the tree could not load.
        case status(String)
    }
    let rowId: String
    let entryId: String
    let label: String
    let kind: Kind
    var children: [PluginSidebarRow] = []

    var key: String? { if case .item(let k, _, _) = kind { k } else { nil } }
    var menu: [MenuEntry] { if case .item(_, _, let m) = kind { m } else { [] } }
    var expandable: Bool { if case .item(_, let h, _) = kind { h } else { false } }
    /// The double-click item: the plugin's menu item `open` (plugin API 1.3).
    var openItem: MenuEntry? { menu.first { $0.id == "open" } }
}

/// The rows by entry id, as the outline builds them, and the entries that have a tree.
struct PluginSidebarRows: Equatable {
    var byEntry: [String: [PluginSidebarRow]] = [:]
    /// Connection types with `sidebar = "tree"` (`<plugin id>/<type id>`).
    var types: Set<String> = []
    func rows(for entryId: String) -> [PluginSidebarRow]? { byEntry[entryId] }
}

/// The library-sidebar trees of plugin entries (plugin API 1.3, `docs/plans/PLUG-API-13.md`). A
/// session (a second helper on the entry) opens when the user expands the entry and stops when it
/// is collapsed. Expanding loads; nothing runs on start-up or on a timer. The plugin can show no
/// prompts there; a menu choice may raise the core's open sheet, shown by the library.
@MainActor @Observable
final class PluginSidebarModel {
    private(set) var rows = PluginSidebarRows()
    /// The open sheet a sidebar session asks for; the library presents it.
    private(set) var openRequestOwner: PluginViewModel?
    /// The Save as Connection sheet a sidebar session asks for (plugin API 1.6); the library presents it.
    private(set) var libraryRequestOwner: PluginViewModel?

    @ObservationIgnored private var sessions: [String: PluginViewModel] = [:]
    @ObservationIgnored private var watchers: [String: AnyCancellable] = [:]
    /// Expanded item keys per entry: their children are asked for and shown.
    @ObservationIgnored private var expanded: [String: Set<String>] = [:]
    @ObservationIgnored private var entryNames: [String: String] = [:]
    /// Whether an entry's session is open (it was expanded).
    func isOpen(_ entryId: String) -> Bool { sessions[entryId] != nil }
    nonisolated static let treeNode = 0
    nonisolated static let loading = "Loading…"

    /// The row an entry with a tree shows before it is expanded, so the outline draws a triangle.
    nonisolated static func placeholder(_ entryId: String, _ text: String = loading) -> PluginSidebarRow {
        PluginSidebarRow(rowId: "plg:\(entryId):status", entryId: entryId, label: text, kind: .status(text))
    }

    /// The user expanded the entry: open its sidebar session and ask for the top level.
    func expand(entry c: ConnectionView, type: PluginTypeView, library: Library, credentials: CredentialsModel?, sessions tabs: SessionsModel) {
        guard sessions[c.id] == nil else { return }
        entryNames[c.id] = c.name
        let via: PluginRoute
        switch PluginEntryRoute.plan(for: c, port: c.port ?? type.defaultPort ?? 0, library: library, running: tabs.runningTunnels) {
        case .route(let r): via = r
        case .gateway, .start:
            // A gateway or tunnel starts only from the entry's own Connect, never from an expand.
            return setRows(c.id, [Self.placeholder(c.id, "Connect the entry once to start its route")])
        }
        let model = PluginViewModel(pluginId: type.pluginId, entryId: c.id)
        sessions[c.id] = model
        expanded[c.id] = []
        watchers[c.id] = model.objectWillChange.sink { [weak self, weak model] _ in
            // objectWillChange fires before the change lands: rebuild on the next turn.
            DispatchQueue.main.async { if let self, let model { self.rebuild(c.id, model) } }
        }
        Task {
            if let credentials, credentials.vault == nil, LoginResolver.hasAssignment(c) || credentials.opensWithoutPrompt {
                await credentials.openInBackground(sessions: tabs)
            }
            await model.open(entry: c.id, library: library, vault: credentials?.vault, allowUnverified: type.tier == "Unverified", via: via, sidebar: true)
            model.askChildren(node: Self.treeNode, parent: nil)
        }
    }

    /// The user collapsed the entry: stop its session; the placeholder comes back.
    func collapse(entryId: String) {
        watchers[entryId] = nil
        if let m = sessions.removeValue(forKey: entryId) {
            if openRequestOwner === m { openRequestOwner = nil }
            if libraryRequestOwner === m { libraryRequestOwner = nil }
            m.close()
        }
        expanded[entryId] = nil
        if rows.byEntry[entryId] != nil { rows.byEntry[entryId] = nil }
    }

    func expand(row: PluginSidebarRow) {
        guard let key = row.key, let m = sessions[row.entryId], !(expanded[row.entryId]?.contains(key) ?? false) else { return }
        expanded[row.entryId, default: []].insert(key)
        if m.children[PluginViewModel.childKey(Self.treeNode, key)] == nil { m.askChildren(node: Self.treeNode, parent: key) }
        rebuild(row.entryId, m)
    }

    func isExpanded(_ row: PluginSidebarRow) -> Bool {
        guard let key = row.key else { return false }
        return expanded[row.entryId]?.contains(key) ?? false
    }

    func collapse(row: PluginSidebarRow) {
        guard let key = row.key else { return }
        expanded[row.entryId]?.remove(key)
    }

    /// A menu choice (right-click, or double-click `open`): sent to the plugin as a user action.
    func choose(_ item: PluginSidebarRow.MenuEntry, on row: PluginSidebarRow) {
        guard let key = row.key, let m = sessions[row.entryId] else { return }
        m.input(node: Self.treeNode, ["kind": "menu", "key": key, "item": item.id])
    }

    func answerOpen(accept: Bool, route: String, saveAsEntry: Bool) {
        guard let m = openRequestOwner, let r = m.openRequest else { return }
        openRequestOwner = nil
        m.answerOpen(r, accept: accept, route: route, saveAsEntry: saveAsEntry)
    }

    func answerLibrary(saved: Int?, credentialLinked: Bool) {
        guard let m = libraryRequestOwner, let r = m.libraryRequest else { return }
        libraryRequestOwner = nil
        m.answerLibrary(r, saved: saved, credentialLinked: credentialLinked)
    }

    /// Stops every session (library closed).
    func closeAll() { for id in Array(sessions.keys) { collapse(entryId: id) } }

    // MARK: rows

    private func setRows(_ entryId: String, _ list: [PluginSidebarRow]) {
        if rows.byEntry[entryId] != list { rows.byEntry[entryId] = list }
    }

    private func rebuild(_ entryId: String, _ m: PluginViewModel) {
        guard sessions[entryId] === m else { return }
        if m.openRequest != nil, openRequestOwner == nil { openRequestOwner = m }
        if m.libraryRequest != nil, libraryRequestOwner == nil { libraryRequestOwner = m }
        if let ended = m.ended { return setRows(entryId, [Self.placeholder(entryId, ended)]) }
        setRows(entryId, level(entryId, m, parent: nil))
    }

    private func level(_ entryId: String, _ m: PluginViewModel, parent: String?) -> [PluginSidebarRow] {
        let k = PluginViewModel.childKey(Self.treeNode, parent)
        if let refused = m.childRefusals[k] { return [Self.placeholder(entryId + ":" + (parent ?? ""), refused)].map { relabel($0, entryId) } }
        guard let items = m.children[k] else { return [relabel(Self.placeholder(entryId + ":" + (parent ?? "")), entryId)] }
        return items.compactMap { item in
            guard let key = item["key"] as? String else { return nil }
            let menu = ((item["menu"] as? [[String: Any]]) ?? []).compactMap { e in
                (e["id"] as? String).map { PluginSidebarRow.MenuEntry(id: $0, title: e["title"] as? String ?? $0) }
            }
            let hasChildren = item["has-children"] as? Bool ?? false
            var row = PluginSidebarRow(rowId: "plg:\(entryId):\(key)", entryId: entryId, label: item["label"] as? String ?? key,
                                       kind: .item(key: key, hasChildren: hasChildren, menu: menu))
            if hasChildren {
                // Unexpanded: one placeholder, so the triangle shows; expanded: the plugin's items.
                row.children = expanded[entryId]?.contains(key) ?? false
                    ? level(entryId, m, parent: key)
                    : [relabel(Self.placeholder(entryId + ":" + key), entryId)]
            }
            return row
        }
    }

    /// A status row under an item keeps the entry it belongs to.
    private func relabel(_ r: PluginSidebarRow, _ entryId: String) -> PluginSidebarRow {
        PluginSidebarRow(rowId: r.rowId, entryId: entryId, label: r.label, kind: r.kind)
    }
}
