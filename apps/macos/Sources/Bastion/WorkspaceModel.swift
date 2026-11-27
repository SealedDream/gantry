import Foundation
import BastionCore

/// Saved workspaces (`workspaces.json` next to the library, via the core). Saving records the
/// open library tabs and their split panes; opening reconnects each through its normal connect
/// sheet, so credentials are asked for again and nothing secret is stored.
@MainActor @Observable
final class WorkspaceModel {
    private(set) var items: [WorkspaceView] = []
    /// The workspace last opened or saved in this run.
    private(set) var currentId: String?
    var error: String?
    private let store: WorkspaceStore?

    static var path: URL { LibraryModel.dataDir.appendingPathComponent("workspaces.json") }

    init() {
        do {
            store = try WorkspaceStore.open(path: Self.path.path)
        } catch {
            store = nil
            self.error = "Saved workspaces could not be read and are not being saved: \(error.userMessage)"
        }
        reload()
    }

    var current: WorkspaceView? { items.first { $0.id == currentId } }

    /// What Save Current Layout would record: library tabs only. Local shells and Quick Connect
    /// tabs have no saved connection to reopen, so they are counted as skipped.
    func snapshot(sessions: SessionsModel, model: LibraryModel) -> (tabs: [WorkspaceTabView], groups: [String?], selected: UInt32, skipped: Int) {
        let saved = sessions.tabs.filter { tab in tab.mode.isRestorable && tab.connectionId.flatMap(model.connection(id:)) != nil }
        let tabs = saved.map { tab in
            WorkspaceTabView(connectionId: tab.connectionId ?? "", mode: tab.mode.rawValue, layout: tab.layoutSteps)
        }
        let selected = saved.firstIndex { $0.id == sessions.selected } ?? 0
        return (tabs, saved.map(\.group), UInt32(selected), sessions.tabs.count - saved.count)
    }

    @discardableResult
    func saveCurrent(name: String, sessions: SessionsModel, model: LibraryModel) -> Bool {
        let s = snapshot(sessions: sessions, model: model)
        let groups = String(decoding: (try? JSONEncoder().encode(sessions.groups)) ?? Data("[]".utf8), as: UTF8.self)
        return change { store in
            currentId = try store.saveGroupedLayout(name: name, tabs: s.tabs, tabGroups: s.groups, groupsJson: groups, selected: s.selected).id
        }
    }

    /// Add to Workspace: append a terminal tab for one saved connection.
    @discardableResult
    func add(connectionId: String, to id: String) -> Bool {
        change { _ = try $0.addTab(id: id, tab: WorkspaceTabView(connectionId: connectionId, mode: ConnectMode.terminal.rawValue, layout: [])) }
    }

    /// A new workspace holding one connection's terminal tab; the core refuses a name already
    /// used, in any case (Save Current Layout is the only way to replace one).
    @discardableResult
    func create(name: String, connectionId: String) -> Bool {
        let tab = WorkspaceTabView(connectionId: connectionId, mode: ConnectMode.terminal.rawValue, layout: [])
        return change { _ = try $0.create(name: name.trimmingCharacters(in: .whitespacesAndNewlines), tabs: [tab]) }
    }

    @discardableResult
    func rename(_ id: String, to name: String) -> Bool {
        change { try $0.rename(id: id, name: name) }
    }

    @discardableResult
    func duplicate(_ id: String) -> String? {
        var copy: String?
        change { copy = try $0.duplicate(id: id).id }
        return copy
    }

    func remove(_ id: String) {
        change { try $0.remove(id: id) }
        if currentId == id { currentId = nil }
    }

    /// Reconnect every tab the core's restore plan keeps (connection still in the library, not
    /// already open in the same mode), one sheet at a time, then select the saved tab.
    func open(_ id: String, commands: Commands) {
        guard let store, let ws = items.first(where: { $0.id == id }) else { return }
        let sessions = commands.sessions
        let existing = ws.tabs.map(\.connectionId).filter { commands.model.connection(id: $0) != nil }
        let live = sessions.tabs.compactMap { t -> WorkspaceTabView? in
            guard !t.ended, t.mode.isRestorable, let c = t.connectionId else { return nil }
            return WorkspaceTabView(connectionId: c, mode: t.mode.rawValue, layout: [])
        }
        let plan: WorkspaceRestorePlan
        do { plan = try store.restorePlan(id: id, existing: existing, open: live) } catch {
            self.error = error.userMessage
            return
        }
        let requests = plan.open.compactMap { tab -> ConnectRequest? in
            guard let c = commands.model.connection(id: tab.connectionId) else { return nil }
            return ConnectRequest(connection: c, mode: ConnectMode(rawValue: tab.mode) ?? .terminal, layout: tab.layout)
        }
        change { try $0.markUsed(id: id) }
        currentId = id
        sessions.expectGroups(ws)
        commands.enqueue(requests, select: plan.select.map { ($0.connectionId, ConnectMode(rawValue: $0.mode) ?? .terminal) })
        if plan.missing > 0 {
            error = plan.missing == 1 ? "1 tab was not opened: its connection was deleted." : "\(plan.missing) tabs were not opened: their connections were deleted."
        }
    }

    /// Run a store change and refresh; a rejected change keeps the list and says why.
    @discardableResult
    private func change(_ body: (WorkspaceStore) throws -> Void) -> Bool {
        guard let store else { return false }
        do {
            try body(store)
            reload()
            return true
        } catch {
            self.error = error.userMessage
            reload()
            return false
        }
    }

    private func reload() {
        items = store?.list() ?? []
    }
}

extension WorkspaceView {
    var lastUsedText: String {
        guard let t = lastUsed else { return "Never" }
        return Date(timeIntervalSince1970: TimeInterval(t)).formatted(.relative(presentation: .named))
    }
}

extension WorkspaceView: Identifiable {}
