import SwiftUI
import BastionCore

/// One table row of the folder dashboard (DASH-01): the core's `OverviewRowView` plus what only
/// the app knows (live status, port). Never holds a secret: the core returns login state and the
/// name of where it comes from only.
struct DashboardRow: Identifiable, Equatable {
    let id: String
    let isFolder: Bool
    let name: String
    let address: String
    let proto: String?
    let type: String
    let status: String
    let user: String
    let login: String
    let lastConnected: String
    let lastConnectedAt: UInt64
    let lastResult: String
    let folder: String
    let tags: String
    let port: String
    let hostColor: String?
    /// Name, address, type, protocol, user and tags, lowercased once for the filter, as the tree's
    /// `FilterKeys` keeps its rows: a byte search, not six locale-aware compares per row per key.
    var key: [UInt8] = []
    /// The name as a sort key, made once: lowercased, each run of digits zero-padded so "c2" comes
    /// before "c10" (as Finder orders names). A byte compare per pair, not a locale-aware compare.
    var nameKey: [UInt8] = []

    /// Login column words (packet DASH-01): where a login comes from, never what it is.
    static func loginText(_ state: String, from: String?) -> String {
        switch state {
        case "saved": "Saved"
        case "inherited": "From \(from ?? "folder")"
        case "offered": "Offered from \(from ?? "another connection")"
        default: "None"
        }
    }

    /// "Connected", "Reconnecting" or empty, from the connection's tabs.
    @MainActor static func status(_ tabs: [TerminalTab]) -> String {
        guard let live = tabs.first(where: { !$0.ended && !$0.isWaiting }) else { return "" }
        return live.panes.contains { $0.linkStatus != nil } ? "Reconnecting" : "Connected"
    }

    /// Filter: the tree filter's matching for connections, plus address, user and tags.
    /// The tree's own byte keys first (its `FilterKeys`), then this row's key, which also holds the
    /// group: no locale-aware compare per row (the tree's fallback for rows it has no key for).
    /// `tag:name` terms must all be tags of the row (folders never match them).
    @MainActor func matches(_ needle: [UInt8], filter: String, connection: ConnectionView?) -> Bool {
        guard !needle.isEmpty else { return true }
        let q = FilterKeys.query(filter)
        if !q.tags.isEmpty {
            guard let connection, q.admits(connection.tags) else { return false }
            return q.text.isEmpty || matches(Array(q.text.lowercased().utf8), filter: q.text, connection: connection)
        }
        if let connection, FilterKeys.matches(connection, filter) == true { return true }
        guard needle.count <= key.count else { return false }
        return key.withUnsafeBytes { k in needle.withUnsafeBytes { memmem(k.baseAddress, k.count, $0.baseAddress, $0.count) != nil } }
    }

    func keyed(group: String? = nil) -> DashboardRow {
        var r = self
        r.key = Array([name, address, type, proto ?? "", user, tags, group ?? ""].joined(separator: "\u{1}").lowercased().utf8)
        r.nameKey = Self.sortKey(name)
        return r
    }

    private static let digitWidth = 10

    static func sortKey(_ text: String) -> [UInt8] {
        let folded = text.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
        var out: [UInt8] = []
        out.reserveCapacity(folded.utf8.count + digitWidth)
        var digits: [UInt8] = []
        func flush() {
            guard !digits.isEmpty else { return }
            if digits.count < digitWidth { out.append(contentsOf: repeatElement(UInt8(ascii: "0"), count: digitWidth - digits.count)) }
            out.append(contentsOf: digits)
            digits.removeAll(keepingCapacity: true)
        }
        for b in folded.utf8 {
            if b >= UInt8(ascii: "0") && b <= UInt8(ascii: "9") { digits.append(b) } else { flush(); out.append(b) }
        }
        flush()
        return out
    }
}

/// Builds the rows for a folder; separate from the view so the unit tests and the UI driver use it.
@MainActor
enum DashboardRows {
    static func load(model: LibraryModel, sessions: SessionsModel, vault: CredentialVault?, folderId: String, deep: Bool) throws -> [DashboardRow] {
        guard let library = model.library else { return [] }
        let t0 = CFAbsoluteTimeGetCurrent()
        let rows = try library.folderOverview(vault: vault, dataDir: LibraryModel.stateDir, folderId: folderId, includeSubfolders: deep)
        DashboardDriver.shared.coreMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        let t1 = CFAbsoluteTimeGetCurrent()
        defer { DashboardDriver.shared.buildMs = (CFAbsoluteTimeGetCurrent() - t1) * 1000 }
        let byId = connections(under: model.folder(id: folderId))
        return rows.map { r in
            let folder = r.kind == "folder"
            return DashboardRow(
                id: r.id, isFolder: folder, name: r.name, address: r.address, proto: r.protocol,
                type: folder ? "Folder" : r.typeLabel,
                status: folder ? "" : DashboardRow.status(sessions.tabs(for: r.id)),
                user: r.username ?? "",
                login: folder ? "" : DashboardRow.loginText(r.login, from: r.loginFrom),
                lastConnected: r.lastConnectedAt.map { Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .abbreviated, time: .shortened) } ?? "",
                lastConnectedAt: r.lastConnectedAt ?? 0,
                lastResult: r.lastResult ?? "",
                folder: r.folderPath.joined(separator: " › "),
                tags: r.tags.joined(separator: ", "),
                port: byId[r.id]?.port.map(String.init) ?? "",
                hostColor: r.hostColor).keyed(group: byId[r.id]?.group)
        }
    }

    /// Every connection under `folder` by id, in one walk (a lookup per row walked the tree per row).
    static func connections(under folder: FolderView?) -> [String: ConnectionView] {
        var out: [String: ConnectionView] = [:]
        func walk(_ f: FolderView) {
            for c in f.connections { out[c.id] = c }
            f.folders.forEach(walk)
        }
        folder.map(walk)
        return out
    }
}

/// The page a selected folder (or the library root) shows in the session area, by the same rule
/// as the connection page: it covers the sessions until a tab is picked.
struct FolderDashboard: View, Equatable {
    /// Its inputs are the folder and whether it is shown; the rest comes from the environment it
    /// observes. Compared by these (`.equatable()`), so a new tab re-creating the hidden page does
    /// not run its body (SwiftUI saw `@self changed` on every tab open; speed wave 3).
    nonisolated static func == (a: Self, b: Self) -> Bool { a.folderId == b.folderId && a.isShown == b.isShown }

    let folderId: String
    /// False while the page is kept mounted behind a tab or a connection page: it neither reloads
    /// nor reports to the UI driver, and opens fresh (no selection, no filter) when shown again.
    var isShown = true
    @Environment(Commands.self) private var commands
    @Environment(SessionsModel.self) private var sessions
    @Environment(AppRouter.self) private var router
    @State private var rows: [DashboardRow] = []
    @State private var loadError: String?
    @State private var selection = Set<DashboardRow.ID>()
    @State private var sort = DashboardSort()
    /// Sorted rows and the filter, outside SwiftUI state (typing refills only the table).
    @State private var controller = DashboardRowsController()
    @AppStorage("folder-dashboard.column-choice") private var columnChoice = ""
    /// "Include subfolders" per folder, for this run (packet: remembered per folder, default off).
    @MainActor static var deepFolders = Set<String>()
    @State private var deep = false
    @State private var loadedKey = ""
    @State private var showingHistory = false
    @State private var showingLogs = false
    /// The header's folder name as last shown. Hidden, the page keeps it, so hiding the page (a new tab
    /// in front) changes nothing in it and does not lay it out again (speed wave 3, first local shell).
    @State private var heldName: String?

    private var model: LibraryModel { commands.model }
    private var locked: Bool { commands.credentials?.vault == nil }
    /// The rows on screen, filtered and sorted (the rows controller keeps them).
    private var visible: [DashboardRow] { controller.shown }

    /// Sorted once per load or sort change, by precomputed keys; filtering keeps that order.
    private func resort() {
        let order = sort
        let t0 = CFAbsoluteTimeGetCurrent()
        let sorted = rows.sorted(by: order.before)
        DashboardDriver.shared.sortMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        controller.setRows(sorted, connections: DashboardRows.connections(under: model.folder(id: folderId)))
    }
    /// Selected connections in table order (folder rows take no connection actions).
    private var chosen: [String] { visible.filter { selection.contains($0.id) && !$0.isFolder }.map(\.id) }

    var body: some View {
        let _ = RenderCount.hit("FolderDashboard")
        VStack(alignment: .leading, spacing: 0) {
            header.padding(DS.Space.m)
            Divider()
            if let loadError {
                Text(loadError).foregroundStyle(.secondary).padding(DS.Space.m)
            } else if rows.isEmpty {
                emptyState
            } else {
                table
            }
        }
        .background(.background)
        .padding(.trailing, commands.tree.inspectorOverlayInset)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("folder-dashboard")
        #if BASTION_TEST_HOOKS
        .onAppear {
            DriverButtons.actions["History…"] = { showingHistory = true }
            DriverButtons.actions["Folder Logs…"] = { showingLogs = true }
        }
        #endif
        .sheet(isPresented: $showingLogs) {
            if let f = model.folder(id: folderId) { SessionLogsView(scope: .folder(f)) }
        }
        .sheet(isPresented: $showingHistory) {
            ActivityView(scope: .folder(id: folderId, name: model.folder(id: folderId)?.name ?? "Folder"))
        }
        .background { if isShown { Color.clear.uiProbe("folder-dashboard-area") } }
        .onAppear {
            deep = Self.deepFolders.contains(folderId)
            reloadIfStale()
            // UI driver: the filter applied at once, as the tree's `bench-filter` drives its own.
            DashboardDriver.shared.applyFilter = { [controller] text in controller.setFilter(text) }
            installShowHooks()
            DashboardDriver.shared.applyDeep = { on in deep = on; reloadIfStale() }
        }
        // A new folder or the subfolders switch loads at once, in the same update as the change, so
        // the page never draws a frame of the old rows; the task below covers the other sources.
        .onChange(of: folderId) { _, id in openFresh(id) }
        .onChange(of: shownFolder?.name, initial: true) { _, name in if let name, name != heldName { heldName = name } }
        .onChange(of: isShown) { _, on in
            // Again with this copy of the view: the page is first built hidden (#1063), and hooks
            // kept from then read `isShown` as false (dash-01-perf noop "NOT SHOWN YET", census 2026-11-17).
            installShowHooks()
            if on { openFresh(folderId) } else { publish() }
        }
        .onChange(of: deep) { _, on in Self.remember(deep: on, folderId); reloadIfStale() }
        // No polling: reload when the library, the sessions, the history or the vault change.
        // Hidden, it loads once (so its table is built) and then waits until it is shown: hiding it
        // as a tab opens no longer reloads every row for that tab (MAC-STALLS, first local shell).
        .task(id: isShown ? loadKey : "hidden") { if isShown || loadedKey.isEmpty { reloadIfStale() } }
        .onChange(of: DashboardDriver.shared.request?.id) { drive() }
        .onChange(of: sort) { resort() }
        // Read only while shown: hidden, the page does not follow the sessions, so a tab opening or
        // closing does not re-render it (`isShown` going true reloads it fresh).
        .onChange(of: isShown ? "\(rows.count)|\(selection.count)|\(statusKey)|\(deep)" : "hidden") { publish() }
    }

    /// The page for `id` as a fresh open shows it: its subfolders setting, no selection, no filter.
    private func openFresh(_ id: String) {
        deep = Self.deepFolders.contains(id)
        selection = []
        controller.clearFilter()
        reloadIfStale()
    }

    /// Changes when any session opens, ends or starts reconnecting.
    private var statusKey: String {
        sessions.tabs.map { "\($0.id)\($0.ended)\($0.panes.contains { $0.linkStatus != nil })" }.joined()
    }

    /// The page's folder, read only while the page is shown: the kept, hidden page then does not
    /// depend on the tree, so a library edit (New Folder) does not re-render and re-lay it out at
    /// window size. Showing it re-renders it with the current folder.
    private var shownFolder: FolderView? { isShown ? model.folder(id: folderId) : nil }
    /// The folder's name while shown; hidden, the name it showed last (`heldName`).
    private var headerName: String? { isShown ? shownFolder?.name : heldName }

    private var header: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            VStack(alignment: .leading, spacing: DS.Space.xxs) {
                HStack(spacing: DS.Space.xs) {
                    Text(headerName ?? "Library").font(DS.Font.title).lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: DS.Space.xs)
                    // LOG-NATIVE-01: sessions of every connection in this folder and its subfolders.
                    if headerName != nil {
                        Button("History…", systemImage: "clock.arrow.circlepath") { showingHistory = true }
                            .quietIcon("Sessions in this folder and its subfolders")
                            .accessibilityIdentifier("folder-dashboard-history")
                        Button("Logs…", systemImage: "doc.text") { showingLogs = true }
                            .quietIcon("Session logs in this folder and its subfolders")
                            .accessibilityIdentifier("folder-dashboard-logs")
                    }
                }
                Text(countLine).font(DS.Font.caption).foregroundStyle(.secondary)
                    .accessibilityIdentifier("folder-dashboard-count")
            }
            // One line when it fits, else filter and switch over the buttons (layout fit). One copy of each control.
            DashboardHeaderLayout(spacing: DS.Space.xs) {
                filterField.dashboardHeaderPart(.filter)
                toggle.dashboardHeaderPart(.toggle)
                columnsMenu.dashboardHeaderPart(.toggle)
                Group { connectActions }.dashboardHeaderPart(.connect)
                Group { editActions }.dashboardHeaderPart(.edit)
            }
        }
    }

    private var countLine: String {
        let connected = rows.filter { $0.status == "Connected" }.count
        var parts = ["\(rows.count) item\(rows.count == 1 ? "" : "s")", "\(connected) connected"]
        if !selection.isEmpty { parts.append("\(selection.count) selected") }
        return parts.joined(separator: " · ")
    }

    /// Its own view, cleared per folder (`clearFilter`): typing runs it and the rows controller, not this page.
    private var filterField: some View { DashboardFilterField(controller: controller) }

    /// Show or hide columns; the same choice as the header's right-click menu (Name always stays).
    private var columnsMenu: some View {
        let choice = DashboardColumn.parse(columnChoice)
        return Menu {
            ForEach(DashboardColumn.all(deep: deep).filter { $0.id != "name" }, id: \.id) { col in
                Toggle(col.title, isOn: Binding(
                    get: { choice[col.id] ?? col.shown },
                    set: { columnChoice = DashboardColumn.toggled(columnChoice, id: col.id, shown: $0) }))
                .accessibilityIdentifier("folder-dashboard-column-\(col.id)")
            }
            Divider()
            Button("Default Columns") { columnChoice = "" }
                .accessibilityIdentifier("folder-dashboard-columns-reset")
        } label: {
            Text("Columns")
        }
        .menuStyle(.button)
        .fixedSize()
        .help("Show or hide columns")
        .accessibilityLabel("Columns")
        .accessibilityIdentifier("folder-dashboard-columns")
        .uiProbe("folder-dashboard-columns")
    }

    private var toggle: some View {
        Toggle("Include subfolders", isOn: $deep)
            .toggleStyle(.checkbox)
            .fixedSize()
            .accessibilityIdentifier("folder-dashboard-subfolders")
    }

    /// Worked out once per draw: `chosen` is a pass over every row, so it must not run per row.
    @ViewBuilder private var connectActions: some View {
        let picked = chosen
        let pickedIds = Set(picked)
        let anyLive = rows.contains { !$0.status.isEmpty && pickedIds.contains($0.id) }
        Button("Connect") { chosen.forEach { commands.run("connect", on: $0) } }
            .dsPrimaryButton()
            .disabled(picked.isEmpty).fixedSize().accessibilityIdentifier("folder-dashboard-connect")
        Button("Disconnect", systemImage: "bolt.slash") { sessions.disconnect(Set(chosen)) }
            .quietIcon("Disconnect")
            .disabled(!anyLive).accessibilityIdentifier("folder-dashboard-disconnect")
        Button("Run Task…", systemImage: "play") {
            MultiExecView.presetHosts = chosen
            router.open("run-on-hosts")
        }
        .quietIcon("Run a task on the selection")
        .disabled(picked.isEmpty).accessibilityIdentifier("folder-dashboard-run")
    }

    @ViewBuilder private var editActions: some View {
        Button("Move…", systemImage: "folder.badge.gearshape") { if let id = selectedVisible.first { commands.run("move", on: id) } }
            .quietIcon(selection.count > 1 ? "Move one item at a time" : "Move to another folder")
            .disabled(selection.count != 1)
            .accessibilityIdentifier("folder-dashboard-move")
        Button("Delete", systemImage: "trash", role: .destructive) { deleteSelected() }
            .quietIcon("Delete")
            .disabled(selection.isEmpty).accessibilityIdentifier("folder-dashboard-delete")
        // Several rows: waits for B3-BULK-EDIT (packet DASH-01).
        Button("Properties", systemImage: "slider.horizontal.3") { if let id = selectedVisible.first { commands.run("properties", on: id) } }
            .quietIcon(selection.count > 1 ? "Editing several items at once is not available yet" : "Edit properties")
            .disabled(selection.count != 1)
            .accessibilityIdentifier("folder-dashboard-properties")
    }

    private var emptyState: some View {
        VStack(spacing: DS.Space.s) {
            Text("This folder is empty.").foregroundStyle(.secondary)
            Button("Add Connection") { commands.addConnection = ParentTarget(id: folderId) }
                .accessibilityIdentifier("folder-dashboard-add")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var table: some View {
        DashboardTable(
            controller: controller, rows: controller.shown, version: controller.version, deep: deep, locked: locked,
            selection: $selection, sort: $sort, columnChoice: $columnChoice,
            menu: { commands.menu(for: $0) }, perform: { commands.perform($0, on: $1) }, open: { open($0) })
            .background { if isShown { Color.clear.uiProbe("folder-dashboard-table") } }
    }

    /// Double-click or Return: a folder row opens its dashboard; connections connect or show their session.
    private func open(_ ids: Set<String>) {
        if let folder = ids.first(where: { id in rows.first { $0.id == id }?.isFolder == true }) {
            commands.selectNode?(folder)
            return
        }
        visible.filter { ids.contains($0.id) }.forEach { commands.run("connect", on: $0.id) }
    }

    /// The selected rows the table shows, in table order: what Delete, Move and Properties act on.
    private var selectedVisible: [String] { visible.filter { selection.contains($0.id) }.map(\.id) }

    private func trimSelection() {
        let shownIds = Set(visible.map(\.id))
        if !selection.isSubset(of: shownIds) { selection = selection.intersection(shownIds) }
    }

    /// Deletes exactly the rows the confirmation names: the selected rows on screen.
    private func deleteSelected() {
        let picked = visible.filter { selection.contains($0.id) }
        guard !picked.isEmpty else { return }
        let names = picked.map(\.name)
        if let confirm = DashboardDriver.shared.confirmDelete {
            guard confirm(names) else { return }
            return delete(picked.map(\.id))
        }
        let alert = NSAlert()
        alert.messageText = names.count == 1 ? "Delete “\(names[0])”?" : "Delete \(names.count) items?"
        alert.informativeText = names.count == 1 ? "" : names.prefix(5).joined(separator: ", ") + (names.count > 5 ? ", …" : "")
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Delete").hasDestructiveAction = true
        alert.addButton(withTitle: "Cancel")
        guard alert.runModalInFront() == .alertFirstButtonReturn else { return }
        delete(picked.map(\.id))
    }

    private func delete(_ ids: [String]) {
        selection.subtract(ids)
        ids.forEach { commands.run("delete", on: $0) }
    }

    /// The controller's after-show hook and the driver's no-op step, bound to this copy of the view.
    private func installShowHooks() {
        // A filter that hides a selected row drops it from the selection: Delete, Move and
        // Properties then never act on a row the user cannot see.
        controller.didShow = { trimSelection(); publish() }
        DashboardDriver.shared.applyNoop = { publish() }
    }

    /// UI driver: what the page shows now. Only while UI suites run; the rows are kept as they
    /// are and turned into text when the driver reads them (no secrets exist in the rows to leak).
    private func publish() {
        guard UIProbe.isActive else { return }
        guard isShown else { DashboardDriver.shared.snapshot = nil; return }
        DashboardDriver.shared.snapshot = DashboardDriver.Snapshot(
            folder: model.folder(id: folderId)?.name ?? "Library", count: countLine, deep: deep, locked: locked,
            shown: visible, selection: selection)
    }

    /// UI driver requests: filter, select by names, subfolders, connect.
    private func drive() {
        guard let r = DashboardDriver.shared.request else { return }
        DashboardDriver.shared.request = nil
        switch r.command {
        case "filter": controller.setFilter(r.arg)
        case "select":
            let names = Set(r.arg.split(separator: ",").map(String.init))
            selection = Set(rows.filter { names.contains($0.name) }.map(\.id))
        case "select-all": selection = Set(visible.map(\.id))
        case "deep": deep = r.arg == "on"
        case "connect": chosen.forEach { commands.run("connect", on: $0) }
        case "open": open(selection)
        case "delete": deleteSelected()
        default: break
        }
        publish()
    }

    /// Everything the rows depend on; a reload records it so one change loads once.
    private var loadKey: String { "\(folderId)|\(deep)|\(model.treeVersion)|\(sessions.historyRevision)|\(statusKey)|\(locked)" }

    private func reloadIfStale() {
        guard loadKey != loadedKey else { return }
        reload()
    }

    @MainActor private static func remember(deep on: Bool, _ folderId: String) {
        if on { deepFolders.insert(folderId) } else { deepFolders.remove(folderId) }
    }

    private func reload() {
        loadedKey = loadKey
        do {
            rows = try DashboardRows.load(model: model, sessions: sessions, vault: commands.credentials?.vault, folderId: folderId, deep: deep)
            loadError = nil
            // The selection survives reloads and filtering; rows that are gone drop out.
            let ids = Set(rows.map(\.id))
            if !selection.isSubset(of: ids) { selection = selection.intersection(ids) }
            resort()
            publish()
            DashboardDriver.shared.loads += 1
        } catch {
            rows = []
            controller.setRows([], connections: [:])
            loadError = "Could not list this folder."
        }
    }
}

/// The UI driver's handle on the folder dashboard (`dash-*` steps in `UIDriverDashboard.swift`).
@MainActor @Observable
final class DashboardDriver {
    static let shared = DashboardDriver()
    struct Request { let id = UUID(); let command: String; let arg: String }
    struct Snapshot {
        let folder: String; let count: String; let deep: Bool; let locked: Bool
        let shown: [DashboardRow]; let selection: Set<String>
        var rows: [String] { shown.map { "\($0.name)|\($0.address)|\($0.type)|\($0.status)|\($0.user)|\($0.login)|\($0.folder)" } }
        var rowCount: Int { shown.count }
        var selected: [String] { shown.filter { selection.contains($0.id) }.map(\.name) }
    }
    var request: Request?
    @ObservationIgnored var snapshot: Snapshot?
    /// How long the last core `folderOverview` call took, for the `dash-bench` step.
    @ObservationIgnored var coreMs: Double = 0
    /// Counts finished reloads, so a timed step can wait for one that started after it.
    @ObservationIgnored var loads = 0
    @ObservationIgnored var sortMs: Double = 0
    @ObservationIgnored var buildMs: Double = 0
    @ObservationIgnored var applyFilter: ((String) -> Void)?
    /// UI driver: stands in for the Delete confirmation, gets the names it would list.
    @ObservationIgnored var confirmDelete: (([String]) -> Bool)?
    @ObservationIgnored var lastDeleteNames: [String] = []
    @ObservationIgnored var applyDeep: ((Bool) -> Void)?
    @ObservationIgnored var applyNoop: (() -> Void)?
}
