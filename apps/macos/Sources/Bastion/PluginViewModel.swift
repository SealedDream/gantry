import AppKit
import Foundation
import SwiftUI
import BastionCore

/// PLUG-06a part 2: one open plugin view. Reads the core's updates (`PluginView.nextUpdate`) on a
/// background task and keeps the node tree, dialogs and the pending confirmation for the renderer.
/// The core checks every node list before it reaches here; this model only draws what it gets.
@MainActor
final class PluginViewModel: ObservableObject {
    struct Node: Identifiable {
        let id: Int
        let parent: Int?
        let kind: String
        let value: Any?
    }
    struct Dialog: Identifiable {
        let id: Int
        let title: String
        let nodes: [Node]
    }
    struct Confirm: Identifiable {
        /// The alert's title: never the raw WIT kind (plugin.wit `confirm-kind`).
        var title: String {
            switch kind {
            case "drop": "Confirm Drop"
            case "truncate": "Confirm Truncate"
            case "delete-rows": "Confirm Delete Rows"
            case "end-session": "Confirm End Session"
            case "run-statements": "Confirm Run Statements"
            default: "Confirm"
            }
        }
        let id: Int
        let kind: String
        let text: String
        let entry: String?
    }

    /// Plugin API 1.2: a plugin asks to open SSH, RDP or VNC. The core checked it; the user
    /// confirms the exact destination in `PluginOpenSheet` (`docs/specs/plugins-amendment-3.md`).
    struct OpenRequest: Identifiable {
        let id: Int
        let plugin: String
        let entryName: String
        let proto: String
        let host: String
        let port: Int
        let label: String
        let reported: Bool
        /// The route the plugin asked for: `entry` or `direct`.
        let route: String
        /// How the plugin entry reaches its server: `direct`, `tunnel`, `socks` or `routed`.
        let entryRoute: String
    }
    /// The core's go-ahead after the user's yes: what the app opens.
    struct OpenGo {
        let proto: String
        let host: String
        let port: Int
        let label: String
        let viaEntryRoute: Bool
        let checkResolved: Bool
        let loopbackOk: Bool
        let saveAsEntry: Bool
    }

    /// Plugin API 1.6: a plugin proposes library connections. The core checked them; the user
    /// picks folder, protocol, host and credential in `PluginSaveConnectionsSheet`.
    struct LibraryProposal {
        let label: String
        let host: String?
        let reported: Bool
        let proto: String
        let osHint: String?
    }
    struct LibraryRequest: Identifiable {
        let id: Int
        let plugin: String
        let entryName: String
        let items: [LibraryProposal]
    }

    let pluginId: String
    @Published var openRequest: OpenRequest?
    @Published var libraryRequest: LibraryRequest?
    /// Save-as-entry choices by request, until the core's `open-go` arrives.
    private var saveChoice: [Int: Bool] = [:]
    /// The library the entry belongs to (set when opened on an entry).
    private(set) var library: Library?
    @Published private(set) var nodes: [Node] = []
    /// When the plugin last set a loaded view (shown as "Updated hh:mm" beside Refresh).
    @Published private(set) var updatedAt: Date?
    @Published private(set) var dialogs: [Dialog] = []
    @Published var confirm: Confirm?
    @Published private(set) var ended: String?
    @Published var message: String?
    @Published private(set) var rows: [Int: [[Any?]]] = [:]
    /// Each table row's key, in the same order as `rows`.
    @Published private(set) var rowKeys: [Int: [String]] = [:]
    /// Why a table has no rows (the plugin's refusal of a row ask), shown in that table.
    @Published private(set) var rowRefusals: [Int: String] = [:]
    @Published private(set) var totals: [Int: Int] = [:]
    @Published private(set) var children: [String: [[String: Any]]] = [:]
    /// A tree ask the plugin refused, by `childKey`: its words, shown in place of the items.
    @Published private(set) var childRefusals: [String: String] = [:]
    /// PLUG-06c: the latest `provide-completions` answer per code editor node, with its ask id
    /// (an editor drops an answer to an older ask). Already checked and capped by the core.
    @Published private(set) var completions: [Int: (ask: Int, items: [CompletionItem])] = [:]

    /// Plugin API 1.5: the cancel switch of each running `exec-go`, by request.
    private var execCancels: [Int: PluginExecCancel] = [:]
    private var view: PluginView?
    /// Set by `close()`; an open still compiling when the window closes must stop its helper.
    private var closed = false
    private var reader: Task<Void, Never>?
    private var nextAsk = 1
    private var askTarget: [Int: (node: Int, parent: String?)] = [:]
    static let firstView = 1
    nonisolated static let pollMs: UInt32 = 250
    static let pageRows = 100

    /// Set when the view is opened on a library entry (a plugin connection type).
    let entryId: String?
    /// The key its tab is found by: the entry, else the plugin.
    var key: String { entryId.map { "entry:\($0)" } ?? pluginId }

    init(pluginId: String, entryId: String? = nil) {
        self.pluginId = pluginId
        self.entryId = entryId
    }

    /// Opens the view off the main thread (a cold open compiles first), then starts reading.
    func open(viewName: String, allowUnverified: Bool) async {
        let id = pluginId, dir = LibraryModel.dataDir.path
        let result = await Task.detached(priority: .userInitiated) {
            Result {
                try PluginHelper.ensurePath()
                return try pluginViewOpen(dataDir: dir, pluginId: id, viewName: viewName, entry: nil, allowUnverified: allowUnverified, safeMode: false)
            }
        }.value
        await opened(result)
    }

    /// Opens the view of the plugin that owns entry `connectionId`'s type, on that entry. The core
    /// reads the entry's login from the vault (when open) and keeps it; it never reaches this app.
    /// `sidebar`: the entry's tree in the library sidebar (plugin API 1.3), a second session.
    func open(entry connectionId: String, library: Library, vault: CredentialVault?, allowUnverified: Bool, via: PluginRoute = .direct, sidebar: Bool = false) async {
        self.library = library
        let dir = LibraryModel.dataDir.path
        let result = await Task.detached(priority: .userInitiated) {
            Result {
                try PluginHelper.ensurePath()
                if sidebar {
                    return try pluginEntrySidebarOpen(library: library, vault: vault, connectionId: connectionId, dataDir: dir, allowUnverified: allowUnverified, safeMode: false, via: via)
                }
                return try pluginEntryViewOpenVia(library: library, vault: vault, connectionId: connectionId, dataDir: dir, allowUnverified: allowUnverified, safeMode: false, via: via)
            }
        }.value
        await opened(result)
    }

    private func opened(_ result: Result<PluginView, Error>) async {
        switch result {
        case .success(let v):
            if closed {
                // The window closed during a cold open: stop the helper that just started.
                Task.detached { v.close() }
                return
            }
            view = v
            startReading(v)
        case .failure(let e):
            ended = "Plugin not opened: \(e.userMessage)"
        }
    }

    /// The view could not be opened; shown in the tab.
    func fail(_ text: String) { ended = text }

    /// The gateway forward this tab opened on (PLUG-08); closed with the tab.
    var gatewayRoute: GatewayRoute?

    func close() {
        for c in execCancels.values { c.cancel() }
        execCancels.removeAll()
        gatewayRoute?.close()
        gatewayRoute = nil
        closed = true
        reader?.cancel()
        reader = nil
        if let v = view { Task.detached { v.close() } }
        view = nil
    }

    private func startReading(_ v: PluginView) {
        reader = Task.detached(priority: .userInitiated) { [weak self] in
            while !Task.isCancelled {
                guard let text = v.nextUpdate(timeoutMs: PluginViewModel.pollMs) else { continue }
                guard let model = self else { return }
                if await model.applyText(text) { return }
            }
        }
    }

    // MARK: updates

    /// Applies one update; true when it was the last (`ended`).
    func applyText(_ text: String) -> Bool {
        guard let data = text.data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return false }
        apply(obj)
        return (obj["type"] as? String) == "ended"
    }

    func apply(_ u: [String: Any]) {
        switch u["type"] as? String {
        case "set-view":
            guard (u["view"] as? Int) == Self.firstView else { return }
            let list = Self.parse(u["nodes"])
            nodes = list
            // "Updated" means the plugin finished a load: no busy mark (a progress node without a value) and no error banner.
            if !list.contains(where: { ($0.kind == "progress" && !($0.value is Double)) || ($0.kind == "banner" && ($0.value as? [String: Any])?["level"] as? String == "error") }) {
                updatedAt = Date()
            }
            reloadTables(in: list)
        case "patch-view":
            guard (u["view"] as? Int) == Self.firstView else { return }
            let upsert = Self.parse(u["upsert"])
            nodes = Self.patched(nodes, upsert: upsert, remove: Set((u["remove"] as? [Int]) ?? []))
            reloadTables(in: upsert)
            reloadTrees(in: upsert)
        case "dialog":
            if let id = u["dialog"] as? Int {
                dialogs.append(Dialog(id: id, title: u["title"] as? String ?? "", nodes: Self.parse(u["nodes"])))
            }
        case "close-dialog":
            let id = u["dialog"] as? Int
            dialogs.removeAll { $0.id == id }
        case "confirm":
            guard let req = u["request"] as? Int else { return }
            let e = u["entry"] as? [String: Any]
            // The environment class is shown only when set: "unclassified" says nothing.
            let env = (e?["environment"] as? String).flatMap { $0.isEmpty || $0 == "unclassified" ? nil : $0 }
            let entry = (e?["name"] as? String).map { n in [n, env].compactMap { $0 }.joined(separator: " · ") }
            confirm = Confirm(id: req, kind: u["kind"] as? String ?? "other", text: u["text"] as? String ?? "", entry: entry)
        case "open-request":
            guard let req = u["request"] as? Int, let host = u["host"] as? String, let port = u["port"] as? Int else { return }
            let e = u["entry"] as? [String: Any]
            openRequest = OpenRequest(id: req, plugin: u["plugin"] as? String ?? pluginId, entryName: e?["name"] as? String ?? "",
                                      proto: u["protocol"] as? String ?? "", host: host, port: port, label: u["label"] as? String ?? "",
                                      reported: u["reported"] as? Bool ?? false, route: u["route"] as? String ?? "entry",
                                      entryRoute: u["entry_route"] as? String ?? "direct")
        case "library-propose":
            guard let req = u["request"] as? Int, let items = u["items"] as? [[String: Any]] else { return }
            let e = u["entry"] as? [String: Any]
            libraryRequest = LibraryRequest(id: req, plugin: u["plugin"] as? String ?? pluginId, entryName: e?["name"] as? String ?? "",
                                            items: items.map { LibraryProposal(label: $0["label"] as? String ?? "", host: $0["host"] as? String,
                                                                               reported: $0["reported"] as? Bool ?? false, proto: $0["protocol"] as? String ?? "ssh",
                                                                               osHint: $0["os_hint"] as? String) })
        case "open-go":
            guard let req = u["request"] as? Int, let host = u["host"] as? String, let port = u["port"] as? Int,
                  let entry = entryId, let library else { return }
            let go = OpenGo(proto: u["protocol"] as? String ?? "", host: host, port: port, label: u["label"] as? String ?? host,
                            viaEntryRoute: (u["route"] as? String) == "entry", checkResolved: u["check_resolved"] as? Bool ?? true,
                            loopbackOk: u["loopback_ok"] as? Bool ?? false, saveAsEntry: saveChoice.removeValue(forKey: req) ?? false)
            PluginViewWindow.openConnection?(go, entry, library)
        case "exec-go":
            guard let req = u["request"] as? Int, let command = u["command"] as? String else { return }
            guard let entry = entryId, let library, let run = PluginViewWindow.runExec else {
                send(["type": "exec", "request": req, "exit": NSNull(), "error": "This view is not opened on an entry."])
                return
            }
            let cancel = PluginExecCancel()
            execCancels[req] = cancel
            let ms = UInt64(u["timeout_ms"] as? Int ?? 30_000)
            run(entry, library, command, ms, cancel) { [weak self] r in
                Task { @MainActor in
                    guard let self, self.execCancels.removeValue(forKey: req) != nil else { return }
                    var answer: [String: Any] = ["type": "exec", "request": req, "stdout": r.stdout, "stderr": r.stderr]
                    answer["exit"] = r.exit.map { Int($0) as Any } ?? NSNull()
                    if let e = r.error { answer["error"] = e }
                    self.send(answer)
                }
            }
        case "exec-cancel":
            if let req = u["request"] as? Int { execCancels.removeValue(forKey: req)?.cancel() }
        case "exec-terminal":
            guard let req = u["request"] as? Int, let command = u["command"] as? String else { return }
            guard let entry = entryId, let library, let open = PluginViewWindow.openExecTerminal else {
                send(["type": "exec", "request": req, "opened": false])
                return
            }
            open(entry, library, command, u["label"] as? String ?? "") { [weak self] opened in
                self?.send(["type": "exec", "request": req, "opened": opened])
            }
        case "clipboard":
            // The core sends this only right after the user pressed Copy in the view (view_files.rs).
            guard let text = u["text"] as? String else { return }
            Self.pasteboard.clearContents()
            Self.pasteboard.setString(text, forType: .string)
        case "save-request":
            guard let req = u["request"] as? Int else { return }
            let path = Self.chooseSavePath(name: u["name"] as? String ?? "export")
            send(["type": "save", "request": req, "path": path.map { $0 as Any } ?? NSNull()])
        case "open-refused":
            if let req = u["request"] as? Int { saveChoice[req] = nil }
            message = u["reason"] as? String
        case "refuse":
            // A refused row ask belongs to its table; other refusals go to the banner.
            if let ask = u["ask"] as? Int, let t = askTarget.removeValue(forKey: ask), t.parent == nil, nodes.contains(where: { $0.id == t.node && $0.kind == "table" }) {
                rowRefusals[t.node] = u["message"] as? String
            } else if let ask = u["ask"] as? Int, let t = refusedTreeAsk(ask) {
                childRefusals[Self.childKey(t.node, t.parent)] = u["message"] as? String ?? ""
            } else {
                message = u["message"] as? String
            }
        case "provide-rows":
            provideRows(u["args"] as? [Any] ?? [])
        case "provide-children":
            provideChildren(u["args"] as? [Any] ?? [])
        case "provide-completions":
            provideCompletions(u["args"] as? [Any] ?? [])
        case "ended":
            ended = PluginsText.ended(u["reason"] as? String ?? "")
            reader?.cancel()
            // The core ends the helper for every reason; closing here makes it certain.
            if let v = view { Task.detached { v.close() } }
        default:
            break
        }
    }

    /// The clipboard plugin copies go to; UI tests use a private pasteboard so a run never changes the user's.
    static var pasteboard: NSPasteboard = .general

    /// The save panel for a plugin's `files.save`; the core writes the file to the path. Nil when cancelled.
    static func chooseSavePath(name: String) -> String? {
        if let url = LibraryIO.scriptedPanelURL { LibraryIO.scriptedPanelURL = nil; return url.path }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = name
        panel.canCreateDirectories = true
        return panel.runModal() == .OK ? panel.url?.path : nil
    }

    static func parse(_ any: Any?) -> [Node] {
        ((any as? [[String: Any]]) ?? []).compactMap { n in
            guard let id = n["id"] as? Int, let c = n["component"] as? [String: Any], let kind = c["kind"] as? String else { return nil }
            return Node(id: id, parent: n["parent"] as? Int, kind: kind, value: c["value"].flatMap { $0 is NSNull ? nil : $0 })
        }
    }

    /// A new list: `remove` dropped, `upsert` replacing nodes by id or added at the end.
    static func patched(_ list: [Node], upsert: [Node], remove: Set<Int>) -> [Node] {
        let byId = Dictionary(upsert.map { ($0.id, $0) }, uniquingKeysWith: { _, b in b })
        let kept = list.filter { !remove.contains($0.id) }.map { byId[$0.id] ?? $0 }
        let known = Set(kept.map(\.id))
        return kept + upsert.filter { !known.contains($0.id) }
    }

    func kids(of id: Int?, in list: [Node]? = nil) -> [Node] {
        (list ?? nodes).filter { $0.parent == id }
    }

    /// The kind of node `id` in `list`, or nil.
    func kind(of id: Int?, in list: [Node]? = nil) -> String? {
        guard let id else { return nil }
        return (list ?? nodes).first { $0.id == id }?.kind
    }

    // MARK: events

    func send(_ event: [String: Any]) {
        guard let v = view, let data = try? JSONSerialization.data(withJSONObject: event),
              let json = String(data: data, encoding: .utf8) else { return }
        Task.detached { [weak self] in
            do { try v.sendEvent(json: json) } catch {
                let text = error.userMessage
                await MainActor.run { self?.message = text }
            }
        }
    }

    func input(node: Int, _ input: [String: Any]) {
        send(["type": "ui", "view": Self.firstView, "node": node, "input": input])
    }

    /// Esc or a click outside closes the top dialog: drop it here and tell the plugin (`cancel`).
    func dismissTopDialog() {
        guard !dialogs.isEmpty else { return }
        dialogs.removeLast()
        send(["type": "cancel", "view": Self.firstView])
    }

    func answer(_ c: Confirm, confirmed: Bool) {
        confirm = nil
        send(["type": "confirm", "request": c.id, "confirmed": confirmed])
    }

    /// The user's answer to the open sheet. `route` is `entry` or `direct`.
    func answerOpen(_ r: OpenRequest, accept: Bool, route: String, saveAsEntry: Bool) {
        openRequest = nil
        if accept { saveChoice[r.id] = saveAsEntry }
        send(["type": "open", "request": r.id, "accept": accept, "route": route, "credential_chosen": false, "save_as_entry": accept && saveAsEntry])
    }

    /// The user's answer to the Save as Connection sheet: how many were saved, or nil (cancelled).
    func answerLibrary(_ r: LibraryRequest, saved: Int?, credentialLinked: Bool) {
        libraryRequest = nil
        send(["type": "library", "request": r.id, "saved": saved.map { $0 as Any } ?? NSNull(), "credential_linked": saved != nil && credentialLinked])
    }

    /// The user selected table rows: their keys go to the plugin.
    func selectRows(node: Int, _ indexes: Set<Int>) {
        let keys = rowKeys[node] ?? []
        let picked = indexes.sorted().compactMap { $0 < keys.count && !keys[$0].isEmpty ? keys[$0] : nil }
        input(node: node, ["kind": "selected", "keys": picked])
    }

    /// The selected item of each tree, by node.
    @Published private(set) var treeSelection: [Int: String] = [:]

    /// The user clicked a tree item: its key goes to the plugin as the tree's selection.
    func selectTreeItem(node: Int, key: String) {
        guard !key.isEmpty else { return }
        treeSelection[node] = key
        input(node: node, ["kind": "selected", "keys": [key]])
    }

    func askRows(node: Int, offset: Int) {
        let ask = takeAsk(node: node, parent: nil)
        send(["type": "rows", "ask": ask, "view": Self.firstView, "node": node, "offset": offset, "count": Self.pageRows])
    }

    func askChildren(node: Int, parent: String?) {
        let ask = takeAsk(node: node, parent: parent)
        var e: [String: Any] = ["type": "children", "ask": ask, "view": Self.firstView, "node": node]
        if let p = parent { e["parent"] = p }
        send(e)
    }

    /// Asks the plugin for completions at `offset` (characters) in `text`; returns the ask id.
    @discardableResult
    func askCompletions(node: Int, text: String, offset: UInt32) -> Int {
        let ask = takeAsk(node: node, parent: nil)
        send(["type": "completions", "ask": ask, "view": Self.firstView, "node": node, "text": text, "offset": Int(offset)])
        return ask
    }

    private func takeAsk(node: Int, parent: String?) -> Int {
        let a = nextAsk
        nextAsk += 1
        askTarget[a] = (node, parent)
        return a
    }

    /// A table sent again (a new result) starts from no rows: the old pages, total and refusal
    /// are dropped, asks still on the way are forgotten, and the first page is asked for.
    /// Before, the grid kept the empty answer to its first ask and never asked again.
    /// Whether a row ask for `node` is on its way (so a grid that appears does not ask twice).
    func rowsPending(node: Int) -> Bool { askTarget.values.contains { $0.node == node && $0.parent == nil } }

    /// A tree sent again is the plugin's "reload" (PostgreSQL: Refresh, a new plan): its cached children and
    /// refusals are dropped, so the tree asks again.
    private func reloadTrees(in list: [Node]) {
        let prefixes = list.filter { $0.kind == "tree" }.map { "\($0.id)/" }
        guard !prefixes.isEmpty else { return }
        for k in children.keys where prefixes.contains(where: { k.hasPrefix($0) }) { children[k] = nil }
        for k in childRefusals.keys where prefixes.contains(where: { k.hasPrefix($0) }) { childRefusals[k] = nil }
        for id in Set(list.filter { $0.kind == "tree" }.map(\.id)) { askChildren(node: id, parent: nil) }
    }

    private func reloadTables(in list: [Node]) {
        for n in list where n.kind == "table" {
            rows[n.id] = nil
            rowKeys[n.id] = nil
            totals[n.id] = nil
            rowRefusals[n.id] = nil
            askTarget = askTarget.filter { !($0.value.node == n.id && $0.value.parent == nil) }
            if view != nil { askRows(node: n.id, offset: 0) }
        }
    }

    private func provideRows(_ args: [Any]) {
        guard let ask = args.first as? Int, let t = askTarget.removeValue(forKey: ask) else { return }
        let list = (args.count > 1 ? args[1] as? [[String: Any]] : nil) ?? []
        let cells = list.map { r in ((r["cells"] as? [[String: Any]]) ?? []).map { Self.cell($0) } }
        rows[t.node] = (rows[t.node] ?? []) + cells
        rowKeys[t.node] = (rowKeys[t.node] ?? []) + list.map { $0["key"] as? String ?? "" }
        rowRefusals[t.node] = nil
        if args.count > 2, let total = args[2] as? Int { totals[t.node] = total }
    }

    /// A refused ask of a tree node (sidebar or tab), taken off the open asks.
    private func refusedTreeAsk(_ ask: Int) -> (node: Int, parent: String?)? {
        guard let t = askTarget[ask], nodes.contains(where: { $0.id == t.node && $0.kind == "tree" }) else { return nil }
        askTarget[ask] = nil
        return t
    }

    private func provideChildren(_ args: [Any]) {
        guard let ask = args.first as? Int, let t = askTarget.removeValue(forKey: ask) else { return }
        children[Self.childKey(t.node, t.parent)] = (args.count > 1 ? args[1] as? [[String: Any]] : nil) ?? []
    }

    private func provideCompletions(_ args: [Any]) {
        guard let ask = args.first as? Int, let t = askTarget.removeValue(forKey: ask) else { return }
        completions[t.node] = (ask, Self.completionItems(args.count > 1 ? args[1] : nil))
    }

    static func completionItems(_ any: Any?) -> [CompletionItem] {
        ((any as? [[String: Any]]) ?? []).compactMap { i in
            guard let label = i["label"] as? String else { return nil }
            return CompletionItem(label: label, insert: i["insert"] as? String ?? label, detail: i["detail"] as? String ?? "")
        }
    }

    static func childKey(_ node: Int, _ parent: String?) -> String { "\(node)/\(parent ?? "")" }

    static func cell(_ c: [String: Any]) -> Any? {
        guard let kind = c["kind"] as? String, kind != "null" else { return nil }
        return c["value"]
    }
}

/// The bundled helper, `Contents/Helpers/bastion-plugin-host`, handed to the core once, just
/// before the first plugin opens (nothing at app start). The core refuses any other path.
enum PluginHelper {
    nonisolated(unsafe) private static var done = false
    private static let lock = NSLock()

    static var bundledPath: String {
        return Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/bastion-plugin-host").path
    }

    static func ensurePath() throws {
        lock.lock()
        defer { lock.unlock() }
        if done { return }
        try pluginHostSetHelperPath(path: bundledPath)
        done = true
    }
}
