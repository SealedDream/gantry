import AppKit
import SwiftUI
import BastionCore

/// A plugin's view in a normal tab (PLUG-06c: no separate window, the database plugin sits beside
/// terminals). The helper starts when the tab opens and stops when it closes
/// (`TerminalTab.closeAll` → `PluginViewModel.close`). Nothing starts at app launch.
@MainActor
enum PluginViewWindow {
    /// Set at app start; the tabs live in its strip.
    static weak var sessions: SessionsModel?
    private static var models: [String: PluginViewModel] = [:]

    /// The open view model of a plugin (the UI driver reads it; nothing else needs it).
    static func model(for id: String) -> PluginViewModel? { models[id] }
    /// `id` is a plugin id, or `entry:<connection id>` for a view opened on an entry.
    static func tab(for id: String) -> TerminalTab? {
        sessions?.tabs.first { if case .plugin(let m) = $0.content { m.key == id } else { false } }
    }

    /// Opens a connection the user confirmed in a plugin's open sheet (set by the app):
    /// the go-ahead, the plugin entry's id and its library.
    static var openConnection: ((PluginViewModel.OpenGo, String, Library) -> Void)?
    /// Plugin API 1.5: runs an `exec-go` command on the entry (entry id, library, command,
    /// timeout ms, cancel) and calls back with the result. Set by the app.
    static var runExec: ((String, Library, String, UInt64, PluginExecCancel, @escaping (PluginExecResult) -> Void) -> Void)?
    /// Plugin API 1.5: opens an `exec-terminal` tab (entry id, library, command, label); false
    /// when it could not. Set by the app.
    /// Opens the terminal tab and calls back with true only once the tab exists; any failure says why in the view.
    static var openExecTerminal: ((String, Library, String, String, @escaping (Bool) -> Void) -> Void)?
    /// Asks for the gateway sign-in of a plugin entry (set by the app).
    static var askGateway: ((PluginGatewayRequest) -> Void)?
    /// Shows a problem in the main window (set by the app).
    static var onProblem: ((String) -> Void)?
    /// The banner's Trust certificate…: pins the entry's certificate after the user compared it,
    /// then opens the entry again so the view connects under the new pin (set by the app).
    static var trustCertificate: ((PluginViewModel) -> Void)?
    /// Starts a saved tunnel through its sign-in and calls back once it runs (set by the app).
    static var startTunnel: ((TunnelDefView, @escaping @MainActor () -> Void) -> Void)?

    /// Opens (or selects) the tab of entry `c`, whose type `type` an installed plugin offers.
    /// The saved logins open first when that needs no prompt or the entry names a login.
    static func show(entry c: ConnectionView, type: PluginTypeView, library: Library, credentials: CredentialsModel?,
                     via chosen: PluginRoute? = nil, route: GatewayRoute? = nil) {
        guard let sessions else { return }
        let key = "entry:\(c.id)"
        if let t = tab(for: key) { sessions.selected = t.id; return }
        let via: PluginRoute
        switch chosen.map(PluginEntryRoute.Plan.route) ?? PluginEntryRoute.plan(for: c, port: c.port ?? type.defaultPort ?? 0, library: library, running: sessions.runningTunnels) {
        case .route(let r): via = r
        case .gateway: askGateway?(PluginGatewayRequest(entry: c, type: type)); return
        case .start(let t):
            // The saved tunnel signs in as usual; the entry opens once it runs.
            startTunnel?(t) { show(entry: c, type: type, library: library, credentials: credentials) }
            return
        }
        let model = PluginViewModel(pluginId: type.pluginId, entryId: c.id)
        model.gatewayRoute = route
        models[key] = model
        sessions.add(TerminalTab(name: c.name, content: .plugin(model)))
        Task {
            if let credentials, credentials.vault == nil, LoginResolver.hasAssignment(c) || credentials.opensWithoutPrompt {
                await credentials.openInBackground(sessions: sessions)
            }
            // Locked logins: the view opens without one, and the plugin shows the server's refusal.
            await model.open(entry: c.id, library: library, vault: credentials?.vault, allowUnverified: type.tier == "Unverified", via: via)
        }
    }

    static func show(pluginId: String, unverified: Bool) {
        guard let sessions else { return }
        if let t = tab(for: pluginId) { sessions.selected = t.id; return }
        let model = PluginViewModel(pluginId: pluginId)
        models[pluginId] = model
        sessions.add(TerminalTab(name: pluginId, content: .plugin(model)))
        Task { await model.open(viewName: "settings", allowUnverified: unverified) }
    }

    /// Closes the plugin's tab (the helper stops with it).
    static func close(pluginId: String) {
        if let t = tab(for: pluginId) { sessions?.close(t) }
        models[pluginId] = nil
    }

    /// Closes the entry's tab and opens it again (a new view reads the entry's TLS rule afresh).
    static func reopen(entryId: String, open: () -> Void) {
        let key = "entry:\(entryId)"
        if let t = tab(for: key) { sessions?.close(t) }
        models[key] = nil
        open()
    }

    /// Called by the tab when it closes from the strip.
    static func closed(_ model: PluginViewModel) {
        model.close()
        if models[model.key] === model { models[model.key] = nil }
    }
}


struct PluginTabView: View {
    @ObservedObject var model: PluginViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let m = model.message {
                HStack { Text(m).lineLimit(1).help(m); Spacer(); Button("Dismiss") { model.message = nil }.controlSize(.small) }
                    .padding(8).background(Color.orange.opacity(0.15))
            }
            if let e = model.ended {
                Text(e).foregroundStyle(.secondary).padding(8).accessibilityIdentifier("plugin-ended")
            }
            if model.nodes.isEmpty && model.ended == nil {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity).accessibilityIdentifier("plugin-loading")
            } else {
                PluginNodes(model: model, list: model.nodes, parent: nil)
                    .padding(12).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
        }
        .frame(minWidth: 420, minHeight: 280)
        .sheet(item: Binding(get: { model.dialogs.last }, set: { if $0 == nil { model.dismissTopDialog() } })) { d in
            VStack(alignment: .leading, spacing: 12) {
                Text(d.title).font(DS.Font.headline)
                PluginNodes(model: model, list: d.nodes, parent: nil)
            }
            .padding(16).frame(minWidth: 360)
        }
        .sheet(item: Binding(get: { model.openRequest }, set: { if $0 == nil, let r = model.openRequest { model.answerOpen(r, accept: false, route: r.route, saveAsEntry: false) } })) { r in
            PluginOpenSheet(request: r) { accept, route, save in model.answerOpen(r, accept: accept, route: route, saveAsEntry: save) }
        }
        .sheet(item: Binding(get: { model.libraryRequest }, set: { if $0 == nil, let r = model.libraryRequest { model.answerLibrary(r, saved: nil, credentialLinked: false) } })) { r in
            PluginSaveConnectionsSheet(request: r) { saved, cred in model.answerLibrary(r, saved: saved, credentialLinked: cred) }
        }
        .alert(model.confirm.map(\.title) ?? "", isPresented: Binding(get: { model.confirm != nil }, set: { if !$0, let c = model.confirm { model.answer(c, confirmed: false) } }), presenting: model.confirm) { c in
            Button("Confirm", role: .destructive) { model.answer(c, confirmed: true) }
            Button("Cancel", role: .cancel) { model.answer(c, confirmed: false) }
        } message: { c in
            Text([c.entry, c.text].compactMap { $0 }.joined(separator: "\n"))
        }
    }
}

/// The children of `parent` in `list`, in order.
struct PluginNodes: View {
    @ObservedObject var model: PluginViewModel
    let list: [PluginViewModel.Node]
    let parent: Int?

    var body: some View {
        ForEach(model.kids(of: parent, in: list)) { n in PluginNodeView(model: model, list: list, node: n) }
    }
}

struct PluginNodeView: View {
    @ObservedObject var model: PluginViewModel
    let list: [PluginViewModel.Node]
    let node: PluginViewModel.Node

    private var rec: [String: Any] { node.value as? [String: Any] ?? [:] }
    private var kids: some View { PluginNodes(model: model, list: list, parent: node.id) }
    /// The children of a split, each one a pane that fills its share.
    private var panes: some View {
        ForEach(model.kids(of: node.id, in: list)) { n in
            PluginNodeView(model: model, list: list, node: n)
                .frame(minWidth: Self.minPane, maxWidth: .infinity, minHeight: Self.minPane, maxHeight: .infinity, alignment: .topLeading)
        }
    }
    /// Smallest split pane: room for a toolbar row or a few tree lines.
    static let minPane: CGFloat = 120
    /// Half the height of the macOS tab strip, which sits across the TabView's top edge.
    static let tabStripOverhang: CGFloat = 12

    var body: some View {
        switch node.kind {
        case "stack":
            if (node.value as? String) == "horizontal" { HStack(alignment: .top, spacing: 8) { kids } } else { VStack(alignment: .leading, spacing: 8) { kids } }
        case "split":
            // Each pane fills its share: without it a pane takes its content's ideal size and the
            // panes overlap or leave the tab half empty (PLUG-08 Mac layout-fit).
            Group {
                if (node.value as? String) == "vertical" { VSplitView { panes } } else { HSplitView { panes } }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case "tabs":
            TabView {
                ForEach(model.kids(of: node.id, in: list)) { t in
                    VStack(alignment: .leading) { PluginNodes(model: model, list: list, parent: t.id) }
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                        .tabItem { Text(t.value as? String ?? "") }
                }
            }
            // The tab strip straddles the TabView's top edge by half its height; inside a split
            // pane that half is clipped, so the pane keeps room for it.
            .padding(.top, Self.tabStripOverhang)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case "tab":
            VStack(alignment: .leading, spacing: 8) { kids }
        case "toolbar":
            PluginToolbar(model: model, list: list, id: node.id)
        case "label":
            Text(node.value as? String ?? "").textSelection(.enabled)
                .foregroundStyle(model.kind(of: node.parent, in: list) == "toolbar" ? .secondary : .primary)
        case "banner":
            let text = rec["text"] as? String ?? ""
            PluginBanner(level: rec["level"] as? String ?? "info", text: text,
                         trust: model.entryId != nil && PluginBanner.isCertificateRefusal(text) ? { PluginViewWindow.trustCertificate?(model) } : nil)
        case "progress":
            if let v = node.value as? Double { ProgressView(value: v) } else { ProgressView().controlSize(.small) }
        case "empty-state":
            VStack(spacing: 4) {
                Text(rec["title"] as? String ?? "").font(DS.Font.headline)
                Text(rec["text"] as? String ?? "").foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity)
        case "button":
            Button(rec["label"] as? String ?? "") { model.input(node: node.id, ["kind": "pressed"]) }
                .disabled(!(rec["enabled"] as? Bool ?? true))
        case "text-field":
            PluginTextField(model: model, node: node.id, label: rec["label"] as? String ?? "", initial: rec["value"] as? String ?? "",
                            placeholder: rec["placeholder"] as? String ?? "", multiLine: rec["multi-line"] as? Bool ?? false)
        case "number-field":
            PluginNumberField(model: model, node: node.id, label: rec["label"] as? String ?? "", initial: rec["value"] as? Double ?? 0)
        case "choice":
            PluginChoice(model: model, node: node.id, label: rec["label"] as? String ?? "", options: rec["options"] as? [String] ?? [], initial: rec["selected"] as? Int)
        case "toggle":
            PluginToggle(model: model, node: node.id, label: rec["label"] as? String ?? "", initial: rec["value"] as? Bool ?? false)
        case "code-editor":
            PluginCodeEditor(model: model, node: node.id, language: rec["language"] as? String ?? "sql", initial: rec["text"] as? String ?? "", readOnly: rec["read-only"] as? Bool ?? false)
        case "table":
            PluginTable(model: model, node: node.id, columns: ((rec["columns"] as? [[String: Any]]) ?? []).map { $0["title"] as? String ?? "" })
        case "tree":
            PluginTree(model: model, node: node.id, parent: nil)
        case "stat":
            PluginStatTile(rec: rec)
        default:
            Text("Unsupported element: \(node.kind)").foregroundStyle(.secondary)
        }
    }
}

struct PluginBanner: View {
    let level: String, text: String
    /// Trust certificate…, when the banner is the core's certificate refusal on an entry.
    var trust: (() -> Void)?

    /// The core's refusal when the server's certificate fails the entry's TLS mode
    /// (`core/src/plugin/broker/stream.rs`).
    nonisolated static func isCertificateRefusal(_ text: String) -> Bool { text.contains("certificate did not pass the TLS mode") }

    var body: some View {
        let color: Color = level == "error" ? .red : level == "warning" ? .orange : .accentColor
        HStack(spacing: 8) {
            Text(text).frame(maxWidth: .infinity, alignment: .leading)
            if let trust {
                Button("Trust Certificate…", action: trust)
                    .help("Read the server's certificate, compare its SHA-256 fingerprint, then pin it")
                    .accessibilityIdentifier("plugin-banner-trust")
                    .background(DriverFrame(name: "plugin-banner-trust"))
            }
        }
        .padding(8).background(color.opacity(0.12))
    }
}

struct PluginTextField: View {
    @ObservedObject var model: PluginViewModel
    let node: Int, label: String, initial: String, placeholder: String, multiLine: Bool
    @State private var text: String?
    var body: some View {
        let b = Binding(get: { text ?? initial }, set: { text = $0 })
        TextField(label, text: b, prompt: Text(placeholder), axis: multiLine ? .vertical : .horizontal)
            .onSubmit { model.input(node: node, ["kind": "text", "value": b.wrappedValue]) }
    }
}

struct PluginNumberField: View {
    @ObservedObject var model: PluginViewModel
    let node: Int, label: String, initial: Double
    @State private var value: Double?
    var body: some View {
        let b = Binding(get: { value ?? initial }, set: { value = $0 })
        TextField(label, value: b, format: .number).onSubmit { model.input(node: node, ["kind": "number", "value": b.wrappedValue]) }
    }
}

struct PluginChoice: View {
    @ObservedObject var model: PluginViewModel
    let node: Int, label: String, options: [String], initial: Int?
    @State private var picked: Int?
    var body: some View {
        Picker(label, selection: Binding(get: { picked ?? initial ?? -1 }, set: { i in
            picked = i
            model.input(node: node, ["kind": "choice", "value": i])
        })) {
            ForEach(Array(options.enumerated()), id: \.offset) { i, o in Text(o).tag(i) }
        }.fixedSize()
    }
}

struct PluginToggle: View {
    @ObservedObject var model: PluginViewModel
    let node: Int, label: String, initial: Bool
    @State private var on: Bool?
    var body: some View {
        Toggle(label, isOn: Binding(get: { on ?? initial }, set: { v in
            on = v
            model.input(node: node, ["kind": "toggled", "value": v])
        }))
    }
}

struct PluginTable: View {
    @ObservedObject var model: PluginViewModel
    let node: Int, columns: [String]
    @State private var selection = Set<Int>()
    var body: some View {
        let rows = model.rows[node] ?? []
        VStack(alignment: .leading, spacing: 4) {
            HStack { ForEach(Array(columns.enumerated()), id: \.offset) { _, c in Text(c).bold().frame(maxWidth: .infinity, alignment: .leading) } }
            List(Array(rows.enumerated()), id: \.offset, selection: $selection) { _, r in
                HStack {
                    ForEach(Array(r.enumerated()), id: \.offset) { _, c in
                        PluginCellView(value: c).frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .opacity(PluginTone.isDimmed(r) ? 0.5 : 1)
            }
            if rows.isEmpty, let why = model.rowRefusals[node] {
                Text(why).foregroundStyle(.secondary).accessibilityIdentifier("plugin-table-empty")
            }
            if let total = model.totals[node], rows.count < total {
                Button("More Rows") { model.askRows(node: node, offset: rows.count) }.controlSize(.small)
            }
        }
        .onAppear { if rows.isEmpty, model.rowRefusals[node] == nil, !model.rowsPending(node: node) { model.askRows(node: node, offset: 0) } }
        .onChange(of: selection) { _, picked in model.selectRows(node: node, picked) }
        .onChange(of: rows.isEmpty) { _, empty in if empty { selection = [] } }
    }
}

struct PluginTree: View {
    @ObservedObject var model: PluginViewModel
    let node: Int, parent: String?
    var body: some View {
        let items = model.children[PluginViewModel.childKey(node, parent)] ?? []
        VStack(alignment: .leading, spacing: 2) {
            ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                let key = item["key"] as? String ?? ""
                let menu = (item["menu"] as? [[String: Any]]) ?? []
                let label = item["label"] as? String ?? key
                // A click selects the item (the plugin shows its details, e.g. PostgreSQL's Object tab).
                let row = Text(label)
                    .padding(.horizontal, 3)
                    .background(model.treeSelection[node] == key ? Color.accentColor.opacity(0.25) : Color.clear, in: RoundedRectangle(cornerRadius: 3))
                    .contentShape(Rectangle())
                    .onTapGesture { model.selectTreeItem(node: node, key: key) }
                    .accessibilityAddTraits(.isButton)
                    .accessibilityAction { model.selectTreeItem(node: node, key: key) }
                Group {
                    if item["has-children"] as? Bool ?? false {
                        DisclosureGroup { PluginTree(model: model, node: node, parent: key) } label: { row }
                    } else {
                        row
                    }
                }
                // The item's menu from the plugin: power, snapshot and connect actions. The plugin
                // confirms risky ones through the core's confirm prompt.
                .contextMenu {
                    ForEach(Array(menu.enumerated()), id: \.offset) { _, m in
                        Button(m["title"] as? String ?? "") {
                            model.input(node: node, ["kind": "menu", "key": key, "item": m["id"] as? String ?? ""])
                        }
                    }
                }
            }
        }
        .padding(.leading, parent == nil ? 0 : 12)
        .onAppear { if items.isEmpty { model.askChildren(node: node, parent: parent) } }
    }
}
