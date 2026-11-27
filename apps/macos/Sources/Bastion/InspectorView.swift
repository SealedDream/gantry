import SwiftUI
import BastionCore

/// Right region: adapts to the selection (connection, folder, nothing). One primary action, compact
/// secondary actions, everything else in the registry overflow menu; destructive actions only there.
/// Buttons take no key equivalents, so typing in a terminal never triggers them.
struct InspectorPane: View {
    let selection: String?
    let commands: Commands
    let select: (String) -> Void
    @Environment(LibraryModel.self) private var model

    var body: some View {
        let _ = RenderCount.hit("InspectorPane")
        Group {
            if let id = selection, let c = model.connection(id: id) {
                ConnectionInspector(connection: c, commands: commands)
            } else {
                folderOrNothing(selection.flatMap { model.folder(id: $0) })
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            TipsLine(panel: .inspector).padding(.horizontal, DS.Space.s).padding(.vertical, DS.Space.xxs)
        }
    }

    /// With nothing selected, a folder inspector for the library root is kept built under "No
    /// Selection", hidden from view, accessibility and the pointer. The first folder selection then
    /// updates it instead of building it: that build cost about 18 ms in the frame after the first
    /// dashboard (MAC-SELECT-SPEED).
    @ViewBuilder private func folderOrNothing(_ folder: FolderView?) -> some View {
        let shown = folder ?? model.tree
        ZStack(alignment: .top) {
            if let shown {
                FolderInspector(folder: shown, commands: commands, select: select)
                    .opacity(folder == nil ? 0 : 1)
                    .accessibilityHidden(folder == nil)
                    .allowsHitTesting(folder != nil)
            }
            if folder == nil {
                ContentUnavailableView("No Selection", systemImage: "sidebar.right",
                                       description: Text("Select a connection or folder."))
            }
        }
    }
}

/// Header shared by both inspectors: icon, name, one secondary line, then the action bar.
private struct InspectorHeader<Actions: View>: View {
    let iconId: String
    var ownIcon: String? = nil
    let title: String
    let subtitle: String
    @ViewBuilder let actions: Actions

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            HStack(alignment: .center, spacing: DS.Space.xs + 2) {
                ConnectionIcon(proto: iconId, own: ownIcon, size: 20)
                    .frame(width: 32, height: 32)
                    .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 7))
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).font(DS.Font.bodyStrong).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                    Text(subtitle).font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        .textSelection(.enabled)
                }
                Spacer(minLength: 0)
            }
            HStack(spacing: DS.Space.xs) { actions }
        }
        .padding(DS.Space.m)
        .uiProbe("inspector-header")
    }
}

/// Collapsible group with a small heading; expansion is remembered per group title.
struct InspectorGroup<Content: View>: View {
    let title: String
    let content: Content
    @AppStorage private var expanded: Bool

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
        _expanded = AppStorage(wrappedValue: true, "inspector.group.\(title)")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            Button { expanded.toggle() } label: {
                HStack(spacing: DS.Space.xxs) {
                    Image(systemName: "chevron.right")
                        .font(DS.Font.size(9, weight: .semibold))
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                    Text(title).font(DS.Font.caption.weight(.semibold))
                    Spacer(minLength: 0)
                }
                .foregroundStyle(.secondary)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(title)
            .accessibilityValue(expanded ? "expanded" : "collapsed")
            if expanded { content }
        }
        .padding(.horizontal, DS.Space.m)
        .padding(.vertical, DS.Space.xs)
    }
}

/// The registry overflow menu for an object. AppKit, and filled when it opens: as a SwiftUI
/// `Menu` its whole action list (with submenus) was built on every inspector update (MAC-SELECT-SPEED).
private struct OverflowMenu: NSViewRepresentable {
    let id: String?
    let commands: Commands
    var excluding: Set<String> = []

    func makeNSView(context: Context) -> OverflowMenuButton {
        let button = OverflowMenuButton()
        button.toolTip = "More actions"
        button.setAccessibilityLabel("More actions")
        return button
    }

    func updateNSView(_ button: OverflowMenuButton, context: Context) {
        button.fill = { [id, commands, excluding] menu in
            ActionMenuBuilder.fill(menu, items: commands.menu(for: id).filter { !excluding.contains($0.id) },
                                   submenu: { commands.submenu(for: $0, on: id) }) { commands.perform($0, on: id) }
        }
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: OverflowMenuButton, context: Context) -> CGSize? { nsView.fittingSize }
}

/// A push button with an ellipsis that shows a menu built at click time, under itself.
final class OverflowMenuButton: NSButton {
    var fill: ((NSMenu) -> Void)?

    init() {
        super.init(frame: .zero)
        bezelStyle = .push
        image = NSImage(systemSymbolName: "ellipsis", accessibilityDescription: "More actions")
        imagePosition = .imageOnly
        target = self
        action = #selector(show)
    }
    required init?(coder: NSCoder) { fatalError("not used") }

    @objc private func show() {
        let menu = NSMenu()
        fill?(menu)
        menu.popUp(positioning: nil, at: NSPoint(x: 0, y: bounds.height + 4), in: self)
    }
}

private struct IconAction: View {
    let symbol: String
    let help: String
    let action: () -> Void

    var body: some View {
        Button(action: action) { Image(systemName: symbol).frame(width: 16).iconHitTarget() }
            .help(help)
            .accessibilityLabel(help)
    }
}

struct ConnectionInspector: View {
    let connection: ConnectionView
    let commands: Commands
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @State private var notes = ""
    @State private var savedNotes = ""
    @State private var hops: [JumpHostView] = []
    @State private var editingOverrides = false

    private var c: ConnectionView { connection }
    private var info: IconView { Icons.info(c.protocol) }
    private var state: SessionStateLabel? { SessionStateLabel.of(c.id, in: sessions.snapshot) }
    private var address: String { (try? model.library?.address(id: c.id)) ?? c.host }
    private var username: String? { (try? model.library?.effectiveUsername(id: c.id)) ?? nil }

    var body: some View {
        // Read once per render: the menu depends on session state, which this view observes.
        let items = commands.menu(for: c.id)
        let primary = items.first(where: \.primary)
        // Header and actions stay fixed; only the groups scroll. A scroll view that reaches the
        // toolbar edge in the `.inspector` column gets the toolbar inset twice (a frame offset and
        // an NSScrollView content inset), which pushed everything a toolbar height down.
        VStack(alignment: .leading, spacing: 0) {
            InspectorHeader(iconId: c.protocol, ownIcon: c.ownIcon, title: c.name, subtitle: "\(username.map { "\($0)@" } ?? "")\(address)") {
                if let primary {
                    Button(primary.label) { commands.perform(primary, on: c.id) }
                        .dsPrimaryButton()
                        .disabled(!primary.enabled)
                        .help(primary.disabledReason ?? "")
                }
                if items.contains(where: { $0.id == "open-sftp" && $0.enabled }) {
                    IconAction(symbol: "externaldrive.connected.to.line.below", help: "Open SFTP") { commands.run("open-sftp", on: c.id) }
                }
                if let d = items.first(where: { $0.id == "disconnect" }), d.enabled {
                    IconAction(symbol: "xmark.circle", help: "Disconnect") { commands.perform(d, on: c.id) }
                }
                IconAction(symbol: "doc.on.clipboard", help: "Copy Address") { commands.run("copy-address", on: c.id) }
                Spacer(minLength: 0)
                OverflowMenu(id: c.id, commands: commands, excluding: [primary?.id ?? ""])
            }
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    InspectorGroup("Overview") {
                        InspectorRow("Protocol") { ProtocolPicker(connection: c) }
                        InspectorSection(rows: [("Host", c.host), ("Port", c.port.map(String.init) ?? "Default")]
                            + (folderPath.map { [("Folder", $0)] } ?? [])
                            + (c.group.map { [("Group", $0)] } ?? []))
                    }
                    if c.protocol == "web" {
                        InspectorGroup("Network") { WebTunnelPicker(connectionId: c.id).font(DS.Font.body) }
                    }
                    if c.protocol != "web" {
                        InspectorGroup("Authentication") {
                            InspectorSection(rows: [("User", username ?? "Ask when connecting")])
                            if c.protocol == "ssh" {
                                CredentialPicker(connection: c).font(DS.Font.body)
                                VaultwardenItemPicker(connection: c).font(DS.Font.body)
                            }
                        }
                    }
                    if c.protocol == "ssh" { network }
                    InspectorGroup("Activity") {
                        HStack(spacing: DS.Space.xs) {
                            if let state {
                                Image(systemName: state.symbol).font(DS.Font.size(state.pointSize))
                                    .foregroundStyle(Color(nsColor: Icons.dynamicColor(state.token)))
                            }
                            Text(activityText).font(DS.Font.body).foregroundStyle(state == nil ? .secondary : .primary)
                        }
                    }
                    if c.unavailable == nil {
                        InspectorGroup("Icon") { OwnIconPicker(connection: c) }
                    }
                    if PluginEntries.type(of: c) != nil {
                        InspectorGroup("Certificate") { PluginEntryTlsRow(connection: c) }
                    }
                    InspectorGroup("Notes") {
                        TextEditor(text: $notes)
                            .font(DS.Font.body)
                            .frame(minHeight: 64)
                            .scrollContentBackground(.hidden)
                            .padding(DS.Space.xxs)
                            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 5))
                            .accessibilityLabel("Notes")
                            .noWritingToolsButton()
                    }
                }
            }
            Divider()
            HistoryFooter(connectionId: c.id, revision: sessions.historyRevision)
        }
        .task(id: c.id) { load() }
        .onChange(of: model.revision) { loadHops() }
        .onChange(of: notes) { _, new in
            guard new != savedNotes else { return }
            Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(600))
                guard notes == new, new != savedNotes else { return }
                saveNotes(new)
            }
        }
        .onDisappear { if notes != savedNotes { saveNotes(notes) } }
        .sheet(isPresented: $editingOverrides) {
            if let e = effective { OverridesSheet(connection: c, effective: e) }
        }
    }

    @ViewBuilder private var network: some View {
        let e = effective
        InspectorGroup("Network") {
            InspectorSection(rows: [("Jump hosts", hops.isEmpty ? "None" : hops.map { "\($0.username)@\($0.key)" }.joined(separator: " → "))]
                + (e?.identityFile.map { [("Identity", $0)] } ?? []))
            if c.sourceStatus == "removed-from-source" {
                Label("No longer in the SSH config", systemImage: "exclamationmark.triangle").font(DS.Font.caption)
            }
            if let e, !e.unresolved.isEmpty {
                Label("Needs \(e.unresolved.map { "<\($0)>" }.joined(separator: ", "))", systemImage: "exclamationmark.circle")
                    .font(DS.Font.caption)
            }
            if e != nil { Button("Personal Overrides…") { editingOverrides = true }.controlSize(.small) }
        }
    }

    private var effective: EffectiveView? {
        guard c.imported, let lib = model.library else { return nil }
        return (try? model.workflow?.effectiveFor(library: lib, connectionId: c.id)) ?? nil
    }

    private var activityText: String {
        let live = sessions.tabs(for: c.id).filter { !$0.ended }.count
        switch state?.label {
        case "Connected": return live == 1 ? "Connected in 1 tab" : "Connected in \(live) tabs"
        case "Connecting": return "Connecting…"
        case "Session ended": return "Session ended"
        default: return "Not connected"
        }
    }

    private var folderPath: String? {
        guard let tree = model.tree else { return nil }
        func find(_ f: FolderView, _ trail: [String]) -> [String]? {
            if f.connections.contains(where: { $0.id == c.id }) { return trail }
            return f.folders.lazy.compactMap { find($0, trail + [$0.name]) }.first
        }
        return find(tree, []).flatMap { $0.isEmpty ? nil : $0.joined(separator: " › ") }
    }

    private func load() {
        let text = (try? model.library?.notes(id: c.id)) ?? ""
        savedNotes = text
        notes = text
        loadHops()
    }

    /// The gateway and ProxyJump hops, refreshed when a property changes.
    private func loadHops() {
        hops = []
        if c.protocol == "ssh", let lib = model.library { hops = sessions.jumpHosts(library: lib, connectionId: c.id) }
    }

    private func saveNotes(_ text: String) {
        let id = c.id
        model.mutate { try $0.setNotes(id: id, notes: text) }
        savedNotes = text
    }
}

struct FolderInspector: View {
    let folder: FolderView
    let commands: Commands
    let select: (String) -> Void
    @Environment(SessionsModel.self) private var sessions

    private var openCount: Int {
        func ids(_ f: FolderView) -> [String] { f.connections.map(\.id) + f.folders.flatMap(ids) }
        let snap = sessions.snapshot
        return Set(ids(folder)).intersection(snap.connected + snap.connecting).count
    }

    private var folderCount: Int {
        func count(_ f: FolderView) -> Int { f.folders.count + f.folders.reduce(0) { $0 + count($1) } }
        return count(folder)
    }

    var body: some View {
        let n = folder.connectionCount
        VStack(alignment: .leading, spacing: 0) {
            InspectorHeader(iconId: "folder", title: folder.name,
                            subtitle: "\(n) connection\(n == 1 ? "" : "s") · \(folderCount) folder\(folderCount == 1 ? "" : "s")") {
                Button("New Connection…") { commands.run("new-connection", on: folder.id) }
                IconAction(symbol: "folder.badge.plus", help: "New Subfolder") { commands.run("new-subfolder", on: folder.id) }
                IconAction(symbol: "slider.horizontal.3", help: "Folder Defaults") { commands.run("properties", on: folder.id) }
                Spacer(minLength: 0)
                OverflowMenu(id: folder.id, commands: commands, excluding: ["new-connection", "new-subfolder"])
            }
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    InspectorGroup("Overview") {
                        InspectorSection(rows: [("Connections", "\(n)"), ("Subfolders", "\(folderCount)"), ("Sessions", "\(openCount)")])
                    }
                    if !folder.connections.isEmpty || !folder.folders.isEmpty {
                        InspectorGroup("Contents") { contents }
                    }
                }
            }
        }
    }

    /// Lazy: only the rows on screen are built (up to 200 buttons were built on every selection).
    private var contents: some View {
        LazyVStack(alignment: .leading, spacing: 2) {
            ForEach(folder.folders, id: \.id) { f in
                row(icon: "folder", name: f.name, detail: "\(f.connectionCount)") { select(f.id) }
            }
            ForEach(folder.connections.prefix(200), id: \.id) { c in
                row(icon: c.protocol, name: c.name, detail: c.host) { select(c.id) }
            }
            if folder.connections.count > 200 {
                Text("\(folder.connections.count - 200) more in the tree").font(DS.Font.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func row(icon: String, name: String, detail: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: DS.Space.xs) {
                ObjectIcon(id: icon, size: 12)
                Text(name).lineLimit(1)
                Spacer(minLength: DS.Space.xs)
                Text(detail).foregroundStyle(.tertiary).lineLimit(1).truncationMode(.middle)
            }
            .font(DS.Font.body)
            .padding(.vertical, 2)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Select \(name)")
    }
}

/// Inspector footer: exactly two lines, "Last connected" and "Last result" (core connection history).
private struct HistoryFooter: View {
    let connectionId: String
    let revision: Int
    @State private var history: ConnectionHistoryView?
    @State private var failed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Last connected: \(connectedText)").lineLimit(1).truncationMode(.tail)
            Text("Last result: \(failed ? "History unavailable" : history?.lastResult ?? "Never connected")")
                .lineLimit(1).truncationMode(.tail)
        }
        .font(DS.Font.caption).foregroundStyle(.secondary).textSelection(.enabled)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.xs)
        .uiProbe("inspector-footer")
        .task(id: "\(connectionId)#\(revision)") {
            do { history = try connectionHistory(dataDir: LibraryModel.dataDir.path, connectionId: connectionId); failed = false } catch { failed = true }
        }
    }

    private var connectedText: String {
        guard let at = history?.lastConnectedAt else { return "Never" }
        let date = Date(timeIntervalSince1970: TimeInterval(at)).formatted(date: .abbreviated, time: .shortened)
        return history?.lastUser.map { "\(date) as \($0)" } ?? date
    }
}

/// Which saved tunnel a web connection's tab opens through ("Direct" when none).
private struct WebTunnelPicker: View {
    let connectionId: String
    @Environment(LibraryModel.self) private var model
    @State private var tunnels: [TunnelDefView] = []
    @State private var current = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.xxs) {
            Picker("Open through", selection: Binding(get: { current }, set: choose)) {
                Text("Direct").tag("")
                ForEach(tunnels, id: \.id) { t in Text("\(t.name) (via \(t.viaName))").tag(t.id) }
            }
            .controlSize(.small)
            if let error { Text(error).font(DS.Font.caption).foregroundStyle(.red) }
        }
        .task(id: "\(connectionId)#\(model.revision)") { load() }
    }

    private func load() {
        guard let library = model.library else { return }
        do {
            tunnels = try library.tunnels().filter { $0.kind != "remote" }
            current = try library.webTunnelPlan(connectionId: connectionId, dataDir: WebTunnels.dataDir.path)?.tunnelId ?? ""
            error = nil
        } catch {
            self.error = "\(error)"
        }
    }

    private func choose(_ id: String) {
        current = id
        model.mutate { try $0.setWebTunnel(connectionId: connectionId, tunnelId: id.isEmpty ? nil : id) }
    }
}

/// Builds and draws the folder inspector once, off screen, after launch: its first build (SwiftUI
/// types, the header's menus, the lazy list) otherwise lands in the frame after the first folder
/// click (MAC-SELECT-SPEED). Nothing is shown and nothing is kept.
@MainActor enum InspectorPrewarm {
    private static var done = false

    static func run(model: LibraryModel, sessions: SessionsModel, settings: SettingsModel, shortcuts: ShortcutsModel, commands: Commands) {
        guard !done, let folder = model.tree?.folders.first else { return }
        done = true
        let pane = InspectorPane(selection: folder.id, commands: commands, select: { _ in })
            .environment(model).environment(sessions).environment(settings).environment(shortcuts)
        let host = NSHostingView(rootView: pane)
        host.frame = NSRect(x: 0, y: 0, width: DS.Size.inspectorIdeal, height: 600)
        host.layoutSubtreeIfNeeded()
        if let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) { host.cacheDisplay(in: host.bounds, to: rep) }
    }
}

extension View {
    /// macOS 15+: no Writing Tools button. In full screen it floated as a round badge over the
    /// window's top-right corner beside the inspector's Notes field (owner round 5).
    @ViewBuilder func noWritingToolsButton() -> some View {
        if #available(macOS 15, *) { writingToolsBehavior(.disabled) } else { self }
    }
}
