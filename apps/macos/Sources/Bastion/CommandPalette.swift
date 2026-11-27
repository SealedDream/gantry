import SwiftUI
import BastionCore

/// One palette row. `run` goes through the same handlers as menus and toolbar buttons:
/// router targets (`ContentView.open`), registry actions (`Commands.perform`), or a selection.
struct PaletteEntry: Identifiable {
    /// The core's entry kinds (`palette.rs`), which also order ties.
    enum Kind: String { case command, action, workspace, tab, connection, setting }

    let id: String
    let kind: Kind
    let title: String
    /// Right-aligned: shortcut, section or host.
    let detail: String
    let symbol: String
    var keywords = ""
    let run: @MainActor () -> Void

    var input: PaletteEntryInput { PaletteEntryInput(kind: kind.rawValue, title: title, detail: detail, keywords: keywords) }
}

/// What the palette can do right now. Registry actions come from the core menu for the
/// selection, so the palette never offers an action without a handler.
@MainActor
enum PaletteCatalog {
    struct Context {
        let commands: Commands
        let router: AppRouter
        let workspaces: WorkspaceModel
        let settings: SettingsModel
        let shortcuts: ShortcutsModel
        let selection: String?
        let select: (String) -> Void
    }

    /// App commands: (title, symbol, router target, shortcut id, keywords). The detail column
    /// shows the configured shortcut; `new-connection` opens the editor directly, ⌘N's `add`
    /// the Add menu, so it shows ⌘N's keys.
    private static let appCommands: [(String, String, String, String, String)] = [
        ("Quick Connect…", "bolt", "quick-connect", "quick-connect", "open host address ssh rdp vnc"),
        ("New Connection…", "plus", "new-connection", "add", "add host"),
        ("New Folder…", "folder.badge.plus", "new-folder", "new-folder", "add group"),
        ("New Local Shell", "terminal", "local-shell", "local-shell", "terminal zsh bash"),
        ("Save Current Layout…", "square.and.arrow.down.on.square", "save-workspace", "save-workspace", "workspace tabs"),
        ("Manage Workspaces…", Icons.symbol("workspace"), "workspace-manager", "workspace-manager", "workspace layout rename duplicate delete"),
        ("Settings…", "gearshape", "settings", "", "preferences options"),
        ("Keyboard Shortcuts…", "keyboard", "keyboard-shortcuts", "", "keys hotkeys bindings settings"),
        ("Credential Manager", Icons.symbol("credential"), "credential-manager", "credential-manager", "passwords keys vault"),
        ("Lock Credentials", "lock", "lock-credentials", "lock-credentials", "vault vaultwarden"),
        ("Show or Hide Library", "sidebar.left", "toggle-library", "toggle-library", "sidebar navigation tree collapse"),
        ("Show or Hide Inspector", "sidebar.right", "toggle-inspector", "toggle-inspector", "details panel"),
        ("Show or Hide File Panel", "folder", "toggle-files-panel", "toggle-files-panel", "sftp files transfer"),
        ("Split Right", "rectangle.split.2x1", "split-right", "split-right", "pane terminal"),
        ("Split Down", "rectangle.split.1x2", "split-down", "split-down", "pane terminal"),
        ("Show Next Tab", "arrow.right.square", "next-tab", "next-tab", "session"),
        ("Show Previous Tab", "arrow.left.square", "previous-tab", "previous-tab", "session"),
        ("Expand All Folders", "chevron.down.2", "expand-all", "", "tree"),
        ("Collapse All Folders", "chevron.up.2", "collapse-all", "", "tree"),
        ("Import SSH Config…", "square.and.arrow.down", "ssh-import", "", "openssh hosts"),
        ("Tasks…", "checklist", "tasks-page", "", "saved checks hooks uptime disk"),
        ("Run Command on Hosts…", "terminal", "run-on-hosts", "", "ad-hoc exec multi host ssh"),
        ("SSH Config Sources…", "doc.text.magnifyingglass", "ssh-sources", "", "openssh watch"),
    ]

    static func entries(_ c: Context) -> [PaletteEntry] {
        var out = appCommands.map { title, symbol, target, shortcutId, keywords in
            // ⌘, belongs to the system Settings item, not to the configurable list.
            let keys = target == "settings" ? "⌘," : c.shortcuts.display(shortcutId)
            return PaletteEntry(id: "cmd:\(target)", kind: .command, title: title, detail: keys, symbol: symbol, keywords: keywords) {
                c.router.open(target)
            }
        }
        out.append(PaletteEntry(id: "cmd:home", kind: .command, title: "Home", detail: "⇧⌘H", symbol: "house",
                                keywords: "start recent start page") { c.router.open("home") })
        if updateChannelConfigured() {
            out.append(PaletteEntry(id: "cmd:check-updates", kind: .command, title: "Check for Updates…", detail: "", symbol: "arrow.down.circle") {
                c.router.open("check-updates")
            })
        }
        out += defaultSettingTypes.map { type in
            PaletteEntry(id: "cmd:defaults:\(type.protocolName)", kind: .command, title: "\(type.label) Defaults…", detail: "",
                         symbol: Icons.symbol(type.protocolName), keywords: "default settings inherit") {
                c.router.open("defaults:\(type.protocolName)")
            }
        }
        out += c.commands.model.tasks.map { t in
            PaletteEntry(id: "task:\(t.id)", kind: .command, title: "Run Task “\(t.name)”",
                         detail: TaskRunOnChoice.load(taskId: t.id) == nil ? "Choose hosts" : "Saved scope", symbol: "checklist", keywords: "task check") {
                c.commands.runOnTask = TaskRunOnRequest(task: t, autoStart: TaskRunOnChoice.load(taskId: t.id) != nil)
            }
        }
        out += selectionActions(c)
        out += c.workspaces.items.map { ws in
            PaletteEntry(id: "ws:\(ws.id)", kind: .workspace, title: "Open Workspace “\(ws.name)”",
                         detail: ws.tabs.count == 1 ? "1 session" : "\(ws.tabs.count) sessions", symbol: Icons.symbol("workspace")) {
                c.workspaces.open(ws.id, commands: c.commands)
            }
        }
        out += c.commands.sessions.tabs.map { tab in
            PaletteEntry(id: "tab:\(tab.id)", kind: .tab, title: "Show Tab “\(tab.title)”", detail: "Open session", symbol: tab.symbol) {
                c.commands.sessions.selected = tab.id
            }
        }
        out += connections(c)
        out += c.settings.definitions.filter { $0.kind != "link" }.map { def in
            let category = c.settings.categories.first { $0.id == def.category }?.label ?? ""
            return PaletteEntry(id: "set:\(def.id)", kind: .setting, title: def.label, detail: "Settings › \(category)",
                                symbol: "gearshape", keywords: def.help) {
                c.router.open("settings-search:\(def.label)")
            }
        }
        return out
    }

    /// The core's menu for the selected node, enabled entries only.
    private static func selectionActions(_ c: Context) -> [PaletteEntry] {
        guard let id = c.selection else { return [] }
        let name = c.commands.model.connection(id: id)?.name ?? c.commands.model.folder(id: id)?.name ?? ""
        return c.commands.menu(for: id).filter(\.enabled).flatMap { item -> [PaletteEntry] in
            let symbol = Icons.actionSymbols[item.glyph] ?? "circle"
            let choices = c.commands.submenu(for: item, on: id).filter(\.enabled)
            guard choices.isEmpty else {
                // A submenu (Add to Workspace) becomes one entry per choice.
                return choices.map { choice in
                    let target = choice.title.replacingOccurrences(of: "…", with: "")
                    return PaletteEntry(id: "act:\(item.id):\(choice.title)", kind: .action, title: "\(item.label) › \(target) — \(name)",
                                        detail: "Selection", symbol: symbol, run: choice.run)
                }
            }
            return [PaletteEntry(id: "act:\(item.id)", kind: .action, title: item.label.replacingOccurrences(of: "…", with: "") + " — \(name)",
                                 detail: "Selection", symbol: symbol) {
                c.commands.perform(item, on: id)
            }]
        }
    }

    private static func connections(_ c: Context) -> [PaletteEntry] {
        guard let tree = c.commands.model.tree else { return [] }
        func walk(_ f: FolderView, _ path: String) -> [PaletteEntry] {
            f.connections.map { conn in
                PaletteEntry(id: "conn:\(conn.id)", kind: .connection, title: conn.name, detail: conn.host,
                             symbol: Icons.symbol(conn.protocol), keywords: "\(path) \(Icons.info(conn.protocol).label)") {
                    c.select(conn.id)
                    c.commands.performDefault(on: conn.id)
                }
            } + f.folders.flatMap { walk($0, "\(path) \($0.name)") }
        }
        return walk(tree, "")
    }

}

/// ⇧⌘P: type to filter, ↑/↓ to move, Return to run, Escape to close. Filtering and ranking are
/// the core's (`palette.rs`), indexed once per opening.
struct CommandPaletteView: View {
    let entries: [PaletteEntry]
    private let index: PaletteIndex?
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""
    @State private var highlighted = 0
    @FocusState private var focused: Bool

    private static let maxRows: UInt32 = 60

    init(entries: [PaletteEntry]) {
        self.entries = entries
        index = try? PaletteIndex(entries: entries.map(\.input))
    }

    private var shown: [PaletteEntry] {
        (index?.rank(query: query, limit: Self.maxRows) ?? []).compactMap { entries.indices.contains(Int($0)) ? entries[Int($0)] : nil }
    }

    var body: some View {
        let rows = shown
        VStack(spacing: 0) {
            HStack(spacing: DS.Space.xs) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Commands, connections, workspaces, settings", text: $query)
                    .textFieldStyle(.plain)
                    .font(DS.Font.title3)
                    .focused($focused)
                    .onSubmit { run(rows) }
                    .onKeyPress(.downArrow) { move(1, rows.count) }
                    .onKeyPress(.upArrow) { move(-1, rows.count) }
                    .onExitCommand { dismiss() }
                    .onChange(of: query) { highlighted = 0 }
            }
            .padding(DS.Space.s)
            Divider()
            if rows.isEmpty {
                Text("No matches").foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 60)
            } else {
                ScrollViewReader { proxy in
                    // At most `maxRows`, so a plain stack; rows are identified by entry, never by
                    // position, so a filtered list never shows a previous row's content.
                    ScrollView {
                        VStack(spacing: 0) {
                            ForEach(Array(rows.enumerated()), id: \.element.id) { index, entry in
                                PaletteRow(entry: entry, isHighlighted: index == highlighted)
                                    .onTapGesture { highlighted = index; run(rows) }
                            }
                        }
                        .padding(DS.Space.xxs)
                    }
                    .frame(height: DS.Size.paletteRows)
                    .onChange(of: highlighted) { _, i in
                        if rows.indices.contains(i) { proxy.scrollTo(rows[i].id) }
                    }
                }
            }
        }
        .frame(width: DS.Size.paletteWidth)
        .onAppear { focused = true }
    }

    private func move(_ by: Int, _ count: Int) -> KeyPress.Result {
        guard count > 0 else { return .handled }
        highlighted = (highlighted + by + count) % count
        return .handled
    }

    private func run(_ rows: [PaletteEntry]) {
        guard rows.indices.contains(highlighted) else { return }
        let entry = rows[highlighted]
        dismiss()
        // Let the palette close first so sheets it opens can present.
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(250))
            entry.run()
        }
    }
}

private struct PaletteRow: View {
    let entry: PaletteEntry
    let isHighlighted: Bool

    var body: some View {
        HStack(spacing: DS.Space.xs) {
            Image(systemName: entry.symbol)
                .frame(width: DS.Space.m)
                .foregroundStyle(isHighlighted ? .primary : .secondary)
            Text(entry.title).lineLimit(1)
            Spacer(minLength: DS.Space.s)
            Text(entry.detail).font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1)
        }
        .padding(.horizontal, DS.Space.xs)
        .frame(height: 26)
        .background(isHighlighted ? Color.accentColor.opacity(0.18) : .clear, in: RoundedRectangle(cornerRadius: 5))
        .contentShape(Rectangle())
    }
}
