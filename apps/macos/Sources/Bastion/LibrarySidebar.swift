import SwiftUI
import BastionCore

/// Connection types that have Default Settings, in menu order (types that can be created).
let defaultSettingTypes: [(protocolName: String, label: String)] = [
    ("ssh", "SSH Terminal"), ("rdp", "Remote Desktop"), ("vnc", "VNC"), ("web", "Web Page"),
]

/// Left region: the filter field and the navigation tree (Favorites, then the library).
struct LibrarySidebar: View {
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @Environment(\.chromeTones) private var tones
    @Environment(AppRouter.self) private var router
    @Environment(ShortcutsModel.self) private var shortcuts
    @Environment(SettingsModel.self) private var settings
    /// The selection object, not a binding: a binding was read while SwiftUI compared inputs, so
    /// every tree click re-ran the window's body and this one (MAC-SELECT-SPEED).
    let sel: LibrarySelection
    @Binding var search: String
    let commands: Commands
    /// ⌥⌘F focus for the Compact search field (Classic's system search takes `searchFocused`).
    var searchFocus: FocusState<Bool>.Binding? = nil

    private var compact: Bool { HeaderStyle.isCompact(settings) }

    private var isFilterEmpty: Bool {
        guard !search.isEmpty, let tree = model.tree else { return false }
        return !OutlineNode.anyMatch(in: tree, filter: search)
            && !sessionRows.byConnection.values.joined().contains { $0.matches(search) }
            && !sessionRows.other.contains { $0.matches(search) }
    }

    /// Open sessions for the tree (UI-05). Only a connection the library still has keeps its rows.
    private var sessionRows: SessionRows {
        sessions.sessionRows { model.connection(id: $0) != nil }
    }

    /// Royal TS keeps the panel's collapse button at its foot; the menu item and ⌃⌘S do the same.
    private var bottomBar: some View {
        VStack(spacing: 0) {
            Divider()
            HStack {
                TipsLine(panel: .library)
                Spacer(minLength: 0)
                Button("Hide Library", systemImage: "sidebar.left") { router.open("toggle-library") }
                    .labelStyle(.iconHitTarget)
                    .buttonStyle(.borderless)
                    .help(shortcuts.help("Hide the library", "toggle-library"))
            }
            .padding(.horizontal, DS.Space.s)
            .padding(.vertical, DS.Space.xxs)
        }
    }

    /// Compact header: search sits at the top of the sidebar. Return on a search that matches
    /// nothing in the tree connects to it, as typed, through Quick Connect (the header has no
    /// Connect or Quick Connect button).
    private var compactSearch: some View {
        TextField("Search or connect", text: $search, prompt: Text("Search or connect"))
            .textFieldStyle(.roundedBorder)
            .onSubmit {
                guard isFilterEmpty else { return }
                commands.quickConnectPrefill = search.trimmingCharacters(in: .whitespaces)
                router.open("quick-connect")
            }
            .onExitCommand { search = "" }
            .help("Name, address, user or tag. tag:name keeps only connections with that tag.")
            .accessibilityIdentifier("library-search")
            .modifier(OptionalFocus(focus: searchFocus))
            .padding(.horizontal, 8)
            .padding(.top, 6)
            // Tones off: no surface of its own. The column's surface shows through, as under the tree
            // (a second `.sidebar` material drew #E5E5E7 over the #F1F1F1 column, nm-colour-match).
            .background { if let tones { tones.sidebar } }
    }

    var body: some View {
        let _ = RenderCount.hit("LibrarySidebar")
        SidebarOutline(sel: sel, search: search, commands: commands)
            .safeAreaInset(edge: .top, spacing: 0) {
                VStack(spacing: 0) {
                    if compact { compactSearch }
                    DocumentStrip()
                }
            }
            .modifier(ClassicSearch(compact: compact, search: $search))
            .background(SizeReporter { sessions.sidebarResized($0.width) })
            .modifier(CompactSidebarHeader(compact: compact))
            .overlay {
                if isFilterEmpty { ContentUnavailableView.search(text: search) }
            }
            .safeAreaInset(edge: .bottom, spacing: 0) { VStack(spacing: 0) { CredentialsSection(); bottomBar } }
            .modifier(ChromeSurface(tone: \.sidebar))
            .background { if TestHooks.isScripted { DriverFrame(name: "library-sidebar") } }
            // A plugin tree's menu choice may ask to open a connection: the core's sheet, as in the tab.
            .sheet(item: Binding(get: { commands.pluginSidebar.openRequestOwner?.openRequest },
                                 set: { if $0 == nil, let r = commands.pluginSidebar.openRequestOwner?.openRequest {
                                     commands.pluginSidebar.answerOpen(accept: false, route: r.route, saveAsEntry: false) } })) { r in
                PluginOpenSheet(request: r) { accept, route, save in commands.pluginSidebar.answerOpen(accept: accept, route: route, saveAsEntry: save) }
            }
            .sheet(item: Binding(get: { commands.pluginSidebar.libraryRequestOwner?.libraryRequest },
                                 set: { if $0 == nil, commands.pluginSidebar.libraryRequestOwner?.libraryRequest != nil {
                                     commands.pluginSidebar.answerLibrary(saved: nil, credentialLinked: false) } })) { r in
                PluginSaveConnectionsSheet(request: r) { saved, cred in commands.pluginSidebar.answerLibrary(saved: saved, credentialLinked: cred) }
            }
    }
}

/// The tree with its open-session rows. It reads the tabs in its own body, so a tab opening or
/// closing re-runs only this view, not the sidebar's chrome and its toolbar item.
private struct SidebarOutline: View {
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @Environment(\.density) private var density
    @Environment(AppearanceSettings.self) private var appearance
    @Environment(\.chromeTones) private var tones
    let sel: LibrarySelection
    let search: String
    let commands: Commands

    var body: some View {
        let _ = RenderCount.hit("SidebarOutline")
        let metrics = themeMetrics(density: density.rawValue)
        LibraryOutline(tree: model.tree, treeVersion: model.treeVersion, tasks: model.tasks, filter: search, sessions: sessions.snapshot,
                       sessionRows: sessions.sessionRows { model.connection(id: $0) != nil }, dynamic: commands.dynamic.rows,
                       plugin: PluginSidebarRows(byEntry: commands.pluginSidebar.rows.byEntry,
                                                 types: Set(PluginEntries.types.filter(\.sidebarTree).map(\.id))),
                       expansionVersion: commands.tree.version, rowHeight: (CGFloat(metrics.treeRow) * DS.Font.zoom).rounded(), iconSize: (CGFloat(metrics.treeIcon) - 2) * DS.Font.zoom,
                       indent: metrics.treeIndent, accent: tones.map { $0.accentUsable ? NSColor(appearance.accent.color) : $0.nsText } ?? NSColor(appearance.accent.color), sel: sel, commands: commands)
    }
}

/// Classic keeps the system sidebar search ("Filter"); Compact draws its own field instead.
private struct ClassicSearch: ViewModifier {
    let compact: Bool
    @Binding var search: String
    func body(content: Content) -> some View {
        if compact { content } else { content.searchable(text: $search, placement: .sidebar, prompt: "Filter") }
    }
}

private struct OptionalFocus: ViewModifier {
    let focus: FocusState<Bool>.Binding?
    func body(content: Content) -> some View {
        if let focus { content.focused(focus) } else { content }
    }
}
