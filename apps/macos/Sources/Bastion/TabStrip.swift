import SwiftUI
import BastionCore

// The session tab strip (Edge-style): tabs shrink to `DS.Size.tabMin`, then the strip scrolls
// with ‹ ›; the selected tab is kept in view; ⇧⌘A lists every tab; tab groups are coloured,
// named, collapsible runs. Group rules (contiguity, folder auto-grouping, close group) live in
// the core (`tabgroups.rs`); the strip crosses as JSON and comes back through `adopt`.

/// A tab group as the core sends it.
struct StripGroup: Codable, Identifiable, Equatable {
    let id: String
    var name: String
    var color: String
    var collapsed: Bool
    /// The folder of an automatic group.
    var folder: String?

    static let colors: [(id: String, label: String)] = tabGroupColors().map { ($0[0], $0[1]) }

    /// Text on a solid chip of `id`: dark on the light colours, white on the rest.
    static func ink(_ id: String) -> Color {
        ["yellow", "cyan", "grey"].contains(id) ? .black.opacity(0.85) : .white
    }

    static func tint(_ id: String) -> Color {
        switch id {
        case "blue": .blue
        case "red": .red
        case "yellow": .yellow
        case "green": .green
        case "pink": .pink
        case "purple": .purple
        case "cyan": .cyan
        default: .gray
        }
    }
}

struct StripState: Codable {
    struct Tab: Codable {
        let id: String
        var connection: String?
        var group: String?
        var detached: Bool?
    }
    var tabs: [Tab]
    var groups: [StripGroup]
}

private struct StripChange: Codable {
    let strip: StripState
    let closed: [String]
}

extension SessionsModel {
    var stripState: StripState {
        StripState(tabs: tabs.map { tab in
            // Quick Connect tabs belong to a throwaway library: no folder, so no auto-group.
            StripState.Tab(id: tab.id.uuidString, connection: tab.connectionId.flatMap { UUID(uuidString: $0) == nil ? nil : $0 },
                           group: tab.group, detached: tab.detached)
        }, groups: groups)
    }

    func group(_ id: String) -> StripGroup? { groups.first { $0.id == id } }

    /// Hidden in the strip: its group is collapsed and it is not the selected tab.
    func isHidden(_ tab: TerminalTab) -> Bool {
        tab.id != selected && (tab.group.flatMap(group)?.collapsed ?? false)
    }

    /// One strip operation (`{"op": "newGroup", …}`, see `StripOp` in the core).
    func groupOp(_ op: [String: Any]) {
        do {
            let opJson = String(decoding: try JSONSerialization.data(withJSONObject: op), as: UTF8.self)
            let out = try tabStripApply(stripJson: try encodedStrip(), opJson: opJson)
            let change = try JSONDecoder().decode(StripChange.self, from: Data(out.utf8))
            adopt(change.strip, closing: change.closed)
            regroup()
        } catch {
            self.error = "The tab groups could not be changed: \(error.userMessage)"
        }
    }

    /// Folder auto-grouping after tabs open or close (setting `tabs.auto-group`).
    func regroup() {
        guard let autoGroup, !tabs.isEmpty, let json = try? encodedStrip(), let out = autoGroup(json),
              let strip = try? JSONDecoder().decode(StripState.self, from: Data(out.utf8)) else { return }
        adopt(strip)
    }

    private func encodedStrip() throws -> String {
        String(decoding: try JSONEncoder().encode(stripState), as: UTF8.self)
    }

    /// Selecting a tab in a collapsed group expands the group.
    func reveal(_ tab: TerminalTab) {
        selected = tab.id
        if let g = tab.group.flatMap(group), g.collapsed { groupOp(["op": "setCollapsed", "group": g.id, "collapsed": false]) }
    }

    /// Workspace open: tabs reconnect one by one; each joins its saved group as it arrives.
    func expectGroups(_ ws: WorkspaceView) {
        pendingGroupDefs = (try? JSONDecoder().decode([StripGroup].self, from: Data(ws.groupsJson.utf8))) ?? []
        pendingGroups = [:]
        for (tab, group) in zip(ws.tabs, ws.tabGroups) {
            guard let group else { continue }
            pendingGroups[tab.connectionId, default: []].append(group)
        }
    }
}

/// What the strip shows, in order: a group's label before its first tab, then its tabs unless
/// it is collapsed.
private enum StripItem: Identifiable {
    case label(StripGroup)
    case tab(TerminalTab)

    var id: String {
        switch self {
        case .label(let g): "group-" + g.id
        case .tab(let t): t.id.uuidString
        }
    }

    var isTab: Bool {
        if case .tab = self { return true }
        return false
    }
}

@MainActor
private func stripItems(_ sessions: SessionsModel) -> [StripItem] {
    var items: [StripItem] = []
    var last: String?
    for tab in sessions.mainTabs where !tab.pinned {
        if let gid = tab.group, gid != last, let g = sessions.group(gid) { items.append(.label(g)) }
        last = tab.group
        if !sessions.isHidden(tab) { items.append(.tab(tab)) }
    }
    return items
}

/// The open tabs in the window toolbar's leading segment, so the window has no separate tab row.
/// Width of the toolbar tab strip for a session area: everything but the trailing items, never
/// under 96 pt (two arrows and the All Tabs button).
func stripWidth(sessionArea: CGFloat, neighbours: CGFloat) -> CGFloat {
    max(96, sessionArea - neighbours)
}

struct SessionTabStrip: View {
    @Environment(SessionsModel.self) private var sessions
    @Environment(SettingsModel.self) private var settings
    @Environment(AppRouter.self) private var router
    @Environment(ShortcutsModel.self) private var shortcuts
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Index of the tab the ‹ › arrows last scrolled to.
    @State private var scrollIndex = 0

    /// Room one icon control takes: + after the tabs, and each ‹ › arrow when the tabs scroll.
    private static let control: CGFloat = DS.Size.minHitTarget + 4
    /// The other toolbar items in the session area: open sessions and + on the leading edge;
    /// Find, Quick Connect, Connect, Split and the inspector toggle on the trailing edge.
    private static let neighbours: CGFloat = 380
    /// Compact header: only the tab group button before the tabs and the inspector toggle after.
    private static let compactNeighbours: CGFloat = 140

    /// The strip takes all the room the session area's toolbar has (owner UX spec 2026-11-04 §4:
    /// tabs fill the bar, actions on the right). A fixed width, not a flexible one: NSToolbar moves
    /// an item that does not fit into the » menu rather than shrinking it.
    // The same width with or without tabs: a width change from 0 meant a new toolbar item
    // identity, and SwiftUI rebuilt the whole toolbar on the first tab and the last close (nm-22).
    private var idealWidth: CGFloat {
        max(Self.minWidth, Self.width(forArea: sessions.sessionAreaWidth, sessions: sessions, settings: settings) - sessions.stripSqueeze) + Self.testSlack
    }

    /// The strip's width for a session area width.
    static func width(forArea area: CGFloat, sessions: SessionsModel, settings: SettingsModel) -> CGFloat {
        stripWidth(sessionArea: area, neighbours: HeaderStyle.isCompact(settings) ? compactNeighbours + sessions.compactLeading : neighbours)
    }
    /// UI driver only (`strip-slack`): makes the strip ask for more room than the bar has, as a
    /// full-screen top-edge hover does, to prove the toolbar shrinks it instead of using ».
    @MainActor static var testSlack: CGFloat = 0
    /// The least the strip takes: ‹ › and +. Below its ideal width NSToolbar now shrinks it to
    /// this before it moves any item into the » menu. A fixed width could not shrink: whenever the
    /// bar had less room than the budget guessed (full-screen hover, owner round 3, item 16), the
    /// trailing item went into » and the round » button appeared.
    static let minWidth: CGFloat = 96

    var body: some View {
        let _ = RenderCount.hit("TabStrip")
        if sessions.mainTabs.isEmpty {
            if HeaderStyle.isCompact(settings) {
                // Compact: + stays where the tabs would be, so a new tab is one click away.
                HStack(spacing: 0) { homeButton; newTabButton; paletteButton; Spacer(minLength: 0) }
                    .frame(minWidth: Self.minWidth, idealWidth: idealWidth, maxWidth: idealWidth, minHeight: 28, maxHeight: 28).id(Int(idealWidth / 8))
            } else {
                Color.clear.frame(minWidth: Self.minWidth, idealWidth: idealWidth, maxWidth: idealWidth, minHeight: 28, maxHeight: 28).id(Int(idealWidth / 8)).accessibilityHidden(true)
            }
        } else if settings.value("tabs.vertical") == "true" {
            allTabsButton
        } else {
            // A fixed width worked out from the session area: NSToolbar moved a flexible strip
            // with many tabs (its ScrollView reports the width of every tab) into the » menu.
            // Laid out for the width the toolbar gives, which can be less than the ideal.
            GeometryReader { g in strip(width: max(Self.minWidth, g.size.width)) }
                .frame(minWidth: Self.minWidth, idealWidth: idealWidth, maxWidth: idealWidth, minHeight: 28, maxHeight: 28, alignment: .leading)
                .accessibilityElement(children: .contain)
                .accessibilityLabel("Session tabs")
                // NSToolbar keeps an item's first measured size when it grows: a new identity per
                // 8 pt step of the room makes it measure the strip again on a window resize.
                .id(Int(idealWidth / 8))
        }
    }

    private func strip(width: CGFloat) -> some View {
        let items = stripItems(sessions)
        let tabIds = items.compactMap { item -> UUID? in if case .tab(let t) = item { return t.id } else { return nil } }
        let pinned = sessions.mainTabs.filter(\.pinned)
        let pinnedWidth = pinned.isEmpty ? 0 : CGFloat(pinned.count) * (DS.Size.pinnedTab + 2) + 10
        let labels = items.reduce(CGFloat(0)) { sum, item in
            if case .label(let g) = item { return sum + GroupLabel.width(g, count: sessions.tabs.filter { $0.group == g.id }.count) + 2 }
            return sum
        }
        // + always, right after the last tab; ‹ › only when the tabs scroll. The tab switcher on the
        // left lists every tab (⇧⌘A too), so the strip has no ⌄ button of its own.
        // Home, + and the palette button.
        let fixed = 3 * Self.control + pinnedWidth
        // Tabby: each tab as wide as its full title, packed to the leading edge; when they pass the
        // room the widest shrink evenly (ellipsis, full title in the help) down to tabMin, then the
        // strip scrolls (owner feedback 12, 2026-11-07; no fixed cap, owner 2026-11-16).
        let natural = items.compactMap { item -> CGFloat? in if case .tab(let t) = item { return TabButton.contentWidth(t) } else { return nil } }
        let room = width - fixed - labels - CGFloat(natural.count) * 2
        let cap = TabButton.shareCap(natural, room: room, floor: DS.Size.tabMin)
        let tabsWidth = natural.reduce(CGFloat(0)) { $0 + min($1, cap ?? .infinity) + 2 }
        let fits = tabsWidth <= width - fixed - labels
        let scrollWidth = fits ? tabsWidth + labels : max(0, width - fixed - 2 * Self.control)
        // No room for even one tab beside ‹ › + (the 96 pt minimum strip): only +; the tab
        // switcher lists every tab. The controls overlapped the next toolbar item.
        let tabsShown = fits || scrollWidth >= DS.Size.minHitTarget * 2
        return ScrollViewReader { proxy in
            HStack(spacing: 2) {
                homeButton
                ForEach(pinned) { tab in
                    TabButton(tab: tab, isSelected: tab.id == sessions.selected,
                              select: { sessions.selected = tab.id }, close: { sessions.requestClose(tab) }, compact: true)
                        .tabHoverPreview(tab, isSelected: tab.id == sessions.selected)
                        .id(tab.id.uuidString)
                        .transition(insertRemove)
                }
                if !pinned.isEmpty { Divider().frame(height: 16) }
                if tabsShown {
                if !fits { arrow("chevron.left", step: -3, ids: tabIds, proxy: proxy) }
                ScrollView(.horizontal, showsIndicators: false) {
                    // Not lazy: scrollTo must reach a tab whose button was never on screen (the
                    // selected tab is always kept in view).
                    HStack(spacing: 2) {
                        ForEach(items) { item in
                            switch item {
                            case .label(let g): GroupLabel(group: g)
                            case .tab(let tab): button(tab, cap: cap).transition(insertRemove)
                            }
                        }
                    }
                    .animation(DS.Motion.spring(reduced: reduceMotion), value: sessions.tabs.map(\.id))
                }
                // The horizontal scroll view stopped ~22 pt short of the last tab's end.
                .contentMargins(.trailing, fits ? 0 : 24, for: .scrollContent)
                .frame(width: scrollWidth)
                .background(DriverFrame(name: "tab-viewport"))
                // A resize gives the strip a new identity (see `body`); the new scroll view starts
                // at the first tab, so bring the selected one back into view (it was left clipped
                // to its close button at narrow widths).
                .onAppear {
                    guard let id = sessions.selected else { return }
                    DispatchQueue.main.async { proxy.scrollTo(id.uuidString, anchor: .center) }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { proxy.scrollTo(id.uuidString, anchor: .center) }
                }
                .onChange(of: sessions.selected) { _, id in
                    guard let id else { return }
                    withAnimation(DS.Motion.spring(reduced: reduceMotion)) { proxy.scrollTo(id.uuidString, anchor: .center) }
                }
                // A burst of new tabs (a workspace opening) selects before their buttons exist;
                // a group label, a pin or a collapse moves the selected tab too.
                .onChange(of: "\(items.count)-\(pinned.count)-\(Int(scrollWidth))") {
                    guard let id = sessions.selected else { return }
                    // Twice: the lazy stack builds the new buttons over the next layout passes.
                    DispatchQueue.main.async { proxy.scrollTo(id.uuidString, anchor: .center) }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { proxy.scrollTo(id.uuidString, anchor: .center) }
                }
                if !fits { arrow("chevron.right", step: 3, ids: tabIds, proxy: proxy) }
                }
                newTabButton
                paletteButton
            }
            .animation(DS.Motion.spring(reduced: reduceMotion), value: sessions.groups)
        }
    }

    private func button(_ tab: TerminalTab, cap: CGFloat?) -> some View {
        TabButton(tab: tab, isSelected: tab.id == sessions.selected,
                  select: { sessions.selected = tab.id }, close: { sessions.requestClose(tab) },
                  width: min(TabButton.contentWidth(tab), cap ?? .infinity))
            // Test hooks only: each strip tab's laid-out frame for the driver's `tab-titles` report.
            .background { if TestHooks.isScripted { DriverFrame(name: "strip-tab-" + tab.id.uuidString) } }
            .tabHoverPreview(tab, isSelected: tab.id == sessions.selected)
            .background { if tab.id == sessions.selected { DriverFrame(name: "active-tab") } }
            .id(tab.id.uuidString)
            .tabDragAndDrop(tab, sessions: sessions)
    }

    private func arrow(_ symbol: String, step: Int, ids: [UUID], proxy: ScrollViewProxy) -> some View {
        Button {
            guard !ids.isEmpty else { return }
            scrollIndex = min(max(scrollIndex + step, 0), ids.count - 1)
            withAnimation(DS.Motion.spring(reduced: reduceMotion)) { proxy.scrollTo(ids[scrollIndex].uuidString, anchor: .leading) }
        } label: {
            Image(systemName: symbol).iconHitTarget()
        }
        .buttonStyle(.borderless)
        .help(step < 0 ? "Scroll tabs left" : "Scroll tabs right")
    }

    /// Tabs grow from nothing and fade (Safari); a plain fade under Reduce Motion.
    private var insertRemove: AnyTransition {
        reduceMotion ? .opacity : .scale(scale: 0.6, anchor: .leading).combined(with: .opacity)
    }

    /// + at the end of the tabs: a new local shell at once (⌘T), never a menu (owner 2026-11-17).
    /// New Connection and New Folder stay in the menu bar, the library and the palette.
    private var newTabButton: some View {
        Button { sessions.openLocal() } label: { Image(systemName: "plus").iconHitTarget() }
            .buttonStyle(.borderless)
            .help(shortcuts.help("New Local Shell", "local-shell"))
            .accessibilityLabel("New Tab")
            .background(DriverFrame(name: "new"))
            // Dropped past the last tab: the tab goes to the end of the strip, out of any group.
            .onDrop(of: [TabDrag.type], isTargeted: nil) { TabDrag.dropAtEnd($0, sessions: sessions) }
    }

    /// At the start of the strip: Home, the Start page with recent sessions (owner round 2, item 6).
    private var homeButton: some View {
        // The same neutral toolbar button as the open-sessions button beside it (owner 2026-11-23).
        ToolbarSymbolButton(symbol: "house", label: "Home", help: "Home (⇧⌘H)") { [router] in router.open("home") }
            .fixedSize()
            .background(DriverFrame(name: "home"))
    }

    /// Beside +: the command palette (owner 2026-11-17).
    private var paletteButton: some View {
        Button { router.open("palette") } label: { Image(systemName: "command").iconHitTarget() }
            .buttonStyle(.borderless)
            .help(shortcuts.help("Command Palette", "palette"))
            .accessibilityLabel("Command Palette")
    }

    private var allTabsButton: some View {
        Button { sessions.showingAllTabs.toggle() } label: { Image(systemName: "chevron.down").iconHitTarget() }
            .buttonStyle(.borderless)
            .help("All Tabs (⇧⌘A)")
    }
}

/// Where the All Tabs list opens: the top centre of the session area.
struct AllTabsAnchor: View {
    @Environment(SessionsModel.self) private var sessions

    var body: some View {
        @Bindable var sessions = sessions
        Color.clear.frame(width: 1, height: 0)
            .popover(isPresented: $sessions.showingAllTabs, arrowEdge: .top) { AllTabsList { sessions.showingAllTabs = false } }
    }
}

/// ⇧⌘A: every open tab, searchable by title, host title or group name, in strip order.
struct AllTabsList: View {
    @Environment(SessionsModel.self) private var sessions
    let done: () -> Void
    @State private var query = ""
    @FocusState private var focused: Bool

    private var matches: [TerminalTab] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return sessions.tabs }
        return sessions.tabs.filter { tab in
            [tab.title, TabTitle.sanitized(tab.remoteTitle) ?? "", tab.group.flatMap(sessions.group)?.name ?? ""].contains { $0.localizedCaseInsensitiveContains(q) }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            TextField("Search \(sessions.tabs.count) tabs", text: $query)
                .textFieldStyle(.roundedBorder)
                .focused($focused)
                .onSubmit { if let first = matches.first { pick(first) } }
            List(matches) { tab in
                Button { pick(tab) } label: {
                    HStack(spacing: DS.Space.xs) {
                        Image(systemName: tab.symbol)
                        Text(tab.title).lineLimit(1)
                        Spacer()
                        if let g = tab.group.flatMap(sessions.group) {
                            Text(g.name.isEmpty ? "Group" : g.name).font(DS.Font.caption).foregroundStyle(StripGroup.tint(g.color))
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .listRowBackground(tab.id == sessions.selected ? Color.accentColor.opacity(0.15) : .clear)
            }
            .listStyle(.plain)
        }
        .padding(DS.Space.s)
        .frame(width: 320, height: 380)
        .onAppear { focused = true }
    }

    private func pick(_ tab: TerminalTab) {
        sessions.reveal(tab)
        done()
    }
}

/// Vertical tabs setting: the strip as a list down the side of the session area.
struct VerticalTabList: View {
    // The ⌄ All Tabs button stays in the toolbar with vertical tabs (`SessionTabStrip`).
    @Environment(SessionsModel.self) private var sessions
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(stripItems(sessions)) { item in
                        switch item {
                        case .label(let g): GroupLabel(group: g)
                        case .tab(let tab):
                            TabButton(tab: tab, isSelected: tab.id == sessions.selected,
                                      select: { sessions.selected = tab.id }, close: { sessions.requestClose(tab) },
                                      width: DS.Size.verticalTabs - DS.Space.m)
                                .id(tab.id.uuidString)
                                .tabDragAndDrop(tab, sessions: sessions)
                        }
                    }
                }
                .padding(DS.Space.xs)
            }
            .onChange(of: sessions.selected) { _, id in
                guard let id else { return }
                withAnimation(DS.Motion.spring(reduced: reduceMotion)) { proxy.scrollTo(id.uuidString, anchor: .center) }
            }
            .animation(DS.Motion.spring(reduced: reduceMotion), value: sessions.groups)
        }
        .background(.bar)
        .modifier(ChromeSurface(tone: \.tabStrip))
    }
}

/// A group's chip, as in Chrome and Edge: the user's group name on a solid chip in the group
/// colour (a dot when it has no name) before its tabs. Click collapses or expands the group at
/// once; right-click opens the group editor (name, colour, ungroup, close). Drop a tab on it to
/// add the tab (owner 2026-11-17).
struct GroupLabel: View {
    @Environment(SessionsModel.self) private var sessions
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let group: StripGroup
    @State private var dropTargeted = false

    private var memberCount: Int { sessions.tabs.filter { $0.group == group.id }.count }

    private static let padding: CGFloat = 7
    private static let maxWidth: CGFloat = 160

    /// The chip's laid-out width, so the strip can place + right after the last tab.
    static func width(_ g: StripGroup, count: Int) -> CGFloat {
        // The chip's own text size: caption times the UI zoom (`DS.Font.caption`).
        let font = NSFont.systemFont(ofSize: DS.Font.points(.caption) * DS.Font.zoom, weight: .semibold)
        func measure(_ s: String) -> CGFloat { ceil((s as NSString).size(withAttributes: [.font: font]).width) }
        var w = g.name.isEmpty ? 6 : measure(g.name)
        if g.collapsed { w += 4 + measure("\(count)") }
        return min(max(w + 2 * padding, DS.Size.minHitTarget), maxWidth)
    }

    var body: some View {
        let tint = StripGroup.tint(group.color)
        let ink = StripGroup.ink(group.color)
        HStack(spacing: DS.Space.xxs) {
            if group.name.isEmpty {
                Circle().fill(ink).frame(width: 6, height: 6)
            } else {
                Text(group.name).font(DS.Font.caption.weight(.semibold)).lineLimit(1).truncationMode(.tail)
            }
            // Collapsed, the chip says how many tabs it hides.
            if group.collapsed { Text("\(memberCount)").font(DS.Font.caption2.weight(.semibold)).monospacedDigit().opacity(0.8) }
        }
        .padding(.horizontal, Self.padding)
        .frame(minWidth: DS.Size.minHitTarget, maxWidth: Self.maxWidth, minHeight: 20)
        .foregroundStyle(ink)
        .background(tint.opacity(dropTargeted ? 0.75 : 1), in: RoundedRectangle(cornerRadius: 6))
        .frame(height: 26)
        .contentShape(Rectangle())
        .onTapGesture(perform: toggle)
        // Right-click: the editor, not a menu (Chrome). Transparent to every other click.
        .background { TabMenuAnchor(action: { [sessions] in sessions.editingGroup = group.id }) }
        .popover(isPresented: Binding(get: { sessions.editingGroup == group.id },
                                      set: { if !$0, sessions.editingGroup == group.id { sessions.editingGroup = nil } }),
                 arrowEdge: .bottom) {
            GroupEditor(group: group, toggle: toggle).environment(sessions)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Tab group \(group.name.isEmpty ? "unnamed" : group.name), \(memberCount) tabs, \(group.collapsed ? "collapsed" : "expanded")")
        .accessibilityAddTraits(.isButton)
        .accessibilityAction(named: "Edit Group") { sessions.editingGroup = group.id }
        .accessibilityAction(named: group.collapsed ? "Expand" : "Collapse", toggle)
        .help((group.collapsed ? "Expand group" : "Collapse group") + "; right-click to edit")
        // Tabs drag as `TabDrag.type` (their uuid), not as plain strings.
        .onDrop(of: [TabDrag.type], isTargeted: $dropTargeted) { TabDrag.dropInto(group: group.id, $0, sessions: sessions) }
    }

    private func toggle() {
        withAnimation(DS.Motion.spring(reduced: reduceMotion)) {
            sessions.groupOp(["op": "setCollapsed", "group": group.id, "collapsed": !group.collapsed])
        }
    }
}

/// Chrome's group editor: "Name this group", a row of colour dots, then collapse, ungroup and
/// close. The name is saved on Return and when the popover closes; a colour at once.
private struct GroupEditor: View {
    @Environment(SessionsModel.self) private var sessions
    let group: StripGroup
    let toggle: () -> Void
    @State private var name = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            TextField("Name this group", text: $name)
                .textFieldStyle(.roundedBorder)
                .focused($focused)
                .onSubmit { saveName(); sessions.editingGroup = nil }
                .accessibilityLabel("Group name")
            HStack(spacing: DS.Space.xxs) {
                ForEach(StripGroup.colors, id: \.id) { c in
                    ColorDot(id: c.id, label: c.label, selected: c.id == current.color) {
                        sessions.groupOp(["op": "recolor", "group": group.id, "color": c.id])
                    }
                }
            }
            Divider()
            HStack(spacing: DS.Space.s) {
                Button(current.collapsed ? "Expand" : "Collapse") { saveName(); sessions.editingGroup = nil; toggle() }
                Button("Ungroup") { sessions.editingGroup = nil; sessions.groupOp(["op": "ungroup", "group": group.id]) }
                Spacer(minLength: 0)
                Button("Close Group") { sessions.editingGroup = nil; sessions.groupOp(["op": "closeGroup", "group": group.id]) }
            }
            .controlSize(.small)
            Button("Move Group to New Window") { sessions.editingGroup = nil; sessions.moveGroupToWindow(group.id) }
                .buttonStyle(.link)
                .controlSize(.small)
        }
        .padding(DS.Space.m)
        .frame(width: 300)
        .onAppear { name = group.name; focused = true }
        .onDisappear(perform: saveName)
    }

    /// The group as it is now (a recolour replaces the strip's copy).
    private var current: StripGroup { sessions.group(group.id) ?? group }

    private func saveName() {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard let g = sessions.group(group.id), trimmed != g.name else { return }
        sessions.groupOp(["op": "rename", "group": group.id, "name": trimmed])
    }
}

/// One colour in the group editor: a filled dot, ringed when chosen.
private struct ColorDot: View {
    let id: String
    let label: String
    let selected: Bool
    let pick: () -> Void

    var body: some View {
        let tint = StripGroup.tint(id)
        Button(action: pick) {
            ZStack {
                Circle().fill(tint).frame(width: selected ? 12 : 18, height: selected ? 12 : 18)
                if selected { Circle().strokeBorder(tint, lineWidth: 2).frame(width: 20, height: 20) }
            }
            .frame(width: DS.Size.minHitTarget + 4, height: DS.Size.minHitTarget + 4)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(label)
        .accessibilityLabel(label)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }
}

extension View {
    /// Drag a tab by its id; dropping it on another tab moves it to that tab's place, joining or
    /// leaving groups by where it lands (core `StripOp::Move`); outside every window it tears off
    /// into a new window (`TabDrag`).
    func tabDragAndDrop(_ tab: TerminalTab, sessions: SessionsModel) -> some View {
        onDrag { TabDrag.provider(for: tab, sessions: sessions) }
            .onDrop(of: [TabDrag.type], isTargeted: nil) { TabDrag.drop($0, onto: tab, sessions: sessions) }
    }
}
