import AppKit
import SwiftUI
import BastionCore

/// The dashboard's sorted rows and its filter, outside SwiftUI state: typing in the filter
/// filters here and refills the table directly, so the page and its header do not run again.
@MainActor final class DashboardRowsController {
    private(set) var sorted: [DashboardRow] = []
    private(set) var shown: [DashboardRow] = []
    private(set) var filter = ""
    /// Bumped whenever `shown` changes; the table compares it with what it shows.
    private(set) var version = 0
    private var connections: [String: ConnectionView] = [:]
    weak var table: DashboardTable.Coordinator?
    /// Called after `shown` changes (the UI driver's snapshot).
    var didShow: (() -> Void)?

    /// A load or a sort: new rows, already sorted, and the connections the filter reads.
    func setRows(_ rows: [DashboardRow], connections: [String: ConnectionView]) {
        sorted = rows
        self.connections = connections
        apply()
    }

    func setFilter(_ text: String) {
        guard text != filter else { return }
        filter = text
        apply()
    }

    /// Posted (object: this controller) by `clearFilter`: the filter boxes empty themselves.
    static let filterCleared = Notification.Name("bastion.dashboard.filter-cleared")

    /// Another folder: no filter, and the boxes show none (also text typed but not yet applied).
    func clearFilter() {
        setFilter("")
        NotificationCenter.default.post(name: Self.filterCleared, object: self)
    }

    private func apply() {
        let needle = Array(filter.lowercased().utf8)
        shown = needle.isEmpty ? sorted : sorted.filter { $0.matches(needle, filter: filter, connection: connections[$0.id]) }
        version &+= 1
        table?.show(shown, version: version)
        didShow?()
    }
}

/// The filter box: its own view, so a key press runs only this view and the rows controller.
struct DashboardFilterField: View {
    let controller: DashboardRowsController
    @State private var text = ""
    /// How long typing must pause before the rows are filtered again.
    private static let pause = Duration.milliseconds(150)

    var body: some View {
        TextField("Filter", text: $text)
            .textFieldStyle(.roundedBorder)
            .frame(minWidth: DS.Size.numberField, idealWidth: DS.Size.toolbarWorkspace, maxWidth: DS.Size.dialogWidth)
            .accessibilityLabel("Filter")
            .accessibilityIdentifier("folder-dashboard-filter")
            .help("Name, address, user or tag. tag:name keeps only connections with that tag.")
            // Cleared per folder here, not by a new identity per folder: that rebuilt the field (in
            // each `ViewThatFits` layout) on every open (MAC-SELECT-SPEED).
            .onReceive(NotificationCenter.default.publisher(for: DashboardRowsController.filterCleared, object: controller)) { _ in
                if !text.isEmpty { text = "" }
            }
            .task(id: text) {
                guard text != controller.filter else { return }
                try? await Task.sleep(for: Self.pause)
                guard !Task.isCancelled else { return }
                controller.setFilter(text)
            }
    }
}

/// The folder dashboard's sort: one column, up or down (a header click, as in Finder).
struct DashboardSort: Equatable {
    var column = "name"
    var ascending = true

    /// For `sorted(by:)`: true when `a` goes before `b`.
    func before(_ a: DashboardRow, _ b: DashboardRow) -> Bool {
        let r = Self.compare(column, a, b)
        return ascending ? r == .orderedAscending : r == .orderedDescending
    }

    private static func compare(_ column: String, _ a: DashboardRow, _ b: DashboardRow) -> ComparisonResult {
        if column == "name" {
            if a.nameKey != b.nameKey { return a.nameKey.lexicographicallyPrecedes(b.nameKey) ? .orderedAscending : .orderedDescending }
            return a.id == b.id ? .orderedSame : (a.id < b.id ? .orderedAscending : .orderedDescending)
        }
        if column == "last-connected" {
            if a.lastConnectedAt == b.lastConnectedAt { return .orderedSame }
            return a.lastConnectedAt < b.lastConnectedAt ? .orderedAscending : .orderedDescending
        }
        return DashboardColumn.text(column, a).localizedCaseInsensitiveCompare(DashboardColumn.text(column, b))
    }
}

/// The dashboard's columns: id (also the defaults key), title, widths, shown by default.
struct DashboardColumn {
    let id: String
    let title: String
    let minWidth: CGFloat
    let idealWidth: CGFloat
    let shown: Bool

    static func all(deep: Bool) -> [DashboardColumn] {
        let narrow = DS.Size.numberField, wide = DS.Size.dashboardAddressIdeal
        return [
            .init(id: "name", title: "Name", minWidth: DS.Size.dashboardNameMin, idealWidth: DS.Size.dashboardNameIdeal, shown: true),
            .init(id: "address", title: "Address", minWidth: narrow, idealWidth: wide, shown: true),
            .init(id: "type", title: "Type", minWidth: narrow, idealWidth: narrow, shown: true),
            .init(id: "status", title: "Status", minWidth: narrow, idealWidth: narrow, shown: true),
            .init(id: "user", title: "User", minWidth: narrow, idealWidth: narrow, shown: true),
            .init(id: "login", title: "Login", minWidth: narrow, idealWidth: wide, shown: true),
            .init(id: "last-connected", title: "Last Connected", minWidth: narrow, idealWidth: wide, shown: true),
            .init(id: "last-result", title: "Last Result", minWidth: narrow, idealWidth: wide, shown: false),
            .init(id: "folder", title: "Folder", minWidth: narrow, idealWidth: wide, shown: deep),
            .init(id: "tags", title: "Tags", minWidth: narrow, idealWidth: wide, shown: false),
            .init(id: "port", title: "Port", minWidth: narrow, idealWidth: narrow, shown: false),
        ]
    }

    static func text(_ column: String, _ r: DashboardRow) -> String {
        switch column {
        case "name": r.name
        case "address": r.address
        case "type": r.type
        case "status": r.status
        case "user": r.user
        case "login": r.login
        case "last-connected": r.lastConnected
        case "last-result": r.lastResult
        case "folder": r.folder
        case "tags": r.tags
        case "port": r.port
        default: ""
        }
    }

    /// The user's own column choices, kept as `id:0|1` pairs.
    static func parse(_ s: String) -> [String: Bool] {
        Dictionary(s.split(separator: "|").compactMap { pair -> (String, Bool)? in
            let p = pair.split(separator: ":")
            return p.count == 2 ? (String(p[0]), p[1] == "1") : nil
        }, uniquingKeysWith: { _, b in b })
    }

    /// `choice` with one column shown or hidden.
    static func toggled(_ choice: String, id: String, shown: Bool) -> String {
        var c = parse(choice)
        c[id] = shown
        return format(c)
    }

    static func format(_ choice: [String: Bool]) -> String {
        choice.sorted { $0.key < $1.key }.map { "\($0.key):\($0.value ? 1 : 0)" }.joined(separator: "|")
    }
}

/// The dashboard's rows in an AppKit table (view-based, cells reused, data reloaded only when the
/// rows, filter or sort change). A SwiftUI Table laid every row out again on each change: most of
/// a second at 5,000 rows.
struct DashboardTable: NSViewRepresentable {
    let controller: DashboardRowsController
    let rows: [DashboardRow]
    /// Bumped by the page whenever `rows` changes; the table reloads only then.
    let version: Int
    let deep: Bool
    let locked: Bool
    @Binding var selection: Set<String>
    @Binding var sort: DashboardSort
    @Binding var columnChoice: String
    let menu: (String) -> [MenuItemView]
    let perform: (MenuItemView, String) -> Void
    let open: (Set<String>) -> Void

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> NSScrollView {
        RenderCount.hit("DashboardTable.make")
        let table = DashboardTableView()
        table.style = .inset
        // Plain rows, as the tree: alternating fills were redrawn in software over the whole table on each reload.
        table.usesAlternatingRowBackgroundColors = false
        table.allowsMultipleSelection = true
        table.allowsColumnReordering = true
        table.allowsColumnResizing = true
        table.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        table.setAccessibilityIdentifier("folder-dashboard-table")
        table.setAccessibilityLabel("Folder contents")
        for c in DashboardColumn.all(deep: deep) {
            let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(c.id))
            col.title = c.title
            col.minWidth = c.minWidth
            col.width = c.idealWidth
            col.sortDescriptorPrototype = NSSortDescriptor(key: c.id, ascending: true)
            table.addTableColumn(col)
        }
        table.autosaveName = "folder-dashboard.columns"
        table.autosaveTableColumns = true
        let c = context.coordinator
        c.table = table
        controller.table = c
        table.dataSource = c
        table.delegate = c
        table.target = c
        table.doubleAction = #selector(Coordinator.doubleClicked)
        table.onReturn = { [weak c] in c?.openSelection() }
        let rowMenu = NSMenu()
        rowMenu.autoenablesItems = false
        rowMenu.delegate = c
        table.menu = rowMenu
        let headerMenu = NSMenu()
        headerMenu.delegate = c
        table.headerView?.menu = headerMenu
        c.observers = [NSTableView.columnDidResizeNotification, NSTableView.columnDidMoveNotification].map { name in
            NotificationCenter.default.addObserver(forName: name, object: table, queue: .main) { [weak table] _ in
                MainActor.assumeIsolated { table?.enumerateAvailableRowViews { view, _ in view.needsDisplay = true } }
            }
        }
        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        return scroll
    }

    static func dismantleNSView(_ scroll: NSScrollView, coordinator: Coordinator) {
        coordinator.observers.forEach(NotificationCenter.default.removeObserver)
        coordinator.observers = []
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        let c = context.coordinator
        c.parent = self
        guard let table = c.table else { return }
        c.applying = true
        defer { c.applying = false }
        let key = "\(deep)|\(columnChoice)"
        if c.columnsKey != key {
            c.columnsKey = key
            let choice = DashboardColumn.parse(columnChoice)
            // Showing or hiding a column made the table write its whole column layout to the
            // defaults at once (about 45 ms); that write now happens after the change is drawn,
            // and only when a column changes (the first build usually changes none: MAC-SELECT-SPEED).
            let changes = DashboardColumn.all(deep: deep).compactMap { col -> (NSTableColumn, Bool)? in
                guard col.id != "name", let column = table.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier(col.id)) else { return nil }
                let hidden = !(choice[col.id] ?? col.shown)
                return column.isHidden == hidden ? nil : (column, hidden)
            }
            if !changes.isEmpty {
                table.autosaveTableColumns = false
                for (column, hidden) in changes { column.isHidden = hidden }
                // Turning autosave back on reads the saved layout back, with its old hidden columns:
                // the choice is set again after it (FOLDER-COLUMNS), which also saves it.
                let wanted = changes.map { ($0.0.identifier, $0.1) }
                DispatchQueue.main.async { [weak table] in
                    guard let table else { return }
                    table.autosaveTableColumns = true
                    for (id, hidden) in wanted { table.tableColumn(withIdentifier: id)?.isHidden = hidden }
                }
            }
            table.enumerateAvailableRowViews { view, _ in view.needsDisplay = true }
        }
        let descriptor = NSSortDescriptor(key: sort.column, ascending: sort.ascending)
        if table.sortDescriptors.first != descriptor { table.sortDescriptors = [descriptor] }
        if c.version != version || c.locked != locked {
            c.locked = locked
            c.show(rows, version: version)
        }
        let wanted = IndexSet(selection.compactMap { c.index[$0] })
        if table.selectedRowIndexes != wanted { table.selectRowIndexes(wanted, byExtendingSelection: false) }
    }

    @MainActor final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSMenuDelegate {
        var parent: DashboardTable?
        weak var table: NSTableView?
        var rows: [DashboardRow] = []
        var index: [String: Int] = [:]
        var version = -1
        var locked = false
        var columnsKey = ""
        /// Column resize and move observers, removed when the table goes away.
        var observers: [NSObjectProtocol] = []
        /// Set while the page pushes state in, so the table's echo is not sent back.
        var applying = false

        func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

        /// No per-column views: each row is one drawn view (`DashboardRowView`). Seven text and
        /// image subviews per row cost about 3.5 ms a row to build, and a filter that brought 30
        /// rows back on screen built them all.
        func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? { nil }

        func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? {
            let t0 = CFAbsoluteTimeGetCurrent()
            let view = (tableView.makeView(withIdentifier: DashboardRowView.identifier, owner: nil) as? DashboardRowView) ?? DashboardRowView()
            if row < rows.count { view.show(rows[row], locked: locked) }
            RenderCount.build(ms: (CFAbsoluteTimeGetCurrent() - t0) * 1000)
            return view
        }

        /// New rows, from SwiftUI (a load) or straight from the rows controller (a filter).
        func show(_ next: [DashboardRow], version next_version: Int) {
            version = next_version
            let oldCount = rows.count
            rows = next
            index = Dictionary(next.enumerated().map { ($1.id, $0) }, uniquingKeysWith: { a, _ in a })
            guard let table else { return }
            let wasApplying = applying
            applying = true
            refill(table, rowCountChanged: oldCount != next.count)
            if let parent {
                let wanted = IndexSet(parent.selection.compactMap { index[$0] })
                if table.selectedRowIndexes != wanted { table.selectRowIndexes(wanted, byExtendingSelection: false) }
            }
            applying = wasApplying
        }

        /// New rows: the row views on screen show their new rows in place, and the table only
        /// learns the new count (`reloadData` dropped every visible row and built them again).
        func refill(_ table: NSTableView, rowCountChanged: Bool) {
            if rowCountChanged { table.noteNumberOfRowsChanged() }
            table.enumerateAvailableRowViews { view, row in
                guard row < rows.count, let view = view as? DashboardRowView else { return }
                view.show(rows[row], locked: locked)
            }
        }

        func tableViewSelectionDidChange(_ notification: Notification) {
            guard !applying, let table, let parent else { return }
            let ids = Set(table.selectedRowIndexes.compactMap { $0 < rows.count ? rows[$0].id : nil })
            if parent.selection != ids { parent.selection = ids }
        }

        func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
            guard !applying, let d = tableView.sortDescriptors.first, let key = d.key, let parent else { return }
            let next = DashboardSort(column: key, ascending: d.ascending)
            if parent.sort != next { parent.sort = next }
        }

        @objc func doubleClicked() {
            guard let table, table.clickedRow >= 0, table.clickedRow < rows.count else { return }
            parent?.open([rows[table.clickedRow].id])
        }

        func openSelection() {
            guard let table, !table.selectedRowIndexes.isEmpty else { return }
            parent?.open(Set(table.selectedRowIndexes.compactMap { $0 < rows.count ? rows[$0].id : nil }))
        }

        func menuNeedsUpdate(_ menu: NSMenu) {
            menu.removeAllItems()
            guard let table, let parent else { return }
            if menu === table.headerView?.menu { return columnItems(menu, table) }
            let row = table.clickedRow
            // Not on a row (the header, or the empty space under the rows): choose the columns.
            guard row >= 0 else { return columnItems(menu, table) }
            guard row < rows.count else { return }
            if !table.selectedRowIndexes.contains(row) { table.selectRowIndexes([row], byExtendingSelection: false) }
            // As before: the row's own menu for one row; several rows use the header buttons.
            guard table.selectedRowIndexes.count == 1 else { return }
            let id = rows[row].id
            let items = parent.menu(id)
            for (i, item) in items.enumerated() {
                if i > 0, items[i - 1].section != item.section { menu.addItem(.separator()) }
                let mi = NSMenuItem(title: item.label, action: #selector(performItem(_:)), keyEquivalent: "")
                mi.target = self
                mi.isEnabled = item.enabled
                mi.image = Icons.actionSymbols[item.glyph].flatMap { NSImage(systemSymbolName: $0, accessibilityDescription: nil) }
                mi.representedObject = MenuAction(item: item, id: id)
                menu.addItem(mi)
            }
        }

        /// Header right-click: choose the columns (Name always stays).
        private func columnItems(_ menu: NSMenu, _ table: NSTableView) {
            for col in table.tableColumns where col.identifier.rawValue != "name" {
                let mi = NSMenuItem(title: col.title, action: #selector(toggleColumn(_:)), keyEquivalent: "")
                mi.target = self
                mi.state = col.isHidden ? .off : .on
                mi.representedObject = col.identifier.rawValue
                menu.addItem(mi)
            }
        }

        @objc func toggleColumn(_ sender: NSMenuItem) {
            guard let id = sender.representedObject as? String, let parent,
                  let col = table?.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier(id)) else { return }
            parent.columnChoice = DashboardColumn.toggled(parent.columnChoice, id: id, shown: col.isHidden)
        }

        @objc func performItem(_ sender: NSMenuItem) {
            guard let a = sender.representedObject as? MenuAction else { return }
            parent?.perform(a.item, a.id)
        }
    }

    private final class MenuAction: NSObject {
        let item: MenuItemView
        let id: String
        init(item: MenuItemView, id: String) { self.item = item; self.id = id }
    }
}

/// Return opens or connects the selected rows, as a double-click does.
final class DashboardTableView: NSTableView {
    var onReturn: (() -> Void)?

    override func keyDown(with event: NSEvent) {
        if event.keyCode == 36 || event.keyCode == 76, event.modifierFlags.intersection(.deviceIndependentFlagsMask).isEmpty {
            onReturn?()
            return
        }
        super.keyDown(with: event)
    }
}

/// One table row drawn as a single view: every shown column's text (and the name's protocol
/// symbol, the login's lock) drawn at that column's place, with no subviews. Accessibility gives
/// one static-text element per shown column, with the labels the separate cells had.
final class DashboardRowView: NSTableRowView {
    static let identifier = NSUserInterfaceItemIdentifier("folder-dashboard-row")
    private var row: DashboardRow?
    private var locked = false

    init() {
        super.init(frame: .zero)
        identifier = Self.identifier
        RenderCount.hit("DashboardRowView.init")
    }

    required init?(coder: NSCoder) { nil }

    func show(_ row: DashboardRow, locked: Bool) {
        guard row != self.row || locked != self.locked else { return }
        self.row = row
        self.locked = locked
        needsDisplay = true
        cachedElements = nil
    }

    private var table: NSTableView? { superview as? NSTableView }

    /// The shown columns and where they sit in this row.
    private var columns: [(id: String, rect: NSRect)] {
        guard let table else { return [] }
        return table.tableColumns.enumerated().compactMap { index, column in
            column.isHidden ? nil : (column.identifier.rawValue, NSRect(x: table.rect(ofColumn: index).minX, y: 0, width: column.width, height: bounds.height))
        }
    }

    /// What one column shows: its words, an optional symbol (before, or after for the lock), and
    /// the accessibility label.
    private func content(_ column: String, _ r: DashboardRow) -> (text: String, symbol: String?, tint: NSColor?, after: Bool, label: String) {
        switch column {
        case "name":
            let tint = r.hostColor.flatMap(HostColors.color(hex:)) ?? .secondaryLabelColor
            return (r.name, r.isFolder ? "folder" : protocolSymbol(r.proto ?? ""), tint, false, r.isFolder ? "Folder \(r.name)" : r.name)
        case "login":
            let lock = locked && !r.isFolder && r.login != "None"
            return (r.login, lock ? "lock" : nil, .secondaryLabelColor, true, lock ? "\(r.login), credentials locked" : r.login)
        default:
            let text = DashboardColumn.text(column, r)
            return (text, nil, nil, false, text)
        }
    }

    override var interiorBackgroundStyle: NSView.BackgroundStyle { isSelected && isEmphasized ? .emphasized : .normal }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard let r = row else { return }
        let emphasized = isSelected && isEmphasized
        for (id, rect) in columns where rect.intersects(dirtyRect) {
            let c = content(id, r)
            let inner = rect.insetBy(dx: DS.Space.xxs, dy: 0)
            var textRect = inner
            if let name = c.symbol, let image = Self.symbol(name) {
                let size = image.size
                let y = rect.minY + ((rect.height - size.height) / 2).rounded()
                let tint = emphasized ? NSColor.alternateSelectedControlTextColor : (c.tint ?? .secondaryLabelColor)
                if c.after {
                    let width = min(Self.width(c.text, id), max(0, inner.width - size.width - DS.Space.xs))
                    textRect.size.width = width
                    Self.draw(image, in: NSRect(x: inner.minX + width + DS.Space.xs, y: y, width: size.width, height: size.height), tint: tint)
                } else {
                    Self.draw(image, in: NSRect(x: inner.minX, y: y, width: size.width, height: size.height), tint: tint)
                    textRect.origin.x += size.width + DS.Space.xs
                    textRect.size.width -= size.width + DS.Space.xs
                }
            }
            guard textRect.width > 0 else { continue }
            let attributes = Self.attributes(monospaced: id == "address", emphasized: emphasized)
            let height = Self.lineHeight(monospaced: id == "address")
            textRect.origin.y = rect.minY + ((rect.height - height) / 2).rounded()
            textRect.size.height = height
            (c.text as NSString).draw(with: textRect, options: [.usesLineFragmentOrigin, .truncatesLastVisibleLine], attributes: attributes)
        }
    }

    override var isFlipped: Bool { true }

    // MARK: Accessibility: one element per shown column.

    private var cachedElements: [NSAccessibilityElement]?

    override func accessibilityChildren() -> [Any]? {
        guard let r = row else { return [] }
        if let cachedElements { return cachedElements }
        let made = columns.map { id, rect -> NSAccessibilityElement in
            let c = content(id, r)
            let e = NSAccessibilityElement()
            e.setAccessibilityRole(.staticText)
            e.setAccessibilityLabel(c.label)
            e.setAccessibilityValue(c.text)
            e.setAccessibilityIdentifier("folder-dashboard-\(id)")
            e.setAccessibilityParent(self)
            e.setAccessibilityFrameInParentSpace(rect)
            return e
        }
        cachedElements = made
        return made
    }

    override func layout() {
        super.layout()
        cachedElements = nil
    }

    // MARK: Shared drawing state, made once.

    private static let plain = NSFont.systemFont(ofSize: NSFont.systemFontSize)
    private static let mono = NSFont.monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
    private static let truncating: NSParagraphStyle = {
        let p = NSMutableParagraphStyle()
        p.lineBreakMode = .byTruncatingTail
        return p
    }()

    private static func attributes(monospaced: Bool, emphasized: Bool) -> [NSAttributedString.Key: Any] {
        [.font: monospaced ? mono : plain, .paragraphStyle: truncating,
         .foregroundColor: emphasized ? NSColor.alternateSelectedControlTextColor : NSColor.labelColor]
    }

    private static func lineHeight(monospaced: Bool) -> CGFloat {
        let f = monospaced ? mono : plain
        return ceil(f.ascender - f.descender + f.leading)
    }

    private static func width(_ text: String, _ column: String) -> CGFloat {
        ceil((text as NSString).size(withAttributes: [.font: column == "address" ? mono : plain]).width)
    }

    @MainActor private static var symbols: [String: NSImage] = [:]
    private static func symbol(_ name: String) -> NSImage? {
        if let hit = symbols[name] { return hit }
        let made = NSImage(systemSymbolName: name, accessibilityDescription: nil)
        symbols[name] = made
        return made
    }

    /// A template symbol drawn in `tint`.
    private static func draw(_ image: NSImage, in rect: NSRect, tint: NSColor) {
        guard let context = NSGraphicsContext.current?.cgContext,
              let cg = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else { return }
        context.saveGState()
        context.translateBy(x: 0, y: rect.maxY + rect.minY)
        context.scaleBy(x: 1, y: -1)
        context.clip(to: rect, mask: cg)
        tint.setFill()
        context.fill(rect)
        context.restoreGState()
    }
}

/// Builds the dashboard's AppKit table, a row view and their fonts and symbols once, off screen,
/// when the app is idle after launch, so the first folder opened does not pay that setup.
/// No library data is used.
@MainActor enum DashboardPrewarm {
    private static var done = false
    private static let protocols = ["ssh", "rdp", "vnc", "web", "local", "sftp"]

    static func run() {
        guard !done else { return }
        done = true
        let table = DashboardTableView()
        table.style = .inset
        table.addTableColumn(NSTableColumn(identifier: NSUserInterfaceItemIdentifier("name")))
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 400, height: 100))
        scroll.documentView = table
        let row = DashboardRowView()
        row.frame = NSRect(x: 0, y: 0, width: 400, height: 24)
        table.addSubview(row)
        for proto in protocols {
            let sample = DashboardRow(id: "prewarm", isFolder: false, name: "Prewarm", address: "localhost", proto: proto, type: proto,
                                      status: "", user: "", login: "Saved", lastConnected: "", lastConnectedAt: 0, lastResult: "",
                                      folder: "", tags: "", port: "", hostColor: nil)
            row.show(sample, locked: true)
            if let rep = row.bitmapImageRepForCachingDisplay(in: row.bounds) { row.cacheDisplay(in: row.bounds, to: rep) }
        }
        _ = row.accessibilityChildren()
    }
}
