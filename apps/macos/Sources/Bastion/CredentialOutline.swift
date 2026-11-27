import AppKit
import SwiftUI
import BastionCore

/// The Credentials tree as an `NSOutlineView`, so it behaves like the Library tree: a click on a
/// folder's name opens or closes it, rename edits the row in place, and drag and drop moves
/// folders and credentials between folders and to the top level (dropping on empty space).
/// A credential is also dragged as its id in plain text, which the Library tree takes as "assign".
struct CredentialOutline: NSViewRepresentable {
    let credentials: CredentialsModel
    @Binding var selection: String?
    /// Set to an id to start renaming that row; cleared once editing starts.
    @Binding var renameRequest: String?
    let menu: (CredentialTreeItemView) -> NSMenu
    let delete: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> NSScrollView {
        let outline = CredentialOutlineView()
        let column = NSTableColumn(identifier: .init("name"))
        column.resizingMask = .autoresizingMask
        outline.addTableColumn(column)
        outline.outlineTableColumn = column
        outline.headerView = nil
        outline.style = .sourceList
        outline.floatsGroupRows = false
        outline.dataSource = context.coordinator
        outline.delegate = context.coordinator
        outline.target = context.coordinator
        outline.action = #selector(Coordinator.clicked)
        outline.registerForDraggedTypes([.credentialNode])
        outline.setDraggingSourceOperationMask(.move, forLocal: true)
        outline.setDraggingSourceOperationMask(.link, forLocal: false)
        outline.draggingDestinationFeedbackStyle = .sourceList
        outline.setAccessibilityLabel("Credentials")
        outline.setAccessibilityIdentifier("credentials-tree")
        outline.coordinator = context.coordinator
        let m = NSMenu()
        m.delegate = context.coordinator
        outline.menu = m
        context.coordinator.outline = outline
        Coordinator.current = context.coordinator

        let scroll = NSScrollView()
        scroll.documentView = outline
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        let c = context.coordinator
        c.parent = self
        c.reload(credentials.tree)
        if let id = renameRequest {
            DispatchQueue.main.async {
                renameRequest = nil
                c.beginRename(id)
            }
        }
    }

    /// One row; a class so the outline view can track it by identity across reloads.
    final class Node {
        let item: CredentialTreeItemView
        var children: [Node]
        init(item: CredentialTreeItemView, children: [Node]) { self.item = item; self.children = children }
        var id: String { item.id }
    }

    @MainActor
    final class Coordinator: NSObject, NSOutlineViewDataSource, NSOutlineViewDelegate, NSMenuDelegate, NSTextFieldDelegate {
        /// The live tree, for the UI driver.
        static weak var current: Coordinator?
        var parent: CredentialOutline?
        weak var outline: NSOutlineView?
        private(set) var roots: [Node] = []
        private var lastTree: [CredentialTreeItemView] = []
        private var expanded = Set<String>()
        private(set) var renamingId: String?
        private var applyingSelection = false

        private typealias Act = CredentialTreeActions

        // MARK: Data

        func reload(_ tree: [CredentialTreeItemView]) {
            guard let outline else { return }
            if tree != lastTree {
                lastTree = tree
                roots = Self.build(tree, parent: nil)
                applyingSelection = true
                outline.reloadData()
                restoreExpansion(roots)
                applyingSelection = false
            }
            syncSelection()
        }

        static func build(_ items: [CredentialTreeItemView], parent: String?) -> [Node] {
            CredentialNode.build(items, parent: parent).map(convert)
        }

        private static func convert(_ n: CredentialNode) -> Node {
            Node(item: n.item, children: (n.children ?? []).map(convert))
        }

        private func restoreExpansion(_ nodes: [Node]) {
            for n in nodes where n.item.isFolder && expanded.contains(n.id) {
                outline?.expandItem(n)
                restoreExpansion(n.children)
            }
        }

        func node(_ id: String, in nodes: [Node]? = nil) -> Node? {
            for n in nodes ?? roots {
                if n.id == id { return n }
                if let hit = node(id, in: n.children) { return hit }
            }
            return nil
        }

        /// Shows the SwiftUI selection in the outline, opening the folders above it.
        private func syncSelection() {
            guard let outline else { return }
            let want = parent?.selection
            let current = outline.selectedRow >= 0 ? (outline.item(atRow: outline.selectedRow) as? Node)?.id : nil
            guard want != current else { return }
            applyingSelection = true
            defer { applyingSelection = false }
            guard let want, let n = node(want) else { outline.deselectAll(nil); return }
            revealAncestors(of: want)
            let row = outline.row(forItem: n)
            if row >= 0 { outline.selectRowIndexes([row], byExtendingSelection: false); outline.scrollRowToVisible(row) }
        }

        private func revealAncestors(of id: String) {
            var chain: [String] = []
            var cur = lastTree.first { $0.id == id }?.parent
            while let p = cur { chain.insert(p, at: 0); cur = lastTree.first { $0.id == p }?.parent }
            for p in chain { if let n = node(p) { expanded.insert(p); outline?.expandItem(n) } }
        }

        func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
            ((item as? Node)?.children ?? roots).count
        }

        func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
            ((item as? Node)?.children ?? roots)[index]
        }

        func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
            (item as? Node).map { $0.item.isFolder && !$0.children.isEmpty } ?? false
        }

        func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
            guard let n = item as? Node else { return nil }
            let cell = (outlineView.makeView(withIdentifier: CredentialCell.id, owner: nil) as? CredentialCell) ?? CredentialCell()
            cell.configure(n.item)
            cell.nameField.delegate = self
            return cell
        }

        func outlineViewItemDidExpand(_ notification: Notification) {
            if let n = notification.userInfo?["NSObject"] as? Node { expanded.insert(n.id) }
        }

        func outlineViewItemDidCollapse(_ notification: Notification) {
            if let n = notification.userInfo?["NSObject"] as? Node { expanded.remove(n.id) }
        }

        func outlineViewSelectionDidChange(_ notification: Notification) {
            guard !applyingSelection, let outline else { return }
            let id = outline.selectedRow >= 0 ? (outline.item(atRow: outline.selectedRow) as? Node)?.id : nil
            if parent?.selection != id { parent?.selection = id }
        }

        // MARK: Mouse and keyboard

        /// A click on a folder's row (its name or icon, not only the arrow) opens or closes it,
        /// as in the Library tree. A click on empty space clears the selection, so New Folder
        /// then goes to the top level.
        @objc func clicked() {
            guard let outline else { return }
            handleClick(outline.clickedRow >= 0 ? outline.item(atRow: outline.clickedRow) as? Node : nil)
        }

        /// A click on `n` (nil = empty space). The UI driver calls this with the row it names.
        func handleClick(_ n: Node?) {
            guard let outline else { return }
            guard let n else { parent?.selection = nil; outline.deselectAll(nil); return }
            let row = outline.row(forItem: n)
            if row >= 0, outline.selectedRow != row { outline.selectRowIndexes([row], byExtendingSelection: false) }
            guard n.item.isFolder, renamingId == nil else { return }
            toggle(n)
        }

        func toggle(_ n: Node) {
            guard let outline else { return }
            if outline.isItemExpanded(n) { outline.animator().collapseItem(n) } else { outline.animator().expandItem(n) }
        }

        func isExpanded(_ id: String) -> Bool {
            guard let outline, let n = node(id) else { return false }
            return outline.isItemExpanded(n)
        }

        func deleteSelection() {
            if let id = parent?.selection { parent?.delete(id) }
        }

        // MARK: Rename

        func beginRename(_ id: String) {
            guard let outline, let n = node(id) else { return }
            revealAncestors(of: id)
            let row = outline.row(forItem: n)
            guard row >= 0 else { return }
            applyingSelection = true
            outline.selectRowIndexes([row], byExtendingSelection: false)
            applyingSelection = false
            parent?.selection = id
            outline.scrollRowToVisible(row)
            guard let cell = outline.view(atColumn: 0, row: row, makeIfNecessary: true) as? CredentialCell else { return }
            renamingId = id
            cell.beginRename(in: outline.window)
        }

        /// The field in edit, for the UI driver.
        var renameField: NSTextField? {
            guard let outline, let id = renamingId, let n = node(id) else { return nil }
            let row = outline.row(forItem: n)
            return row >= 0 ? (outline.view(atColumn: 0, row: row, makeIfNecessary: false) as? CredentialCell)?.nameField : nil
        }

        func controlTextDidEndEditing(_ obj: Notification) {
            guard let field = obj.object as? NSTextField, let id = renamingId, let model = parent?.credentials else { return }
            renamingId = nil
            field.isEditable = false
            let name = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if !name.isEmpty, name != lastTree.first(where: { $0.id == id })?.name { Act.rename(model, id, to: name) }
            // A refused name (taken, too long) shows the old one again.
            if let n = node(id) { field.stringValue = n.item.name }
            outline?.window?.makeFirstResponder(outline)
        }

        /// Escape cancels the rename and restores the old name.
        func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
            guard selector == #selector(NSResponder.cancelOperation(_:)), let id = renamingId else { return false }
            renamingId = nil
            let field = control as? NSTextField
            field?.abortEditing()
            field?.isEditable = false
            field?.stringValue = node(id)?.item.name ?? ""
            outline?.window?.makeFirstResponder(outline)
            return true
        }

        // MARK: Context menu

        func menuNeedsUpdate(_ menu: NSMenu) {
            menu.removeAllItems()
            guard let outline, outline.clickedRow >= 0, let n = outline.item(atRow: outline.clickedRow) as? Node,
                  let built = parent?.menu(n.item) else { return }
            for item in built.items { built.removeItem(item); menu.addItem(item) }
        }

        // MARK: Drag and drop

        func outlineView(_ outlineView: NSOutlineView, pasteboardWriterForItem item: Any) -> NSPasteboardWriting? {
            guard let n = item as? Node, renamingId == nil else { return nil }
            let p = NSPasteboardItem()
            p.setString(n.id, forType: .credentialNode)
            // Plain text too: the Library tree assigns a credential dropped on a folder or connection.
            if !n.item.isFolder { p.setString(n.id, forType: .string) }
            return p
        }

        private func draggedIds(_ info: NSDraggingInfo) -> [String] {
            info.draggingPasteboard.pasteboardItems?.compactMap { $0.string(forType: .credentialNode) } ?? []
        }

        /// The folder a drop lands in (nil = top level). Dropping on a credential means its folder.
        static func dropFolder(_ item: Node?) -> String? {
            guard let item else { return nil }
            return item.item.isFolder ? item.id : item.item.parent
        }

        /// True when every dragged id may move into `folder` (never into itself or its own subtree).
        func canMove(_ ids: [String], to folder: String?) -> Bool {
            guard let model = parent?.credentials, !ids.isEmpty else { return false }
            return ids.allSatisfy { id in
                guard let f = folder else { return true }
                return id != f && !Act.isInside(model, f, id)
            }
        }

        func outlineView(_ outlineView: NSOutlineView, validateDrop info: NSDraggingInfo, proposedItem item: Any?,
                         proposedChildIndex index: Int) -> NSDragOperation {
            let ids = draggedIds(info)
            let folder = Self.dropFolder(item as? Node)
            guard canMove(ids, to: folder) else { return [] }
            // The tree is sorted by name, so a drop always lands on the folder (or the top level).
            outlineView.setDropItem(folder.flatMap { node($0) }, dropChildIndex: NSOutlineViewDropOnItemIndex)
            return .move
        }

        func outlineView(_ outlineView: NSOutlineView, acceptDrop info: NSDraggingInfo, item: Any?, childIndex index: Int) -> Bool {
            move(draggedIds(info), to: Self.dropFolder(item as? Node))
        }

        @discardableResult
        func move(_ ids: [String], to folder: String?) -> Bool {
            guard let model = parent?.credentials, canMove(ids, to: folder) else { return false }
            if let folder { expanded.insert(folder) }
            for id in ids { Act.move(model, id, to: folder) }
            return true
        }
    }
}

extension NSPasteboard.PasteboardType {
    /// A row of the Credentials tree being moved inside it.
    static let credentialNode = NSPasteboard.PasteboardType("app.bastion.credential-node")
}

/// The outline itself: Delete removes the selected row, Return renames it (as in Finder).
final class CredentialOutlineView: NSOutlineView {
    weak var coordinator: CredentialOutline.Coordinator?

    override func keyDown(with event: NSEvent) {
        switch event.keyCode {
        case 51, 117: coordinator?.deleteSelection()
        case 36, 76:
            if selectedRow >= 0, let n = item(atRow: selectedRow) as? CredentialOutline.Node { coordinator?.beginRename(n.id) }
        default: super.keyDown(with: event)
        }
    }

    override func menu(for event: NSEvent) -> NSMenu? {
        let row = self.row(at: convert(event.locationInWindow, from: nil))
        return row >= 0 ? super.menu(for: event) : nil
    }
}

/// Icon, name (editable in place) and, for a credential, its username.
final class CredentialCell: NSTableCellView {
    static let id = NSUserInterfaceItemIdentifier("credential-cell")
    let icon = NSImageView()
    let nameField = NSTextField(labelWithString: "")
    let detail = NSTextField(labelWithString: "")

    init() {
        super.init(frame: .zero)
        identifier = Self.id
        imageView = icon
        textField = nameField
        icon.contentTintColor = .secondaryLabelColor
        nameField.lineBreakMode = .byTruncatingTail
        nameField.cell?.usesSingleLineMode = true
        detail.textColor = .secondaryLabelColor
        detail.lineBreakMode = .byTruncatingTail
        detail.alignment = .right
        detail.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        nameField.setContentCompressionResistancePriority(.defaultLow + 1, for: .horizontal)
        let stack = NSStackView(views: [icon, nameField, detail])
        stack.spacing = DS.Space.xs
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -DS.Space.xs),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
            icon.widthAnchor.constraint(equalToConstant: 16),
        ])
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError() }

    func configure(_ item: CredentialTreeItemView) {
        let symbol = item.isFolder ? "folder" : item.kind == "ssh-key" ? "key" : item.kind == "unsupported" ? "questionmark.circle" : "person"
        icon.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
        nameField.stringValue = item.name
        nameField.isEditable = false
        detail.stringValue = item.isFolder ? "" : item.username
        detail.isHidden = detail.stringValue.isEmpty
        setAccessibilityLabel(item.kind == "unsupported" ? "\(item.name), Unsupported" : item.name)
    }

    func beginRename(in window: NSWindow?) {
        nameField.isEditable = true
        nameField.isSelectable = true
        window?.makeFirstResponder(nameField)
        nameField.currentEditor()?.selectAll(nil)
    }
}
