import SwiftUI
import BastionCore

/// One row of the Credentials section: a user folder or a named credential, with its children.
struct CredentialNode: Identifiable {
    let item: CredentialTreeItemView
    let children: [CredentialNode]?

    var id: String { item.id }

    /// Folders first, then credentials, each by name (the core's tree has no order of its own).
    static func build(_ items: [CredentialTreeItemView], parent: String? = nil) -> [CredentialNode] {
        items.filter { $0.parent == parent }
            .sorted { ($0.isFolder ? 0 : 1, $0.name.localizedLowercase) < ($1.isFolder ? 0 : 1, $1.name.localizedLowercase) }
            .map { CredentialNode(item: $0, children: $0.isFolder ? build(items, parent: $0.id) : nil) }
    }
}

/// What the delete-in-use sheet shows: the credential and the hosts/folders still pointing at it.
struct CredentialInUse: Identifiable {
    let id: String
    let name: String
    let users: [CredentialUsageView]
}

/// Folder, rename, move and delete steps for the Credentials section, all through the core vault.
/// Rename and move keep ids, so hosts that use a credential follow it. Shared with the UI driver.
@MainActor
enum CredentialTreeActions {
    static func item(_ c: CredentialsModel, _ id: String) -> CredentialTreeItemView? { c.tree.first { $0.id == id } }

    static func named(_ c: CredentialsModel, _ name: String) -> CredentialTreeItemView? {
        c.tree.first { $0.name == name } ?? c.tree.first { path(c, $0) == name }
    }

    @discardableResult
    static func newFolder(_ c: CredentialsModel, name: String? = nil, parent: String?) -> String? {
        var created: String?
        let taken = Set(c.tree.filter { $0.parent == parent }.map(\.name))
        let fresh = name ?? (["New Folder"] + (2...99).map { "New Folder \($0)" }).first { !taken.contains($0) } ?? "New Folder"
        c.mutate { created = try $0.addFolder(name: fresh, parent: parent) }
        return created
    }

    static func rename(_ c: CredentialsModel, _ id: String, to name: String) {
        guard let it = item(c, id) else { return }
        let name = name.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, name != it.name else { return }
        c.mutate { v in
            if it.isFolder { try v.renameFolder(id: id, name: name) } else { try v.renameCredential(id: id, name: name) }
        }
    }

    static func move(_ c: CredentialsModel, _ id: String, to folder: String?) {
        guard let it = item(c, id), it.parent != folder, id != folder else { return }
        c.mutate { v in
            if it.isFolder { try v.moveFolder(id: id, parent: folder) } else { try v.moveCredential(id: id, folder: folder) }
        }
    }

    /// Deletes a folder (the core refuses a non-empty one) or an unused credential. A credential in
    /// use is kept, and its users come back for the warning.
    static func delete(_ c: CredentialsModel, library: Library?, _ id: String) -> CredentialInUse? {
        guard let it = item(c, id) else { return nil }
        if it.isFolder {
            c.mutate { try $0.removeFolder(id: id) }
            return nil
        }
        guard let library else { return nil }
        var result: CredentialRemoveView?
        c.mutate { result = try $0.removeChecked(library: library, id: id, force: false) }
        guard let result, !result.removed else { return nil }
        return CredentialInUse(id: id, name: it.name, users: result.users)
    }

    static func forceDelete(_ c: CredentialsModel, library: LibraryModel, _ id: String) {
        guard let lib = library.library else { return }
        c.mutate { _ = try $0.removeChecked(library: lib, id: id, force: true) }
        library.reload()
    }

    static func path(_ c: CredentialsModel, _ f: CredentialTreeItemView) -> String {
        var parts = [f.name], cur = f.parent
        while let p = cur, let it = item(c, p) { parts.insert(it.name, at: 0); cur = it.parent }
        return parts.joined(separator: " / ")
    }

    /// Where New Folder goes: into the selected folder, beside the selected credential, or the
    /// top level when nothing is selected.
    static func targetFolder(_ c: CredentialsModel, selection: String?) -> String? {
        guard let id = selection, let it = item(c, id) else { return nil }
        return it.isFolder ? it.id : it.parent
    }

    /// True when `id` lies inside `ancestor` (a folder cannot move into its own subtree).
    static func isInside(_ c: CredentialsModel, _ id: String, _ ancestor: String) -> Bool {
        var cur = item(c, id)?.parent
        while let p = cur { if p == ancestor { return true }; cur = item(c, p)?.parent }
        return false
    }
}

/// The Credentials section under the connection tree (Royal TS style): user folders and named
/// credentials from the one vault. Names and usernames only; secrets never reach this view.
struct CredentialsSection: View {
    @Environment(CredentialsModel.self) private var credentials
    @Environment(LibraryModel.self) private var library
    @Environment(SessionsModel.self) private var sessions
    @Environment(AppRouter.self) private var router
    @AppStorage("sidebar.credentials.expanded") private var expanded = true
    /// Dragged by the bar's top edge and remembered (owner 2026-11-16: move it like the panels).
    @AppStorage("sidebar.credentials.height") private var savedHeight = Double(DS.Size.credentialsSection)
    @State private var dragStart: CGFloat?
    @State private var liveHeight: CGFloat?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var selection: String?
    @State private var renameRequest: String?
    @State private var inUse: CredentialInUse?

    private typealias Act = CredentialTreeActions
    private var nodes: [CredentialNode] { CredentialNode.build(credentials.tree) }
    private var folders: [CredentialTreeItemView] {
        credentials.tree.filter(\.isFolder).sorted { Act.path(credentials, $0) < Act.path(credentials, $1) }
    }

    var body: some View {
        VStack(spacing: 0) {
            Divider().overlay(alignment: .center) { if expanded && credentials.vault != nil { resizeHandle } }
            header
            if expanded && credentials.vault == nil {
                // Locked (UI-03): one row, not an empty resizable block.
                lockedRow
            } else if expanded {
                content.frame(height: height)
                    .transition(reduceMotion ? .opacity : .move(edge: .bottom).combined(with: .opacity))
            }
        }
        .clipped()
        .sheet(item: $inUse) { info in
            CredentialInUseSheet(info: info) { Act.forceDelete(credentials, library: library, $0) }
        }
        .onChange(of: credentials.pendingInUse?.id) { _, _ in
            if let pending = credentials.pendingInUse { inUse = pending; credentials.pendingInUse = nil }
        }
    }

    private var header: some View {
        HStack(spacing: DS.Space.xs) {
            // Animated as the side panels are; only the bar's own height changes, so the library
            // outline above just resizes its scroll view.
            Button { withAnimation(DS.Motion.spring(reduced: reduceMotion)) { expanded.toggle() } } label: {
                Label("Credentials", systemImage: expanded ? "chevron.down" : "chevron.right")
                    .font(DS.Font.subheadline.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            Spacer()
            if credentials.vault != nil {
                Menu {
                    Button("New Credential…") { router.open("credential-manager") }
                    Button("New Folder") { startRename(Act.newFolder(credentials, parent: selectedFolder)) }
                } label: { Image(systemName: "plus").iconHitTarget() }
                    // A plain button-style menu takes its label's size (a borderless menu button
                    // drew 20x14 whatever the label), as the sidebar's workspace row does.
                    .menuStyle(.button)
                    .buttonStyle(.plain)
                    .menuIndicator(.hidden)
                    .help("Add a credential or folder")
                    .accessibilityLabel("Add credential or folder")
            }
        }
        .padding(.horizontal, DS.Space.s)
        .padding(.vertical, DS.Space.xxs)
    }

    private var height: CGFloat {
        liveHeight ?? min(max(CGFloat(savedHeight), DS.Size.credentialsSectionMin), DS.Size.credentialsSectionMax)
    }

    /// The bar's top edge: drag up or down to resize it. The live height is view state during the drag;
    /// the setting is written once, at the end.
    private var resizeHandle: some View {
        Color.clear
            .frame(height: DS.Space.xs)
            .contentShape(Rectangle())
            .onHover { inside in if inside { NSCursor.resizeUpDown.push() } else { NSCursor.pop() } }
            .gesture(DragGesture(minimumDistance: 1, coordinateSpace: .global)
                .onChanged { g in
                    let start = dragStart ?? height
                    dragStart = start
                    liveHeight = min(max(start - g.translation.height, DS.Size.credentialsSectionMin), DS.Size.credentialsSectionMax)
                }
                .onEnded { _ in
                    if let h = liveHeight { savedHeight = Double(h.rounded()) }
                    dragStart = nil; liveHeight = nil
                })
            .accessibilityElement()
            .accessibilityLabel("Credentials height")
            .accessibilityIdentifier("credentials-resize")
            .help("Drag to resize")
    }

    @ViewBuilder private var content: some View {
        if nodes.isEmpty {
            emptyState("No credentials", button: "New Credential…") { router.open("credential-manager") }
        } else {
            CredentialOutline(credentials: credentials, selection: $selection, renameRequest: $renameRequest,
                              menu: menu, delete: delete)
        }
    }

    private var lockedRow: some View {
        Button { Task { await credentials.openInBackground(sessions: sessions) } } label: {
            Label("Unlock…", systemImage: "lock")
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(.secondary)
        .padding(.horizontal, DS.Space.s)
        .padding(.vertical, DS.Space.xs)
        .help("Unlock the vault")
        .accessibilityIdentifier("credentials-unlock")
    }

    private func emptyState(_ label: String, button: String, action: @escaping () -> Void) -> some View {
        VStack(spacing: DS.Space.xs) {
            Text(label).foregroundStyle(.secondary)
            Button(button, action: action)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// The row's context menu, as AppKit items (the outline is an `NSOutlineView`).
    private func menu(_ item: CredentialTreeItemView) -> NSMenu {
        let m = NSMenu()
        if item.isFolder {
            m.addItem(ClosureMenuItem(title: "New Folder") { startRename(Act.newFolder(credentials, parent: item.id)) })
        } else {
            m.addItem(ClosureMenuItem(title: "Edit…") { router.open("credential-manager") })
        }
        m.addItem(ClosureMenuItem(title: "Rename") { startRename(item.id) })
        let move = NSMenuItem(title: "Move To", action: nil, keyEquivalent: "")
        let sub = NSMenu()
        sub.autoenablesItems = false
        let top = ClosureMenuItem(title: "Top Level") { Act.move(credentials, item.id, to: nil) }
        top.isEnabled = item.parent != nil
        sub.addItem(top)
        sub.addItem(.separator())
        for f in folders where f.id != item.id && f.id != item.parent && !Act.isInside(credentials, f.id, item.id) {
            sub.addItem(ClosureMenuItem(title: Act.path(credentials, f)) { Act.move(credentials, item.id, to: f.id) })
        }
        move.submenu = sub
        m.addItem(move)
        m.addItem(.separator())
        m.addItem(ClosureMenuItem(title: "Delete") { delete(item.id) })
        return m
    }

    private var selectedFolder: String? { Act.targetFolder(credentials, selection: selection) }

    private func startRename(_ id: String?) {
        guard let id else { return }
        guard Act.item(credentials, id) != nil else { return }
        if !expanded { expanded = true }
        selection = id
        renameRequest = id
    }

    private func delete(_ id: String) {
        inUse = Act.delete(credentials, library: library.library, id)
    }
}

/// Delete-in-use warning: one line per host or folder still using the credential.
struct CredentialInUseSheet: View {
    let info: CredentialInUse
    let delete: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("“\(info.name)” is in use").font(DS.Font.headline)
            Text("Used by \(info.users.count). They will have no credential.").foregroundStyle(.secondary)
            List(info.users, id: \.nodeId) { u in
                Label((u.path + [u.name]).joined(separator: " / "), systemImage: u.isFolder ? "folder" : "server.rack")
            }
            .frame(minHeight: 80, maxHeight: 200)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Delete Anyway", role: .destructive) { delete(info.id); dismiss() }
            }
        }
        .padding(DS.Space.l)
        .frame(width: 380)
    }
}
