import SwiftUI
import AppKit
import BastionCore

/// Recently Deleted (B10). Delete moves folders and connections here; they come back with
/// Restore until the keep time (`library.deleted-retention-days`) passes. Inline secrets stay in
/// the vault until then: every prune uses `Library.liveConnectionIds()` (the tree plus this list).
@MainActor enum RecentlyDeleted {
    static let setting = "library.deleted-retention-days"
    /// UI driver: replaces the clock (seconds added to now), so a suite can pass the keep time.
    static var clockOffset: Int64 = 0

    static func now() -> Int64 { Int64(Date().timeIntervalSince1970) + clockOffset }

    static func retentionDays(_ settings: SettingsModel) -> UInt32 { UInt32(settings.value(setting)) ?? 30 }

    /// Drop what is past the keep time; prune the dropped connections' inline secrets and save.
    static func purge(model: LibraryModel, settings: SettingsModel, credentials: CredentialsModel?, days: UInt32? = nil) {
        guard let library = model.library, !library.deletedItems().isEmpty else { return }
        let gone = library.purgeDeleted(now: now(), retentionDays: days ?? retentionDays(settings))
        guard !gone.isEmpty else { return }
        model.mutate { _ in }
        credentials?.pruneInline(library: model.library)
    }

    /// Put an item back; returns a note when it went to the top of the library instead.
    @discardableResult
    static func restore(_ id: String, model: LibraryModel) -> String? {
        var note: String?
        model.mutate { library in
            let r = try library.restoreNode(id: id)
            note = r.atRootBecauseParentMissing ? "Its folder is gone: restored to the top of the library." : nil
        }
        return note
    }

    static func deletePermanently(_ ids: [String], model: LibraryModel, credentials: CredentialsModel?) {
        model.mutate { library in for id in ids { _ = try library.deletePermanently(id: id) } }
        credentials?.pruneInline(library: model.library)
    }

    static func empty(model: LibraryModel, credentials: CredentialsModel?) {
        model.mutate { _ = $0.emptyDeleted() }
        credentials?.pruneInline(library: model.library)
    }

    /// "Delete permanently?" with the names; true when confirmed. The UI driver answers with `alert`.
    static func confirm(_ title: String, names: [String], button: String) -> Bool {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = names.prefix(5).joined(separator: ", ") + (names.count > 5 ? ", …" : "")
        alert.alertStyle = .warning
        alert.addButton(withTitle: button).hasDestructiveAction = true
        alert.addButton(withTitle: "Cancel").keyEquivalent = "\u{1b}"
        return alert.runModalInFront() == .alertFirstButtonReturn
    }

    static func age(_ seconds: Int64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(seconds))
        return date.formatted(date: .abbreviated, time: .shortened)
    }
}

/// View › Recently Deleted…: the list, Restore, Delete Permanently and Empty.
struct RecentlyDeletedView: View {
    @Environment(LibraryModel.self) private var model
    @Environment(SettingsModel.self) private var settings
    @Environment(CredentialsModel.self) private var credentials
    @Environment(Commands.self) private var commands
    private var dismiss = PanelDismiss()
    @State private var items: [DeletedItemView] = []
    @State private var selection = Set<String>()
    @State private var note: String?
    @State private var sort = [KeyPathComparator(\DeletedItemView.deletedAt, order: .reverse)]

    private var picked: [DeletedItemView] { items.filter { selection.contains($0.id) } }
    private var days: UInt32 { RecentlyDeleted.retentionDays(settings) }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Recently Deleted").font(DS.Font.bodyStrong)
                Spacer()
                Text(days == 0 ? "Keep: off" : "Keep: \(days) days").font(DS.Font.caption).foregroundStyle(.secondary)
                    .help("Items are deleted for good after this time. Change it in Settings › General.")
            }
            .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            if items.isEmpty {
                EmptyState(symbol: "trash", title: "Nothing deleted", message: days == 0 ? "Keep time is off." : "Deleted items stay here \(days) days.") { EmptyView() }
            } else {
                Table(items.sorted(using: sort), selection: $selection, sortOrder: $sort) {
                    TableColumn("Name", value: \.name) { d in
                        Label(d.name, systemImage: d.kind == "folder" ? "folder" : "terminal").lineLimit(1)
                            .help(d.kind == "folder" ? "\(d.connectionCount) connections" : d.name)
                    }
                    TableColumn("From") { d in Text(d.parentName ?? "Library").lineLimit(1).foregroundStyle(.secondary) }
                    TableColumn("Deleted", value: \.deletedAt) { d in Text(RecentlyDeleted.age(d.deletedAt)).lineLimit(1).foregroundStyle(.secondary) }
                }
                .contextMenu(forSelectionType: String.self) { ids in
                    Button("Restore") { restore(ids) }
                    Divider()
                    Button("Delete Permanently…", role: .destructive) { deletePermanently(ids) }
                } primaryAction: { ids in restore(ids) }
                .onDeleteCommand { deletePermanently(selection) }
            }
            if let note {
                Text(note).font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, DS.Space.m).padding(.top, DS.Space.xs)
            }
            Divider()
            HStack(spacing: DS.Space.xs) {
                Button("Empty…") { emptyAll() }.disabled(items.isEmpty)
                    .help("Delete everything here for good")
                Button("Delete…") { deletePermanently(selection) }.disabled(selection.isEmpty)
                    .help("Delete the selected items for good")
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Restore") { restore(selection) }.keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(selection.isEmpty)
                    .help("Put back in its folder, or at the top if the folder is gone")
            }
            .padding(DS.Space.s)
        }
        .panelFrame(width: DS.Size.managerWidth + 120, height: DS.Size.managerHeight)
        .onAppear(perform: reload)
        .onChange(of: model.revision) { _, _ in reload() }
    }

    private func reload() {
        items = model.library?.deletedItems() ?? []
        selection = selection.intersection(Set(items.map(\.id)))
    }

    private func restore(_ ids: Set<String>) {
        let notes = items.filter { ids.contains($0.id) }.compactMap { RecentlyDeleted.restore($0.id, model: model) }
        note = notes.first
        if ids.count == 1, let id = ids.first { commands.selectNode?(id) }
        reload()
    }

    private func deletePermanently(_ ids: Set<String>) {
        let names = items.filter { ids.contains($0.id) }.map(\.name)
        guard !names.isEmpty, RecentlyDeleted.confirm(names.count == 1 ? "Delete “\(names[0])” permanently?" : "Delete \(names.count) items permanently?", names: names, button: "Delete") else { return }
        RecentlyDeleted.deletePermanently(Array(ids), model: model, credentials: credentials)
        note = nil
        reload()
    }

    private func emptyAll() {
        guard RecentlyDeleted.confirm("Empty Recently Deleted?", names: items.map(\.name), button: "Empty") else { return }
        RecentlyDeleted.empty(model: model, credentials: credentials)
        note = nil
        reload()
    }
}

/// Purge at open, on a library switch and once a day; asks before Off drops what is kept.
@MainActor struct RecentlyDeletedHooks: ViewModifier {
    let model: LibraryModel
    let settings: SettingsModel
    let credentials: CredentialsModel

    func body(content: Content) -> some View {
        content
            .task(id: model.library.map { ObjectIdentifier($0) }) {
                while !Task.isCancelled {
                    RecentlyDeleted.purge(model: model, settings: settings, credentials: credentials)
                    try? await Task.sleep(for: .seconds(24 * 60 * 60))
                }
            }
            .onChange(of: settings.value(RecentlyDeleted.setting)) { old, new in
                guard new == "0", let count = model.library?.deletedItems().count, count > 0 else { return }
                let names = model.library?.deletedItems().map(\.name) ?? []
                if RecentlyDeleted.confirm("Delete \(count) kept item\(count == 1 ? "" : "s") now?", names: names, button: "Delete") {
                    RecentlyDeleted.purge(model: model, settings: settings, credentials: credentials, days: 0)
                } else {
                    settings.set(RecentlyDeleted.setting, old)
                }
            }
    }
}
extension DeletedItemView: Identifiable {}
