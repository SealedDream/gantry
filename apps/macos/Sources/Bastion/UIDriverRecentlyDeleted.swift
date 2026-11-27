#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for Recently Deleted (B10).
/// `deleted = <name>, …` what Recently Deleted holds, oldest first (`none` when empty)
/// `deleted-folder <folder> = <name>, …` the folder's subfolders, then its connections (`none` when empty, `gone` when not in the tree)
/// `deleted-restore <name>` Restore, as the window's button does; prints the note when it went to the top
/// `deleted-days <n>` move the clock n days ahead and purge, as the daily timer does
/// `deleted-inline-set <connection>` give the connection an inline password (a random value; `test-vault` first)
/// `deleted-inline <connection> = yes|no` whether its inline password is still in the vault
/// `deleted-prune` prune inline secrets as a credential edit does
/// `deleted-undo` Edit › Undo in the main window
extension Driver {
    func deletedStep(_ cmd: String, _ arg: String) async {
        guard let sv = UIDriver.services else { return write("FAIL \(cmd): no services") }
        let model = commands.model
        let parts = arg.components(separatedBy: " = ")
        let expected: String? = arg.hasPrefix("= ") ? String(arg.dropFirst(2)) : parts.count == 2 ? parts[1] : nil
        let subject = parts.count == 2 ? parts[0] : arg
        func check(_ tag: String, _ got: String) {
            write("\(expected == nil || expected == got ? "" : "FAIL ")\(tag) \(got)")
        }
        func connection(_ name: String) -> ConnectionView? { AppIpc.connections(in: model.tree).first { $0.name == name } }
        func folder(_ name: String, in f: FolderView?) -> FolderView? {
            guard let f else { return nil }
            return f.name == name ? f : f.folders.lazy.compactMap { folder(name, in: $0) }.first
        }
        switch cmd {
        case "deleted":
            await settle(0.3)
            let names = (model.library?.deletedItems() ?? []).map(\.name)
            check("DELETED", names.isEmpty ? "none" : names.joined(separator: ", "))
        case "deleted-folder":
            await settle(0.3)
            guard let f = folder(subject, in: model.tree) else { return check("DELETED-FOLDER \(subject)", "gone") }
            let names = f.folders.map(\.name) + f.connections.map(\.name)
            check("DELETED-FOLDER \(subject)", names.isEmpty ? "none" : names.joined(separator: ", "))
        case "deleted-restore":
            guard let item = model.library?.deletedItems().first(where: { $0.name == subject }) else { return write("FAIL DELETED-RESTORE \(subject): not deleted") }
            let note = RecentlyDeleted.restore(item.id, model: model)
            await settle(0.3)
            write("DELETED-RESTORE \(subject)\(note.map { " -> \($0)" } ?? "")")
        case "deleted-days":
            guard let n = Int64(subject) else { return write("FAIL deleted-days \(arg)") }
            RecentlyDeleted.clockOffset = n * 86_400
            RecentlyDeleted.purge(model: model, settings: sv.settings, credentials: sv.credentials)
            await settle(0.3)
            write("DELETED-DAYS \(n)")
        case "deleted-inline-set":
            guard let c = connection(subject), let vault = sv.credentials.vault else { return write("FAIL deleted-inline-set \(subject)") }
            do {
                try vault.setInlinePassword(connectionId: c.id, username: "tester", password: UUID().uuidString)
                DeletedIds.byName[subject] = c.id
                write("DELETED-INLINE-SET \(subject)")
            } catch { write("FAIL deleted-inline-set \(subject): \(error)") }
        case "deleted-inline":
            guard let id = DeletedIds.byName[subject] ?? connection(subject)?.id, let vault = sv.credentials.vault else { return write("FAIL deleted-inline \(subject)") }
            let has = ((try? vault.inlineFor(connectionId: id)) ?? nil) != nil
            check("DELETED-INLINE \(subject)", has ? "yes" : "no")
        case "deleted-prune":
            sv.credentials.pruneInline(library: model.library)
            write("DELETED-PRUNE")
        case "deleted-undo":
            let undo = ([window].compactMap { $0 } + NSApp.windows).compactMap(\.undoManager).first { $0.canUndo }
            let can = undo?.canUndo == true
            undo?.undo()
            await settle(0.5)
            write("\(can ? "" : "FAIL ")DELETED-UNDO")
        default:
            write("FAIL unknown step \(cmd)")
        }
    }

    @MainActor enum DeletedIds { static var byName: [String: String] = [:] }
}
#endif
