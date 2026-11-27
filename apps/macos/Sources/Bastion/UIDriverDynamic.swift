#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for dynamic folders (B15). Results are printed as text:
/// `dyn-allowed <true|false>` whether the entries show (false under a managed ban); FAIL when not as given
/// `dyn-wait <folder>|<seconds>` until that folder's Refresh ends; prints its outcome
/// `dyn-expect <folder>|<outcome>` FAIL unless the last outcome starts with it (`done 2 1`, `refused`, `revoked`…)
/// `dyn-review` the open consent sheet's program, arguments, time limit and warning count
/// `dyn-bound <folder>|<yes|no>` FAIL unless the folder is bound to a task (or not)
/// `dyn-menu <folder>|<yes|no>` FAIL unless the folder's menu has (or lacks) Dynamic Folder…
/// `row-tip <row name>` a tree row's tooltip, as `dump` names the row
extension Driver {
    /// Handles one of these steps; false when `cmd` is not one.
    func dynamicStep(_ cmd: String, _ arg: String) async -> Bool {
        let dynamic = commands.dynamic
        let parts = arg.split(separator: "|", maxSplits: 1).map(String.init)
        switch cmd {
        case "dyn-allowed":
            write("\(arg.isEmpty || arg == String(dynamic.allowed) ? "" : "FAIL ")DYN-ALLOWED \(dynamic.allowed)")
        case "dyn-wait":
            guard let id = dynamicFolderId(parts.first ?? "") else { write("FAIL dyn-wait \(arg): no folder"); return true }
            let deadline = CFAbsoluteTimeGetCurrent() + (parts.count > 1 ? Double(parts[1]) ?? 20 : 20)
            while dynamic.isRunning(id) && CFAbsoluteTimeGetCurrent() < deadline { await settle(0.2) }
            await settle(0.4)
            write("\(dynamic.isRunning(id) ? "FAIL " : "")DYN-WAIT \(parts[0]) -> \(dynamic.lastOutcome[id] ?? "-")")
        case "dyn-expect":
            guard parts.count == 2, let id = dynamicFolderId(parts[0]) else { write("FAIL dyn-expect \(arg)"); return true }
            let got = dynamic.lastOutcome[id] ?? "-"
            write("\(got.hasPrefix(parts[1]) ? "" : "FAIL ")DYN-EXPECT \(parts[0]) \(parts[1]) -> \(got)")
        case "dyn-review":
            guard let r = dynamic.trusting?.review else { write("FAIL dyn-review: no consent sheet"); return true }
            write("DYN-REVIEW program=\(r.program) args=\(r.args.joined(separator: " ")) timeout=\(r.timeoutSecs) trusted=\(r.trusted) warnings=\(r.warnings.count)")
        case "dyn-bound":
            guard parts.count == 2, let id = dynamicFolderId(parts[0]) else { write("FAIL dyn-bound \(arg)"); return true }
            let bound = dynamic.taskId(of: id) != nil
            write("\(bound == (parts[1] == "yes") ? "" : "FAIL ")DYN-BOUND \(parts[0]) -> \(bound ? "yes" : "no")")
        case "dyn-menu":
            guard parts.count == 2, let id = dynamicFolderId(parts[0]) else { write("FAIL dyn-menu \(arg)"); return true }
            let menu = NSMenu()
            dynamic.appendMenu(menu, folderId: id, folderName: parts[0])
            let has = menu.items.contains { $0.title == "Dynamic Folder…" }
            write("\(has == (parts[1] == "yes") ? "" : "FAIL ")DYN-MENU \(parts[0]) -> \(menu.items.map(\.title).filter { !$0.isEmpty }.joined(separator: " | "))")
        case "row-tip":
            guard let r = row(named: arg), let cell = outline?.view(atColumn: 0, row: r, makeIfNecessary: true) else {
                write("FAIL row-tip \(arg)"); return true
            }
            write("ROW-TIP \(arg) -> \((cell.toolTip ?? "-").replacingOccurrences(of: "\n", with: " / "))")
        default:
            return false
        }
        return true
    }

    /// A folder's id by name, anywhere in the library.
    private func dynamicFolderId(_ name: String) -> String? {
        func find(_ f: FolderView) -> String? {
            if let hit = f.folders.first(where: { $0.name == name }) { return hit.id }
            return f.folders.lazy.compactMap(find).first
        }
        return commands.model.tree.flatMap(find)
    }
}
#endif
