#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for the PostgreSQL live suite (PG-LIVE): every feature of the plugin's view against a
/// real server. Node ids are the plugin's (plugins/official/postgres/src/lib.rs). `<name>` is the entry.
/// `pg-sql <name> <sql…>` puts the SQL in the editor and runs it as ⌘↩ does; prints the status line, the
/// Messages text and the first result row
/// `pg-cancel <name> <sql…>` runs the SQL, presses Cancel after 1.5 s; prints the status line
/// `pg-expect <name> <node> <text…>` FAIL unless the node's text (a table: its rows) contains the text within 20 s
/// Tree keys are written with `/` for the plugin's separator (U+001F).
/// `pg-tree <name> <parent key|-> <label,label…>` asks the navigator for children; FAIL unless each label is there
/// `pg-plan <name> <text…>` the plan tree shows a node with the text
/// `pg-tree-select <name> <key>` selects a navigator item as a click does
/// `pg-tree-menu <name> <key> <item>` a navigator item's context-menu entry
/// `pg-copy <name> <text…>` Copy of the selected rows; the clipboard must hold the text
/// `pg-export <name> <file> <text…>` Export CSV through the save panel to <file>; the file must hold the text
/// `pg-input <name> <node> pressed|toggled <0|1>|number <n>|choice <i>|text <s>|sorted <col> <0|1>` one input
extension Driver {
    private func pgText(_ m: PluginViewModel, _ id: Int) -> String {
        guard let node = m.nodes.first(where: { $0.id == id }) else { return "" }
        if let t = node.value as? String { return t }
        let d = node.value as? [String: Any]
        if let t = d?["text"] as? String { return t }
        if node.kind == "table" { return (m.rows[id] ?? []).map { $0.map { $0.map { "\($0)" } ?? "NULL" }.joined(separator: "|") }.joined(separator: "\n") }
        return d.map { "\($0)" } ?? ""
    }

    private func pgWaitStatus(_ m: PluginViewModel, before: String, limit: Int = 240) async {
        var n = 0
        while n < limit, pgText(m, 33) == before || pgText(m, 33).hasPrefix("Running") { try? await Task.sleep(nanoseconds: 250_000_000); n += 1 }
        await settle(0.3)
    }

    func postgresLiveStep(_ cmd: String, _ a: [String]) async -> Bool {
        guard cmd.hasPrefix("pg-") else { return false }
        guard let c = a.first.flatMap({ commands.model.connection(named: $0) }), let m = PluginViewWindow.model(for: "entry:\(c.id)") else {
            write("FAIL \(cmd): no tab"); return true
        }
        let rest = a.dropFirst().joined(separator: " ")
        switch cmd {
        case "pg-sql", "pg-cancel":
            let before = pgText(m, 33)
            m.input(node: 19, ["kind": "text", "value": rest])
            m.input(node: 19, ["kind": "run", "value": rest])
            if cmd == "pg-cancel" {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                let mid = pgText(m, 33)
                m.input(node: 13, ["kind": "pressed"])
                await pgWaitStatus(m, before: mid, limit: 60)
                write("PG-CANCEL \(c.name) during=\(mid) status=\(pgText(m, 33)) ended=\(m.ended ?? "none")")
                return true
            }
            await pgWaitStatus(m, before: before)
            var tries = 0
            while tries < 20, (m.rows[27] ?? []).isEmpty, !pgText(m, 33).contains(" 0 row") { try? await Task.sleep(nanoseconds: 125_000_000); tries += 1 }
            let first = (m.rows[27] ?? []).first.map { $0.map { $0.map { "\($0)" } ?? "NULL" }.joined(separator: "|") } ?? "none"
            let sets = (m.nodes.first { $0.id == 24 }?.value as? [String: Any])?["options"] as? [String] ?? []
            write("PG-SQL \(c.name) status=\(pgText(m, 33)) rows=\((m.rows[27] ?? []).count) first=\(first) sets=\(sets.count) messages=\(pgText(m, 29).replacingOccurrences(of: "\n", with: " / ")) banner=\(m.message ?? "none") ended=\(m.ended ?? "none")")
        case "pg-expect":
            guard a.count >= 3, let id = Int(a[1]) else { write("FAIL pg-expect: args"); return true }
            let want = a.dropFirst(2).joined(separator: " ")
            var tries = 0
            while tries < 80, !pgText(m, id).contains(want) { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            let text = pgText(m, id)
            write("\(text.contains(want) ? "" : "FAIL ")PG-EXPECT \(c.name) node=\(id) want=\(want) got=\(String(text.prefix(300)).replacingOccurrences(of: "\n", with: " / "))")
        case "pg-tree":
            guard a.count >= 2 else { write("FAIL pg-tree: args"); return true }
            let parent = a[1] == "-" ? nil : a[1].replacingOccurrences(of: "/", with: "\u{1f}")
            let key = PluginViewModel.childKey(6, parent)
            m.askChildren(node: 6, parent: parent)
            var tries = 0
            while tries < 80, m.children[key] == nil { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            let items = m.children[key] ?? []
            let labels = items.map { $0["label"] as? String ?? "" }
            let want = a.count > 2 ? a[2...].joined(separator: " ").split(separator: ",").map(String.init) : []
            let missing = want.filter { w in !labels.contains { $0 == w || $0.hasPrefix(w + " (") || $0.hasPrefix(w + "(") } }
            let keys = items.prefix(12).map { ($0["key"] as? String ?? "").replacingOccurrences(of: "\u{1f}", with: "/") }.joined(separator: " ; ")
            write("\(m.children[key] == nil || !missing.isEmpty ? "FAIL " : "")PG-TREE \(c.name) parent=\(a[1]) count=\(items.count) labels=\(labels.prefix(20).joined(separator: ",")) missing=\(missing.joined(separator: ",")) keys=\(keys)")
        case "pg-plan":
            // `pg-plan <name> <text…>`: FAIL unless the plan tree's top level shows a node with the text (within 20 s).
            let want = a.dropFirst().joined(separator: " ")
            let key = PluginViewModel.childKey(32, nil)
            func labels() -> [String] { (m.children[key] ?? []).map { $0["label"] as? String ?? "" } }
            var tries = 0
            while tries < 80, !labels().contains(where: { $0.contains(want) }) { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            let ok = labels().contains(where: { $0.contains(want) })
            write("\(ok ? "" : "FAIL ")PG-PLAN \(c.name) want=\(want) labels=\(labels().prefix(5).joined(separator: " | ")) refusal=\(m.childRefusals[key] ?? "none")")
        case "pg-tree-select":
            m.selectTreeItem(node: 6, key: rest.replacingOccurrences(of: "/", with: "\u{1f}"))  // the row's click path
            await settle(0.5)
            write("PG-TREE-SELECT \(c.name) key=\(rest)")
        case "pg-tree-menu":
            guard a.count == 3 else { write("FAIL pg-tree-menu: args"); return true }
            let before = pgText(m, 33)
            m.input(node: 6, ["kind": "menu", "key": a[1].replacingOccurrences(of: "/", with: "\u{1f}"), "item": a[2]])
            await pgWaitStatus(m, before: before, limit: 80)
            write("PG-TREE-MENU \(c.name) item=\(a[2]) status=\(pgText(m, 33)) rows=\((m.rows[27] ?? []).count)")
        case "pg-copy":
            // `pg-copy <name> <text…>`: presses Copy (select rows first); FAIL unless the clipboard holds the text.
            // A private pasteboard stands in for the user's.
            let board = NSPasteboard(name: .init("app.bastion.uitest.pg"))
            board.clearContents()
            PluginViewModel.pasteboard = board
            m.input(node: 25, ["kind": "pressed"])
            let want = a.dropFirst().joined(separator: " ")
            var tries = 0
            while tries < 40, !(board.string(forType: .string) ?? "").contains(want) { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            let got = board.string(forType: .string) ?? ""
            write("\(got.contains(want) ? "" : "FAIL ")PG-COPY \(c.name) chars=\(got.count) first=\(got.split(separator: "\n").first.map(String.init) ?? "none") banner=\(m.message ?? "none")")
        case "pg-export":
            // `pg-export <name> <file> <text…>`: presses Export CSV; the save panel answers <file> (in the library's
            // folder); FAIL unless the core wrote it with the text in it.
            guard a.count >= 3 else { write("FAIL pg-export: args"); return true }
            let url = URL(fileURLWithPath: a[1], relativeTo: LibraryModel.dataDir).standardizedFileURL
            try? FileManager.default.removeItem(at: url)
            LibraryIO.scriptedPanelURL = url
            m.input(node: 26, ["kind": "pressed"])
            let want = a.dropFirst(2).joined(separator: " ")
            var tries = 0
            func text() -> String { (try? String(contentsOf: url, encoding: .utf8)) ?? "" }
            while tries < 40, !text().contains(want) { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            write("\(text().contains(want) ? "" : "FAIL ")PG-EXPORT \(c.name) bytes=\(text().utf8.count) header=\(text().split(separator: "\n").first.map(String.init) ?? "none") banner=\(m.message ?? "none")")
        case "pg-input":
            guard a.count >= 3, let id = Int(a[1]) else { write("FAIL pg-input: args"); return true }
            let v = a.count > 3 ? a[3] : ""
            let input: [String: Any]
            switch a[2] {
            case "pressed": input = ["kind": "pressed"]
            case "toggled": input = ["kind": "toggled", "value": v == "1"]
            case "number": input = ["kind": "number", "value": Double(v) ?? 0]
            case "choice": input = ["kind": "choice", "value": Int(v) ?? 0]
            case "sorted": input = ["kind": "sorted", "column": Int(v) ?? 0, "ascending": a.count > 4 && a[4] == "1"]
            default: input = ["kind": "text", "value": a.dropFirst(3).joined(separator: " ")]
            }
            m.input(node: id, input)
            await settle(0.8)
            write("PG-INPUT \(c.name) node=\(id) \(a[2]) banner=\(m.message ?? "none")")
        default:
            return false
        }
        return true
    }
}
#endif
