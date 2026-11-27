#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

// DASH-01: UI-driver steps for the folder dashboard. `dash-state` logs the page as text:
//   DASHBOARD folder=<name> count=<header line> deep=on|off locked=yes|no rows=<n> selected=<names>
//   DASH-ROW <name>|<address>|<type>|<status>|<user>|<login>|<folder>
// `dash-filter <text>`, `dash-select <name,name>`, `dash-select-all`, `dash-deep on|off`,
// `dash-connect` and `dash-open` act as the page's controls do.
// `dash-expect-rows <n>` and `dash-expect <text>` fail the run when the page differs.
extension Driver {
    func dashboardStep(_ cmd: String, _ arg: String) async {
        let line = arg.isEmpty ? cmd : "\(cmd) \(arg)"
        let d = DashboardDriver.shared
        switch cmd {
        case "dash-state", "dash-expect-rows", "dash-expect":
            await settle(0.2)
            guard let s = d.snapshot, UIDriver.services?.sessions.folderPage != nil else { return write("FAIL \(line): no folder dashboard") }
            if cmd == "dash-expect-rows" { return write("\(s.rowCount == Int(arg) ? "" : "FAIL ")\(line) -> rows \(s.rowCount)") }
            if cmd == "dash-expect" {
                let text = ([s.count] + s.rows).joined(separator: "\n")
                return write("\(text.contains(arg) ? "" : "FAIL ")\(line) -> \(s.count)")
            }
            write("DASHBOARD folder=\(s.folder) count=\(s.count) deep=\(s.deep ? "on" : "off") locked=\(s.locked ? "yes" : "no") rows=\(s.rowCount) selected=\(s.selected.joined(separator: ","))")
            s.rows.prefix(40).forEach { write("DASH-ROW \($0)") }
        case "dash-delete":
            // Delete with the confirmation answered yes; logs the names it listed.
            guard UIDriver.services?.sessions.folderPage != nil else { return write("FAIL \(line): no folder dashboard") }
            d.lastDeleteNames = []
            d.confirmDelete = { names in DashboardDriver.shared.lastDeleteNames = names; return true }
            d.request = DashboardDriver.Request(command: "delete", arg: "")
            await settle(0.5)
            d.confirmDelete = nil
            write("DASH-DELETE confirmed \(d.lastDeleteNames.joined(separator: ","))")
        case "dash-expect-delete":
            let got = d.lastDeleteNames.joined(separator: ",")
            write("\(got == arg ? "" : "FAIL ")\(line) -> \(got)")
        case "dash-filter", "dash-select", "dash-select-all", "dash-deep", "dash-connect", "dash-open":
            guard UIDriver.services?.sessions.folderPage != nil else { return write("FAIL \(line): no folder dashboard") }
            d.request = DashboardDriver.Request(command: String(cmd.dropFirst("dash-".count)), arg: arg)
            await settle(0.3)
            write(line)
        case "dash-columns", "dash-expect-columns", "dash-columns-menu", "dash-column":
            guard UIDriver.services?.sessions.folderPage != nil else { return write("FAIL \(line): no folder dashboard") }
            await dashboardColumnsStep(cmd, arg)
        case "dash-bench":
            await dashboardBench(arg)
        case "dash-bench-filter":
            await dashboardSync("filter " + arg)
        case "dash-bench-sync":
            await dashboardSync(arg)
        default:
            write("FAIL \(line): unknown dashboard step")
        }
    }
}

// `dash-bench open <folder>` | `dash-bench deep on|off` | `dash-bench filter <text>`: one timed
// change, from the request until the page has published its new rows and the window has drawn.
// Budgets (docs/TESTING.md, DASH-01 packet): open or subfolders 150 ms, filter 50 ms.
extension Driver {
    private static let dashBenchTimeout = 5.0

    func dashboardBench(_ arg: String) async {
        let parts = arg.split(separator: " ", maxSplits: 1).map(String.init)
        guard let what = parts.first else { return write("FAIL dash-bench: no change named") }
        let value = parts.count > 1 ? parts[1] : ""
        let d = DashboardDriver.shared
        let before = d.snapshot?.rowCount
        let loadsBefore = d.loads
        let budget: Double = what == "filter" ? 50 : 150
        d.snapshot = nil
        // The suites launch the app in the background, where macOS naps it and coalesces timers;
        // a page in use is in front. Measure it as in front: no nap, timers on time.
        let activity = ProcessInfo.processInfo.beginActivity(options: [.userInitiated, .latencyCritical], reason: "dash-bench")
        defer { ProcessInfo.processInfo.endActivity(activity) }
        let renders = RenderCount.counts
        let t0 = CFAbsoluteTimeGetCurrent()
        switch what {
        case "open":
            func find(_ f: FolderView) -> FolderView? { f.name == value ? f : f.folders.lazy.compactMap(find).first }
            guard let id = commands.model.tree.flatMap(find)?.id else { return write("FAIL dash-bench \(arg): no such folder") }
            commands.selectNode?(id)
        case "deep", "filter", "noop": d.request = DashboardDriver.Request(command: what, arg: value)
        default: return write("FAIL dash-bench \(arg): unknown change")
        }
        func done() -> Bool {
            guard let s = d.snapshot else { return false }
            switch what {
            case "open": return s.folder == value && d.loads > loadsBefore
            case "deep": return s.deep == (value == "on") && s.rowCount != before
            default: return true
            }
        }
        while !done() {
            if CFAbsoluteTimeGetCurrent() - t0 > Self.dashBenchTimeout { return write("FAIL dash-bench \(arg): page did not update") }
            try? await Task.sleep(for: .milliseconds(1))
        }
        window?.contentView?.layoutSubtreeIfNeeded()
        window?.displayIfNeeded()
        let ms = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        // A no-op is the harness floor (request, update cycle, publish, draw): reported, never failed.
        // Information only (coordinator 2026-11-14): budgets are checked on the `dash-bench-sync` steps.
        let over = false
        write(String(format: "%@DASH-BENCH %@ '%@' %.1f ms -> %d rows (budget %.0f ms; core call %.1f ms; bodies %@)", over ? "FAIL " : "", what, value, ms,
                     d.snapshot?.rowCount ?? -1, budget, what == "filter" || what == "noop" ? 0 : d.coreMs, RenderCount.delta(since: renders)))
    }
}

extension Driver {
    /// `dash-bench-sync open <folder>` | `deep on|off` | `filter <text>` | `noop`: one change timed
    /// as the tree's bench steps are (`time-select`, `bench-filter`): apply, one yield, layout,
    /// display, all on the main thread with no wait for a later update. Fails over budget, and
    /// fails when the page has not shown the change by then. A step that built the table is "cold".
    func dashboardSync(_ arg: String) async {
        let parts = arg.split(separator: " ", maxSplits: 1).map(String.init)
        guard let what = parts.first else { return write("FAIL dash-bench-sync: no change named") }
        let value = parts.count > 1 ? parts[1] : ""
        let d = DashboardDriver.shared
        let budget: Double = what == "filter" ? 50 : (what == "noop" ? 50 : 150)
        let renders = RenderCount.counts, loads = d.loads
        // Found before the clock starts: `window` walks the view tree to find the main window.
        let win = window
        let t0 = CFAbsoluteTimeGetCurrent()
        switch what {
        case "open":
            func find(_ f: FolderView) -> FolderView? { f.name == value ? f : f.folders.lazy.compactMap(find).first }
            guard let id = commands.model.tree.flatMap(find)?.id else { return write("FAIL dash-bench-sync \(arg): no such folder") }
            commands.selectNode?(id)
        case "deep": d.applyDeep?(value == "on")
        case "filter": d.applyFilter?(value)
        case "noop": d.applyNoop?()
        default: return write("FAIL dash-bench-sync \(arg): unknown change")
        }
        await Task.yield()
        win?.contentView?.layoutSubtreeIfNeeded()
        win?.displayIfNeeded()
        let ms = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        let s = d.snapshot
        let shown: Bool = switch what {
        case "open": s?.folder == value && d.loads > loads
        case "deep": s?.deep == (value == "on") && d.loads > loads
        default: s != nil
        }
        let delta = RenderCount.delta(since: renders)
        let cold = delta.contains("DashboardTable.make") ? " cold" : ""
        let ok = shown && ms <= budget
        write(String(format: "%@DASH-SYNC %@%@ '%@' %.1f ms -> %d rows (budget %.0f ms; core call %.1f ms, rows built %.1f ms, sorted %.1f ms; %@bodies %@)", ok ? "" : "FAIL ", what, cold, value, ms,
                     s?.rowCount ?? -1, budget, what == "open" || what == "deep" ? d.coreMs : 0, what == "open" || what == "deep" ? d.buildMs : 0, what == "open" || what == "deep" ? d.sortMs : 0, shown ? "" : "NOT SHOWN YET; ", delta))
    }
}

#endif
