#if BASTION_TEST_HOOKS
import AppKit

// FOLDER-COLUMNS: UI-driver steps for the dashboard's column chooser, with real mouse events.
//   dash-columns                      logs DASH-COLUMNS <shown ids, left to right>
//   dash-expect-columns <a,b,…>       fails unless exactly these columns are shown
//   dash-column <id> on|off           fails unless that column is shown (on) or hidden (off)
//   dash-columns-menu button => Item  left-clicks the Columns button, picks Item in its menu
//   dash-columns-menu header => Item  right-clicks the table header, picks Item in its menu
extension Driver {
    private var dashTable: NSTableView? {
        window?.contentView?.superview?.allSubviews(of: NSTableView.self)
            .filter { $0.accessibilityIdentifier() == "folder-dashboard-table" }
            // The prewarmed page keeps a table of its own off screen: take the one on screen.
            .filter { !$0.isHiddenOrHasHiddenAncestor }
            .max { $0.visibleRect.width * $0.visibleRect.height < $1.visibleRect.width * $1.visibleRect.height }
    }

    func dashboardColumnsStep(_ cmd: String, _ arg: String) async {
        let line = arg.isEmpty ? cmd : "\(cmd) \(arg)"
        switch cmd {
        case "dash-column":
            // `dash-column <id> on|off`: that column is shown (on) or hidden (off).
            await settle(0.2)
            let p = arg.split(separator: " ").map(String.init)
            guard p.count == 2, let col = dashTable?.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier(p[0])) else { return write("FAIL \(line): no such column") }
            let ok = col.isHidden == (p[1] == "off")
            write("\(ok ? "" : "FAIL ")\(line) -> \(col.isHidden ? "off" : "on")")
        case "dash-columns", "dash-expect-columns":
            await settle(0.2)
            guard let table = dashTable else { return write("FAIL \(line): no dashboard table") }
            let shown = table.tableColumns.filter { !$0.isHidden }.map(\.identifier.rawValue).joined(separator: ",")
            let all = window?.contentView?.superview?.allSubviews(of: NSTableView.self).filter { $0.accessibilityIdentifier() == "folder-dashboard-table" }.count ?? 0
            let hidden = table.tableColumns.filter(\.isHidden).map(\.identifier.rawValue).joined(separator: ",")
            if cmd == "dash-columns" { return write("DASH-COLUMNS \(shown) hidden=\(hidden) tables=\(all) choice=\(UserDefaults.standard.string(forKey: "folder-dashboard.column-choice") ?? "-")") }
            write("\(shown == arg ? "" : "FAIL ")\(line) -> \(shown)")
        default:
            await dashboardColumnsMenu(line, arg)
        }
    }

    private func dashboardColumnsMenu(_ line: String, _ arg: String) async {
        let halves = arg.components(separatedBy: " => ")
        guard halves.count == 2, let window, let table = dashTable else { return write("FAIL \(line): no dashboard") }
        let pick = halves[1]
        var titles: [String] = []
        var picked = false
        let observer = NotificationCenter.default.addObserver(forName: NSMenu.didBeginTrackingNotification, object: nil, queue: nil) { note in
            let box = DashMenuBox(menu: note.object as? NSMenu)
            MainActor.assumeIsolated {
                guard let menu = box.menu, menu.supermenu == nil, menu !== NSApp.mainMenu else { return }
                // A delegate-filled menu may begin tracking before its delegate has filled it.
                if menu.items.isEmpty { menu.delegate?.menuNeedsUpdate?(menu) }
                titles = menu.items.filter { !$0.isSeparatorItem }.map(\.title)
                if titles.isEmpty { titles = ["(empty, delegate \(menu.delegate.map { String(describing: type(of: $0)) } ?? "none"))"] }
                let index = menu.items.firstIndex { $0.title == pick }
                picked = index != nil
                let held = DashMenuBox(menu: menu)
                RunLoop.main.perform(inModes: [.eventTracking, .default, .modalPanel]) {
                    MainActor.assumeIsolated {
                        held.menu?.cancelTracking()
                        if let index { DispatchQueue.main.async { held.menu?.performActionForItem(at: index) } }
                    }
                }
            }
        }
        defer { NotificationCenter.default.removeObserver(observer) }
        if halves[0] == "header" {
            // As the tree's `menu` step: a real right-click event on the header, the menu the header gives for
            // it, and the item run through NSMenu (a quiet run's inactive window opens no context menu itself).
            guard let header = table.headerView else { return write("FAIL \(line): no header") }
            let r = header.headerRect(ofColumn: 0)
            let point = header.convert(NSPoint(x: r.midX, y: r.midY), to: nil)
            let down = NSEvent.mouseEvent(with: .rightMouseDown, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                          windowNumber: window.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)!
            guard let menu = header.menu(for: down) else { return write("FAIL \(line): no header menu") }
            menu.delegate?.menuNeedsUpdate?(menu)
            titles = menu.items.filter { !$0.isSeparatorItem }.map(\.title)
            if let index = menu.items.firstIndex(where: { $0.title == pick }) { picked = true; menu.performActionForItem(at: index) }
        } else {
            // A real left click where the Columns button is drawn (its probe frame); the menu is answered as it opens.
            guard let frame = UIProbe.frames["folder-dashboard-columns"], let content = window.contentView else {
                return write("FAIL \(line): no Columns button")
            }
            if !window.isKeyWindow { window.makeKey() }
            let local = content.isFlipped ? NSPoint(x: frame.midX, y: frame.midY) : NSPoint(x: frame.midX, y: content.bounds.height - frame.midY)
            click(at: content.convert(local, to: nil), in: window)
        }
        await settle(1.0)
        write("\(picked ? "" : "FAIL ")\(line) -> menu=[\(titles.joined(separator: "|"))]")
    }
}

private struct DashMenuBox: @unchecked Sendable { let menu: NSMenu? }
#endif
