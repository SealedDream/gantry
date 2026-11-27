#if BASTION_TEST_HOOKS
import AppKit

// `toolbar-layout`: where the tab strip and the session actions sit in the title bar. Each toolbar item
// is drawn by an AppKit item viewer; its frame is read from the title-bar view tree. Owner UX spec
// 2026-11-04 §4: the strip fills the bar and every action is on its right.
extension Driver {
    static let trailingActions = ["Find", "Quick Connect", "Connect", "Split", "Inspector"]

    /// The inspector toggle button in its trailing titlebar accessory, and its frame in window coordinates.
    func inspectorAccessoryControl() -> (view: NSView, rect: NSRect)? {
        guard let window else { return nil }
        for vc in window.titlebarAccessoryViewControllers where vc.view.identifier == InspectorAccessoryInstaller.InstallerView.identifier {
            if let b = vc.view.allSubviews(of: NSButton.self).first { return (b, b.convert(b.bounds, to: nil)) }
        }
        return nil
    }

    /// Toolbar items left to right: label (or identifier) and window x range.
    func toolbarItemFrames() -> [(label: String, x0: CGFloat, x1: CGFloat)] {
        guard let frameView = window?.contentView?.superview else { return [] }
        var frames: [(label: String, x0: CGFloat, x1: CGFloat)] = []
        func walk(_ view: NSView) {
            if String(describing: type(of: view)).contains("ToolbarItemViewer"),
               let item = view.value(forKey: "item") as? NSToolbarItem {
                let r = view.convert(view.bounds, to: nil)
                let label = item.label.isEmpty ? item.paletteLabel : item.label
                // SwiftUI items have no label and a UUID identifier: name them by the title their
                // button draws (the open-sessions count), which is what the user sees.
                // The tab switcher shows no count since the tab bar redesign: named by its control.
                let drawn = (view.allSubviews(of: SessionsCountButton.self).isEmpty ? nil : Self.sessionsMenuLabel)
                    ?? view.allSubviews(of: NSButton.self).first { !$0.title.isEmpty }?.title
                    ?? view.allSubviews(of: NSControl.self).compactMap { $0.accessibilityLabel() }.first { !$0.isEmpty }
                frames.append((label.isEmpty ? (drawn ?? item.itemIdentifier.rawValue) : label, r.minX, r.maxX))
            }
            view.subviews.forEach(walk)
        }
        walk(frameView)
        // The inspector toggle is a trailing titlebar accessory, flush right (owner 2026-11-23): reported with the items.
        if let (_, r) = inspectorAccessoryControl() { frames.append(("Inspector", r.minX, r.maxX)) }
        return frames.sorted { $0.x0 < $1.x0 }
    }

    /// NSToolbar's own spacer items, by the label AppKit gives them.
    static let toolbarSpacers: Set<String> = ["Flexible Space", "Space"]
    /// The name `toolbarItemFrames` gives the tab switcher (`SessionsCountButton`).
    static let sessionsMenuLabel = "open-sessions"

    /// Owner 2026-11-05 (c): the open-sessions menu ("▣ N ▾") is the first item after the
    /// sidebar toggle, sidebar shown or hidden.
    func sessionsMenuPlace() -> String {
        guard let window, let s = UIDriver.services?.sessions else { return "FAIL sessions-menu: no window" }
        let frames = toolbarItemFrames().filter { $0.x1 > $0.x0 }
        guard let menu = frames.firstIndex(where: { $0.label == Self.sessionsMenuLabel }) else {
            return "FAIL SESSIONS-MENU no tab switcher (\(s.tabs.count) tabs): " + frames.map(\.label).joined(separator: ", ")
        }
        // Only the leading item (the sidebar toggle in Classic, the library switcher in Compact) may
        // sit left of it. Both are SwiftUI items with UUID identifiers and no label, so the check
        // is by position: none of them can be told apart by name.
        let before = frames[..<menu].map(\.label)
        // Linked against the macOS 27 SDK the toolbar reports a flexible space before the sidebar
        // toggle (nm-sessions-menu-left, census 2026-11-17); a spacer is no item a user sees.
        let ok = before.filter { !Self.toolbarSpacers.contains($0) }.count <= 1
        return "\(ok ? "" : "FAIL ")SESSIONS-MENU \(Int(window.frame.width))pt at x=\(Int(frames[menu].x0)) after [\(before.joined(separator: ", "))] next=\(frames.indices.contains(menu + 1) ? frames[menu + 1].label : "-")"
    }

    func toolbarLayoutReport() -> String {
        guard let window else { return "FAIL toolbar-layout: no window" }
        let frames = toolbarItemFrames()
        // The strip is the only unlabelled item wider than 90 pt over the session area.
        guard let strip = frames.filter({ !Self.trailingActions.contains($0.label) && $0.x1 - $0.x0 > 90 && !$0.label.contains("Space") })
            .max(by: { ($0.x1 - $0.x0) < ($1.x1 - $1.x0) }) else { return "FAIL toolbar-layout: no tab strip" }
        let actions = frames.filter { Self.trailingActions.contains($0.label) }
        let left = actions.filter { $0.x0 < strip.x1 - 1 }.map(\.label)
        let fill = Int((strip.x1 - strip.x0) / window.frame.width * 100)
        let parts = ["strip \(Int(strip.x0))–\(Int(strip.x1))"] + actions.map { "\($0.label) \(Int($0.x0))" }
        let verdict = left.isEmpty ? "" : "FAIL toolbar-layout: left of the tabs: \(left.joined(separator: ", ")) "
        return "\(verdict)TOOLBAR-LAYOUT \(Int(window.frame.width))pt area \(Int(UIDriver.services?.sessions.sessionAreaWidth ?? -1)) fill \(fill)% " + parts.joined(separator: ", ")
    }

    // MARK: toolbar-click (owner point 30): a real click on a top-right toolbar button, then its effect.

    /// The control a toolbar item draws, by label, and its frame in window coordinates.
    func toolbarControl(_ label: String) -> (view: NSView, rect: NSRect)? {
        guard let frameView = window?.contentView?.superview else { return nil }
        var found: (NSView, NSRect)?
        func walk(_ view: NSView) {
            guard found == nil else { return }
            if String(describing: type(of: view)).contains("ToolbarItemViewer"),
               let item = view.value(forKey: "item") as? NSToolbarItem,
               case let control = view.allSubviews(of: NSControl.self).first ?? view,
               (item.label.isEmpty ? item.paletteLabel : item.label) == label || control.accessibilityLabel() == label {
                found = (control, control.convert(control.bounds, to: nil))
                return
            }
            view.subviews.forEach(walk)
        }
        walk(frameView)
        if found == nil, label == "Inspector" { return inspectorAccessoryControl() }
        return found
    }

    /// What the top-right buttons change, as one line the suites match against.
    func toolbarEffects(menu: [String]) -> String {
        guard let s = UIDriver.services?.sessions else { return "no services" }
        let popover = NSApp.windows.contains { $0.isVisible && String(describing: type(of: $0)).contains("Popover") }
        let sheet = NSApp.windows.contains { $0.attachedSheet != nil }
        return "searching=\(s.searching ? "yes" : "no") popover=\(popover ? "yes" : "no") inspector=\(commands.tree.inspectorPresented ? "on" : "off")"
            + " tabs=\(s.tabs.count) panes=\(s.selectedTab?.panes.count ?? 0) sheet=\(sheet ? "yes" : "no") page=\(s.connectionPage == nil ? "no" : "yes")"
            + " menu=[\(menu.joined(separator: "|"))]"
    }

    /// `toolbar-click <Label>[ menu] [=> token token …]`: clicks the item (its arrow segment with
    /// `menu`) through the window's event path, reads any menu it opens (then closes it), and fails
    /// unless the effects line holds every expected token.
    func toolbarClick(_ arg: String) async {
        let halves = arg.components(separatedBy: " => ")
        var words = halves[0].split(separator: " ").map(String.init)
        let arrow = words.last == "menu"
        if arrow { words.removeLast() }
        let label = words.joined(separator: " ")
        let expect = halves.count > 1 ? halves[1].split(separator: " ").map(String.init) : []
        guard let window, let (control, rect) = toolbarControl(label) else {
            return write("FAIL TOOLBAR-CLICK \(label): no such item (have \(toolbarItemFrames().map(\.label).joined(separator: ", ")))")
        }
        let enabled = (control as? NSControl)?.isEnabled ?? true
        // Segmented controls: the icon segment is the first 28 pt, the arrow the last 14 pt.
        let x = control is NSSegmentedControl ? (arrow ? rect.maxX - 7 : rect.minX + 14) : rect.midX
        var titles: [String] = []
        let observer = NotificationCenter.default.addObserver(forName: NSMenu.didBeginTrackingNotification, object: nil, queue: nil) { note in
            let box = UncheckedMenu(menu: note.object as? NSMenu)
            MainActor.assumeIsolated {
                guard let menu = box.menu, menu.supermenu == nil, menu !== NSApp.mainMenu else { return }
                titles = menu.items.filter { !$0.isSeparatorItem }.map(\.title)
                menu.perform(#selector(NSMenu.cancelTracking), with: nil, afterDelay: 0.05, inModes: [.eventTracking, .default, .modalPanel])
            }
        }
        click(at: NSPoint(x: x, y: rect.midY), in: window)
        await settle(0.8)
        NotificationCenter.default.removeObserver(observer)
        let effects = "enabled=\(enabled ? "yes" : "no") " + toolbarEffects(menu: titles)
        let missing = expect.filter { !effects.contains($0) }
        write("\(missing.isEmpty ? "" : "FAIL ")TOOLBAR-CLICK \(label)\(arrow ? " menu" : "") -> \(effects)" + (missing.isEmpty ? "" : " missing \(missing.joined(separator: " "))"))
    }
}

private struct UncheckedMenu: @unchecked Sendable { let menu: NSMenu? }

// MARK: header-layout (HEADER-A): the Compact header's one row, left to right.
extension Driver {
    /// Controls that left the header in Compact; they must not be in the toolbar.
    static let classicOnly = ["Find", "Quick Connect", "Connect", "Split", "Add"]
    /// Widest a toolbar item holding only an icon may be. Linked against the macOS 27 SDK an icon
    /// item sits in its own glass capsule, 44 pt for the switcher (was 40 before; header-a-mac,
    /// census 2026-11-17); a switcher with its library name is well over 100 pt.
    static let iconItemMaxWidth: CGFloat = 48
    /// The switcher's trailing edge may sit this far from the sidebar's divider.
    static let dividerTolerance: CGFloat = 14
    /// Most the inspector toggle may sit from the window's right edge: its accessory inset plus the button's own padding.
    static let inspectorEdgeTolerance: CGFloat = 24

    func compactHeaderReport() -> String {
        guard let window, let sv = UIDriver.services else { return "FAIL header-layout: no window" }
        let frames = toolbarItemFrames().filter { $0.x1 > $0.x0 }
        var fails: [String] = []
        let leftovers = frames.filter { Self.classicOnly.contains($0.label) }.map(\.label)
        if !leftovers.isEmpty { fails.append("classic items: \(leftovers.joined(separator: ", "))") }
        let shown = commands.tree.libraryShown(autoHide: sv.settings.value("tree.auto-hide") == "true")
        // SwiftUI items are unlabelled: by place. Switcher first; then the tab group button, the
        // strip and the inspector toggle (labelled) last.
        let switcherItem = frames.first
        let count = frames.count > 1 ? frames[1] : nil
        let inspector = frames.last { $0.label == "Inspector" }
        let switcher = switcherItem.map { NSRect(x: $0.x0, y: 0, width: $0.x1 - $0.x0, height: 1) }
        if frames.count < 4 { fails.append("\(frames.count) items, want switcher, tab group button, tabs, inspector") }
        if inspector == nil { fails.append("no inspector toggle") }
        if let inspector, let last = frames.last, last.x0 > inspector.x0 { fails.append("inspector not at the end") }
        // Flush with the right edge (owner 2026-11-23): the button's own edge inset is all that is left.
        if let inspector, window.frame.width - inspector.x1 > Self.inspectorEdgeTolerance {
            fails.append("inspector \(Int(window.frame.width - inspector.x1)) pt from the right edge")
        }
        if shown, let count, count.x0 < sv.sessions.sidebarWidth - 1 { fails.append("tab group button left of the divider") }
        let divider = sv.sessions.sidebarWidth
        if shown, let switcher, abs(switcher.maxX - divider) > Self.dividerTolerance {
            fails.append("switcher ends at \(Int(switcher.maxX)), divider at \(Int(divider))")
        }
        if !shown, let switcher, switcher.width > Self.iconItemMaxWidth { fails.append("switcher not an icon while the library is hidden") }
        // The selected tab shows its icon and title, not just its close button (owner check, #876).
        var active = "-"
        if !sv.sessions.mainTabs.isEmpty, sv.settings.value("tabs.vertical") != "true" {
            if let tab = DriverEvents.headerFrame("active-tab"), let port = DriverEvents.headerFrame("tab-viewport") {
                let seen = max(0, min(tab.maxX, port.maxX) - max(tab.minX, port.minX))
                active = "\(Int(seen))/\(Int(tab.width))pt"
                if seen < tab.width - 2 { fails.append("active tab clipped: \(active) visible") }
            } else if DriverEvents.headerFrame("tab-viewport") != nil {
                fails.append("active tab not in the strip")
            }
        }
        let parts = frames.map { "\($0.label.isEmpty ? "?" : $0.label) \(Int($0.x0))–\(Int($0.x1))" }
        let head = "HEADER-LAYOUT \(Int(window.frame.width))pt library \(shown ? "shown" : "hidden") divider \(Int(divider)) switcher \(switcher.map { "\(Int($0.minX))–\(Int($0.maxX))" } ?? "-") active tab \(active)"
        return (fails.isEmpty ? "" : "FAIL header-layout: \(fails.joined(separator: "; ")) ") + head + " | " + parts.joined(separator: ", ")
    }
}
// MARK: header-menu, header-search (HEADER-A): real clicks on the Compact header's menus.
extension Driver {
    /// `header-menu <control label> [=> <item title>]`: clicks the control by its accessibility
    /// label through the window's event path, lists the menu it opens, picks `<item title>` (or
    /// closes the menu), then reports what changed: tabs, sheet, library, popover.
    func headerMenu(_ arg: String) async {
        let halves = arg.components(separatedBy: " => ")
        let label = halves[0]
        let pick = halves.count > 1 ? halves[1] : nil
        guard let window, let sv = UIDriver.services else { return write("FAIL HEADER-MENU \(label): no window") }
        guard let rect = DriverEvents.headerFrame(label) ?? headerAXFrame(label, in: window).map({ window.convertFromScreen($0) }) else {
            return write("FAIL HEADER-MENU \(label): no such control (recorded: \(DriverEvents.headerViews.keys.sorted().joined(separator: ", ")))")
        }
        let tabsBefore = sv.sessions.tabs.count
        var titles: [String] = []
        var picked = false
        let observer = NotificationCenter.default.addObserver(forName: NSMenu.didBeginTrackingNotification, object: nil, queue: nil) { note in
            let box = UncheckedMenu(menu: note.object as? NSMenu)
            MainActor.assumeIsolated {
                guard let menu = box.menu, menu.supermenu == nil, menu !== NSApp.mainMenu else { return }
                titles = menu.items.filter { !$0.isSeparatorItem }.map(\.title)
                let index = pick.flatMap { p in menu.items.firstIndex { $0.title == p } }
                picked = index != nil
                // Close first, then run the item as a click on it would (after tracking ends).
                let held = UncheckedMenu(menu: menu)
                RunLoop.main.perform(inModes: [.eventTracking, .default, .modalPanel]) {
                    MainActor.assumeIsolated {
                        held.menu?.cancelTracking()
                        if let index { DispatchQueue.main.async { held.menu?.performActionForItem(at: index) } }
                    }
                }
            }
        }
        click(at: NSPoint(x: rect.midX, y: rect.midY), in: window)
        await settle(1.0)
        NotificationCenter.default.removeObserver(observer)
        let shown = commands.tree.libraryShown(autoHide: sv.settings.value("tree.auto-hide") == "true")
        let sheet = window.attachedSheet.map { "shown \(sheetText($0))" } ?? "none"
        let effects = "menu=[\(titles.joined(separator: "|"))] picked=\(pick.map { picked ? $0 : "MISSING \($0)" } ?? "-") tabs \(tabsBefore)->\(sv.sessions.tabs.count) sheet \(sheet) library \(shown ? "shown" : "hidden")"
        let ok = !titles.isEmpty && (pick == nil || picked)
        write("\(ok ? "" : "FAIL ")HEADER-MENU \(label) -> \(effects)")
    }

    /// `header-click <control> [=> tab]`: one real click on a header control that acts at once (no
    /// menu), then reports what changed. With `=> tab` it fails unless exactly one tab opened (the
    /// compact +: a new local shell at once, owner 2026-11-17).
    func headerClick(_ arg: String) async {
        let halves = arg.components(separatedBy: " => ")
        let label = halves[0]
        let expectTab = halves.count > 1 && halves[1] == "tab"
        guard let window, let sv = UIDriver.services else { return write("FAIL HEADER-CLICK \(label): no window") }
        guard let rect = DriverEvents.headerFrame(label) ?? headerAXFrame(label, in: window).map({ window.convertFromScreen($0) }) else {
            return write("FAIL HEADER-CLICK \(label): no such control")
        }
        let tabsBefore = sv.sessions.tabs.count
        click(at: NSPoint(x: rect.midX, y: rect.midY), in: window)
        await settle(1.0)
        let tabsAfter = sv.sessions.tabs.count
        let sheet = window.attachedSheet.map { "shown \(sheetText($0))" } ?? "none"
        let ok = !expectTab || tabsAfter == tabsBefore + 1
        write("\(ok ? "" : "FAIL ")HEADER-CLICK \(label) -> tabs \(tabsBefore)->\(tabsAfter) sheet \(sheet)")
    }

    /// `header-search <text>`: types `<text>` into the sidebar's search field and presses Return
    /// (the field's action); reports how many rows match and whether Quick Connect opened with the text.
    func headerSearch(_ text: String) async {
        let fields = NSApp.windows.flatMap { ($0.contentView?.superview ?? $0.contentView)?.allSubviews(of: NSTextField.self) ?? [] }
            .filter { $0.isEditable && ($0 is NSSearchField || $0.placeholderString == "Search or connect") }
        guard let field = fields.first else {
            let names = Set(NSApp.windows.flatMap { ($0.contentView?.superview ?? $0.contentView)?.allSubviews(of: NSView.self) ?? [] }
                .map { String(describing: type(of: $0)) }.filter { $0.contains("Search") })
            return write("FAIL HEADER-SEARCH: no field (search views: \(names.sorted().joined(separator: ", ")))")
        }
        field.stringValue = text
        NotificationCenter.default.post(name: NSControl.textDidChangeNotification, object: field)
        (field.delegate as? NSTextFieldDelegate)?.controlTextDidChange?(Notification(name: NSControl.textDidChangeNotification, object: field))
        await settle(0.3)
        let rows = outline?.numberOfRows ?? -1
        let placeholder = field.placeholderString ?? (field.cell as? NSSearchFieldCell)?.placeholderString ?? ""
        field.sendAction(field.action, to: field.target)
        await settle(1.0)
        let qc = popover.flatMap { $0.contentView?.allSubviews(of: NSTextField.self).first { $0.isEditable }?.stringValue }
        let ok = qc == text
        write("\(ok ? "" : "FAIL ")HEADER-SEARCH \"\(placeholder)\" text=\(text) rows=\(rows) quick-connect=\(qc.map { "shown \"\($0)\"" } ?? "none")")
        field.stringValue = ""
        NotificationCenter.default.post(name: NSControl.textDidChangeNotification, object: field)
        (field.delegate as? NSTextFieldDelegate)?.controlTextDidChange?(Notification(name: NSControl.textDidChangeNotification, object: field))
    }

    /// Like `axFrame`, but also starts from every view in the title bar: toolbar items' SwiftUI
    /// hosts are not reached from the window's own accessibility tree.
    func headerAXFrame(_ label: String, in window: NSWindow) -> NSRect? {
        if let frame = axFrame(label: label, in: window) { return frame }
        let roots = (window.contentView?.superview?.allSubviews(of: NSView.self) ?? []).filter { String(describing: type(of: $0)).contains("Hosting") }
        for root in roots {
            var queue: [Any] = [root]
            var visited = 0
            while !queue.isEmpty, visited < 2000 {
                let ax = queue.removeFirst() as AnyObject
                visited += 1
                let names = [ax.accessibilityLabel?() ?? nil, ax.accessibilityTitle?() ?? nil, ax.accessibilityIdentifier?() ?? nil]
                if names.contains(label), let frame = ax.accessibilityFrame?(), frame.width > 0 { return frame }
                queue += ((ax.accessibilityChildren?() ?? nil) ?? [])
            }
        }
        return nil
    }
}
#endif
