#if BASTION_TEST_HOOKS
import AppKit
import SwiftUI

/// UI driver steps that assert the library panel's state (owner point 25, 2026-11-07). Each step
/// writes one `LIB-…` line, prefixed with `FAIL` when the panel is not as expected.
extension Driver {
    /// Handles a library step; false when `cmd` is not one.
    func libraryStep(_ cmd: String, _ arg: String) async -> Bool {
        switch cmd {
        case "library-expect": await libraryExpect(arg)
        case "library-toolbar-button": await libraryToolbarButton()
        case "library-rapid": await libraryRapid(Int(arg) ?? 6)
        case "library-tab-during-slide": await libraryTabDuringSlide()
        case "library-resize-during-slide": await libraryResizeDuringSlide(arg)
        case "library-a11y": libraryAccessibility()
        default: return false
        }
        return true
    }

    private var libraryAutoHide: Bool { UIDriver.services?.settings.value("tree.auto-hide") == "true" }

    /// The sidebar item of the main window's split view controller (NavigationSplitView's column).
    private var sidebarItem: NSSplitViewItem? {
        let root = window?.contentView?.superview ?? window?.contentView
        for split in root?.allSubviews(of: NSSplitView.self) ?? [] {
            if let c = split.delegate as? NSSplitViewController, let item = c.splitViewItems.first(where: { $0.behavior == .sidebar }) { return item }
        }
        return nil
    }

    /// The library column as AppKit has it: its width when expanded, 0 when collapsed.
    private var columnWidth: Int {
        guard let item = sidebarItem, !item.isCollapsed else { return 0 }
        return Int(item.viewController.view.frame.width)
    }

    /// `library-expect shown=on|off [saved=on|off] [docked=on|off]`: waits for the split view to
    /// settle, then checks the model and the real column geometry agree with what is asked.
    private func libraryExpect(_ arg: String) async {
        _ = await settleSplitViews()
        let want = Dictionary(uniqueKeysWithValues: arg.split(separator: " ").compactMap { kv -> (String, String)? in
            let p = kv.split(separator: "=", maxSplits: 1).map(String.init)
            return p.count == 2 ? (p[0], p[1]) : nil
        })
        let tree = commands.tree
        let shown = tree.libraryShown(autoHide: libraryAutoHide)
        let width = columnWidth
        let have = ["shown": shown ? "on" : "off", "saved": tree.libraryVisible ? "on" : "off",
                    "docked": AutoDock.shared.docked ? "on" : "off"]
        var problems = want.compactMap { k, v in have[k] == v ? nil : "\(k)=\(have[k] ?? "?") (want \(v))" }
        // Geometry must follow the model: a shown library has a usable column, a hidden one none.
        if shown && width < Int(DS.Size.sidebarMin) - 1 { problems.append("column width \(width) < \(Int(DS.Size.sidebarMin)) while shown") }
        if !shown && width > 1 { problems.append("column width \(width) while hidden") }
        let item = sidebarItem
        let v = item?.viewController.view
        let diag = "collapsed=\(item.map { $0.isCollapsed ? "yes" : "no" } ?? "?") frame=\(v.map { NSStringFromRect($0.frame) } ?? "-") hidden=\(v?.isHiddenOrHasHiddenAncestor == true ? "yes" : "no") items=\((v?.superview as? NSSplitView)?.arrangedSubviews.map { "\(Int($0.frame.width))\($0.isHidden ? "h" : "")" }.joined(separator: ",") ?? "-")"
        let state = have.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " ")
        let tail = problems.isEmpty ? "" : " | " + problems.joined(separator: "; ")
        write("\(problems.isEmpty ? "" : "FAIL ")LIB-EXPECT \(arg) | \(state) width=\(width) window=\(Int(window?.frame.width ?? 0)) \(diag)\(tail)")
    }

    /// The toolbar's own sidebar button (NavigationSplitView's toggle), clicked as a user would.
    private func libraryToolbarButton() async {
        guard let w = window, let toolbar = w.toolbar,
              let item = toolbar.items.first(where: { $0.itemIdentifier == .toggleSidebar || $0.itemIdentifier.rawValue.lowercased().contains("togglesidebar") })
        else { return write("FAIL LIB-TOOLBAR-BUTTON: no sidebar toggle in the toolbar (\(window?.toolbar?.items.map { $0.itemIdentifier.rawValue }.joined(separator: ",") ?? "-"))") }
        // The item's own button in the title bar (SwiftUI gives the item no action of its own).
        let root = w.contentView?.superview
        let button = (item.view as? NSButton) ?? item.view?.allSubviews(of: NSButton.self).first
            ?? root?.allSubviews(of: NSButton.self).first { $0.action.map { NSStringFromSelector($0).contains("toggleSidebar") } ?? false }
        if let button { button.performClick(nil) }
        else if let action = item.action, NSApp.sendAction(action, to: item.target, from: item) {}
        else { return write("FAIL LIB-TOOLBAR-BUTTON: the toggle has no button or action") }
        await settle(0.6)
        write("LIB-TOOLBAR-BUTTON clicked")
    }

    /// `library-rapid <n>`: n toggles through the router 40 ms apart (faster than the slide).
    private func libraryRapid(_ n: Int) async {
        guard let sv = UIDriver.services else { return write("FAIL library-rapid") }
        for _ in 0..<n {
            sv.router.open("toggle-library")
            try? await Task.sleep(for: .milliseconds(40))
        }
        write("LIB-RAPID \(n)")
    }

    /// Toggle, then switch tabs while the panel is still sliding.
    private func libraryTabDuringSlide() async {
        guard let sv = UIDriver.services else { return write("FAIL library-tab-during-slide") }
        sv.router.open("toggle-library")
        try? await Task.sleep(for: .milliseconds(60))
        sv.sessions.selectNeighbourTab(forward: true)
        write("LIB-TAB-DURING-SLIDE tab \(sv.sessions.selectedTab?.title ?? "-")")
    }

    /// `library-resize-during-slide WxH`: toggle, then resize the window mid-slide.
    private func libraryResizeDuringSlide(_ arg: String) async {
        let p = arg.split(separator: "x").compactMap { Double($0) }
        guard let sv = UIDriver.services, let w = window, p.count == 2 else { return write("FAIL library-resize-during-slide \(arg)") }
        sv.router.open("toggle-library")
        try? await Task.sleep(for: .milliseconds(60))
        var f = w.frame
        f.origin.y += f.height - p[1]
        f.size = NSSize(width: p[0], height: p[1])
        w.setFrame(f, display: true)
        write("LIB-RESIZE-DURING-SLIDE \(arg)")
    }

    /// Focus and VoiceOver: a hidden library must not hold keyboard focus or stay visible to
    /// VoiceOver; a shown one exposes its outline.
    private func libraryAccessibility() {
        let shown = commands.tree.libraryShown(autoHide: libraryAutoHide)
        let col = sidebarItem?.viewController.view
        let outline = col.flatMap { $0.allSubviews(of: KeyOutlineView.self).first }
        var problems: [String] = []
        if !shown, let r = window?.firstResponder as? NSView, let col, r.isDescendant(of: col), !AutoDock.shared.docked {
            problems.append("keyboard focus stays in the hidden library")
        }
        let onScreen = outline != nil && columnWidth > 1
        if shown && (!onScreen || outline?.accessibilityRole() != .outline) { problems.append("library outline not exposed to VoiceOver") }
        if !shown && onScreen { problems.append("hidden library still visible to VoiceOver") }
        let responder = (window?.firstResponder).map { String(describing: type(of: $0)) } ?? "none"
        let tail = problems.isEmpty ? "" : " | " + problems.joined(separator: "; ")
        write("\(problems.isEmpty ? "" : "FAIL ")LIB-A11Y shown=\(shown ? "on" : "off") focus=\(responder)\(tail)")
    }
}
#endif
