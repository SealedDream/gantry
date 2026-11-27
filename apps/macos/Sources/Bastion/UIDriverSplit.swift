#if BASTION_TEST_HOOKS
import AppKit

/// `split-dump`: every split view in the key window, with each item's frame and limits (MAC-HEADER-FIT).
extension Driver {
    func splitDump() -> String {
        guard let root = NSApp.windows.first(where: { $0.isVisible && $0.contentView != nil && $0.toolbar != nil })?.contentView else { return "SPLIT none" }
        var lines: [String] = ["SPLIT window=\(Int(root.window?.frame.width ?? 0))"]
        func walk(_ v: NSView, _ depth: Int) {
            if let s = v as? NSSplitView {
                let ctl = s.delegate.map { String(describing: type(of: $0)) } ?? "-"
                lines.append("SPLIT d=\(depth) \(ctl) w=\(Int(s.frame.width)) autosave=\(s.autosaveName ?? "-")")
                if let c = s.delegate as? NSSplitViewController {
                    for (i, it) in c.splitViewItems.enumerated() {
                        let f = it.viewController.view.frame
                        lines.append("  item\(i) beh=\(it.behavior.rawValue) x=\(Int(f.minX)) w=\(Int(f.width)) min=\(Int(it.minimumThickness)) max=\(Int(it.maximumThickness)) hold=\(it.holdingPriority.rawValue) collapsed=\(it.isCollapsed) vc=\(type(of: it.viewController))")
                    }
                }
                for c in s.constraints where c.isActive && (c.firstAttribute == .width || c.firstAttribute == .leading || c.firstAttribute == .trailing) {
                    lines.append("  c \(c)")
                }
                for sub in s.arrangedSubviews {
                    for c in sub.constraints where c.isActive && c.firstAttribute == .width { lines.append("  sub-c \(c)") }
                    lines.append("  fit=\(Int(sub.fittingSize.width)) hug=\(sub.contentHuggingPriority(for: .horizontal).rawValue)")
                }
            }
            for s in v.subviews { walk(s, depth + 1) }
        }
        walk(root.superview ?? root, 0)
        return lines.joined(separator: "\n")
    }

    /// `split-min <window> <points>`: shrinks the window as far as it goes and checks that the first
    /// split column keeps its minimum (Settings sidebar, same modifier-order fault as #1432).
    func splitMin(_ arg: String) async -> String {
        let p = arg.split(separator: " ").map(String.init)
        guard p.count == 2, let want = Int(p[1]) else { return "FAIL split-min: usage split-min <window> <points>" }
        guard let w = findWindow(p[0]) else { return "FAIL split-min \(p[0]): no window" }
        guard let ctl = Self.firstSplitController(w.contentView) else { return "FAIL split-min \(p[0]): no split view" }
        let saved = w.frame
        w.setContentSize(NSSize(width: 100, height: w.contentLayoutRect.height))
        await settle(0.8)
        let item = ctl.splitViewItems[0]
        let width = Int(item.viewController.view.frame.width.rounded())
        let minimum = Int(item.minimumThickness.rounded())
        w.setFrame(saved, display: true)
        let ok = width >= want && minimum >= want
        return "\(ok ? "" : "FAIL ")SPLIT-MIN \(p[0]) window=\(Int(w.frame.width)) col0 w=\(width) min=\(minimum) want>=\(want)"
    }

    static func firstSplitController(_ v: NSView?) -> NSSplitViewController? {
        guard let v else { return nil }
        if let s = v as? NSSplitView, let c = s.delegate as? NSSplitViewController { return c }
        for sub in v.subviews { if let c = firstSplitController(sub) { return c } }
        return nil
    }
}
#endif
