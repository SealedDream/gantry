#if BASTION_TEST_HOOKS
import AppKit

// Layout evenness (overnight item 9): for every row of controls in a visible window (toolbars, button
// rows, icon strips) the controls of one group must have the same size, share a centre line and sit at
// even gaps (within 1 pt). A row is a set of 3+ controls whose vertical centres agree within 2 pt and
// that sit in the same parent. Frames come from the same view walk as `fit` (SwiftUI exposes no
// accessibility tree without an assistive client; AppKit-backed controls report their AX frames).
// Icons: an icon-only button must carry an accessibility label or tooltip naming its action, and two
// buttons in a row must not share one label. Run with `even <name>` or with BASTION_FIT_EVEN=1 on `fit`.
extension Driver {
    static let evenTolerance: CGFloat = 1
    /// Buttons further apart than this are separate groups (a toolbar leading and trailing cluster).
    static let evenClusterGap: CGFloat = 24
    /// The action name a user (and VoiceOver) gets: the accessibility label first, as SwiftUI puts a
    /// button's label there and not in the AppKit title or tooltip.
    func evenName(_ e: FitElement) -> String {
        let v = e.view
        let candidates: [String?] = [v.accessibilityLabel(), (v as? NSControl)?.cell?.accessibilityLabel(),
                                     v.accessibilityTitle(), e.text, v.toolTip]
        return candidates.compactMap { $0 }.first { !$0.isEmpty } ?? ""
    }

    func evenProblems(in window: NSWindow) -> [String] {
        let t = Self.evenTolerance
        let items = fitElements(in: window).filter { e in
            guard ["button", "icon-button", "toolbar-item", "popup", "segment"].contains(e.kind) else { return false }
            guard let s = e.scroll else { return true }
            return s.insetBy(dx: -t, dy: -t).contains(e.frame)
        }
        func describe(_ e: FitElement) -> String { "\(e.kind)(\(type(of: e.view))) \"\(e.text.prefix(30))\" \(Int(e.frame.minX)),\(Int(window.frame.height - e.frame.maxY)) \(Int(e.frame.width))x\(Int(e.frame.height))" }
        // Rows by centre line across the whole window, then contiguous clusters (gap <= evenClusterGap).
        // Grouping by parent view merged unrelated SwiftUI clusters that share one hosting view.
        // The header (toolbar, tab strip) is MAC-IDLE-01's: BASTION_EVEN_HEADER=1 includes it.
        let header = ProcessInfo.processInfo.environment["BASTION_EVEN_HEADER"] == "1"
        let contentTop = window.contentLayoutRect.maxY
        let group = items.filter { header || (!$0.inToolbar && $0.frame.minY < contentTop - 1) }
        var problems: [String] = []
        do {
            var rows: [[FitElement]] = []
            for e in group.sorted(by: { $0.frame.midY < $1.frame.midY }) {
                if var last = rows.last, abs(last[0].frame.midY - e.frame.midY) <= 2 { last.append(e); rows[rows.count - 1] = last } else { rows.append([e]) }
            }
            for row in rows where row.count >= 3 {
                let sortedRow = row.sorted { $0.frame.minX < $1.frame.minX }
                var clusters: [[FitElement]] = []
                for e in sortedRow {
                    if let last = clusters.last?.last, e.frame.minX - last.frame.maxX <= Self.evenClusterGap { clusters[clusters.count - 1].append(e) } else { clusters.append([e]) }
                }
                for r in clusters where r.count >= 3 {
                let tag = "row of \(r.count) at y=\(Int(window.frame.height - r[0].frame.midY))"
                // Icon-only buttons form the strict group (same kind): equal size, equal gaps.
                for kind in Set(r.map(\.kind)) {
                    let g = r.filter { $0.kind == kind }
                    guard g.count >= 3 else { continue }
                    if kind == "icon-button" || kind == "toolbar-item" {
                        let w = g.map(\.frame.width), h = g.map(\.frame.height)
                        if (w.max()! - w.min()!) > t || (h.max()! - h.min()!) > t { problems.append("UNEQUAL SIZE in \(tag): " + g.map(describe).joined(separator: " | ")) }
                    }
                    let centres = g.map(\.frame.midY)
                    if centres.max()! - centres.min()! > t { problems.append("OFF CENTRE LINE in \(tag): " + g.map(describe).joined(separator: " | ")) }
                    let gaps = zip(g, g.dropFirst()).map { $1.frame.minX - $0.frame.maxX }
                    if gaps.allSatisfy({ $0 >= 0 }), gaps.max()! - gaps.min()! > t { problems.append("UNEVEN GAPS \(gaps.map { String(format: "%.1f", $0) }.joined(separator: "/")) in \(tag): " + g.map(describe).joined(separator: " | ")) }
                }
                let icons = r.filter { $0.kind == "icon-button" }
                // SwiftUI buttons keep their label in SwiftUI's accessibility tree, which a view walk
                // cannot read without an assistive client: only AppKit controls are checked for a name.
                let unnamed = icons.filter { evenName($0).isEmpty && !String(describing: type(of: $0.view)).contains("SwiftUI") }
                unnamed.forEach { problems.append("ICON WITHOUT ACTION NAME in \(tag): \(describe($0))") }
                let names = icons.map { evenName($0) }.filter { !$0.isEmpty }
                if Set(names).count != names.count { problems.append("DUPLICATE ICON ACTION in \(tag): \(names.joined(separator: ", "))") }
                }
            }
        }
        return problems
    }

    func even(_ name: String) async {
        await settle(0.3)
        var failures = 0
        for (i, w) in NSApp.windows.filter({ $0.isVisible && $0.frame.width > 40 && $0.frame.height > 20 }).enumerated() {
            let problems = evenProblems(in: w)
            failures += problems.count
            let title = w.title.isEmpty ? (w.identifier?.rawValue ?? String(describing: type(of: w))) : w.title
            problems.forEach { write("FAIL EVEN \(name) [\(title) \(Int(w.frame.width))x\(Int(w.frame.height))] \($0)") }
            if !problems.isEmpty { await capture(w, "even-\(name)-\(i)") }
        }
        write("EVEN \(name) \(NSApp.effectiveAppearance.name.rawValue) \(failures == 0 ? "ok" : "\(failures) problems")")
    }
}
#endif
