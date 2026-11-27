import SwiftUI

/// Layout-fit for the SwiftUI start window (UI driver `doc-start-fit`). SwiftUI draws its controls
/// without NSViews, so the view-walking `fit` cannot see them; each start-window control reports
/// its frame here instead (test builds only; a no-op otherwise), with the same rules as `fit`:
/// icon buttons and rows need 24 pt, bezeled buttons and checkboxes keep AppKit's height, every
/// control lies inside the window and no two overlap.
@MainActor
enum StartWindowFit {
    enum Kind: String { case icon, button, toggle, row, field }
    struct Probe { let kind: Kind; let label: String; let frame: CGRect; var pinned = false }
    private(set) static var probes: [String: Probe] = [:]
    static let minHit: CGFloat = 24

    static func record(_ id: String, _ probe: Probe?) {
        #if BASTION_TEST_HOOKS
        probes[id] = probe
        #endif
    }

    /// Problems for a window of `size` (SwiftUI global coordinates: top-left origin, content area).
    static func problems(size: CGSize) -> (list: [String], checked: Int) {
        let shown = Array(probes.values)
        let bounds = CGRect(origin: .zero, size: size).insetBy(dx: -1, dy: -1)
        var out: [String] = []
        for p in shown {
            let desc = "\(p.kind.rawValue) '\(p.label)' \(Int(p.frame.minX)),\(Int(p.frame.minY)) \(Int(p.frame.width))x\(Int(p.frame.height))"
            // Inside a scroller a control may run below the window; it may never leave it sideways or
            // at the top, and pinned controls (actions, Cancel / Create) must be wholly inside.
            let sideways = p.frame.minX < bounds.minX || p.frame.maxX > bounds.maxX || p.frame.minY < bounds.minY
            if sideways || (p.pinned && !bounds.contains(p.frame)) { out.append("outside the window: \(desc)") }
            if [.icon, .row].contains(p.kind), p.frame.height < minHit - 0.5 { out.append("hit target under \(Int(minHit)) pt: \(desc)") }
            if p.kind == .icon, p.frame.width < minHit - 0.5 { out.append("hit target under \(Int(minHit)) pt wide: \(desc)") }
        }
        let solid = shown.filter { $0.kind != .row }
        for i in solid.indices { for j in solid.indices where j > i {
            let a = solid[i].frame.insetBy(dx: 1, dy: 1), b = solid[j].frame.insetBy(dx: 1, dy: 1)
            if a.intersects(b) { out.append("overlap: '\(solid[i].label)' / '\(solid[j].label)'") }
        } }
        return (out, shown.count)
    }
}

extension View {
    /// Report this start-window control's frame to `StartWindowFit` (test builds; free otherwise).
    func startFit(_ kind: StartWindowFit.Kind, _ label: String, pinned: Bool = false) -> some View {
        #if BASTION_TEST_HOOKS
        let id = "\(kind.rawValue):\(label)"
        return background(GeometryReader { g in
            Color.clear
                .onAppear { StartWindowFit.record(id, .init(kind: kind, label: label, frame: g.frame(in: .global), pinned: pinned)) }
                .onChange(of: g.frame(in: .global)) { _, f in StartWindowFit.record(id, .init(kind: kind, label: label, frame: f, pinned: pinned)) }
                .onDisappear { StartWindowFit.record(id, nil) }
        })
        #else
        return self
        #endif
    }
}
