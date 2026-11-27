import SwiftUI
import BastionCore

/// One terminal inside a tab's split tree.
@MainActor @Observable
final class TerminalPane: Identifiable {
    let id = UUID()
    let terminal: Terminal
    var remoteTitle: String?
    var ended = false
    /// Set while a supervised SSH link is reconnecting or paused for sleep.
    var linkStatus: String?
    /// Text a program asked to copy (OSC 52, policy "ask"), waiting for Allow or Deny.
    var clipboardRequest: String?
    /// TERM-MARKS: an `ssh` line the user typed here, offered as "Save as Connection".
    var sshOffer: TypedSshTarget?

    init(terminal: Terminal) {
        self.terminal = terminal
        TriggerRuntime.shared.attach(terminal)
        TermEventsRuntime.shared.start()
    }
}

enum SplitAxis: String, Sendable {
    /// Side by side (⌘D).
    case right
    /// Stacked (⇧⌘D).
    case down
}

enum PaneDirection: Sendable { case left, right, up, down }

/// Share of a split given to its first side; the divider drags it. The range matches the core's
/// `workspace::RATIO_MIN…RATIO_MAX`, which saved workspaces are clamped to.
@MainActor @Observable
final class SplitRatio {
    static let range: ClosedRange<CGFloat> = 0.1...0.9
    var value: CGFloat

    init(_ value: CGFloat = 0.5) { self.value = min(Self.range.upperBound, max(Self.range.lowerBound, value)) }
}

/// A tab's layout: a single pane, or two subtrees split along an axis.
/// Structural operations return a new tree; panes and ratios are shared.
@MainActor
indirect enum PaneNode {
    case leaf(TerminalPane)
    case split(SplitAxis, SplitRatio, PaneNode, PaneNode)

    var leaves: [TerminalPane] {
        switch self {
        case .leaf(let p): [p]
        case .split(_, _, let a, let b): a.leaves + b.leaves
        }
    }

    /// The shape in pre-order for a saved workspace: `right:0.620`/`down:0.500` (axis and the
    /// first side's share) then both sides, or `leaf`. The core validates and clamps it.
    var layoutSteps: [String] {
        switch self {
        case .leaf: ["leaf"]
        case .split(let axis, let ratio, let a, let b):
            [axis.rawValue + ":" + String(format: "%.3f", Double(ratio.value))] + a.layoutSteps + b.layoutSteps
        }
    }

    /// Each pane's rectangle when the tree fills `rect` (dividers ignored).
    func frames(in rect: CGRect) -> [(pane: TerminalPane, rect: CGRect)] {
        switch self {
        case .leaf(let p): return [(p, rect)]
        case .split(let axis, let ratio, let a, let b):
            let (ra, rb) = axis == .right
                ? rect.divided(atDistance: rect.width * ratio.value, from: .minXEdge)
                : rect.divided(atDistance: rect.height * ratio.value, from: .minYEdge)
            return a.frames(in: ra) + b.frames(in: rb)
        }
    }

    /// The pane next to `from` in `direction`: the nearest one beyond that edge, preferring the
    /// most overlap on the other axis. Nil at the edge of the tab.
    func neighbour(of from: UUID, _ direction: PaneDirection) -> TerminalPane? {
        let all = frames(in: CGRect(x: 0, y: 0, width: 1, height: 1))
        guard let origin = all.first(where: { $0.pane.id == from })?.rect else { return nil }
        let eps = 1e-6
        func gap(_ r: CGRect) -> CGFloat? {
            switch direction {
            case .left: r.maxX <= origin.minX + eps ? origin.minX - r.maxX : nil
            case .right: r.minX >= origin.maxX - eps ? r.minX - origin.maxX : nil
            case .up: r.maxY <= origin.minY + eps ? origin.minY - r.maxY : nil
            case .down: r.minY >= origin.maxY - eps ? r.minY - origin.maxY : nil
            }
        }
        func overlap(_ r: CGRect) -> CGFloat {
            direction == .left || direction == .right
                ? min(r.maxY, origin.maxY) - max(r.minY, origin.minY)
                : min(r.maxX, origin.maxX) - max(r.minX, origin.minX)
        }
        return all
            .compactMap { c in gap(c.rect).flatMap { g in overlap(c.rect) > eps ? (c.pane, g, overlap(c.rect)) : nil } }
            .min { ($0.1, -$0.2) < ($1.1, -$1.2) }?.0
    }

    /// The tree with `target` replaced by a split of `target` and `pane` (new pane after it),
    /// `target` keeping `ratio` of the space.
    func splitting(_ target: UUID, with pane: TerminalPane, axis: SplitAxis, ratio: CGFloat = 0.5) -> PaneNode {
        switch self {
        case .leaf(let p) where p.id == target: .split(axis, SplitRatio(ratio), self, .leaf(pane))
        case .leaf: self
        case .split(let ax, let r, let a, let b):
            .split(ax, r, a.splitting(target, with: pane, axis: axis, ratio: ratio), b.splitting(target, with: pane, axis: axis, ratio: ratio))
        }
    }

    /// The tree without `target`; a split left with one side collapses into it. Nil when nothing is left.
    func removing(_ target: UUID) -> PaneNode? {
        switch self {
        case .leaf(let p): p.id == target ? nil : self
        case .split(let ax, let r, let a, let b):
            switch (a.removing(target), b.removing(target)) {
            case (let a?, let b?): .split(ax, r, a, b)
            case (let a?, nil): a
            case (nil, let b?): b
            case (nil, nil): nil
            }
        }
    }
}

/// Renders a split tree; the focused pane gets an accent outline once there is more than one.
struct PaneTreeView: View {
    let tab: TerminalTab
    let node: PaneNode
    let isActive: Bool

    var body: some View { tree }

    /// Type-erased because the view recurses.
    private var tree: AnyView {
        switch node {
        case .leaf(let pane):
            AnyView(
                TerminalViewRepresentable(tab: tab, pane: pane, isActive: isActive)
                    .id(pane.id)
                    .overlay {
                        if tab.panes.count > 1 && tab.focusedPane == pane.id {
                            Rectangle().strokeBorder(Color.accentColor.opacity(0.8), lineWidth: 1).allowsHitTesting(false)
                        }
                    }
                    .overlay(alignment: .topTrailing) {
                        ReconnectBadge(status: pane.linkStatus, name: tab.name)
                            .animation(DS.Motion.panel, value: ReconnectBadge.isReconnecting(pane.linkStatus))
                    }
                    // Inset, not overlaid: the terminal gets the remaining rows and nothing is hidden.
                    .safeAreaInset(edge: .top, spacing: 0) { ClipboardRequestBar(pane: pane) }
                    .safeAreaInset(edge: .top, spacing: 0) { TypedSshBar(pane: pane) }
                    .safeAreaInset(edge: .bottom, spacing: 0) { RemoteLinkBar(pane: pane) }
            )
        case .split(let axis, let ratio, let a, let b):
            AnyView(SplitContainer(axis: axis, ratio: ratio,
                                   first: PaneTreeView(tab: tab, node: a, isActive: isActive),
                                   second: PaneTreeView(tab: tab, node: b, isActive: isActive)))
        }
    }
}

/// Two subtrees with a draggable divider between them.
private struct SplitContainer: View {
    let axis: SplitAxis
    let ratio: SplitRatio
    let first: PaneTreeView
    let second: PaneTreeView
    /// Ratio when the current drag began.
    @State private var dragStart: CGFloat?

    /// Visible hairline plus an invisible grab area either side of it.
    private static let grabWidth: CGFloat = 7

    var body: some View {
        GeometryReader { geo in
            let horizontal = axis == .right
            let total = horizontal ? geo.size.width : geo.size.height
            let firstLength = max(0, (total - 1) * ratio.value)
            let layout = horizontal ? AnyLayout(HStackLayout(spacing: 0)) : AnyLayout(VStackLayout(spacing: 0))
            layout {
                first.frame(width: horizontal ? firstLength : nil, height: horizontal ? nil : firstLength)
                Divider()
                second.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .overlay(alignment: .topLeading) {
                Color.clear
                    .contentShape(Rectangle())
                    .frame(width: horizontal ? Self.grabWidth : nil, height: horizontal ? nil : Self.grabWidth)
                    .offset(x: horizontal ? firstLength - Self.grabWidth / 2 : 0, y: horizontal ? 0 : firstLength - Self.grabWidth / 2)
                    .onHover { inside in
                        if inside { (horizontal ? NSCursor.resizeLeftRight : NSCursor.resizeUpDown).push() } else { NSCursor.pop() }
                    }
                    .gesture(DragGesture(minimumDistance: 1, coordinateSpace: .local)
                        .onChanged { drag in
                            let start = dragStart ?? ratio.value
                            dragStart = start
                            let delta = (horizontal ? drag.translation.width : drag.translation.height) / max(total, 1)
                            ratio.value = min(SplitRatio.range.upperBound, max(SplitRatio.range.lowerBound, start + delta))
                        }
                        .onEnded { _ in dragStart = nil })
                    .accessibilityLabel("Split divider")
            }
        }
    }
}
