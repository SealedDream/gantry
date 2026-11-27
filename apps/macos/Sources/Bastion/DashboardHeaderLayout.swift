import SwiftUI

/// The folder dashboard's control row: one line when it fits, else filter and switch over the
/// buttons, else filter, switch, connect buttons and edit buttons on lines of their own.
///
/// Replaces a three-way `ViewThatFits`, which kept three copies of every button and measured each
/// of them per layout pass (the first-select stall). Here each control exists once.
struct DashboardHeaderLayout: Layout {
    enum Part { case filter, toggle, connect, edit }

    struct PartKey: LayoutValueKey { static let defaultValue = Part.connect }

    var spacing: CGFloat

    struct Line { var items: [(index: Int, width: CGFloat)]; var height: CGFloat; var gapBefore: Int? }

    /// Each control's measurements, taken once per layout pass: `arrange` runs for every proposal
    /// and for placement, and measuring every button each time was part of the folder-select stall.
    struct Sizes { var parts: [Part]; var ideal: [CGSize]; var fMin: CGFloat; var fMax: CGFloat }

    func makeCache(subviews: Subviews) -> Sizes {
        let parts = subviews.map { $0[PartKey.self] }
        let filter = parts.firstIndex(of: .filter)
        return Sizes(parts: parts, ideal: subviews.map { $0.sizeThatFits(.unspecified) },
                     fMin: filter.map { subviews[$0].sizeThatFits(ProposedViewSize(width: 0, height: nil)).width } ?? 0,
                     fMax: filter.map { subviews[$0].sizeThatFits(ProposedViewSize(width: .infinity, height: nil)).width } ?? 0)
    }

    func updateCache(_ cache: inout Sizes, subviews: Subviews) { cache = makeCache(subviews: subviews) }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout Sizes) -> CGSize {
        let lines = arrange(width: proposal.width, sizes: cache)
        let height = lines.map(\.height).reduce(0, +) + spacing * CGFloat(max(lines.count - 1, 0))
        let used = lines.map { lineWidth($0) }.max() ?? 0
        return CGSize(width: proposal.width ?? used, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout Sizes) {
        var y = bounds.minY
        for line in arrange(width: bounds.width, sizes: cache) {
            var x = bounds.minX
            let gap = line.gapBefore == nil ? 0 : max(bounds.width - lineWidth(line), 0)
            for (n, item) in line.items.enumerated() {
                if n > 0 { x += spacing }
                if line.gapBefore == n { x += spacing + gap }
                subviews[item.index].place(at: CGPoint(x: x, y: y + line.height / 2), anchor: .leading,
                                           proposal: ProposedViewSize(width: item.width, height: nil))
                x += item.width
            }
            y += line.height + spacing
        }
    }

    private func lineWidth(_ line: Line) -> CGFloat {
        line.items.map(\.width).reduce(0, +) + spacing * CGFloat(max(line.items.count - 1, 0))
            + (line.gapBefore == nil ? 0 : spacing)
    }

    /// Picks the first arrangement whose ideal widths fit, like `ViewThatFits`, else the last.
    private func arrange(width: CGFloat?, sizes: Sizes) -> [Line] {
        let parts = sizes.parts, ideal = sizes.ideal, fMin = sizes.fMin, fMax = sizes.fMax
        let filter = parts.firstIndex(of: .filter)
        func ids(_ wanted: Part...) -> [Int] { parts.indices.filter { wanted.contains(parts[$0]) } }
        func sum(_ idx: [Int]) -> CGFloat {
            idx.map { ideal[$0].width }.reduce(0, +) + spacing * CGFloat(max(idx.count - 1, 0))
        }
        /// The filter takes `filterWidth` (or its ideal), kept between its smallest and largest width.
        func line(_ idx: [Int], filterWidth: CGFloat?, gapBefore: Int? = nil) -> Line {
            let items = idx.map { i -> (index: Int, width: CGFloat) in
                guard i == filter else { return (i, ideal[i].width) }
                return (i, min(max(filterWidth ?? ideal[i].width, fMin), fMax))
            }
            return Line(items: items, height: idx.map { ideal[$0].height }.max() ?? 0, gapBefore: gapBefore)
        }
        let top = ids(.filter, .toggle), actions = ids(.connect, .edit)
        let limit = width ?? .infinity
        let rest = sum(ids(.toggle)) + spacing
        // One line: the filter grows by half the spare room, as it did beside a Spacer in an HStack.
        let oneLine = sum(top) + spacing * 2 + sum(actions)
        if oneLine <= limit {
            let spare = width.map { $0 - oneLine } ?? 0
            let grown = filter.map { ideal[$0].width + spare / 2 }
            return [line(top + actions, filterWidth: grown, gapBefore: top.count)]
        }
        if max(sum(top), sum(actions)) <= limit {
            return [line(top, filterWidth: width.map { $0 - rest }), line(actions, filterWidth: nil)]
        }
        return [line(ids(.filter), filterWidth: width), line(ids(.toggle), filterWidth: nil),
                line(ids(.connect), filterWidth: nil), line(ids(.edit), filterWidth: nil)]
    }
}

extension View {
    /// Tags a control with its place in `DashboardHeaderLayout`.
    func dashboardHeaderPart(_ part: DashboardHeaderLayout.Part) -> some View {
        layoutValue(key: DashboardHeaderLayout.PartKey.self, value: part)
    }
}
