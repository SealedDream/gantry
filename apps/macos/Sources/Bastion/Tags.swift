import SwiftUI
import BastionCore

extension Tags {
    /// Every tag in the library, sorted.
    static func all(in tree: FolderView?) -> [String] {
        var seen = Set<String>()
        func walk(_ f: FolderView) {
            f.connections.forEach { seen.formUnion($0.tags) }
            f.folders.forEach(walk)
        }
        tree.map(walk)
        return seen.sorted()
    }
}

/// One small tag label: secondary text on a faint fill. With `onRemove`, a × button follows.
struct TagChip: View {
    let text: String
    var onRemove: (() -> Void)?

    var body: some View {
        HStack(spacing: 0) {
            Text(text).font(DS.Font.caption).lineLimit(1)
            if let onRemove {
                Button(action: onRemove) {
                    Image(systemName: "xmark").font(DS.Font.size(8, weight: .semibold))
                        .frame(width: 24, height: 24).contentShape(Rectangle())
                }
                .buttonStyle(.borderless)
                .help("Remove \(text)")
                .accessibilityLabel("Remove tag \(text)")
            }
        }
        .foregroundStyle(.secondary)
        .padding(.leading, 6)
        .padding(.trailing, onRemove == nil ? 6 : 0)
        .padding(.vertical, onRemove == nil ? 2 : 0)
        .background(RoundedRectangle(cornerRadius: 4).fill(Color.secondary.opacity(0.12)))
    }
}

/// Tag editor for Properties: chips, then a field. Enter or a comma adds what was typed; library
/// tags that start with it are offered below. `text` is the stored comma-separated value.
struct TagField: View {
    @Binding var text: String
    let suggestions: [String]
    @State private var draft = ""

    private var tags: [String] { Tags.split(text) }
    private var matching: [String] {
        let d = draft.trimmingCharacters(in: .whitespaces).lowercased()
        guard !d.isEmpty else { return [] }
        return Array(suggestions.filter { $0.hasPrefix(d) && $0 != d && !tags.contains($0) }.prefix(6))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            if !tags.isEmpty {
                FlowRow(spacing: DS.Space.xs) {
                    ForEach(tags, id: \.self) { t in TagChip(text: t) { remove(t) } }
                }
            }
            TextField("Add tag", text: $draft)
                .textFieldStyle(.roundedBorder)
                .onSubmit { add(draft) }
                .onChange(of: draft) { _, v in if v.contains(",") { add(v) } }
            if !matching.isEmpty {
                FlowRow(spacing: DS.Space.s) {
                    ForEach(matching, id: \.self) { s in
                        Button(s) { add(s) }.buttonStyle(.link).font(DS.Font.caption).frame(minHeight: 24)
                    }
                }
            }
        }
    }

    private func add(_ raw: String) {
        let next = Tags.normalize(tags + raw.split(separator: ",").map(String.init))
        draft = ""
        text = next.joined(separator: ", ")
    }

    private func remove(_ tag: String) { text = tags.filter { $0 != tag }.joined(separator: ", ") }
}

/// Lays children left to right and wraps to a new line when the width runs out.
struct FlowRow: Layout {
    var spacing: CGFloat

    private struct Row { var items: [Int] = []; var width: CGFloat = 0; var height: CGFloat = 0 }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(width: proposal.width ?? .infinity, subviews)
        let height = rows.reduce(0) { $0 + $1.height } + spacing * CGFloat(max(rows.count - 1, 0))
        return CGSize(width: rows.map(\.width).max() ?? 0, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in arrange(width: bounds.width, subviews) {
            var x = bounds.minX
            for i in row.items {
                let s = subviews[i].sizeThatFits(.unspecified)
                subviews[i].place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(s))
                x += s.width + spacing
            }
            y += row.height + spacing
        }
    }

    private func arrange(width: CGFloat, _ subviews: Subviews) -> [Row] {
        var rows = [Row()]
        for i in subviews.indices {
            let s = subviews[i].sizeThatFits(.unspecified)
            if !rows[rows.count - 1].items.isEmpty && rows[rows.count - 1].width + spacing + s.width > width {
                rows.append(Row())
            }
            let last = rows.count - 1
            rows[last].width += (rows[last].items.isEmpty ? 0 : spacing) + s.width
            rows[last].height = max(rows[last].height, s.height)
            rows[last].items.append(i)
        }
        return rows
    }
}
