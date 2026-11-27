import SwiftUI

/// One line at the top of a page saying what it is, with a link to its sibling page
/// (owner round 2, item 10: Activity and Audit Log looked like the same thing).
struct PageNote: View {
    @Environment(AppRouter.self) private var router
    let text: String
    let linkTitle: String
    let linkTarget: String
    /// Vertical padding inside the link label: caption line (13 pt) + 2 × 6 = 25 pt hit target.
    private static let linkPad: CGFloat = 6

    var body: some View {
        HStack(spacing: DS.Space.xs) {
            Text(text).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
            // The label carries the padding so the link's own hit target is 24 pt tall, not the
            // 13 pt caption line (LOG-NATIVE-01 fit: SMALL hit target).
            Button { router.open(linkTarget) } label: {
                Text(linkTitle).padding(.vertical, Self.linkPad).contentShape(Rectangle())
            }
            .buttonStyle(.link).accessibilityLabel(linkTitle)
            Spacer(minLength: 0)
        }
        .font(DS.Font.caption)
        .padding(.horizontal, 10).padding(.top, 8 - Self.linkPad)
    }
}
