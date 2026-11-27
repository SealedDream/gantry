import SwiftUI

/// The filter field of a list page, one style everywhere (owner round 2, item 7).
struct ListFilterField: View {
    @Binding var text: String
    private static let width: CGFloat = 200

    var body: some View {
        TextField("Filter", text: $text)
            .textFieldStyle(.roundedBorder)
            .frame(width: Self.width)
            .controlSize(.small)
            .accessibilityLabel("Filter")
    }

    /// Case-insensitive substring match on any field; an empty filter matches everything.
    static func matches(_ filter: String, _ fields: [String]) -> Bool {
        let q = filter.trimmingCharacters(in: .whitespaces)
        return q.isEmpty || fields.contains { $0.localizedCaseInsensitiveContains(q) }
    }
}
