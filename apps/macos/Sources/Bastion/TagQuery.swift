import Foundation

/// Connection tags (owner 2026-11-16): stored lower case without duplicates (core
/// `properties::normalize_tags`), typed in Properties, matched by the library filter.
enum Tags {
    /// Lower case, trimmed, no blanks, no duplicates; first order kept. Same rule as the core's.
    static func normalize<S: Sequence>(_ tags: S) -> [String] where S.Element == String {
        var out: [String] = []
        for t in tags {
            let v = t.trimmingCharacters(in: .whitespaces).lowercased()
            if !v.isEmpty && !out.contains(v) { out.append(v) }
        }
        return out
    }

    /// The stored comma text as tags.
    static func split(_ text: String) -> [String] { normalize(text.split(separator: ",").map(String.init)) }
}

/// A filter string split into `tag:name` terms (all must match) and the remaining free text.
struct TagQuery: Equatable {
    let tags: [String]
    let text: String

    static let prefix = "tag:"

    static func parse(_ filter: String) -> TagQuery {
        guard filter.range(of: prefix, options: .caseInsensitive) != nil else { return TagQuery(tags: [], text: filter) }
        var tags: [String] = []
        var words: [Substring] = []
        for w in filter.split(separator: " ", omittingEmptySubsequences: true) {
            if w.count > prefix.count, w.lowercased().hasPrefix(prefix) {
                tags.append(String(w.dropFirst(prefix.count)))
            } else {
                words.append(w)
            }
        }
        return TagQuery(tags: Tags.normalize(tags), text: tags.isEmpty ? filter : words.joined(separator: " "))
    }

    /// Whether `tags` holds every tag the query names.
    func admits(_ tags: [String]) -> Bool { self.tags.allSatisfy(tags.contains) }
}
