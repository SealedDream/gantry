import SwiftUI
import BastionCore

/// Rows for a credential picker: credentials grouped under their folder path (root first, then
/// folders in tree order), names only and never a secret. Shared by the inspector and the property
/// dialog so both show the same tree, and by the UI driver.
struct CredentialPickerGroup: Identifiable {
    /// `Customers › Acme`; nil for credentials at the section root.
    let header: String?
    let items: [CredentialTreeItemView]
    var id: String { header ?? "" }

    static func build(_ tree: [CredentialTreeItemView]) -> [CredentialPickerGroup] {
        var out: [CredentialPickerGroup] = []
        func walk(_ nodes: [CredentialNode], path: [String]) {
            let creds = nodes.filter { !$0.item.isFolder }.map(\.item)
            if !creds.isEmpty {
                out.append(CredentialPickerGroup(header: path.isEmpty ? nil : path.joined(separator: " › "), items: creds))
            }
            for f in nodes where f.item.isFolder { walk(f.children ?? [], path: path + [f.item.name]) }
        }
        walk(CredentialNode.build(tree), path: [])
        return out
    }

    /// The first row's text: what the item gets from its parents, by name.
    static func inheritLabel(_ resolved: String?) -> String {
        resolved.map { "Inherit (\($0))" } ?? "Ask when connecting"
    }

    /// One string for driver logs: `Inherit (…)|a,b|Folder › Sub: c`.
    static func text(_ groups: [CredentialPickerGroup], inherit: String) -> String {
        ([inherit] + groups.map { g in
            let names = g.items.map(\.name).joined(separator: ",")
            return g.header.map { "\($0): \(names)" } ?? names
        }).joined(separator: "|")
    }
}

/// The picker's rows: "Inherit (resolved)" tagged nil, then credentials in folder sections.
struct CredentialPickerRows: View {
    let groups: [CredentialPickerGroup]
    let inherit: String
    var detail: (CredentialTreeItemView) -> String = { $0.name }

    var body: some View {
        Text(inherit).tag(String?.none)
        ForEach(groups) { g in
            if let header = g.header {
                Section(header) { rows(g) }
            } else {
                rows(g)
            }
        }
    }

    private func rows(_ g: CredentialPickerGroup) -> some View {
        ForEach(g.items, id: \.id) { Text(detail($0)).tag(Optional($0.id)) }
    }
}
