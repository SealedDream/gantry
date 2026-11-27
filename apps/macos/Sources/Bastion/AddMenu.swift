import SwiftUI
import BastionCore

/// Searchable, grouped Add menu built from the core's catalogue. Types without a working
/// implementation are listed with their status and cannot be created.
struct AddMenu: View {
    let addFolder: () -> Void
    let addConnection: (_ protocolName: String) -> Void
    /// Closes the AppKit popover that hosts the menu (the toolbar's + button).
    var close: (() -> Void)? = nil
    @Environment(\.dismiss) private var dismiss
    @State private var search = ""
    /// Types this app opens itself (H15); the core marks them as connecting.
    static let handledTypes = ["rdp", "vnc", "web", "telnet"]
    /// Passed to `addConnection` for the "From Template…" row (B9).
    static let fromTemplate = "from-template"
    /// Built once: an FFI call per open made the + button slow (owner feedback 9, 2026-11-07).
    /// Serial is not offered (owner 2026-11-15, Not planned); old serial entries still load.
    @MainActor static let catalog = connectionCatalogFor(handled: AddMenu.handledTypes).filter { $0.id != "serial" }
    private var catalog: [TypeDescriptorView] { Self.catalog }

    private var groups: [(String, [TypeDescriptorView])] {
        let matching = catalog.filter {
            search.isEmpty || $0.label.localizedCaseInsensitiveContains(search) || $0.group.localizedCaseInsensitiveContains(search)
        }
        let order = matching.map(\.group).reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
        return order.map { group in (group, matching.filter { $0.group == group }) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            TextField("Add…", text: $search)
                .textFieldStyle(.roundedBorder)
                .padding(DS.Space.xs)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: DS.Space.xs) {
                    if search.isEmpty || "from template".localizedCaseInsensitiveContains(search) { templateRow }
                    ForEach(groups, id: \.0) { group, items in
                        Text(group.uppercased())
                            .font(DS.Font.caption2.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, DS.Space.xs)
                            .padding(.top, DS.Space.xxs)
                        ForEach(items, id: \.id) { row($0) }
                    }
                    pluginRows
                    if groups.isEmpty && pluginTypes.isEmpty {
                        Text("Nothing matches “\(search)”.").foregroundStyle(.secondary).padding(DS.Space.xs)
                    }
                }
                .padding(DS.Space.xxs)
            }
        }
        .frame(width: DS.Size.addMenuWidth, height: 420)
    }

    /// Installed plugins' connection types (PLUG-PVE-01), read when the menu draws.
    private var pluginTypes: [PluginTypeView] {
        PluginEntries.types.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || "plugins".localizedCaseInsensitiveContains(search) }
    }

    @ViewBuilder private var pluginRows: some View {
        if !pluginTypes.isEmpty {
            Text("PLUGINS")
                .font(DS.Font.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, DS.Space.xs)
                .padding(.top, DS.Space.xxs)
            ForEach(pluginTypes, id: \.id) { t in
                Button {
                    if let close { close() } else { dismiss() }
                    addConnection(t.id)
                } label: {
                    HStack(spacing: DS.Space.xs) {
                        Image(systemName: "puzzlepiece.extension").foregroundStyle(.tint).frame(width: DS.Space.m + DS.Space.xxs)
                        Text(t.name)
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, DS.Space.xs)
                    .padding(.vertical, DS.Space.xxs)
                    .contentShape(Rectangle())
                }
                .buttonStyle(AddRowStyle())
                .help("Add \(t.name) (plugin \(t.pluginName), \(t.tier))")
            }
        }
    }

    /// New from Template…: the sheet asks for each token once.
    private var templateRow: some View {
        Button {
            if let close { close() } else { dismiss() }
            addConnection(Self.fromTemplate)
        } label: {
            HStack(spacing: DS.Space.xs) {
                Image(systemName: "doc.badge.plus").foregroundStyle(.tint).frame(width: DS.Space.m + DS.Space.xxs)
                Text("From Template…")
                Spacer(minLength: 0)
            }
            .padding(.horizontal, DS.Space.xs)
            .padding(.vertical, DS.Space.xxs)
            .contentShape(Rectangle())
        }
        .buttonStyle(AddRowStyle())
        .help("New connection from a saved template")
    }

    private func row(_ t: TypeDescriptorView) -> some View {
        let telnetOff = t.id == "telnet" && !TelnetPolicy.allowedNow
        let enabled = t.support != "planned" && !telnetOff
        return Button {
            if let close { close() } else { dismiss() }
            if t.id == "folder" { addFolder() } else { addConnection(t.id) }
        } label: {
            HStack(alignment: .top, spacing: DS.Space.xs) {
                Image(systemName: catalogSymbol(t.id))
                    .foregroundStyle(enabled ? AnyShapeStyle(.tint) : AnyShapeStyle(.tertiary))
                    .frame(width: DS.Space.m + DS.Space.xxs)
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: DS.Space.xxs) {
                        Text(t.label).foregroundStyle(enabled ? .primary : .secondary)
                        switch t.support {
                        case "store-only": Badge(text: "Saves only", color: .orange)
                        case "planned": Badge(text: "Planned")
                        default: EmptyView()
                        }
                    }
                    Text(telnetOff ? TelnetPolicy.offText : t.summary).font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(2)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, DS.Space.xs)
            .padding(.vertical, DS.Space.xxs)
            .contentShape(Rectangle())
        }
        .buttonStyle(AddRowStyle())
        .disabled(!enabled)
        .help(enabled ? "Add \(t.label)" : telnetOff ? TelnetPolicy.offText : "\(t.label) is not implemented yet")
    }
}

/// Hover/pressed highlight for Add menu rows.
private struct AddRowStyle: ButtonStyle {
    @State private var hovering = false
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(RoundedRectangle(cornerRadius: 5)
                .fill(Color.accentColor.opacity(configuration.isPressed ? 0.25 : hovering ? 0.12 : 0)))
            .onHover { hovering = $0 }
    }
}

func catalogSymbol(_ id: String) -> String {
    switch id {
    case "folder": "folder"
    case "credential": "key"
    case "ssh", "telnet": "terminal"
    case "rdp", "vnc": "display"
    case "web": "globe"
    case "sftp", "ftp": "arrow.up.arrow.down.square"
    case "hyperv": "server.rack"
    case "powershell": "chevron.left.forwardslash.chevron.right"
    case "gateway": "point.3.connected.trianglepath.dotted"
    case "command-task": "bolt"
    default: "questionmark.square"
    }
}
