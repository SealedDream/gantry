import SwiftUI

/// A plugin view's toolbar (owner pick "C", 2026-11-23): Refresh as a quiet icon button with the
/// time of the last update, the plugin's labels and other buttons in order, and one accent Connect
/// button on the right for the run of connection-type buttons (the first is the default action,
/// the others are in its menu).
struct PluginToolbar: View {
    @ObservedObject var model: PluginViewModel
    let list: [PluginViewModel.Node]
    let id: Int

    /// Icon names drawn as connection types; a toolbar's buttons with these become one Connect button.
    static let connectIcons: Set<String> = ["ssh", "rdp", "vnc", "telnet", "web"]
    static let disabledHint = "Select a row first"

    var body: some View {
        let kids = model.kids(of: id, in: list)
        let connect = kids.filter { Self.icon($0).map(Self.connectIcons.contains) ?? false }
        HStack(spacing: 8) {
            ForEach(kids.filter { !connect.map(\.id).contains($0.id) }) { n in
                if Self.icon(n) == "refresh" {
                    refresh(n)
                } else {
                    PluginNodeView(model: model, list: list, node: n)
                }
            }
            Spacer(minLength: 8)
            if !connect.isEmpty { ConnectButton(model: model, nodes: connect) }
        }
        .frame(minHeight: 28)
    }

    @ViewBuilder private func refresh(_ n: PluginViewModel.Node) -> some View {
        let r = Self.rec(n)
        let label = r["label"] as? String ?? "Refresh"
        Button { model.input(node: n.id, ["kind": "pressed"]) } label: {
            Image(systemName: "arrow.clockwise").frame(width: 24, height: 24).contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .foregroundStyle(.secondary)
        .disabled(!(r["enabled"] as? Bool ?? true))
        .help(label)
        .accessibilityLabel(label)
        .accessibilityIdentifier("plugin-toolbar-refresh")
        if let t = model.updatedAt {
            Text("Updated \(t.formatted(date: .omitted, time: .shortened))")
                .font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1)
                .accessibilityIdentifier("plugin-toolbar-updated")
        }
    }

    static func rec(_ n: PluginViewModel.Node) -> [String: Any] { n.value as? [String: Any] ?? [:] }
    static func icon(_ n: PluginViewModel.Node) -> String? { n.kind == "button" ? rec(n)["icon"] as? String : nil }
}

/// One accent "Connect" button: pressing it runs the first connection button; the menu lists them all.
private struct ConnectButton: View {
    @ObservedObject var model: PluginViewModel
    let nodes: [PluginViewModel.Node]

    var body: some View {
        let enabled = nodes.filter { PluginToolbar.rec($0)["enabled"] as? Bool ?? true }
        let first = enabled.first ?? nodes[0]
        Menu {
            ForEach(nodes) { n in
                let r = PluginToolbar.rec(n)
                Button { model.input(node: n.id, ["kind": "pressed"]) } label: {
                    Label { Text(r["label"] as? String ?? "") } icon: { glyph(n, .labelColor).renderingMode(.template) }
                }
                .disabled(!(r["enabled"] as? Bool ?? true))
            }
        } label: {
            Label { Text("Connect") } icon: { glyph(first, .labelColor).renderingMode(.template) }
        } primaryAction: {
            model.input(node: first.id, ["kind": "pressed"])
        }
        .menuStyle(.button)
        .buttonStyle(.borderedProminent)
        .fixedSize()
        .disabled(enabled.isEmpty)
        .help(enabled.isEmpty ? PluginToolbar.disabledHint : "Connect with \(PluginToolbar.rec(first)["label"] as? String ?? "")")
        .accessibilityIdentifier("plugin-toolbar-connect")
    }

    private func glyph(_ n: PluginViewModel.Node, _ color: NSColor) -> Image {
        let art = (PluginToolbar.icon(n) ?? "ssh") + "-mono"
        let label = PluginToolbar.rec(n)["label"] as? String ?? ""
        let image = ConnectionIcons.glyph(art, color: color, token: "label", size: 14, label: label).copy() as! NSImage
        image.isTemplate = true // takes the button's text colour: white on the accent fill, grey when disabled or inactive
        return Image(nsImage: image)
    }
}
