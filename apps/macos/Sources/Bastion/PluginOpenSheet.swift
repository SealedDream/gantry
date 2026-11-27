import SwiftUI

/// The core-worded sheet for a plugin's `open.connection` (plugin API 1.2,
/// `docs/specs/plugins-amendment-3.md` section 6). The plugin's label is the only plugin text
/// and sits behind a fixed prefix; protocol, host and port are in one monospaced field. An
/// address the server did not report carries a warning, and then Cancel is the default button.
struct PluginOpenSheet: View {
    let request: PluginViewModel.OpenRequest
    /// accept, route (`entry` or `direct`), save as entry.
    let answer: (Bool, String, Bool) -> Void
    @State private var route: String
    @State private var saveAsEntry = false

    init(request: PluginViewModel.OpenRequest, answer: @escaping (Bool, String, Bool) -> Void) {
        self.request = request
        self.answer = answer
        _route = State(initialValue: request.route)
    }

    private var protoName: String { request.proto.uppercased() }
    /// The entry reaches its server some other way than direct: offer both routes.
    private var entryRouted: Bool { request.entryRoute != "direct" }
    private var destination: String {
        let host = request.host.contains(":") ? "[\(request.host)]" : request.host
        return "\(request.proto)://\(host):\(request.port)"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("Open \(protoName) connection?").font(DS.Font.headline)
            Grid(alignment: .leading, horizontalSpacing: DS.Space.s, verticalSpacing: DS.Space.xs) {
                GridRow {
                    Text("Plugin").foregroundStyle(.secondary)
                    Text(request.plugin).lineLimit(1).truncationMode(.middle)
                }
                GridRow {
                    Text("Entry").foregroundStyle(.secondary)
                    Text(request.entryName).lineLimit(1).truncationMode(.middle)
                }
                GridRow {
                    Text("From the plugin:").foregroundStyle(.secondary)
                    Text(verbatim: request.label).italic().lineLimit(1).truncationMode(.tail)
                        .accessibilityIdentifier("plugin-open-label")
                }
                GridRow {
                    Text("Destination").foregroundStyle(.secondary)
                    Text(verbatim: destination).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                        .lineLimit(1).truncationMode(.middle)
                        .padding(.horizontal, DS.Space.xxs).background(Color.secondary.opacity(0.12))
                        .accessibilityIdentifier("plugin-open-destination")
                }
                GridRow {
                    Text("Route").foregroundStyle(.secondary)
                    if entryRouted {
                        Picker("Route", selection: $route) {
                            Text("Through the entry's route").tag("entry")
                            Text("Direct").tag("direct")
                        }
                        .labelsHidden().fixedSize()
                        .accessibilityIdentifier("plugin-open-route")
                    } else {
                        Text("Direct")
                    }
                }
            }
            if request.reported {
                Label("\(request.entryName) reported this address.", systemImage: "checkmark.seal").foregroundStyle(.secondary)
                    .accessibilityIdentifier("plugin-open-reported")
            } else {
                Label("The server did not report this address. Check it before you connect.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("plugin-open-warning")
            }
            Text("You will be asked to sign in.").foregroundStyle(.secondary).font(DS.Font.caption)
            Toggle("Save as a library entry", isOn: $saveAsEntry).accessibilityIdentifier("plugin-open-save")
            if saveAsEntry {
                Text("Saved in the entry's folder as \u{201C}\(request.label)\u{201D}, route: \(route == "entry" && entryRouted ? "the entry's route" : "direct").")
                    .foregroundStyle(.secondary).font(DS.Font.caption).lineLimit(2)
            }
            HStack {
                Spacer()
                if request.reported {
                    Button("Cancel", role: .cancel) { answer(false, route, false) }.keyboardShortcut(.cancelAction)
                    Button("Open") { answer(true, route, saveAsEntry) }.keyboardShortcut(.defaultAction)
                        .accessibilityIdentifier("plugin-open-open")
                } else {
                    Button("Open") { answer(true, route, saveAsEntry) }.accessibilityIdentifier("plugin-open-open")
                    Button("Cancel", role: .cancel) { answer(false, route, false) }.keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(DS.Space.m)
        .frame(width: DS.Size.dialogWidth)
        .accessibilityIdentifier("plugin-open-sheet")
    }
}
