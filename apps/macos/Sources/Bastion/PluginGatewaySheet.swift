import SwiftUI
import BastionCore

/// A plugin entry behind a gateway (PLUG-08 Mac): signs in to the gateway like the RDP, VNC and
/// web connect sheets (`GatewayLogin`), then opens the entry's tab on the loopback forward the
/// core opened to the entry's host and port. The tab owns the route and closes it with itself.
struct PluginGatewayRequest: Identifiable {
    let entry: ConnectionView
    let type: PluginTypeView
    var id: String { entry.id }
}

struct PluginGatewaySheet: View {
    let request: PluginGatewayRequest
    let close: () -> Void
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @Environment(CredentialsModel.self) private var credentials
    @State private var login: GatewayLogin?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("Open \(request.entry.name)").font(DS.Font.headline)
            Form {
                if let login { GatewaySection(login: login, retry: { Task { await connect() } }) }
                if let error { CodedError(area: "PLUG", message: error, lineLimit: 3) }
            }
            .formStyle(.grouped)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { login?.discard(); close() }.keyboardShortcut(.cancelAction)
                Button("Connect") { Task { await connect() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy || !(login?.ready ?? false))
            }
        }
        .padding(DS.Space.m)
        .frame(width: 440)
        .onAppear { if login == nil { login = GatewayLogin(library: model.library, connectionId: request.entry.id) } }
    }

    private func connect() async {
        guard let login, let library = model.library else { return }
        busy = true
        defer { busy = false }
        switch await login.open(sessions: sessions, library: library, connectionId: request.entry.id) {
        case .via(let port):
            PluginViewWindow.show(entry: request.entry, type: request.type, library: library, credentials: credentials,
                                  via: .forward(port: port, target: request.entry.host), route: login.handOff())
            close()
        case .direct:
            error = "This connection has no gateway."
        case .needsTrust:
            break
        case .failed(let message):
            error = message
        }
    }
}
