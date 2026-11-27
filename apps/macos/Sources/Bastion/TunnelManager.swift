import SwiftUI
import BastionCore

/// Saved tunnels (core `tunneldefs`, stored in the library) and the ones running now. Start signs
/// in to the tunnel's SSH connection through the normal connect sheet; local listeners bind
/// 127.0.0.1 only.
struct TunnelManagerView: View {
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @Environment(Commands.self) private var commands
    private var dismiss = PanelDismiss()
    @State private var tunnels: [TunnelDefView] = []
    @State private var selection: String?
    @State private var editing: TunnelDefView?
    @State private var problem: String?
    /// Redraws the status column while tunnels run (connection counts).
    @State private var tick = 0
    @State private var sort = [KeyPathComparator(\TunnelDefView.name)]
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private var selected: TunnelDefView? { tunnels.first { $0.id == selection } }
    @State private var filter = ""
    private var sortedTunnels: [TunnelDefView] { tunnels.filter { ListFilterField.matches(filter, [$0.name, $0.viaName, $0.kind]) }.sorted(using: sort) }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Tunnels").font(DS.Font.bodyStrong)
                Spacer()
                ListFilterField(text: $filter)
            }
            .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            if tunnels.isEmpty {
                EmptyState(symbol: "arrow.left.arrow.right", title: "No tunnels",
                           message: "Save a port forward or SOCKS proxy over one of your SSH connections.") {
                    Button("Add Tunnel…") { editing = TunnelManagerView.blank(via: sshConnections.first) }.keyboardShortcut(.defaultAction).dsPrimaryButton()
                        .disabled(sshConnections.isEmpty)
                }
            } else {
                Table(sortedTunnels, selection: $selection, sortOrder: $sort) {
                    TableColumn("Name", value: \.name) { t in Text(t.name).lineLimit(1) }
                    TableColumn("Forward", value: \.summary) { t in Text(verbatim: t.summary).font(DS.Font.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1) }
                    TableColumn("Via", value: \.viaName) { t in Text(t.viaName).lineLimit(1) }
                    TableColumn("Status") { t in status(t).id(tick) }
                }
                .contextMenu(forSelectionType: String.self) { ids in
                    if let t = tunnels.first(where: { $0.id == ids.first }) {
                        Button(running(t) ? "Stop" : "Start…") { toggle(t) }
                        Button("Edit…") { editing = t }
                        Divider()
                        Button("Delete", role: .destructive) { remove(t) }
                    }
                } primaryAction: { ids in
                    if let t = tunnels.first(where: { $0.id == ids.first }) { toggle(t) }
                }
                .onDeleteCommand { selected.map(remove) }
            }
            if let problem {
                Text(problem).font(DS.Font.caption).foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, DS.Space.m).padding(.top, DS.Space.xs)
            }
            Divider()
            HStack(spacing: DS.Space.xs) {
                Group {
                    Button("Add Tunnel", systemImage: "plus") { editing = TunnelManagerView.blank(via: sshConnections.first) }
                        .disabled(sshConnections.isEmpty).help("Add Tunnel…")
                    Button("Delete", systemImage: "minus") { selected.map(remove) }.disabled(selected == nil).help("Delete")
                    Button("Edit", systemImage: "pencil") { editing = selected }.disabled(selected == nil).help("Edit…")
                }
                .labelStyle(.iconHitTarget).buttonStyle(.borderless)
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                if !tunnels.isEmpty {
                    Button(selected.map(running) == true ? "Stop" : "Start…") { selected.map(toggle) }
                        .keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(selected == nil)
                }
            }
            .padding(DS.Space.s)
        }
        .frame(minWidth: 0, idealWidth: DS.Size.managerWidth + 220, maxWidth: DS.Size.managerWidth + 220, minHeight: 0, idealHeight: DS.Size.managerHeight, maxHeight: DS.Size.managerHeight)
        .onAppear(perform: reload)
        .onReceive(timer) { _ in if !sessions.runningTunnels.isEmpty || !sessions.tabs.isEmpty { tick += 1 } }
        .sheet(item: $editing, onDismiss: reload) { TunnelEditSheet(tunnel: $0, connections: sshConnections) }
    }

    private var sshConnections: [ConnectionView] { AppIpc.connections(in: model.tree).filter { $0.protocol == "ssh" } }

    static func blank(via: ConnectionView?) -> TunnelDefView {
        TunnelDefView(id: "", name: "", viaId: via?.id ?? "", viaName: via?.name ?? "", kind: "local", localPort: 0, host: "", port: 0, summary: "")
    }

    private func running(_ t: TunnelDefView) -> Bool {
        sessions.runningTunnels[t.id]?.isRunning() == true || tabForward(t)?.status.running == true
    }

    private func tabForward(_ t: TunnelDefView) -> (status: ForwardStatusView, terminal: Terminal)? { sessions.tabForward(t.id, via: t.viaId) }

    @ViewBuilder private func status(_ t: TunnelDefView) -> some View {
        if let r = sessions.runningTunnels[t.id], r.isRunning() {
            Label("Running · \(r.connections()) connections", systemImage: "circle.fill").labelStyle(.titleAndIcon)
                .font(DS.Font.caption).foregroundStyle(.green)
        } else if let f = tabForward(t)?.status, f.running {
            Label("Running · \(f.connections) connections · with the connection", systemImage: "circle.fill").labelStyle(.titleAndIcon)
                .font(DS.Font.caption).foregroundStyle(.green).lineLimit(1)
                .help(f.port.map { "Port \($0)" + (f.movedFrom.map { " (saved \($0) was taken)" } ?? "") } ?? "")
        } else if let e = sessions.runningTunnels[t.id]?.lastError() ?? tabForward(t)?.status.lastError {
            Text("Stopped: \(e)").font(DS.Font.caption).foregroundStyle(.red).lineLimit(1)
        } else {
            Text("Stopped").font(DS.Font.caption).foregroundStyle(.secondary)
        }
    }

    private func toggle(_ t: TunnelDefView) {
        if sessions.runningTunnels[t.id]?.isRunning() != true, tabForward(t)?.status.running == true {
            problem = sessions.stopTabForward(t.id, via: t.viaId)
            tick += 1
            return
        }
        if running(t) {
            sessions.runningTunnels[t.id]?.stop()
            sessions.runningTunnels[t.id] = nil
            return
        }
        guard let via = model.connection(id: t.viaId) else { problem = "The tunnel's SSH connection no longer exists."; return }
        dismiss()
        commands.enqueue([ConnectRequest(connection: via, mode: .tunnel, tunnelId: t.id)], select: nil)
    }

    private func remove(_ t: TunnelDefView) {
        guard let library = model.library else { return }
        sessions.runningTunnels[t.id]?.stop()
        sessions.runningTunnels[t.id] = nil
        do { try library.removeTunnel(id: t.id); try library.save(); model.reload(); problem = nil } catch { problem = errorText(error) }
        reload()
    }

    private func reload() { tunnels = (try? model.library?.tunnels()) ?? [] }
}

extension TunnelDefView: Identifiable {}

extension SessionsModel {
    /// A "start with connection" tunnel the core runs on an open SSH tab of its connection, with that
    /// tab's terminal; nil when no open tab runs it or reports a failure for it.
    func tabForward(_ tunnelId: String, via: String) -> (status: ForwardStatusView, terminal: Terminal)? {
        for tab in tabs(for: via) where !tab.ended {
            for pane in tab.panes {
                if let f = pane.terminal.forwards().first(where: { $0.id == tunnelId }), f.running || f.lastError != nil {
                    return (f, pane.terminal)
                }
            }
        }
        return nil
    }

    /// Stops a tunnel running on its connection's tab; it stays stopped, also after a reconnect, until
    /// Start is used. Returns the error text, nil when stopped.
    func stopTabForward(_ tunnelId: String, via: String) -> String? {
        guard let on = tabForward(tunnelId, via: via) else { return nil }
        do { try on.terminal.stopForward(tunnelId: tunnelId); return nil } catch { return errorText(error) }
    }
}

/// Add or edit a tunnel; validation (ports, hosts, clashes) is the core's.
struct TunnelEditSheet: View {
    @State var tunnel: TunnelDefView
    let connections: [ConnectionView]
    @Environment(LibraryModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var localPort = ""
    @State private var port = ""
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text(tunnel.id.isEmpty ? "Add Tunnel" : "Edit Tunnel").font(DS.Font.bodyStrong)
            Form {
                TextField("Name", text: $tunnel.name)
                Picker("Over SSH connection", selection: $tunnel.viaId) {
                    ForEach(connections, id: \.id) { Text($0.name).tag($0.id) }
                }
                Picker("Type", selection: $tunnel.kind) {
                    Text("Local").tag("local"); Text("Remote").tag("remote"); Text("SOCKS").tag("dynamic")
                }
                .pickerStyle(.segmented)
                switch tunnel.kind {
                case "remote":
                    TextField("Server port (127.0.0.1 on the server)", text: $port)
                    TextField("To host (from this Mac)", text: $tunnel.host)
                    TextField("To port", text: $localPort)
                case "dynamic":
                    TextField("Local SOCKS port (127.0.0.1)", text: $localPort)
                default:
                    TextField("Local port (127.0.0.1)", text: $localPort)
                    TextField("To host (from the server)", text: $tunnel.host)
                    TextField("To port", text: $port)
                }
                Toggle("Start when the connection opens", isOn: $tunnel.startWithConnection)
                    .help("Runs on the connection's own SSH session and follows its reconnects")
            }
            .formStyle(.columns)
            Text(problem ?? "Listeners on this Mac bind 127.0.0.1 only; a remote forward binds 127.0.0.1 on the server.")
                .font(DS.Font.caption).foregroundStyle(problem == nil ? .secondary : Color.red).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button(tunnel.id.isEmpty ? "Add" : "Save", action: save).keyboardShortcut(.defaultAction).dsPrimaryButton()
            }
        }
        .padding(DS.Space.m)
        .frame(width: DS.Size.dialogWidth + 100)
        .onAppear {
            localPort = tunnel.localPort == 0 ? "" : String(tunnel.localPort)
            port = tunnel.port == 0 ? "" : String(tunnel.port)
        }
    }

    private func save() {
        guard let library = model.library else { return }
        var t = tunnel
        t.localPort = UInt16(localPort.trimmingCharacters(in: .whitespaces)) ?? 0
        t.port = UInt16(port.trimmingCharacters(in: .whitespaces)) ?? 0
        do {
            _ = try library.putTunnel(tunnel: t)
            try library.save()
            model.reload()
            dismiss()
        } catch { problem = errorText(error) }
    }
}
