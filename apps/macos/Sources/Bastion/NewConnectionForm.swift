import SwiftUI
import BastionCore

struct AddConnectionView: View {
    var parent: String? = nil
    @Environment(LibraryModel.self) private var model
    @Environment(CredentialsModel.self) private var credentials
    @Environment(SessionsModel.self) private var sessions
    /// Closes the form in the inspector (Cancel, Escape, or after Add).
    var close: () -> Void = {}
    @State private var name = ""
    @State private var host = ""
    @State private var proto: String
    @State private var port = ""
    @State private var user = ""
    /// Saved with the connection (encrypted vault, inline secret), so Connect never asks again.
    @State private var password = ""
    @State private var saving = false
    @State private var shell = localShellOptions().first?.id ?? "login"
    @State private var program = ""
    @State private var startFolder = ""
    /// The plugin type's own fields (PostgreSQL: Database), by key.
    @State private var fieldValues: [String: String] = [:]

    private var isLocal: Bool { proto == "local" }

    /// The open request when the form stays mounted between opens (`NewConnectionOverlay`): each new
    /// request clears the fields and takes its type.
    var target: ParentTarget? = nil
    /// Registers the form's frame for the UI driver; the mounted-once overlay registers its own.
    var probe = true
    /// The id the UI driver waits for (`timed-route new-connection`).
    static let probeId = "new-connection-form"

    init(parent: String? = nil, proto: String = "ssh", close: @escaping () -> Void = {},
         target: ParentTarget? = nil, probe: Bool = true) {
        self.parent = parent
        self.close = close
        self.target = target
        self.probe = probe
        _proto = State(initialValue: proto)
    }

    private func reset(to target: ParentTarget) {
        name = ""; host = ""; port = ""; user = ""; password = ""
        program = ""; startFolder = ""; saving = false; fieldValues = [:]
        shell = localShellOptions().first?.id ?? "login"
        proto = target.protocolName ?? "ssh"
    }

    var body: some View {
        Form {
            TextField("Name", text: $name)
            Picker("Type", selection: $proto) {
                ForEach(["ssh", "rdp", "vnc", "web"], id: \.self) { Text($0.uppercased()) }
                Text(TelnetPolicy.allowedNow ? "Telnet" : "Telnet (off)").tag("telnet")
                Text("Local Terminal").tag("local")
                Text("Services (read-only)").tag("services")
                Text("Processes (read-only)").tag("processes")
                Text("Event Log (read-only)").tag("eventlog")
                ForEach(PluginEntries.types, id: \.id) { Text($0.name).tag($0.id) }
            }
            if proto == "telnet" { TelnetWarningBand() }
            if isLocal {
                Picker("Shell", selection: $shell) {
                    ForEach(localShellOptions(), id: \.id) { Text($0.label).tag($0.id) }
                }
                if shell == "custom" { TextField("Program", text: $program, prompt: Text("/usr/local/bin/nu")) }
                TextField("Start folder", text: $startFolder, prompt: Text("Home folder"))
            } else {
                TextField("Host", text: $host)
                TextField("Port", text: $port, prompt: pluginType?.defaultPort.map { Text(String($0)) })
                TextField("User", text: $user)
                ForEach(pluginType?.fields ?? [], id: \.key) { f in
                    TextField(f.label, text: Binding(get: { fieldValues[f.key] ?? "" }, set: { fieldValues[f.key] = $0 }))
                }
                if takesPassword {
                    SecureField(pluginType == nil ? "Password" : "Secret", text: $password, prompt: Text("Optional — saved encrypted"))
                        .help(pluginType == nil ? "" : "For an API token: User is the token ID, Secret the token's secret.")
                }
            }
            LabeledContent("Saves to", value: model.activeName)
                .help("New items go to the library open in the sidebar: Personal or the selected document.")
        }
        .formStyle(.grouped)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .safeAreaInset(edge: .top, spacing: 0) {
            Text("New Connection").font(DS.Font.bodyStrong)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding([.horizontal, .top], DS.Space.m)
                .accessibilityAddTraits(.isHeader)
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            HStack(spacing: DS.Space.s) {
                Spacer(minLength: 0)
                Button("Cancel", action: close).keyboardShortcut(.cancelAction)
                Button("Add Connection") { Task { await add() } }
                .keyboardShortcut(.defaultAction)
                .disabled(saving || name.isEmpty || (proto == "telnet" && !TelnetPolicy.allowedNow) || (isLocal ? shell == "custom" && program.isEmpty : host.isEmpty || (!port.isEmpty && UInt16(port) == nil)))
            }
            .padding(DS.Space.m)
        }
        .onExitCommand(perform: close)
        .onChange(of: target) { _, t in if let t { reset(to: t) } }
        .uiProbe(probe ? AddConnectionView.probeId : "")
    }

    /// Protocols that sign in with a username and password (not local tools or web pages).
    private var takesPassword: Bool { ["ssh", "rdp", "vnc"].contains(proto) || pluginType != nil }

    /// The installed plugin type chosen in Type, if any (PLUG-PVE-01).
    private var pluginType: PluginTypeView? { PluginEntries.types.first { $0.id == proto } }

    /// One dialog (owner feedback 2026-11-07 #2): the connection, then its password as the
    /// connection's own vault secret, so the first Connect goes straight in.
    private func add() async {
        saving = true
        defer { saving = false }
        var created: String?
        model.mutate {
            if isLocal {
                let id = try $0.addConnection(parent: parent, name: name, protocol: proto, host: "", port: nil, username: nil)
                try $0.setProperty(id: id, key: "local.shell", value: shell)
                if shell == "custom" { try $0.setProperty(id: id, key: "local.path", value: program) }
                if !startFolder.isEmpty { try $0.setProperty(id: id, key: "local.cwd", value: startFolder) }
            } else if let type = pluginType {
                let id = try $0.addPluginConnection(dataDir: LibraryModel.dataDir.path, parent: parent, name: name, host: host, typeId: type.id)
                if let p = UInt16(port) { try $0.setProperty(id: id, key: "port", value: String(p)) }
                for f in type.fields {
                    let v = fieldValues[f.key]?.trimmingCharacters(in: .whitespaces) ?? ""
                    if !v.isEmpty { try $0.setPluginField(dataDir: LibraryModel.dataDir.path, id: id, key: f.key, value: v) }
                }
                created = id
            } else {
                created = try $0.addConnection(parent: parent, name: name, protocol: proto, host: host,
                                               port: UInt16(port), username: user.isEmpty ? nil : user)
            }
        }
        if let created, takesPassword, !password.isEmpty { await savePassword(connectionId: created) }
        password = ""
        close()
    }

    private func savePassword(connectionId: String) async {
        if credentials.vaultForSave() == nil { await credentials.openInBackground(sessions: sessions) }
        guard let vault = credentials.vault else {
            model.error = "The connection was added, but the credential vault is locked, so its password was not saved. Add it in Properties › Credentials."
            return
        }
        do {
            try vault.setInlinePassword(connectionId: connectionId, username: user, password: password)
            try vault.save()
            model.mutate { try $0.setInlineMarker(connectionId: connectionId, kind: "password") }
        } catch {
            model.error = "The connection was added, but its password was not saved: \(errorText(error))"
        }
    }
}

/// The New Connection form over the sessions' trailing edge while the inspector column is closed.
/// Mounted once and shown or hidden: building its AppKit-backed fields on every open, or opening the
/// column for it (a whole-window re-layout), cost 80-120 ms against the 50 ms stall budget
/// (MAC-NEWCONN-STALL, 2026-11-16). Each open clears the fields (`AddConnectionView.target`).
struct NewConnectionOverlay: View {
    @Environment(Commands.self) private var commands
    let shown: Bool

    var body: some View {
        let target = commands.addConnection
        InspectorOverlay {
            AddConnectionView(parent: target?.id, proto: target?.protocolName ?? "ssh",
                              close: { [commands] in commands.addConnection = nil }, target: target, probe: false)
        }
        .overlay { if shown { Color.clear.uiProbe(AddConnectionView.probeId) } }
        .opacity(shown ? 1 : 0)
        .allowsHitTesting(shown)
        .disabled(!shown)
        .accessibilityHidden(!shown)
    }
}
