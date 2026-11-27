import SwiftUI
import BastionCore

/// Protocols a host connection can be switched between; the core checks the same list
/// (`properties::SWITCHABLE_PROTOCOLS`, owner feedback 10, 2026-11-07).
let switchableProtocols = ["ssh", "rdp", "vnc", "telnet"]

/// Short protocol label: "SSH", "RDP", …
func protocolLabel(_ proto: String) -> String {
    switch proto {
    case "eventlog": "Event Log"
    case "local": "Local"
    case "services": "Services"
    case "processes": "Processes"
    case "web": "Web"
    case "serial": "Serial"
    default: proto.uppercased()
    }
}

/// Icon plus label, so the protocol reads at a glance (owner feedback 10).
struct ProtocolBadge: View {
    let proto: String

    var body: some View {
        Label(protocolLabel(proto), systemImage: protocolSymbol(proto))
            .font(DS.Font.caption.weight(.semibold))
            .padding(.horizontal, DS.Space.xs)
            .padding(.vertical, 2)
            .background(.quaternary.opacity(0.6), in: Capsule())
            .accessibilityLabel("Protocol \(protocolLabel(proto))")
    }
}

/// Changes a host connection between SSH, RDP, VNC and Telnet (core property `protocol`);
/// other types show their protocol read-only.
struct ProtocolPicker: View {
    let connection: ConnectionView
    /// Test builds record the frame under this id for the UI driver (the page's picker only; the inspector has one too).
    var probe: String? = nil
    @Environment(LibraryModel.self) private var model

    var body: some View {
        if switchableProtocols.contains(connection.protocol) {
            Picker("Protocol", selection: Binding(get: { connection.protocol }, set: change)) {
                ForEach(switchableProtocols, id: \.self) { p in
                    Label(protocolLabel(p), systemImage: protocolSymbol(p)).tag(p)
                }
            }
            .labelsHidden()
            // Its own width, not the row's: a stretched menu pushed Connect off the page (owner point 22).
            .fixedSize()
            // Where the UI driver clicks it: on macOS 26+ SwiftUI draws it with no NSPopUpButton (#1104).
            .uiProbe(probe ?? "")
            .help("Change the connection type")
            .accessibilityIdentifier("protocol-picker")
        } else {
            ProtocolBadge(proto: connection.protocol)
        }
    }

    private func change(_ to: String) {
        guard to != connection.protocol else { return }
        model.mutate { try $0.setProperty(id: connection.id, key: "protocol", value: to) }
    }
}

/// The page a clicked connection shows in the session area (owner feedback 6, UI-04): header,
/// login line, Connect with the next steps beside it, history, notes. No boxes: space and a
/// hairline separate the parts. Selecting a tab returns to the service.
struct ConnectionPage: View {
    let connection: ConnectionView
    @Environment(Commands.self) private var commands
    @Environment(SessionsModel.self) private var sessions
    @Environment(LibraryModel.self) private var model
    @Environment(CredentialsModel.self) private var credentials
    @State private var history: ConnectionHistoryView?
    @State private var historyError = false
    @State private var showingLogs = false
    @State private var login: ConnectionSummary.LoginState = .none
    @State private var notes = ""
    /// Types whose terminal output can be logged (the core schema's `session_log`).
    static let loggedProtocols: Set<String> = ["ssh", "sftp", "telnet", "local"]
    /// Types with a file browser and SSH tunnels.
    static let sshProtocols: Set<String> = ["ssh", "sftp"]

    private var c: ConnectionView { connection }
    private var address: String { sessionAddress(user: nil, host: c.host, port: c.port) }
    private var openTabs: [TerminalTab] { sessions.tabs(for: c.id).filter { !$0.ended && !$0.isWaiting } }
    private var isProduction: Bool { HostColors.shared.productionIds.contains(c.id) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: DS.Space.m) {
                header
                if c.protocol == "telnet" { TelnetWarningBand() }
                loginLine
                actions
                Divider()
                historySection
                SessionHistoryList(scope: .connection(id: c.id, name: c.name), revision: sessions.historyRevision)
                if !notes.isEmpty { notesSection }
            }
            .padding(DS.Space.m)
            .frame(maxWidth: DS.Size.connectionPageMax, alignment: .leading)
            .uiProbe("connection-page-content")
            // At the leading edge with the normal inset, the readable column capped above (owner
            // 2026-11-16: "move the writing to the left"). In full screen the inspector overlays this
            // area, so the trailing inset keeps the page beside it rather than under it (owner point 22).
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.trailing, commands.tree.inspectorOverlayInset)
        }
        .background(.background)
        .uiProbe("connection-page-area")
        .accessibilityIdentifier("connection-page")
        .task(id: "\(c.id)-\(sessions.historyRevision)-\(credentials.vault == nil)") { load() }
        .sheet(isPresented: $showingLogs) { SessionLogsView(scope: .connection(c)) }
        #if BASTION_TEST_HOOKS
        .onAppear { DriverButtons.actions["Logs…"] = { showingLogs = true } }
        #endif
    }

    // Icon in the identity colour, name, address; the protocol picker under them as a compact
    // control. The name keeps the column's full width at 600-700 pt windows (layout fit).
    private var header: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            HStack(alignment: .firstTextBaseline, spacing: DS.Space.xs) {
                Image(systemName: protocolSymbol(c.protocol))
                    .font(DS.Font.title2)
                    .foregroundStyle(HostColors.shared.paint(for: c.id).map { Color(nsColor: $0.accent) } ?? .secondary)
                    .accessibilityHidden(true)
                Text(c.name).font(DS.Font.title).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                if isProduction {
                    Text("Production").font(DS.Font.caption.weight(.semibold)).foregroundStyle(.red)
                        .accessibilityLabel("Production connection")
                }
            }
            Text(address).font(DS.Font.body.monospaced()).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
            ProtocolPicker(connection: c, probe: "protocol-picker")
        }
    }

    // Which login a connect will use; clicking it opens the Logins editor. No secret.
    private var loginLine: some View {
        Button(action: openLogins) {
            Label(ConnectionSummary.loginLine(login), systemImage: "key.horizontal")
                .font(DS.Font.body)
                .fixedSize(horizontal: false, vertical: true)
                .multilineTextAlignment(.leading)
                .frame(minHeight: DS.Size.minHitTarget, alignment: .leading)
                .contentShape(Rectangle())
        }
        .buttonStyle(.link)
        .accessibilityLabel(ConnectionSummary.loginLine(login))
        .help("Edit this connection's logins")
        .accessibilityIdentifier("connection-page-login")
    }

    private func openLogins() {
        commands.editorStartPage = "credentials"
        commands.run("properties", on: c.id)
    }

    // Connect first (Return), then the quieter next steps. At narrow widths the quiet buttons
    // fold into one menu so Connect is never clipped (owner point 22).
    private var actions: some View {
        HStack(spacing: DS.Space.xs) {
            Button("Connect") { commands.run("connect-new-tab", on: c.id) }
                .dsPrimaryButton()
                .keyboardShortcut(.defaultAction)
                .fixedSize()
                .uiProbe("connection-page-connect")
            ViewThatFits(in: .horizontal) {
                HStack(spacing: DS.Space.xs) { quietButtons(folded: false) }
                HStack(spacing: DS.Space.xs) { moreMenu(folded: true) }
            }
            .buttonStyle(.borderless)
            .labelStyle(.iconHitTarget)
        }
    }

    /// Icon buttons with tooltips for the next steps; Properties (and, when narrow, all of them) sits in "…".
    @ViewBuilder private func quietButtons(folded: Bool) -> some View {
        if let open = openTabs.first {
            Button("Show Session", systemImage: "terminal") { sessions.selected = open.id }
                .iconTip("Show Session")
        }
        if Self.sshProtocols.contains(c.protocol) {
            Button("Files", systemImage: "folder") { commands.run("open-sftp", on: c.id) }
                .iconTip("Files")
            Button("Tunnel", systemImage: "arrow.left.arrow.right") { commands.panel = .tunnels }
                .iconTip("Tunnel Manager")
        }
        if ConnectionTool.applies(to: c) {
            IconMenuButton(symbol: "wrench.and.screwdriver", help: "Tools",
                           items: toolItems, identifier: "connection-page-tools")
        }
        if Self.loggedProtocols.contains(c.protocol) {
            Button("Logs…", systemImage: "doc.text") { showingLogs = true }
                .iconTip("This connection's session logs")
                .accessibilityIdentifier("connection-page-logs")
        }
        moreMenu(folded: false)
    }

    private var toolItems: [IconMenuItem] {
        ConnectionTool.allCases.map { tool in
            IconMenuItem(title: tool.label, symbol: protocolSymbol(tool.iconId)) { commands.openTool(tool, on: c) }
        }
    }

    /// The "…" menu: Properties always; when the column is too narrow the icon actions fold in here too.
    private func moreMenu(folded: Bool) -> some View {
        var items: [IconMenuItem] = []
        if folded {
            if let open = openTabs.first { items.append(IconMenuItem(title: "Show Session") { sessions.selected = open.id }) }
            if Self.sshProtocols.contains(c.protocol) {
                items.append(IconMenuItem(title: "Files") { commands.run("open-sftp", on: c.id) })
                items.append(IconMenuItem(title: "Tunnel Manager") { commands.panel = .tunnels })
            }
            if ConnectionTool.applies(to: c) { items += toolItems }
            if Self.loggedProtocols.contains(c.protocol) { items.append(IconMenuItem(title: "Logs…") { showingLogs = true }) }
            items.append(.separator)
        }
        items.append(IconMenuItem(title: "Properties") { commands.run("properties", on: c.id) })
        return IconMenuButton(symbol: "ellipsis", help: "More actions", items: items, identifier: "connection-page-more")
    }

    // The two stored facts, just above the session list's own History heading.
    private var historySection: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            // Label over value, so a narrow column never squeezes the value (layout fit).
            ForEach([("Last connected", lastConnected),
                     ("Last result", ConnectionSummary.lastResult(history?.lastResult)),
                     ("Open sessions", openTabs.isEmpty ? "None" : "\(openTabs.count)")], id: \.0) { label, value in
                VStack(alignment: .leading, spacing: 1) {
                    Text(label).font(DS.Font.caption).foregroundStyle(.secondary)
                    Text(value).font(DS.Font.body).textSelection(.enabled)
                }
            }
        }
        .accessibilityIdentifier("connection-history")
    }

    private var notesSection: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            Divider()
            Text("Notes").font(DS.Font.bodyStrong)
            Text(notes).font(DS.Font.body).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
        }
        .accessibilityIdentifier("connection-page-notes")
    }

    private var lastConnected: String {
        guard let at = history?.lastConnectedAt else { return "Never" }
        let date = Date(timeIntervalSince1970: TimeInterval(at)).formatted(date: .abbreviated, time: .shortened)
        return history?.lastUser.map { "\(date) as \($0)" } ?? date
    }

    private func load() {
        do {
            history = try connectionHistory(dataDir: LibraryModel.dataDir.path, connectionId: c.id)
            historyError = false
        } catch {
            historyError = true
        }
        notes = (try? model.library?.notes(id: c.id)) ?? ""
        login = loginState()
    }

    /// What a connect will use, read without opening the vault (which may prompt).
    private func loginState() -> ConnectionSummary.LoginState {
        let user = c.effectiveUsername ?? ""
        if c.inlineCredential != nil { return .inline(user: user) }
        guard let vault = credentials.vault, let library = model.library else {
            return LoginResolver.hasAssignment(c) ? .locked(user: user) : .none
        }
        let offers = (try? LoginResolver.offers(for: c.id, library: library, vault: vault, passwordsOnly: c.protocol == "rdp")) ?? []
        guard let best = offers.first else { return .none }
        return .offer(user: best.username.isEmpty ? user : best.username, source: best.source,
                      sourceName: best.sourceName, autoUse: best.autoUse)
    }
}
