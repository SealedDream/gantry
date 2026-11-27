import SwiftUI
import BastionCore

/// Link state shown by the session title bar's dot (spec §3: green, amber, red).
enum SessionLinkState: String {
    case connected, connecting, disconnected

    var color: Color {
        switch self {
        case .connected: .green
        case .connecting: .orange
        case .disconnected: .red
        }
    }

    var label: String {
        switch self {
        case .connected: "Connected"
        case .connecting: "Connecting"
        case .disconnected: "Disconnected"
        }
    }

    @MainActor static func of(_ tab: TerminalTab) -> SessionLinkState {
        if tab.ended || tab.isWaiting { return .disconnected }
        if tab.panes.contains(where: { $0.linkStatus != nil }) { return .connecting }
        return .connected
    }
}

/// `user@host:port` for a saved connection; the user and port are left out when unknown.
func sessionAddress(user: String?, host: String, port: UInt16?) -> String {
    let who = user.flatMap { $0.isEmpty ? nil : $0 }.map { "\($0)@" } ?? ""
    return who + host + (port.map { ":\($0)" } ?? "")
}

/// Bar above a saved connection's session (spec §3): status dot and the status line on the left,
/// Reconnect and Unpin on the right. It sits on the session's own surface (no bar material, no
/// divider), compact and quiet, like Tabby's (owner 2026-11-15). Unpin hides it on every tab; the
/// only way back is Settings › Terminal › Session bar (`terminal.session-bar`). A disconnected
/// session still shows it, since Reconnect lives there.
struct SessionTitleBar: View {
    let tab: TerminalTab
    let connection: ConnectionView
    @Environment(Commands.self) private var commands
    @Environment(SettingsModel.self) private var settings

    private var state: SessionLinkState { SessionLinkState.of(tab) }
    /// Reads `treeVersion` so a colour or Privileged change (which replaces the tree) redraws the bar (UI-01).
    private var paint: HostColors.Paint? { _ = commands.model.treeVersion; return HostColors.shared.paint(for: connection.id) }
    private var pinned: Bool { settings.value("terminal.session-bar") != "false" }
    private func unpin() { _ = settings.set("terminal.session-bar", "false") }
    @Environment(CredentialsModel.self) private var credentials
    private var hostPort: String { sessionAddress(user: nil, host: connection.host, port: connection.port) }
    /// "Name (address) · user · SSH · key · Connecting · Logging" (UI-04, W21). No secret.
    private var status: String {
        let user = credentials.lastLogin(for: connection.id)?.username ?? connection.effectiveUsername
        return ConnectionSummary.statusLine(
            name: connection.name, address: hostPort, user: user,
            security: ConnectionSummary.security(protocolName: connection.protocol, loginKind: connection.inlineCredential),
            state: state == .connected ? nil : state.label, logging: tab.isLogging)
    }

    var body: some View {
        Group {
            if pinned || state == .disconnected { bar }
        }
        .zIndex(1)
        // The UI driver's `title-bar-button <label>` presses Reconnect, Pin or Unpin by name.
        .onReceive(NotificationCenter.default.publisher(for: DriverEvents.pressTitleBarButton)) { note in
            switch note.object as? String {
            case "Reconnect": reconnect()
            case "Unpin": unpin()
            default: break
            }
        }
    }

    private func reconnect() { commands.run("reconnect", on: connection.id) }

    private var bar: some View {
        HStack(spacing: DS.Space.xs) {
            Circle().fill(state.color).frame(width: 8, height: 8)
                .accessibilityLabel(state.label)
            // UI-01: a privileged host says so in words, not colour alone.
            if paint?.privileged == true {
                Text("Production").font(DS.Font.caption.weight(.semibold))
                    .foregroundStyle(HostColors.tintsText ? Color(nsColor: paint?.name ?? .labelColor) : .primary)
                    .lineLimit(1).fixedSize()
                    .help("Privileged host")
            }
            // Narrow panes (split, inspector open): the address shortens to host:port, then hides,
            // and the buttons drop their titles, rather than eliding mid-text (layout fit).
            ViewThatFits(in: .horizontal) {
                content(status, titled: true)
                content(status, titled: false)
                content("\(connection.name) (\(hostPort))", titled: false)
                content(sessionAddress(user: nil, host: connection.host, port: connection.port), titled: false)
                content(nil, titled: false)
            }
        }
        .help(status)
        .padding(.horizontal, DS.Space.s)
        // UI-01: the identity colour as a thin strip along the bar's bottom edge (no height change).
        .overlay(alignment: .bottom) {
            if let p = paint { Rectangle().fill(Color(nsColor: p.accent)).frame(height: 2).allowsHitTesting(false).accessibilityHidden(true) }
        }
        .foregroundStyle(.secondary)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("session-title-bar")
    }

    @ViewBuilder private func content(_ text: String?, titled: Bool) -> some View {
        HStack(spacing: DS.Space.xs) {
            if let text {
                Text(text).font(DS.Font.caption.monospaced()).lineLimit(1).fixedSize().textSelection(.enabled)
            }
            Spacer(minLength: DS.Space.xs)
            reconnectButton(titled: titled)
            if pinned {
                Button(action: unpin) { barLabel("Unpin", "pin.slash", titled: false) }
                    .buttonStyle(.borderless)
                    .help("Hide the session bar (Settings › Terminal › Session bar shows it again)")
            }
        }
    }

    /// A title-bar button's label at least the minimum hit target tall (was 17 pt).
    private func barLabel(_ title: String, _ symbol: String, titled: Bool) -> some View {
        Group {
            if titled { Label(title, systemImage: symbol) } else { Label(title, systemImage: symbol).labelStyle(.iconOnly) }
        }
        .frame(minWidth: DS.Size.minHitTarget, minHeight: DS.Size.minHitTarget)
        .contentShape(Rectangle())
    }

    @ViewBuilder private func reconnectButton(titled: Bool) -> some View {
        let button = Button(action: reconnect) { barLabel("Reconnect", "arrow.clockwise", titled: titled) }
            .help("Close this session and connect again")
        if state == .disconnected {
            // Quiet: an outline marks the next step; no filled accent button (owner 2026-11-15).
            button.dsSecondaryButton().tint(.primary)
        } else {
            button.buttonStyle(.borderless)
        }
    }
}
