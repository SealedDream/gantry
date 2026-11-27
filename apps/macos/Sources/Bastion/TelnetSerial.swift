import AppKit
import SwiftUI
import BastionCore

/// Telnet and serial terminals (B7, `docs/plans/B7-TELNET-SERIAL.md`). The core makes every
/// decision (policy, password opt-in, port names); this file shows it.

/// Settings → Security → Allow Telnet under the managed policy.
@MainActor enum TelnetPolicy {
    static let settingId = "security.allow-telnet"
    /// Set by `SettingsModel.init`; the Add menu lives in an AppKit popover without the environment.
    static weak var settings: SettingsModel?

    /// The administrator's reason when managed policy forbids Telnet, else nil.
    static var lock: String? { telnetPolicyLock() }

    /// Read through the settings model so SwiftUI redraws when the switch changes.
    static var allowedNow: Bool {
        guard let settings else { return false }
        return lock == nil && settings.value(settingId) == "true"
    }

    /// Short, one line: why Telnet is greyed out.
    static var offText: String {
        lock != nil ? "Turned off by your administrator." : "Off. Turn on in Settings → Security → Allow Telnet."
    }
}

/// The permanent yellow band on the add form and the connection page. One line.
struct TelnetWarningBand: View {
    var body: some View {
        Label("Telnet is not encrypted: anyone on the network can read what you type.", systemImage: "exclamationmark.triangle.fill")
            .font(DS.Font.caption)
            .lineLimit(1)
            .truncationMode(.tail)
            .padding(.horizontal, DS.Space.s)
            .padding(.vertical, DS.Space.xxs)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.yellow.opacity(0.25), in: RoundedRectangle(cornerRadius: 6))
            .help(telnetWarning())
            .accessibilityIdentifier("telnet-warning")
    }
}

/// Allow Telnet: asks once when turned on, never when turned off; disabled under managed policy.
struct AllowTelnetToggle: View {
    let label: String
    @Environment(SettingsModel.self) private var settings

    var body: some View {
        let lock = TelnetPolicy.lock
        Toggle(label, isOn: Binding(get: { lock == nil && settings.value(TelnetPolicy.settingId) == "true" }, set: change))
            .labelsHidden()
            .toggleStyle(.switch)
            .disabled(lock != nil)
            .help(lock ?? telnetWarning())
            .accessibilityIdentifier("allow-telnet")
    }

    private func change(_ on: Bool) {
        guard on else { settings.set(TelnetPolicy.settingId, "false"); return }
        let alert = NSAlert()
        alert.messageText = "Allow Telnet?"
        alert.informativeText = telnetWarning()
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Allow Telnet")
        alert.addButton(withTitle: "Cancel")
        if alert.runModalInFront() == .alertFirstButtonReturn { settings.set(TelnetPolicy.settingId, "true") }
    }
}

/// Under a Telnet or serial terminal: the serial status line (`COM3 · 115200 8N1`), and after a
/// drop the reason with Reconnect (Telnet) or Reopen (serial). Nothing for other terminals.
struct RemoteLinkBar: View {
    let pane: TerminalPane
    @State private var busy = false
    @State private var failure: String?

    var body: some View {
        let t = pane.terminal
        if t.canReconnect() {
            RemoteLinkBarContent(serial: t.serialStatus(), lost: pane.linkStatus.map { failure ?? $0 }, busy: busy, reconnect: reconnect)
        }
    }

    private func reconnect() {
        busy = true
        failure = nil
        let t = pane.terminal
        Task {
            let result = await Task.detached { Result { try t.reconnect() } }.value
            busy = false
            if case .failure(let e) = result { failure = errorText(e) } else { pane.linkStatus = t.linkStatus() }
        }
    }
}

/// What `RemoteLinkBar` draws, without a terminal (also shown by the UI driver for layout fit).
struct RemoteLinkBarContent: View {
    let serial: String?
    let lost: String?
    var busy = false
    var reconnect: () -> Void = {}

    var body: some View {
        if serial != nil || lost != nil {
            HStack(spacing: DS.Space.s) {
                if let serial { Text(serial).monospacedDigit() }
                if let lost {
                    Label(lost, systemImage: "bolt.horizontal.circle").foregroundStyle(.orange).lineLimit(1)
                    Spacer(minLength: 0)
                    Button(serial != nil ? "Reopen" : "Reconnect", action: reconnect)
                        .disabled(busy)
                        .accessibilityIdentifier("remote-reconnect")
                } else {
                    Spacer(minLength: 0)
                }
            }
            .font(DS.Font.caption)
            .padding(.horizontal, DS.Space.s)
            .padding(.vertical, DS.Space.xxs)
            .background(.bar)
        }
    }
}

extension SessionsModel {
    /// A serial entry from an older library: Serial is Not planned (owner 2026-11-15). It stays in
    /// the tree and its properties load; Connect only says so.
    func refuseUnsupported(connection: ConnectionView) {
        let reason = "\(connection.name): Serial connections are not supported."
        self.error = reason
        recordOutcome(connection.id, user: nil, failure: reason)
    }

    /// A saved Telnet connection. `login` is typed only when the connection's own opt-in is on
    /// (checked in the core). The connect runs off the main thread.
    func openTelnet(connection: ConnectionView, library: Library, settings: SettingsFile, username: String, login: SshLogin?) async {
        guard let manager else { self.error = "The session manager could not start."; return }
        let id = connection.id
        connecting.insert(id)
        defer { connecting.remove(id) }
        let result = await Task.detached {
            Result { try manager.connectTelnet(library: library, settings: settings, connectionId: id, username: username, login: login, cols: 80, rows: 24) }
        }.value
        switch result {
        case .success(let t):
            add(TerminalTab(name: connection.name, content: .terminal(t), connectionId: id))
            recordOutcome(id, user: username.isEmpty ? nil : username, failure: nil)
        case .failure(let e):
            let reason = "Could not open \(connection.name): \(errorText(e))"
            self.error = reason
            recordOutcome(id, user: nil, failure: reason)
        }
    }
}

extension Commands {
    /// Telnet: refused with the reason while it is off; otherwise the saved password only when the
    /// connection has "Type the saved password after the login prompt" on.
    func openTelnet(_ c: ConnectionView, library: Library) {
        guard TelnetPolicy.allowedNow else {
            sessions.error = TelnetPolicy.lock.map { "Telnet is turned off by your administrator: \($0)" }
                ?? "Telnet is off. Turn on Allow Telnet in Settings → Security."
            return
        }
        guard let file = settings.coreFile else { sessions.error = "Settings could not be read."; return }
        let optedIn = (try? library.propertyValues(id: c.id))?.first { $0.key == "telnet_send_password" }?.own == "true"
        Task {
            var user = c.effectiveUsername ?? ""
            var login: SshLogin?
            if optedIn, let credentials,
               let saved = await DirectConnect.savedLogin(c, library: library, sessions: sessions, credentials: credentials, passwordsOnly: true) {
                user = saved.0
                login = saved.1
            }
            await sessions.openTelnet(connection: c, library: library, settings: file, username: user, login: login)
        }
    }
}
