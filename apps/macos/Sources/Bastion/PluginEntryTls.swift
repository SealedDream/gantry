import AppKit
import SwiftUI
import BastionCore

/// A plugin entry's certificate rule (PLUG-PVE-01): system trust, or one pinned certificate the
/// user compared and accepted. The core owns the setting; the plugin never sees or changes it.
struct PluginEntryTlsRow: View {
    let connection: ConnectionView
    @Environment(LibraryModel.self) private var model
    @State private var busy = false

    private var tls: PluginEntryTlsView? { try? model.library?.pluginEntryTls(id: connection.id) }

    var body: some View {
        let pin = tls?.mode == "pinned" ? tls?.pinSha256 : nil
        VStack(alignment: .leading, spacing: DS.Space.xxs) {
            Text(pin.map { "Pinned: \(PluginEntryTlsRow.short($0))" } ?? (tls?.damaged == true ? "Pin unreadable: system trust" : "System trust"))
                .font(DS.Font.body)
                .lineLimit(1)
                .help(pin.map { "SHA-256 \($0)" } ?? (tls?.damaged == true ? "The saved pin could not be read. Trust the server's certificate again." : "The server's certificate must be valid for its name."))
                .accessibilityIdentifier("plugin-tls-state")
            HStack(spacing: DS.Space.xs) {
                Button("Trust Server Certificate…") { Task { await trust() } }
                    .disabled(busy || connection.host.isEmpty)
                    .help("Read the server's certificate, compare its fingerprint, then pin it")
                if pin != nil {
                    Button("Use System Trust") { set(mode: "verify-full", pin: nil) }
                        .disabled(busy)
                }
            }
            .controlSize(.small)
        }
    }

    /// `ab12cd…9f0e`: enough to recognise, the whole value is in the tooltip.
    static func short(_ pin: String) -> String {
        pin.count > 12 ? "\(pin.prefix(6))…\(pin.suffix(4))" : pin
    }

    /// Groups of four, for comparing with the server's own display.
    static func grouped(_ pin: String) -> String {
        stride(from: 0, to: pin.count, by: 4).map { i -> String in
            let a = pin.index(pin.startIndex, offsetBy: i)
            let b = pin.index(a, offsetBy: min(4, pin.count - i))
            return String(pin[a..<b])
        }.joined(separator: " ")
    }

    private func trust() async {
        busy = true
        defer { busy = false }
        await PluginCertificateTrust.ask(connection, model: model)
    }

    private func set(mode: String, pin: String?) {
        model.mutate { try $0.setPluginEntryTls(id: connection.id, mode: mode, pinSha256: pin) }
    }
}

/// Trust Server Certificate (Properties → Certificate, and the dashboard banner): reads the
/// server's certificate, shows its SHA-256 for the user to compare, and pins it on Trust.
@MainActor
enum PluginCertificateTrust {
    /// True when the user trusted the certificate and the pin was saved.
    @discardableResult
    static func ask(_ connection: ConnectionView, model: LibraryModel) async -> Bool {
        let host = connection.host
        let port = connection.port ?? PluginEntries.type(of: connection)?.defaultPort ?? 443
        let result = await Task.detached(priority: .userInitiated) { Result { try pluginCertificateProbe(host: host, port: port) } }.value
        switch result {
        case .failure(let e):
            model.error = "\(connection.name): certificate not read: \(e.userMessage)"
            return false
        case .success(let pin):
            guard confirm(connection: connection, host: host, port: port, pin: pin) else { return false }
            model.mutate { try $0.setPluginEntryTls(id: connection.id, mode: "pinned", pinSha256: pin) }
            return (try? model.library?.pluginEntryTls(id: connection.id))??.pinSha256 == pin
        }
    }

    private static func confirm(connection: ConnectionView, host: String, port: UInt16, pin: String) -> Bool {
        if TestHooks.isScripted, let answer = scriptedAnswer { scriptedAnswer = nil; return answer }
        let alert = NSAlert()
        alert.messageText = "Trust this certificate for \(connection.name)?"
        alert.informativeText = "\(host):\(port)\nSHA-256\n\(PluginEntryTlsRow.grouped(pin))\n\nCompare it with the server before you trust it."
        alert.addButton(withTitle: "Trust")
        alert.addButton(withTitle: "Cancel").keyEquivalent = "\u{1b}"
        return alert.runModalInFront() == .alertFirstButtonReturn
    }

    /// UI driver only: the answer the next question takes without showing the alert.
    static var scriptedAnswer: Bool?
}
