import SwiftUI
import BastionCore

extension SessionsModel {
    enum FtpsConnectResult: Sendable {
        case connected(FilesBrowser)
        case unknownCertificate(fingerprint: String)
        case failed(String)
    }

    /// Runs the blocking FTPS sign-in off the main thread.
    func connectFtps(library: Library, connectionId: String, username: String, password: String, trusted: String?) async -> FtpsConnectResult {
        guard let manager else { return .failed("The session manager could not start.") }
        return await Task.detached {
            do {
                return .connected(try manager.connectFtps(library: library, connectionId: connectionId, username: username,
                                                          password: password, trustedFingerprint: trusted))
            } catch FfiError.HostKeyUnknown(let fingerprint) {
                return .unknownCertificate(fingerprint: fingerprint)
            } catch FfiError.AuthFailed {
                return .failed("Authentication failed. Check the username and password.")
            } catch FfiError.Failed(let message, _) {
                return .failed(message)
            } catch {
                return .failed("\(error)")
            }
        }.value
    }
}

/// User and password for one FTPS sign-in. The server certificate is pinned on first use, like
/// an SSH host key; a different certificate later is prompted again as changed.
struct FtpsConnectSheet: View {
    let connection: ConnectionView
    @Environment(SessionsModel.self) private var sessions
    @Environment(LibraryModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var username = ""
    @State private var password = ""
    @State private var busy = false
    @State private var error: String?
    @State private var pending: String?
    @State private var accepted: String?

    private var port: UInt16 { connection.port ?? 21 }
    private var pinKey: String { "\(connection.host):\(port)" }
    private var pins: RdpCertificatePins { RdpCertificatePins(dataDir: LibraryModel.dataDir, file: "ftps_certificates.json") }

    var body: some View {
        Form {
            LabeledContent("Host", value: pinKey)
            TextField("User", text: $username)
            SecureField("Password", text: $password)
            Text("FTPS encrypts the sign-in and every transfer (explicit TLS). Plain FTP is not offered.")
                .font(DS.Font.callout).foregroundStyle(.secondary)
            if let error { CodedError(area: "FILE", message: error) }
        }
        .formStyle(.grouped)
        .scrollDisabled(true)
        .fixedSize(horizontal: false, vertical: true)
        .frame(width: 440)
        .disabled(busy)
        .onAppear { username = connection.username ?? "" }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button(busy ? "Connecting…" : "Connect") { Task { await connect() } }
                    .disabled(busy || username.isEmpty)
            }
        }
        .sheet(item: Binding(get: { pending.map(PendingFtpsCertificate.init) }, set: { pending = $0?.value })) { cert in
            HostKeyPrompt(host: pinKey, fingerprint: cert.value, subject: "certificate", changed: pins.pin(pinKey) != nil,
                          trust: {
                              accepted = cert.value
                              pending = nil
                              Task { await connect() }
                          },
                          cancel: { pending = nil })
        }
    }

    private func connect() async {
        guard let library = model.library else { return error = "The library is not open." }
        busy = true
        error = nil
        let result = await sessions.connectFtps(library: library, connectionId: connection.id, username: username,
                                                password: password, trusted: accepted ?? pins.pin(pinKey))
        busy = false
        switch result {
        case .connected(let browser):
            if let accepted {
                do { try pins.save(pinKey, fingerprint: accepted) } catch { sessions.error = "Could not store the certificate pin: \(error)" }
            }
            sessions.add(TerminalTab(name: "\(connection.name) — Files", content: .files(browser), connectionId: connection.id))
            password = ""
            dismiss()
        case .unknownCertificate(let fingerprint):
            pending = fingerprint
        case .failed(let message):
            error = message
        }
    }
}

private struct PendingFtpsCertificate: Identifiable {
    let value: String
    var id: String { value }
}
