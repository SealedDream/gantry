import SwiftUI
import BastionCore

/// Sign-in to the gateway an RDP, VNC or web connection goes through (Gateway property). The
/// connect sheet shows `GatewaySection`, calls `open` before connecting, and hands the route to
/// the tab it opens; a route no tab took is closed when the sheet goes away. The password lives
/// only here until it is handed to the core.
@MainActor @Observable
final class GatewayLogin {
    /// Nil for a direct connection.
    let hop: GatewayHopView?
    /// Why the gateway cannot be used (a deleted gateway, an unsupported type); connecting is refused.
    let problem: String?
    var username: String
    var password = ""
    /// Unknown gateway host key waiting for the user's decision.
    var pendingFingerprint: String?
    private var trusted: String?
    private(set) var route: GatewayRoute?

    init(library: Library?, connectionId: String) {
        var hop: GatewayHopView?
        var problem: String?
        do { hop = try library?.gatewayRoute(connectionId: connectionId) } catch { problem = "Gateway: \(error)" }
        self.hop = hop
        self.problem = problem
        username = hop?.username ?? ""
    }

    var ready: Bool { problem == nil && (hop == nil || !username.trimmingCharacters(in: .whitespaces).isEmpty) }

    enum Outcome {
        /// Connect directly, or through this loopback port.
        case direct
        case via(UInt16)
        /// The host-key prompt is up; `trust()` and connect again.
        case needsTrust
        case failed(String)
    }

    /// Opens the route once (kept for retries of the desktop sign-in) or reports why not.
    func open(sessions: SessionsModel, library: Library?, connectionId: String) async -> Outcome {
        if let problem { return .failed(problem) }
        guard hop != nil else { return .direct }
        if let route, route.isRunning() { return .via(route.localPort()) }
        guard let library else { return .failed("The library is not open.") }
        let login: SshLogin = password.isEmpty ? .agent : .password(password: password)
        switch await sessions.openGatewayRoute(library: library, connectionId: connectionId, username: username, login: login, trust: trusted) {
        case .opened(let r):
            route = r
            password = ""
            return .via(r.localPort())
        case .unknownHost(let fingerprint):
            pendingFingerprint = fingerprint
            return .needsTrust
        case .failed(let message):
            return .failed("Gateway \(hop?.name ?? ""): \(message)")
        }
    }

    func trust() {
        trusted = pendingFingerprint
        pendingFingerprint = nil
    }

    /// The route for the tab that now owns it; the sheet no longer closes it.
    func handOff() -> GatewayRoute? {
        defer { route = nil }
        return route
    }

    func discard() {
        route?.close()
        route = nil
    }
}

/// The gateway rows of an RDP, VNC or web connect sheet; nothing for a direct connection.
struct GatewaySection: View {
    @Bindable var login: GatewayLogin
    /// Connect again after the user trusted the gateway's host key.
    let retry: () -> Void

    var body: some View {
        if let problem = login.problem {
            Section("Gateway") { Text(problem).foregroundStyle(.red) }
        } else if let hop = login.hop {
            Section("Gateway") {
                LabeledContent("Through", value: "\(hop.name) (\(hop.key))")
                TextField("Gateway user", text: $login.username)
                SecureField("Gateway password", text: $login.password, prompt: Text("Empty: use the SSH agent"))
            }
            .sheet(item: Binding(get: { login.pendingFingerprint.map(PendingGatewayKey.init) }, set: { login.pendingFingerprint = $0?.value })) { key in
                HostKeyPrompt(host: "gateway \(hop.key)", fingerprint: key.value,
                              trust: { login.trust(); retry() },
                              cancel: { login.pendingFingerprint = nil })
            }
        }
    }
}

private struct PendingGatewayKey: Identifiable {
    let value: String
    var id: String { value }
}

extension SessionsModel {
    enum GatewayRouteResult: Sendable {
        case opened(GatewayRoute)
        case unknownHost(fingerprint: String)
        case failed(String)
    }

    /// Runs the blocking gateway sign-in off the main thread.
    func openGatewayRoute(library: Library, connectionId: String, username: String, login: SshLogin, trust: String?) async -> GatewayRouteResult {
        guard let manager else { return .failed("The session manager could not start.") }
        return await Task.detached {
            do {
                return .opened(try manager.openGatewayRoute(library: library, connectionId: connectionId, username: username,
                                                            login: login, trustFingerprint: trust))
            } catch FfiError.HostKeyUnknown(let fingerprint) {
                return .unknownHost(fingerprint: fingerprint)
            } catch FfiError.AuthFailed {
                return .failed("authentication failed. Check the gateway user and password.")
            } catch FfiError.Failed(let message, _) {
                return .failed(message)
            } catch {
                return .failed("\(error)")
            }
        }.value
    }
}
