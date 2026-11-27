import Foundation
import BastionCore

/// RDP with a saved login opens with no sheet, as SSH does (owner points 23 and 26). Which saved
/// login is the core's answer (`LoginResolver`), released by `releaseLogin`. The sheet
/// appears only to ask something: no saved password, a gateway sign-in, an unknown or changed
/// certificate, or a failed attempt (with its reason, a timeout included).
extension DirectConnect {
    static func rdpEligible(_ r: ConnectRequest, credentials: CredentialsModel) -> Bool {
        let c = r.connection
        guard r.mode != .system, !r.connectAs, r.library == nil, r.tunnelId == nil, !c.imported else { return false }
        switch credentials.lastLogin(for: c.id)?.login {
        case .password, .vault: return true
        default: break
        }
        return c.inlineCredential != nil || LoginResolver.mayAutoConnect(c, credentials: credentials, passwordsOnly: true)
    }

    static func attemptRdp(_ r: ConnectRequest, model: LibraryModel, sessions: SessionsModel,
                           credentials: CredentialsModel) async -> Outcome {
        let c = r.connection
        guard let library = model.library else { return .needsSheet(retry: true) }
        // A gateway asks for its own sign-in, and a gateway lookup error is shown by the sheet.
        do { if try library.gatewayRoute(connectionId: c.id) != nil { return .needsSheet(retry: true) } } catch {
            return .needsSheet(retry: true)
        }
        let pinKey = "\(c.host):\(c.port ?? RdpDefaults.port)"
        // No pinned certificate: the sheet runs the attempt and asks to trust it.
        guard let pin = RdpCertificatePins(dataDir: LibraryModel.dataDir).pin(pinKey) else { return .needsSheet(retry: true) }
        guard let login = await savedRdpLogin(c, library: library, sessions: sessions, credentials: credentials) else {
            return .needsSheet(retry: false)
        }
        let target = sessions.rdpTarget(c, library: library, username: login.username, domain: login.domain,
                                        trustedFingerprint: pin, via: nil)
        switch await sessions.connectRdp(target: target, password: login.password) {
        case .connected(let session):
            sessions.recordOutcome(c.id, user: login.username, failure: nil)
            // A vault login is asked from the core again next time; only a typed or own password is kept for the run.
            if !login.fromVault {
                credentials.remember(RememberedLogin(username: login.username, login: .password(password: login.password),
                                                     domain: login.domain.isEmpty ? nil : login.domain), for: c.id)
            }
            let tab = TerminalTab(name: c.name, content: .rdp(session), connectionId: c.id)
            if let replacing = r.replacing { sessions.replace(replacing, with: tab) } else { sessions.add(tab, layout: r.layout) }
            return .opened
        case .unknownCertificate:
            // The certificate changed since it was pinned: the sheet asks about it.
            return .needsSheet(retry: true)
        case .failed(let message):
            sessions.recordOutcome(c.id, user: login.username, failure: message)
            if message == RdpConnectFailure.auth { credentials.forgetLastLogin(for: c.id) }
            return .needsSheet(retry: false, failure: "\(c.name): \(message)")
        }
    }

    private struct RdpLogin {
        let username: String
        let domain: String
        let password: String
        /// Released by the core for this connect (`releaseLogin`), not typed or the connection's own.
        var fromVault = false
    }

    /// The password typed last time, the connection's own password, else the core's first login
    /// when it is `autoUse`. A login saved for another connection is only offered: the sheet
    /// shows it and releases it after the user confirms (decision D1).
    private static func savedRdpLogin(_ c: ConnectionView, library: Library, sessions: SessionsModel,
                                      credentials: CredentialsModel) async -> RdpLogin? {
        var credentialId: String?
        if let last = credentials.lastLogin(for: c.id) {
            switch last.login {
            case .password(let p): return RdpLogin(username: last.username, domain: last.domain ?? "", password: p)
            // Confirmed earlier in this run; `releaseLogin` refuses it once it is no longer offered.
            // The id is not checked against `passwordsOnly` here: `releaseLogin` hands out a
            // password or nothing, so an SSH key remembered by mistake is refused there too.
            case .vault(let id): credentialId = id
            default: break
            }
        }
        if credentials.vault == nil { await credentials.openInBackground(sessions: sessions) }
        guard let vault = credentials.vault else { return nil }
        if credentialId == nil {
            // The connection's own password keeps its own path (no vault credential is named).
            if let own = try? vault.rdpLoginFor(library: library, connectionId: c.id, credentialId: nil) { return rdpLogin(own, for: c) }
            let offers = await LoginResolver.resolve(c, library: library, credentials: credentials, sessions: sessions, passwordsOnly: true)
            guard let first = offers.first, first.autoUse else { return nil }
            credentialId = first.credentialId
        }
        guard let credentialId else { return nil }
        do {
            let saved = try vault.releaseLogin(library: library, connectionId: c.id, credentialId: credentialId)
            return rdpLogin(saved, for: c, fromVault: true)
        } catch {
            credentials.forgetLastLogin(for: c.id)
            return nil
        }
    }

    private static func rdpLogin(_ saved: RdpSavedLogin, for c: ConnectionView, fromVault: Bool = false) -> RdpLogin? {
        let (domain, user) = RdpAccount.split(saved.username, domain: "")
        let username = user.isEmpty ? (c.effectiveUsername ?? c.username ?? "") : user
        guard !username.isEmpty else { return nil }
        return RdpLogin(username: username, domain: domain, password: saved.password, fromVault: fromVault)
    }
}
