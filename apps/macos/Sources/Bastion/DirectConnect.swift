import Foundation
import BastionCore

/// Opens an SSH connection that already has everything it needs (the login used a moment ago, its
/// own saved secret, or a login the core says it may use without asking) without presenting the connect sheet: the
/// handshake starts from the double-click itself, and the sheet appears only when the attempt
/// cannot start or does not succeed (owner points 23 and 26).
@MainActor
enum DirectConnect {
    enum Outcome {
        case opened
        /// Show the sheet. `retry` false: the saved login was tried and failed, so the sheet asks
        /// instead of trying it again.
        case needsSheet(retry: Bool, failure: String? = nil)
    }

    /// Plain SSH with a saved login; Connect as…, Quick Connect, tunnels, imported hosts and the
    /// file panel keep the sheet.
    static func eligible(_ r: ConnectRequest, credentials: CredentialsModel) -> Bool {
        let c = r.connection
        if c.protocol == "rdp" { return rdpEligible(r, credentials: credentials) }
        guard c.protocol == "ssh", !r.connectAs, r.library == nil, r.tunnelId == nil, r.filePanelFor == nil, !c.imported else { return false }
        return credentials.lastLogin(for: c.id) != nil || c.inlineCredential != nil
            || LoginResolver.mayAutoConnect(c, credentials: credentials, passwordsOnly: false)
    }

    static func attempt(_ r: ConnectRequest, model: LibraryModel, sessions: SessionsModel, credentials: CredentialsModel) async -> Outcome {
        if r.connection.protocol == "rdp" { return await attemptRdp(r, model: model, sessions: sessions, credentials: credentials) }
        guard let library = model.library,
              let (username, login) = await savedLogin(r.connection, library: library, sessions: sessions, credentials: credentials) else {
            return .needsSheet(retry: true)
        }
        let c = r.connection
        let result = await sessions.connect(library: library, connectionId: c.id, username: username, login: login,
                                            trust: nil, mode: r.mode, systemView: r.systemView)
        switch result {
        case .connected(let content):
            // SEC-03: a successful reuse starts the remembered login's time again.
            if let last = credentials.lastLogin(for: c.id) { credentials.remember(last, for: c.id) }
            let name = r.mode == .files ? "\(c.name) — Files" : c.name
            let tab = TerminalTab(name: name, content: content, connectionId: c.id)
            if let replacing = r.replacing { sessions.replace(replacing, with: tab) } else { sessions.add(tab, layout: r.layout) }
            return .opened
        case .failed:
            credentials.forgetLastLogin(for: c.id)
            return .needsSheet(retry: false)
        case .unknownHost, .needsCode, .weakAlgorithms, .tunnel:
            // A question only the sheet asks: it runs the same attempt and asks it.
            return .needsSheet(retry: true)
        }
    }

    /// The login the sheet would use without asking, or nil when it would ask: the one used a
    /// moment ago, the connection's own secret, else the core's first login when it is `autoUse`.
    /// A login saved for another connection is only offered, so the sheet shows it (decision D1).
    static func savedLogin(_ c: ConnectionView, library: Library, sessions: SessionsModel,
                           credentials: CredentialsModel, passwordsOnly: Bool = false) async -> (String, SshLogin)? {
        if let last = credentials.lastLogin(for: c.id) {
            // A vault login confirmed earlier in this run: only while the core still offers it.
            guard case .vault(let id) = last.login else { return (last.username, last.login) }
            if LoginResolver.stillOffered(id, to: c, credentials: credentials, passwordsOnly: false) { return (last.username, last.login) }
            credentials.forgetLastLogin(for: c.id)
        }
        if credentials.vault == nil { await credentials.openInBackground(sessions: sessions) }
        guard let vault = credentials.vault else { return nil }
        let user = c.effectiveUsername ?? ""
        if let inline = try? vault.inlineFor(connectionId: c.id) {
            // An inline secret on a Production host asks first (the sheet's confirmation).
            guard !isProduction(c, library: library) else { return nil }
            return (user.isEmpty ? inline.username : user, .vault(credentialId: c.id))
        }
        let offers = await LoginResolver.resolve(c, library: library, credentials: credentials, sessions: sessions, passwordsOnly: passwordsOnly)
        guard let first = offers.first, first.autoUse else { return nil }
        return (user, .vault(credentialId: first.credentialId))
    }

    private static func isProduction(_ c: ConnectionView, library: Library) -> Bool {
        (try? library.propertyValues(id: c.id))?.first { $0.key == "environment" }?.effective == "production"
    }
}
