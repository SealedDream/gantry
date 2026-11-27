import Foundation
import SwiftUI
import BastionCore
import BastionRdp

/// Server certificates the user accepted, keyed `host:port` → SHA-256 hex, in
/// `<data dir>/rdp_certificates.json`. Trust on first use: a changed certificate is prompted
/// again, flagged as changed, and only replaces the pin when the user accepts it.
struct RdpCertificatePins {
    let url: URL

    /// `file` is `rdp_certificates.json` for RDP, `ftps_certificates.json` for FTPS.
    init(dataDir: URL, file: String = "rdp_certificates.json") { url = dataDir.appendingPathComponent(file) }

    func load() -> [String: String] {
        guard let data = try? Data(contentsOf: url) else { return [:] }
        return (try? JSONDecoder().decode([String: String].self, from: data)) ?? [:]
    }

    func pin(_ key: String) -> String? { load()[key] }

    func save(_ key: String, fingerprint: String) throws {
        var all = load()
        all[key] = fingerprint
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(all).write(to: url, options: [.atomic])
    }
}

/// Protocols the app can open a session for.
let connectableProtocols: Set<String> = ["local", "services", "processes", "eventlog", "ssh", "rdp", "vnc", "web", "sftp", "scp", "ftps"]

enum RdpDefaults {
    static let port: UInt16 = 3389
}

extension SessionsModel {
    enum RdpConnectResult: Sendable {
        case connected(RdpSession)
        case unknownCertificate(fingerprint: String)
        case failed(String)
    }

    /// Runs the blocking connect off the main thread. The target's `trustedFingerprint` is the
    /// certificate to accept for this attempt (a stored pin, or one the user just verified).
    func connectRdp(target: RdpTarget, password: String) async -> RdpConnectResult {
        // The connect blocks for up to the core's 30 s establish timeout: run it on its own queue,
        // never on the Swift cooperative pool, so a hung server cannot starve other tasks.
        await withCheckedContinuation { done in
            Self.rdpConnectQueue.async {
                OpenH264.prepare()
                done.resume(returning: Self.blockingRdpConnect(target: target, password: password))
            }
        }
    }

    private static let rdpConnectQueue = DispatchQueue(label: "bastion.rdp.connect", qos: .userInitiated, attributes: .concurrent)

    private nonisolated static func blockingRdpConnect(target: RdpTarget, password: String) -> RdpConnectResult {
        do {
            let session = try RdpSession()
            try session.connect(target: target, password: password)
            return .connected(session)
        } catch RdpError.CertificateUnknown(let fingerprint) {
            return .unknownCertificate(fingerprint: fingerprint)
        } catch RdpError.AuthFailed {
            return .failed(RdpConnectFailure.auth)
        } catch RdpError.Failed(let message) {
            return .failed(message)
        } catch {
            return .failed(error.userMessage)
        }
    }

    /// The RDP target for a connection's saved properties (sheet and direct connect share it).
    func rdpTarget(_ c: ConnectionView, library: Library?, username: String, domain: String,
                   trustedFingerprint: String?, via: UInt16?) -> RdpTarget {
        let options = try? library?.rdpOptions(connectionId: c.id)
        let size = DesktopFit.rdpConnectSize(library, connectionId: c.id)
        return RdpTarget(host: c.host, port: c.port ?? RdpDefaults.port, username: username,
                         domain: domain.isEmpty ? nil : domain, width: size.width, height: size.height,
                         trustedFingerprint: trustedFingerprint,
                         nlaOnly: RdpNla.required(connection: options?.nlaOnly ?? false),
                         viaLoopbackPort: via,
                         clipboard: options?.clipboard ?? false,
                         sharedFolder: options?.sharedFolder,
                         audio: options?.audio ?? false)
    }
}

enum RdpConnectFailure {
    static let auth = "Authentication failed. Check the username and password."
}

/// Username, domain and password for one RDP connect; the password lives only in this sheet's
/// state until it is handed to the RDP library.
struct RdpConnectSheet: View {
    let connection: ConnectionView
    @Environment(SessionsModel.self) private var sessions
    @Environment(LibraryModel.self) private var model
    @Environment(CredentialsModel.self) private var credentials
    @Environment(\.dismiss) private var dismiss
    @State private var username = ""
    @State private var domain = ""
    @State private var password = ""
    @State private var busy = false
    @State private var error: String?
    @State private var pending: String?
    @State private var accepted: String?
    @State private var gateway: GatewayLogin?
    /// The password came from the vault or the last sign-in: a failure forgets the latter.
    @State private var savedPassword = false
    /// A saved login is being tried: the "Reconnecting…" card covers the form (owner points 23, 26).
    @State private var autoConnecting: Bool
    /// Saved password logins the core offers this connection, best first (`LoginResolver`).
    @State private var offers: [LoginOffer] = []
    /// The offered login to connect with; nil: the typed username and password.
    @State private var selectedLogin: String?
    /// "Use this login for <connection> from now on", for a login saved for another connection.
    @State private var keepLogin = false

    /// false after a direct connect already tried the saved login: fill the form, do not retry it.
    let autoConnect: Bool

    /// `failure`: why the direct connect with the saved login did not open (shown in the form).
    init(connection: ConnectionView, autoConnect: Bool = true, failure: String? = nil) {
        self.connection = connection
        self.autoConnect = autoConnect
        _error = State(initialValue: failure)
        _autoConnecting = State(initialValue: autoConnect && (connection.inlineCredential != nil || LoginResolver.hasAssignment(connection)))
    }

    private var port: UInt16 { connection.port ?? RdpDefaults.port }
    private var options: RdpOptionsView? { try? model.library?.rdpOptions(connectionId: connection.id) }

    /// What this connection shares with the server (Redirection properties), shown before connecting.
    private var sharing: String {
        guard let o = options else { return "Nothing" }
        let parts = [o.clipboard ? "clipboard text" : nil, o.audio ? "sound" : nil,
                     o.sharedFolder.map { "folder \(($0 as NSString).abbreviatingWithTildeInPath)" }].compactMap { $0 }
        return parts.isEmpty ? "Nothing" : parts.joined(separator: ", ")
    }
    private var pinKey: String { "\(connection.host):\(port)" }
    private var pins: RdpCertificatePins { RdpCertificatePins(dataDir: LibraryModel.dataDir) }

    var body: some View {
        Form {
            LabeledContent("Host", value: pinKey)
            if !offers.isEmpty {
                // The core's list, each with where it comes from. The password is released only on Connect.
                Picker("Login", selection: Binding(get: { selectedLogin }, set: { selectedLogin = $0; keepLogin = false })) {
                    ForEach(offers) { Text($0.label).tag(Optional($0.credentialId)) }
                    Divider()
                    Text("Type a username and password").tag(String?.none)
                }
                if canKeepLogin {
                    Toggle("Use this login for \(connection.name) from now on", isOn: $keepLogin)
                        .lineLimit(1).truncationMode(.middle)
                        .help("Add it to this connection’s logins, so the next connect does not ask.")
                }
            }
            if selectedOffer == nil {
                TextField("User", text: $username)
                TextField("Domain (optional)", text: $domain)
                SecureField("Password", text: $password)
            }
            LabeledContent("Shares", value: sharing)
            if let gateway { GatewaySection(login: gateway) { Task { await connect() } } }
            if let error { CodedError(area: "RDP", message: error) }
        }
        .scrollDisabled(true)
        .fixedSize(horizontal: false, vertical: true)
        .formStyle(.grouped)
        .frame(width: 440)
        .disabled(busy)
        .overlay { if autoConnecting { ReconnectingCard(name: connection.name, reconnect: savedPassword) { dismiss() } } }
        .onAppear {
            username = connection.effectiveUsername ?? connection.username ?? ""
            if gateway == nil { gateway = GatewayLogin(library: model.library, connectionId: connection.id) }
        }
        .task { await fillSavedLogin() }
        .onDisappear { gateway?.discard() }
        .onChange(of: loginState, initial: true) { _, state in LoginResolver.sheetState = state }
        .onReceive(NotificationCenter.default.publisher(for: DriverEvents.pressButton)) { note in
            driverLoginStep(note.object as? String ?? "")
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button(busy ? "Connecting…" : "Connect") { Task { await connect() } }
                    .disabled(busy || (selectedOffer == nil && username.isEmpty) || gateway?.ready == false)
            }
        }
        .sheet(item: Binding(get: { pending.map(PendingCertificate.init) }, set: { pending = $0?.value })) { cert in
            HostKeyPrompt(host: pinKey, fingerprint: cert.value, subject: "certificate", changed: pins.pin(pinKey) != nil,
                          trust: {
                              accepted = cert.value
                              pending = nil
                              Task { await connect() }
                          },
                          cancel: { pending = nil })
        }
    }

    private var selectedOffer: LoginOffer? { offers.first { $0.credentialId == selectedLogin } }
    /// A login saved for another connection can be kept; the connection's own needs no question.
    private var canKeepLogin: Bool { selectedOffer.map { !$0.autoUse } ?? false }
    private var loginState: String {
        LoginResolver.sheetText(offers: offers, selected: selectedLogin, keep: canKeepLogin ? keepLogin : nil)
    }

    /// UI driver (`login-pick <label>|typed`, `login-keep on|off`): the same state the controls set.
    private func driverLoginStep(_ step: String) {
        if step.hasPrefix("login-pick:") {
            let want = String(step.dropFirst("login-pick:".count))
            selectedLogin = offers.first { $0.label == want || $0.name == want }?.credentialId
            keepLogin = false
        } else if step.hasPrefix("login-keep:") {
            keepLogin = step.hasSuffix(":on") && canKeepLogin
        }
    }

    /// Saved properties connect at once (owner feedback 2026-11-07 #2, #3): the password typed a
    /// moment ago, the connection's own password, else the core's first login when the connection
    /// may use it without asking. A login saved for another connection is selected and waits for
    /// Connect (owner decision D1). Nothing saved: the form.
    private func fillSavedLogin() async {
        if autoConnect, credentials.lastLogin(for: connection.id) != nil { autoConnecting = true }
        await tryFillSavedLogin()
        autoConnecting = false
    }

    private func tryFillSavedLogin() async {
        guard let library = model.library else { return }
        let last = autoConnect ? credentials.lastLogin(for: connection.id) : nil
        if let last, case .password(let p) = last.login {
            username = last.username
            domain = last.domain ?? ""
            password = p
            savedPassword = true
        } else {
            offers = await LoginResolver.resolve(connection, library: library, credentials: credentials, sessions: sessions, passwordsOnly: true)
            var own: RdpSavedLogin?
            do {
                // The connection's own password keeps its own path (no vault credential is named).
                if autoConnect, connection.inlineCredential != nil { own = try credentials.vault?.rdpLoginFor(library: library, connectionId: connection.id, credentialId: nil) }
            } catch {
                self.error = errorText(error)
                return
            }
            if let own {
                (domain, username) = RdpAccount.split(own.username, domain: domain)
                password = own.password
                savedPassword = true
            } else if case .vault(let id)? = last?.login, offers.contains(where: { $0.credentialId == id }) {
                // Confirmed earlier in this run.
                selectedLogin = id
            } else if let first = offers.first {
                selectedLogin = first.credentialId
                guard first.autoUse else { return }
            } else {
                return
            }
        }
        guard autoConnect, selectedOffer != nil || !username.isEmpty, gateway?.ready != false else { return }
        autoConnecting = true
        await connect()
    }

    /// The offered login's password, released by the core for this connection only now that the
    /// user (or the connection's own setting) chose it. nil: the error is shown.
    private func releaseSelected(_ offer: LoginOffer) -> (user: String, domain: String, password: String)? {
        guard let library = model.library, let vault = credentials.vault else {
            error = "Saved logins are locked. Type a username and password, or unlock them in Credentials."
            return nil
        }
        do {
            let saved = try vault.releaseLogin(library: library, connectionId: connection.id, credentialId: offer.credentialId)
            let (domain, user) = RdpAccount.split(saved.username, domain: "")
            let name = user.isEmpty ? (connection.effectiveUsername ?? connection.username ?? "") : user
            guard !name.isEmpty else {
                error = "The saved login “\(offer.name)” has no username. Type a username and password."
                return nil
            }
            return (name, domain, saved.password)
        } catch {
            self.error = errorText(error)
            return nil
        }
    }

    private func connect() async {
        busy = true
        error = nil
        var via: UInt16?
        switch await gateway?.open(sessions: sessions, library: model.library, connectionId: connection.id) ?? .direct {
        case .direct: break
        case .via(let port): via = port
        case .needsTrust: busy = false; return
        case .failed(let message): busy = false; error = message; return
        }
        let offer = selectedOffer
        var login = (user: username, domain: domain, password: password)
        if let offer {
            guard let released = releaseSelected(offer) else { busy = false; autoConnecting = false; return }
            login = released
        }
        let target = sessions.rdpTarget(connection, library: model.library, username: login.user, domain: login.domain,
                                        trustedFingerprint: accepted ?? pins.pin(pinKey), via: via)
        let result = await sessions.connectRdp(target: target, password: login.password)
        busy = false
        switch result {
        case .connected: sessions.recordOutcome(connection.id, user: login.user, failure: nil)
        case .failed(let message): sessions.recordOutcome(connection.id, user: login.user, failure: message)
        case .unknownCertificate: break
        }
        switch result {
        case .connected(let session):
            if let offer {
                // The core hands the password out again next time; nothing is copied here. A login
                // saved for another connection joins this one when asked, else it stays confirmed
                // for this run (by id), so Reconnect goes straight through.
                if !offer.autoUse {
                    if keepLogin {
                        LoginResolver.keep(offer.credentialId, for: connection, model: model, credentials: credentials)
                    } else {
                        credentials.remember(RememberedLogin(username: login.user, login: .vault(credentialId: offer.credentialId)), for: connection.id)
                    }
                }
            } else {
                credentials.remember(RememberedLogin(username: username, login: .password(password: password), domain: domain.isEmpty ? nil : domain), for: connection.id)
                if !savedPassword { await rememberAnswer() }
            }
            if let accepted {
                do { try pins.save(pinKey, fingerprint: accepted) } catch { sessions.error = "Could not store the certificate pin: \(error)" }
            }
            let tab = TerminalTab(name: connection.name, content: .rdp(session), connectionId: connection.id)
            tab.gatewayRoute = gateway?.handOff()
            sessions.add(tab)
            password = ""
            dismiss()
        case .unknownCertificate(let fingerprint):
            autoConnecting = false
            pending = fingerprint
        case .failed(let message):
            error = message
            if savedPassword || offer != nil {
                credentials.forgetLastLogin(for: connection.id)
                savedPassword = false
            }
        }
    }

    /// A password typed here becomes the connection's own secret, so the next open goes straight
    /// through (owner points 23 and 26). Stored as DOMAIN\\user when a domain was given.
    private func rememberAnswer() async {
        guard !password.isEmpty, model.library != nil else { return }
        if credentials.vaultForSave() == nil { await credentials.openInBackground(sessions: sessions) }
        guard let vault = credentials.vaultForSave() ?? credentials.vault else {
            sessions.error = "\(connection.name): signed in, but saved logins are locked, so this login was not remembered."
            return
        }
        let account = domain.isEmpty ? username : "\(domain)\\\(username)"
        do {
            try vault.setInlinePassword(connectionId: connection.id, username: account, password: password)
            try vault.save()
            model.mutate { try $0.setInlineMarker(connectionId: connection.id, kind: "password") }
        } catch {
            sessions.error = "\(connection.name): signed in, but the login was not remembered: \(errorText(error))"
        }
    }
}

/// `DOMAIN\user` in a saved login becomes the Domain and User fields; a typed domain wins.
enum RdpAccount {
    static func split(_ account: String, domain: String) -> (domain: String, user: String) {
        guard domain.isEmpty, let slash = account.firstIndex(of: "\\") else { return (domain, account) }
        return (String(account[..<slash]), String(account[account.index(after: slash)...]))
    }
}

private struct PendingCertificate: Identifiable {
    let value: String
    var id: String { value }
}

/// Codex R05: the managed policy can only add the NLA requirement (as Tauri `rdp.rs`).
enum RdpNla {
    static func required(connection: Bool) -> Bool { connection || policyState().requireRdpNla }

}
