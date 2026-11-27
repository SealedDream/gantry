import Foundation

/// The words on the connection page's login line and the session status line (UI-04). Pure, so
/// `tests/connection-summary` checks them without the app. No secret ever reaches these.
enum ConnectionSummary {
    /// Where the login a connect will use comes from, as the core ranks it (`LoginOffer`).
    enum LoginState: Equatable {
        /// The core's best offer: its username, `source` and `sourceName`, and whether it connects without asking.
        case offer(user: String, source: String, sourceName: String, autoUse: Bool)
        /// A secret saved inline on the connection.
        case inline(user: String)
        /// A login is assigned but the vault is locked, so which one is unknown until it opens.
        case locked(user: String)
        case none
    }

    /// "Signs in as admin · from folder Customer A". One line.
    static func loginLine(_ state: LoginState) -> String {
        switch state {
        case .none:
            return "No login saved"
        case .locked(let user):
            return signsInAs(user) + "Credentials locked"
        case .inline(let user):
            return signsInAs(user) + "Saved for this connection"
        case let .offer(user, source, sourceName, autoUse):
            let origin: String
            switch source {
            case _ where !autoUse: origin = sourceName.isEmpty ? "Offered" : "Offered from \(sourceName)"
            case "inherited": origin = sourceName.isEmpty ? "From a folder" : "From folder \(sourceName)"
            case "named": origin = "Named by this connection"
            default: origin = "Saved for this connection"
            }
            return signsInAs(user) + origin
        }
    }

    private static func signsInAs(_ user: String) -> String {
        user.isEmpty ? "" : "Signs in as \(user) · "
    }

    /// "SSH · key", "RDP · password": the protocol and how it authenticates, when known.
    static func security(protocolName: String, loginKind: String?) -> String {
        let proto = protocolName.uppercased()
        switch loginKind {
        case "ssh-key": return "\(proto) · key"
        case "password": return "\(proto) · password"
        default: return proto
        }
    }

    /// The status line under a session: "Name (address) · user · SSH · key · Reconnecting · Logging".
    static func statusLine(name: String, address: String, user: String?, security: String,
                           state: String?, logging: Bool) -> String {
        var parts = ["\(name) (\(address))"]
        if let user, !user.isEmpty { parts.append(user) }
        parts.append(security)
        if let state, !state.isEmpty { parts.append(state) }
        if logging { parts.append("Logging") }
        return parts.joined(separator: " · ")
    }

    /// History fallback before the activity store: "OK", an error line, or nil before the first try.
    static func lastResult(_ result: String?) -> String {
        guard let result, !result.isEmpty else { return "None yet" }
        return result
    }
}
