import Foundation

// Activity log for the sessions the app drives itself (LOG-RDP-01, Native Mac): RDP, VNC and web
// tabs. SSH, SFTP, SCP and FTPS are recorded by the core's session manager and must not be begun
// here too. Metadata only: no secrets, no keystrokes, no content. Same rules as Native Windows
// (`MainWindow.SessionActivity.cs`, #985 and #1004). Foundation only, so
// `tests/session-activity-test.sh` builds it without the app.

/// What `activity_begin` needs to know about one library connection.
struct SessionActivityStart: Equatable {
    struct Folder: Equatable { let id: String; let name: String }

    let connectionId: String
    let connectionName: String
    /// Root first, library folders only (the core takes UUIDs).
    let folderPath: [Folder]
    let protocolName: String
    let host: String
    let port: Int?
    /// The connection's own username, if it has one.
    let ownUsername: String?
    /// Its username inherited from a folder, used when it has no own one.
    let inheritedUsername: String?

    static let app = "native-mac"

    static func isAppRecorded(_ protocolName: String) -> Bool { ["rdp", "vnc", "web"].contains(protocolName) }

    private static func nonBlank(_ s: String?) -> String? {
        guard let t = s?.trimmingCharacters(in: .whitespaces), !t.isEmpty else { return nil }
        return t
    }

    /// The core refuses a start whose login source is "unknown" (that value is only ever read),
    /// so say where the login came from: VNC asks for a password; the others use the connection's
    /// own user, an inherited one, or ask.
    static func loginSource(_ protocolName: String, ownUsername: String?, inheritedUsername: String?) -> String {
        if protocolName == "vnc" { return "typed" }
        if nonBlank(ownUsername) != nil { return "own" }
        if nonBlank(inheritedUsername) != nil { return "inherited" }
        return "typed"
    }

    /// A web connection's host is a URL: record its host name and a non-default port only.
    static func webTarget(_ url: String) -> (host: String, port: Int?) {
        guard let c = URLComponents(string: url), let host = c.host, !host.isEmpty else { return (url, nil) }
        let defaultPort = c.scheme == "https" ? 443 : c.scheme == "http" ? 80 : nil
        return (host, c.port.flatMap { $0 == defaultPort ? nil : $0 })
    }

    var username: String? {
        protocolName == "vnc" ? nil : Self.nonBlank(ownUsername) ?? Self.nonBlank(inheritedUsername)
    }

    /// The `start_json` for `activity_begin`.
    func json(startedAt: UInt64, appVersion: String, deviceName: String) -> String {
        let (host, port) = protocolName == "web" ? Self.webTarget(self.host) : (self.host, self.port)
        var start: [String: Any] = [
            "connectionId": connectionId, "connectionName": connectionName,
            "folderPath": folderPath.map { ["id": $0.id, "name": $0.name] },
            "protocol": protocolName, "host": host, "route": [String](),
            "loginSource": Self.loginSource(protocolName, ownUsername: ownUsername, inheritedUsername: inheritedUsername),
            "startedAt": startedAt, "app": Self.app, "appVersion": appVersion, "deviceName": deviceName,
        ]
        if let port { start["port"] = port }
        if let username { start["username"] = username }
        return Self.encode(start)
    }

    /// The `end_json` for `activity_end`; `connectedAt` nil for a connect that never opened.
    static func endJSON(connectedAt: UInt64?, endedAt: UInt64, reason: String) -> String {
        var end: [String: Any] = ["endedAt": endedAt, "endReason": reason]
        if let connectedAt { end["connectedAt"] = connectedAt }
        return encode(end)
    }

    private static func encode(_ object: [String: Any]) -> String {
        let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data("{}".utf8)
        return String(decoding: data, as: UTF8.self)
    }

    static func nowMs() -> UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) }
}
