import Foundation

/// A jump host as the core resolves it for a saved connection (`SessionManager.jumpHosts`):
/// its `host:port` key and the user it signs in as.
struct SavedHop: Equatable {
    let key: String
    let username: String
}

/// One jump host Test Connection dials.
struct TestRouteHop: Equatable {
    let host: String
    let port: UInt16
    let username: String

    init(host: String, port: UInt16, username: String) {
        self.host = host
        self.port = port
        self.username = username
    }

    /// From a `host:port` key, split at the last colon (IPv6 hosts hold colons too).
    init?(key: String, username: String) {
        guard let colon = key.lastIndex(of: ":"), let port = UInt16(key[key.index(after: colon)...]) else { return nil }
        var host = String(key[..<colon])
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        guard !host.isEmpty else { return nil }
        self.init(host: host, port: port, username: username)
    }
}

/// A1-NM-01: the jump hosts of a test, so a saved login is tested over the route a real connect
/// dials. The saved chain comes from the core (a shared gateway first, then the SSH config's
/// ProxyJump hops). Only the gateway can be changed in the dialog: when it is, the dialog's
/// gateway replaces the saved one ahead of the same ProxyJump hops. The core still decides: a
/// saved login goes only over the saved route; an edited one needs a typed password.
enum TestConnectionRoute {
    static func hops(saved: [SavedHop], savedGatewayId: String, dialogGatewayId: String, dialogGateway: TestRouteHop?) -> [TestRouteHop] {
        let chain = saved.compactMap { TestRouteHop(key: $0.key, username: $0.username) }
        if dialogGatewayId == savedGatewayId { return chain }
        let proxyJumps = savedGatewayId.isEmpty ? chain : Array(chain.dropFirst())
        return (dialogGateway.map { [$0] } ?? []) + proxyJumps
    }
}
