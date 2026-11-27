import Foundation
import BastionCore

/// How a plugin entry reaches its server (PLUG-08 Mac): direct, or through a saved tunnel to it.
/// A local forward whose destination is the entry's host and port is used for any entry; an entry
/// with a gateway may also use a running SOCKS tunnel. A stopped saved forward is started first,
/// through the usual sign-in; otherwise a gateway entry signs in to its gateway for a forward.
/// The core refuses a gateway entry sent direct.
@MainActor
enum PluginEntryRoute {
    enum Plan {
        case route(PluginRoute)
        /// Start this saved tunnel (its SSH sign-in), then open again.
        case start(TunnelDefView)
        /// A gateway entry with no saved forward: sign in to the gateway for a forward.
        case gateway
    }

    static func plan(for c: ConnectionView, port: UInt16, library: Library, running: [String: RunningTunnel]) -> Plan {
        let gateway = (try? library.pluginEntryGateway(id: c.id)) ?? nil
        let defs = (try? library.tunnels()) ?? []
        let forwards = defs.filter { $0.kind == "local" && $0.port == port && $0.host.caseInsensitiveCompare(c.host) == .orderedSame && $0.localPort != 0 }
        let socks = gateway == nil ? [] : defs.filter { $0.kind == "dynamic" && $0.localPort != 0 }
        let isUp = { (t: TunnelDefView) in running[t.id]?.isRunning() == true }
        if let t = forwards.first(where: isUp) { return .route(.forward(port: t.localPort, target: t.host)) }
        if let t = socks.first(where: isUp) { return .route(.socks(port: t.localPort)) }
        if gateway == nil { return .route(.direct) }
        if let t = forwards.first { return .start(t) }
        // No saved tunnel: sign in to the gateway and forward to the entry (`PluginGatewaySheet`).
        return .gateway
    }
}
