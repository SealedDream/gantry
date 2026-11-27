import Foundation

/// Web tabs through a saved tunnel (core `web_tunnel_plan`).
@MainActor enum WebTunnels {
    /// Root of the per-tunnel web data folders the core creates and prunes.
    static var dataDir: URL { LibraryModel.dataDir.appendingPathComponent("web-tunnels", isDirectory: true) }

    /// `url` with its host and port replaced by a local forward's `127.0.0.1:PORT`.
    static func url(_ url: URL, through address: String) -> URL? {
        let parts = address.split(separator: ":")
        guard parts.count == 2, let port = Int(parts[1]), var c = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        c.host = String(parts[0])
        c.port = port
        return c.url
    }
}
