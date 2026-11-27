/// How a connect opens a connection, decided from its protocol alone (no core, no UI), so the
/// rule can be tested without the app: `apps/macos/tests/connect-route-test.sh`.

/// Protocols whose connection opens a files tab rather than a terminal.
let fileProtocols: Set<String> = ["sftp", "scp", "ftps"]

/// Connection types whose tab is a read-only system view (`SystemView` in the core).
let systemViewProtocols: Set<String> = ["services", "processes", "eventlog"]

enum ConnectMode: String, Identifiable, Sendable {
    /// `tunnel`: sign in only to start a saved tunnel (Tunnel Manager); no tab opens.
    /// `system`: a Services, Processes or Event Log connection.
    case terminal, files, tunnel, system
    var id: String { rawValue }
    /// Modes the core's open-session sets and workspaces hold (`TabMode`); a system view tab is
    /// reopened from the library instead, and saving one made the whole set invalid.
    var isRestorable: Bool { self == .terminal || self == .files }
}

/// `local`: a local shell tab. `mosh`: the local `mosh` client in a terminal tab, no sign-in
/// sheet. `queue`: the connect queue (sign-in sheet or saved login) in that mode.
enum ConnectRoute: Equatable, Sendable {
    /// `telnet`: its own terminal tab (B7), no sign-in sheet. `unsupported`: a serial entry from an
    /// older library (Serial is Not planned, owner 2026-11-15): it loads, but does not connect.
    case local, mosh, telnet, unsupported, queue(ConnectMode)

    /// The mode a connection of `protocol` opens in.
    static func mode(forProtocol p: String) -> ConnectMode {
        fileProtocols.contains(p) ? .files : systemViewProtocols.contains(p) ? .system : .terminal
    }

    /// `usesMosh`: the connection's effective Connection › Transport is Mosh (`MoshTransport.uses`).
    /// Mosh applies only to an SSH terminal; files, system views and tunnels stay on SSH.
    static func of(protocol p: String, mode: ConnectMode, usesMosh: Bool) -> ConnectRoute {
        if p == "local" { return .local }
        if p == "telnet", mode == .terminal { return .telnet }
        if p == "serial" { return .unsupported }
        if p == "ssh", mode == .terminal, usesMosh { return .mosh }
        return .queue(mode)
    }
}
