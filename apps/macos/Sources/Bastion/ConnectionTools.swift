import BastionCore

/// Read-only tools that hang under an SSH (or SSH-managed RDP) connection in the library (owner feedback 11,
/// 2026-11-07): each opens the core's system view over that connection's SSH login.
enum ConnectionTool: String, CaseIterable, Identifiable {
    case services, processes, eventlog

    var id: String { rawValue }
    /// `Commands.run` action id: `tool:<raw value>`.
    static let actionPrefix = "tool:"
    var action: String { Self.actionPrefix + rawValue }

    var label: String {
        switch self {
        case .services: "Services"
        case .processes: "Processes"
        case .eventlog: "Event Log"
        }
    }

    /// Core icon id; `Icons.symbols` maps it.
    var iconId: String { rawValue }

    /// SSH connections, and RDP connections with management via SSH on, carry the tools: the core
    /// reads them over an SSH session (`ConnectionView.hasTools`).
    static func applies(to c: ConnectionView) -> Bool { c.hasTools }

    /// Row id of the tool under connection `connectionId` (never a library id).
    func rowId(for connectionId: String) -> String { "tool:\(rawValue):\(connectionId)" }
}
