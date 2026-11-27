import Foundation
import BastionCore

/// Mosh transport (core `remoteshell`): an SSH connection whose effective Connection › Transport is
/// Mosh opens the local `mosh` client in a terminal tab, with no sign-in sheet (Mosh logs in with
/// SSH keys or the agent). tmux attach needs nothing here: the core adds it to both the SSH shell
/// and the Mosh command line when Terminal › tmux is "Attach or create".
enum MoshTransport {
    static let property = "ssh.transport"
    static let mosh = "mosh"

    @MainActor static func uses(_ c: ConnectionView, library: Library) -> Bool {
        guard c.protocol == "ssh" else { return false }
        let values = (try? library.propertyValues(id: c.id)) ?? []
        return values.first { $0.key == property }?.effective == mosh
    }
}

extension SessionsModel {
    /// Start Mosh for a saved SSH connection. The core refuses gateways, jump hosts and a missing
    /// `mosh` client with a reason, shown as the session error.
    func openMosh(connection: ConnectionView, library: Library) {
        do {
            let t = try Terminal.moshConnection(library: library, connectionId: connection.id, cols: 80, rows: 24)
            add(TerminalTab(name: connection.name, content: .terminal(t), connectionId: connection.id))
            recordOutcome(connection.id, user: nil, failure: nil)
        } catch {
            let reason = "Could not start Mosh for \(connection.name): \(errorText(error))"
            self.error = reason
            recordOutcome(connection.id, user: nil, failure: reason)
        }
    }
}
