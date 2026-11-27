import Foundation
import BastionCore

/// While Bastion's own SSH agent runs, a new Local Shell tab gets its socket in `SSH_AUTH_SOCK`, so
/// `ssh`, `git` and friends in that shell sign with the keys added in View › SSH Agent. The core PTY
/// spawner takes no environment, so the shell starts as `/usr/bin/env SSH_AUTH_SOCK=… <shell> -l`
/// (the same approach as Tauri, #216). `BASTION_SSH_AUTH_SOCK` carries the same path, because a shell
/// profile may export its own agent over ours.
enum LocalShellAgent {
    static let envProgram = "/usr/bin/env"
    static let fallbackShell = "/bin/zsh"

    /// The program and arguments for a local login shell, or nil to use the core's plain login shell.
    static func launch(socket: String?, shell: String?) -> (program: String, args: [String])? {
        guard let socket, !socket.isEmpty else { return nil }
        let login = shell.flatMap { $0.hasPrefix("/") ? $0 : nil } ?? fallbackShell
        return (envProgram, ["SSH_AUTH_SOCK=\(socket)", "BASTION_SSH_AUTH_SOCK=\(socket)", login, "-l"])
    }

    /// The program and arguments to start, read on the main actor (the agent status lives there).
    @MainActor
    static func plan() -> (program: String, args: [String])? {
        let status = AgentKeysModel.shared.status
        return launch(socket: status.running ? status.socket : nil, shell: ProcessInfo.processInfo.environment["SHELL"])
    }

    /// A Local Shell terminal for `plan`: wrapped with the agent socket while the agent runs. Any thread.
    static func terminal(_ plan: (program: String, args: [String])?, cols: UInt16, rows: UInt16) throws -> Terminal {
        guard let (program, args) = plan else { return try Terminal.localShell(cols: cols, rows: rows) }
        return try Terminal.localProgram(program: program, args: args, cols: cols, rows: rows)
    }
}
