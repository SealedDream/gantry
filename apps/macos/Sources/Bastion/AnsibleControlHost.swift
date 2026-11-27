import Foundation
import BastionCore

/// Ansible on a control host: connect the chosen SSH connection as usual (vault login, host-key
/// rules), then over SFTP on that session make the run folder, upload the inventory and playbook,
/// and type the one-line command the core planned (`ansibleRemotePlan`). The command checks that
/// Ansible exists, runs it, and removes the run folder.
@MainActor enum AnsibleControlHost {
    /// How long a pending run waits for its connect (a login sheet the user leaves open).
    static let connectWait: TimeInterval = 300

    private static var key: String { "ansibleControlHost." + LibraryModel.libraryPath.path }

    /// The control host last used with this library.
    static var remembered: String? {
        get { UserDefaults.standard.string(forKey: key) }
        set { UserDefaults.standard.set(newValue, forKey: key) }
    }

    /// 16 lowercase hex characters, unique per run.
    nonisolated static func newRunId() -> String { String(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased().prefix(16)) }

    /// Connect `host` and run once its terminal is up.
    static func start(_ input: AnsibleRunInput, uploadFolder: Bool, host: ConnectionView, commands: Commands, sessions: SessionsModel) {
        remembered = host.id
        let runId = newRunId()
        commands.afterConnect[host.id] = (Date().addingTimeInterval(connectWait), { tab in
            guard let terminal = tab.terminal else { return }
            run(input, uploadFolder: uploadFolder, runId: runId, on: terminal, host: host.name, sessions: sessions)
        })
        commands.requestConnect(host, .terminal)
    }

    private static func run(_ input: AnsibleRunInput, uploadFolder: Bool, runId: String, on terminal: Terminal, host: String, sessions: SessionsModel) {
        Task.detached {
            var made: (FilesBrowser, String)?
            do {
                let sftp = try terminal.openSftp()
                let home = try sftp.home()
                let plan = try ansibleRemotePlan(input: input, home: home, runId: runId, uploadFolder: uploadFolder)
                made = (sftp, plan.dir)
                for dir in plan.dirs { try sftp.mkdir(path: dir) }
                for u in plan.uploads { _ = try sftp.upload(local: u.local, remote: u.remote, overwrite: false) }
                try terminal.write(bytes: Data((plan.command + "\r").utf8))
            } catch {
                if let (sftp, dir) = made { _ = try? sftp.remove(path: dir, isDir: true) }
                let text = errorText(error)
                await MainActor.run { sessions.error = "Ansible on \(host): \(text)" }
            }
        }
    }
}

extension Commands {
    /// A pending control-host run for this connection, if it has not expired.
    func runAfterConnect(_ connectionId: String) {
        guard let pending = afterConnect.removeValue(forKey: connectionId), pending.deadline > Date(),
              let tab = sessions.liveTab(for: connectionId) else { return }
        pending.run(tab)
    }
}

/// Where the local `ansible` programs are: PATH plus where pip, pipx and Homebrew put them (a GUI
/// app's PATH is short).
enum AnsibleLocal {
    /// UI driver: a PATH to search instead (proves the "not installed" message).
    @MainActor static var pathOverride: String?

    @MainActor static var searchPath: String {
        if let pathOverride { return pathOverride }
        let extra = ["/opt/homebrew/bin", "/usr/local/bin", "\(NSHomeDirectory())/.local/bin"]
        return (extra + [ProcessInfo.processInfo.environment["PATH"] ?? "/usr/bin:/bin"]).joined(separator: ":")
    }

    /// The full path of `program`, or nil when it is not installed.
    @MainActor static func find(_ program: String, path: String) -> String? {
        path.split(separator: ":").map { "\($0)/\(program)" }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }
}
