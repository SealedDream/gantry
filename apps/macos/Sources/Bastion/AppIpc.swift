import AppKit
import BastionCore

/// Serves the companion CLI (`bastion ping|open`) over the core's local IPC socket: same-user
/// peers only, with this launch's token. Requests name a connection; replies are short status
/// messages and never contain secrets. Opening goes through the normal connect flow, so the
/// user still signs in and confirms host keys in the app.
final class AppIpc: IpcHandler, @unchecked Sendable {
    @MainActor private static var server: IpcServer?
    @MainActor private static var handler: AppIpc?
    @MainActor private weak var commands: Commands?

    @MainActor private init(commands: Commands) { self.commands = commands }

    @MainActor static func start(commands: Commands, dataDir: URL) {
        guard server == nil else { return }
        let h = AppIpc(commands: commands)
        handler = h
        do {
            server = try IpcServer.start(dataDir: dataDir.path, handler: h)
            NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: nil, queue: .main) { _ in
                MainActor.assumeIsolated { server?.stop() }
            }
        } catch {
            // Another instance serves the CLI; this one runs without it.
            NSLog("Gantry: CLI socket not started: %@", "\(error)")
        }
    }

    func openConnection(name: String, files: Bool, protocol kind: String?) -> String? {
        DispatchQueue.main.sync { MainActor.assumeIsolated { self.openOnMain(name: name, files: files, kind: kind) } }
    }

    func openTunnel(name: String) -> String? {
        DispatchQueue.main.sync { MainActor.assumeIsolated { self.tunnelOnMain(name: name) } }
    }

    @MainActor private func tunnelOnMain(name: String) -> String? {
        guard let commands, let lib = commands.model.library else { return "Gantry is shutting down" }
        guard let t = (try? lib.findTunnel(key: name)) ?? nil else { return "no tunnel named \(name)" }
        if commands.sessions.runningTunnels[t.id]?.isRunning() == true { return nil }
        guard let via = commands.model.connection(id: t.viaId) else { return "the tunnel's SSH connection no longer exists" }
        commands.enqueue([ConnectRequest(connection: via, mode: .tunnel, tunnelId: t.id)], select: nil)
        QuietLaunch.activate()
        return nil
    }

    /// `kind` is the protocol filter (`sshp` asks for `ssh`).
    @MainActor private func openOnMain(name: String, files: Bool, kind: String?) -> String? {
        guard let commands else { return "Gantry is shutting down" }
        let matches = Self.connections(in: commands.model.tree).filter { ($0.id == name || $0.name == name) && (kind == nil || $0.protocol == kind) }
        guard let c = matches.first else { return "no \(kind.map { "\($0.uppercased()) " } ?? "")connection named \(name)" }
        if matches.count > 1 { return "\(matches.count) connections are named \(name); use the id (bastion list --json)" }
        if files && !["ssh", "sftp"].contains(c.protocol) { return "\(c.name) is not an SSH connection; --files needs SSH" }
        commands.run(files ? "open-sftp" : "connect", on: c.id)
        QuietLaunch.activate()
        return nil
    }

    @MainActor static func connections(in folder: FolderView?) -> [ConnectionView] {
        guard let folder else { return [] }
        return folder.connections + folder.folders.flatMap { connections(in: $0) }
    }
}
