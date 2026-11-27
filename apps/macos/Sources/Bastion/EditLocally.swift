import AppKit
import BastionCore

/// "Edit Locally" and "Follow Terminal Folder" for one files view (core `filepanel`, #149).
/// Edit: the file downloads into an owner-only folder, opens in its default app, and every save
/// (size + SHA-256 change, polled once a second) queues an upload that replaces the remote file.
@MainActor
final class EditLocallyRunner: ObservableObject {
    /// Seconds between polls of the edited copies and of the terminal's folder.
    static let pollInterval: Duration = .seconds(1)
    static weak var active: EditLocallyRunner?

    @Published private(set) var watched: [EditCopyView] = []
    @Published var error: String?
    /// Uploads saved copies; set by the files view.
    var upload: ((URL, String) -> Void)?

    private let model: EditLocalModel?
    private var timer: Task<Void, Never>?

    init() {
        do { model = try EditLocalModel(base: LibraryModel.dataDir.path, session: UUID().uuidString.lowercased()) }
        catch { model = nil; self.error = "Edit Locally is unavailable: \(error)" }
    }

    deinit { timer?.cancel() }

    /// Download `remote` with `browser`, watch it, and open it. `open: false` skips the app (driver).
    func edit(remote: String, with browser: FilesBrowser, open: Bool = true) {
        guard let model else { return }
        Task {
            let result = await Task.detached { () -> Result<String, Error> in
                Result {
                    let local = try model.localPath(remote: remote)
                    _ = try browser.download(remote: remote, local: local, overwrite: true)
                    try model.watch(local: local, remote: remote)
                    return local
                }
            }.value
            switch result {
            case .success(let local):
                error = nil
                watched = model.watched()
                if open { NSWorkspace.shared.open(URL(fileURLWithPath: local)) }
                startPolling()
            case .failure(let e):
                error = "Could not edit \((remote as NSString).lastPathComponent): \(e)"
            }
        }
    }

    func stop(_ local: String) {
        _ = model?.unwatch(local: local)
        watched = model?.watched() ?? []
    }

    private func startPolling() {
        guard timer == nil else { return }
        timer = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: Self.pollInterval)
                self?.pollOnce()
            }
        }
    }

    private func pollOnce() {
        guard let model else { return }
        let poll = model.poll()
        for copy in poll.changed { upload?(URL(fileURLWithPath: copy.local), (copy.remote as NSString).deletingLastPathComponent) }
        if !poll.gone.isEmpty || !poll.changed.isEmpty { watched = model.watched() }
    }
}

/// The remote folder the terminal is in (OSC 7), for "Follow Terminal Folder".
@MainActor
enum TerminalFolder {
    static let followKey = "bastion.files.follow"

    static func current(of tab: TerminalTab?) -> String? {
        guard let tab, let root = tab.root else { return nil }
        let pane = root.leaves.first { $0.id == tab.focusedPane } ?? root.leaves.first
        return pane?.terminal.cwd()
    }
}
