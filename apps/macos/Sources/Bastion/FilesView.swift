import AppKit
import SwiftUI
import UniformTypeIdentifiers
import BastionCore

/// SFTP browser for one session: navigate, upload, download, rename, new folder. Files and folders
/// can be dropped in from Finder and dragged out to it; folders copy recursively through the
/// transfer queue. Every call runs off the main thread; failures are shown inline and never ignored.
struct FilesView: View {
    let browser: FilesBrowser
    /// The SSH tab beside a docked panel; enables "Follow Terminal Folder". Nil for files tabs.
    let tab: TerminalTab?
    @StateObject private var queue: TransferQueueRunner
    @StateObject private var editor = EditLocallyRunner()
    @AppStorage(TerminalFolder.followKey) private var follow = false

    init(browser: FilesBrowser, tab: TerminalTab? = nil) {
        self.browser = browser
        self.tab = tab
        _queue = StateObject(wrappedValue: TransferQueueRunner(browser: browser))
    }
    @State private var path = ""
    @State private var entries: [RemoteFile] = []
    @State private var selection: Set<String> = []
    @State private var dropTargeted = false
    @State private var busy = false
    @State private var status: String?
    @State private var isError = false
    @State private var renaming: RemoteFile?
    @State private var newName = ""
    @State private var creatingFolder = false
    @State private var editing: RemoteEditDocument?

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            table
            if !queue.jobs.isEmpty {
                Divider()
                TransferQueueView(runner: queue)
            }
            if let error = queue.queueError ?? editor.error {
                Divider()
                Text(error).font(DS.Font.caption).foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 10).padding(.vertical, 4)
            }
            if let status {
                Divider()
                Text(status).font(DS.Font.caption).foregroundStyle(isError ? .red : .secondary)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 10).padding(.vertical, 4)
            }
        }
        .onAppear {
            TransferQueueRunner.active = queue
            EditLocallyRunner.active = editor
            queue.onJobEnded = { navigate(to: path) }
            editor.upload = { [queue] url, dir in queue.upload([url], into: dir, rule: "replace") }
        }
        .task(id: follow && tab != nil) { await followTerminal() }
        .task { if path.isEmpty { await run { let h = try browser.home(); return (h, try browser.list(path: h)) } } }
        .onReceive(NotificationCenter.default.publisher(for: .filesRefresh)) { _ in navigate(to: path) }
        .onReceive(NotificationCenter.default.publisher(for: .filesDrop)) { n in
            if let urls = n.object as? [URL] { upload(urls) }
        }
        .onReceive(NotificationCenter.default.publisher(for: .filesExport)) { n in
            if let (names, dir) = n.object as? ([String], URL) { download(entries.filter { names.contains($0.name) }, into: dir) }
        }
        .sheet(item: $editing) { RemoteEditorSheet(doc: $0) }
        .alert("Rename", isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
            TextField("New name", text: $newName)
            Button("Rename") { if let f = renaming { rename(f, to: newName) } }
            Button("Cancel", role: .cancel) {}
        }
        .alert("New Folder", isPresented: $creatingFolder) {
            TextField("Name", text: $newName)
            Button("Create") { makeFolder(newName) }
            Button("Cancel", role: .cancel) {}
        }
    }

    private var toolbar: some View {
        HStack(spacing: 8) {
            Button("Up", systemImage: "chevron.up") { navigate(to: parent(of: path)) }
                .disabled(path == "/" || path.isEmpty)
                .iconTip("Up")
            Text(path).font(DS.Font.style(.body, design: .monospaced)).lineLimit(1).truncationMode(.head)
            Spacer()
            if busy { ProgressView().controlSize(.small) }
            if tab != nil {
                Toggle(isOn: $follow) { Label("Follow Terminal Folder", systemImage: "location") }
                    .toggleStyle(.button)
                    .iconTip("Follow Terminal Folder")
            }
            Button("Refresh", systemImage: "arrow.clockwise") { navigate(to: path) }
                .iconTip("Refresh")
                .background(DriverFrame(name: "sftp-refresh"))
            Button("New Folder", systemImage: "folder.badge.plus") { newName = ""; creatingFolder = true }
                .iconTip("New Folder")
            Button("Upload", systemImage: "square.and.arrow.up", action: chooseUpload)
                .iconTip("Upload")
            Button("Download", systemImage: "square.and.arrow.down", action: chooseDownload)
                .disabled(selectedFiles.isEmpty)
                .iconTip("Download")
                .background(DriverFrame(name: "sftp-download"))
            Button("Edit", systemImage: "square.and.pencil") { if let f = selectedFile { edit(f) } }
                .disabled(selectedFile.map { $0.kind != "file" } ?? true)
                .iconTip("Edit this text file on the server")
            Menu {
                Button("Rename…", systemImage: "pencil") {
                    if let f = selectedFile { newName = f.name; renaming = f }
                }
                .disabled(selectedFile == nil)
            } label: {
                Label("More", systemImage: "ellipsis")
            }
            .menuIndicator(.hidden)
            .menuStyle(.borderlessButton)
            .fixedSize()
            .iconTip("More: Rename")
            .accessibilityIdentifier("sftp-more")
        }
        .disabled(busy)
        .labelStyle(.iconHitTarget)
        .buttonStyle(.borderless)
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
    }

    private var table: some View {
        Table(entries, selection: $selection) {
            TableColumn("Name") { (f: RemoteFile) in
                Label(f.name, systemImage: icon(f))
                    .onDrag { dragOut(f) }
            }
            TableColumn("Size") { (f: RemoteFile) in
                Text(sizeText(f)).foregroundStyle(.secondary)
            }
            .width(90)
            TableColumn("Modified") { (f: RemoteFile) in
                Text(dateText(f)).foregroundStyle(.secondary)
            }
            .width(150)
        }
        .contextMenu(forSelectionType: String.self) { names in
            if names.count == 1, let f = entries.first(where: { $0.id == names.first }), f.kind != "dir" {
                if f.kind == "file" { Button("Edit") { edit(f) } }
                Button("Edit Locally") { editor.edit(remote: remotePath(path, f.name), with: browser) }
            }
            if names.count == 1, let f = entries.first(where: { $0.id == names.first }) {
                Button("Rename…") { newName = f.name; renaming = f }
            }
        } primaryAction: { names in
            guard let name = names.first, let f = entries.first(where: { $0.id == name }) else { return }
            if f.kind == "dir" { navigate(to: remotePath(path, f.name)) } else if f.kind == "file" { edit(f) }
        }
        .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
            dropIn(providers)
            return true
        }
        .overlay {
            if dropTargeted { RoundedRectangle(cornerRadius: 4).stroke(Color.accentColor, lineWidth: 2).allowsHitTesting(false) }
        }
    }

    private func edit(_ f: RemoteFile) {
        editing = RemoteEditDocument(browser: browser, path: remotePath(path, f.name))
    }

    private func bytes(_ n: UInt64) -> String { ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file) }

    private var selectedFiles: [RemoteFile] { entries.filter { selection.contains($0.id) } }
    /// The one selected entry, for Rename.
    private var selectedFile: RemoteFile? { selection.count == 1 ? selectedFiles.first : nil }

    private func icon(_ f: RemoteFile) -> String {
        switch f.kind {
        case "dir": return "folder"
        case "symlink": return "arrow.turn.up.right"
        default: return "doc"
        }
    }

    private func sizeText(_ f: RemoteFile) -> String {
        f.kind == "dir" ? "—" : ByteCountFormatter.string(fromByteCount: Int64(f.size), countStyle: .file)
    }

    private func dateText(_ f: RemoteFile) -> String {
        guard let m = f.modified else { return "" }
        return Date(timeIntervalSince1970: TimeInterval(m)).formatted(date: .abbreviated, time: .shortened)
    }

    // MARK: Actions

    private func navigate(to target: String) {
        Task { await run { (target, try browser.list(path: target)) } }
    }

    /// While following, open the terminal's folder (OSC 7) whenever it changes.
    private func followTerminal() async {
        guard follow, tab != nil else { return }
        while !Task.isCancelled {
            if let dir = TerminalFolder.current(of: tab), dir != path, !busy { navigate(to: dir) }
            try? await Task.sleep(for: EditLocallyRunner.pollInterval)
        }
    }

    private func chooseUpload() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        guard panel.runModal() == .OK else { return }
        upload(panel.urls)
    }

    private func chooseDownload() {
        let picked = selectedFiles
        guard !picked.isEmpty else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.prompt = "Download Here"
        guard panel.runModal() == .OK, let dir = panel.url else { return }
        download(picked, into: dir)
    }

    /// Files and folders dropped from Finder.
    private func dropIn(_ providers: [NSItemProvider]) {
        Task {
            var urls: [URL] = []
            for provider in providers {
                if let url = await fileURL(from: provider) { urls.append(url) }
            }
            if !urls.isEmpty { upload(urls) }
        }
    }

    private func fileURL(from provider: NSItemProvider) async -> URL? {
        await withCheckedContinuation { cont in
            _ = provider.loadObject(ofClass: URL.self) { url, _ in cont.resume(returning: url) }
        }
    }

    /// Dragging a row to Finder: the file (or folder, recursively) downloads into a temporary folder
    /// that Finder then copies from. Folders are offered as folders so Finder keeps their structure.
    private func dragOut(_ f: RemoteFile) -> NSItemProvider {
        let provider = NSItemProvider()
        provider.suggestedName = f.name
        let type: UTType = f.kind == "dir" ? .folder : .data
        let dir = path
        let b = browser
        provider.registerFileRepresentation(forTypeIdentifier: type.identifier, fileOptions: [], visibility: .all) { done in
            let staging = FileManager.default.temporaryDirectory.appendingPathComponent("bastion-drag-\(UUID().uuidString)")
            Task.detached {
                do {
                    try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)
                    let plan = try FileTransfers.planDownload([f], from: dir, into: staging, with: b)
                    try FileTransfers.download(plan, with: b) { _ in }
                    done(staging.appendingPathComponent(f.name), false, nil)
                } catch {
                    done(nil, false, error)
                    await MainActor.run { report("\(error)") }
                }
            }
            return nil
        }
        return provider
    }

    /// Finder drops, Upload and the driver queue every file; the transfer list shows each one.
    private func upload(_ urls: [URL]) {
        queue.upload(urls, into: path)
    }

    private func download(_ picked: [RemoteFile], into localDir: URL) {
        queue.download(picked, from: path, into: localDir)
    }

    private func rename(_ f: RemoteFile, to name: String) {
        guard isValidName(name) else { return report("A name cannot be empty or contain “/”.") }
        let dir = path
        Task {
            await run(done: "Renamed \(f.name) to \(name)") {
                try browser.rename(from: remotePath(dir, f.name), to: remotePath(dir, name))
                return (dir, try browser.list(path: dir))
            }
        }
    }

    private func makeFolder(_ name: String) {
        guard isValidName(name) else { return report("A name cannot be empty or contain “/”.") }
        let dir = path
        Task {
            await run(done: "Created \(name)") {
                try browser.mkdir(path: remotePath(dir, name))
                return (dir, try browser.list(path: dir))
            }
        }
    }

    /// Runs a blocking SFTP call off the main thread, then shows the resulting directory.
    private func run(done: String? = nil, _ work: @escaping @Sendable () throws -> (String, [RemoteFile])) async {
        busy = true
        let reconnectsBefore = browser.reconnects()
        let result = await Task.detached { Result { try work() } }.value
        busy = false
        switch result {
        case .success(let (dir, list)):
            path = dir
            entries = list
            selection = []
            // With "Reconnect automatically" the browser redials on the next call after a drop.
            let reconnected = browser.reconnects() > reconnectsBefore
            status = reconnected ? [done, "Reconnected after the connection dropped."].compactMap { $0 }.joined(separator: ". ") : done
            isError = false
        case .failure(let error):
            report((error as? FileTransfers.TransferError)?.errorDescription ?? "\(error)")
        }
    }

    private func report(_ message: String) {
        status = message
        isError = true
    }

    private func isValidName(_ s: String) -> Bool { !s.isEmpty && !s.contains("/") && s != "." && s != ".." }
    private func parent(of p: String) -> String {
        let up = (p as NSString).deletingLastPathComponent
        return up.isEmpty ? "/" : up
    }
}

private func remotePath(_ dir: String, _ name: String) -> String { joinRemote(dir, name) }

extension Notification.Name {
    /// Refresh the open SFTP browsers (UI driver).
    static let filesRefresh = Notification.Name("BastionFilesRefresh")
    /// Upload these local URLs into the open folder, as a Finder drop does (UI driver).
    static let filesDrop = Notification.Name("BastionFilesDrop")
    /// Download `([names], folder URL)` from the open folder, as Download does (UI driver).
    static let filesExport = Notification.Name("BastionFilesExport")
}

extension RemoteFile: Identifiable {
    public var id: String { name }
}
