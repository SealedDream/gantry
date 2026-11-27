import Foundation
import BastionCore

/// Recursive uploads and downloads for a files tab, built on the browser's one-file calls. A
/// transfer first plans every file (so progress has a total), then copies them in order, creating
/// folders on the way. Calls block, so they run off the main thread.
enum FileTransfers {
    /// One file to copy: where from, where to, how big.
    struct Item: Sendable {
        let from: String
        let to: String
        let size: UInt64
    }

    /// Everything one transfer will do: folders to create first, then files.
    struct Plan: Sendable {
        var folders: [String] = []
        var files: [Item] = []
        var totalBytes: UInt64 { files.reduce(0) { $0 + $1.size } }
    }

    /// Progress reported before and after each file; `bytes` counts finished files only.
    struct Progress: Sendable {
        let filesDone: Int
        let filesTotal: Int
        let bytes: UInt64
        let totalBytes: UInt64
        let current: String
        var fraction: Double {
            totalBytes == 0 ? Double(filesDone) / Double(max(filesTotal, 1)) : Double(bytes) / Double(totalBytes)
        }
    }

    enum TransferError: LocalizedError {
        case exists(String)
        var errorDescription: String? {
            switch self {
            case .exists(let p): return "“\(p)” already exists; nothing was copied."
            }
        }
    }

    // MARK: Upload

    /// Plans copying local files and folders into `remoteDir`. Symlinked folders are skipped so a
    /// loop cannot recurse forever; symlinked files are copied as their target.
    static func planUpload(_ urls: [URL], into remoteDir: String, existing: Set<String>) throws -> Plan {
        var plan = Plan()
        for url in urls {
            let name = url.lastPathComponent
            if existing.contains(name) { throw TransferError.exists(name) }
            try addLocal(url, remote: joinRemote(remoteDir, name), to: &plan)
        }
        return plan
    }

    private static func addLocal(_ url: URL, remote: String, to plan: inout Plan) throws {
        let keys: [URLResourceKey] = [.isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey]
        let values = try url.resourceValues(forKeys: Set(keys))
        if values.isSymbolicLink == true, (try? url.resolvingSymlinksInPath().resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true {
            return
        }
        if values.isDirectory == true {
            plan.folders.append(remote)
            let children = try FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: keys)
            for child in children.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
                try addLocal(child, remote: joinRemote(remote, child.lastPathComponent), to: &plan)
            }
        } else {
            let size = (try? url.resolvingSymlinksInPath().resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? values.fileSize ?? 0
            plan.files.append(Item(from: url.path, to: remote, size: UInt64(size)))
        }
    }

    static func upload(_ plan: Plan, with browser: FilesBrowser, progress: (Progress) -> Void) throws {
        for folder in plan.folders { try browser.mkdir(path: folder) }
        try copy(plan, progress: progress) { try browser.upload(local: $0.from, remote: $0.to, overwrite: false) }
    }

    // MARK: Download

    /// Plans copying remote entries from `remoteDir` into the local folder `localDir`.
    static func planDownload(_ entries: [RemoteFile], from remoteDir: String, into localDir: URL, with browser: FilesBrowser, checkExisting: Bool = true) throws -> Plan {
        var plan = Plan()
        for entry in entries {
            let local = localDir.appendingPathComponent(entry.name)
            if checkExisting && FileManager.default.fileExists(atPath: local.path) { throw TransferError.exists(local.path) }
            try addRemote(entry, remote: joinRemote(remoteDir, entry.name), local: local, with: browser, to: &plan)
        }
        return plan
    }

    private static func addRemote(_ entry: RemoteFile, remote: String, local: URL, with browser: FilesBrowser, to plan: inout Plan) throws {
        switch entry.kind {
        case "dir":
            plan.folders.append(local.path)
            let children = try browser.list(path: remote).filter { $0.name != "." && $0.name != ".." }
            for child in children.sorted(by: { $0.name < $1.name }) {
                try addRemote(child, remote: joinRemote(remote, child.name), local: local.appendingPathComponent(child.name), with: browser, to: &plan)
            }
        case "file", "symlink":
            plan.files.append(Item(from: remote, to: local.path, size: entry.size))
        default:
            return // devices, sockets: nothing to copy
        }
    }

    static func download(_ plan: Plan, with browser: FilesBrowser, progress: (Progress) -> Void) throws {
        for folder in plan.folders {
            try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true)
        }
        try copy(plan, progress: progress) { try browser.download(remote: $0.from, local: $0.to, overwrite: false) }
    }

    // MARK: Shared

    private static func copy(_ plan: Plan, progress: (Progress) -> Void, one: (Item) throws -> UInt64) throws {
        let total = plan.totalBytes
        var bytes: UInt64 = 0
        for (i, item) in plan.files.enumerated() {
            let name = (item.from as NSString).lastPathComponent
            progress(Progress(filesDone: i, filesTotal: plan.files.count, bytes: bytes, totalBytes: total, current: name))
            bytes += try one(item)
        }
        progress(Progress(filesDone: plan.files.count, filesTotal: plan.files.count, bytes: bytes, totalBytes: total, current: ""))
    }
}

/// `dir/name` on the server, which always uses `/`.
func joinRemote(_ dir: String, _ name: String) -> String { dir.hasSuffix("/") ? dir + name : dir + "/" + name }
