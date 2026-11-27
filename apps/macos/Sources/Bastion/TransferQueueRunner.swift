import Foundation
import BastionCore

/// Runs the file panel's transfer queue (core `TransferQueueModel`) for one SFTP browser: takes the
/// next job when a slot is free, probes the target so the overwrite rule decides before any byte
/// moves, copies with the browser off the main thread, and reports back. Pausing a running file
/// lets that file finish (SFTP copies a file in one call); queued files wait until resumed.
@MainActor
final class TransferQueueRunner: ObservableObject {
    /// Files copied at once.
    static let parallel: UInt32 = 2
    /// The runner of the files view the UI driver acts on.
    static weak var active: TransferQueueRunner?

    @Published private(set) var jobs: [TransferJobView] = []
    @Published private(set) var summary = TransferSummaryView(active: 0, queued: 0, failed: 0, total: 0, done: 0, speed: 0)
    /// The rule new jobs get when their target already exists.
    @Published var rule: String = UserDefaults.standard.string(forKey: ruleKey) ?? "ask" {
        didSet { UserDefaults.standard.set(rule, forKey: Self.ruleKey) }
    }
    /// Called on the main thread after a job ends, so the browser can reload its folder.
    var onJobEnded: (() -> Void)?
    /// The last error that kept files from being queued at all.
    @Published var queueError: String?

    private static let ruleKey = "bastion.transfers.overwrite"
    private let model = TransferQueueModel(parallel: TransferQueueRunner.parallel)
    private let browser: FilesBrowser

    init(browser: FilesBrowser) {
        self.browser = browser
        Self.all.add(self)
    }

    /// Every runner still alive (one per files view), held weakly.
    private static let all = NSHashTable<TransferQueueRunner>.weakObjects()
    /// Files copying or queued across every open files view, for the quit question (CLOSE-01).
    static var runningTransfers: Int {
        all.allObjects.map { Int($0.summary.active) + Int($0.summary.queued) }.reduce(0, +)
    }

    static let rules: [(id: String, title: String)] = [
        ("ask", "Ask"), ("replace", "Replace"), ("replace_if_newer", "Replace if newer"), ("rename", "Keep both"), ("skip", "Skip"),
    ]

    // MARK: Queueing

    /// Queue local files and folders for upload into `remoteDir`; folders are created first.
    /// `rule` overrides the user's overwrite rule (Edit Locally always replaces).
    func upload(_ urls: [URL], into remoteDir: String, rule: String? = nil) {
        enqueue(upload: true, rule: rule) { b in
            let plan = try FileTransfers.planUpload(urls, into: remoteDir, existing: [])
            for folder in plan.folders { try? b.mkdir(path: folder) }
            return plan
        }
    }

    /// Queue remote entries of `remoteDir` for download into `localDir`.
    func download(_ entries: [RemoteFile], from remoteDir: String, into localDir: URL) {
        enqueue(upload: false) { b in
            let plan = try FileTransfers.planDownload(entries, from: remoteDir, into: localDir, with: b, checkExisting: false)
            for folder in plan.folders { try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true) }
            return plan
        }
    }

    private func enqueue(upload: Bool, rule override: String? = nil, _ plan: @escaping @Sendable (FilesBrowser) throws -> FileTransfers.Plan) {
        let b = browser
        let rule = override ?? rule
        Task {
            let result = await Task.detached { Result { try plan(b) } }.value
            switch result {
            case .success(let p):
                queueError = nil
                for item in p.files {
                    do { _ = try model.add(upload: upload, source: item.from, target: item.to, total: item.size, overwrite: rule) }
                    catch { queueError = "\(error)" }
                }
                pump()
            case .failure(let error):
                queueError = (error as? FileTransfers.TransferError)?.errorDescription ?? "\(error)"
            }
        }
    }

    // MARK: Controls

    func pause(_ id: UInt64) { act { try $0.pause(id: id) } }
    func resume(_ id: UInt64) { act { try $0.resume(id: id) } }
    func retry(_ id: UInt64) { act { try $0.retry(id: id) } }
    func cancel(_ id: UInt64) { act { try $0.cancel(id: id) } }
    func answer(_ id: UInt64, rule: String) { act { try $0.answerConflict(id: id, rule: rule) } }
    func clearFinished() { model.clearFinished(); refresh() }

    private func act(_ f: (TransferQueueModel) throws -> Void) {
        do { try f(model) } catch { queueError = "\(error)" }
        pump()
    }

    // MARK: Worker

    private func refresh() {
        jobs = model.jobs()
        summary = model.summary()
    }

    /// Start every job a free slot allows.
    private func pump() {
        while let job = model.startNext() { run(job) }
        refresh()
    }

    private func run(_ job: TransferJobView) {
        let b = browser
        let m = model
        Task {
            await Task.detached { Self.copy(job, browser: b, model: m) }.value
            pump()
            onJobEnded?()
        }
    }

    /// Probe, resolve and copy one job. Every outcome lands in the model.
    nonisolated private static func copy(_ job: TransferJobView, browser: FilesBrowser, model: TransferQueueModel) {
        let upload = job.direction == "upload"
        do {
            let probe = try upload ? remoteProbe(job, browser: browser) : localProbe(job, browser: browser)
            let r = try model.resolve(id: job.id, exists: probe.exists, targetModified: probe.targetModified,
                                      sourceModified: probe.sourceModified, taken: probe.taken)
            guard r.action == "copy" else { return }
            let started = Date()
            let bytes = upload
                ? try browser.upload(local: job.source, remote: r.target, overwrite: r.replace)
                : try browser.download(remote: job.source, local: r.target, overwrite: r.replace)
            if model.jobs().first(where: { $0.id == job.id })?.state == "cancelled" { return }
            try model.progress(id: job.id, done: bytes, elapsedMs: UInt64(max(1, Date().timeIntervalSince(started) * 1000)))
            try model.finish(id: job.id)
        } catch {
            try? model.fail(id: job.id, error: (error as? FfiError).map { "\($0)" } ?? error.localizedDescription)
        }
    }

    private struct Probe { var exists: Bool; var targetModified: Int64?; var sourceModified: Int64?; var taken: [String] }

    nonisolated private static func remoteProbe(_ job: TransferJobView, browser: FilesBrowser) throws -> Probe {
        let dir = (job.target as NSString).deletingLastPathComponent
        let name = (job.target as NSString).lastPathComponent
        let listing = try browser.list(path: dir.isEmpty ? "/" : dir)
        let target = listing.first { $0.name == name }
        let source = try? FileManager.default.attributesOfItem(atPath: job.source)[.modificationDate] as? Date
        return Probe(exists: target != nil, targetModified: target?.modified.map(Int64.init), sourceModified: source.map { Int64($0.timeIntervalSince1970) },
                     taken: listing.map(\.name))
    }

    nonisolated private static func localProbe(_ job: TransferJobView, browser: FilesBrowser) throws -> Probe {
        let fm = FileManager.default
        let dir = (job.target as NSString).deletingLastPathComponent
        let exists = fm.fileExists(atPath: job.target)
        let target = try? fm.attributesOfItem(atPath: job.target)[.modificationDate] as? Date
        let sourceDir = (job.source as NSString).deletingLastPathComponent
        let sourceName = (job.source as NSString).lastPathComponent
        let source = exists ? (try? browser.list(path: sourceDir.isEmpty ? "/" : sourceDir))?.first { $0.name == sourceName }?.modified.map(Int64.init) : nil
        return Probe(exists: exists, targetModified: target.map { Int64($0.timeIntervalSince1970) },
                     sourceModified: source, taken: (try? fm.contentsOfDirectory(atPath: dir)) ?? [])
    }
}
