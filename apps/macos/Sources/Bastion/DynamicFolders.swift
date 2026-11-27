import AppKit
import BastionCore

/// One generated row under a dynamic folder: an item the task printed, a sub-folder it named, or
/// a status row (a failure, or the count of skipped entries). Never saved (C8).
struct DynamicRow: Equatable {
    enum Kind: Equatable { case item(protocolName: String), group, status }
    let rowId: String
    let title: String
    /// The row's tooltip: the address of an item, or the full error text of a status row.
    let tip: String
    let kind: Kind
    /// Quick Connect address of an item; nil for groups and status rows.
    let address: String?
    var children: [DynamicRow] = []
}

/// Generated rows by folder id, as the outline builds them. Compared by value on each update.
struct DynamicRows: Equatable {
    var byFolder: [String: [DynamicRow]] = [:]
    func rows(for folderId: String) -> [DynamicRow] { byFolder[folderId] ?? [] }
}

/// B15 dynamic folders (core #1166, review #1126) on Native Mac. A folder bound to a saved local
/// task shows the items the task prints after the user clicks Refresh. Manual only (C11): nothing
/// runs on open, start-up, expand or a timer. The first Refresh of a task asks for trust on a sheet
/// that shows exactly what runs; Trust and Run trusts that review's hash (C1, H1). Generated rows
/// are not in the document (C8): opening one fills Quick Connect; Make Permanent copies them in.
/// A managed ban hides every entry (C2). A failure is one row under the folder; its tooltip has the detail.
@MainActor @Observable
final class DynamicFoldersModel {
    /// A finished run, or a refusal (`run` nil, `title` set). `library` is the document it belongs to.
    private struct Result {
        let library: ObjectIdentifier
        let run: DynamicFolderRun?
        let output: DynamicRunView
        var title: String?
    }

    /// The consent sheet's request: the review shown, and the folder to run once trusted.
    struct TrustRequest: Identifiable {
        let folderId: String
        let folderName: String
        let review: DynamicReviewView
        var id: String { folderId + review.sha256 }
    }

    /// The edit sheet's request.
    struct EditRequest: Identifiable {
        let folderId: String
        let folderName: String
        var id: String { folderId }
    }

    static let switchFile = "dynamic-folders-enabled"
    static let skippedShown = 20
    static let pollInterval: TimeInterval = 0.25

    @ObservationIgnored private let model: LibraryModel
    @ObservationIgnored private let sessions: SessionsModel
    @ObservationIgnored private var results: [String: Result] = [:]
    @ObservationIgnored private var running: [String: DynamicFolderRun] = [:]
    @ObservationIgnored private var poll: Timer?
    /// Opens Quick Connect with an address (set by the main window).
    @ObservationIgnored var quickConnect: ((String) -> Void)?
    /// Expands a folder in the tree (set by Commands).
    @ObservationIgnored var expand: ((String) -> Void)?
    /// What the outline shows under each folder.
    private(set) var rows = DynamicRows()
    var editing: EditRequest?
    var trusting: TrustRequest?
    /// The last outcome per folder, for the UI driver: `<state> <items> <skipped>`, `refused`, `revoked`.
    @ObservationIgnored private(set) var lastOutcome: [String: String] = [:]

    init(model: LibraryModel, sessions: SessionsModel) {
        self.model = model
        self.sessions = sessions
    }

    // MARK: Switch and policy

    /// The user's own switch (off by default), kept with this computer's data, never in a document.
    var userEnabled: Bool {
        get { (try? String(contentsOf: Self.switchURL, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) == "1" }
        set {
            if newValue { try? "1".write(to: Self.switchURL, atomically: true, encoding: .utf8) }
            else { try? FileManager.default.removeItem(at: Self.switchURL) }
        }
    }

    private static var switchURL: URL { LibraryModel.dataDir.appendingPathComponent(switchFile) }

    /// False under a managed ban (or an unreadable policy): every entry is hidden.
    var allowed: Bool { dynamicFoldersAllowed() }

    func taskId(of folderId: String) -> String? { (try? model.library?.dynamicFolderTask(folderId: folderId)) ?? nil }
    func isRunning(_ folderId: String) -> Bool { running[folderId] != nil }
    func canMakePermanent(_ folderId: String) -> Bool {
        guard let r = results[folderId], r.run != nil else { return false }
        return r.output.state == "done" && !r.output.items.isEmpty
    }

    // MARK: Menu

    /// The folder menu's entries; none under a managed ban.
    func appendMenu(_ menu: NSMenu, folderId: String, folderName: String) {
        guard allowed else { return }
        menu.addItem(.separator())
        menu.addItem(ClosureMenuItem(title: "Dynamic Folder…") { [weak self] in
            self?.editing = EditRequest(folderId: folderId, folderName: folderName)
        })
        guard taskId(of: folderId) != nil else { return }
        if isRunning(folderId) {
            menu.addItem(ClosureMenuItem(title: "Cancel Refresh") { [weak self] in self?.cancel(folderId) })
        } else {
            menu.addItem(ClosureMenuItem(title: "Refresh") { [weak self] in self?.refresh(folderId: folderId, name: folderName) })
        }
        if canMakePermanent(folderId) {
            menu.addItem(ClosureMenuItem(title: "Make Permanent…") { [weak self] in self?.confirmMakePermanent(folderId: folderId, name: folderName) })
        }
        menu.addItem(ClosureMenuItem(title: "Remove Trust") { [weak self] in self?.revoke(folderId: folderId) })
    }

    // MARK: Edit

    /// Bind a task to the folder (or none), and save the user's switch. The core decides which tasks qualify (C3).
    func save(folderId: String, taskId: String?, enabled: Bool) throws {
        guard let library = model.library else { throw FfiError.Failed(message: "No library is open.", code: "other") }
        userEnabled = enabled
        // Switching off keeps the binding: the core refuses every run while the switch is off.
        if taskId == self.taskId(of: folderId) { return }
        try library.setDynamicFolderTask(folderId: folderId, taskId: taskId, userEnabled: enabled)
        model.mutate { _ in }
        results[folderId] = nil
        publish()
    }

    /// Saved custom local tasks that may feed a folder, as the core lists them.
    func choices() -> [(id: String, name: String)] {
        (model.library?.dynamicFolderTaskChoices() ?? []).compactMap { $0.count == 2 ? ($0[0], $0[1]) : nil }
    }

    // MARK: Refresh

    /// Refresh: the consent sheet first when the task is not trusted, then a background run.
    func refresh(folderId: String, name: String) {
        guard running[folderId] == nil, let library = model.library else { return }
        guard let manager = sessions.manager else { return fail(folderId, "Refresh refused", "The session manager could not start.") }
        do {
            let review = try dynamicFolderReview(manager: manager, library: library, folderId: folderId)
            if review.trusted { return start(folderId: folderId) }
            trusting = TrustRequest(folderId: folderId, folderName: name, review: review)
        } catch {
            fail(folderId, "Refresh refused", errorText(error))
        }
    }

    /// The user's "Trust and Run": trusts exactly the review the sheet showed, then runs.
    func trustAndRun(_ request: TrustRequest) {
        trusting = nil
        guard let library = model.library, let manager = sessions.manager else { return }
        do {
            try dynamicFolderTrust(manager: manager, library: library, folderId: request.folderId,
                                   reviewedSha256: request.review.sha256, userEnabled: userEnabled)
            start(folderId: request.folderId)
        } catch {
            fail(request.folderId, "Trust refused", errorText(error))
        }
    }

    private func start(folderId: String) {
        guard let library = model.library, let manager = sessions.manager else { return }
        do {
            let run = try DynamicFolderRun.start(manager: manager, library: library, folderId: folderId, userEnabled: userEnabled)
            running[folderId] = run
            lastOutcome[folderId] = "running"
            startPolling()
        } catch {
            fail(folderId, "Refresh refused", errorText(error))
        }
    }

    func cancel(_ folderId: String) { running[folderId]?.cancel() }

    private func startPolling() {
        guard poll == nil else { return }
        poll = Timer.scheduledTimer(withTimeInterval: Self.pollInterval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.collect() }
        }
    }

    /// Picks up finished runs; stops polling once none is left.
    private func collect() {
        let library = model.library.map(ObjectIdentifier.init)
        for (folderId, run) in running where run.isFinished() {
            running[folderId] = nil
            let output = run.output()
            results[folderId] = library.map { Result(library: $0, run: run, output: output) }
            lastOutcome[folderId] = "\(output.state) \(output.items.count) \(output.skipped.count)"
            expand?(folderId)
        }
        if running.isEmpty { poll?.invalidate(); poll = nil }
        publish()
    }

    // MARK: Make permanent, revoke

    private func confirmMakePermanent(folderId: String, name: String) {
        guard let r = results[folderId], let run = r.run else { return }
        let n = r.output.items.count
        let alert = NSAlert()
        alert.messageText = "Make Permanent?"
        alert.informativeText = "Add \(n) item\(n == 1 ? "" : "s") to “\(name)” as ordinary connections."
        alert.addButton(withTitle: "Add")
        alert.addButton(withTitle: "Cancel")
        let finish: (NSApplication.ModalResponse) -> Void = { [weak self] response in
            guard response == .alertFirstButtonReturn else { return }
            MainActor.assumeIsolated { self?.makePermanent(folderId: folderId, run: run) }
        }
        if let window = NSApp.windows.first(where: { $0.contentView?.firstSubview(of: KeyOutlineView.self) != nil }) {
            alert.beginSheetModal(for: window, completionHandler: finish)
        } else {
            finish(alert.runModalInFront())
        }
    }

    private func makePermanent(folderId: String, run: DynamicFolderRun) {
        guard let library = model.library else { return }
        do {
            let added = try library.dynamicFolderMakePermanent(folderId: folderId, run: run)
            model.mutate { _ in }
            results[folderId] = nil
            lastOutcome[folderId] = "permanent \(added)"
            publish()
        } catch {
            fail(folderId, "Make Permanent failed", errorText(error))
        }
    }

    private func revoke(folderId: String) {
        guard let library = model.library, let manager = sessions.manager else { return }
        do {
            let removed = try dynamicFolderRevoke(manager: manager, library: library, folderId: folderId)
            lastOutcome[folderId] = removed ? "revoked" : "not-trusted"
        } catch {
            fail(folderId, "Remove Trust failed", errorText(error))
        }
    }

    // MARK: Rows

    /// A refusal or failure: one row under the folder titled `title`, the core's text in its tooltip.
    private func fail(_ folderId: String, _ title: String, _ detail: String) {
        if let library = model.library.map(ObjectIdentifier.init) {
            results[folderId] = Result(library: library, run: nil,
                                       output: DynamicRunView(state: "failed", items: [], skipped: [], error: detail, exit: nil, millis: 0),
                                       title: title)
        }
        lastOutcome[folderId] = "refused"
        expand?(folderId)
        publish()
    }

    /// Rebuilds `rows`; results of another document are dropped.
    func publish() {
        let current = model.library.map(ObjectIdentifier.init)
        results = results.filter { $0.value.library == current }
        var next = DynamicRows()
        for (folderId, r) in results { next.byFolder[folderId] = Self.rows(folderId: folderId, output: r.output, title: r.title) }
        if next != rows { rows = next }
    }

    static func stateText(_ o: DynamicRunView) -> String {
        switch o.state {
        case "timed_out": "Timed out"
        case "cancelled": "Cancelled"
        default: "Refresh failed"
        }
    }

    /// The rows under one folder: generated sub-folders and items, then the skipped count; or one status row.
    static func rows(folderId: String, output o: DynamicRunView, title: String? = nil) -> [DynamicRow] {
        let prefix = "dyn:\(folderId):"
        if o.state != "done" {
            let title = title ?? stateText(o)
            let detail = [o.error, o.exit.map { "Exit code \($0)" }].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: "\n")
            return [DynamicRow(rowId: prefix + "status", title: title, tip: detail.isEmpty ? title : detail, kind: .status, address: nil)]
        }
        var top: [DynamicRow] = []
        for item in o.items {
            let row = DynamicRow(rowId: prefix + item.id, title: item.name, tip: description(item),
                                 kind: .item(protocolName: item.protocol), address: address(item))
            insert(row, path: item.path, prefix: prefix, into: &top)
        }
        if !o.skipped.isEmpty {
            top.append(DynamicRow(rowId: prefix + "skipped", title: "\(o.skipped.count) skipped",
                                  tip: o.skipped.prefix(skippedShown).joined(separator: "\n"), kind: .status, address: nil))
        }
        return top
    }

    /// Puts `row` under the generated sub-folders named by `path`, creating them in order.
    private static func insert(_ row: DynamicRow, path: [String], prefix: String, into rows: inout [DynamicRow], key: String = "") {
        guard let segment = path.first else { return rows.append(row) }
        let groupKey = key + "/" + segment
        let groupId = prefix + groupKey
        let rest = Array(path.dropFirst())
        if let i = rows.firstIndex(where: { $0.rowId == groupId }) {
            insert(row, path: rest, prefix: prefix, into: &rows[i].children, key: groupKey)
        } else {
            var group = DynamicRow(rowId: groupId, title: segment, tip: "Generated folder \(segment)", kind: .group, address: nil)
            insert(row, path: rest, prefix: prefix, into: &group.children, key: groupKey)
            rows.append(group)
        }
    }

    /// One line for the tooltip. Generated, so never saved; never a secret (the core drops secret fields).
    static func description(_ i: GeneratedItemView) -> String {
        let user = i.username.map { $0.isEmpty ? "" : "\($0)@" } ?? ""
        return "Generated \(i.protocol.uppercased()) · \(user)\(i.host)\(i.port.map { ":\($0)" } ?? ""). Double-click opens Quick Connect."
    }

    /// The Quick Connect address: SSH as user@host:port, other types with their scheme.
    static func address(_ i: GeneratedItemView) -> String {
        if i.host.contains("://") { return i.host }
        let scheme: String = switch i.protocol.lowercased() {
        case "ssh": ""
        case "web": "https://"
        case let p: p + "://"
        }
        let user = scheme.isEmpty ? (i.username.map { $0.isEmpty ? "" : "\($0)@" } ?? "") : ""
        return "\(scheme)\(user)\(i.host)\(i.port.map { ":\($0)" } ?? "")"
    }
}
