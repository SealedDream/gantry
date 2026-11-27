import AppKit
import BastionCore

/// Connect All and Reconnect All on a folder (B4). The core plans (`plan_connect_all`): which
/// connections have a login of their own (`ready`) and which have none (`needsLogin`). Ready ones
/// go through the normal connect queue, one after another, so hooks, managed policy, wake and the
/// saved-login connect all apply as for a single connect. A needs-login connection is never opened
/// with a login the app picked: it opens only when the user asks, one by one, in the sign-in sheet
/// with its automatic sign-in turned off (`ConnectRequest.askLogin`).
extension Commands {
    /// Connect All on `folderId` (`nil`: the whole library).
    func connectAll(under folderId: String?) {
        Task { @MainActor in await startBulk(under: folderId, reconnecting: nil) }
    }

    /// Reconnect All: ends the folder's open sessions, then connects those same connections by
    /// the same rules as Connect All. Connections without a session are left alone.
    func reconnectAll(under folderId: String?) {
        let open = openConnectionIds.intersection(connectionIdsBelow(folderId))
        guard !open.isEmpty else { return }
        Task { @MainActor in await startBulk(under: folderId, reconnecting: open) }
    }

    private var openConnectionIds: Set<String> { Set(sessions.tabs.filter { !$0.ended }.compactMap(\.connectionId)) }

    private func startBulk(under folderId: String?, reconnecting: Set<String>?) async {
        guard let library = model.library, let credentials else { return }
        await credentials.openInBackground(sessions: sessions)
        guard let vault = credentials.vault else {
            sessions.error = "Connect All needs your saved logins, and they are still locked."
            return
        }
        let plan: BulkConnectPlanView
        do {
            plan = try vault.planConnectAll(library: library, folderId: folderId, openIds: reconnecting == nil ? Array(openConnectionIds) : [])
        } catch {
            sessions.error = "Connect All: \(error)"
            return
        }
        let summary = BulkConnectSummary(plan: plan, only: reconnecting) { [model] in model.connection(id: $0)?.name ?? $0 }
        lastBulkSummary = summary
        guard summary.total > 0 else {
            sessions.error = summary.blocked.isEmpty ? "Nothing to connect in this folder." : "Nothing to connect in this folder.\(summary.blockedText)"
            return
        }
        if plan.needsConfirmation, !(await BulkConnectDialog.confirmStart(summary)) { return }
        if let reconnecting { sessions.disconnect(reconnecting) }
        startReady(summary.ready)
        guard !summary.needsLogin.isEmpty || !summary.blocked.isEmpty else { return }
        if await BulkConnectDialog.showSummary(summary) { openOneByOne(summary.needsLogin) }
    }

    private func startReady(_ ids: [String]) {
        let ready = ids.compactMap(model.connection(id:))
        if let bulkRecorder { return bulkRecorder(ready.map { ConnectRequest(connection: $0, mode: Self.mode(for: $0)) }) }
        let batch = HookBatch()
        ready.forEach { requestConnect($0, Self.mode(for: $0), batch: batch) }
    }

    /// The user asked: each opens in the sign-in sheet, which neither connects on its own nor
    /// skips the sheet with a saved login. A Mosh connection has no sign-in sheet (Mosh logs in
    /// with SSH keys or the agent): it opens with Mosh, as a normal connect does.
    private func openOneByOne(_ ids: [String]) {
        let connections = ids.compactMap(model.connection(id:))
        // Telnet has no sign-in sheet either (B7): it opens its own tab. A serial entry is refused there.
        let isMosh = { [self] (c: ConnectionView) in [.mosh, .telnet, .unsupported].contains(route(c, Self.mode(for: c), library: model.library)) }
        let mosh = connections.filter(isMosh)
        let requests = connections.filter { !isMosh($0) }.map {
            ConnectRequest(connection: $0, mode: Self.mode(for: $0), autoConnect: false, askLogin: true)
        }
        if let bulkRecorder {
            return bulkRecorder(mosh.map { ConnectRequest(connection: $0, mode: .terminal) } + requests)
        }
        let batch = HookBatch()
        mosh.forEach { requestConnect($0, .terminal, batch: batch) }
        for r in requests {
            hookBatches[r.connection.id] = batch
            gateBeforeConnect(r.connection.id, batch: batch) { [weak self] in self?.enqueue([r], select: nil) }
        }
    }

    func connectionIdsBelow(_ folderId: String?) -> Set<String> {
        func collect(_ f: FolderView) -> [String] { f.connections.map(\.id) + f.folders.flatMap(collect) }
        guard let folder = folderId.flatMap(model.folder(id:)) ?? model.tree else { return [] }
        return Set(collect(folder))
    }
}

/// What a Connect All run does, by connection id, with the names the dialogs show.
struct BulkConnectSummary {
    let ready: [String]
    let needsLogin: [String]
    /// Types the managed policy forbids (`skippedBlocked`): never opened, only named.
    let blocked: [String]
    let names: [String: String]

    /// `only` (Reconnect All) keeps the connections that had a session.
    init(plan: BulkConnectPlanView, only: Set<String>?, name: (String) -> String) {
        let keep = { (id: String) in only?.contains(id) ?? true }
        ready = plan.ready.filter(keep)
        needsLogin = plan.needsLogin.filter(keep)
        blocked = plan.skippedBlocked.filter(keep)
        names = Dictionary((ready + needsLogin + blocked).map { ($0, name($0)) }, uniquingKeysWith: { a, _ in a })
    }

    var total: Int { ready.count + needsLogin.count }

    /// "Opening 12. 3 need a login: a, b, c. 2 blocked by policy: d, e."
    var text: String {
        let need = needsLogin.isEmpty ? "" : " \(needsLogin.count) \(needsLogin.count == 1 ? "needs" : "need") a login: \(list(needsLogin))."
        return "Opening \(ready.count).\(need)\(blockedText)"
    }

    /// " 2 blocked by policy: d, e." or "" when none.
    var blockedText: String {
        blocked.isEmpty ? "" : " \(blocked.count) blocked by policy: \(list(blocked))."
    }

    private func list(_ ids: [String]) -> String {
        let shown = ids.prefix(BulkConnectDialog.namesShown).map { names[$0] ?? $0 }
        let more = ids.count > shown.count ? ", and \(ids.count - shown.count) more" : ""
        return shown.joined(separator: ", ") + more
    }
}

/// The two questions Connect All asks, as sheets on the main window (the UI driver answers them
/// with its `alert <button>` step).
@MainActor enum BulkConnectDialog {
    /// Names listed in the summary before "and N more".
    nonisolated static let namesShown = 8

    static func confirmStart(_ s: BulkConnectSummary) async -> Bool {
        let alert = NSAlert()
        alert.messageText = "Connect \(s.total) connections?"
        let wait = s.needsLogin.isEmpty ? "All of them open now." : "\(s.ready.count) open now. \(s.needsLogin.count) need a login and wait until you open them."
        alert.informativeText = wait + s.blockedText
        alert.addButton(withTitle: "Connect")
        alert.addButton(withTitle: "Cancel").keyEquivalent = "\u{1b}"
        return await present(alert)
    }

    /// True when the user chose to open the connections that need a login. With only blocked
    /// connections to report, the sheet just says so (one OK button) and returns false.
    static func showSummary(_ s: BulkConnectSummary) async -> Bool {
        let alert = NSAlert()
        alert.messageText = "Connect All"
        guard !s.needsLogin.isEmpty else {
            alert.informativeText = s.text + " Your administrator's policy does not allow that type."
            alert.addButton(withTitle: "OK").keyEquivalent = "\r"
            _ = await present(alert)
            return false
        }
        alert.informativeText = s.text + " They have no login of their own, so none was used without asking."
        alert.addButton(withTitle: "Open One by One")
        alert.addButton(withTitle: "Not Now").keyEquivalent = "\u{1b}"
        return await present(alert)
    }

    private static func present(_ alert: NSAlert) async -> Bool {
        guard let window = NSApp.keyWindow ?? NSApp.mainWindow ?? NSApp.windows.first(where: { $0.isVisible && $0.canBecomeMain }) else {
            return alert.runModalInFront() == .alertFirstButtonReturn
        }
        return await withCheckedContinuation { done in
            alert.beginSheetModal(for: window) { done.resume(returning: $0 == .alertFirstButtonReturn) }
        }
    }
}
