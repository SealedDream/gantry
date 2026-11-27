import AppKit
import BastionCore

/// Spec §1 (docs/specs/session-restore-and-tab-bar.md): the core keeps the open-session set,
/// saved after every tab change. After a clean quit the next launch follows "Restore sessions on
/// launch" and reconnects the tabs. After a crash it puts the tabs back in place, not connected:
/// nobody may be at the machine, so nothing signs in until the user connects a tab (decision D15;
/// the core's plan says so with `autoReconnect` false). A tab that is still waiting when the app
/// quits normally keeps waiting at the next launch. No secrets are saved: tabs connect through
/// the usual connect path (vault, agent or the connect sheet).
@MainActor @Observable
final class SessionRestore {
    /// One per app: a second window must not begin (or save) a second time.
    static let shared = SessionRestore()
    /// What the core saves per tab (`open_sessions` set JSON).
    struct SavedTab: Codable, Equatable {
        let connection: String
        let mode: String
        var layout: SavedLayout?
        var group: String?
        var cwd: String?
        /// B12: the torn-off window it is in (`SavedSet.windows`); nil for the main window.
        var window: String?
    }

    /// B12: a torn-off window (core `SavedWindow`): its frame in screen coordinates (AppKit,
    /// bottom-left origin) and its front tab as an index into the set's tabs.
    struct SavedWindow: Codable, Equatable {
        let id: String
        let x: Double
        let y: Double
        let width: Double
        let height: Double
        var selected: Int?

        var frame: NSRect { NSRect(x: x, y: y, width: width, height: height) }
    }

    struct SavedSet: Codable, Equatable {
        let tabs: [SavedTab]
        let selected: Int?
        let groups: [StripGroup]
        var windows: [SavedWindow] = []
        /// `waitingKey` of every tab that is still waiting since a crash. Not part of the core's
        /// set: kept beside it (`waitingFile`), so such a tab still waits after a clean quit.
        var waiting: [String] = []

        private enum CodingKeys: String, CodingKey { case tabs, selected, groups, windows }
    }

    /// The tabs of the saved set that the user never connected after a crash, one key per tab
    /// (connection ids and modes only, no secret). A clean quit must not turn them into tabs
    /// that sign in by themselves at the next launch (decision D15).
    private nonisolated static let waitingFile = "open-sessions-waiting.json"
    static func waitingKey(connection: String, mode: String) -> String { "\(connection)|\(mode)" }

    /// The core's launch plan (`Library.openSessionsBegin`).
    struct Plan: Decodable {
        let lastExit: String
        let restore: Bool
        let tabs: [SavedTab]
        let selected: Int?
        let groups: [StripGroup]
        let missing: Int
        let autoReconnect: Bool
        /// B12: torn-off windows to reopen (absent from a core older than B12-C).
        var windows: [SavedWindow]?
    }

    @ObservationIgnored private var began = false
    @ObservationIgnored private var lastSaved: SavedSet?
    @ObservationIgnored private var quitObserver: NSObjectProtocol?
    private(set) var lastPlan: Plan?
    var error: String?

    /// Spec §5: the unlocked document's own state directory (fixed at `begin`).
    @ObservationIgnored private var dataDir = LibraryModel.dataDir.path

    /// Once per launch, after the library loads: ask the core what to reopen and queue it.
    func begin(commands: Commands, settings: SettingsModel) {
        guard !began, let lib = commands.model.library else { return }
        began = true
        dataDir = LibraryModel.stateDir
        quitObserver = NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification,
                                                              object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.markCleanQuit() }
        }
        let restoreOnLaunch = settings.value(openSessionsRestoreSettingId()) != "false"
        let plan: Plan
        do {
            let json = try lib.openSessionsBegin(dataDir: dataDir, restoreOnLaunch: restoreOnLaunch)
            plan = try JSONDecoder().decode(Plan.self, from: Data(json.utf8))
        } catch {
            self.error = "Open sessions could not be restored: \(error.userMessage)"
            return
        }
        lastPlan = plan
        guard plan.restore, !plan.tabs.isEmpty else { return }
        if plan.missing > 0 {
            error = plan.missing == 1 ? "1 tab was not restored: its connection was deleted."
                                      : "\(plan.missing) tabs were not restored: their connections were deleted."
        }
        // After a crash every tab waits. After a clean quit only the tabs that were still
        // waiting then do; the others were connected and reconnect as before.
        Self.queueWindows(plan, in: commands.sessions)
        let waiting = plan.autoReconnect ? stillWaiting(plan) : Set(plan.tabs.indices)
        restoreWaiting(plan, waiting, commands: commands, library: lib)
        let live = plan.tabs.indices.filter { !waiting.contains($0) }
        guard !live.isEmpty else { return }
        let requests = live.compactMap { i -> ConnectRequest? in
            let tab = plan.tabs[i]
            guard let c = commands.model.connection(id: tab.connection) else { return nil }
            return ConnectRequest(connection: c, mode: ConnectMode(rawValue: tab.mode) ?? .terminal, layout: tab.layout?.steps ?? [])
        }
        let select = plan.selected.flatMap { live.contains($0) ? plan.tabs[$0] : nil }
        commands.enqueue(requests, select: select.map { ($0.connection, ConnectMode(rawValue: $0.mode) ?? .terminal) })
    }

    /// B12: every restored tab's window, in plan order, for `SessionsModel.placeRestored`; each
    /// window's frame and front tab. A tab whose window is not in the plan goes to the main window.
    static func queueWindows(_ plan: Plan, in sessions: SessionsModel) {
        let windows = Dictionary((plan.windows ?? []).compactMap { w in UUID(uuidString: w.id).map { ($0, w) } }, uniquingKeysWith: { a, _ in a })
        sessions.pendingWindows = [:]
        for tab in plan.tabs {
            let window = tab.window.flatMap(UUID.init(uuidString:)).flatMap { windows[$0] == nil ? nil : $0 }
            sessions.pendingWindows[tab.connection, default: []].append(window)
        }
        for (id, w) in windows {
            sessions.pendingWindowFrames[id] = w.frame
            if let i = w.selected, plan.tabs.indices.contains(i) {
                sessions.pendingWindowFronts[id] = waitingKey(connection: plan.tabs[i].connection, mode: plan.tabs[i].mode)
            }
        }
    }

    /// Which tabs of a clean-quit plan were still waiting when the app quit (`waitingFile`). No
    /// file: none. A file that cannot be read: all of them, so a damaged file never makes a
    /// tab sign in by itself.
    private func stillWaiting(_ plan: Plan) -> Set<Int> {
        let url = URL(fileURLWithPath: dataDir).appendingPathComponent(Self.waitingFile)
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        guard let data = try? Data(contentsOf: url), let keys = try? JSONDecoder().decode([String].self, from: data) else {
            return Set(plan.tabs.indices)
        }
        var left = Dictionary(keys.map { ($0, 1) }, uniquingKeysWith: +)
        var waiting: Set<Int> = []
        for (i, tab) in plan.tabs.enumerated() {
            let key = Self.waitingKey(connection: tab.connection, mode: tab.mode)
            guard let n = left[key], n > 0 else { continue }
            left[key] = n - 1
            waiting.insert(i)
        }
        return waiting
    }

    /// Decision D15: a waiting tab comes back and waits (after a crash that is every remote tab).
    /// No connect request is queued for it, no sheet opens and no saved login is read. A saved local
    /// terminal is not remote: its shell starts again.
    private func restoreWaiting(_ plan: Plan, _ waiting: Set<Int>, commands: Commands, library: Library) {
        let sessions = commands.sessions
        var selected: TerminalTab?
        for (index, saved) in plan.tabs.enumerated() where waiting.contains(index) {
            guard let c = commands.model.connection(id: saved.connection) else { continue }
            if c.protocol == "local" {
                sessions.openLocal(connection: c, library: library)
                continue
            }
            let tab = sessions.addWaiting(connection: c, mode: ConnectMode(rawValue: saved.mode) ?? .terminal,
                                          layout: saved.layout?.steps ?? [])
            if index == plan.selected { selected = tab }
        }
        if let selected { sessions.selected = selected.id }
    }

    /// The set for the tabs open now: saved connections' terminal and files tabs only (local shells,
    /// Quick Connect and Services/Processes/Event Log tabs are left out: the core's set has no
    /// `system` mode and refused the whole save, which showed an error sheet on every tab change).
    static func currentSet(_ sessions: SessionsModel, isSaved: (String) -> Bool,
                           frame: (UUID) -> NSRect? = { TabWindows.windows[$0]?.frame }) -> SavedSet {
        let kept = sessions.tabs.filter { t in
            !t.ended && t.mode.isRestorable && (t.connectionId.map(isSaved) ?? false)
        }
        let tabs = kept.map { t in
            SavedTab(connection: t.connectionId ?? "", mode: t.mode.rawValue,
                     layout: SavedLayout(steps: t.layoutSteps), group: t.group, cwd: nil,
                     window: sessions.windowed[t.id]?.uuidString)
        }
        let used = Set(tabs.compactMap(\.group))
        // B12: each torn-off window that holds a kept tab and has a frame; a tab whose window has
        // none (not shown yet) is saved in the main window.
        var windows: [SavedWindow] = []
        for t in kept {
            guard let w = sessions.windowed[t.id], !windows.contains(where: { $0.id == w.uuidString }), let f = frame(w) else { continue }
            windows.append(SavedWindow(id: w.uuidString, x: f.minX, y: f.minY, width: f.width, height: f.height,
                                       selected: kept.firstIndex { $0.id == sessions.windowSelected[w] }))
        }
        let saved = Set(windows.map(\.id))
        let placed = tabs.map { t in
            var t = t
            if let w = t.window, !saved.contains(w) { t.window = nil }
            return t
        }
        return SavedSet(tabs: placed, selected: kept.firstIndex { $0.id == sessions.selected },
                        groups: sessions.groups.filter { used.contains($0.id) }, windows: windows,
                        waiting: kept.filter(\.isWaiting).map { waitingKey(connection: $0.connectionId ?? "", mode: $0.mode.rawValue) })
    }

    /// After every tab change (cheap when nothing changed). Not before `begin`, so a launch
    /// never overwrites the set it is about to restore.
    /// The files are written on `saveQueue`, not the main thread: the core's write ends in a full
    /// fsync, and the first tab of every launch (no set saved yet) waited for it inside the update
    /// that opened the tab (first local shell profile, 2026-11-26).
    func save(_ set: SavedSet) {
        guard began, set != lastSaved else { return }
        let json: String
        let waiting: Data
        do {
            json = String(decoding: try JSONEncoder().encode(set), as: UTF8.self)
            waiting = try JSONEncoder().encode(set.waiting)
        } catch {
            self.error = "Open sessions could not be saved: \(error.userMessage)"
            return
        }
        lastSaved = set
        let dir = dataDir
        Self.saveQueue.async { [weak self] in
            do {
                // The waiting list first: if only one of the two writes happens, a tab waits rather
                // than signs in by itself.
                try Self.saveWaiting(waiting, dataDir: dir)
                try openSessionsSave(dataDir: dir, setJson: json)
            } catch {
                let message = "Open sessions could not be saved: \(error.userMessage)"
                // Not saved: the next tab change writes the set again.
                DispatchQueue.main.async { self?.lastSaved = nil; self?.error = message }
            }
        }
    }

    /// Serial: the saves land in the order they were made, and the clean-quit mark after them all.
    private nonisolated static let saveQueue = DispatchQueue(label: "bastion.open-sessions-save", qos: .utility)

    /// Owner-only, written in one step. An empty list is still written: a missing file and an
    /// empty one both mean that no tab waits.
    private nonisolated static func saveWaiting(_ json: Data, dataDir: String) throws {
        let url = URL(fileURLWithPath: dataDir).appendingPathComponent(waitingFile)
        try json.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    /// Waits until every queued save is on disk (the UI driver's `crash` step ends the process
    /// without `willTerminate`).
    nonisolated static func waitForSaves() { saveQueue.sync {} }

    func markCleanQuit() {
        guard began else { return }
        let dir = dataDir
        // After every queued save: the mark rewrites the set as it is on disk.
        Self.saveQueue.sync {
            do { try openSessionsMarkCleanQuit(dataDir: dir) } catch {
                NSLog("Gantry: could not mark a clean quit: %@", error.userMessage)
            }
        }
    }
}

/// The core's `PaneLayout` JSON (`{"kind":"leaf"}` or `{"kind":"split","axis","ratio","first","second"}`),
/// converted to and from the app's pre-order split steps (`PaneNode.layoutSteps`: "right:0.500 leaf leaf").
indirect enum SavedLayout: Codable, Equatable {
    case leaf
    case split(axis: String, ratio: Double, first: SavedLayout, second: SavedLayout)

    private enum Keys: String, CodingKey { case kind, axis, ratio, first, second }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        guard try c.decode(String.self, forKey: .kind) == "split" else { self = .leaf; return }
        self = .split(axis: try c.decode(String.self, forKey: .axis), ratio: try c.decodeIfPresent(Double.self, forKey: .ratio) ?? 0.5,
                      first: try c.decode(SavedLayout.self, forKey: .first), second: try c.decode(SavedLayout.self, forKey: .second))
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        switch self {
        case .leaf: try c.encode("leaf", forKey: .kind)
        case let .split(axis, ratio, first, second):
            try c.encode("split", forKey: .kind)
            try c.encode(axis, forKey: .axis)
            try c.encode(ratio, forKey: .ratio)
            try c.encode(first, forKey: .first)
            try c.encode(second, forKey: .second)
        }
    }

    /// Nil for one pane (no steps) or steps that do not form a tree.
    init?(steps: [String]) {
        guard !steps.isEmpty else { return nil }
        var rest = steps[...]
        guard let tree = Self.parse(&rest), rest.isEmpty, tree != .leaf else { return nil }
        self = tree
    }

    private static func parse(_ rest: inout ArraySlice<String>) -> SavedLayout? {
        guard let step = rest.popFirst() else { return nil }
        if step == "leaf" { return .leaf }
        let parts = step.split(separator: ":")
        guard let axis = parts.first.map(String.init), let first = parse(&rest), let second = parse(&rest) else { return nil }
        return .split(axis: axis, ratio: parts.count > 1 ? Double(parts[1]) ?? 0.5 : 0.5, first: first, second: second)
    }

    var steps: [String] {
        switch self {
        case .leaf: ["leaf"]
        case let .split(axis, ratio, first, second): [axis + ":" + String(format: "%.3f", ratio)] + first.steps + second.steps
        }
    }
}
