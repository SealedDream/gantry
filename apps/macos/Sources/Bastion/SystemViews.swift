import AppKit
import SwiftUI
import BastionCore

/// A Services, Processes or Event Log tab. The core runs fixed read-only commands over one SSH
/// session; this view only polls it, and only while its tab is selected and its window is on
/// screen (not minimised, hidden or fully covered).
struct SystemViewTab: View {
    let system: SystemView
    let isActive: Bool
    /// Opens an SSH terminal on the same connection.
    let openTerminal: () -> Void
    @State private var windowVisible = true

    var body: some View {
        let polling = isActive && windowVisible
        Group {
            switch system.view() {
            case "services": ServicesTable(system: system, active: isActive, polling: polling, openTerminal: openTerminal)
            case "processes": ProcessesTable(system: system, active: isActive, polling: polling, openTerminal: openTerminal)
            default: EventsList(system: system, active: isActive, polling: polling, openTerminal: openTerminal)
            }
        }
        .background(.background)
        .background(WindowOcclusion(isVisible: $windowVisible))
        .onChange(of: polling, initial: true) { SystemViewProbe.polling(system, polling) }
    }
}

/// Reports whether the hosting window is visible on screen (`NSWindow.occlusionState`).
private struct WindowOcclusion: NSViewRepresentable {
    @Binding var isVisible: Bool

    func makeNSView(context: Context) -> NSView { Probe(report: { isVisible = $0 }) }
    func updateNSView(_ nsView: NSView, context: Context) {}

    final class Probe: NSView {
        let report: (Bool) -> Void
        private var token: NSObjectProtocol?
        init(report: @escaping (Bool) -> Void) {
            self.report = report
            super.init(frame: .zero)
        }
        required init?(coder: NSCoder) { nil }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            token.map(NotificationCenter.default.removeObserver)
            guard let window else { return }
            // Quiet driver runs sit behind the owner's windows on purpose: count them as visible,
            // or the system views would never poll (the pause itself is not what they test).
            if QuietLaunch.isOn { return report(true) }
            report(window.occlusionState.contains(.visible))
            token = NotificationCenter.default.addObserver(forName: NSWindow.didChangeOcclusionStateNotification, object: window, queue: .main) { [weak self] _ in
                guard let self, let w = self.window else { return }
                self.report(w.occlusionState.contains(.visible))
            }
        }

        override func viewWillMove(toWindow newWindow: NSWindow?) {
            super.viewWillMove(toWindow: newWindow)
            if newWindow == nil { token.map(NotificationCenter.default.removeObserver); token = nil }
        }
    }
}

/// Poll `work` every `interval` while `polling`, off the main thread; one request at a time.
private struct Poller: ViewModifier {
    let polling: Bool
    let paused: Bool
    let interval: Duration
    let work: @Sendable () async -> Void

    func body(content: Content) -> some View {
        content.task(id: polling && !paused) {
            guard polling && !paused else { return }
            while !Task.isCancelled {
                await work()
                try? await Task.sleep(for: interval)
            }
        }
    }
}

private enum Poll {
    static let services: Duration = .seconds(15)
    static let processes: Duration = .seconds(2)
    static let events: Duration = .seconds(2)
}

/// Shared header: OS, row count, last refresh or error, Pause, Refresh and Open in Terminal.
private struct SystemHeader<Filters: View>: View {
    let title: String
    let system: SystemView
    let active: Bool
    let count: Int
    let status: String?
    let error: String?
    @Binding var paused: Bool
    @Binding var search: String
    let refresh: () -> Void
    let openTerminal: () -> Void
    @ViewBuilder var filters: Filters

    var body: some View {
        HStack(spacing: DS.Space.s) {
            Text(title).font(DS.Font.headline)
            Text(system.os() == "windows" ? "Windows" : "Linux").foregroundStyle(.secondary)
            Text("\(count)").foregroundStyle(.secondary).monospacedDigit().accessibilityIdentifier("sysview-count")
            filters
            Spacer()
            if let error {
                Text(error).foregroundStyle(.red).lineLimit(1).truncationMode(.tail).help(error).accessibilityIdentifier("sysview-error")
            } else if let status {
                Text(status).foregroundStyle(.secondary).monospacedDigit()
            }
            TextField("Filter", text: $search).textFieldStyle(.roundedBorder).frame(width: 160)
            Toggle("Pause", isOn: $paused).toggleStyle(.button).help("Stop refreshing")
            Button("Refresh", systemImage: "arrow.clockwise", action: refresh).keyboardShortcut(active ? KeyboardShortcut("r", modifiers: .command) : nil).quietIcon("Refresh now (⌘R)")
            Button("Open in Terminal", systemImage: "terminal", action: openTerminal).keyboardShortcut(active ? KeyboardShortcut("t", modifiers: [.command, .option]) : nil).quietIcon("An SSH terminal on this host (⌥⌘T)")
        }
        .controlSize(.small)
        .padding(.horizontal, DS.Space.m)
        .padding(.vertical, DS.Space.xs)
        Divider()
    }
}

private func matches(_ search: String, _ fields: String...) -> Bool {
    let q = search.trimmingCharacters(in: .whitespaces)
    return q.isEmpty || fields.contains { $0.localizedCaseInsensitiveContains(q) }
}

private func clock() -> String { Date.now.formatted(date: .omitted, time: .standard) }

/// What each system view last showed (rows after filtering, refreshes, first row, error), for the
/// UI driver; keyed by the view object.
@MainActor
enum SystemViewProbe {
    struct Snapshot { var rows = 0; var refreshes = 0; var sample = ""; var error: String?; var polling = false }
    static var latest: [ObjectIdentifier: Snapshot] = [:]

    static func polling(_ system: SystemView, _ on: Bool) {
        var s = latest[ObjectIdentifier(system)] ?? Snapshot()
        s.polling = on
        latest[ObjectIdentifier(system)] = s
    }

    static func record(_ system: SystemView, rows: Int, sample: String, error: String?) {
        var s = latest[ObjectIdentifier(system)] ?? Snapshot()
        s.rows = rows
        s.refreshes += 1
        s.sample = sample
        s.error = error
        latest[ObjectIdentifier(system)] = s
    }
}

private struct ServicesTable: View {
    let system: SystemView
    /// The selected tab: only it owns ⌘R and ⌥⌘T (every tab stays mounted).
    let active: Bool
    let polling: Bool
    let openTerminal: () -> Void
    @State private var rows: [SysServiceView] = []
    @State private var error: String?
    @State private var updated: String?
    @State private var paused = false
    @State private var search = ""
    @State private var sort = [KeyPathComparator(\SysServiceView.name)]

    private var shown: [SysServiceView] {
        rows.filter { matches(search, $0.name, $0.description, $0.state, $0.sub) }.sorted(using: sort)
    }

    var body: some View {
        VStack(spacing: 0) {
            SystemHeader(title: "Services", system: system, active: active, count: shown.count, status: updated.map { "Updated \($0)" }, error: error,
                         paused: $paused, search: $search, refresh: { Task { await load() } }, openTerminal: openTerminal) {}
            Table(shown, sortOrder: $sort) {
                TableColumn("Name", value: \.name) { Text($0.name).textSelection(.enabled) }
                TableColumn("Description", value: \.description)
                TableColumn("State", value: \.state) { r in Text(r.state).foregroundStyle(r.state == "failed" ? .red : .primary) }.width(90)
                TableColumn(system.os() == "windows" ? "Start type" : "Sub-state", value: \.detail).width(100)
            }
        }
        .modifier(Poller(polling: polling, paused: paused, interval: Poll.services) { await load() })
    }

    private func load() async {
        let system = system
        let result = await Task.detached { Result { try system.services() } }.value
        switch result {
        case .success(let r): rows = r; error = nil; updated = clock()
        case .failure(let e): error = "\(e)"
        }
        SystemViewProbe.record(system, rows: shown.count, sample: shown.prefix(40).map { "\($0.name)=\($0.state)" }.joined(separator: " "), error: error)
    }
}

extension SysServiceView: Identifiable {
    public var id: String { name }
    /// Sub-state on Linux, start type on Windows.
    var detail: String { sub.isEmpty ? startType : sub }
}

extension SysProcessView: Identifiable {
    public var id: UInt32 { pid }
    var cpuSort: Double { cpuPercent ?? cpuSeconds ?? 0 }
}

private struct ProcessesTable: View {
    let system: SystemView
    /// The selected tab: only it owns ⌘R and ⌥⌘T (every tab stays mounted).
    let active: Bool
    let polling: Bool
    let openTerminal: () -> Void
    @State private var rows: [SysProcessView] = []
    @State private var error: String?
    @State private var updated: String?
    @State private var paused = false
    @State private var search = ""
    @State private var sort = [KeyPathComparator(\SysProcessView.memBytes, order: .reverse)]

    private var shown: [SysProcessView] {
        rows.filter { matches(search, $0.name, $0.user, String($0.pid)) }.sorted(using: sort)
    }

    var body: some View {
        VStack(spacing: 0) {
            SystemHeader(title: "Processes", system: system, active: active, count: shown.count, status: updated.map { "Updated \($0)" }, error: error,
                         paused: $paused, search: $search, refresh: { Task { await load() } }, openTerminal: openTerminal) {}
            Table(shown, sortOrder: $sort) {
                TableColumn("PID", value: \.pid) { Text(String($0.pid)).monospacedDigit() }.width(70)
                TableColumn("Name", value: \.name) { Text($0.name).textSelection(.enabled) }
                TableColumn("User", value: \.user).width(120)
                TableColumn(system.os() == "windows" ? "CPU s" : "CPU %", value: \.cpuSort) { p in
                    Text(p.cpuPercent.map { String(format: "%.1f", $0) } ?? p.cpuSeconds.map { String(format: "%.1f", $0) } ?? "–").monospacedDigit()
                }.width(70)
                TableColumn("Memory", value: \.memBytes) { Text(ByteCountFormatter.string(fromByteCount: Int64($0.memBytes), countStyle: .memory)).monospacedDigit() }.width(90)
            }
        }
        .modifier(Poller(polling: polling, paused: paused, interval: Poll.processes) { await load() })
    }

    private func load() async {
        let system = system
        let result = await Task.detached { Result { try system.processes() } }.value
        switch result {
        case .success(let r): rows = r; error = nil; updated = clock()
        case .failure(let e): error = "\(e)"
        }
        SystemViewProbe.record(system, rows: shown.count, sample: shown.prefix(40).map { "\($0.pid):\($0.name)" }.joined(separator: " "), error: error)
    }
}

private struct EventRowItem: Identifiable {
    let id: Int
    let event: SysEventView
}

private let linuxPriorities = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
private let windowsLevels = ["Critical", "Error", "Warning", "Information", "Verbose"]

private struct EventsList: View {
    let system: SystemView
    /// The selected tab: only it owns ⌘R and ⌥⌘T (every tab stays mounted).
    let active: Bool
    let polling: Bool
    let openTerminal: () -> Void
    @State private var events: [EventRowItem] = []
    @State private var next = 0
    @State private var error: String?
    @State private var paused = false
    @State private var search = ""
    @State private var unit = ""
    @State private var appliedUnit = ""
    @State private var priority = -1
    @State private var log = "System"
    @State private var level = 0
    @State private var follow = true
    @State private var selected: Set<Int> = []
    @State private var snippetStatus: (message: String, isError: Bool)?
    private let limit = Int(sysViewLimits().maxEventsKept)

    private var isWindows: Bool { system.os() == "windows" }

    private var filter: SysEventFilter {
        isWindows
            ? SysEventFilter(unit: nil, priority: nil, log: log, level: level > 0 ? UInt8(level) : nil)
            : SysEventFilter(unit: appliedUnit.isEmpty ? nil : appliedUnit, priority: priority >= 0 ? UInt8(priority) : nil, log: nil, level: nil)
    }

    private var shown: [EventRowItem] {
        events.filter { matches(search, $0.event.message, $0.event.source, $0.event.level) }
    }

    var body: some View {
        VStack(spacing: 0) {
            SystemHeader(title: isWindows ? "Event Log" : "Journal", system: system, active: active, count: shown.count,
                         status: polling && !paused ? "Live" : "Paused", error: error,
                         paused: $paused, search: $search, refresh: { Task { await load() } }, openTerminal: openTerminal) {
                if isWindows {
                    Picker("Log", selection: $log) { ForEach(sysWindowsLogs, id: \.self) { Text($0) } }.frame(width: 150)
                    Picker("Level", selection: $level) {
                        Text("All levels").tag(0)
                        ForEach(windowsLevels.indices, id: \.self) { Text("\(windowsLevels[$0]) and worse").tag($0 + 1) }
                    }.frame(width: 190)
                } else {
                    TextField("Unit", text: $unit, prompt: Text("all units")).textFieldStyle(.roundedBorder).frame(width: 140)
                        .onSubmit { appliedUnit = unit.trimmingCharacters(in: .whitespaces) }
                    Picker("Priority", selection: $priority) {
                        Text("All priorities").tag(-1)
                        ForEach(linuxPriorities.indices, id: \.self) { Text("\(linuxPriorities[$0]) and worse").tag($0) }
                    }.frame(width: 190)
                }
                Toggle("Follow", isOn: $follow).toggleStyle(.checkbox).help("Keep the newest event in view")
                Button("Save Snippet…", systemImage: "square.and.arrow.down") { saveSnippet(selectedOrVisible) }
                    .disabled(shown.isEmpty)
                    .quietIcon("Save the selected events, or all shown events, to a text file")
            }
            if let snippetStatus {
                Text(snippetStatus.message).font(DS.Font.caption).foregroundStyle(snippetStatus.isError ? .red : .secondary)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.xs)
                    .accessibilityIdentifier("log-snippet-status")
            }
            ScrollViewReader { proxy in
                List(shown, selection: $selected) { item in
                    HStack(alignment: .firstTextBaseline, spacing: DS.Space.s) {
                        Text(item.event.time.replacingOccurrences(of: "T", with: " ").prefix(23)).foregroundStyle(.secondary).monospacedDigit()
                        Text(item.event.level).foregroundStyle(levelColour(item.event.level)).frame(width: 80, alignment: .leading)
                        Text(item.event.source).foregroundStyle(.secondary).lineLimit(1).frame(width: 160, alignment: .leading)
                        Text(item.event.message).textSelection(.enabled).lineLimit(4)
                    }
                    .font(DS.Font.style(.callout, design: .monospaced))
                    .id(item.id)
                }
                .contextMenu(forSelectionType: Int.self) { ids in
                    Button(ids.count > 1 ? "Copy \(ids.count) Lines" : "Copy Line") { LogSnippet.copy(lines(ids)) }
                        .disabled(ids.isEmpty)
                    Button("Copy All Shown") { LogSnippet.copy(lines(nil)) }
                    Divider()
                    Button("Save Snippet…") { saveSnippet(ids.isEmpty ? lines(nil) : lines(ids)) }
                }
                .onCopyCommand { selected.isEmpty ? [] : [NSItemProvider(object: cleanLogSnippet(text: lines(selected).joined(separator: "\n"), stripAnsi: true) as NSString)] }
                .onChange(of: next) {
                    if follow, let last = shown.last { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
        }
        // A new filter starts the tail again from the newest events (the core resets its cursor).
        .onChange(of: log) { restart() }
        .onChange(of: level) { restart() }
        .onChange(of: priority) { restart() }
        .onChange(of: appliedUnit) { restart() }
        .modifier(Poller(polling: polling, paused: paused, interval: Poll.events) { await load() })
        .onReceive(NotificationCenter.default.publisher(for: .logCopyVisible)) { _ in if active { LogSnippet.copy(lines(nil)) } }
        .onReceive(NotificationCenter.default.publisher(for: .logSaveSnippet)) { _ in if active { saveSnippet(selectedOrVisible) } }
    }

    /// One plain line per event, as it is shown: time, level, source, message.
    private func lines(_ ids: Set<Int>?) -> [String] {
        shown.filter { ids?.contains($0.id) ?? true }.map { e in
            "\(e.event.time.replacingOccurrences(of: "T", with: " ").prefix(23))  \(e.event.level)  \(e.event.source)  \(e.event.message)"
        }
    }

    private var selectedOrVisible: [String] { lines(selected.isEmpty ? nil : selected) }

    private func saveSnippet(_ text: [String]) {
        let title = isWindows ? "Event Log \(log)" : "Journal"
        if let r = LogSnippet.save(text, name: title, header: LogSnippet.header(title)) { snippetStatus = r }
    }

    private func levelColour(_ l: String) -> Color {
        switch l.lowercased() {
        case "emerg", "alert", "crit", "critical", "err", "error": .red
        case "warning": .orange
        default: .secondary
        }
    }

    private func restart() {
        events = []
        Task { await load() }
    }

    private func load() async {
        let system = system, filter = filter
        let result = await Task.detached { Result { try system.tail(filter: filter) } }.value
        switch result {
        case .success(let new):
            error = nil
            events.append(contentsOf: new.enumerated().map { EventRowItem(id: next + $0.offset, event: $0.element) })
            next += new.count
            if events.count > limit { events.removeFirst(events.count - limit) }
        case .failure(let e):
            error = "\(e)"
        }
        SystemViewProbe.record(system, rows: shown.count, sample: shown.suffix(20).map { "[\($0.event.level) \($0.event.source)] \($0.event.message)" }.joined(separator: " | "), error: error)
    }
}

private let sysWindowsLogs = ["System", "Application", "Security", "Setup"]
