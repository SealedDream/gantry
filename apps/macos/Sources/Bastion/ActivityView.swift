import AppKit
import SwiftUI
import UniformTypeIdentifiers
import BastionCore

/// Activity (LOG-NATIVE-01, Native Mac): every session of every protocol from the core's activity
/// store, newest first. Filters for time, protocol, user, result and free text; sortable columns;
/// Export… writes exactly the rows shown. Read-only: nothing here writes to the store.
struct ActivityView: View {
    private var dismiss = PanelDismiss()
    @State private var filter: ActivityFilter
    @State private var rows: [ActivityRecord] = []
    @State private var hasMore = false
    @State private var loading = false
    @State private var error: String?
    @State private var selection: Set<String> = []
    @State private var transcript: TranscriptTarget?
    @State private var sortOrder: [KeyPathComparator<ActivityRecord>] = [KeyPathComparator(\.startedAt, order: .reverse)]

    /// The core caps a page at 500.
    static let pageSize: UInt32 = 500

    init(scope: ActivityFilter.Scope? = nil) {
        var f = ActivityFilter()
        f.scope = scope
        _filter = State(initialValue: f)
    }

    private var shown: [ActivityRecord] { rows.filter { $0.matches(filter.text) }.sorted(using: sortOrder) }

    var body: some View {
        VStack(spacing: 0) {
            PageNote(text: "What happened in your sessions: connects, disconnects, task runs.",
                     linkTitle: "Audit Log", linkTarget: "audit-log")
            if let scope = filter.scope {
                Text(scope.title).font(DS.Font.headline).lineLimit(1).truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading).padding([.horizontal, .top], 10)
            }
            filters
            Divider()
            table
            Divider()
            footer
        }
        .panelFrame(width: 900, height: 560)
        .task(id: CoreQuery(filter)) { await reload() }
        .sheet(item: $transcript) { TranscriptView(target: $0) }
    }

    private var filters: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 8) { filterControls }
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) { rangePicker; protocolPicker; resultPicker }
                HStack(spacing: 8) { userField; searchField }
            }
        }
        .controlSize(.small)
        .padding(10)
    }

    @ViewBuilder private var filterControls: some View {
        rangePicker; protocolPicker; resultPicker; userField; searchField
    }

    private var rangePicker: some View {
        Picker("Time", selection: $filter.range) {
            ForEach(ActivityFilter.Range.allCases) { Text($0.rawValue).tag($0) }
        }
        .labelsHidden().fixedSize().help("Time").accessibilityLabel("Time")
    }

    private var protocolPicker: some View {
        Picker("Protocol", selection: $filter.protocolName) {
            Text("All protocols").tag("")
            ForEach(ActivityFilter.protocols, id: \.self) { Text($0.uppercased()).tag($0) }
        }
        .labelsHidden().fixedSize().help("Protocol").accessibilityLabel("Protocol")
    }

    private var resultPicker: some View {
        Picker("Result", selection: $filter.result) {
            ForEach(ActivityFilter.Result.allCases) { Text($0.rawValue).tag($0) }
        }
        .labelsHidden().fixedSize().help("Result").accessibilityLabel("Result")
    }

    private var userField: some View {
        TextField("User", text: $filter.user)
            .textFieldStyle(.roundedBorder).frame(width: 110)
            .help("Exact user name").accessibilityLabel("User")
    }

    private var searchField: some View {
        TextField("Search", text: $filter.text)
            .textFieldStyle(.roundedBorder).frame(minWidth: 120, maxWidth: 220)
            .help("Connection, host, user or result").accessibilityLabel("Search")
    }

    private var table: some View {
        Table(shown, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Started", value: \.startedAt) { r in
                Text(r.startDate, format: .dateTime.month(.abbreviated).day().hour().minute())
                    .help(r.startDate.formatted(date: .complete, time: .standard))
            }
            .width(min: 100, ideal: 100)
            TableColumn("Connection", value: \.connectionName) { r in Text(r.connectionName).help(r.connectionName) }
                .width(min: 80, ideal: 100)
            TableColumn("Protocol", value: \.protocolName) { r in Text(r.protocolName.uppercased()) }
                .width(min: 50, ideal: 50)
            TableColumn("Host", value: \.host) { r in Text(r.target).help(r.target) }
                .width(min: 70, ideal: 90)
            TableColumn("User") { r in Text(r.username ?? "") }
                .width(min: 50, ideal: 56)
            TableColumn("Duration") { r in Text(r.durationText).monospacedDigit() }
                .width(min: 56, ideal: 56)
            TableColumn("Result") { r in resultCell(r) }
                .width(min: 100, ideal: 110)
        }
        .contextMenu(forSelectionType: String.self) { ids in
            if let r = record(ids), let target = TranscriptTarget(r) {
                Button("Open Transcript") { transcript = target }
                Button("Show Transcript in Finder") { reveal(target.path) }
            }
            Button("Copy") { copy(ids) }.disabled(ids.isEmpty)
        } primaryAction: { ids in
            if let target = record(ids).flatMap(TranscriptTarget.init) { transcript = target }
        }
        .overlay {
            if shown.isEmpty && !loading {
                Text(error ?? (rows.isEmpty ? "No sessions" : "No match")).foregroundStyle(.secondary)
            }
        }
        .accessibilityLabel("Sessions")
    }

    private func resultCell(_ r: ActivityRecord) -> some View {
        HStack(spacing: 4) {
            Image(systemName: r.open ? "circle.dotted" : r.isOk ? "checkmark.circle" : "xmark.octagon")
                .foregroundStyle(r.open ? Color.secondary : r.isOk ? Color.green : Color.red)
                .accessibilityHidden(true)
            Text(r.resultText).lineLimit(1)
            if r.transcriptPath != nil {
                Image(systemName: "doc.text").foregroundStyle(.secondary).help("Transcript").accessibilityLabel("Transcript")
            }
        }
        .help(r.resultText)
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Text(countText).foregroundStyle(.secondary).lineLimit(1)
            if hasMore { Button("Show More") { Task { await loadMore() } }.disabled(loading) }
            if loading { ProgressView().controlSize(.small) }
            Spacer(minLength: 8)
            Menu("Export…") {
                Button("CSV…") { export(csv: true) }
                Button("JSON…") { export(csv: false) }
            }
            .fixedSize().disabled(shown.isEmpty).help("Save the rows shown")
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction).dsPrimaryButton()
        }
        .controlSize(.small)
        .padding(10)
    }

    private var countText: String {
        let n = shown.count
        return (n == 1 ? "1 session" : "\(n) sessions") + (hasMore ? "+" : "")
    }

    // MARK: Loading

    /// What the core query depends on (free text is applied locally and needs no reload).
    private struct CoreQuery: Equatable {
        let range: ActivityFilter.Range, proto: String, user: String, result: ActivityFilter.Result
        init(_ f: ActivityFilter) { range = f.range; proto = f.protocolName; user = f.user; result = f.result }
    }

    private func reload() async {
        rows = []
        hasMore = false
        await loadMore()
    }

    private func loadMore() async {
        loading = true
        defer { loading = false }
        let query = CoreQuery(filter)
        let json = filter.coreJSON()
        let offset = UInt32(rows.count)
        let dir = LibraryModel.dataDir.path
        let result = await Task.detached(priority: .userInitiated) {
            Result { try ActivityExport.decode(activityQueryJson(dataDir: dir, filterJson: json, offset: offset, limit: Self.pageSize)) }
        }.value
        guard query == CoreQuery(filter) else { return } // the filter changed while loading
        switch result {
        case .success(let page):
            rows += page
            hasMore = page.count == Int(Self.pageSize)
            error = nil
        case .failure(let e):
            error = "Activity unavailable: \(e.localizedDescription)"
        }
    }

    // MARK: Actions

    private func record(_ ids: Set<String>) -> ActivityRecord? {
        guard ids.count == 1, let id = ids.first else { return nil }
        return rows.first { $0.id == id }
    }

    private func reveal(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    private func copy(_ ids: Set<String>) {
        let picked = shown.filter { ids.contains($0.id) }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(ActivityExport.csv(picked), forType: .string)
    }

    private func export(csv: Bool) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [csv ? .commaSeparatedText : .json]
        panel.nameFieldStringValue = "Gantry activity." + (csv ? "csv" : "json")
        panel.message = "Saves the \(shown.count) rows shown."
        let text = csv ? ActivityExport.csv(shown) : ActivityExport.json(shown)
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try text.write(to: url, atomically: true, encoding: .utf8) } catch {
            self.error = "Export failed: \(error.localizedDescription)"
        }
    }
}
