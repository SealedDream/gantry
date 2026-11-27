import AppKit
import SwiftUI
import BastionCore

/// Session logs of one connection, or of every connection in a folder and its subfolders
/// (LOG-CORE-02). Where each connection's logs live comes from the core (`session_log_plan`).
struct SessionLogsView: View {
    enum Scope {
        case connection(ConnectionView)
        case folder(FolderView)

        var title: String {
            switch self {
            case .connection(let c): c.name
            case .folder(let f): f.name
            }
        }

        @MainActor var connections: [ConnectionView] {
            switch self {
            case .connection(let c): [c]
            case .folder(let f): Array(DashboardRows.connections(under: f).values)
            }
        }
    }

    let scope: Scope
    @Environment(Commands.self) private var commands
    @Environment(\.dismiss) private var dismiss
    @State private var files: [SessionLogFile] = []
    @State private var shown: [SessionLogFile] = []
    @State private var query = ""
    @State private var searchText = false
    @State private var selection = Set<SessionLogFile.ID>()
    @State private var error: String?

    var body: some View {
        VStack(spacing: 0) {
            Text(scope.title).font(DS.Font.headline).lineLimit(1).truncationMode(.middle)
                .frame(maxWidth: .infinity, alignment: .leading).padding([.horizontal, .top], 10)
            filters
            Divider()
            table
            Divider()
            footer
        }
        .panelFrame(width: 820, height: 520)
        .task { await reload() }
        .task(id: FilterKey(query: query, content: searchText, count: files.count)) { await applyFilter() }
        .accessibilityIdentifier("session-logs")
    }

    private struct FilterKey: Equatable { let query: String; let content: Bool; let count: Int }

    private var filters: some View {
        HStack(spacing: 8) {
            TextField("Filter", text: $query).textFieldStyle(.roundedBorder).frame(maxWidth: 320)
                .help("File or connection name")
                .accessibilityIdentifier("session-logs-filter")
            Toggle("Search text", isOn: $searchText).toggleStyle(.checkbox).fixedSize()
                .help("Also match text inside the logs (first 8 MB of each)")
            Spacer(minLength: 8)
        }
        .controlSize(.small)
        .padding(10)
    }

    private var table: some View {
        Table(shown, selection: $selection) {
            TableColumn("Modified") { Text($0.modified.formatted(date: .numeric, time: .standard)).monospacedDigit() }
                .width(min: 140, ideal: 160)
            TableColumn("Connection") { Text($0.connection).lineLimit(1).truncationMode(.middle) }
                .width(min: 100, ideal: 160)
            TableColumn("File") { Text($0.name).lineLimit(1).truncationMode(.middle).help($0.url.path) }
                .width(min: 160, ideal: 300)
            TableColumn("Size") { Text(ByteCountFormatter.string(fromByteCount: $0.bytes, countStyle: .file)).monospacedDigit() }
                .width(min: 60, ideal: 70)
        }
        .contextMenu(forSelectionType: SessionLogFile.ID.self) { ids in
            Button("Open") { open(ids) }
            Button("Show in Finder") { reveal(ids) }
        } primaryAction: { open($0) }
        .overlay {
            if shown.isEmpty { Text(files.isEmpty ? "No session logs" : "No matches").foregroundStyle(.secondary) }
        }
    }

    private var footer: some View {
        HStack(spacing: 8) {
            if let error {
                Text(error).foregroundStyle(.red).lineLimit(1).truncationMode(.tail).help(error)
            } else {
                Text(shown.count == 1 ? "1 file" : "\(shown.count) files").foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 8)
            Button("Show in Finder") { reveal(selection.isEmpty ? Set(shown.prefix(1).map(\.id)) : selection) }
                .fixedSize().disabled(shown.isEmpty).help("Reveal the selected log")
            Button("Export…") { export() }
                .fixedSize().disabled(shown.isEmpty).help("Copy the selected logs, or all shown, to a folder")
                .accessibilityIdentifier("session-logs-export")
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction).dsPrimaryButton()
        }
        .controlSize(.small)
        .padding(10)
    }

    // MARK: Loading

    /// Each connection's log folder, from the core's plan for a session started now.
    private func reload() async {
        guard let library = commands.model.library else { return }
        let dataDir = LibraryModel.dataDir.path
        let offset = Int32(TimeZone.current.secondsFromGMT() / 60)
        var folders: [URL: String] = [:]
        for c in scope.connections {
            guard let plan = try? library.sessionLogPlan(connectionId: c.id, dataDir: dataDir, app: "native-mac", version: DiagnosticsExport.version.0, utcOffsetMinutes: offset) else { continue }
            folders[URL(fileURLWithPath: plan.path).deletingLastPathComponent()] = c.name
        }
        files = await Task.detached { SessionLogFiles.list(folders) }.value
    }

    private func applyFilter() async {
        let (all, q, content) = (files, query, searchText)
        // Content search reads files: off the main thread, and a newer keystroke cancels this one.
        let result = await Task.detached { SessionLogFiles.filter(all, query: q, content: content) }.value
        guard !Task.isCancelled else { return }
        shown = result
        selection = selection.intersection(result.map(\.id))
    }

    // MARK: Actions

    private func urls(_ ids: Set<SessionLogFile.ID>) -> [URL] { shown.filter { ids.contains($0.id) }.map(\.url) }

    private func open(_ ids: Set<SessionLogFile.ID>) { urls(ids).forEach { NSWorkspace.shared.open($0) } }

    private func reveal(_ ids: Set<SessionLogFile.ID>) {
        let list = urls(ids)
        if !list.isEmpty { NSWorkspace.shared.activateFileViewerSelecting(list) }
    }

    private func export() {
        let chosen = selection.isEmpty ? shown : shown.filter { selection.contains($0.id) }
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.prompt = "Export"
        panel.message = chosen.count == 1 ? "Export 1 session log" : "Export \(chosen.count) session logs"
        guard panel.runModal() == .OK, let folder = panel.url else { return }
        do {
            _ = try SessionLogFiles.export(chosen, to: folder)
            error = nil
        } catch {
            self.error = "Export failed: \(errorText(error))"
        }
    }
}
