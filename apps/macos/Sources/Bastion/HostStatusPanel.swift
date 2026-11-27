import SwiftUI
import BastionCore

/// Host status dashboard (core `hoststatus`): the connections with "Show on host status" turned on,
/// checked with a low-frequency TCP connect while this sheet is open and not at all once it closes.
struct HostStatusPanel: View {
    @Environment(LibraryModel.self) private var model
    @Environment(Commands.self) private var commands
    private var dismiss = PanelDismiss()
    @State private var dashboard = HostStatusDashboard(intervalSecs: Self.defaultInterval)
    @State private var rows: [HostStatusView] = []
    @State private var targets: UInt32 = 0
    @State private var selection: String?
    @State private var interval = Self.defaultInterval
    @State private var problem: String?
    /// Reads the core's snapshot; the checks themselves run on the core's own schedule.
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    static let defaultInterval: UInt32 = 60
    static let intervals: [UInt32] = [30, 60, 300, 900]

    var body: some View {
        VStack(spacing: 0) {
            Text("Host Status").font(DS.Font.bodyStrong)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            if targets == 0 {
                EmptyState(symbol: "dot.radiowaves.left.and.right", title: "No hosts to check",
                           message: "Turn on General › Show on host status for a connection or folder.") { EmptyView() }
            } else {
                Table(rows, selection: $selection) {
                    TableColumn("Host") { r in Text(r.name).lineLimit(1) }
                    TableColumn("State") { r in state(r) }
                    TableColumn("Latency") { r in
                        Text(r.latencyMs.map { "\($0) ms" } ?? "—").font(DS.Font.caption.monospacedDigit()).foregroundStyle(.secondary)
                    }
                    TableColumn("Checked") { r in
                        Text(r.checkedAt.map(Self.relative) ?? "—").font(DS.Font.caption).foregroundStyle(.secondary)
                    }
                }
                .contextMenu(forSelectionType: String.self) { ids in
                    if let id = ids.first, model.connection(id: id) != nil { Button("Connect") { connect(id) } }
                } primaryAction: { ids in ids.first.map(connect) }
            }
            if let problem {
                Text(problem).font(DS.Font.caption).foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, DS.Space.m).padding(.top, DS.Space.xs)
            }
            Divider()
            HStack(spacing: DS.Space.s) {
                Picker("Check every", selection: $interval) {
                    ForEach(Self.intervals, id: \.self) { Text(Self.intervalLabel($0)).tag($0) }
                }
                .fixedSize()
                .onChange(of: interval) { _, v in dashboard.setInterval(intervalSecs: v) }
                Button("Check Now") { dashboard.checkNow() }.disabled(targets == 0)
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
            }
            .padding(DS.Space.s)
        }
        .panelFrame(width: DS.Size.managerWidth + 160, height: DS.Size.managerHeight)
        .onAppear(perform: start)
        .onDisappear { dashboard.setVisible(visible: false) }
        .onChange(of: model.revision) { load() }
        .onReceive(timer) { _ in rows = dashboard.snapshot() }
    }

    private func start() {
        load()
        dashboard.setVisible(visible: true)
        rows = dashboard.snapshot()
    }

    private func load() {
        guard let library = model.library else { return }
        do { targets = try dashboard.load(library: library); problem = nil } catch { problem = errorText(error) }
    }

    private func connect(_ id: String) {
        guard let c = model.connection(id: id) else { return }
        dismiss()
        commands.enqueue([ConnectRequest(connection: c, mode: .terminal)], select: nil)
    }

    @ViewBuilder private func state(_ r: HostStatusView) -> some View {
        switch r.state {
        case "up": Label("Up", systemImage: "circle.fill").foregroundStyle(.green)
        case "down": Label("Down", systemImage: "circle.fill").foregroundStyle(.red).help(r.error ?? "")
        case "skipped": Label("Skipped", systemImage: "circle.dashed").foregroundStyle(.secondary).help(r.error ?? "Not checked")
        default: Label("Checking…", systemImage: "circle").foregroundStyle(.secondary)
        }
    }

    static func relative(_ unix: UInt64) -> String {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return f.localizedString(for: Date(timeIntervalSince1970: TimeInterval(unix)), relativeTo: Date())
    }

    static func intervalLabel(_ secs: UInt32) -> String {
        secs < 60 ? "\(secs) seconds" : secs == 60 ? "1 minute" : "\(secs / 60) minutes"
    }
}

extension HostStatusView: Identifiable {}
