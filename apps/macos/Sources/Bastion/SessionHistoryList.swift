import AppKit
import SwiftUI
import BastionCore

/// Connection page → History (LOG-NATIVE-01): the connection's last sessions, newest first, from
/// the core activity store. "Show All…" opens Activity limited to the connection. Read-only.
struct SessionHistoryList: View {
    let scope: ActivityFilter.Scope
    /// Changes when a session opens or ends (`SessionsModel.historyRevision`).
    let revision: Int
    @State private var rows: [ActivityRecord] = []
    @State private var failed = false
    @State private var showingAll = false
    @State private var transcript: TranscriptTarget?

    static let shownCount: UInt32 = 20

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            HStack(spacing: DS.Space.xs) {
                Text("History").font(DS.Font.bodyStrong)
                Spacer(minLength: DS.Space.xs)
                Button("Show All…") { showingAll = true }.controlSize(.small).fixedSize()
            }
            if failed {
                Text("History unavailable").foregroundStyle(.secondary)
            } else if rows.isEmpty {
                Text("No sessions").foregroundStyle(.secondary)
            } else {
                Grid(alignment: .leading, horizontalSpacing: DS.Space.s, verticalSpacing: DS.Space.xxs) {
                    ForEach(rows) { row($0) }
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("session-history")
        .task(id: revision) { await load() }
        .sheet(isPresented: $showingAll) { ActivityView(scope: scope) }
        .sheet(item: $transcript) { TranscriptView(target: $0) }
        #if BASTION_TEST_HOOKS
        .onAppear { DriverButtons.actions["Show All…"] = { showingAll = true } }
        #endif
    }

    private func row(_ r: ActivityRecord) -> some View {
        GridRow {
            Text(r.startDate, format: .dateTime.month(.abbreviated).day().hour().minute())
                .help(r.startDate.formatted(date: .complete, time: .standard))
            Text(r.username ?? "").lineLimit(1).truncationMode(.tail)
            Text(r.durationText).monospacedDigit()
            HStack(spacing: DS.Space.xxs) {
                Image(systemName: r.open ? "circle.dotted" : r.isOk ? "checkmark.circle" : "xmark.octagon")
                    .foregroundStyle(r.open ? Color.secondary : r.isOk ? Color.green : Color.red)
                    .accessibilityHidden(true)
                Text(r.resultText).lineLimit(1)
                if let target = TranscriptTarget(r) {
                    Button { transcript = target } label: { Image(systemName: "doc.text") }
                    .buttonStyle(.borderless).frame(minWidth: DS.Size.minHitTarget, minHeight: DS.Size.minHitTarget)
                    .help("Open transcript").accessibilityLabel("Open transcript")
                }
            }
        }
        .font(DS.Font.body)
        .accessibilityElement(children: .combine)
    }

    private func load() async {
        var f = ActivityFilter()
        f.scope = scope
        let json = f.coreJSON()
        let dir = LibraryModel.dataDir.path
        let result = await Task.detached(priority: .utility) {
            Result { try ActivityExport.decode(activityQueryJson(dataDir: dir, filterJson: json, offset: 0, limit: Self.shownCount)) }
        }.value
        switch result {
        case .success(let page): rows = page; failed = false
        case .failure: failed = true
        }
    }
}
