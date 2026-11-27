import AppKit
import SwiftUI
import BastionCore

/// Audit Log (LOG-NATIVE-01, Native Mac): the core's audit records, newest first, read-only, with
/// the hash-chain status ("Log intact" / "Changed at record N"). No edit or delete.
struct AuditLogView: View {
    private var dismiss = PanelDismiss()
    @State private var records: [AuditRecord] = []
    @State private var total = 0
    @State private var status: AuditVerify?
    @State private var error: String?
    @State private var loading = false
    @State private var search = ""
    @State private var selection: Set<String> = []

    static let pageSize: UInt32 = 500

    private var shown: [AuditRecord] { records.filter { $0.matches(search) } }

    var body: some View {
        VStack(spacing: 0) {
            PageNote(text: "Security record: vault unlocks, credential use, host keys, exports. Append-only.",
                     linkTitle: "Session activity", linkTarget: "activity")
            HStack(spacing: 8) {
                statusLabel
                Spacer(minLength: 8)
                TextField("Search", text: $search)
                    .textFieldStyle(.roundedBorder).frame(minWidth: 120, maxWidth: 220)
                    .help("Category, action, target, outcome or details").accessibilityLabel("Search")
            }
            .controlSize(.small)
            .padding(10)
            Divider()
            table
            Divider()
            footer
        }
        .panelFrame(width: 900, height: 560)
        .task { await load(reset: true) }
    }

    @ViewBuilder private var statusLabel: some View {
        if let status {
            Label(status.text, systemImage: status.intact ? "checkmark.seal" : "exclamationmark.triangle")
                .foregroundStyle(status.intact ? Color.secondary : Color.red)
                .lineLimit(1)
                .help(status.intact ? "Every record follows from the one before it" : "A record was changed or removed after it was written")
                .accessibilityIdentifier("audit-status")
        }
    }

    private var table: some View {
        Table(shown, selection: $selection) {
            TableColumn("Time") { r in
                Text(r.date, format: .dateTime.month(.abbreviated).day().hour().minute().second())
                    .help(r.date.formatted(date: .complete, time: .standard))
            }
            .width(min: 110, ideal: 120)
            TableColumn("Category") { r in Text(r.categoryText).help(r.categoryText) }.width(min: 80, ideal: 110)
            TableColumn("Action") { r in Text(r.action).help(r.action) }.width(min: 70, ideal: 100)
            TableColumn("Target") { r in Text(r.target ?? "").help(r.target ?? "") }.width(min: 70, ideal: 110)
            TableColumn("Outcome") { r in
                Text(r.outcomeText).foregroundStyle(r.isSuccess ? Color.primary : Color.red)
            }
            .width(min: 60, ideal: 70)
            TableColumn("Details") { r in Text(r.detailsText).help(r.detailsText) }.width(min: 80, ideal: 200)
        }
        .contextMenu(forSelectionType: String.self) { ids in
            Button("Copy") { copy(ids) }.disabled(ids.isEmpty)
        }
        .overlay {
            if shown.isEmpty && !loading {
                Text(error ?? (records.isEmpty ? "No records" : "No match")).foregroundStyle(.secondary)
            }
        }
        .accessibilityLabel("Audit records")
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Text(records.count < total ? "\(records.count) of \(total) records" : (total == 1 ? "1 record" : "\(total) records"))
                .foregroundStyle(.secondary).lineLimit(1)
            if records.count < total { Button("Show More") { Task { await load(reset: false) } }.disabled(loading) }
            if loading { ProgressView().controlSize(.small) }
            Spacer(minLength: 8)
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction).dsPrimaryButton()
        }
        .controlSize(.small)
        .padding(10)
    }

    private func load(reset: Bool) async {
        loading = true
        defer { loading = false }
        let dir = LibraryModel.dataDir.path
        let offset = reset ? 0 : UInt32(records.count)
        let result = await Task.detached(priority: .userInitiated) {
            Result { () throws -> (AuditPage, AuditVerify?) in
                let page = try AuditPage.decode(auditReadJson(dataDir: dir, offset: offset, limit: Self.pageSize))
                let verify = reset ? try AuditVerify.decode(auditVerifyJson(dataDir: dir)) : nil
                return (page, verify)
            }
        }.value
        switch result {
        case .success(let (page, verify)):
            records = reset ? page.records : records + page.records
            total = page.total
            if let verify { status = verify }
            error = nil
        case .failure(let e):
            error = "Audit log unavailable: \(e.localizedDescription)"
        }
    }

    private func copy(_ ids: Set<String>) {
        let text = shown.filter { ids.contains($0.id) }.map {
            [ISO8601DateFormatter().string(from: $0.date), $0.categoryText, $0.action, $0.target ?? "", $0.outcomeText, $0.detailsText].joined(separator: "\t")
        }.joined(separator: "\n")
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
