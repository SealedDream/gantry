import AppKit
import SwiftUI
import BastionCore

/// The transfer list under the file browser: one row per file with progress, speed and ETA, the
/// controls its state allows, inline answers for a conflict, and the "if the file exists" rule.
struct TransferQueueView: View {
    @ObservedObject var runner: TransferQueueRunner
    @State private var expanded = true

    var body: some View {
        VStack(spacing: 0) {
            header
            if expanded {
                Divider()
                List(runner.jobs, id: \.id) { job in
                    TransferRow(job: job, runner: runner)
                }
                .listStyle(.plain)
                .frame(minHeight: 60, idealHeight: rowsHeight, maxHeight: 180)
            }
        }
    }

    private var rowsHeight: CGFloat { CGFloat(min(runner.jobs.count, 5)) * 30 + 6 }

    private var header: some View {
        HStack(spacing: 8) {
            Button { expanded.toggle() } label: {
                Image(systemName: expanded ? "chevron.down" : "chevron.right").frame(width: 12)
            }
            .help(expanded ? "Hide transfers" : "Show transfers")
            Text("Transfers").font(DS.Font.callout.weight(.semibold))
            Text(summaryText).font(DS.Font.caption).foregroundStyle(.secondary).monospacedDigit()
            Spacer()
            Picker("If the file exists", selection: $runner.rule) {
                ForEach(TransferQueueRunner.rules, id: \.id) { Text($0.title).tag($0.id) }
            }
            .pickerStyle(.menu)
            .fixedSize()
            .help("What a new transfer does when the target already exists")
            Button("Clear Finished") { runner.clearFinished() }
                .disabled(!runner.jobs.contains { TransferRow.finished.contains($0.state) && $0.state != "failed" })
        }
        .buttonStyle(.borderless)
        .controlSize(.small)
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
    }

    private var summaryText: String {
        let s = runner.summary
        var parts: [String] = []
        if s.active > 0 { parts.append("\(s.active) running") }
        if s.queued > 0 { parts.append("\(s.queued) queued") }
        if s.failed > 0 { parts.append("\(s.failed) failed") }
        if s.speed > 0 { parts.append(TransferRow.rate(s.speed)) }
        return parts.isEmpty ? "Idle" : parts.joined(separator: " · ")
    }
}

struct TransferRow: View {
    let job: TransferJobView
    @ObservedObject var runner: TransferQueueRunner

    static let finished: Set<String> = ["done", "skipped", "failed", "cancelled"]

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: job.direction == "upload" ? "arrow.up" : "arrow.down")
                .foregroundStyle(.secondary).frame(width: 14)
            Text((job.source as NSString).lastPathComponent)
                .lineLimit(1).truncationMode(.middle)
                .frame(minWidth: 80, maxWidth: .infinity, alignment: .leading)
                .help("\(job.source) → \(job.target)")
            status
            controls
        }
        .font(DS.Font.callout)
        .contextMenu {
            Button("Copy Source Path") { copy(job.source) }
            Button("Copy Target Path") { copy(job.target) }
        }
    }

    @ViewBuilder private var status: some View {
        switch job.state {
        case "running":
            ProgressView(value: job.total > 0 ? Double(job.done) / Double(job.total) : 0).frame(width: 90)
            Text(detail).font(DS.Font.caption).foregroundStyle(.secondary).monospacedDigit().frame(width: 110, alignment: .trailing)
        case "conflict":
            Text("Already exists").font(DS.Font.caption).foregroundStyle(.orange)
        case "failed":
            Text(job.error ?? "Failed").font(DS.Font.caption).foregroundStyle(.red).lineLimit(1).truncationMode(.tail)
                .frame(maxWidth: 200, alignment: .trailing).help(job.error ?? "")
        default:
            Text(label).font(DS.Font.caption).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var controls: some View {
        HStack(spacing: 4) {
            switch job.state {
            case "conflict":
                Button("Replace") { runner.answer(job.id, rule: "replace") }
                Button("Keep Both") { runner.answer(job.id, rule: "rename") }
                Button("Skip") { runner.answer(job.id, rule: "skip") }
            case "queued", "running":
                icon("pause.fill", "Pause") { runner.pause(job.id) }
                icon("xmark", "Cancel") { runner.cancel(job.id) }
            case "paused":
                icon("play.fill", "Resume") { runner.resume(job.id) }
                icon("xmark", "Cancel") { runner.cancel(job.id) }
            case "failed":
                icon("arrow.clockwise", "Retry") { runner.retry(job.id) }
            default:
                EmptyView()
            }
        }
        .buttonStyle(.borderless)
        .controlSize(.small)
    }

    private func icon(_ name: String, _ help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) { Image(systemName: name).iconHitTarget() }.help(help).accessibilityLabel(help)
    }

    private var label: String {
        switch job.state {
        case "queued": return "Queued"
        case "paused": return "Paused"
        case "done": return Self.bytes(job.total)
        case "skipped": return "Skipped"
        case "cancelled": return "Cancelled"
        default: return job.state.capitalized
        }
    }

    private var detail: String {
        guard job.speed > 0 else { return "\(Self.bytes(job.done)) of \(Self.bytes(job.total))" }
        let eta = job.eta.map { " · \(Self.duration($0))" } ?? ""
        return Self.rate(job.speed) + eta
    }

    static func bytes(_ n: UInt64) -> String { ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file) }
    static func rate(_ bps: Double) -> String { bytes(UInt64(bps)) + "/s" }
    static func duration(_ secs: UInt64) -> String {
        secs < 60 ? "\(secs)s" : secs < 3600 ? "\(secs / 60)m \(secs % 60)s" : "\(secs / 3600)h \(secs % 3600 / 60)m"
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }
}
