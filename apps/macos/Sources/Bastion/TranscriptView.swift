import AppKit
import SwiftUI

/// What the viewer opens: a session's transcript file and its title parts.
struct TranscriptTarget: Identifiable, Equatable {
    let path: String
    let connection: String
    let started: Date
    var id: String { path }

    init(path: String, connection: String, started: Date) {
        self.path = path; self.connection = connection; self.started = started
    }

    init?(_ r: ActivityRecord) {
        guard let path = r.transcriptPath else { return nil }
        self.init(path: path, connection: r.connectionName, started: r.startDate)
    }
}

/// The transcript text and its load state. Pages are read off the main thread and appended to the
/// text view, so a large log shows its first page at once and the window never waits for the rest.
@MainActor @Observable
final class TranscriptModel {
    private(set) var lines: [TranscriptLine] = []
    private(set) var loading = false
    private(set) var error: String?
    private(set) var hasTimes = false
    private(set) var hits: [Int] = []
    private(set) var current: Int?
    var showTimes = true { didSet { if oldValue != showTimes { render() } } }
    /// UTF-16 offset of each line in the text view, for Find.
    @ObservationIgnored private var offsets: [Int] = []
    @ObservationIgnored private var length = 0
    @ObservationIgnored private var cancelled = false
    @ObservationIgnored weak var textView: NSTextView?

    func load(_ url: URL) {
        loading = true
        Task.detached(priority: .userInitiated) { [weak self] in
            do {
                try TranscriptText.read(url) { page in
                    DispatchQueue.main.sync {
                        MainActor.assumeIsolated {
                            guard let self, !self.cancelled else { return false }
                            self.append(page)
                            return true
                        }
                    }
                }
                await MainActor.run { self?.loading = false }
            } catch {
                let text = "Transcript unavailable: \(error.localizedDescription)"
                await MainActor.run { self?.loading = false; self?.error = text }
            }
        }
    }

    func cancel() { cancelled = true }

    private func append(_ page: [TranscriptLine]) {
        lines += page
        if !hasTimes, TranscriptText.hasTimes(page) {
            hasTimes = true
            render()
        } else {
            appendText(page)
        }
    }

    private func appendText(_ page: [TranscriptLine]) {
        var text = ""
        for line in page {
            offsets.append(length)
            let shown = line.display(showTimes: showTimes) + "\n"
            length += shown.utf16.count
            text += shown
        }
        textView?.textStorage?.append(NSAttributedString(string: text, attributes: Self.attributes))
    }

    /// Rebuilds the text (Show times changed, or the view attached).
    private func render() {
        offsets = []; length = 0
        textView?.textStorage?.setAttributedString(NSAttributedString())
        appendText(lines)
        if let current { reveal(current) }
    }

    func attach(_ view: NSTextView) {
        textView = view
        render()
    }

    func find(_ query: String) {
        hits = TranscriptText.find(query, in: lines)
        current = nil
        step(forward: true)
    }

    func step(forward: Bool) {
        guard let next = TranscriptText.step(hits, from: current, forward: forward) else { return }
        current = next
        reveal(next)
    }

    private func reveal(_ line: Int) {
        guard let view = textView, line < offsets.count else { return }
        let end = line + 1 < offsets.count ? offsets[line + 1] - 1 : length - 1
        let range = NSRange(location: offsets[line], length: max(0, end - offsets[line]))
        view.setSelectedRange(range)
        view.scrollRangeToVisible(range)
        view.showFindIndicator(for: range)
    }

    /// The selection, or the whole transcript when nothing is selected.
    func copyText() -> String {
        if let view = textView, view.selectedRange().length > 0, let storage = view.textStorage {
            return (storage.string as NSString).substring(with: view.selectedRange())
        }
        return TranscriptText.copyText(lines, selected: [], showTimes: showTimes)
    }

    static let attributes: [NSAttributedString.Key: Any] = [
        .font: NSFont.monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular),
        .foregroundColor: NSColor.textColor,
    ]
}

/// Transcript viewer (LOG-NATIVE-01 item 4, Native Mac): a read-only sheet titled
/// "<connection> — <started>" with Find (⌘F), Show times (only when the log has timestamps), Copy
/// and Show in Finder.
struct TranscriptView: View {
    let target: TranscriptTarget
    @Environment(\.dismiss) private var dismiss
    @State private var model = TranscriptModel()
    @State private var query = ""
    @FocusState private var findFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Text(TranscriptText.title(connection: target.connection, started: target.started))
                    .font(DS.Font.headline).lineLimit(1).truncationMode(.middle)
                    .accessibilityIdentifier("transcript-title")
                Spacer(minLength: 8)
                if model.hasTimes {
                    Toggle("Show times", isOn: $model.showTimes).toggleStyle(.checkbox).fixedSize()
                }
                findField
            }
            .controlSize(.small)
            .padding(10)
            Divider()
            TranscriptTextView(model: model)
                .overlay {
                    if let error = model.error { Text(error).foregroundStyle(.secondary).padding() }
                }
            Divider()
            footer
        }
        .frame(minWidth: 560, idealWidth: 900, maxWidth: .infinity, minHeight: 420, idealHeight: 600, maxHeight: .infinity)
        .onAppear { model.load(URL(fileURLWithPath: target.path)) }
        .onDisappear { model.cancel() }
        .background { Button("Find") { findFocused = true }.keyboardShortcut("f").hidden() }
        #if BASTION_TEST_HOOKS
        .onAppear { TranscriptDriverHook.model = model }
        #endif
    }

    private var findField: some View {
        HStack(spacing: 4) {
            TextField("Find", text: $query)
                .textFieldStyle(.roundedBorder).frame(minWidth: 120, maxWidth: 220)
                .focused($findFocused)
                .onSubmit { model.step(forward: true) }
                .onChange(of: query) { model.find(query) }
                .help("Find in the transcript (⌘F)").accessibilityLabel("Find")
            Button { model.step(forward: false) } label: { Image(systemName: "chevron.up") }
                .disabled(model.hits.isEmpty).help("Find Previous").accessibilityLabel("Find Previous")
                .keyboardShortcut("g", modifiers: [.command, .shift])
            Button { model.step(forward: true) } label: { Image(systemName: "chevron.down") }
                .disabled(model.hits.isEmpty).help("Find Next").accessibilityLabel("Find Next")
                .keyboardShortcut("g")
        }
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Text(statusText).foregroundStyle(.secondary).lineLimit(1).monospacedDigit()
                .accessibilityIdentifier("transcript-status")
            if model.loading { ProgressView().controlSize(.small) }
            Spacer(minLength: 8)
            Button("Copy") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(model.copyText(), forType: .string)
            }
            .disabled(model.lines.isEmpty).help("Copy the selection, or the whole transcript")
            Button("Show in Finder") {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: target.path)])
            }
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction).dsPrimaryButton()
        }
        .controlSize(.small)
        .padding(10)
    }

    private var statusText: String {
        let n = model.lines.count
        var s = n == 1 ? "1 line" : "\(n) lines"
        if !query.trimmingCharacters(in: .whitespaces).isEmpty {
            let k = model.hits.count
            if k == 0 { s += " · no match" } else if let c = model.current, let i = model.hits.firstIndex(of: c) { s += " · \(i + 1) of \(k)" }
        }
        return s
    }
}

/// A read-only, selectable AppKit text view (fast for large text, native selection and copy).
private struct TranscriptTextView: NSViewRepresentable {
    let model: TranscriptModel

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        if let text = scroll.documentView as? NSTextView {
            text.isEditable = false
            text.isSelectable = true
            text.isRichText = false
            text.usesFindBar = true
            text.drawsBackground = true
            text.backgroundColor = .textBackgroundColor
            text.textContainerInset = NSSize(width: 6, height: 6)
            text.layoutManager?.allowsNonContiguousLayout = true
            text.setAccessibilityLabel("Transcript")
            model.attach(text)
        }
        return scroll
    }

    func updateNSView(_ view: NSScrollView, context: Context) {}
}

#if BASTION_TEST_HOOKS
/// The open viewer's model, for the UI driver.
@MainActor enum TranscriptDriverHook { static weak var model: TranscriptModel? }
#endif
