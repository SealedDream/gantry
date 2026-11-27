import SwiftUI
import BastionCore

/// One remote text file opened for editing over SFTP (core `remoteedit`). The fingerprint from
/// open (or the last save) goes back with every save, so a file changed on the server meanwhile is
/// never overwritten silently: the save comes back as a conflict and the user chooses.
@MainActor @Observable
final class RemoteEditDocument {
    enum State: Equatable { case loading, ready, saving, conflict, failed(String) }

    let browser: FilesBrowser
    let path: String
    var text = ""
    private(set) var original = ""
    private(set) var state = State.loading
    private var fingerprint: String?

    init(browser: FilesBrowser, path: String) {
        self.browser = browser
        self.path = path
    }

    var isDirty: Bool { text != original }

    func load() async {
        state = .loading
        let (b, p) = (browser, path)
        switch await Task.detached(operation: { Result { try b.editOpen(path: p) } }).value {
        case .success(let json):
            guard let obj = Self.object(json), let t = obj["text"] as? String else { state = .failed("The server sent an unreadable reply."); return }
            text = t
            original = t
            fingerprint = Self.json(obj["fingerprint"])
            state = .ready
        case .failure(let e):
            state = .failed(errorText(e))
        }
    }

    /// Saves; `force` overwrites a copy that changed on the server. True once written.
    @discardableResult
    func save(force: Bool = false) async -> Bool {
        state = .saving
        let (b, p, t, f) = (browser, path, text, fingerprint)
        switch await Task.detached(operation: { Result { try b.editSave(path: p, text: t, fingerprintJson: f, force: force) } }).value {
        case .success(let json):
            guard let obj = Self.object(json) else { state = .failed("The server sent an unreadable reply."); return false }
            if obj["saved"] as? Bool == true {
                fingerprint = Self.json(obj["fingerprint"])
                original = t
                state = .ready
                return true
            }
            state = .conflict
            return false
        case .failure(let e):
            state = .failed(errorText(e))
            return false
        }
    }

    private static func object(_ s: String) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: Data(s.utf8))) as? [String: Any]
    }

    private static func json(_ v: Any?) -> String? {
        guard let v, !(v is NSNull), let d = try? JSONSerialization.data(withJSONObject: v) else { return nil }
        return String(decoding: d, as: UTF8.self)
    }
}

/// Sheet editor for a remote text file: monospaced text, Save (⌘S), Revert, and a conflict
/// choice when the server copy changed since it was opened.
struct RemoteEditorSheet: View {
    @State var doc: RemoteEditDocument
    @Environment(\.dismiss) private var dismiss
    @State private var confirmingClose = false

    var body: some View {
        VStack(spacing: 0) {
            switch doc.state {
            case .loading:
                ProgressView("Opening \(doc.path)…").frame(maxWidth: .infinity, maxHeight: .infinity)
            default:
                TextEditor(text: $doc.text)
                    .font(DS.Font.style(.body, design: .monospaced))
                    .autocorrectionDisabled()
                    .disabled(doc.state == .saving)
            }
            Divider()
            HStack {
                Text(statusText).font(DS.Font.caption).foregroundStyle(isError ? .red : .secondary).lineLimit(2)
                Spacer()
                if doc.state == .conflict {
                    Button("Reload Server Copy") { Task { await doc.load() } }
                    Button("Overwrite") { Task { await doc.save(force: true) } }
                }
                Button("Revert") { doc.text = doc.original }.disabled(!doc.isDirty)
                Button("Close") { if doc.isDirty { confirmingClose = true } else { dismiss() } }
                    .keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Save") { Task { await doc.save() } }
                    .keyboardShortcut("s", modifiers: .command)
                    .disabled(!doc.isDirty || doc.state == .saving || doc.state == .loading)
            }
            .padding(DS.Space.s)
        }
        .frame(minWidth: 640, idealWidth: 760, minHeight: 420, idealHeight: 560)
        .navigationTitle(doc.path)
        .task { if doc.state == .loading { await doc.load() } }
        .confirmationDialog("Close without saving?", isPresented: $confirmingClose) {
            Button("Discard Changes", role: .destructive) { dismiss() }
        } message: { Text("Your changes to \(doc.path) have not been saved.") }
    }

    private var isError: Bool {
        if case .failed = doc.state { return true }
        return doc.state == .conflict
    }

    private var statusText: String {
        switch doc.state {
        case .loading: ""
        case .saving: "Saving…"
        case .conflict: "\(doc.path) changed on the server since you opened it. Nothing was written."
        case .failed(let m): m
        case .ready: doc.isDirty ? "Edited" : doc.path
        }
    }
}

extension RemoteEditDocument: Identifiable {}
