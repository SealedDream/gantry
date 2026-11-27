import AppKit
import SwiftUI
import BastionCore

/// Where OSC 52 copies go; the UI driver swaps in a private pasteboard.
@MainActor
enum TerminalClipboard {
    static var board = NSPasteboard.general

    static func copy(_ text: String) {
        board.clearContents()
        board.setString(text, forType: .string)
    }
}

/// "A program wants to copy …" above a pane, for the `ask` OSC 52 policy. Nothing is copied
/// until the user allows it; the remote side never learns the answer.
struct ClipboardRequestBar: View {
    let pane: TerminalPane

    var body: some View {
        if let text = pane.clipboardRequest {
            HStack(spacing: DS.Space.s) {
                Image(systemName: "doc.on.clipboard").foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 0) {
                    Text("The remote program wants to copy \(text.count) characters to your clipboard.").font(DS.Font.caption)
                    Text(text.prefix(80).replacingOccurrences(of: "\n", with: " ⏎ ")).font(DS.Font.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                Button("Deny") { pane.clipboardRequest = nil }
                Button("Allow") { TerminalClipboard.copy(text); pane.clipboardRequest = nil }.keyboardShortcut(.defaultAction).dsPrimaryButton()
            }
            .controlSize(.small)
            .padding(.horizontal, DS.Space.s).padding(.vertical, DS.Space.xs)
            .background(.bar)
            .overlay(alignment: .bottom) { Divider() }
        }
    }
}

/// Snippets (core `snippets`): pick one and send it to the focused terminal (and, while
/// broadcasting, to every session in the group). Multi-line snippets are confirmed first.
@MainActor @Observable
final class SnippetsModel {
    private(set) var items: [SnippetView] = []
    var query = "" { didSet { reload() } }
    var error: String?
    private let library: SnippetLibrary?

    init(dataDir: URL) {
        do { library = try SnippetLibrary.open(dataDir: dataDir.path) } catch {
            library = nil
            self.error = "Snippets could not be read: \(errorText(error))"
        }
        reload()
    }

    func reload() { items = library?.search(query: query) ?? [] }

    @discardableResult
    func put(name: String, text: String, id: String?) -> Bool {
        do { _ = try library?.put(name: name, text: text, id: id); error = nil; reload(); return true } catch { self.error = errorText(error); return false }
    }

    func remove(_ id: String) {
        do { try library?.remove(id: id); reload() } catch { self.error = errorText(error) }
    }

    /// Sends a stored snippet through the core (`SnippetLibrary.send`): pasted into the focused
    /// tab and broadcast members, audited by name and tab count. Without `confirmed`, a multi-line
    /// snippet or a send to several tabs comes back `.needsConfirm` and nothing is sent. Each
    /// target then gets Return so the snippet runs as a command, as before.
    func send(_ s: SnippetView, sessions: SessionsModel, confirmed: Bool) -> SnippetSend? {
        let targets = sessions.snippetTargets
        guard let library, !targets.isEmpty else { error = "No session to send to."; return nil }
        do {
            let r = try library.send(id: s.id, terminals: targets, confirmed: confirmed, audit: sessions.manager)
            if case .sent = r { targets.forEach { try? $0.write(bytes: Data("\r".utf8)) } }
            error = nil
            return r
        } catch {
            self.error = errorText(error)
            return nil
        }
    }
}

struct SnippetsView: View {
    @Environment(SnippetsModel.self) private var snippets
    @Environment(SessionsModel.self) private var sessions
    @Environment(LibraryModel.self) private var library
    private var dismiss = PanelDismiss()
    @AppStorage("snippets.substitute-variables") private var substitute = false
    @State private var showingVariables = false
    @State private var sendError: String?
    @State private var selection: String?
    @State private var editing: SnippetView?
    @State private var adding = false
    @State private var confirming: SnippetView?

    private var selected: SnippetView? { snippets.items.first { $0.id == selection } }

    var body: some View {
        @Bindable var model = snippets
        VStack(spacing: 0) {
            HStack {
                Text("Snippets").font(DS.Font.bodyStrong)
                Spacer()
                TextField("Search", text: $model.query).textFieldStyle(.roundedBorder).frame(width: 200)
            }
            .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            if snippets.items.isEmpty {
                EmptyState(symbol: "text.append", title: snippets.query.isEmpty ? "No snippets" : "No matches",
                           message: "Save commands you type often and send them to a session.") {
                    Button("Add Snippet…") { adding = true }.keyboardShortcut(.defaultAction).dsPrimaryButton()
                }
            } else {
                List(snippets.items, id: \.id, selection: $selection) { s in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(s.name)
                        Text(s.text).font(DS.Font.caption.monospaced()).foregroundStyle(.secondary).lineLimit(s.multiline ? 2 : 1)
                    }
                    .tag(s.id)
                }
            }
            if let e = snippets.error ?? sendError { Text(e).font(DS.Font.caption).foregroundStyle(.red).padding(.horizontal, DS.Space.m) }
            Divider()
            HStack(spacing: DS.Space.xs) {
                Toggle("Replace $Variables$", isOn: $substitute)
                    .help("Fill $Host$, $Username$, $Port$ and the like from the focused session's connection before sending; $$ sends a literal $.")
                Button("Variables", systemImage: "dollarsign.circle") { showingVariables.toggle() }
                    .labelStyle(.iconHitTarget).buttonStyle(.borderless)
                    .iconTip("Variables for the focused session's connection")
                    .disabled(focusedConnection == nil)
                    .popover(isPresented: $showingVariables) { VariablesList(connectionId: focusedConnection ?? "") }
                Spacer()
            }
            .padding(.horizontal, DS.Space.s).padding(.top, DS.Space.xs)
            HStack(spacing: DS.Space.xs) {
                if !snippets.items.isEmpty { Button("Add Snippet…") { adding = true } }
                Group {
                    Button("Edit", systemImage: "pencil") { editing = selected }
                        .iconTip("Edit")
                    Button("Delete", systemImage: "trash") { selected.map { snippets.remove($0.id) } }
                        .iconTip("Delete")
                }
                .labelStyle(.iconHitTarget).buttonStyle(.borderless).disabled(selected == nil)
                Spacer()
                Text(sessions.broadcastTargets.isEmpty ? "Sends to the focused session" : "Sends to \(sessions.broadcastTargets.count) broadcast sessions")
                    .font(DS.Font.caption).foregroundStyle(.secondary)
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                if !snippets.items.isEmpty {
                    Button("Send") { selected.map(send) }.keyboardShortcut(.defaultAction).dsPrimaryButton()
                        .disabled(selected == nil || sessions.selectedTab?.terminal == nil)
                }
            }
            .padding(DS.Space.s)
        }
        .panelFrame(width: DS.Size.managerWidth + 80, height: DS.Size.managerHeight + 40)
        .sheet(isPresented: $adding) { SnippetEditSheet(snippet: nil) }
        .sheet(item: $editing) { SnippetEditSheet(snippet: $0) }
        .confirmationDialog("Send “\(confirming?.name ?? "")”?", isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } })) {
            Button("Send \(confirming?.text.split(whereSeparator: \.isNewline).count ?? 0) Line(s)") { confirming.map { deliver($0, confirmed: true) }; confirming = nil }
        } message: { Text("Each line runs as a command in \(max(1, sessions.broadcastTargets.count)) session(s).") }
    }

    private func send(_ s: SnippetView) {
        // Variables are filled per send, so they are confirmed here; stored text the core confirms.
        if substitute, s.multiline { confirming = s } else { deliver(s, confirmed: false) }
    }

    private func deliver(_ s: SnippetView, confirmed: Bool) {
        guard substitute else {
            switch snippets.send(s, sessions: sessions, confirmed: confirmed) {
            case .needsConfirm: confirming = s
            case .sent: dismiss()
            case nil: sendError = snippets.error
            }
            return
        }
        do {
            sessions.sendToFocused(try SnippetVariables.resolve(s.text, sessions: sessions, library: library))
            dismiss()
        } catch {
            sendError = "\(error)"
        }
    }

    private var focusedConnection: String? { sessions.selectedTab?.connectionId }
}

/// `$Name$` substitution for a snippet (core `vars`), from the focused session's connection.
@MainActor
enum SnippetVariables {
    struct Refused: Error, CustomStringConvertible { let description: String }

    static func resolve(_ text: String, sessions: SessionsModel, library: LibraryModel) throws -> String {
        // Values belong to one connection, so a broadcast would send the wrong host to the others.
        guard sessions.broadcastTargets.isEmpty else { throw Refused(description: "Variables are filled from one connection; stop broadcasting or turn off Replace $Variables$.") }
        guard let id = sessions.selectedTab?.connectionId, let lib = library.library else {
            throw Refused(description: "The focused session has no saved connection to fill variables from.")
        }
        return try lib.substitute(id: id, template: text)
    }
}

/// The `$Name$` variables a snippet can use for one connection (core `vars`); secret ones are
/// listed by name only because sending them is always refused.
private struct VariablesList: View {
    let connectionId: String
    @Environment(LibraryModel.self) private var library

    var body: some View {
        let vars = try? library.library?.variables(id: connectionId)
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            Text("Variables").font(DS.Font.bodyStrong)
            Grid(alignment: .leading, horizontalSpacing: DS.Space.m, verticalSpacing: DS.Space.xxs) {
                ForEach(vars?.plain ?? [], id: \.name) { v in
                    GridRow {
                        Text("$\(v.name)$").font(DS.Font.caption.monospaced())
                        Text(v.value.isEmpty ? "—" : v.value).font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }
            if let secret = vars?.secret, !secret.isEmpty {
                Text("Never sent: " + secret.map { "$\($0)$" }.joined(separator: ", ")).font(DS.Font.caption).foregroundStyle(.secondary)
            }
        }
        .padding(DS.Space.m)
        .frame(minWidth: 280)
    }
}

extension SnippetView: Identifiable {}

struct SnippetEditSheet: View {
    let snippet: SnippetView?
    @Environment(SnippetsModel.self) private var snippets
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var text = ""

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text(snippet == nil ? "Add Snippet" : "Edit Snippet").font(DS.Font.bodyStrong)
            TextField("Name", text: $name).textFieldStyle(.roundedBorder)
            TextEditor(text: $text).font(DS.Font.size(12, design: .monospaced)).frame(height: 120)
                .overlay(RoundedRectangle(cornerRadius: 4).strokeBorder(.separator))
            Text(snippets.error ?? "Keep passwords and keys in the vault; snippets that look like secrets are refused.")
                .font(DS.Font.caption).foregroundStyle(snippets.error == nil ? .secondary : Color.red)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { snippets.error = nil; dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Save") { if snippets.put(name: name, text: text, id: snippet?.id) { dismiss() } }.keyboardShortcut(.defaultAction).dsPrimaryButton()
            }
        }
        .padding(DS.Space.m)
        .frame(width: DS.Size.dialogWidth + 80)
        .onAppear { if let s = snippet { (name, text) = (s.name, s.text) } }
    }
}

/// Choose the sessions that share input, then confirm. While a group is active every member
/// shows a banner and typing in one types in all.
struct BroadcastView: View {
    @Environment(SessionsModel.self) private var sessions
    @Environment(\.dismiss) private var dismiss
    @State private var chosen: Set<UUID> = []
    @State private var confirming = false

    private var candidates: [TerminalTab] { sessions.tabs.filter { $0.terminal != nil && !$0.ended } }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("Broadcast Input").font(DS.Font.bodyStrong)
            Text("Everything typed in one of these sessions is typed in all of them.").font(DS.Font.caption).foregroundStyle(.secondary)
            if candidates.count < 2 {
                Text("Open at least two terminal sessions first.").foregroundStyle(.secondary)
            } else {
                ForEach(candidates) { tab in
                    Toggle(tab.name, isOn: Binding(get: { chosen.contains(tab.id) }, set: { on in if on { chosen.insert(tab.id) } else { chosen.remove(tab.id) } }))
                }
            }
            HStack {
                if !sessions.broadcastTargets.isEmpty { Button("Stop Broadcast", role: .destructive) { sessions.stopBroadcast(); dismiss() } }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Start…") { confirming = true }.keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(chosen.count < 2)
            }
        }
        .padding(DS.Space.m)
        .frame(width: DS.Size.dialogWidth + 40)
        .onAppear { chosen = sessions.broadcastTargets.isEmpty ? Set(candidates.map(\.id)) : sessions.broadcastTargets }
        .confirmationDialog("Broadcast to \(chosen.count) sessions?", isPresented: $confirming) {
            Button("Start Broadcast") { sessions.startBroadcast(chosen); dismiss() }
        } message: {
            Text(candidates.filter { chosen.contains($0.id) }.map(\.name).joined(separator: ", ") + ". Commands you type will run on every one of these hosts.")
        }
    }
}

/// Shown above the tabs while a broadcast group is active.
struct BroadcastBanner: View {
    @Environment(SessionsModel.self) private var sessions
    var body: some View {
        if !sessions.broadcastTargets.isEmpty {
            HStack(spacing: DS.Space.s) {
                Image(systemName: "dot.radiowaves.left.and.right").foregroundStyle(.orange)
                Text("Broadcasting input to \(sessions.broadcastTargets.count) sessions: \(sessions.tabs.filter { sessions.broadcastTargets.contains($0.id) }.map(\.name).joined(separator: ", "))")
                    .font(DS.Font.caption).lineLimit(1)
                Spacer()
                Button("Stop") { sessions.stopBroadcast() }.controlSize(.small)
            }
            .padding(.horizontal, DS.Space.s).padding(.vertical, DS.Space.xxs)
            .background(Color.orange.opacity(0.15))
        }
    }
}
