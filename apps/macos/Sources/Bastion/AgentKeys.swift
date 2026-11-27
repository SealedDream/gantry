import AppKit
import SwiftUI
import BastionCore

/// Bastion's own SSH agent (core `keyagent`): key files the user adds are served to `ssh`, `git`
/// and other tools on an owner-only socket. Only comments and fingerprints reach the UI.
@MainActor @Observable
final class AgentKeysModel {
    static let shared = AgentKeysModel(dataDir: LibraryModel.dataDir)

    private(set) var status = AgentStatus(running: false, socket: nil, confirm: false, keys: [])
    var error: String?
    /// UI tests: a key-tool sheet to open filled in and run (`key-tool` driver step), and its outcome.
    var driverKeyTool: KeyToolRequest?
    var driverKeyToolResult: String?
    private let service: KeyAgentService?

    init(dataDir: URL) {
        do { service = try KeyAgentService(dataDir: dataDir.path) } catch {
            service = nil
            self.error = "The SSH agent could not start: \(errorText(error))"
        }
        status = service?.status() ?? status
    }

    func needsPassphrase(_ path: String) -> Bool { service?.needsPassphrase(path: path) ?? false }

    @discardableResult
    func add(_ path: String, passphrase: String?) async -> Bool {
        await run { try $0.addKeyFile(path: path, passphrase: passphrase) }
    }

    func remove(_ fingerprint: String) async { await run { try $0.removeKey(fingerprint: fingerprint) } }

    func setConfirm(_ on: Bool) async { await run { try $0.setConfirm(handler: on ? AgentConfirmDialog() : nil) } }

    func stop() {
        if let s = service?.stop() { status = s }
    }

    @discardableResult
    private func run(_ body: @escaping @Sendable (KeyAgentService) throws -> AgentStatus) async -> Bool {
        guard let service else { return false }
        switch await Task.detached(operation: { Result { try body(service) } }).value {
        case .success(let s):
            status = s
            error = nil
            return true
        case .failure(let e):
            error = errorText(e)
            status = service.status()
            return false
        }
    }
}

/// "Allow a program to sign with …?" on the main thread; the agent's task waits for the answer.
final class AgentConfirmDialog: AgentConfirm, @unchecked Sendable {
    func allow(comment: String, fingerprint: String) -> Bool {
        if TestHooks.isScripted { return false }
        return DispatchQueue.main.sync {
            let alert = NSAlert()
            alert.messageText = "Allow a program to sign with \(comment)?"
            alert.informativeText = fingerprint
            alert.addButton(withTitle: "Allow")
            alert.addButton(withTitle: "Deny")
            QuietLaunch.activate()
            return alert.runModalInFront() == .alertFirstButtonReturn
        }
    }
}

struct AgentKeysView: View {
    private var dismiss = PanelDismiss()
    @State private var agent = AgentKeysModel.shared
    @State private var selection: String?
    @State private var pendingPath: String?
    @State private var passphrase = ""
    @State private var keyTool: KeyToolMode?

    var body: some View {
        VStack(spacing: 0) {
            Text("SSH Agent").font(DS.Font.bodyStrong)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            if agent.status.keys.isEmpty {
                Text("No keys. Add a key file to serve it to ssh, git and other tools.")
                    .font(DS.Font.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 80)
            } else {
                Table(agent.status.keys, selection: $selection) {
                    TableColumn("Key") { (k: AgentKeyView) in Text(k.comment.isEmpty ? (k.file as NSString).lastPathComponent : k.comment) }
                    TableColumn("Fingerprint") { (k: AgentKeyView) in
                        Text("\(k.algorithm) \(k.fingerprint)").font(DS.Font.style(.body, design: .monospaced)).foregroundStyle(.secondary)
                    }
                }
                .frame(minHeight: 140)
            }
            Divider()
            Form {
                Toggle("Confirm each use", isOn: Binding(get: { agent.status.confirm }, set: { on in Task { await agent.setConfirm(on) } }))
                    .help("Ask before every signature")
                if let sock = agent.status.socket {
                    LabeledContent("SSH_AUTH_SOCK") {
                        HStack {
                            Text(sock).font(DS.Font.style(.caption, design: .monospaced)).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                            Button("Copy") {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString("export SSH_AUTH_SOCK=\(sock)", forType: .string)
                            }
                        }
                    }
                } else {
                    LabeledContent("Status", value: "Not running")
                }
                if let e = agent.error { Text(e).foregroundStyle(.red) }
            }
            .formStyle(.grouped)
            .scrollDisabled(true)
            .fixedSize(horizontal: false, vertical: true)
            Divider()
            HStack {
                Button("Add Key…", action: chooseKey)
                Button("Remove") { if let fp = selection { Task { await agent.remove(fp) }; selection = nil } }
                    .disabled(selection == nil)
                Button("Remove All") { agent.stop() }.disabled(agent.status.keys.isEmpty)
                Spacer()
                Menu("Keys") {
                    Button("Generate Key…") { keyTool = .generate }
                    Button("Inspect Key…") { keyTool = .inspect }
                    Button("Convert Key…") { keyTool = .convert }
                }
                .fixedSize().help("Generate, inspect or convert a key file")
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
            }
            .padding(DS.Space.s)
        }
        .panelFrame(width: 620)
        .sheet(item: $keyTool, onDismiss: { agent.driverKeyTool = nil }) { KeyToolSheet(mode: $0, request: agent.driverKeyTool) }
        .onChange(of: agent.driverKeyTool?.id) { _, id in if id != nil { keyTool = agent.driverKeyTool?.mode } }
        .alert("Passphrase", isPresented: Binding(get: { pendingPath != nil }, set: { if !$0 { pendingPath = nil } })) {
            SecureField("Passphrase", text: $passphrase)
            Button("Add") { add(pendingPath ?? "", passphrase) }
            Button("Cancel", role: .cancel) { passphrase = "" }
        } message: { Text("\(URL(fileURLWithPath: pendingPath ?? "").lastPathComponent) is encrypted.") }
    }

    private func chooseKey() {
        let panel = NSOpenPanel()
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        panel.showsHiddenFiles = true
        guard panel.runModal() == .OK, let path = panel.url?.path else { return }
        if agent.needsPassphrase(path) { passphrase = ""; pendingPath = path } else { add(path, nil) }
    }

    private func add(_ path: String, _ pass: String?) {
        Task {
            await agent.add(path, passphrase: pass)
            passphrase = ""
        }
    }
}

extension AgentKeyView: Identifiable {
    public var id: String { fingerprint }
}
