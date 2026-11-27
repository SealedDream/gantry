import AppKit
import SwiftUI
import BastionCore

/// Run one approved command on several SSH connections (core `multiexec`): choose hosts, type the
/// command, confirm (with an extra acknowledgement when production or other sensitive hosts are
/// included), then follow each host's state, exit code and output; cancel, retry failures, export.
struct MultiExecView: View {
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @Environment(Commands.self) private var commands
    private var dismiss = PanelDismiss()
    @State private var chosen: Set<String> = []
    @State private var command = ""
    @State private var concurrency = 4
    @State private var username = ""
    @State private var useAgent = false
    @State private var password = ""
    @State private var review: ExecReviewView?
    @State private var confirming = false
    @State private var productionAck = false
    @State private var run: MultiExec?
    @State private var results: [HostResultView] = []
    @State private var ranIds: [String] = []
    @State private var problem: String?
    @State private var saved = false
    private let timer = Timer.publish(every: 0.5, on: .main, in: .common).autoconnect()

    /// Set by the UI driver to choose hosts without clicking each checkbox.
    @MainActor static var scriptedHosts: [String]?
    /// Connection ids to start with, set by the folder dashboard's Run Task… and used once.
    @MainActor static var presetHosts: [String]?
    /// UI driver: the hosts chosen at the last review.
    @MainActor static var lastChosen: [String] = []
    /// UI driver: tick the sensitive-host acknowledgement (as the toggle does).
    @MainActor static var scriptedAck = false
    /// The latest run, for the UI driver to read results.
    @MainActor static weak var current: MultiExec?

    private var hosts: [ConnectionView] { AppIpc.connections(in: model.tree).filter { $0.protocol == "ssh" } }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Run Command on Hosts").font(DS.Font.bodyStrong).padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            if run != nil { progress } else if confirming { confirmation } else { setup }
            if let problem { Text(problem).font(DS.Font.caption).foregroundStyle(.red).padding(.horizontal, DS.Space.m).padding(.top, DS.Space.xs) }
            Divider()
            HStack {
                if let run {
                    Button("Cancel Run") { run.cancel() }.disabled(run.isFinished())
                    Button("Retry Failed") { run.retryFailed() }.disabled(!run.isFinished())
                    Menu("Export") {
                        Button("JSON…") { export("json") }
                        Button("CSV…") { export("csv") }
                    }
                    .fixedSize()
                }
                Spacer()
                if confirming && run == nil {
                    Button("Back") { confirming = false }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                    Button("Run Now", action: start).keyboardShortcut(.defaultAction).dsPrimaryButton()
                } else {
                    Button("Done") { run?.cancel(); dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                    Button(saved ? "Saved" : "Save as Task", action: saveAsTask).dsSecondaryButton()
                        .disabled(saved || command.trimmingCharacters(in: .whitespaces).isEmpty)
                        .help("Save this command as a task (runs over SSH).")
                    if run == nil { Button("Run…", action: startReview).keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(chosen.isEmpty || command.trimmingCharacters(in: .whitespaces).isEmpty) }
                }
            }
            .padding(DS.Space.s)
        }
        .panelFrame(width: 860, height: 600)
        .onAppear {
            if let s = Self.scriptedHosts { chosen = Set(hosts.filter { s.contains($0.name) }.map(\.id)) }
            if let p = Self.presetHosts { chosen = Set(hosts.map(\.id).filter(p.contains)); Self.presetHosts = nil }
        }
        .onReceive(timer) { _ in if let run { results = run.results() } }
    }

    /// Second step: exactly what will run, where, as whom; sensitive hosts in red.
    private var confirmation: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("Run this command on \(chosen.count) hosts?").font(DS.Font.bodyStrong)
            Text(command.trimmingCharacters(in: .whitespaces)).font(DS.Font.size(13, design: .monospaced))
                .padding(DS.Space.s).frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 4).fill(.quaternary))
            ForEach(hosts.filter { chosen.contains($0.id) }, id: \.id) { h in
                let sensitive = review?.sensitive.contains(h.name) == true
                Label("\(h.name) — \(h.host)\(sensitive ? " (sensitive)" : "")", systemImage: sensitive ? "exclamationmark.triangle.fill" : "server.rack")
                    .foregroundStyle(sensitive ? .red : .primary)
            }
            Text("Up to \(concurrency) at a time. Each host's output and exit code are kept; you can cancel, retry failures and export.")
                .font(DS.Font.caption).foregroundStyle(.secondary)
            Spacer()
        }
        .padding(DS.Space.m)
    }

    private var setup: some View {
        HStack(alignment: .top, spacing: 0) {
            List(hosts, id: \.id) { h in
                Toggle(isOn: Binding(get: { chosen.contains(h.id) }, set: { on in if on { chosen.insert(h.id) } else { chosen.remove(h.id) } })) {
                    VStack(alignment: .leading) { Text(h.name); Text(h.host).font(DS.Font.caption).foregroundStyle(.secondary) }
                }
            }
            .frame(width: 260)
            Divider()
            Form {
                TextField("Command", text: $command, prompt: Text("uptime"))
                Stepper("At a time: \(concurrency)", value: $concurrency, in: 1...16)
                if withoutCredential.isEmpty {
                    Text(chosen.isEmpty ? "" : "Saved credentials").foregroundStyle(.secondary)
                        .help("Each chosen host signs in with its own saved credential.")
                } else {
                    TextField("User", text: $username)
                        .help(signInHelp)
                    Toggle("Use SSH agent", isOn: $useAgent)
                    if !useAgent {
                        SecureField("Password", text: $password).help(signInHelp)
                    }
                }
                if review?.needsProductionAck == true {
                    Toggle("I understand this includes sensitive hosts: \(review?.sensitive.joined(separator: ", ") ?? "")", isOn: $productionAck)
                        .foregroundStyle(.red)
                }
                Text("One line, run exactly as typed. Hosts must already be trusted (connect once to verify their keys).")
                    .font(DS.Font.caption).foregroundStyle(.secondary)
            }
            .formStyle(.grouped)
        }
    }

    private var progress: some View {
        TaskResultsGrid(rows: gridRows, openInTerminal: { id in dismiss(); commands.openTaskHost(id) },
                        openAll: { ids in dismiss(); commands.openTaskHostsBroadcast(ids) })
    }

    /// Core results by host name, mapped back to the chosen connections (same order).
    private var gridRows: [TaskGridRow] {
        let chosenHosts = hosts.filter { ranIds.contains($0.id) }
        return zip(chosenHosts, results).map { c, r in
            TaskGridRow(id: c.id, host: r.host, state: r.state, exit: r.exit.map(Int.init), stdout: r.stdout, stderr: r.stderr, error: r.error, millis: r.millis)
        }
    }

    /// Chosen hosts without a saved credential: only they use the typed user and password (or the
    /// agent). The core signs every other host in with its own saved credential.
    private var withoutCredential: [ConnectionView] { hosts.filter { chosen.contains($0.id) && $0.credentialId == nil } }

    private var signInHelp: String {
        let names = withoutCredential.map(\.name)
        return "For hosts without a saved credential: " + names.prefix(5).joined(separator: ", ") + (names.count > 5 ? " and \(names.count - 5) more" : "")
    }

    private var login: SshLogin {
        if useAgent || withoutCredential.isEmpty { return .agent }
        return .password(password: password)
    }

    /// Save the command as a custom task run over SSH (`sh -c <command>`), for Tasks and Run on….
    private func saveAsTask() {
        guard let library = model.library else { return }
        let line = command.trimmingCharacters(in: .whitespaces)
        let t = TaskView(id: "", name: String(line.prefix(60)), favorite: false, builtin: false, kind: "custom",
                         program: "sh", args: ["-c", line], runOn: "ssh", timeoutSecs: 60)
        do {
            let id = try library.saveTask(task: t)
            try library.trustTask(taskId: id, dataDir: LibraryModel.dataDir.path)
            model.mutate { _ in }
            problem = nil
            saved = true
        } catch { problem = errorText(error) }
    }

    private func startReview() {
        guard let lib = model.library else { return }
        if Self.scriptedAck { productionAck = true; Self.scriptedAck = false }
        Self.lastChosen = hosts.filter { chosen.contains($0.id) }.map(\.name)
        do {
            review = try reviewExec(library: lib, connectionIds: Array(chosen), command: command, concurrency: UInt32(concurrency))
            problem = nil
            if review?.needsProductionAck == true && !productionAck {
                problem = "Sensitive hosts are included: tick the acknowledgement first."
                return
            }
            confirming = true
        } catch { problem = errorText(error) }
    }

    func start() {
        guard let lib = model.library else { return }
        do {
            ranIds = hosts.filter { chosen.contains($0.id) }.map(\.id)
            let r = try sessions.multiExec(library: lib, ids: ranIds, command: command,
                                           concurrency: UInt32(concurrency), username: username, login: login, productionAck: productionAck)
            r.run()
            run = r
            Self.current = r
            password = ""
        } catch { problem = errorText(error) }
    }

    private func export(_ format: String) {
        guard let run, let text = try? run.export(format: format) else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "bastion-run.\(format)"
        if panel.runModal() == .OK, let url = panel.url {
            do { try text.write(to: url, atomically: true, encoding: .utf8) } catch { problem = errorText(error) }
        }
    }
}
