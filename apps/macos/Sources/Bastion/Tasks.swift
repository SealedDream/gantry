import AppKit
import SwiftUI
import BastionCore

/// Tasks (Royal TS): built-in checks and saved commands run against a connection. The core turns
/// each into an argument vector, applies the policy and writes the audit record; this file only
/// asks for confirmation when the core says so and shows the output in its own tab.
struct TaskEditRequest: Identifiable {
    let id = UUID()
    var task: TaskView
}

extension Commands {
    /// Run `task` against `connectionId` (the last connection selected in the tree).
    func runTask(_ task: TaskView, on connectionId: String?) {
        guard let connectionId, let conn = model.connection(id: connectionId) else {
            sessions.error = "Select a connection in the library first, then run “\(task.name)” on it."
            return
        }
        Task { @MainActor in _ = await self.launchTask(task, on: conn) }
    }

    /// Start `task` on `conn` in its own tab, after the Production confirmation and the SSH
    /// password when they apply. Nil when the user cancelled or the core refused it (reported).
    func launchTask(_ task: TaskView, on conn: ConnectionView) async -> TaskRun? {
        guard let library = model.library else { return nil }
        guard let answers = await Self.askTaskAnswers(task, library: library) else { return nil }
        guard let review = try? reviewTask(library: library, taskId: task.id, connectionId: conn.id, answers: answers) else {
            // Refused (for example a secret variable): starting reports and audits the same error.
            return startTask(task, on: conn, login: .agent, confirmed: false, answers: answers)
        }
        // SSH tasks sign in like Run on Hosts: the connection's vault credential, else a password
        // asked for here (a sheet, never stored), else the SSH agent.
        let overSsh = task.kind == "custom" && task.runOn == "ssh"
        if review.needsConfirmation {
            let alert = NSAlert()
            alert.messageText = "Run “\(task.name)” on \(conn.name)?"
            alert.informativeText = "\(conn.name) is marked sensitive (for example production).\n\n\(review.display)"
            alert.alertStyle = .warning
            alert.addButton(withTitle: "Run")
            alert.addButton(withTitle: "Cancel").keyEquivalent = "\u{1b}"
            guard await Self.present(alert) == .alertFirstButtonReturn else { return nil }
        }
        var login: SshLogin = .agent
        if let cred = conn.credentialId {
            login = .vault(credentialId: cred)
        } else if overSsh {
            guard let asked = await Self.askPassword(for: conn) else { return nil }
            login = asked
        }
        return startTask(task, on: conn, login: login, confirmed: review.needsConfirmation, answers: answers)
    }

    @discardableResult
    private func startTask(_ task: TaskView, on conn: ConnectionView, login: SshLogin, confirmed: Bool, answers: [String: String]) -> TaskRun? {
        guard let library = model.library else { return nil }
        guard let manager = sessions.manager else { sessions.error = "The session manager could not start."; return nil }
        do {
            let run = try TaskRun.start(manager: manager, library: library, taskId: task.id, connectionId: conn.id,
                                        username: conn.username ?? "", login: login, confirmed: confirmed, answers: answers)
            sessions.add(TerminalTab(name: "\(task.name) · \(conn.name)", content: .task(run)))
            return run
        } catch {
            sessions.error = "\(error)"
            return nil
        }
    }

    /// Show `alert` as a sheet on the main window (so it never blocks the run loop), modal otherwise.
    static func present(_ alert: NSAlert) async -> NSApplication.ModalResponse {
        guard let window = NSApp.mainWindow ?? NSApp.keyWindow ?? NSApp.windows.first(where: { $0.isVisible && $0.canBecomeMain }) else {
            return alert.runModalInFront()
        }
        return await withCheckedContinuation { done in alert.beginSheetModal(for: window) { done.resume(returning: $0) } }
    }

    /// A password for an SSH task on a connection without a saved credential; "Use SSH Agent" skips it.
    static func askPassword(for conn: ConnectionView) async -> SshLogin? {
        let alert = NSAlert()
        alert.messageText = "Password for \(conn.username ?? "")@\(conn.host)"
        alert.informativeText = "\(conn.name) has no saved credential. The password is used for this task only."
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        alert.accessoryView = field
        alert.addButton(withTitle: "Run")
        alert.addButton(withTitle: "Cancel").keyEquivalent = "\u{1b}"
        alert.addButton(withTitle: "Use SSH Agent")
        alert.window.initialFirstResponder = field
        switch await present(alert) {
        case .alertFirstButtonReturn: return .password(password: field.stringValue)
        case .alertThirdButtonReturn: return .agent
        default: return nil
        }
    }

    /// Run the hooks for `connectionId` at `when` (`after_connect`, `after_disconnect`), folder
    /// hooks first (core `hooks_for`), without waiting for them. Before-connect hooks go through
    /// `gateBeforeConnect`. A local-program task that came in a document and was never saved in
    /// Tasks on this Mac is refused (trust rule T01). In a Connect All run (`batch`), a multi-host
    /// hook runs once for the run.
    func runHooks(_ when: String, for connectionId: String, batch: HookBatch? = nil) {
        let tasks = model.library?.tasks() ?? []
        for r in runnableHooks(when, for: connectionId) {
            let task = tasks.first { $0.id == r.hook.taskId }
            switch r.hook.target {
            case "snippet": sendHookSnippet(r.hook.snippetId ?? "", to: connectionId)
            case "multi_host":
                guard let task, batch?.claim(ownerId: r.ownerId, taskId: task.id, when: when) ?? true else { continue }
                // Set on the folder by the user: run on every host in it, subfolders included.
                for id in multiHostTargets(r) { runTask(task, on: id) }
            default:
                if let task { runTask(task, on: connectionId) }
            }
        }
    }

    /// The hooks that may run now, in core order; untrusted ones are reported and left out.
    private func runnableHooks(_ when: String, for connectionId: String) -> [ResolvedHookView] {
        guard let library = model.library,
              let hooks = try? library.resolvedTaskHooks(connectionId: connectionId, when: when, dataDir: LibraryModel.dataDir.path)
        else { return [] }
        let tasks = library.tasks()
        return hooks.filter { r in
            if r.untrusted {
                let name = tasks.first { $0.id == r.hook.taskId }?.name ?? "Task"
                sessions.error = "“\(name)” came from a document and runs a local program. Open it in Tasks and save it to allow it as a hook."
                return false
            }
            return r.runnable
        }
    }

    private func multiHostTargets(_ r: ResolvedHookView) -> [String] {
        DashboardRows.connections(under: model.folder(id: r.ownerId)).keys.sorted()
    }

    /// Before-connect hooks (B5): each task runs in its own tab and the connect waits for it,
    /// with "Running <task>…" and Cancel at the foot of the window. A task that fails, times out
    /// or is cancelled stops the connect; its tab keeps the output and the user is told why.
    /// `connect` runs at once when there is nothing to wait for, so a connect without hooks is
    /// as fast as before.
    func gateBeforeConnect(_ connectionId: String, batch: HookBatch? = nil, then connect: @escaping () -> Void) {
        let hooks = runnableHooks("before_connect", for: connectionId).filter { $0.hook.target != "snippet" }
        guard !hooks.isEmpty else { return connect() }
        Task { @MainActor in
            if await self.awaitBeforeConnect(hooks, connectionId: connectionId, batch: batch) { connect() }
        }
    }

    private func awaitBeforeConnect(_ hooks: [ResolvedHookView], connectionId: String, batch: HookBatch?) async -> Bool {
        let tasks = model.library?.tasks() ?? []
        let connName = model.connection(id: connectionId)?.name ?? "the connection"
        for r in hooks {
            guard let task = tasks.first(where: { $0.id == r.hook.taskId }) else { continue }
            var targets = [connectionId]
            if r.hook.target == "multi_host" {
                guard batch?.claim(ownerId: r.ownerId, taskId: task.id, when: "before_connect") ?? true else { continue }
                targets = multiHostTargets(r)
            }
            for id in targets {
                guard let conn = model.connection(id: id) else { continue }
                guard let run = await launchTask(task, on: conn) else {
                    sessions.error = "Not connected to \(connName): before-connect task “\(task.name)” did not start."
                    return false
                }
                let out = await waitForHook(run, task: task.name)
                if case .stop(let why) = HookGate.verdict(task: task.name, connection: connName, state: out.state, exit: out.exit,
                                                          stdout: out.stdout, stderr: out.stderr, error: out.error) {
                    sessions.error = why
                    return false
                }
            }
        }
        return true
    }

    /// Poll `run` until it ends, showing the gate bar meanwhile. The task's own timeout bounds it.
    private func waitForHook(_ run: TaskRun, task: String) async -> TaskRunView {
        let gate = HookGateState(task: task, run: run)
        hookGates.append(gate)
        defer { hookGates.removeAll { $0.id == gate.id } }
        while !run.isFinished() {
            try? await Task.sleep(for: Self.hookPollInterval)
        }
        return run.output()
    }

    static let hookPollInterval = Duration.milliseconds(200)

    /// An after-connect snippet hook: sent to the connection's new session. A multi-line snippet
    /// still needs its confirmation, so it is not sent and the user is told.
    private func sendHookSnippet(_ snippetId: String, to connectionId: String) {
        guard let terminal = sessions.liveTab(for: connectionId)?.terminal else { return }
        do {
            let store = try SnippetLibrary.open(dataDir: LibraryModel.dataDir.path)
            switch try store.send(id: snippetId, terminals: [terminal], confirmed: false, audit: sessions.manager) {
            case .sent: try? terminal.write(bytes: Data("\r".utf8))
            default: sessions.error = "A multi-line snippet hook needs confirmation. Send it from Snippets."
            }
        } catch {
            sessions.error = "Snippet hook: \(errorText(error))"
        }
    }

    func newTask() {
        editingTask = TaskEditRequest(task: TaskView(id: "", name: "", favorite: false, builtin: false, kind: "custom",
                                                     program: "", args: [], runOn: "local", timeoutSecs: 60))
    }
}

/// Context-menu entries for task rows, the Tasks folder and connection rows.
@MainActor
enum TaskMenus {
    static func fillTaskMenu(_ menu: NSMenu, task: TaskView?, connectionId: String?, commands: Commands) {
        menu.removeAllItems()
        if let task {
            let target = connectionId.flatMap(commands.model.connection(id:))?.name
            let run = ClosureMenuItem(title: target.map { "Run on \($0)" } ?? "Run (select a connection first)") { commands.runTask(task, on: connectionId) }
            run.isEnabled = target != nil
            menu.addItem(run)
            menu.addItem(ClosureMenuItem(title: "Run on…") { commands.runOnTask = TaskRunOnRequest(task: task) })
            menu.addItem(.separator())
            menu.addItem(ClosureMenuItem(title: task.favorite ? "Remove from Favorites" : "Add to Favorites") {
                commands.model.mutate { try $0.setTaskFavorite(taskId: task.id, favorite: !task.favorite) }
            })
            if !task.builtin {
                menu.addItem(ClosureMenuItem(title: "Edit Task…") { commands.editingTask = TaskEditRequest(task: task) })
                menu.addItem(ClosureMenuItem(title: "Delete Task") { commands.model.mutate { try $0.removeTask(taskId: task.id) }; TaskRunOnChoice.forget(taskId: task.id) })
            }
            else {
                // A built-in edits in place (owner round 4): saved under its own id as a custom
                // task; Restore Default drops the edit. Edit a Copy stays (owner round 3, item 9).
                menu.addItem(ClosureMenuItem(title: "Edit…") {
                    var edit = task
                    edit.kind = "custom"
                    commands.editingTask = TaskEditRequest(task: edit)
                })
                if task.kind == "custom" {
                    menu.addItem(ClosureMenuItem(title: "Restore Default") { commands.model.mutate { try $0.removeTask(taskId: task.id) } })
                }
                menu.addItem(ClosureMenuItem(title: "Edit a Copy…") {
                    commands.editingTask = TaskEditRequest(task: TaskView(id: "", name: "\(task.name) copy", favorite: false, builtin: false,
                                                                          kind: "custom", program: task.program, args: task.args,
                                                                          runOn: task.runOn, timeoutSecs: task.timeoutSecs))
                })
            }
            menu.addItem(.separator())
        }
        menu.addItem(ClosureMenuItem(title: "New Task…") { commands.newTask() })
    }

    /// "Run Task ›" and "Run Command on Hosts…" for a folder or a selection.
    static func appendScopeItems(_ menu: NSMenu, preset: TaskRunOnChoice, commands: Commands) {
        menu.addItem(.separator())
        let entry = NSMenuItem(title: "Run Task", action: nil, keyEquivalent: "")
        let sub = NSMenu(title: "Run Task")
        for t in commands.model.tasks.sorted(by: { $0.favorite && !$1.favorite }) {
            sub.addItem(ClosureMenuItem(title: t.name) { commands.runOnTask = TaskRunOnRequest(task: t, preset: preset, autoStart: true) })
        }
        entry.submenu = sub
        menu.addItem(entry)
        menu.addItem(ClosureMenuItem(title: "Run Command on Hosts…") {
            let ids = preset.folderId.flatMap(commands.model.folder(id:)).map { AppIpc.connections(in: $0).map(\.id) } ?? preset.hostIds
            MultiExecView.presetHosts = ids
            commands.panel = .runOnHosts
        })
    }

    /// "Run Task ›" (favourites first) and "Attached Tasks…" on a connection's menu.
    static func appendConnectionItems(_ menu: NSMenu, connectionId: String, commands: Commands) {
        let tasks = commands.model.tasks.sorted { $0.favorite && !$1.favorite }
        menu.addItem(.separator())
        let entry = NSMenuItem(title: "Run Task", action: nil, keyEquivalent: "")
        let sub = NSMenu(title: "Run Task")
        for t in tasks {
            let item = ClosureMenuItem(title: t.name) { commands.runTask(t, on: connectionId) }
            item.image = t.favorite ? NSImage(systemSymbolName: "star.fill", accessibilityDescription: "favorite") : nil
            sub.addItem(item)
        }
        entry.submenu = sub
        menu.addItem(entry)
        menu.addItem(ClosureMenuItem(title: "Attached Tasks…") { commands.taskHooks = ParentTarget(id: connectionId) })
    }
}

/// A task's output tab: the command, live state and exit status, with Cancel while it runs.
/// Polls the run only while it is running, so a finished tab costs nothing.
struct TaskOutputView: View {
    let run: TaskRun
    @State private var output: TaskRunView?
    /// Pause keeps the shown output still while the task keeps running.
    @State private var paused = false
    @State private var frozen = ""
    @State private var snippetStatus: (message: String, isError: Bool)?

    private var isRunning: Bool { output?.state ?? "running" == "running" }

    private var status: String {
        guard let o = output else { return "Starting…" }
        let secs = String(format: "%.1f s", Double(o.millis) / 1000)
        switch o.state {
        case "running": return "Running…"
        case "done": return o.exit.map { "Exit status \($0) · \(secs)" } ?? "Finished · \(secs)"
        case "timed_out": return "Timed out · \(secs)"
        case "cancelled": return "Cancelled · \(secs)"
        default: return "Failed · \(secs)"
        }
    }

    private var failed: Bool { output.map { $0.state != "running" && !($0.state == "done" && $0.exit == 0) } ?? false }

    private var text: String {
        guard let o = output else { return "" }
        return [o.stdout, o.stderr, o.error.map { "Error: \($0)" } ?? ""].filter { !$0.isEmpty }.joined(separator: "\n")
    }

    private var shownText: String { paused && isRunning ? frozen : text }

    private func saveSnippet() {
        let title = "Task \(run.display())"
        if let r = LogSnippet.save([shownText], name: "task-output", header: LogSnippet.header(title)) { snippetStatus = r }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: DS.Space.s) {
                Text(run.display())
                    .font(DS.Font.style(.callout, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                Spacer()
                if isRunning { ProgressView().controlSize(.small) }
                if isRunning {
                    Toggle("Pause View", isOn: $paused).toggleStyle(.button).help("Hold the shown output while the task keeps running")
                        .onChange(of: paused) { frozen = paused ? text : "" }
                }
                Button("Copy All") { LogSnippet.copy([shownText]) }.disabled(shownText.isEmpty)
                Button("Save Snippet…") { saveSnippet() }.disabled(shownText.isEmpty)
                Text(status).foregroundStyle(failed ? .red : .secondary).accessibilityIdentifier("task-status")
                if isRunning { Button("Cancel") { run.cancel() }.keyboardShortcut(".", modifiers: .command).help("Stop the task (⌘.)") }
            }
            .padding(.horizontal, DS.Space.m)
            .padding(.vertical, DS.Space.xs)
            if let snippetStatus {
                Text(snippetStatus.message).font(DS.Font.caption).foregroundStyle(snippetStatus.isError ? .red : .secondary)
                    .padding(.horizontal, DS.Space.m).padding(.bottom, DS.Space.xs)
                    .accessibilityIdentifier("log-snippet-status")
            }
            Divider()
            ScrollView {
                Text(shownText)
                    .font(DS.Font.style(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(DS.Space.m)
            }
            .contextMenu {
                Button("Copy All") { LogSnippet.copy([shownText]) }
                Button("Save Snippet…") { saveSnippet() }
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .logCopyVisible)) { _ in LogSnippet.copy([shownText]) }
        .onReceive(NotificationCenter.default.publisher(for: .logSaveSnippet)) { _ in saveSnippet() }
        .task {
            while !Task.isCancelled {
                output = run.output()
                if run.isFinished() { break }
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
    }
}

/// New or edited custom task: a program and one argument per line, each may use `$Host$`,
/// `$Port$`, `$Username$`, `$Name$` and `$Meta.key$`. Secrets cannot be substituted.
struct TaskEditorSheet: View {
    @Environment(LibraryModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let request: TaskEditRequest
    @State private var name = ""
    @State private var program = ""
    @State private var args = ""
    @State private var runOn = "local"
    @State private var timeout = 60
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.m) {
            Text(request.task.id.isEmpty ? "New Task" : "Edit Task").font(DS.Font.headline)
            Form {
                TextField("Name", text: $name)
                TextField("Program", text: $program, prompt: Text("/usr/bin/curl"))
                LabeledContent("Arguments") {
                    TextEditor(text: $args).font(DS.Font.style(.body, design: .monospaced)).frame(minHeight: 80)
                }
                Picker("Run on", selection: $runOn) {
                    Text("This Mac").tag("local")
                    Text("The connection (SSH)").tag("ssh")
                }
                Stepper("Timeout: \(timeout) s", value: $timeout, in: 1...3600, step: 5)
            }
            Text(verbatim: "One per line · $Host$ $Port$ $Username$ $Name$ $Meta.key$ $Ask:Label$")
                .font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1)
                .help("$Ask:Label$ asks for a value once per run, used on every host. $$ is a literal $. Arguments are passed as they are, without a shell.")
            if let error { Text(error).foregroundStyle(.red).font(DS.Font.caption) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Save") { save() }.keyboardShortcut(.defaultAction).dsPrimaryButton()
            }
        }
        .padding(DS.Space.l)
        .frame(width: 460)
        .onAppear {
            let t = request.task
            name = t.name; program = t.program; args = t.args.joined(separator: "\n"); runOn = t.runOn; timeout = Int(t.timeoutSecs)
        }
    }

    private func save() {
        guard let library = model.library else { return }
        var t = request.task
        t.name = name; t.program = program; t.runOn = runOn; t.timeoutSecs = UInt32(timeout)
        t.args = args.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
        do {
            let id = try library.saveTask(task: t)
            // Saved by the user here: this exact content may run as a hook (T01).
            try library.trustTask(taskId: id, dataDir: LibraryModel.dataDir.path)
            model.mutate { _ in }
            dismiss()
        } catch {
            self.error = "\(error)"
        }
    }
}

/// Tasks run before or after this connection connects (the property dialog's Tasks page).
/// Hooks on a connection or a folder (B5). A folder's hooks run for every connection inside,
/// before the connection's own; "All hosts" runs the task on every host in the folder.
struct TaskHooksSheet: View {
    @Environment(LibraryModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let connectionId: String
    @State private var hooks: [TaskHookView] = []
    @State private var snippets: [SnippetView] = []
    @State private var error: String?

    private var isFolder: Bool { model.folder(id: connectionId) != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.m) {
            Text("Attached Tasks").font(DS.Font.headline)
            Text(model.connection(id: connectionId)?.name ?? model.folder(id: connectionId)?.name ?? "").foregroundStyle(.secondary)
            Table(model.tasks) {
                TableColumn("Task", value: \.name)
                TableColumn("Before connect") { t in toggle(t.id, "before_connect") }.width(100)
                TableColumn("After connect") { t in toggle(t.id, "after_connect") }.width(100)
                TableColumn("After disconnect") { t in toggle(t.id, "after_disconnect") }.width(110)
                TableColumn("All hosts") { t in toggle(t.id, "after_connect", target: "multi_host").disabled(!isFolder) }.width(70)
            }
            .frame(minHeight: 180)
            if !snippets.isEmpty {
                Table(snippets) {
                    TableColumn("Snippet", value: \.name)
                    TableColumn("After connect") { s in toggle(s.id, "after_connect", target: "snippet") }.width(100)
                }
                .frame(minHeight: 100)
            }
            if let error { Text(error).foregroundStyle(.red).font(DS.Font.caption) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Save") {
                    do {
                        try model.library?.setTaskHooks(connectionId: connectionId, hooks: hooks)
                        model.mutate { _ in }
                        dismiss()
                    } catch { self.error = errorText(error) }
                }.keyboardShortcut(.defaultAction).dsPrimaryButton()
            }
        }
        .padding(DS.Space.l)
        .frame(width: 620)
        .onAppear {
            hooks = (try? model.library?.taskHooks(connectionId: connectionId)) ?? []
            snippets = (try? SnippetLibrary.open(dataDir: LibraryModel.dataDir.path).search(query: "")) ?? []
        }
    }

    private func toggle(_ id: String, _ when: String, target: String = "task") -> some View {
        Toggle("", isOn: binding(id, when, target)).labelsHidden().help(Self.help(when, target))
    }

    private static func help(_ when: String, _ target: String) -> String {
        switch (when, target) {
        case (_, "multi_host"): "After a connection in this folder connects, run on every host in it"
        case ("after_disconnect", _): "Run once when the session ends"
        default: ""
        }
    }

    private func matches(_ h: TaskHookView, _ id: String, _ when: String, _ target: String) -> Bool {
        h.when == when && (h.target.isEmpty ? "task" : h.target) == target && (target == "snippet" ? h.snippetId == id : h.taskId == id)
    }

    private func binding(_ id: String, _ when: String, _ target: String) -> Binding<Bool> {
        Binding(get: { hooks.contains { matches($0, id, when, target) } },
                set: { on in
                    hooks.removeAll { matches($0, id, when, target) }
                    guard on else { return }
                    hooks.append(target == "snippet"
                        ? TaskHookView(taskId: "", when: when, target: target, snippetId: id)
                        : TaskHookView(taskId: id, when: when, target: target, snippetId: nil))
                })
    }
}

extension TaskView: Identifiable {}
