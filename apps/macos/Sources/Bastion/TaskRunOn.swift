import AppKit
import SwiftUI
import BastionCore

/// Owner point 31: right-click a task › "Run on…" picks a folder (every host in it, subfolders
/// included) or ticked hosts, runs the task on each and shows every host's result. The last choice
/// is remembered per task on this Mac.
struct TaskRunOnRequest: Identifiable {
    let id = UUID()
    let task: TaskView
    /// Hosts or folder to start with (a folder's or selection's right-click), instead of the saved one.
    var preset: TaskRunOnChoice?
    /// Run at once on the preset or saved scope, without the chooser.
    var autoStart = false
}

/// The remembered target of one task: a folder or a set of hosts.
struct TaskRunOnChoice: Codable, Equatable {
    var folderId: String?
    var hostIds: [String] = []
    /// Every host with this tag, resolved when the task runs.
    var tag: String?

    private static func key(_ taskId: String) -> String { "taskRunOn.\(taskId)" }

    static func load(taskId: String, defaults: UserDefaults = .standard) -> TaskRunOnChoice? {
        guard let data = defaults.data(forKey: key(taskId)) else { return nil }
        return try? JSONDecoder().decode(TaskRunOnChoice.self, from: data)
    }

    /// A deleted task's choice goes with it, so the per-task keys do not pile up.
    static func forget(taskId: String, defaults: UserDefaults = .standard) {
        defaults.removeObject(forKey: key(taskId))
    }

    func save(taskId: String, defaults: UserDefaults = .standard) {
        guard let data = try? JSONEncoder().encode(self) else { return }
        defaults.set(data, forKey: Self.key(taskId))
    }
}

/// One host's run inside a "Run on…" batch.
@MainActor @Observable
final class TaskHostRun: Identifiable {
    let id: String
    let name: String
    var run: TaskRun?
    var view: TaskRunView?
    var problem: String?

    init(id: String, name: String) { self.id = id; self.name = name }

    var state: String { problem != nil ? "failed" : view?.state ?? "starting" }
    var isFinished: Bool { problem != nil || (run?.isFinished() ?? false) }

    func poll() { if let run { view = run.output() } }

    var gridRow: TaskGridRow {
        if let problem { return TaskGridRow(id: id, host: name, state: "failed", error: problem) }
        guard let v = view else { return TaskGridRow(id: id, host: name, state: "starting") }
        return TaskGridRow(id: id, host: name, state: v.state, exit: v.exit.map(Int.init), stdout: v.stdout, stderr: v.stderr, error: v.error, millis: v.millis)
    }
}

struct TaskRunOnSheet: View {
    let task: TaskView
    var preset: TaskRunOnChoice?
    var autoStart = false
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @Environment(Commands.self) private var commands
    @Environment(\.dismiss) private var dismiss
    @State private var mode = Mode.folder
    @State private var tag: String?
    @State private var folderId: String?
    @State private var hostIds: Set<String> = []
    @State private var runs: [TaskHostRun] = []
    @State private var selected: String?
    @State private var password = ""
    @State private var problem: String?
    @State private var lastSaved = false
    private let timer = Timer.publish(every: 0.5, on: .main, in: .common).autoconnect()

    /// Set by the UI driver: choose these instead of clicking.
    @MainActor static var scripted: TaskRunOnChoice?
    /// The open sheet's runs, for the UI driver.
    @MainActor static var current: [TaskHostRun] = []

    private var overSsh: Bool { task.kind == "custom" && task.runOn == "ssh" }
    private func eligible(_ c: ConnectionView) -> Bool { !overSsh || c.protocol == "ssh" }
    private var hosts: [ConnectionView] { AppIpc.connections(in: model.tree).filter(eligible) }

    private var folders: [(FolderView, Int)] {
        func walk(_ f: FolderView, _ depth: Int) -> [(FolderView, Int)] {
            [(f, depth)] + f.folders.flatMap { walk($0, depth + 1) }
        }
        return model.tree.map { $0.folders.flatMap { walk($0, 0) } } ?? []
    }

    enum Mode { case folder, tag, hosts }

    private var targets: [ConnectionView] {
        switch mode {
        case .folder: return folderId.flatMap(model.folder(id:)).map { AppIpc.connections(in: $0).filter(eligible) } ?? []
        case .tag: return tag.map { t in hosts.filter { $0.tags.contains(t) } } ?? []
        case .hosts: return hosts.filter { hostIds.contains($0.id) }
        }
    }

    private var needsPassword: Bool { overSsh && targets.contains { $0.credentialId == nil } }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Run “\(task.name)” on…").font(DS.Font.bodyStrong).padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            if runs.isEmpty { chooser } else { results }
            if let problem { Text(problem).font(DS.Font.caption).foregroundStyle(.red).padding(.horizontal, DS.Space.m).padding(.top, DS.Space.xs) }
            Divider()
            HStack {
                if !runs.isEmpty {
                    Button("Cancel Runs") { runs.forEach { $0.run?.cancel() } }.disabled(runs.allSatisfy(\.isFinished))
                }
                Spacer()
                Button(runs.isEmpty ? "Cancel" : "Done") { runs.forEach { $0.run?.cancel() }; dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                if runs.isEmpty {
                    Button("Run on \(targets.count) Host\(targets.count == 1 ? "" : "s")", action: start)
                        .keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(targets.isEmpty)
                }
            }
            .padding(DS.Space.m)
        }
        .frame(minWidth: 640, idealWidth: 820, minHeight: 420, idealHeight: 560)
        .onAppear(perform: restore)
        .onReceive(timer) { _ in
            runs.forEach { $0.poll() }
            if !runs.isEmpty && !lastSaved && runs.allSatisfy(\.isFinished) {
                lastSaved = true
                TaskLastResult(summary: TaskGrid.tally(runs.map(\.gridRow)), at: Date()).save(taskId: task.id)
            }
        }
    }

    private var chooser: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Picker("", selection: $mode) {
                Text("Folder").tag(Mode.folder)
                Text("Tag").tag(Mode.tag)
                Text("Hosts").tag(Mode.hosts)
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            if mode == .tag {
                let tags = Tags.all(in: model.tree)
                List(tags, id: \.self, selection: $tag) { t in
                    Text("\(t)  (\(hosts.filter { $0.tags.contains(t) }.count))").tag(Optional(t))
                }
                .overlay { if tags.isEmpty { Text("No tags in the library.").foregroundStyle(.secondary) } }
            } else if mode == .folder {
                List(folders, id: \.0.id, selection: $folderId) { folder, depth in
                    let count = AppIpc.connections(in: folder).filter(eligible).count
                    Label("\(folder.name)  (\(count))", systemImage: "folder")
                        .padding(.leading, CGFloat(depth) * 14).tag(Optional(folder.id))
                }
            } else {
                List(hosts, id: \.id) { c in
                    Toggle(isOn: Binding(get: { hostIds.contains(c.id) },
                                         set: { if $0 { hostIds.insert(c.id) } else { hostIds.remove(c.id) } })) {
                        Text(c.name) + Text("  \(c.host)").foregroundStyle(.secondary)
                    }
                }
            }
            if needsPassword {
                SecureField("Password for hosts without a saved credential (empty: SSH agent)", text: $password)
            }
            if overSsh { Text("Only SSH connections are listed: this task runs over SSH.").font(DS.Font.caption).foregroundStyle(.secondary) }
        }
        .padding(DS.Space.m)
    }

    private var results: some View {
        TaskResultsGrid(rows: runs.map(\.gridRow), limit: TimeInterval(max(task.timeoutSecs, 30)),
                        openInTerminal: { id in dismiss(); commands.openTaskHost(id) },
                        openAll: { ids in dismiss(); commands.openTaskHostsBroadcast(ids) })
    }

    private func restore() {
        let saved = Self.scripted ?? preset ?? TaskRunOnChoice.load(taskId: task.id)
        guard let saved else { return }
        mode = saved.tag != nil ? .tag : saved.folderId != nil ? .folder : .hosts
        folderId = saved.folderId
        tag = saved.tag
        hostIds = Set(saved.hostIds)
        if autoStart && !targets.isEmpty { start() }
    }

    private func start() {
        guard let library = model.library, let manager = sessions.manager else { return problem = "The session manager could not start." }
        let chosen = targets
        switch mode {
        case .folder: TaskRunOnChoice(folderId: folderId).save(taskId: task.id)
        case .tag: TaskRunOnChoice(tag: tag).save(taskId: task.id)
        case .hosts: TaskRunOnChoice(hostIds: hostIds.sorted()).save(taskId: task.id)
        }
        Task { @MainActor in
            // Prompt variables are asked once for the whole run.
            guard let answers = await Commands.askTaskAnswers(task, library: library) else { return }
            let sensitive = chosen.filter { (try? reviewTask(library: library, taskId: task.id, connectionId: $0.id, answers: answers))?.needsConfirmation == true }
            if !sensitive.isEmpty {
                let alert = NSAlert()
                alert.messageText = "Run “\(task.name)” on \(chosen.count) hosts?"
                alert.informativeText = "These are marked sensitive (for example production):\n" + sensitive.map(\.name).joined(separator: ", ")
                alert.alertStyle = .warning
                alert.addButton(withTitle: "Run")
                alert.addButton(withTitle: "Cancel").keyEquivalent = "\u{1b}"
                guard await Commands.present(alert) == .alertFirstButtonReturn else { return }
            }
            runs = chosen.map { conn in
                let entry = TaskHostRun(id: conn.id, name: conn.name)
                let login: SshLogin = conn.credentialId.map { .vault(credentialId: $0) }
                    ?? (password.isEmpty ? .agent : .password(password: password))
                do {
                    entry.run = try TaskRun.start(manager: manager, library: library, taskId: task.id, connectionId: conn.id,
                                                  username: conn.username ?? "", login: login,
                                                  confirmed: sensitive.contains { $0.id == conn.id }, answers: answers)
                } catch {
                    entry.problem = "\(error)"
                }
                return entry
            }
            password = ""
            selected = runs.first?.id
            Self.current = runs
        }
    }
}
