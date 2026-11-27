import AppKit
import SwiftUI
import BastionCore

/// A task's last run on this Mac: the tally only ("3 ok · 1 failed"), never the output.
struct TaskLastResult: Codable, Equatable {
    var summary: String
    var at: Date

    private static func key(_ taskId: String) -> String { "taskLast.\(taskId)" }

    static func load(taskId: String, defaults: UserDefaults = .standard) -> TaskLastResult? {
        defaults.data(forKey: key(taskId)).flatMap { try? JSONDecoder().decode(TaskLastResult.self, from: $0) }
    }

    func save(taskId: String, defaults: UserDefaults = .standard) {
        if let data = try? JSONEncoder().encode(self) { defaults.set(data, forKey: Self.key(taskId)) }
    }
}

/// Tasks (design C): saved checks as cards with their command, scope and last result; Run uses the
/// saved scope, or asks for hosts the first time. The hooks attached to folders and connections
/// are listed below. Ad-hoc commands go through "Run Command…".
struct TasksPage: View {
    @Environment(LibraryModel.self) private var model
    @Environment(Commands.self) private var commands
    @Environment(AppRouter.self) private var router
    private var dismiss = PanelDismiss()
    @State private var hooks: [(owner: String, hook: TaskHookView)] = []
    @State private var problem: String?

    /// Built-in quick checks offered when the library has none of them yet.
    static let examples: [(name: String, program: String, args: [String])] = [
        ("Uptime check", "uptime", []),
        ("Disk space", "df", ["-h", "/"]),
    ]

    @State private var filter = ""
    private var saved: [TaskView] { model.tasks.filter { !$0.builtin && ListFilterField.matches(filter, [$0.name, $0.program] + $0.args) }.sorted { ($0.favorite ? 0 : 1, $0.name) < ($1.favorite ? 0 : 1, $1.name) } }
    private var missingExamples: [(name: String, program: String, args: [String])] {
        Self.examples.filter { e in !model.tasks.contains { $0.name == e.name } }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Tasks").font(DS.Font.bodyStrong)
                Spacer()
                ListFilterField(text: $filter)
                if !missingExamples.isEmpty {
                    Button("Add Examples", systemImage: "sparkles") { addExamples() }
                        .quietIcon("Add examples: " + missingExamples.map(\.name).joined(separator: ", "))
                }
                Button("Run Command…", systemImage: "terminal") { dismiss(); router.open("run-on-hosts") }
                    .quietIcon("Run a command on hosts")
                Button("New Task…", systemImage: "plus") { dismiss(); commands.newTask() }
                    .quietIcon("New task")
            }
            .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: DS.Space.m) {
                    if saved.isEmpty {
                        Text("No saved tasks. Add the examples or create one.").foregroundStyle(.secondary)
                    }
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 260), spacing: DS.Space.s)], alignment: .leading, spacing: DS.Space.s) {
                        ForEach(saved, id: \.id) { card($0) }
                    }
                    hooksSection
                }
                .padding(DS.Space.m)
            }
            if let problem { Text(problem).font(DS.Font.caption).foregroundStyle(.red).padding(.horizontal, DS.Space.m) }
            Divider()
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton() }.padding(DS.Space.s)
        }
        .panelFrame(width: 760, height: 560)
        .onAppear(perform: loadHooks)
    }

    private func card(_ t: TaskView) -> some View {
        let scope = TaskRunOnChoice.load(taskId: t.id)
        let last = TaskLastResult.load(taskId: t.id)
        return VStack(alignment: .leading, spacing: DS.Space.xs) {
            HStack {
                Text(t.name).font(DS.Font.bodyStrong).lineLimit(1)
                if t.favorite { Image(systemName: "star.fill").font(DS.Font.caption2).foregroundStyle(.yellow) }
                Spacer()
                Text(t.runOn == "ssh" ? "SSH" : "This Mac").font(DS.Font.caption).foregroundStyle(.secondary)
            }
            Text(([t.program] + t.args).joined(separator: " ")).font(DS.Font.size(11, design: .monospaced))
                .lineLimit(1).truncationMode(.tail).help(([t.program] + t.args).joined(separator: " "))
            Text(scopeText(scope)).font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1)
            Text(last.map { "\($0.summary) · \($0.at.formatted(.relative(presentation: .named)))" } ?? "Not run yet")
                .font(DS.Font.caption).foregroundStyle(.tertiary).lineLimit(1)
            HStack {
                Button("Run") { run(t, auto: scope != nil) }.dsPrimaryButton()
                Button("Run on…") { run(t, auto: false) }
                Spacer()
                Menu {
                    Button("Edit…") { dismiss(); commands.editingTask = TaskEditRequest(task: t) }
                    Button(t.favorite ? "Remove from Favorites" : "Add to Favorites") {
                        model.mutate { try $0.setTaskFavorite(taskId: t.id, favorite: !t.favorite) }
                    }
                    Divider()
                    Button("Delete", role: .destructive) { model.mutate { try $0.removeTask(taskId: t.id) } }
                } label: { Image(systemName: "ellipsis") }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize().help("More")
                .accessibilityLabel("More task actions")
            }
            .controlSize(.small)
        }
        .padding(DS.Space.s)
        .background(RoundedRectangle(cornerRadius: 6).strokeBorder(.separator))
        .contentShape(Rectangle())
        // Right-click has the card's actions too (owner round 2, item 9).
        .contextMenu {
            Button("Run") { run(t, auto: scope != nil) }
            Button("Run on…") { run(t, auto: false) }
            Divider()
            Button("Edit…") { dismiss(); commands.editingTask = TaskEditRequest(task: t) }
            Button(t.favorite ? "Remove from Favorites" : "Add to Favorites") {
                model.mutate { try $0.setTaskFavorite(taskId: t.id, favorite: !t.favorite) }
            }
            Divider()
            Button("Delete", role: .destructive) { model.mutate { try $0.removeTask(taskId: t.id) } }
        }
        .accessibilityIdentifier("task-card-\(t.name)")
    }

    private var hooksSection: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            Text("Hooks").font(DS.Font.bodyStrong)
            if hooks.isEmpty {
                Text("None. Attach tasks to a folder or connection from its right-click menu (Attached Tasks…).")
                    .font(DS.Font.caption).foregroundStyle(.secondary)
            }
            ForEach(Array(hooks.enumerated()), id: \.offset) { _, h in
                HStack {
                    Text(Self.whenLabel(h.hook.when)).frame(width: 120, alignment: .leading).foregroundStyle(.secondary)
                    Text(h.hook.target == "snippet" ? "Snippet" : model.tasks.first { $0.id == h.hook.taskId }?.name ?? "Missing task")
                    Spacer()
                    Text(h.owner).foregroundStyle(.secondary).lineLimit(1)
                }
                .font(DS.Font.caption)
            }
        }
    }

    static func whenLabel(_ when: String) -> String {
        switch when {
        case "before_connect": "Before connect"
        case "after_connect": "After connect"
        case "after_disconnect": "After disconnect"
        default: when
        }
    }

    private func scopeText(_ scope: TaskRunOnChoice?) -> String {
        guard let scope else { return "Scope: choose on first run" }
        if let f = scope.folderId { return "Scope: folder \(model.folder(id: f)?.name ?? "(deleted)")" }
        let names = scope.hostIds.compactMap { model.connection(id: $0)?.name }
        return "Scope: " + (names.count <= 3 ? names.joined(separator: ", ") : "\(names.count) hosts")
    }

    private func run(_ t: TaskView, auto: Bool) {
        dismiss()
        commands.runOnTask = TaskRunOnRequest(task: t, autoStart: auto)
    }

    private func loadHooks() {
        guard let library = model.library, let root = model.tree else { return }
        func folders(_ f: FolderView) -> [FolderView] { [f] + f.folders.flatMap(folders) }
        let owners = folders(root).map { ($0.id, $0.name) } + AppIpc.connections(in: root).map { ($0.id, $0.name) }
        hooks = owners.flatMap { id, name in ((try? library.taskHooks(connectionId: id)) ?? []).map { (name, $0) } }
    }

    private func addExamples() {
        do { try Self.addExamplesThrowing(model: model); problem = nil } catch { problem = errorText(error) }
    }

    /// Saves the example checks the library does not have yet (also used by snapshots).
    @discardableResult
    static func addExamples(model: LibraryModel) -> Bool {
        (try? addExamplesThrowing(model: model)) != nil
    }

    private static func addExamplesThrowing(model: LibraryModel) throws {
        guard let library = model.library else { return }
        do {
            for e in examples where !model.tasks.contains(where: { $0.name == e.name }) {
                let t = TaskView(id: "", name: e.name, favorite: false, builtin: false, kind: "custom",
                                 program: e.program, args: e.args, runOn: "ssh", timeoutSecs: 30)
                let id = try library.saveTask(task: t)
                try library.trustTask(taskId: id, dataDir: LibraryModel.dataDir.path)
            }
            model.mutate { _ in }
        }
    }
}

#if BASTION_TEST_HOOKS
/// Snapshot only (`BASTION_SNAPSHOT_SHEET=task-grid`): the results grid with sample rows, for review.
struct TaskGridDemo: View {
    @Environment(\.dismiss) private var dismiss
    static let rows: [TaskGridRow] = [
        TaskGridRow(id: "1", host: "web-01", state: "done", exit: 0, stdout: "/dev/sda1  40G  12G  26G  32% /\n", millis: 412),
        TaskGridRow(id: "2", host: "web-02", state: "done", exit: 0, stdout: "/dev/sda1  40G  12G  26G  32% /\n", millis: 388),
        TaskGridRow(id: "3", host: "db-01", state: "done", exit: 0, stdout: "/dev/nvme0n1p2  200G  181G  19G  91% /\n", millis: 530),
        TaskGridRow(id: "4", host: "build-03", state: "running"),
        TaskGridRow(id: "5", host: "old-nas", state: "failed", error: "host key not trusted yet: connect once and verify it first"),
    ]
    var body: some View {
        VStack(spacing: 0) {
            Text("Disk space · 5 hosts").font(DS.Font.bodyStrong).frame(maxWidth: .infinity, alignment: .leading).padding(DS.Space.m)
            Divider()
            TaskResultsGrid(rows: Self.rows, openInTerminal: { _ in }, openAll: { _ in })
            Divider()
            HStack { Spacer(); Button("Done") { dismiss() }.dsSecondaryButton() }.padding(DS.Space.s)
        }
        .frame(width: 820, height: 420)
    }
}
#endif
