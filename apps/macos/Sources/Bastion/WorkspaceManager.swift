import SwiftUI
import BastionCore

/// Saved workspace list: name, session count, last used. Double-click or Return opens; the
/// context menu and the bottom bar hold the rest. Delete asks first.
struct WorkspaceManagerView: View {
    @Environment(WorkspaceModel.self) private var workspaces
    @Environment(Commands.self) private var commands
    private var dismiss = PanelDismiss()
    @State private var selection: String?
    @State private var naming: NameRequest?
    @State private var deleting: WorkspaceView?

    var body: some View {
        VStack(spacing: 0) {
            Text("Workspaces").font(DS.Font.bodyStrong)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            if workspaces.items.isEmpty {
                EmptyState(symbol: Icons.symbol("workspace"), title: "No saved workspaces",
                           message: "Save the open sessions to reopen them together.") {
                    Button("Save Current Layout…") { naming = .save }
                        .disabled(commands.sessions.tabs.isEmpty)
                }
            } else {
                table
            }
            Divider()
            bottomBar
        }
        .frame(minWidth: 0, idealWidth: DS.Size.managerWidth, maxWidth: DS.Size.managerWidth, minHeight: 0, idealHeight: DS.Size.managerHeight, maxHeight: DS.Size.managerHeight)
        .sheet(item: $naming) { request in
            WorkspaceNameSheet(request: request, select: { selection = $0 })
        }
        .confirmationDialog("Delete “\(deleting?.name ?? "")”?", isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } })) {
            Button("Delete Workspace", role: .destructive) {
                if let ws = deleting { workspaces.remove(ws.id) }
                deleting = nil
            }
        } message: {
            Text("The saved layout is removed. Open sessions and connections are not affected.")
        }
    }

    private var table: some View {
        Table(workspaces.items, selection: $selection) {
            TableColumn("Name") { ws in
                HStack(spacing: DS.Space.xs) {
                    Image(systemName: Icons.symbol("workspace")).foregroundStyle(.secondary)
                    Text(ws.name).lineLimit(1)
                    if ws.id == workspaces.currentId {
                        Text("Current").font(DS.Font.caption).foregroundStyle(.secondary)
                    }
                }
            }
            TableColumn("Sessions") { ws in Text("\(ws.tabs.count)").monospacedDigit() }
                .width(min: 60, ideal: 70, max: 90)
            TableColumn("Last Used") { ws in Text(ws.lastUsedText).foregroundStyle(.secondary) }
                .width(min: 90, ideal: 120, max: 160)
        }
        .contextMenu(forSelectionType: String.self) { ids in
            if let id = ids.first, let ws = workspaces.items.first(where: { $0.id == id }) {
                Button("Open") { open(id) }
                Button("Rename…") { naming = .rename(ws) }
                Button("Duplicate") { selection = workspaces.duplicate(id) ?? selection }
                Divider()
                Button("Delete…", role: .destructive) { deleting = ws }
            }
        } primaryAction: { ids in
            if let id = ids.first { open(id) }
        }
        .onDeleteCommand { deleting = selected }
    }

    private var selected: WorkspaceView? { workspaces.items.first { $0.id == selection } }

    private var bottomBar: some View {
        HStack(spacing: DS.Space.xs) {
            // With no workspaces the empty state carries Save and there is nothing to act on, so
            // the bar keeps only Done.
            if !workspaces.items.isEmpty {
                Button("Save Current Layout…") { naming = .save }
                    .disabled(commands.sessions.tabs.isEmpty)
                    .help("Save the open sessions as a workspace (⇧⌘S)")
            }
            Spacer()
            if !workspaces.items.isEmpty { Group {
                Button("Rename", systemImage: "pencil") { selected.map { naming = .rename($0) } }
                    .iconTip("Rename the selected workspace")
                Button("Duplicate", systemImage: "plus.square.on.square") { selection = selection.flatMap(workspaces.duplicate) ?? selection }
                    .iconTip("Duplicate the selected workspace")
                Button("Delete", systemImage: "trash") { deleting = selected }
                    .iconTip("Delete the selected workspace")
            }
            .labelStyle(.iconHitTarget)
            .buttonStyle(.borderless)
            .disabled(selected == nil) }
            Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
            if !workspaces.items.isEmpty {
                Button("Open") { selection.map(open) }
                    .keyboardShortcut(.defaultAction).dsPrimaryButton()
                    .disabled(selected == nil)
            }
        }
        .padding(DS.Space.s)
    }

    private func open(_ id: String) {
        dismiss()
        workspaces.open(id, commands: commands)
    }
}

enum NameRequest: Identifiable {
    case save
    case rename(WorkspaceView)
    /// A new workspace holding this connection (Add to Workspace › New Workspace…).
    case create(ConnectionView)

    var id: String {
        switch self {
        case .save: "save"
        case .rename(let ws): "rename-\(ws.id)"
        case .create(let c): "create-\(c.id)"
        }
    }
}

/// Compact dialog for Save Current Layout and Rename: one field, what will be saved, and
/// whether an existing workspace is replaced.
struct WorkspaceNameSheet: View {
    let request: NameRequest
    var select: (String) -> Void = { _ in }
    @Environment(WorkspaceModel.self) private var workspaces
    @Environment(SessionsModel.self) private var sessions
    @Environment(LibraryModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @FocusState private var focused: Bool

    private var trimmed: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }
    private var clash: WorkspaceView? {
        workspaces.items.first { $0.name.caseInsensitiveCompare(trimmed) == .orderedSame }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text(heading).font(DS.Font.bodyStrong)
            VStack(alignment: .leading, spacing: DS.Space.xxs) {
                TextField("Workspace name", text: $name)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused)
                    .onSubmit(confirm)
                Text(note).font(DS.Font.caption).foregroundStyle(problem != nil ? .red : .secondary)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button(confirmTitle, action: confirm)
                    .keyboardShortcut(.defaultAction).dsPrimaryButton()
                    .disabled(trimmed.isEmpty || problem != nil)
            }
        }
        .padding(DS.Space.m)
        .frame(width: DS.Size.dialogWidth)
        .onAppear {
            switch request {
            case .save: name = workspaces.current?.name ?? ""
            case .rename(let ws): name = ws.name
            case .create: name = ""
            }
            focused = true
        }
    }

    private var isSave: Bool { if case .save = request { true } else { false } }

    private var heading: String {
        switch request {
        case .save: "Save current layout"
        case .rename: "Rename workspace"
        case .create: "New workspace"
        }
    }

    private var confirmTitle: String {
        switch request {
        case .save: clash != nil ? "Replace" : "Save"
        case .rename: "Rename"
        case .create: "Create"
        }
    }

    private var problem: String? {
        switch request {
        case .rename(let ws): if let c = clash, c.id != ws.id { return "Another workspace has this name." }
        case .create: if clash != nil { return "Another workspace has this name." }
        case .save: break
        }
        return nil
    }

    private var note: String {
        if let problem { return problem }
        if case .create(let c) = request { return "1 session · \(c.name)" }
        guard isSave else { return " " }
        let s = workspaces.snapshot(sessions: sessions, model: model)
        var parts = [s.tabs.count == 1 ? "1 session" : "\(s.tabs.count) sessions"]
        if s.skipped > 0 { parts.append("\(s.skipped) local or Quick Connect not saved") }
        if let c = clash { parts.append("replaces “\(c.name)”") }
        return parts.joined(separator: " · ")
    }

    private func confirm() {
        guard !trimmed.isEmpty, problem == nil else { return }
        switch request {
        case .save:
            if workspaces.saveCurrent(name: trimmed, sessions: sessions, model: model), let id = workspaces.currentId { select(id) }
        case .rename(let ws):
            workspaces.rename(ws.id, to: trimmed)
        case .create(let c):
            workspaces.create(name: trimmed, connectionId: c.id)
        }
        dismiss()
    }
}
