import SwiftUI
import BastionCore

/// Dynamic Folder…: the user's switch and the task that fills the folder. Only tasks the core
/// accepts are listed (a saved custom task that runs locally, C3); the core checks again on save.
struct DynamicFolderEditSheet: View {
    let request: DynamicFoldersModel.EditRequest
    let dynamic: DynamicFoldersModel
    @Environment(\.dismiss) private var dismiss
    @State private var enabled = false
    @State private var taskId = ""
    @State private var choices: [(id: String, name: String)] = []
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("Dynamic Folder").font(DS.Font.headline)
            Text(request.folderName).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).help(request.folderName)
            Toggle("Allow dynamic folders on this computer", isOn: $enabled)
                .help("Runs only when you choose Refresh, and only after you trust the task.")
            Picker("Task", selection: $taskId) {
                Text("None").tag("")
                ForEach(choices, id: \.id) { Text($0.name).tag($0.id) }
            }
            .help("A saved custom task that runs on this computer and prints Royal JSON.")
            if choices.isEmpty {
                Text("No eligible task: save a custom task that runs locally.").font(DS.Font.caption).foregroundStyle(.secondary)
            }
            if let error {
                Text(error).font(DS.Font.caption).foregroundStyle(.red).lineLimit(2).help(error)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Save") { save() }.keyboardShortcut(.defaultAction).dsPrimaryButton()
            }
        }
        .padding(DS.Space.l)
        .frame(width: 440)
        // UI driver (`top-button`): SwiftUI controls here carry no AppKit title to click.
        .onReceive(NotificationCenter.default.publisher(for: DriverEvents.pressButton)) { note in
            guard let step = note.object as? String else { return }
            switch step {
            case "toggle-allow": enabled.toggle()
            case "Save": save()
            case "Cancel": dismiss()
            case "task:None": taskId = ""
            case let t where t.hasPrefix("task:"):
                if let c = choices.first(where: { $0.name == t.dropFirst(5) }) { taskId = c.id }
            default: break
            }
        }
        .onAppear {
            choices = dynamic.choices()
            taskId = dynamic.taskId(of: request.folderId) ?? ""
            enabled = dynamic.userEnabled
        }
    }

    private func save() {
        do {
            try dynamic.save(folderId: request.folderId, taskId: taskId.isEmpty ? nil : taskId, enabled: enabled)
            dismiss()
        } catch {
            self.error = errorText(error)
        }
    }
}

/// The consent sheet before a task runs for the first time: exactly what runs, as the core
/// reports it. Trust and Run trusts this review only; any change to the task asks again (C1, H1).
struct DynamicFolderTrustSheet: View {
    let request: DynamicFoldersModel.TrustRequest
    let dynamic: DynamicFoldersModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        let r = request.review
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("Trust this task?").font(DS.Font.headline)
            Text("“\(r.taskName)” runs on this computer with your rights and fills “\(request.folderName)”.")
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: DS.Space.xxs) {
                line("Program", r.program)
                line("Arguments", r.args.isEmpty ? "None" : r.args.joined(separator: " "))
                line("Time limit", "\(r.timeoutSecs) s")
                ForEach(r.warnings, id: \.self) { w in
                    Label(w, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(DS.Font.caption)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .textSelection(.enabled)
            Text("Any change to the task asks again.").font(DS.Font.caption).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Trust and Run") {
                    dismiss()
                    dynamic.trustAndRun(request)
                }.dsPrimaryButton()
            }
        }
        .padding(DS.Space.l)
        .frame(width: 520)
        .onReceive(NotificationCenter.default.publisher(for: DriverEvents.pressButton)) { note in
            switch note.object as? String {
            case "Trust and Run": dismiss(); dynamic.trustAndRun(request)
            case "Cancel": dismiss()
            default: break
            }
        }
    }

    private func line(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: DS.Space.xs) {
            Text(label).foregroundStyle(.secondary).frame(width: 84, alignment: .leading)
            Text(value).font(.system(.body, design: .monospaced)).fixedSize(horizontal: false, vertical: true)
        }
    }
}
