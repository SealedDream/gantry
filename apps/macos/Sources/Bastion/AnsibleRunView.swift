import SwiftUI
import AppKit
import BastionCore

/// File › Run Ansible…: an ad-hoc command or a playbook against an inventory. The shared core
/// (`ansibleRunPlan`) validates the sheet and returns the argv; it is started in a terminal tab
/// directly (`/usr/bin/env`, never a shell), so nothing typed here is ever re-parsed by a shell.
/// "Control host" runs it on a saved SSH connection instead (`AnsibleControlHost`).
struct AnsibleRunView: View {
    @Environment(LibraryModel.self) private var model
    @Environment(Commands.self) private var commands
    @Environment(SessionsModel.self) private var sessions
    @Environment(\.dismiss) private var dismiss
    @State private var kind = "adhoc"
    @State private var inventory = ""
    @State private var pattern = "all"
    @State private var module = "ping"
    @State private var moduleArgs = ""
    @State private var playbook = ""
    @State private var limit = ""
    @State private var check = true
    @State private var diff = false
    @State private var becomeRoot = false
    @State private var forks = ""
    @State private var verbosity = 0
    @State private var tags = ""
    @State private var extraVars = ""
    @State private var onHost = false
    @State private var hostId = AnsibleControlHost.remembered ?? ""
    @State private var uploadFolder = false
    @State private var problem: String?
    /// Set when the local Ansible program is missing: offers the control host instead.
    @State private var missingLocally = false
    @State private var saved = false

    /// UI driver: the plan last computed (argv joined by spaces, then warnings), and what a run did.
    @MainActor static var lastPlan = ""
    /// UI driver: field values applied when the sheet opens (`key=value`).
    @MainActor static var scripted: [String: String] = [:]
    /// UI driver: presses Run on the open sheet.
    @MainActor static var runNow: (() -> Void)?
    /// UI driver: presses Save as Task on the open sheet.
    @MainActor static var saveNow: (() -> Void)?

    private var input: AnsibleRunInput {
        AnsibleRunInput(kind: kind, inventory: inventory, pattern: pattern, module: module, moduleArgs: moduleArgs,
                        playbook: playbook, limit: limit.isEmpty ? nil : limit, check: check, diff: diff,
                        becomeRoot: becomeRoot, forks: UInt32(forks), verbosity: UInt8(verbosity),
                        tags: kind == "playbook" && !tags.isEmpty ? tags : nil, extraVars: extraVars.isEmpty ? nil : extraVars)
    }

    private var plan: Result<AnsibleRunPlan, Error> { Result { try ansibleRunPlan(input: input) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Run Ansible").font(DS.Font.bodyStrong).padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            Form {
                Picker("Run on", selection: $onHost) {
                    Text("This Mac").tag(false)
                    Text("Control host").tag(true)
                }
                .pickerStyle(.segmented)
                .help("Control host: a saved SSH connection with Ansible installed. The inventory and playbook are copied there for the run and removed after. Targets need key login; password-only targets are not supported here.")
                if onHost { hostPicker }
                Picker("Run", selection: $kind) {
                    Text("Ad-hoc command").tag("adhoc")
                    Text("Playbook").tag("playbook")
                }
                .pickerStyle(.segmented)
                HStack {
                    TextField("Inventory", text: $inventory, prompt: Text("/path/to/inventory.ini"))
                    Button("Choose…", action: chooseInventory)
                    Button("Use Library", action: useLibrary)
                }
                if kind == "adhoc" {
                    TextField("Hosts", text: $pattern, prompt: Text("all"))
                    TextField("Module", text: $module, prompt: Text("ping"))
                    TextField("Arguments", text: $moduleArgs, prompt: Text("optional, for -a"))
                } else {
                    HStack {
                        TextField("Playbook", text: $playbook, prompt: Text("/path/to/site.yml"))
                        Button("Choose…", action: choosePlaybook)
                    }
                    if onHost {
                        Toggle("Upload playbook folder", isOn: $uploadFolder)
                            .help("Copy the playbook's whole folder (roles, group_vars, templates), not only the file.")
                    }
                    TextField("Tags", text: $tags, prompt: Text("optional, comma-separated"))
                }
                TextField("Limit", text: $limit, prompt: Text("optional"))
                TextField("Extra vars", text: $extraVars, prompt: Text("optional, key=value"))
                    .help("Passed with -e. Visible in the process list: never put passwords here.")
                Toggle("Check mode (dry run)", isOn: $check)
                Toggle("Show diffs", isOn: $diff)
                Toggle("Become root", isOn: $becomeRoot)
                TextField("Forks", text: $forks, prompt: Text("default"))
                Stepper("Verbosity: \(verbosity)", value: $verbosity, in: 0...5)
                preview
            }
            .formStyle(.grouped)
            if let message = problem {
                HStack {
                    Text(message).font(DS.Font.caption).foregroundStyle(.red).lineLimit(2)
                        .help("A GUI app searches PATH, /opt/homebrew/bin, /usr/local/bin and ~/.local/bin.")
                    if missingLocally {
                        Button("Use control host") { onHost = true; problem = nil; missingLocally = false }
                            .dsSecondaryButton()
                    }
                }
                .padding(.horizontal, DS.Space.m)
            }
            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button(saved ? "Saved" : "Save as Task", action: saveAsTask).dsSecondaryButton()
                    .disabled(saved || !isReady || (onHost && (host == nil || uploadFolder)))
                    .help(onHost ? (uploadFolder ? "A task copies the playbook file only. Turn off Upload playbook folder to save."
                                                 : "Save as a task that runs on the control host over SSH.")
                                 : "Save as a task that runs on this Mac.")
                Button("Run", action: run).keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(!isReady || (onHost && host == nil))
            }
            .padding(DS.Space.s)
        }
        .frame(width: 560)
        .onAppear { applyScripted(); Self.runNow = { run() }; Self.saveNow = { saveAsTask() } }
        .onDisappear { Self.runNow = nil; Self.saveNow = nil }
        .onChange(of: planText) { _, text in Self.lastPlan = text; saved = false }
    }

    /// Save the run as a custom task (core `ansibleTask`): on this Mac, or over SSH on the control
    /// host, which becomes the task's saved Run on… scope. No password is stored.
    private func saveAsTask() {
        guard let library = model.library, isReady else { return }
        let target = onHost ? host : nil
        if onHost && target == nil { return }
        do {
            let spec = try ansibleTask(input: input, mode: onHost ? "host" : "local", hostName: target?.name)
            let t = TaskView(id: "", name: spec.name, favorite: false, builtin: false, kind: "custom",
                             program: spec.program, args: spec.args, runOn: spec.runOn, timeoutSecs: 600)
            let id = try library.saveTask(task: t)
            try library.trustTask(taskId: id, dataDir: LibraryModel.dataDir.path)
            if let target { TaskRunOnChoice(hostIds: [target.id]).save(taskId: id) }
            model.mutate { _ in }
            problem = nil
            saved = true
            Self.lastPlan = "SAVED \(spec.runOn) \(spec.name)"
        } catch { problem = errorText(error) }
    }

    private var isReady: Bool { if case .success = plan { return true } else { return false } }

    private var planText: String {
        switch plan {
        case .success(let p): return (["PLAN"] + (onHost ? ["@host"] : []) + p.argv).joined(separator: " ") + p.warnings.map { " | WARN \($0)" }.joined()
        case .failure(let e): return "ERROR \(errorText(e))"
        }
    }

    @ViewBuilder private var preview: some View {
        switch plan {
        case .success(let p):
            VStack(alignment: .leading, spacing: DS.Space.xs) {
                Text(p.argv.joined(separator: " ")).font(DS.Font.size(12, design: .monospaced)).textSelection(.enabled)
                ForEach(p.warnings, id: \.self) { Label($0, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange).font(DS.Font.caption) }
            }
        case .failure(let e):
            Text(errorText(e)).font(DS.Font.caption).foregroundStyle(.red)
        }
    }

    private func applyScripted() {
        for (k, v) in Self.scripted {
            switch k {
            case "kind": kind = v
            case "inventory": inventory = v
            case "pattern": pattern = v
            case "module": module = v
            case "args": moduleArgs = v
            case "playbook": playbook = v
            case "limit": limit = v
            case "check": check = v == "1"
            case "become": becomeRoot = v == "1"
            case "tags": tags = v
            case "extra": extraVars = v
            case "host": onHost = !v.isEmpty; hostId = model.sshConnections.first { $0.name == v }?.id ?? ""
            case "folder": uploadFolder = v == "1"
            case "searchpath": AnsibleLocal.pathOverride = v.isEmpty ? nil : v
            default: break
            }
        }
        if Self.scripted["inventory"] == nil && inventory.isEmpty { useLibrary() }
    }

    private func chooseInventory() {
        let panel = NSOpenPanel()
        panel.title = "Ansible Inventory"
        if panel.runModal() == .OK, let url = panel.url { inventory = url.path }
    }

    private func choosePlaybook() {
        let panel = NSOpenPanel()
        panel.title = "Ansible Playbook"
        if panel.runModal() == .OK, let url = panel.url { playbook = url.path }
    }

    /// Export the whole library as an INI inventory next to the library and point the sheet at it.
    private func useLibrary() {
        guard let library = model.library else { return }
        let path = LibraryModel.dataDir.appendingPathComponent("ansible-run-inventory.ini").path
        do {
            _ = try library.exportAnsibleInventory(path: path, ids: nil, yaml: false)
            inventory = path
            problem = nil
        } catch {
            problem = "Could not export the library inventory: \(errorText(error))"
        }
    }

    private var host: ConnectionView? { hostId.isEmpty ? nil : model.connection(id: hostId) }

    @ViewBuilder private var hostPicker: some View {
        let hosts = model.sshConnections
        if hosts.isEmpty {
            Text("No SSH connections to use as a control host.").font(DS.Font.caption).foregroundStyle(.secondary)
        } else {
            Picker("Control host", selection: $hostId) {
                Text("Choose…").tag("")
                ForEach(hosts, id: \.id) { Text($0.name).tag($0.id) }
            }
        }
    }

    private func run() {
        guard case .success(let p) = plan else { return }
        if onHost {
            guard let host else { return }
            AnsibleControlHost.start(input, uploadFolder: uploadFolder, host: host, commands: commands, sessions: sessions)
            Self.lastPlan = "STARTED host \(host.name)"
            dismiss()
            return
        }
        let path = AnsibleLocal.searchPath
        guard AnsibleLocal.find(p.argv[0], path: path) != nil else {
            problem = "\(p.argv[0]) not found on this Mac. Install: brew install ansible"
            missingLocally = true
            Self.lastPlan = "MISSING \(problem ?? "")"
            return
        }
        do {
            let t = try Terminal.localProgram(program: "/usr/bin/env", args: ["PATH=\(path)"] + p.argv, cols: 80, rows: 24)
            sessions.add(TerminalTab(name: p.argv.first ?? "ansible", terminal: t))
            dismiss()
        } catch {
            problem = "Could not start \(p.argv.first ?? "ansible"): \(errorText(error))"
        }
    }
}
