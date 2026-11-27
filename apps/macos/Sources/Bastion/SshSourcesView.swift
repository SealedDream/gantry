import SwiftUI
import BastionCore

/// Settings for the optional shared SSH config workflow, placeholder answers, and the change
/// preview after a manual `git pull`. Bastion only reads the config files; nothing here writes them.
struct SshSourcesView: View {
    var checkOnAppear = false
    static let syncNowNotification = Notification.Name("BastionSshSourcesSyncNow")
    @Environment(LibraryModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var scanConfigD = true
    @State private var placeholders = true
    @State private var overrides = true
    @State private var changeDetection = true
    @State private var sshDir = ""
    @State private var answers: [String: String] = [:]
    @State private var usage: [String: UInt32] = [:]
    @State private var preview: ChangePreview?
    @State private var importAdded = true
    @State private var message: String?
    @State private var isError = false

    var body: some View {
        Form {
            Section {
                Toggle("Scan config.d for files not included by config", isOn: $scanConfigD)
                Toggle("Placeholders such as <user>", isOn: $placeholders)
                Toggle("Personal overrides", isOn: $overrides)
                Toggle("Detect changes after a manual pull", isOn: $changeDetection)
                TextField("Directory (default ~/.ssh)", text: $sshDir)
            } header: {
                Text("Sources")
            } footer: {
                Text("Each option works on its own. Config files are only read: Gantry never edits, commits or pushes them. Manual connections need none of this.")
            }
            if placeholders {
                Section("Placeholder values") {
                    if names.isEmpty { Text("No placeholders found in the sources.").foregroundStyle(.secondary) }
                    ForEach(names, id: \.self) { name in
                        LabeledContent {
                            TextField("value", text: Binding(get: { answers[name] ?? "" }, set: { answers[name] = $0 }))
                                .labelsHidden()
                                .multilineTextAlignment(.trailing)
                        } label: {
                            Text("<\(name)>").font(DS.Font.style(.body, design: .monospaced))
                            if let n = usage[name] { Text("used by \(n) host\(n == 1 ? "" : "s")").font(DS.Font.caption) }
                        }
                    }
                }
            }
            if changeDetection {
                Section("Changes since last refresh") { changeSection }
            }
            if let message {
                Text(message).foregroundStyle(isError ? .red : .secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 560, height: 620)
        .onReceive(NotificationCenter.default.publisher(for: Self.syncNowNotification)) { _ in apply() }
        .onAppear {
            load()
            if checkOnAppear { check() }
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) { Button("Save", action: save) }
        }
    }

    private var names: [String] { Set(usage.keys).union(answers.keys).sorted() }

    @ViewBuilder private var changeSection: some View {
        HStack {
            Button("Sync Now", action: apply).accessibilityIdentifier("ssh-sync-now")
            Button("Check for Changes", action: check)
            Spacer()
            Text(lastSyncedText).font(DS.Font.caption).foregroundStyle(.secondary).accessibilityIdentifier("ssh-last-synced")
        }
        Toggle("Also import new hosts", isOn: $importAdded)
        if let p = preview {
            if !p.hasBaseline {
                Text("No baseline yet: every host counts as new. Importing or applying sets the baseline.").font(DS.Font.caption).foregroundStyle(.secondary)
            }
            if p.hosts.isEmpty {
                Text("No changes in \(p.root).").foregroundStyle(.secondary)
            }
            ForEach(p.hosts, id: \.identity) { c in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(c.kind.capitalized).font(DS.Font.caption.bold()).foregroundStyle(color(c.kind))
                        Text(c.alias)
                        Spacer()
                        Text(c.sourceFile).font(DS.Font.caption).foregroundStyle(.secondary)
                    }
                    ForEach(c.fields, id: \.field) { f in
                        Text("\(f.field): \(f.old ?? "—") → \(f.new ?? "—")").font(DS.Font.caption.monospaced()).foregroundStyle(.secondary)
                    }
                }
            }
            if !p.hosts.isEmpty {
                Text("Changed hosts are updated; your favourites, tags, notes and overrides stay. Removed hosts are kept and marked, not deleted.")
                    .font(DS.Font.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var lastSyncedText: String {
        guard let s = preview?.lastSyncedSecs else { return "Never synced" }
        let d = Date(timeIntervalSince1970: TimeInterval(s))
        return "Last synced \(d.formatted(date: .abbreviated, time: .shortened))"
    }

    private func color(_ kind: String) -> Color {
        switch kind {
        case "added": return .green
        case "removed": return .red
        default: return .orange
        }
    }

    private func load() {
        guard let wf = model.workflow else { return report("The SSH config workflow could not be opened.") }
        let s = wf.settings()
        (scanConfigD, placeholders, overrides, changeDetection) = (s.scanConfigD, s.placeholders, s.overrides, s.changeDetection)
        sshDir = s.sshDir ?? ""
        answers = wf.placeholderValues()
        usage = wf.sourcePlaceholders()
    }

    private func save() {
        guard let wf = model.workflow else { return }
        do {
            try wf.setSettings(v: WorkflowSettingsView(scanConfigD: scanConfigD, placeholders: placeholders, overrides: overrides,
                                                       changeDetection: changeDetection, sshDir: sshDir.isEmpty ? nil : sshDir))
            for name in names { try wf.setPlaceholder(name: name, value: answers[name] ?? "") }
            usage = wf.sourcePlaceholders()
            message = "Saved."
            isError = false
        } catch {
            report("\(error)")
        }
    }

    private func check() {
        guard let wf = model.workflow else { return }
        do { preview = try wf.changes(); message = nil } catch { report("\(error)") }
    }

    private func apply() {
        guard let wf = model.workflow, let lib = model.library else { return }
        do {
            let r = try wf.applyRefresh(library: lib, importAdded: importAdded)
            model.reload()
            preview = try wf.changes()
            message = "Synced: updated \(r.updated), marked \(r.markedRemoved) removed, imported \(r.added)."
            isError = false
        } catch {
            report("\(error)")
        }
    }

    private func report(_ m: String) {
        message = m
        isError = true
    }
}

/// Personal values for one imported host, stored apart from the config files.
struct OverridesSheet: View {
    let connection: ConnectionView
    let effective: EffectiveView
    @Environment(LibraryModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var user = ""
    @State private var hostname = ""
    @State private var port = ""
    @State private var identityFile = ""
    @State private var proxyJump = ""
    @State private var credentialRef = ""
    @State private var answers: [String: String] = [:]
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                TextField("User", text: $user, prompt: Text(effective.user ?? "from config"))
                TextField("HostName", text: $hostname, prompt: Text(effective.hostname))
                TextField("Port", text: $port, prompt: Text(effective.port.map(String.init) ?? "22"))
                TextField("IdentityFile", text: $identityFile, prompt: Text(effective.identityFile ?? "none"))
                TextField("ProxyJump", text: $proxyJump, prompt: Text(effective.proxyJump ?? "none"))
                TextField("Credential reference", text: $credentialRef, prompt: Text("provider:item"))
            } header: {
                Text("Overrides for \(connection.name)")
            } footer: {
                Text("Leave a field empty to use the value from the SSH config.")
            }
            if !effective.sourcePlaceholders.isEmpty {
                Section("Placeholder values for this host") {
                    ForEach(effective.sourcePlaceholders, id: \.self) { name in
                        TextField("<\(name)>", text: Binding(get: { answers[name] ?? "" }, set: { answers[name] = $0 }),
                                  prompt: Text("global value"))
                    }
                }
            }
            if let error { Text(error).foregroundStyle(.red) }
        }
        .formStyle(.grouped)
        .frame(width: 440)
        .onAppear(perform: load)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button("Save", action: save).disabled(!port.isEmpty && UInt16(port) == nil)
            }
        }
    }

    private func load() {
        guard let o = model.workflow?.getOverride(identity: effective.identity) else { return }
        user = o.user ?? ""
        hostname = o.hostname ?? ""
        port = o.port.map(String.init) ?? ""
        identityFile = o.identityFile ?? ""
        proxyJump = o.proxyJump ?? ""
        credentialRef = o.credentialRef ?? ""
        answers = o.placeholders
    }

    private func save() {
        let v = HostOverrideView(user: user, hostname: hostname, port: UInt16(port), identityFile: identityFile,
                                 proxyJump: proxyJump, credentialRef: credentialRef, placeholders: answers)
        do {
            try model.workflow?.setOverride(identity: effective.identity, v: v)
            model.reload()
            dismiss()
        } catch {
            self.error = "\(error)"
        }
    }
}
