import SwiftUI
import BastionCore

/// The Credentials page's pending choice. Assignments (`credential_id`, `credential_name`) are
/// properties in the library; an inline secret goes to the vault under the connection's id and
/// only a marker goes to the library (`Library.setInlineMarker`).
@MainActor @Observable
final class CredentialDraft {
    enum Mode: String, CaseIterable, Identifiable {
        case inline = "Specify username and password"
        case existing = "Use an existing credential"
        case parent = "Use the parent folder's credential"
        case name = "Specify a credential name"
        var id: String { rawValue }
    }
    enum Tab: String, CaseIterable { case credential = "Credential", keyFile = "Private Key File" }

    var mode = Mode.parent
    var tab = Tab.credential
    var credentialId: String?
    var credentialName = ""
    var username = ""
    var password = ""
    var keyPath = ""
    var keyText = ""
    var passphrase = ""
    /// What the connection had when the dialog opened (`password` / `ssh-key`), if anything.
    private(set) var storedInline: String?
    private var initial: (Mode, String?, String) = (.parent, nil, "")
    private(set) var dirty = false

    func load(values: [String: PropertyValueView], inlineKind: String?, inlineUser: String?) {
        storedInline = inlineKind
        credentialId = values["credential_id"]?.own
        credentialName = values["credential_name"]?.own ?? ""
        mode = inlineKind != nil ? .inline : credentialId != nil ? .existing : !credentialName.isEmpty ? .name : .parent
        tab = inlineKind == "ssh-key" ? .keyFile : .credential
        // The inline login starts from the connection's own user (set in New Connection or
        // General), so choosing "Specify username and password" or switching the Credential /
        // Private Key File tab never shows an empty username (owner feedback 2026-11-07 #5).
        username = inlineUser ?? values["username"]?.effective ?? ""
        password = ""; keyText = ""; keyPath = ""; passphrase = ""
        initial = (mode, credentialId, credentialName)
        dirty = false
    }

    func touch() { dirty = true }

    /// The Logins list changed the connection (saved at once): show its new default without
    /// turning that into a pending edit. Typed, unsaved fields are left alone.
    func loginsChanged(defaultId: String?) {
        credentialId = defaultId
        if mode == .existing || mode == .parent { mode = defaultId == nil ? .parent : .existing }
        initial = (mode, credentialId, initial.2)
    }

    /// Property edits implied by the choice: only the chosen kind of assignment stays set.
    var propertyEdits: [String: String] {
        guard dirty || (mode, credentialId, credentialName) != initial else { return [:] }
        return [
            "credential_id": mode == .existing ? (credentialId ?? "") : "",
            "credential_name": mode == .name ? credentialName.trimmingCharacters(in: .whitespaces) : "",
        ]
    }

    /// True when an inline secret must be written (new, changed) or removed.
    var inlineChanged: Bool {
        if mode != .inline { return storedInline != nil }
        return dirty
    }
}

struct CredentialsPage: View {
    let target: EditorTarget
    @Bindable var draft: CredentialDraft
    let values: [String: PropertyValueView]
    /// Renders an ordinary schema field (the User name override).
    let field: (PropertyDefView) -> AnyView
    let usernameDef: PropertyDefView?
    @Environment(CredentialsModel.self) private var credentials
    @Environment(SessionsModel.self) private var sessions
    @Environment(\.openWindow) private var openWindow
    @State private var reveal = false

    private var isConnection: Bool { !target.isDefaults }
    private var supportsKeys: Bool {
        if case .connection(_, _, let p) = target { return ["ssh", "sftp", "scp"].contains(p) }
        return false
    }
    private var modes: [CredentialDraft.Mode] { isConnection ? CredentialDraft.Mode.allCases : [.existing, .parent, .name] }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.m) {
            if supportsKeys && draft.mode == .inline {
                Picker("Kind", selection: Binding(get: { draft.tab }, set: { draft.tab = $0; draft.touch() })) {
                    ForEach(CredentialDraft.Tab.allCases, id: \.self) { Text($0.rawValue) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                .frame(maxWidth: .infinity)
            }
            Picker("Credential", selection: Binding(get: { draft.mode }, set: { draft.mode = $0; draft.touch() })) {
                ForEach(modes) { Text(label(for: $0)).tag($0) }
            }
            .labelsHidden()
            .accessibilityIdentifier("credential-mode")
            switch draft.mode {
            case .inline: inline
            case .existing: existing
            case .parent: parent
            case .name: named
            }
            // Saved credentials are the subject of these two choices; an inline secret or a name stands alone.
            if case .connection(let id, _, _) = target, draft.mode == .existing || draft.mode == .parent {
                LoginsList(connectionId: id) { draft.loginsChanged(defaultId: $0) }
            }
        }
        .task {
            if credentials.vault == nil { await credentials.openInBackground(sessions: sessions) }
            if case .connection(let id, _, _) = target, draft.storedInline != nil, !draft.dirty,
               let inline = try? credentials.vault?.inlineFor(connectionId: id) {
                draft.username = inline.username
            }
        }
    }

    private func label(for mode: CredentialDraft.Mode) -> String {
        if mode == .parent, case .type = target { return "Inherit nothing (ask when connecting)" }
        return mode.rawValue
    }

    // MARK: Modes

    @ViewBuilder private var inline: some View {
        Label("For Windows domain accounts use: domain\\username", systemImage: "info.circle")
            .font(DS.Font.caption).foregroundStyle(.secondary)
        row("Username") {
            TextField("Username", text: Binding(get: { draft.username }, set: { draft.username = $0; draft.touch() }))
                .textFieldStyle(.roundedBorder)
        }
        if draft.tab == .credential {
            row("Password") {
                HStack(spacing: DS.Space.xxs) {
                    Group {
                        let prompt = draft.storedInline == "password" ? "Saved — leave empty to keep" : "Password"
                        let text = Binding(get: { draft.password }, set: { draft.password = $0; draft.touch() })
                        if reveal { TextField(prompt, text: text) } else { SecureField(prompt, text: text) }
                    }
                    .textFieldStyle(.roundedBorder)
                    Button(reveal ? "Hide password" : "Show password", systemImage: reveal ? "eye.slash" : "eye") { reveal.toggle() }
                        .labelStyle(.iconHitTarget)
                        .buttonStyle(.borderless)
                        .help(reveal ? "Hide the password" : "Show the password while typing")
                }
            }
        } else {
            row("Key file") {
                HStack {
                    TextField(draft.storedInline == "ssh-key" ? "Saved key — choose a file or paste to replace" : "~/.ssh/id_ed25519",
                              text: Binding(get: { draft.keyPath }, set: { draft.keyPath = $0; draft.touch() }))
                        .textFieldStyle(.roundedBorder)
                    Button("Choose…", action: chooseKey)
                }
            }
            row("Or paste key") {
                TextEditor(text: Binding(get: { draft.keyText }, set: { draft.keyText = $0; draft.touch() }))
                    .font(DS.Font.style(.caption, design: .monospaced))
                    .frame(height: 64)
                    .overlay(RoundedRectangle(cornerRadius: 4).strokeBorder(.separator))
            }
            row("Passphrase") {
                SecureField("Only if the key is encrypted", text: Binding(get: { draft.passphrase }, set: { draft.passphrase = $0; draft.touch() }))
                    .textFieldStyle(.roundedBorder)
            }
            Text("The key is read once, decrypted with the passphrase and stored in the encrypted vault; the file is not needed afterwards.")
                .font(DS.Font.caption).foregroundStyle(.secondary)
        }
        warning
    }

    private var warning: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            Label(InlineSecretWarning.text, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            Text("Kept encrypted in this Mac's vault for this connection only: never in the library file or an export, deleted with the connection, and Production hosts ask again before it is used.")
                .font(DS.Font.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button("Open Credential Manager…", action: openManager)
        }
        .padding(DS.Space.s)
        .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
    }

    @ViewBuilder private var existing: some View {
        row("Credential") {
            if credentials.vault == nil {
                Text("Unlocking the vault…").foregroundStyle(.secondary)
            } else {
                HStack {
                    // Folders as sections; the first row goes back to inheriting from the parents.
                    Picker("Credential", selection: Binding(get: { draft.credentialId }, set: { id in
                        draft.credentialId = id
                        if id == nil { draft.mode = .parent }
                        draft.touch()
                    })) {
                        CredentialPickerRows(groups: CredentialPickerGroup.build(credentials.tree), inherit: inheritRow,
                                             detail: { $0.username.isEmpty ? $0.name : "\($0.name) (\($0.username))" })
                    }
                    .labelsHidden()
                    .accessibilityIdentifier("credential-picker")
                    Button("Manage…", action: openManager)
                }
            }
        }
        if credentials.vault != nil && credentials.items.isEmpty {
            Text("No saved credentials yet. Create one in the Credential Manager, then choose it here.")
                .font(DS.Font.caption).foregroundStyle(.secondary)
        }
        usernameOverride
    }

    @ViewBuilder private var parent: some View {
        Text(inheritedText).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        usernameOverride
    }

    @ViewBuilder private var named: some View {
        row("Credential name") {
            TextField("Name of a saved credential", text: Binding(get: { draft.credentialName }, set: { draft.credentialName = $0; draft.touch() }))
                .textFieldStyle(.roundedBorder)
        }
        Text(nameStatus).font(DS.Font.caption).foregroundStyle(.secondary)
        usernameOverride
    }

    @ViewBuilder private var usernameOverride: some View {
        if let usernameDef { field(usernameDef) }
    }

    private func row(_ label: String, @ViewBuilder _ content: () -> some View) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: DS.Space.s) {
            Text(label).font(DS.Font.bodyStrong).frame(width: DS.Size.editorLabel, alignment: .trailing)
            content()
        }
    }

    // MARK: Text

    /// What the item gets from further up when it sets nothing itself.
    private var inheritedText: String {
        let id = values["credential_id"], name = values["credential_name"]
        let from = { (v: PropertyValueView) -> String in
            v.source == "typedefault" ? "the \((v.from ?? "").uppercased()) Default Settings" : "“\(v.from ?? "Library")”"
        }
        if let id, id.own == nil, let eff = id.effective {
            let shown = credentials.credential(id: eff)?.name ?? "a saved credential"
            return "Uses \(shown), inherited from \(from(id))."
        }
        if let name, name.own == nil, let eff = name.effective {
            return "Uses the credential named “\(eff)”, inherited from \(from(name))."
        }
        return "Nothing is inherited: Gantry asks for a password when connecting."
    }

    /// "Inherit (name)" when the parents set a saved credential and this item sets none itself.
    private var inheritRow: String {
        guard let v = values["credential_id"], v.own == nil, let eff = v.effective else {
            return CredentialPickerGroup.inheritLabel(nil)
        }
        return CredentialPickerGroup.inheritLabel(credentials.credential(id: eff)?.name ?? "a saved credential")
    }

    private var nameStatus: String {
        let n = draft.credentialName.trimmingCharacters(in: .whitespaces)
        guard !n.isEmpty else { return "Looked up when connecting, so a shared library works with each person's own vault." }
        guard let vault = credentials.vault else { return "Looked up when connecting." }
        return vault.findByName(name: n) != nil ? "Found in your vault." : "No single credential in your vault has this name yet."
    }

    // MARK: Actions

    private func openManager() {
        credentials.source = .local
        openWindow(id: CredentialManagerView.windowId)
        bringToFront(CredentialManagerView.windowId)
    }

    private func chooseKey() {
        let panel = NSOpenPanel()
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        panel.showsHiddenFiles = true
        if panel.runModal() == .OK, let url = panel.url {
            draft.keyPath = url.path
            draft.touch()
        }
    }
}

/// Properties › Credentials › Logins: the saved logins of one connection, as the core lists them
/// (A1-NM-01, the Native Windows "Logins" dialog). The first own login is the default and
/// connects without asking; the others are offered in the connect sheet. Add, Remove and Make
/// Default are saved at once, like the Windows dialog.
struct LoginsList: View {
    let connectionId: String
    /// The connection's default credential id after a change.
    let changed: (String?) -> Void
    @Environment(CredentialsModel.self) private var credentials
    @Environment(LibraryModel.self) private var model
    @State private var selection: String?

    private var loaded: Result<[LoginOffer], Error> {
        _ = model.revision
        guard let vault = credentials.vault, let library = model.library else { return .success([]) }
        return Result { try LoginResolver.offers(for: connectionId, library: library, vault: vault, passwordsOnly: false) }
    }
    private var rows: [LoginOffer] { (try? loaded.get()) ?? [] }
    /// The core could not list the logins: said here, not shown as an empty list.
    private var loadError: String? {
        if case .failure(let error) = loaded { return "The logins could not be read: \(errorText(error))" }
        return nil
    }
    private var addable: [CredentialView] {
        let own = Set(rows.filter(\.isOwn).map(\.credentialId))
        return credentials.items.filter { !own.contains($0.id) }.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }
    private var selected: LoginOffer? { rows.first { $0.credentialId == selection } }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            Text("Logins").font(DS.Font.bodyStrong)
            if credentials.vault == nil {
                Text("Saved logins are locked.").foregroundStyle(.secondary)
            } else {
                if let loadError {
                    Text(loadError).font(DS.Font.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                }
                list
                HStack(spacing: DS.Space.xs) {
                    Menu("Add") {
                        ForEach(addable, id: \.id) { c in
                            Button(c.username.isEmpty ? c.name : "\(c.name) (\(c.username))") { add(c.id) }
                        }
                    }
                    .fixedSize()
                    .disabled(addable.isEmpty)
                    .help("Add a saved credential to this connection’s logins")
                    Button("Make Default") { if let s = selected { makeDefault(s.credentialId) } }
                        .disabled(selected == nil || selected?.source == "default")
                    Button("Remove") { if let s = selected { remove(s.credentialId) } }
                        .disabled(selected?.isOwn != true)
                    Spacer(minLength: 0)
                }
                Text(note).font(DS.Font.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityIdentifier("logins-list")
    }

    private var list: some View {
        VStack(spacing: 0) {
            if rows.isEmpty {
                Text("No saved login. Gantry asks when connecting.")
                    .foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(DS.Space.xs)
            }
            ForEach(rows) { row in
                HStack(spacing: DS.Space.xs) {
                    Image(systemName: row.kind == "ssh-key" ? "key" : "person").foregroundStyle(.secondary)
                    Text(row.username.isEmpty ? row.name : row.username).lineLimit(1)
                    Spacer(minLength: DS.Space.xs)
                    Text(row.origin).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
                .padding(.horizontal, DS.Space.xs)
                .frame(minHeight: 24)
                .background(selection == row.credentialId ? Color.accentColor.opacity(0.18) : .clear)
                .contentShape(Rectangle())
                .onTapGesture { selection = row.credentialId }
            }
        }
        .padding(.vertical, DS.Space.xxs)
        .overlay(RoundedRectangle(cornerRadius: 4).strokeBorder(.separator))
    }

    private var note: String {
        rows.contains { !$0.isOwn }
            ? "The default connects without asking. Logins marked From come from a folder; those marked Saved for belong to another connection on this host and are offered in the connect sheet."
            : "The default connects without asking; the others are offered in the connect sheet."
    }

    private func add(_ id: String) { change { try $0.addLogin(library: $1, connectionId: connectionId, credentialId: id) } }
    private func makeDefault(_ id: String) { change { try $0.setDefaultLogin(library: $1, connectionId: connectionId, credentialId: id) } }
    private func remove(_ id: String) { change { _ = try $0.removeLogin(library: $1, connectionId: connectionId, credentialId: id) } }

    private func change(_ edit: (CredentialVault, Library) throws -> Void) {
        LoginResolver.change(connectionId, model: model, credentials: credentials, edit)
        changed(model.connection(id: connectionId)?.credentialId)
    }
}

extension CredentialDraft {
    /// Write or remove the inline secret for `connectionId`. Returns an error sentence on failure.
    func saveInline(connectionId: String, library: Library, credentials: CredentialsModel) -> String? {
        // The connection's saved login is about to change: the one remembered for this run goes.
        if inlineChanged || !propertyEdits.isEmpty { credentials.forgetLastLogin(for: connectionId) }
        guard inlineChanged else { return nil }
        guard let vault = credentials.vaultForSave() else { return "Saved logins are locked; choose Unlock in Credentials, then Apply again." }
        do {
            if mode != .inline {
                _ = try vault.removeInline(connectionId: connectionId)
                try vault.save()
                try library.setInlineMarker(connectionId: connectionId, kind: nil)
                return nil
            }
            if tab == .credential {
                try vault.setInlinePassword(connectionId: connectionId, username: username, password: password)
            } else {
                var key = keyText
                if key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !keyPath.isEmpty {
                    key = try String(contentsOfFile: (keyPath as NSString).expandingTildeInPath, encoding: .utf8)
                }
                try vault.setInlineKey(connectionId: connectionId, username: username, privateKey: key, passphrase: passphrase.isEmpty ? nil : passphrase)
                key = ""
            }
            try vault.save()
            try library.setInlineMarker(connectionId: connectionId, kind: tab == .credential ? "password" : "ssh-key")
            password = ""; keyText = ""; passphrase = ""
            return nil
        } catch {
            return errorText(error)
        }
    }
}
