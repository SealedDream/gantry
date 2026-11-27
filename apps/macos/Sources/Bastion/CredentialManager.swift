import AppKit
import SwiftUI
import BastionCore

enum CredentialSource: String, CaseIterable, Identifiable {
    case local, vaultwarden, onepassword, keepass, hcvault
    var id: String { rawValue }
}

/// Credential Manager window: credential sources on the left (with their lock state), the chosen
/// source's workspace on the right. Secrets are write-only here; listings carry names and usernames.
struct CredentialManagerView: View {
    static let windowId = "credentials"
    @Environment(CredentialsModel.self) private var credentials
    @Environment(VaultwardenModel.self) private var vaultwarden

    var body: some View {
        @Bindable var credentials = credentials
        NavigationSplitView {
            List(selection: Binding(get: { credentials.source }, set: { if let s = $0 { credentials.source = s } })) {
                Section("Sources") {
                    sourceRow(.local, title: "Local Vault", symbol: "lock.shield",
                              status: credentials.vault == nil ? "Locked" : count(credentials.items.count, "credential"))
                    sourceRow(.vaultwarden, title: "Vaultwarden", symbol: "server.rack", status: vaultwardenStatus)
                    ForEach(ExternalProviders.Kind.allCases) { k in
                        sourceRow(CredentialSource(rawValue: k.rawValue)!, title: k.title, symbol: k.symbol, status: ExternalProviders.shared.status(k))
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 260)
        } detail: {
            switch credentials.source {
            case .local: LocalVaultPane()
            case .vaultwarden: VaultwardenProviderPane()
            case .onepassword, .keepass, .hcvault: ExternalProviderPane(kind: ExternalProviders.Kind(rawValue: credentials.source.rawValue)!).id(credentials.source)
            }
        }
        .frame(minWidth: 760, minHeight: 460)
        .onAppear { vaultwarden.refresh() }
    }

    private var vaultwardenStatus: String {
        if vaultwarden.configuredServer == nil { return "Not set up" }
        return vaultwarden.isUnlocked ? count(vaultwarden.items.count, "item") : "Locked"
    }

    private func sourceRow(_ source: CredentialSource, title: String, symbol: String, status: String) -> some View {
        HStack(spacing: DS.Space.xs) {
            Image(systemName: symbol).frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                Text(status).font(DS.Font.caption).foregroundStyle(.secondary)
            }
        }
        .tag(source)
        .accessibilityLabel("\(title), \(status)")
    }
}

func count(_ n: Int, _ noun: String) -> String { "\(n) \(noun)\(n == 1 ? "" : "s")" }

/// A source's name and status go in the window's title and subtitle and its actions in the
/// toolbar, rather than a second header strip under the toolbar.
extension View {
    func sourceHeader<Actions: View>(_ title: String, status: String, @ViewBuilder actions: () -> Actions) -> some View {
        navigationTitle(title)
            .navigationSubtitle(status)
            .toolbar { ToolbarItemGroup(placement: .primaryAction) { actions() } }
    }
}

/// Finished empty state: subtle icon, short title, one line, one action.
struct EmptyState<Action: View>: View {
    let symbol: String
    let title: String
    let message: String
    @ViewBuilder let action: Action

    var body: some View {
        VStack(spacing: DS.Space.xs) {
            Image(systemName: symbol).font(DS.Font.size(28, weight: .light)).foregroundStyle(.tertiary)
            Text(title).font(DS.Font.bodyStrong)
            Text(message).font(DS.Font.body).foregroundStyle(.secondary).multilineTextAlignment(.center)
            action.padding(.top, DS.Space.xxs)
        }
        .frame(maxWidth: DS.Size.emptyStateWidth)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Local encrypted vault: status, searchable list filtered by type, and the editor.
private struct LocalVaultPane: View {
    @Environment(CredentialsModel.self) private var credentials
    @Environment(SessionsModel.self) private var sessions
    @Environment(VaultwardenModel.self) private var vaultwarden
    @State private var selected: Set<String> = []
    @State private var query = ""
    @State private var sort = [KeyPathComparator(\CredentialRow.name)]
    @State private var isOpening = false

    /// The editor shows the one selected credential; none (or several) means "new".
    private var selection: Binding<String?> {
        Binding(get: { selected.count == 1 ? selected.first : nil }, set: { selected = $0.map { [$0] } ?? [] })
    }

    var body: some View {
        Group {
            if credentials.vault == nil {
                EmptyState(symbol: "lock", title: "Local Vault is locked", message: "Unlocking reads the vault key from the system keychain.") {
                    Button("Unlock", action: unlock).keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(isOpening)
                }
            } else {
                HSplitView {
                    list.frame(minWidth: 300, idealWidth: 380, maxWidth: 520)
                    CredentialEditor(selection: selection).frame(minWidth: 320, maxWidth: .infinity)
                }
            }
        }
        .sourceHeader("Local Vault", status: credentials.vault == nil ? "Locked · Protected by system keychain"
                      : "Unlocked · \(count(credentials.items.count, "credential")) · Protected by system keychain") {
            if credentials.vault != nil {
                Button("Lock", systemImage: "lock") { credentials.lockAll(sessions: sessions, vaultwarden: vaultwarden) }
                    .iconTip("Lock the local vault and Vaultwarden")
            }
        }
        .alert("Credential Vault", isPresented: Binding(get: { credentials.error != nil }, set: { if !$0 { credentials.error = nil } })) {
            Button("OK") { credentials.error = nil }
        } message: { CodedAlert.text("VAULT", credentials.error) }
    }

    private var shown: [CredentialRow] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        return credentials.items
            .filter { c in q.isEmpty || [c.name, c.username, c.folder ?? ""].contains { $0.lowercased().contains(q) } }
            .map(CredentialRow.init)
            .sorted(using: sort)
    }

    private var list: some View {
        VStack(spacing: 0) {
            TextField("Search", text: $query).textFieldStyle(.roundedBorder).padding(DS.Space.xs)
            Table(shown, selection: $selected, sortOrder: $sort) {
                TableColumn("Name", value: \.name) { r in Label(r.name, systemImage: r.symbol) }
                TableColumn("Username", value: \.username) { r in Text(r.username).foregroundStyle(.secondary) }
                TableColumn("Folder", value: \.folder) { r in Text(r.folder).foregroundStyle(.secondary) }
                TableColumn("Type", value: \.type) { r in Text(r.type).foregroundStyle(.secondary) }.width(70)
            }
            .contextMenu(forSelectionType: String.self) { ids in
                Button("Copy Username") { copyUsernames(ids) }.disabled(ids.isEmpty)
                Divider()
                Button(ids.count > 1 ? "Delete \(ids.count) Credentials" : "Delete", role: .destructive) { delete(ids) }
                    .disabled(ids.isEmpty)
            }
            .onDeleteCommand { delete(selected) }
            .overlay {
                if credentials.items.isEmpty {
                    EmptyState(symbol: "key", title: "No credentials", message: "Add a password or SSH key to use it for connections.") {
                        Button("Add Credential") { selected = [] }
                    }
                } else if shown.isEmpty {
                    ContentUnavailableView.search(text: query)
                }
            }
            Divider()
            HStack(spacing: DS.Space.xs) {
                Button("Add", systemImage: "plus") { selected = [] }.labelStyle(.iconHitTarget).help("Add credential")
                Button("Delete", systemImage: "minus") { delete(selected) }.labelStyle(.iconHitTarget).help("Delete the selected credentials")
                    .disabled(selected.isEmpty)
                Spacer()
            }
            .buttonStyle(.borderless)
            .padding(DS.Space.xs)
        }
    }

    private func unlock() {
        isOpening = true
        Task {
            await credentials.openInBackground(sessions: sessions)
            isOpening = false
            selected = credentials.items.first.map { [$0.id] } ?? []
        }
    }

    private func delete(_ ids: Set<String>) {
        guard !ids.isEmpty else { return }
        if credentials.mutate({ v in for id in ids { try v.remove(id: id) } }) { selected = [] }
    }

    private func copyUsernames(_ ids: Set<String>) {
        let names = credentials.items.filter { ids.contains($0.id) }.map(\.username).filter { !$0.isEmpty }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(names.joined(separator: "\n"), forType: .string)
    }
}

/// Add or edit one credential. The secret field is write-only: empty on edit keeps the stored one.
private struct CredentialEditor: View {
    @Binding var selection: String?
    @Environment(CredentialsModel.self) private var credentials
    @Environment(LibraryModel.self) private var library
    @State private var draft = Draft()
    @State private var generating = false

    struct Draft: Equatable {
        var id: String?
        var name = ""
        var folder = ""
        var username = ""
        var kind = Kind.password
        var secret = ""
    }

    enum Kind: String, CaseIterable { case password = "Password", sshKey = "SSH Key" }

    var body: some View {
        Form {
            Section(draft.id == nil ? "New credential" : "Details") {
                TextField("Name", text: $draft.name)
                TextField("Folder", text: $draft.folder, prompt: Text("Optional"))
                Picker("Type", selection: $draft.kind) { ForEach(Kind.allCases, id: \.self) { Text($0.rawValue) } }
                    .pickerStyle(.segmented)
                    .disabled(draft.id != nil)
                TextField("Username", text: $draft.username)
                if draft.kind == .password {
                    LabeledContent("Password") {
                        HStack {
                            SecureField("Password", text: $draft.secret, prompt: Text(draft.id == nil ? "Required" : "Unchanged"))
                                .labelsHidden()
                            Button("Generate…") { generating = true }.fixedSize()
                        }
                    }
                } else {
                    LabeledContent("Private key") {
                        HStack {
                            SecureField("Private key", text: $draft.secret, prompt: Text(draft.id == nil ? "Paste or choose" : "Unchanged"))
                                .labelsHidden()
                            Button("Choose…", action: chooseKey).fixedSize()
                        }
                    }
                    .help("Unencrypted OpenSSH or PEM keys. Keep passphrase-protected keys as key files.")
                }
            }
            if !usedBy.isEmpty {
                Section("Used by") { Text(usedBy.joined(separator: ", ")).foregroundStyle(.secondary) }
            }
        }
        .formStyle(.grouped)
        // The commit button sits under the form like a dialog's, not inside a grouped box of its own.
        .safeAreaInset(edge: .bottom, spacing: 0) {
            HStack {
                Spacer()
                Button(draft.id == nil ? "Add Credential" : "Save", action: save)
                    .keyboardShortcut(.defaultAction).dsPrimaryButton()
                    .disabled(draft.name.trimmingCharacters(in: .whitespaces).isEmpty || (draft.id == nil && draft.secret.isEmpty))
            }
            .padding(.horizontal, DS.Space.l)
            .padding(.bottom, DS.Space.m)
        }
        .sheet(isPresented: $generating) { PasswordGeneratorSheet { draft.secret = $0 } }
        .onAppear { load(selection) }
        .onChange(of: selection) { _, id in load(id) }
    }

    private var usedBy: [String] {
        guard let id = draft.id, let tree = library.tree else { return [] }
        func walk(_ f: FolderView) -> [String] { f.connections.filter { $0.credentialId == id }.map(\.name) + f.folders.flatMap(walk) }
        return walk(tree)
    }

    private func load(_ id: String?) {
        credentials.error = nil
        guard let c = credentials.credential(id: id) else { draft = Draft(); return }
        draft = Draft(id: c.id, name: c.name, folder: c.folder ?? "", username: c.username, kind: c.kind == "ssh-key" ? .sshKey : .password)
    }

    private func save() {
        var savedId: String?
        let d = draft
        let ok = credentials.mutate { v in
            savedId = d.kind == .password
                ? try v.savePassword(id: d.id, name: d.name, folder: d.folder, username: d.username, password: d.secret)
                : try v.saveSshKey(id: d.id, name: d.name, folder: d.folder, username: d.username, privateKey: d.secret)
        }
        draft.secret = ""
        if ok { selection = savedId; load(savedId) }
    }

    private func chooseKey() {
        let panel = NSOpenPanel()
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        panel.showsHiddenFiles = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { draft.secret = try String(contentsOf: url, encoding: .utf8) } catch { credentials.error = "Could not read the key file: \(error.localizedDescription)" }
    }
}

/// One row of the credentials table, with sortable string columns.
struct CredentialRow: Identifiable {
    let id: String
    let name: String
    let username: String
    let folder: String
    let type: String
    let symbol: String

    init(_ c: CredentialView) {
        id = c.id
        name = c.name
        username = c.username
        folder = c.folder ?? ""
        // "unsupported": a kind a newer version wrote; kept as is, delete only.
        type = c.kind == "ssh-key" ? "SSH key" : c.kind == "unsupported" ? "Unsupported" : "Password"
        symbol = c.kind == "ssh-key" ? "key" : c.kind == "unsupported" ? "questionmark.circle" : "person.badge.key"
    }
}
