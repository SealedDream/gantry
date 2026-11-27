import SwiftUI
import BastionCore

/// Vaultwarden source of the Credential Manager. Not set up: a two-step setup (server, then
/// sign-in). Set up: provider status (server, lock state, last sync), unlock, and the item list.
struct VaultwardenProviderPane: View {
    @Environment(VaultwardenModel.self) private var vaultwarden
    @State private var settingUp = false

    var body: some View {
        if vaultwarden.configuredServer == nil || settingUp {
            VaultwardenSetupFlow(onDone: { settingUp = false }, canCancel: vaultwarden.configuredServer != nil)
        } else {
            VaultwardenStatusPane(changeAccount: { settingUp = true })
        }
    }
}

private struct VaultwardenSetupFlow: View {
    let onDone: () -> Void
    let canCancel: Bool
    @Environment(VaultwardenModel.self) private var vaultwarden
    @State private var step = Step.server
    @State private var server = ""
    @State private var serverProblem: String?
    @State private var password = ""
    @State private var code = ""

    enum Step { case server, signIn }

    var body: some View {
        @Bindable var vw = vaultwarden
        Form {
            switch step {
            case .server:
                Section {
                    TextField("Server", text: $server, prompt: Text("https://vault.example.com"))
                        .onSubmit(continueToSignIn)
                    if let serverProblem { Text(serverProblem).font(DS.Font.caption).foregroundStyle(.red) }
                } footer: {
                    footer("https only; http is allowed on this Mac for a local server.") {
                        Button("Continue", action: continueToSignIn).keyboardShortcut(.defaultAction).dsPrimaryButton()
                            .disabled(server.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
            case .signIn:
                Section {
                    LabeledContent("Server", value: vw.serverUrl)
                    TextField("E-mail", text: $vw.email)
                    SecureField("Master password", text: $password)
                    if vaultwarden.needsCode {
                        TextField("Authenticator code", text: $code, prompt: Text("6 digits"))
                    }
                    if let error = vaultwarden.error { CodedError(area: "VAULT", message: error) }
                } footer: {
                    footer("The master password is not stored.") {
                        Button("Back") { step = .server }
                        Button(vaultwarden.isBusy ? "Signing in…" : "Sign In", action: signIn).keyboardShortcut(.defaultAction).dsPrimaryButton()
                            .disabled(vaultwarden.isBusy || vw.email.isEmpty || password.isEmpty || (vaultwarden.needsCode && code.count != 6))
                    }
                }
            }
        }
        .formStyle(.grouped)
        .sourceHeader("Set up Vaultwarden", status: step == .server ? "Step 1 of 2 · Server" : "Step 2 of 2 · Sign in") {
            if canCancel { Button("Cancel", action: onDone) }
        }
        .onAppear { server = vaultwarden.serverUrl }
    }

    /// One hint line, then the step's buttons on the trailing edge.
    private func footer<B: View>(_ hint: String, @ViewBuilder buttons: () -> B) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(hint).font(DS.Font.caption).foregroundStyle(.secondary)
            Spacer()
            buttons()
        }
        .padding(.top, DS.Space.xxs)
    }

    private func continueToSignIn() {
        do {
            vaultwarden.serverUrl = try checkVaultwardenUrl(url: server)
            serverProblem = nil
            step = .signIn
        } catch {
            serverProblem = error.userMessage
        }
    }

    private func signIn() {
        Task {
            if await vaultwarden.unlock(password: password, code: vaultwarden.needsCode ? code : nil) {
                password = ""
                onDone()
            }
            code = ""
        }
    }
}

private struct VaultwardenStatusPane: View {
    let changeAccount: () -> Void
    @Environment(VaultwardenModel.self) private var vaultwarden
    @Environment(LibraryModel.self) private var library
    @State private var password = ""
    @State private var code = ""
    @State private var query = ""

    var body: some View {
        Group {
            if vaultwarden.isUnlocked { items } else { unlockForm }
        }
        .sourceHeader("Vaultwarden", status: status) {
            if vaultwarden.isUnlocked {
                Button("Sync", systemImage: "arrow.clockwise") { Task { await vaultwarden.resync() } }
                    .disabled(vaultwarden.isBusy).help("Fetch the items again")
                Button("Lock", systemImage: "lock") { vaultwarden.lock() }.help("Lock Vaultwarden")
            }
            Menu("More", systemImage: "ellipsis.circle") {
                Button("Change Account…", action: changeAccount)
            }
            .help("More")
        }
        .onAppear { vaultwarden.refresh() }
    }

    private var status: String {
        let host = URL(string: vaultwarden.configuredServer ?? "")?.host ?? vaultwarden.configuredServer ?? ""
        guard vaultwarden.isUnlocked else { return "\(host) · \(vaultwarden.email) · Locked" }
        let synced = vaultwarden.lastSync.map { "Synced \($0.formatted(.relative(presentation: .named)))" } ?? "Not synced"
        return "\(host) · Unlocked · \(synced)"
    }

    private var unlockForm: some View {
        Form {
            Section {
                LabeledContent("Account", value: vaultwarden.email)
                SecureField("Master password", text: $password).onSubmit(unlock)
                if vaultwarden.needsCode { TextField("Authenticator code", text: $code, prompt: Text("6 digits")) }
                if let error = vaultwarden.error { CodedError(area: "VAULT", message: error) }
            }
            HStack {
                Spacer()
                Button(vaultwarden.isBusy ? "Unlocking…" : "Unlock", action: unlock).keyboardShortcut(.defaultAction).dsPrimaryButton()
                    .disabled(vaultwarden.isBusy || password.isEmpty || (vaultwarden.needsCode && code.count != 6))
            }
        }
        .formStyle(.grouped)
    }

    private var shown: [VaultwardenItemView] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return vaultwarden.items }
        return vaultwarden.items.filter { $0.name.lowercased().contains(q) || ($0.username ?? "").lowercased().contains(q) }
    }

    private var items: some View {
        VStack(spacing: 0) {
            TextField("Search items", text: $query).textFieldStyle(.roundedBorder).padding(DS.Space.xs)
            Table(shown) {
                TableColumn("Name", value: \.name)
                TableColumn("Username") { Text($0.username ?? "—").foregroundStyle(.secondary) }
                TableColumn("Used by") { Text(usedBy($0.id).joined(separator: ", ")).foregroundStyle(.secondary) }
            }
            .overlay { if shown.isEmpty { ContentUnavailableView.search(text: query) } }
            if vaultwarden.skipped > 0 {
                Text("\(vaultwarden.skipped) organisation or unreadable items not shown")
                    .font(DS.Font.caption).foregroundStyle(.secondary).padding(DS.Space.xs)
            }
        }
    }

    private func unlock() {
        guard !password.isEmpty else { return }
        Task {
            if await vaultwarden.unlock(password: password, code: vaultwarden.needsCode ? code : nil) { password = "" }
            code = ""
        }
    }

    private func usedBy(_ id: String) -> [String] {
        guard let tree = library.tree else { return [] }
        func walk(_ f: FolderView) -> [String] { f.connections.filter { $0.vaultwardenItem == id }.map(\.name) + f.folders.flatMap(walk) }
        return walk(tree)
    }
}

extension VaultwardenItemView: Identifiable {}
