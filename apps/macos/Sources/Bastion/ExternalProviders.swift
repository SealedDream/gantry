import AppKit
import SwiftUI
import BastionCore

/// 1Password, KeePass and HashiCorp Vault as read-only credential sources (core `providers`).
/// Passwords, key files and tokens go straight to the core on unlock; the UI only ever sees
/// KeePass entry titles and usernames. A connect uses `SshLogin.provider("<id>:<item>")` and the
/// core reads the secret at dial time. Locations (never secrets) are remembered in providers.json.
@MainActor @Observable
final class ExternalProviders {
    static let shared = ExternalProviders(dataDir: LibraryModel.dataDir)

    enum Kind: String, CaseIterable, Identifiable {
        case onepassword, keepass, hcvault
        var id: String { rawValue }
        var title: String {
            switch self {
            case .onepassword: "1Password"
            case .keepass: "KeePass"
            case .hcvault: "HashiCorp Vault"
            }
        }
        var symbol: String {
            switch self {
            case .onepassword: "key.horizontal"
            case .keepass: "lock.doc"
            case .hcvault: "cylinder.split.1x2"
            }
        }
        /// What an item reference looks like, shown as a field prompt.
        var itemPrompt: String {
            switch self {
            case .onepassword: "vault/item/field"
            case .keepass: "entry uuid"
            case .hcvault: "path#key"
            }
        }
    }

    /// Where each provider lives. No secret is stored here.
    struct Config: Codable, Equatable {
        var opPath = ""
        var opAccount = ""
        var keepassPath = ""
        var vaultUrl = ""
        var vaultKv: UInt8 = 2
        var vaultNamespace = ""
    }

    var config: Config
    private(set) var handles: [Kind: CredentialProviderHandle] = [:]
    private(set) var statuses: [Kind: ProviderStatusView] = [:]
    private(set) var keepassItems: [ProviderItemView] = []
    var error: String?
    private let configURL: URL

    init(dataDir: URL) {
        configURL = dataDir.appendingPathComponent("providers.json")
        config = (try? JSONDecoder().decode(Config.self, from: Data(contentsOf: configURL))) ?? Config()
    }

    func status(_ kind: Kind) -> String {
        guard let s = statuses[kind] else { return "Not set up" }
        switch s.status {
        case "available": return kind == .keepass ? "Unlocked · \(count(keepassItems.count, "entry"))" : "Ready"
        case "locked": return "Locked"
        default: return s.reason.map { "Unavailable: \($0)" } ?? "Unavailable"
        }
    }

    func isReady(_ kind: Kind) -> Bool { statuses[kind]?.status == "available" }

    /// Any provider currently usable for logins (auto-lock must lock it too).
    var anyUnlocked: Bool { Kind.allCases.contains(where: isReady) }

    /// Opens (or re-opens with the current config) and, when given, unlocks and registers it so
    /// connects can read from it. Returns false with `error` set on failure.
    @discardableResult
    func open(_ kind: Kind, secret: String?, keyFile: String?) async -> Bool {
        error = nil
        save()
        let c = config
        let result: Result<(CredentialProviderHandle, ProviderCheck, [ProviderItemView]), Error> = await Task.detached {
            Result {
                let h: CredentialProviderHandle
                switch kind {
                case .onepassword: h = try CredentialProviderHandle.openOnepassword(opPath: c.opPath, account: c.opAccount)
                case .keepass: h = CredentialProviderHandle.openKeepass(path: (c.keepassPath as NSString).expandingTildeInPath)
                case .hcvault: h = try CredentialProviderHandle.openHcvault(baseUrl: c.vaultUrl, kvVersion: c.vaultKv, namespace: c.vaultNamespace)
                }
                let check = (kind == .onepassword && (secret ?? "").isEmpty) ? .ok : try h.unlock(secret: secret, keyfilePath: keyFile)
                if check == .ok { h.register() }
                return (h, check, check == .ok ? try h.items() : [])
            }
        }.value
        switch result {
        case .success(let (h, check, items)):
            handles[kind] = h
            if kind == .keepass { keepassItems = items }
            refresh()
            if check == .authFailed { error = kind == .onepassword ? "1Password refused the token or is signed out." : "\(kind.title) refused that password, key file or token." }
            return check == .ok
        case .failure(let e):
            error = errorText(e)
            return false
        }
    }

    /// Tests `item` without revealing it.
    func check(_ kind: Kind, item: String) async -> ProviderCheck? {
        guard let h = handles[kind] else { error = "\(kind.title) is not set up."; return nil }
        let r = await Task.detached { Result { try h.checkItem(item: item) } }.value
        switch r {
        case .success(let c): return c
        case .failure(let e): error = errorText(e); return nil
        }
    }

    func lock(_ kind: Kind) {
        handles[kind]?.lock()
        if kind == .keepass { keepassItems = [] }
        refresh()
    }

    /// Part of "Lock Credentials": every provider forgets its unlock and is unregistered.
    func lockAll() {
        lockAllProviders()
        handles.values.forEach { $0.lock() }
        keepassItems = []
        refresh()
    }

    func refresh() {
        statuses = handles.mapValues { $0.status() }
    }

    private func save() {
        do {
            try FileManager.default.createDirectory(at: configURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder().encode(config).write(to: configURL, options: .atomic)
        } catch {
            self.error = "providers.json was not saved: \(errorText(error))"
        }
    }
}

/// Credential Manager pane for one external provider: where it is, unlock, and item check.
struct ExternalProviderPane: View {
    let kind: ExternalProviders.Kind
    @State private var providers = ExternalProviders.shared
    @State private var secret = ""
    @State private var keyFile = ""
    @State private var busy = false
    @State private var item = ""
    @State private var checkResult: String?

    var body: some View {
        @Bindable var p = providers
        Form {
            Section("Location") {
                switch kind {
                case .onepassword:
                    TextField("op CLI path", text: $p.config.opPath, prompt: Text("Found on PATH"))
                    TextField("Account", text: $p.config.opAccount, prompt: Text("Default account"))
                    SecureField("Service-account token", text: $secret, prompt: Text("Optional; desktop-app sign-in needs none"))
                case .keepass:
                    HStack {
                        TextField("Database", text: $p.config.keepassPath, prompt: Text("~/Passwords.kdbx"))
                        Button("Choose…") { choose { p.config.keepassPath = $0 } }
                    }
                    SecureField("Master password", text: $secret)
                    HStack {
                        TextField("Key file", text: $keyFile, prompt: Text("Optional"))
                        Button("Choose…") { choose { keyFile = $0 } }
                    }
                case .hcvault:
                    TextField("Server", text: $p.config.vaultUrl, prompt: Text("https://vault.example.com/v1/secret"))
                    Picker("KV version", selection: $p.config.vaultKv) { Text("1").tag(UInt8(1)); Text("2").tag(UInt8(2)) }
                        .pickerStyle(.segmented)
                    TextField("Namespace", text: $p.config.vaultNamespace, prompt: Text("Optional"))
                    SecureField("Token", text: $secret)
                }
            }
            if kind == .keepass, !providers.keepassItems.isEmpty {
                Section("Entries") {
                    Table(providers.keepassItems) {
                        TableColumn("Title", value: \.title)
                        TableColumn("Username") { Text($0.username ?? "") }
                        TableColumn("Group") { Text($0.group.joined(separator: "/")) }
                    }
                    .frame(minHeight: 160)
                }
            }
            if providers.statuses[kind] != nil {
                Section("Check an item") {
                    HStack {
                        TextField("Item", text: $item, prompt: Text(kind.itemPrompt))
                        Button("Check") { Task { await runCheck() } }.disabled(item.isEmpty || busy)
                    }
                    if let checkResult { Text(checkResult).font(DS.Font.caption).foregroundStyle(.secondary) }
                    Text("Connections use \(kind.rawValue):\(kind.itemPrompt) as their login.").font(DS.Font.caption).foregroundStyle(.secondary)
                }
            }
            if let e = providers.error { Text(e).foregroundStyle(.red) }
        }
        .formStyle(.grouped)
        .disabled(busy)
        .sourceHeader(kind.title, status: providers.status(kind)) {
            if providers.isReady(kind) {
                Button("Lock", systemImage: "lock") { providers.lock(kind) }
            }
            Button(providers.isReady(kind) ? "Reconnect" : "Unlock", systemImage: "lock.open") { Task { await unlock() } }
                .disabled(busy || !canUnlock)
        }
    }

    private var canUnlock: Bool {
        switch kind {
        case .onepassword: true
        case .keepass: !providers.config.keepassPath.isEmpty && (!secret.isEmpty || !keyFile.isEmpty)
        case .hcvault: !providers.config.vaultUrl.isEmpty && !secret.isEmpty
        }
    }

    private func unlock() async {
        busy = true
        defer { busy = false }
        if await providers.open(kind, secret: secret.isEmpty ? nil : secret, keyFile: keyFile.isEmpty ? nil : keyFile) { secret = "" }
    }

    private func runCheck() async {
        busy = true
        defer { busy = false }
        checkResult = switch await providers.check(kind, item: item) {
        case .ok: "Found. The secret stays in the core."
        case .notFound: "No such item."
        case .authFailed: "\(kind.title) refused access."
        case nil: nil
        }
    }

    private func choose(_ pick: (String) -> Void) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url { pick(url.path) }
    }
}

/// Connect sheet rows for a provider login: provider, then a KeePass entry or a typed item.
struct ProviderLoginFields: View {
    @Binding var reference: String
    @State private var providers = ExternalProviders.shared
    @State private var kind = ExternalProviders.Kind.keepass
    @State private var item = ""

    var body: some View {
        Picker("Provider", selection: $kind) {
            ForEach(ExternalProviders.Kind.allCases) { Text($0.title).tag($0) }
        }
        .onChange(of: kind) { _, _ in item = ""; update() }
        .onAppear(perform: load)
        if !providers.isReady(kind) {
            Text("\(kind.title) is \(providers.status(kind).lowercased()). Unlock it in More → Credentials….").foregroundStyle(.secondary)
        } else if kind == .keepass {
            Picker("Entry", selection: $item) {
                Text("Choose…").tag("")
                ForEach(providers.keepassItems, id: \.id) { Text("\($0.title) (\($0.username ?? "no user"))").tag($0.id) }
            }
            .onChange(of: item) { _, _ in update() }
        } else {
            TextField("Item", text: $item, prompt: Text(kind.itemPrompt))
                .onChange(of: item) { _, _ in update() }
        }
    }

    private func load() {
        guard let i = reference.firstIndex(of: ":"), let k = ExternalProviders.Kind(rawValue: String(reference[..<i])) else { return }
        kind = k
        item = String(reference[reference.index(after: i)...])
    }

    private func update() {
        reference = providers.isReady(kind) && !item.isEmpty ? "\(kind.rawValue):\(item)" : ""
    }
}

extension ProviderItemView: Identifiable {}
