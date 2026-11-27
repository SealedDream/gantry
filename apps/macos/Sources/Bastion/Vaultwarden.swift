import SwiftUI
import BastionCore

/// A Vaultwarden (Bitwarden-compatible) account as a credential source. The master password is
/// typed per unlock and handed straight to the core; decrypted items stay in Rust and the UI
/// sees names and usernames only. Server URL and e-mail are remembered in `vaultwarden.json`.
@MainActor @Observable
final class VaultwardenModel {
    private(set) var items: [VaultwardenItemView] = []
    private(set) var isUnlocked = false
    private(set) var isBusy = false
    private(set) var skipped: UInt32 = 0
    /// The server asked for an authenticator code; the next unlock sends one.
    private(set) var needsCode = false
    var serverUrl = ""
    var email = ""
    var error: String?
    /// Server of the last successful sign-in (remembered in vaultwarden.json); nil until set up.
    private(set) var configuredServer: String?
    private(set) var lastSync: Date?
    let session: VaultwardenSession

    init(dataDir: URL) {
        session = VaultwardenSession(dataDir: dataDir.path)
        let config = session.config()
        serverUrl = config.serverUrl ?? ""
        email = config.email ?? ""
        configuredServer = config.serverUrl
    }

    func item(id: String?) -> VaultwardenItemView? { items.first { $0.id == id } }

    /// Logs in and syncs off the main thread. Returns false (with `error` set) on failure.
    /// When the account uses two-step login, the first attempt sets `needsCode` instead.
    @discardableResult
    func unlock(password: String, code: String? = nil) async -> Bool {
        let (session, url, mail) = (session, serverUrl, email)
        return await run { try session.unlock(serverUrl: url, email: mail, masterPassword: password, totp: code) }
    }

    /// Fetches the items again with the in-memory refresh token (no master password, no code).
    @discardableResult
    func resync() async -> Bool {
        let session = session
        return await run { try session.resync() }
    }

    private func run(_ call: @escaping @Sendable () throws -> [VaultwardenItemView]) async -> Bool {
        isBusy = true
        error = nil
        let result = await Task.detached { Result { try call() } }.value
        isBusy = false
        refresh()
        switch result {
        case .success:
            needsCode = false
            return true
        case .failure(FfiError.TwoFactorRequired):
            error = needsCode ? "That code was not accepted. Enter the current code." : nil
            needsCode = true
        case .failure(FfiError.AuthFailed): error = "Wrong e-mail or master password."
        case .failure(let e): error = "\(e)"
        }
        return false
    }

    func lock() {
        session.lock()
        needsCode = false
        refresh()
    }

    /// Re-read state after a change made elsewhere (Lock Credentials locks this session too).
    func refresh() {
        isUnlocked = session.isUnlocked()
        items = session.items()
        skipped = session.skipped()
        lastSync = session.lastSync().map { Date(timeIntervalSince1970: TimeInterval($0)) }
        configuredServer = session.config().serverUrl
    }
}

/// Inspector row: assign a Vaultwarden item to an SSH connection. Shown once unlocked (or when an
/// item is already assigned), since item names are only known while unlocked.
struct VaultwardenItemPicker: View {
    let connection: ConnectionView
    @Environment(VaultwardenModel.self) private var vaultwarden
    @Environment(LibraryModel.self) private var model

    var body: some View {
        if vaultwarden.isUnlocked || connection.vaultwardenItem != nil {
            InspectorRow("Vaultwarden") { picker }
        }
    }

    private var picker: some View {
        Picker("Vaultwarden", selection: Binding(
            get: { connection.vaultwardenItem },
            set: { id in model.mutate { try $0.setVaultwardenItem(connectionId: connection.id, itemId: id) } })) {
            Text("None").tag(String?.none)
            if let id = connection.vaultwardenItem, vaultwarden.item(id: id) == nil {
                Text("Assigned (locked)").tag(Optional(id))
            }
            ForEach(vaultwarden.items, id: \.id) { Text($0.name).tag(Optional($0.id)) }
        }
        .labelsHidden()
    }
}
