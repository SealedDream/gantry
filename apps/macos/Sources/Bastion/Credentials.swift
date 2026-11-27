import SwiftUI
import LocalAuthentication
import BastionCore

/// The encrypted credential vault (`credentials.vault` next to the library). Opened lazily,
/// because opening reads the vault key from the login Keychain. Secrets typed here go straight
/// to the core and are never read back; listings carry names and usernames only.
@MainActor @Observable
final class CredentialsModel {
    private(set) var items: [CredentialView] = []
    /// The Credentials section: folders and credentials with their parent (names only, no secrets).
    private(set) var tree: [CredentialTreeItemView] = []
    /// Set by the UI driver to show the delete-in-use sheet as the section would.
    var pendingInUse: CredentialInUse?
    private(set) var vault: CredentialVault?
    var error: String?
    /// Source shown in the Credential Manager window.
    var source: CredentialSource = .local

    static var vaultPath: URL { LibraryModel.dataDir.appendingPathComponent("credentials.vault") }

    /// The login a connection last signed in with when it was typed (password, key file), or the
    /// offered vault login the user confirmed (by id, no secret): memory only, dropped when the
    /// vault locks, the app quits or the connection's logins change. Reconnect, Recent sessions
    /// and a second double-click reuse it with no prompt (owner feedback 2026-11-07 #2, #3).
    /// SEC-03: reused only while the core's rule allows (`security.session-login-reuse-minutes`
    /// and the managed maximum), counted from the last successful sign-in.
    @ObservationIgnored private var lastLogins = RememberedLoginStore<RememberedLogin>(
        usable: { rememberedLoginUsable(rememberedAt: $0, now: $1, minutes: $2) })
    /// Set by the app: the user's `security.session-login-reuse-minutes` (0 = until Lock or quit).
    var userReuseMinutes: () -> UInt32 = { 0 }

    /// Call after every successful sign-in with this login: its reuse time starts again.
    func remember(_ login: RememberedLogin, for connectionId: String) { lastLogins.remember(login, for: connectionId) }
    func lastLogin(for connectionId: String) -> RememberedLogin? { lastLogins.login(for: connectionId, minutes: sessionLoginReuseMinutes(userMinutes: userReuseMinutes())) }
    func forgetLastLogin(for connectionId: String) { lastLogins.forget(connectionId) }

    /// Set by the app from `security.confirm-vault-open`: opening needs the device owner first.
    var confirmOpen: () -> Bool = { false }
    /// The Touch ID / password request in progress (the UI driver cancels it after a capture).
    private(set) var pendingConfirmation: LAContext?
    /// Bumped by `lock()`: an open that started before a lock must not install its vault afterwards.
    private(set) var lockGeneration = 0
    /// Reads the vault off the main thread. The UI driver swaps it to hold a read open (M03 race test).
    var readVault: @Sendable (String) async throws -> CredentialVault = { path in
        try await Task.detached { try CredentialVault.open(path: path) }.value
    }

    /// Opens the vault once and hands it to the session manager for vault logins. With Touch ID
    /// confirmation on, only `openInBackground` can open it (the prompt is asynchronous).
    /// The vault inside the Personal document (OF-F). Set by the app; when it returns a vault no
    /// Keychain read happens at all, so there is nothing to prompt for or cancel.
    var personalVault: () -> CredentialVault? = { nil }
    /// One legacy Keychain read at a time: every caller awaits the same task (owner point 14:
    /// concurrent callers each started a read, so the prompt appeared twice).
    private var pendingRead: Task<Void, Never>?

    /// Install the document's vault when there is one. True when the vault is now open.
    private func useDocumentVault(_ sessions: SessionsModel?) -> Bool {
        if vault != nil { return true }
        guard let v = personalVault() else { return false }
        vault = v
        refresh(v)
        sessions?.useVault(v)
        pruneInline(library: currentLibrary())
        error = nil
        return true
    }

    /// The vault for saving typed secrets: open, or reopened from the Personal document without a
    /// prompt. `nil` only for the old layout while its Keychain read was cancelled.
    func vaultForSave() -> CredentialVault? {
        if vault == nil { _ = useDocumentVault(nil) }
        return vault
    }

    /// Opening now shows no prompt: it is open, or the Personal document holds it and no
    /// confirmation is asked. `LoginResolver` then looks for offered logins on any connection.
    var opensWithoutPrompt: Bool { vault != nil || (!confirmOpen() && personalVault() != nil) }

    @discardableResult
    func open(sessions: SessionsModel) -> CredentialVault? {
        if let vault { return vault }
        if confirmOpen() { return nil }
        if useDocumentVault(sessions) { return vault }
        do {
            let v = try CredentialVault.open(path: Self.vaultPath.path)
            vault = v
            refresh(v)
            sessions.useVault(v)
            pruneInline(library: currentLibrary())
            return v
        } catch {
            if !KeychainQuiet.isCancel(error) { self.error = "Could not open saved logins: \(KeychainQuiet.message(error))" }
            return nil
        }
    }

    /// Like `open`, but the Keychain read (which may wait for a system prompt) runs off the main thread.
    func openInBackground(sessions: SessionsModel) async {
        guard vault == nil else { return }
        if let pendingRead { await pendingRead.value; return }
        let task = Task { await openInBackgroundOnce(sessions: sessions) }
        pendingRead = task
        await task.value
        pendingRead = nil
    }

    private func openInBackgroundOnce(sessions: SessionsModel) async {
        let generation = lockGeneration
        if confirmOpen() {
            guard pendingConfirmation == nil else { return }
            let context = LAContext()
            pendingConfirmation = context
            defer { if pendingConfirmation === context { pendingConfirmation = nil } }
            // Touch ID where available, otherwise the login password; the system draws the prompt.
            do {
                guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "open the credential vault") else { return }
            } catch {
                if generation == lockGeneration, !KeychainQuiet.isCancel(error), (error as? LAError)?.code != .userCancel, (error as? LAError)?.code != .appCancel {
                    self.error = "Saved logins stay locked: \(error.localizedDescription)"
                }
                return
            }
        }
        if generation == lockGeneration, useDocumentVault(sessions) { return }
        let path = Self.vaultPath.path
        do {
            let v = try await readVault(path)
            // Locked (or opened elsewhere) while the read was pending: drop this result.
            guard generation == lockGeneration, vault == nil else { return }
            vault = v
            refresh(v)
            sessions.useVault(v)
            pruneInline(library: currentLibrary())
        } catch {
            if generation == lockGeneration, !KeychainQuiet.isCancel(error) { self.error = "Could not open saved logins: \(KeychainQuiet.message(error))" }
        }
    }

    private func refresh(_ v: CredentialVault) {
        items = v.list()
        tree = v.treeItems()
    }

    /// Re-read the listings after a change made off the main thread (KeePass import).
    func reload() {
        if let vault { refresh(vault) }
    }

    func credential(id: String?) -> CredentialView? { items.first { $0.id == id } }

    /// Delete inline secrets of connections no longer in `library` (after a delete or a purge).
    /// The live set is the tree plus Recently Deleted (B10), so a deleted connection keeps its
    /// password until it is purged. A locked vault is pruned the next time this runs while it is open.
    func pruneInline(library: Library?) {
        guard let library, let vault else { return }
        do {
            // Saved only when something was removed: a save reseals the vault (Argon2, ~90 ms on the
            // main thread), and the prune on every background open of the vault stalled the window
            // with nothing to write (first folder select in perf-budgets, 2026-11-16).
            guard try vault.pruneInline(liveConnectionIds: library.liveConnectionIds()) > 0 else { return }
            try vault.save()
            refresh(vault)
        } catch {
            self.error = "\(error)"
        }
    }

    /// The open library, for pruning when the vault opens (set by the app).
    var currentLibrary: () -> Library? = { nil }

    /// UI driver only: an in-memory-key vault in the throwaway library (no Keychain item).
    func openEphemeralForTest(sessions: SessionsModel) {
        let path = Self.vaultPath.appendingPathExtension("test").path
        do {
            let v: CredentialVault
            do { v = try CredentialVault.openEphemeral(path: path) } catch {
                // A test vault left by an earlier run on this folder is sealed with a key that
                // died with that run: nothing can open it again. Start a new one.
                try FileManager.default.removeItem(atPath: path)
                v = try CredentialVault.openEphemeral(path: path)
            }
            vault = v
            refresh(v)
            sessions.useVault(v)
        } catch {
            self.error = "\(error)"
        }
    }

    /// Forget the decrypted vault here; the next use opens it again from the Keychain.
    func lock() {
        lockGeneration += 1
        TabPreviews.shared.clear()
        pendingConfirmation?.invalidate()
        pendingConfirmation = nil
        vault = nil
        items = []
        tree = []
        lastLogins.forgetAll()
    }

    /// "Lock Credentials": the local vault, Vaultwarden and every broker lease, at once.
    func lockAll(sessions: SessionsModel, vaultwarden: VaultwardenModel) {
        sessions.lockCredentials()
        lock()
        vaultwarden.refresh()
        ExternalProviders.shared.lockAll()
        DocumentLock.lockAll()
    }

    /// Applies a change, seals the vault to disk and refreshes the list. Returns false on error.
    @discardableResult
    func mutate(_ change: (CredentialVault) throws -> Void) -> Bool {
        // A locked vault never blocks saving typed credentials (owner point 16): the Personal
        // document's vault reopens here with the key already in memory, no prompt.
        if vault == nil { _ = useDocumentVault(nil) }
        guard let vault else { return false }
        defer { refresh(vault) }
        do {
            try change(vault)
            try vault.save()
            return true
        } catch {
            self.error = "\(error)"
            return false
        }
    }
}

/// A typed login kept for the running app only (`CredentialsModel.lastLogin`).
struct RememberedLogin {
    let username: String
    let login: SshLogin
    /// RDP only.
    var domain: String? = nil
}

/// Inspector row: assign a vault credential to an SSH connection (Connect then logs in with it).
struct CredentialPicker: View {
    let connection: ConnectionView
    @Environment(CredentialsModel.self) private var credentials
    @Environment(SessionsModel.self) private var sessions
    @Environment(LibraryModel.self) private var model

    var body: some View {
        InspectorRow("Credential") {
            if credentials.vault != nil {
                Picker("Credential", selection: Binding(
                    get: { connection.credentialId },
                    set: { id in model.mutate { try $0.setCredential(connectionId: connection.id, credentialId: id) } })) {
                    CredentialPickerRows(groups: CredentialPickerGroup.build(credentials.tree), inherit: inheritRow)
                }
                .labelsHidden()
            } else {
                // Opening reads the vault key from the Keychain (and may prompt), so it never happens just
                // because the inspector appeared: only on request, and off the main thread.
                HStack(spacing: DS.Space.xs) {
                    Text(connection.credentialId == nil ? "Ask when connecting" : "Saved credential")
                        .foregroundStyle(.secondary).lineLimit(1)
                    Spacer(minLength: 0)
                    Button("Unlock…") { Task { await credentials.openInBackground(sessions: sessions) } }
                        .controlSize(.small)
                        .help("Open the local vault to choose a credential")
                }
            }
        }
    }
}

extension CredentialPicker {
    /// "Inherit (name)" from the core's resolution when the host sets nothing itself.
    private var inheritRow: String {
        guard connection.credentialId == nil, let lib = model.library,
              let eff = try? credentials.vault?.effectiveCredential(library: lib, connectionId: connection.id) else {
            return CredentialPickerGroup.inheritLabel(nil)
        }
        return CredentialPickerGroup.inheritLabel(credentials.credential(id: eff.credentialId)?.name)
    }
}

/// `security.auto-lock`: locks the local vault, Vaultwarden and broker leases once the user has
/// given no keyboard or mouse input (system-wide) for the chosen time. The core decides; this only
/// samples idle time every 15 seconds, and only while something is unlocked.
@MainActor
final class CredentialAutoLock {
    private let settings: SettingsModel
    private let credentials: CredentialsModel
    private let sessions: SessionsModel
    private let vaultwarden: VaultwardenModel
    private var timer: Timer?

    init(settings: SettingsModel, credentials: CredentialsModel, sessions: SessionsModel, vaultwarden: VaultwardenModel) {
        self.settings = settings
        self.credentials = credentials
        self.sessions = sessions
        self.vaultwarden = vaultwarden
    }

    func start() {
        observeSessionLock()
        let t = Timer(timeInterval: 15, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                // ~0 = any input event type.
                let idle = CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: CGEventType(rawValue: ~0)!)
                self.check(idleSeconds: UInt64(max(0, idle)))
            }
        }
        t.tolerance = 5
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    /// `security.lock-on-screen-lock`: the screen locked (distributed `com.apple.screenIsLocked`,
    /// which also fires when a sleeping Mac requires the password) or the user switched away (fast
    /// user switching). Plain sleep without a lock leaves credentials alone, so sessions with
    /// automatic reconnect can resume on wake within the broker's limits.
    private func observeSessionLock() {
        let lockNow: @Sendable (Notification) -> Void = { [weak self] _ in
            MainActor.assumeIsolated { self?.lockForSessionEvent() }
        }
        if ScreenLockGate.observesRealScreenLock(testHooksBuild: testHooksBuild(), environment: ProcessInfo.processInfo.environment) {
            DistributedNotificationCenter.default().addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main, using: lockNow)
        }
        let ws = NSWorkspace.shared.notificationCenter
        ws.addObserver(forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: .main, using: lockNow)
    }

    /// Anything Lock Credentials would lock: the local vault, Vaultwarden, documents or an external provider.
    private var anyUnlocked: Bool {
        credentials.vault != nil || vaultwarden.isUnlocked || DocumentLock.anyUnlocked() || ExternalProviders.shared.anyUnlocked
    }

    /// Returns true when it locked.
    @discardableResult
    func lockForSessionEvent() -> Bool {
        // The user's choice OR the managed requirement (TM-04): the core decides, fail closed.
        guard anyUnlocked, lockOnOsLockDue(userValue: settings.value("security.lock-on-screen-lock")) else { return false }
        credentials.lockAll(sessions: sessions, vaultwarden: vaultwarden)
        return true
    }

    /// Returns true when it locked.
    @discardableResult
    func check(idleSeconds: UInt64) -> Bool {
        guard anyUnlocked, autoLockDue(value: settings.value("security.auto-lock"), idleSecs: idleSeconds) else { return false }
        credentials.lockAll(sessions: sessions, vaultwarden: vaultwarden)
        return true
    }
}
