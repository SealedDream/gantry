import AppKit
import LocalAuthentication
import Security
import SwiftUI
import BastionCore

/// Spec §5 (docs/specs/session-restore-and-tab-bar.md): document-first launch. Until a document
/// is unlocked the window is covered by the Unlock screen (last document) or the Welcome screen
/// (no last document, or it is missing). Locking the active document, by hand (⌘L), after the
/// idle time, on screen lock or on sleep, brings the Unlock screen back; sessions keep running
/// underneath unless "Close sessions on lock" is on. The core enforces the password back-off and
/// the managed policy; this file only presents them.
@MainActor @Observable
final class DocumentGate {
    static let shared = DocumentGate()

    enum Phase: Equatable { case deciding, open, unlock(path: String), welcome }

    /// One row of `recentDocumentDetails` (core `docunlock::RecentDocument`).
    struct Recent: Decodable, Equatable {
        let path: String
        let name: String?
        let id: String?
        let present: Bool
        let protected: Bool
        let biometric: Bool
        let lastOpenedAt: UInt64?
        /// Connections at the last save or lock on this Mac (core); nil when never recorded.
        var connectionCount: UInt32? = nil
        var displayName: String { name ?? ((path as NSString).lastPathComponent as NSString).deletingPathExtension }
    }

    /// UI test runs keep the old Personal-first launch unless the script asks for the gate, so the
    /// existing driver tests (which use `library.json`) are unchanged.
    static let enabled: Bool = {
        // Snapshots render the main window, so they skip the document gate as driver runs do.
        let scripted = TestHooks.isScripted || TestHooks.env("BASTION_SNAPSHOT") != nil
        return !scripted || TestHooks.env("BASTION_UI_DOCUMENT_GATE") != nil
    }()

    private(set) var phase: Phase = .deciding { didSet { DocumentMenuState.shared.refresh() } }
    private(set) var recents: [Recent] = []
    var password = ""
    var problem: String?
    private(set) var waitSecs: UInt64 = 0
    private(set) var failures: UInt32 = 0
    /// "Keep unlocked until screen locks": no idle auto-lock this run; screen lock and sleep still lock.
    var rememberUntilQuit = false
    /// The sheet's popup: keep this document's key for Touch ID on this Mac (applied after a
    /// password unlock; Touch ID itself only runs when a copy is already saved).
    var saveForTouchID = false
    /// Touch ID is showing over the sheet: the password field waits.
    private(set) var touchIDRunning = false
    /// The last document (or one picked from Recents/Open) whose file is gone: Welcome says so.
    private(set) var missing: Recent?
    /// Bumped by File › New Document…: the Welcome form focuses and selects its Name field.
    private(set) var createFocusRequest = 0
    /// New Document… came from an open document: the form offers Cancel back to it.
    private(set) var canCancelCreate = false
    /// The start window's right half shows the create form instead of unlock/welcome.
    private(set) var creating = false
    /// The start window's selected recent row (an unprotected or missing one has no unlock phase).
    private(set) var selectedPath: String?
    @ObservationIgnored private var countdown: Timer?
    /// The launch sign-in (the last document's Unlock screen): once it succeeds the Personal
    /// library is shown, with the document unlocked beside it (owner feedback 2026-11-07 #1).
    /// A document picked or created by hand opens itself.
    @ObservationIgnored private(set) var launchSignIn = false
    /// The document the gate last signed in to. While Personal is shown, ⌘L, idle and screen
    /// lock still lock this one and bring its Unlock screen back.
    @ObservationIgnored private(set) var signedInId: String?
    @ObservationIgnored weak var model: LibraryModel?
    @ObservationIgnored weak var sessions: SessionsModel?
    @ObservationIgnored var settings: SettingsModel?

    var isOpen: Bool { !Self.enabled || phase == .open }
    var biometricAllowed: Bool { documentBiometricUnlockAllowed() }

    private var dataDir: String { LibraryModel.dataDir.path }

    // MARK: Launch

    func decide(model: LibraryModel, sessions: SessionsModel, settings: SettingsModel) {
        self.model = model
        self.sessions = sessions
        self.settings = settings
        guard Self.enabled, phase == .deciding else { return }
        reloadRecents()
        // Only the last document itself: when it is gone, never fall back to an older one's Unlock.
        // Personal is the encrypted source of truth (OF-F): with no other document to resume, open it.
        guard let last = recents.first else { if model.personalDocument != nil { openPersonal() } else { phase = .welcome }; return }
        // LIB-01: Personal was the library showing at quit (Show Personal); it opens with the device key.
        if let personal = model.personalDocument, Self.samePath(last.path, personal.info().path) { openPersonal(); return }
        if last.present { launchSignIn = true; showUnlock(path: last.path) } else { noteMissing(last); phase = .welcome }
    }

    static func samePath(_ a: String, _ b: String) -> Bool {
        URL(fileURLWithPath: a).standardizedFileURL.path == URL(fileURLWithPath: b).standardizedFileURL.path
    }

    /// Remember the notice for `recent` and drop every missing entry from Recents.
    private func noteMissing(_ recent: Recent) {
        missing = recent
        selectedPath = recent.path
        for r in recents where !r.present {
            do { try forgetRecentDocument(dataDir: dataDir, path: r.path) } catch { problem = errorText(error) }
        }
        reloadRecents()
    }

    /// The moved/deleted notice's "Remove from Recents" (already dropped) just dismisses it.
    func dismissMissing() {
        if selectedPath == missing?.path { selectedPath = nil }
        missing = nil
    }

    /// File › New Document…: the Welcome create form, its Name field focused and selected.
    func showCreate() {
        let wasOpen = phase == .open
        showWelcome()
        canCancelCreate = wasOpen
        creating = true
        createFocusRequest += 1
    }

    /// The create form's Cancel (Esc): back to the open document, or the start window's unlock/welcome.
    func leaveCreate() {
        if canCancelCreate { cancelCreate(); return }
        creating = false
        if let r = recents.first(where: { $0.present }) { showUnlock(path: r.path) }
    }

    /// Cancel on the create form opened from a document: back to it.
    func cancelCreate() {
        canCancelCreate = false
        creating = false
        phase = .open
    }

    /// A Recents row picked in the start window: a protected one shows its unlock, an
    /// unprotected one waits for Open, a missing one shows Locate.
    func select(_ path: String?) {
        guard let path, path != selectedPath || creating else { return }
        if let r = recents.first(where: { $0.path == path }), r.present, r.protected { showUnlock(path: path); return }
        if case .unlock = phase { phase = .welcome }
        stopCountdown()
        password = ""
        problem = nil
        creating = false
        selectedPath = path
    }

    /// The start window's row menu: forget this document in Recents (the file stays).
    func removeRecent(_ recent: Recent) {
        if missing?.path == recent.path { dismissMissing() }
        do { try forgetRecentDocument(dataDir: dataDir, path: recent.path) } catch { problem = errorText(error) }
        reloadRecents()
        guard selectedPath == recent.path else { return }
        selectedPath = nil
        showWelcome()
    }

    func reloadRecents() {
        do {
            let json = try recentDocumentDetails(dataDir: dataDir)
            recents = try JSONDecoder().decode([Recent].self, from: Data(json.utf8))
        } catch {
            recents = []
            problem = "Recent documents could not be read: \(errorText(error))"
        }
    }

    /// Open (locked) the document at `path` and show its Unlock screen; an unprotected one opens.
    func showUnlock(path: String) {
        guard let model else { return }
        if !FileManager.default.isReadableFile(atPath: path) {
            // Moved, deleted or unreadable: Welcome with the notice, never an Unlock screen.
            let r = recents.first { $0.path == path } ?? Recent(path: path, name: nil, id: nil, present: false, protected: false, biometric: false, lastOpenedAt: nil)
            showWelcome()
            noteMissing(Recent(path: r.path, name: r.name, id: r.id, present: false, protected: r.protected, biometric: r.biometric, lastOpenedAt: r.lastOpenedAt))
            return
        }
        guard let doc = model.openDocumentHandle(path: path) else {
            let failure = problem  // unreadable or corrupt: say why on Welcome
            showWelcome()
            problem = failure
            return
        }
        password = ""
        problem = nil
        creating = false
        // No password: no sign-in, so the document itself shows (LIB-01, as on Native Windows).
        guard doc.info.protected, doc.info.locked else { launchSignIn = false; finishUnlock(doc.id); return }
        phase = .unlock(path: path)
        selectedPath = path
        refreshBackoff()
        saveForTouchID = DocumentTouchID.hasCopy(doc.id)
        if touchIDReady(doc) && !TestHooks.isScripted { unlockWithBiometrics() }
    }

    /// The user saved this document for Touch ID here, and policy and hardware allow it.
    func touchIDReady(_ doc: OpenDocument) -> Bool {
        DocumentTouchID.available && DocumentTouchID.hasCopy(doc.id)
    }

    var unlockingDocument: OpenDocument? {
        guard case .unlock(let path) = phase else { return nil }
        return model?.documents.first { $0.info.path == path }
    }

    // MARK: Unlock

    func unlockWithPassword() {
        guard let doc = unlockingDocument, waitSecs == 0, !password.isEmpty else { return }
        do {
            try doc.handle.unlock(password: password)
            password = ""
            applyTouchIDChoice(doc)
            finishUnlock(doc.id)
        } catch {
            password = ""
            problem = errorText(error)
            refreshBackoff()
        }
    }

    /// Touch ID over the sheet, once: the same authenticated context opens this document's
    /// sealed key and, when Personal is still closed at launch, Personal's device key, so no
    /// second prompt follows. Cancel or any failure leaves the password field.
    func unlockWithBiometrics() {
        guard let doc = unlockingDocument, touchIDReady(doc), !touchIDRunning else { return }
        touchIDRunning = true
        Task { @MainActor in
            defer { touchIDRunning = false }
            guard let context = await DocumentTouchID.authenticate(name: doc.info.name) else { return }
            guard unlockingDocument?.id == doc.id else { return }
            do {
                guard try DocumentTouchID.unlock(doc.handle, context: context) else {
                    problem = "Touch ID is not saved for this document on this Mac. Enter the password."
                    return
                }
                if model?.personalDeferred == true { model?.openDeferredPersonal(context: context) }
                finishUnlock(doc.id)
            } catch EnclaveSeal.Failure.cancelled {
                // The password field stays.
            } catch {
                problem = errorText(error)
            }
        }
    }

    private func finishUnlock(_ id: String) {
        guard let model else { return }
        // Personal still closed (password unlock, or its key was not opened): show the document
        // itself, so launch asks once; Personal opens with its own Touch ID when it is picked.
        if model.personalDeferred { launchSignIn = false }
        model.refreshDocument(id)
        model.activate(launchSignIn ? nil : id)
        launchSignIn = false
        signedInId = id
        model.documents.first { $0.id == id }?.handle.noteOpened()
        stopCountdown()
        failures = 0
        waitSecs = 0
        problem = nil
        canCancelCreate = false
        creating = false
        phase = .open
    }

    /// The popup after a password unlock: save or forget this Mac's Touch ID copy.
    private func applyTouchIDChoice(_ doc: OpenDocument) {
        if !saveForTouchID { if DocumentTouchID.hasCopy(doc.id) { DocumentTouchID.forget(doc.id) }; return }
        guard DocumentTouchID.available, !DocumentTouchID.isSaved(doc.id), !UIProbe.isActive else { return }
        do { try DocumentTouchID.save(doc.handle) } catch {
            model?.error = "Touch ID unlock could not be saved: \(errorText(error))"
        }
    }

    private func refreshBackoff() {
        guard let doc = unlockingDocument else { stopCountdown(); return }
        let s = doc.handle.unlockStatus()
        failures = s.failures
        waitSecs = s.waitSecs
        if waitSecs > 0 { startCountdown() } else { stopCountdown() }
    }

    private func startCountdown() {
        guard countdown == nil else { return }
        let t = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refreshBackoff() }
        }
        RunLoop.main.add(t, forMode: .common)
        countdown = t
    }

    private func stopCountdown() {
        countdown?.invalidate()
        countdown = nil
    }

    // MARK: Lock

    /// The active document was locked (⌘L, auto-lock, Lock Credentials): cover the window.
    func documentLocked(path: String?, returnToPersonal: Bool = false) {
        guard Self.enabled, phase == .open, let path else { return }
        if settings?.value("document.close-sessions-on-lock") == "true" { sessions.map { s in s.tabs.forEach(s.close) } }
        // Signed in while Personal was shown: unlocking returns to Personal, not the document.
        launchSignIn = returnToPersonal
        phase = .unlock(path: path)
        selectedPath = path
        password = ""
        problem = nil
        refreshBackoff()
    }

    // MARK: Welcome actions

    func openAnother() {
        launchSignIn = false
        guard let url = DocumentDialogs.chooseOpen(title: "Open Document") else { return }
        showUnlock(path: url.path)
    }

    /// A recent document whose file moved: pick it again and forget the old path.
    func locate(_ recent: Recent) {
        guard let url = DocumentDialogs.chooseOpen(title: "Locate “\(recent.displayName)”") else { return }
        do { try forgetRecentDocument(dataDir: dataDir, path: recent.path) } catch { problem = errorText(error) }
        missing = nil
        showUnlock(path: url.path)
    }

    func showWelcome() {
        launchSignIn = false
        reloadRecents()
        stopCountdown()
        password = ""
        problem = nil
        canCancelCreate = false
        creating = false
        phase = .welcome
    }

    /// Show the Personal library (its own encrypted `Personal.bastion`, or the older `library.json`).
    func openPersonal() {
        missing = nil
        model?.activate(nil)
        phase = .open
    }

    struct NewDocument {
        var name = "Untitled"
        var password = ""
        var confirm = ""
        var touchID = false
    }

    /// Create, protect, save and open a new document. Returns an error to show, or nil.
    func create(_ form: NewDocument) -> String? {
        create(form, target: { DocumentDialogs.chooseSave(title: "Create New Document", name: $0) })
    }

    /// The start window's form: saved as `<name>.<ext>` in `folder` (a UI run's scripted answer
    /// wins, as the save panel's would); never over an existing file.
    func create(_ form: NewDocument, folder: URL) -> String? {
        var exists = false
        let result = create(form, target: { name in
            if let s = DocumentDialogs.nextScripted() { return s.isEmpty ? nil : URL(fileURLWithPath: s) }
            let url = folder.appendingPathComponent("\(name).\(documentExtension())")
            exists = FileManager.default.fileExists(atPath: url.path)
            return exists ? nil : url
        })
        return exists ? "A file with that name is already in this folder." : result
    }

    private func create(_ form: NewDocument, target: (String) -> URL?) -> String? {
        guard let model else { return "The library is not ready." }
        let name = form.name.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return "Enter a name." }
        // No password = an unprotected document; Touch ID needs a password to wrap.
        guard form.password == form.confirm else { return "Passwords do not match." }
        guard !form.touchID || !form.password.isEmpty else { return "Touch ID needs a password." }
        guard let url = target(name) else { return nil }
        do {
            let handle = try BastionDocument.create(name: name, dataDir: dataDir)
            if !form.password.isEmpty { try handle.setPassword(password: form.password) }
            try handle.saveAs(path: url.path)
            let touchIDProblem = form.touchID && biometricAllowed ? enableTouchID(handle) : nil
            let id = model.adopt(handle)
            finishUnlock(id)
            if let touchIDProblem { model.error = touchIDProblem }
            return nil
        } catch {
            return errorText(error)
        }
    }
}

extension DocumentGate {
    /// Turn on Touch ID unlock for a just-created document. A Keychain failure (e.g. an unsigned
    /// build without the keychain entitlement) leaves the document created, password-only, and
    /// returns the message to show instead of failing the whole create.
    fileprivate func enableTouchID(_ handle: BastionDocument) -> String? {
        // UI test runs never write the login Keychain (an unsigned build would prompt or stall).
        if UIProbe.isActive { return "Touch ID unlock could not be set up (UI test run: Keychain skipped). The document uses its password." }
        do {
            try DocumentTouchID.save(handle)
            return nil
        } catch {
            return "Touch ID unlock could not be set up (\(errorText(error))). The document uses its password."
        }
    }
}

// MARK: - Library hooks

@MainActor
extension LibraryModel {
    /// Spec §5: per-document state (open sessions, recents, history) lives in the active
    /// document's own directory; the Personal library keeps the app data directory.
    static var stateDir: String {
        (try? DocumentGate.shared.model?.activeDocument?.handle.stateDir()) ?? dataDir.path
    }

    /// The open document at `path`, opening it (locked when protected) if needed.
    func openDocumentHandle(path: String) -> OpenDocument? {
        if let d = documents.first(where: { $0.info.path == path }) { return d }
        do {
            let id = adopt(try BastionDocument.open(path: path, dataDir: Self.dataDir.path))
            return documents.first { $0.id == id }
        } catch {
            DocumentGate.shared.problem = "Could not open \((path as NSString).lastPathComponent): \(errorText(error))"
            return nil
        }
    }
}

// MARK: - Auto-lock

/// `document.auto-lock-minutes` (policy can only shorten it), screen lock and sleep lock the
/// active protected document. The core decides (`documentAutoLockDue`); this samples idle time
/// every 15 seconds while a protected document is unlocked.
@MainActor
final class DocumentAutoLock {
    static let shared = DocumentAutoLock()
    private static let sampleSeconds: TimeInterval = 15
    private static let defaultMinutes: UInt32 = 15
    private var timer: Timer?

    func start() {
        guard DocumentGate.enabled, timer == nil else { return }
        let t = Timer(timeInterval: Self.sampleSeconds, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                let idle = CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: CGEventType(rawValue: ~0)!)
                self?.check(idleSecs: UInt64(max(0, idle)))
            }
        }
        t.tolerance = 5
        RunLoop.main.add(t, forMode: .common)
        timer = t
        let screen: @Sendable (Notification) -> Void = { [weak self] _ in MainActor.assumeIsolated { _ = self?.check(idleSecs: 0, screenLocked: true) } }
        let sleep: @Sendable (Notification) -> Void = { [weak self] _ in MainActor.assumeIsolated { _ = self?.check(idleSecs: 0, asleep: true) } }
        if ScreenLockGate.observesRealScreenLock(testHooksBuild: testHooksBuild(), environment: ProcessInfo.processInfo.environment) {
            DistributedNotificationCenter.default().addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main, using: screen)
        }
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main, using: sleep)
    }

    /// The user's setting, capped by the managed policy's maximum.
    var minutes: UInt32 {
        let user = UInt32(DocumentGate.shared.settings?.value("document.auto-lock-minutes") ?? "") ?? Self.defaultMinutes
        return documentAutoLockMinutes(userMinutes: user)
    }

    /// Returns the reason when it locked ("idle", "screenLocked", "sleep").
    @discardableResult
    func check(idleSecs: UInt64, screenLocked: Bool = false, asleep: Bool = false) -> String? {
        // Every unlocked protected document, not only the active one (Codex M02).
        guard let model = DocumentGate.shared.model,
              model.documents.contains(where: { $0.info.protected && !$0.info.locked }) else { return nil }
        guard let reason = documentAutoLockDue(minutes: minutes, idleSecs: idleSecs, screenLocked: screenLocked,
                                               asleep: asleep,
                                               rememberUntilQuit: DocumentGate.shared.rememberUntilQuit && !screenLocked && !asleep) else { return nil }
        model.lockAllDocuments()
        return reason
    }
}

// MARK: - Keychain (wrapped key, Touch ID)

/// The wrapped document key (core `exportWrappedKey`, never the password) in a data-protection
/// Keychain item that only Touch ID / Face ID of the currently enrolled fingers can read
/// (`kSecAccessControlBiometryCurrentSet`: re-enrolling invalidates it).
enum DocumentKeychain {
    enum Failure: Error, LocalizedError {
        case cancelled
        case status(OSStatus)
        var errorDescription: String? {
            switch self {
            case .cancelled: return "Touch ID was cancelled."
            case .status(let s): return (SecCopyErrorMessageString(s, nil) as String?) ?? "Keychain error \(s)"
            }
        }
    }

    private static let service = "dev.bastion.document-key"

    private static func base(_ id: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: id, kSecUseDataProtectionKeychain as String: true]
    }

    static func store(documentId id: String, wrapped: String) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error) else {
            throw error?.takeRetainedValue() ?? Failure.status(errSecParam)
        }
        SecItemDelete(base(id) as CFDictionary)
        var item = base(id)
        item[kSecAttrAccessControl as String] = access
        item[kSecValueData as String] = Data(wrapped.utf8)
        let s = SecItemAdd(item as CFDictionary, nil)
        guard s == errSecSuccess else { throw Failure.status(s) }
    }

    static func exists(documentId id: String) -> Bool {
        var q = base(id)
        let context = LAContext()
        context.interactionNotAllowed = true
        q[kSecUseAuthenticationContext as String] = context
        let s = SecItemCopyMatching(q as CFDictionary, nil)
        return s == errSecSuccess || s == errSecInteractionNotAllowed
    }

    /// Legacy read with an already authenticated context (no prompt of its own).
    static func read(documentId id: String, context: LAContext) throws -> String? {
        var q = base(id)
        q[kSecReturnData as String] = true
        q[kSecUseAuthenticationContext as String] = context
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecItemNotFound || s == errSecMissingEntitlement { return nil }
        if s == errSecUserCanceled || s == errSecAuthFailed { throw EnclaveSeal.Failure.cancelled }
        guard s == errSecSuccess, let data = out as? Data else { throw Failure.status(s) }
        return String(data: data, encoding: .utf8)
    }

    static func delete(documentId id: String) {
        SecItemDelete(base(id) as CFDictionary)
    }
}

// MARK: - Screens

/// Covers the main window while no document is unlocked: the start window (StartWindow.swift).
struct DocumentGateView: View {
    @Bindable var gate: DocumentGate

    var body: some View {
        ZStack {
            Rectangle().fill(.background).ignoresSafeArea()
            switch gate.phase {
            case .deciding, .open: EmptyView()
            case .unlock, .welcome: StartWindow(gate: gate)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("document-gate")
    }
}
