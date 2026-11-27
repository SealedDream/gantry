import LocalAuthentication
import SwiftUI
import BastionCore

@main
struct BastionApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model: LibraryModel
    @State private var sessions: SessionsModel
    @State private var commands: Commands
    @State private var settings: SettingsModel
    @State private var appearance: AppearanceSettings
    @State private var credentials: CredentialsModel
    @State private var vaultwarden: VaultwardenModel
    @State private var router: AppRouter
    @State private var workspaces: WorkspaceModel
    @State private var themes: ThemesModel
    @State private var snippets: SnippetsModel
    @State private var shortcuts: ShortcutsModel
    @StateObject private var menuState: MenuState
    @State private var autoLock: CredentialAutoLock

    init() {
        StartupProbe.report("app-init-start")
        defer { StartupProbe.report("app-init-end") }
        // Before any window reads the defaults: old generated frame keys slow every save (AutosaveKeys).
        if case let n = AutosaveKeys.removeStale(), n > 0 { NSLog("Gantry: removed %d old window and split-view keys", n) }
        let model = LibraryModel()
        let sessions = SessionsModel(dataDir: LibraryModel.dataDir)
        let settings = SettingsModel()
        let credentials = CredentialsModel()
        credentials.confirmOpen = { settings.value("security.confirm-vault-open") == "true" }
        credentials.userReuseMinutes = { UInt32(settings.value("security.session-login-reuse-minutes")) ?? 0 }
        sessions.confirmCloseEnabled = { settings.value("terminal.confirm-close") == "true" }
        QuitConfirm.shared.sessions = sessions
        PluginViewWindow.sessions = sessions
        PluginEntries.reload()
        QuitConfirm.shared.isEnabled = { settings.value("terminal.confirm-close") == "true" }
        TerminalFonts.registerBundledFont()
        let vaultwarden = VaultwardenModel(dataDir: LibraryModel.dataDir)
        let workspaces = WorkspaceModel()
        let shortcuts = ShortcutsModel()
        let router = AppRouter()
        _router = State(initialValue: router)
        _themes = State(initialValue: ThemesModel(dataDir: LibraryModel.dataDir))
        _snippets = State(initialValue: SnippetsModel(dataDir: LibraryModel.dataDir))
        sessions.autoGroup = { [weak model] strip in
            try? model?.library?.tabStripAutoGroup(stripJson: strip, enabled: settings.value("tabs.auto-group") == "true")
        }
        sessions.wantsLog = { [weak model] id in ((try? model?.library?.sessionLog(connectionId: id)) ?? nil) ?? false }
        SessionLogPurge.run(library: model.library, settingFolder: settings.value("logging.session-log-folder"))
        sessions.startPlannedLog = { [weak model] t, id in
            guard let library = model?.library else { throw FfiError.Failed(message: "The library is not open.", code: "other") }
            return try t.startPlannedLog(library: library, connectionId: id, dataDir: LibraryModel.dataDir.path, app: "native-mac",
                                         version: DiagnosticsExport.version.0, utcOffsetMinutes: Int32(TimeZone.current.secondsFromGMT() / 60))
        }
        _workspaces = State(initialValue: workspaces)
        _shortcuts = State(initialValue: shortcuts)
        // Made here, not in StateObject's lazy autoclosure: that runs inside the App body's first
        // evaluation, where MenuState's own observation reads (the open tabs) became the App body's.
        // The first tab then re-ran the whole App scene once: main menu, window root and every
        // nested host re-resolved, about 60 ms of the first local shell (MAC-FIRST-SHELL).
        let menuState = MenuState(shortcuts: shortcuts, workspaces: workspaces, sessions: sessions, router: router)
        _menuState = StateObject(wrappedValue: menuState)
        _model = State(initialValue: model)
        _sessions = State(initialValue: sessions)
        _settings = State(initialValue: settings)
        _appearance = State(initialValue: AppearanceSettings(settings: settings))
        credentials.currentLibrary = { [weak model] in model?.library }
        credentials.personalVault = { [weak model] in try? model?.personalDocument?.vault() }
        // The document's vault is already decrypted in memory: show saved logins without an Unlock click.
        if model.personalDocument != nil { credentials.open(sessions: sessions) }
        _credentials = State(initialValue: credentials)
        _vaultwarden = State(initialValue: vaultwarden)
        let commands = Commands(model: model, sessions: sessions, tree: TreeStateModel(dataDir: LibraryModel.dataDir), settings: settings,
                                workspaces: workspaces)
        commands.credentials = credentials
        PluginViewWindow.onProblem = { [weak model] in model?.error = $0 }
        PluginViewWindow.trustCertificate = { [weak model, weak commands] view in
            guard let model, let commands, let id = view.entryId, let c = model.connection(id: id) else { return }
            Task { @MainActor in
                guard await PluginCertificateTrust.ask(c, model: model) else { return }
                PluginViewWindow.reopen(entryId: id) { commands.openPluginEntry(id) }
            }
        }
        // Plugin API 1.2: the user confirmed a plugin's open request and the core said go.
        PluginViewWindow.openConnection = { [weak model] go, entryId, library in
            guard let model else { return }
            Task { @MainActor in
                do {
                    var host = go.host
                    if go.checkResolved {
                        // Direct route and a name: resolve once, check every address, connect to one.
                        let (h, p, lo) = (go.host, UInt16(go.port), go.loopbackOk)
                        let ips = try await Task.detached { try pluginOpenResolve(host: h, port: p, loopbackOk: lo) }.value
                        guard let first = ips.first else { return }
                        host = first
                    }
                    if go.saveAsEntry {
                        guard library === model.library else { model.error = "Only entries in the main library can be saved."; return }
                        var saved: String?
                        model.mutate { saved = try $0.pluginOpenSave(entryId: entryId, protocol: go.proto, host: go.host, port: UInt16(go.port), label: go.label, viaEntryRoute: go.viaEntryRoute) }
                        if let id = saved, let c = model.connection(id: id) { commands.requestConnect(c, .terminal) }
                        return
                    }
                    let lib = try library.pluginOpenLibrary(entryId: entryId, protocol: go.proto, host: host, port: UInt16(go.port), label: go.label, viaEntryRoute: go.viaEntryRoute)
                    guard let c = lib.tree().connections.first else { return }
                    commands.requestConnect(c, .terminal, library: lib)
                } catch {
                    model.error = error.userMessage
                }
            }
        }
        // Plugin API 1.5: a declared command on the entry, with the login an SSH tab would use
        // without asking. No saved login: the command fails with that reason.
        PluginViewWindow.runExec = { [weak model, weak sessions, weak credentials] entryId, library, command, ms, cancel, done in
            Task { @MainActor in
                guard let model, let sessions, let credentials, let manager = sessions.manager, let c = model.connection(id: entryId) else {
                    return done(PluginExecResult(exit: nil, stdout: "", stderr: "", error: "The entry or the session manager is not available."))
                }
                guard let (user, login) = await DirectConnect.savedLogin(c, library: library, sessions: sessions, credentials: credentials) else {
                    return done(PluginExecResult(exit: nil, stdout: "", stderr: "", error: "No saved login for \(c.name): add one in its properties."))
                }
                let r = await Task.detached { manager.pluginExec(library: library, entryId: entryId, username: user, login: login, command: command, timeoutMs: ms, cancel: cancel) }.value
                done(r)
            }
        }
        // Plugin API 1.5: "opened" only once the terminal tab exists; a failure says why (Windows: OpenPluginExecTerminalAsync).
        PluginViewWindow.openExecTerminal = { [weak model, weak sessions] entryId, library, command, label, done in
            guard let model, let sessions else { done(false); return }
            do {
                let lib = try library.pluginExecTerminalLibrary(entryId: entryId, command: command, label: label)
                guard let c = lib.tree().connections.first else { model.error = "The terminal did not open."; done(false); return }
                let before = Set(sessions.tabs.map(\.id))
                commands.requestConnect(c, .terminal, library: lib)
                Task { @MainActor in
                    for _ in 0..<60 { // up to 15 s: the tab appears when the connect starts
                        if sessions.tabs.contains(where: { !before.contains($0.id) && ($0.connectionId == c.id || $0.name == c.name) }) { done(true); return }
                        try? await Task.sleep(nanoseconds: 250_000_000)
                    }
                    model.error = "The terminal did not open."
                    done(false)
                }
            } catch {
                model.error = error.userMessage
                done(false)
            }
        }
        PluginViewWindow.askGateway = { commands.pluginGateway = $0 }
        PluginViewWindow.startTunnel = { [weak model, weak sessions] t, then in
            guard let model, let sessions, let via = model.connection(id: t.viaId) else { model?.error = "The tunnel's SSH connection no longer exists."; return }
            commands.enqueue([ConnectRequest(connection: via, mode: .tunnel, tunnelId: t.id)], select: nil)
            // PLUG-08: the entry opens once the tunnel runs (the sign-in may take a while).
            Task { @MainActor in
                for _ in 0..<600 {
                    if sessions.runningTunnels[t.id]?.isRunning() == true { return then() }
                    try? await Task.sleep(nanoseconds: 200_000_000)
                }
            }
        }
        _commands = State(initialValue: commands)
        _autoLock = State(initialValue: CredentialAutoLock(settings: settings, credentials: credentials, sessions: sessions, vaultwarden: vaultwarden))
    }

    var body: some Scene {
        let _ = RenderCount.hit("App")
        // A fixed id: without one SwiftUI names the window-frame and split-view defaults keys after the
        // scene's generic type, so every build that changes the view tree added two new keys to
        // Bastion.plist (about 2,100 stale keys on a dev Mac). Existing keys are left as they are.
        WindowGroup("Gantry", id: "main") {
            WindowRootLayout {
                shared(ContentView())
            }
                .onAppear {
                    StartupProbe.report("on-appear")
                    UIZoom.shared.terminalZoom = { [sessions] in sessions.zoom($0) }
                    UIZoom.shared.isRecordingShortcut = { [shortcuts] in shortcuts.isRecording }
                    UIZoom.shared.installKeyMonitor()
                    sessions.useVaultwarden(vaultwarden.session)
                    autoLock.start()
                    DocumentAutoLock.shared.start()
                    AppIpc.start(commands: commands, dataDir: LibraryModel.dataDir)
                    #if BASTION_TEST_HOOKS
                    UIDriver.services = .init(settings: settings, autoLock: autoLock, credentials: credentials, vaultwarden: vaultwarden,
                                              sessions: sessions, router: router, workspaces: workspaces, shortcuts: shortcuts, themes: themes, snippets: snippets)
                    Snapshot.runIfRequested(model: model, sessions: sessions, appearance: appearance, credentials: credentials,
                                            vaultwarden: vaultwarden, commands: commands)
                    #endif
                    StartupProbe.windowAppeared()
                    WindowLaunchApplier.applyOnce(settings: settings)
                }
        }
        .commands {
            AppMenus(router: router, state: menuState)
            DocumentMenus(model: model)
        }
        // A tab torn off the strip (`TabWindows.swift`).
        WindowGroup("Session", id: TabWindows.sceneId, for: UUID.self) { $id in
            shared(TabWindowView(id: id))
                .frame(minWidth: 480, minHeight: 300)
        }
        .defaultSize(width: 900, height: 600)
        Window("Credentials", id: CredentialManagerView.windowId) {
            shared(CredentialManagerView())
        }
        .defaultSize(width: 860, height: 520)
        Settings {
            shared(SettingsView())
        }
    }

    /// Every window gets the same models and the user's appearance.
    private func shared<V: View>(_ view: V) -> some View {
        view
            .uiZoomRoot()
            .environment(model)
            .environment(sessions)
            .environment(commands)
            .environment(settings)
            .environment(appearance)
            .environment(credentials)
            .environment(vaultwarden)
            .environment(router)
            .environment(workspaces)
            .environment(shortcuts)
            .environment(themes)
            .environment(snippets)
            .modifier(ThemedRoot(settings: appearance))
    }
}

/// Run unbundled (`swift run`), the process starts as a background app: its windows never
/// become key and keystrokes stay with the launching terminal. Promote it to a regular app.
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// UI-driver runs stay in the background (`QuietLaunch`): accessory policy, no activation.
    func applicationWillFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(QuietLaunch.policy)
        // The app has its own tab strip: never macOS's window tab bar (it would show a second bar when windows merge).
        NSWindow.allowsAutomaticWindowTabbing = false
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        DiagnosticsExport.startLog()
        DialogFront.install()
        // After SwiftUI has built the menu bar.
        DispatchQueue.main.async { FullScreenMenu.install() }
        guard !QuietLaunch.isOn else { return }
        NSApp.activate(ignoringOtherApps: true)
    }

    /// ⌘Q with a live session asks first (CLOSE-01); quits the app starts itself do not.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        let reply = QuitConfirm.shared.shouldTerminate()
        // B12: the app now closes every window; torn-off windows keep their tabs for the saved set.
        if reply == .terminateNow { TabWindows.isTerminating = true }
        return reply
    }

    /// Finder › Open With / double-click on a `.bastion` file.
    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls { NotificationCenter.default.post(name: .bastionOpenDocument, object: url) }
    }
}

/// Owns the open documents — the Personal library (`library.json`) plus any `.bastion` files
/// (`Documents.swift`) — and republishes the active one's tree after each mutation. `library`
/// is always the active document's library, so every view and command works on it unchanged.
@MainActor @Observable
final class LibraryModel {
    /// Bumps `treeVersion`, so views compare one integer instead of the whole tree.
    private(set) var tree: FolderView? {
        didSet {
            treeVersion &+= 1
            if !keepColours { HostColors.shared.refresh(library: library, tree: tree) }
            index = tree.map(Self.index) ?? ([:], [:])
            let empty = tree.map { $0.folders.isEmpty && $0.connections.isEmpty } ?? true
            if empty != isEmpty { isEmpty = empty }
        }
    }
    /// True while the library has no folders or connections. The window root reads this instead of
    /// `tree`, so a library edit does not re-evaluate and re-lay out the whole window (first New
    /// Folder trace: about 30 ms of root layout per edit).
    private(set) var isEmpty = true
    /// Connections and folders by id, rebuilt with each new tree: the folder page and inspector
    /// look up many ids per update, and a tree walk per lookup showed in the first-select stall.
    @ObservationIgnored private var index: (connections: [String: ConnectionView], folders: [String: FolderView]) = ([:], [:])

    private static func index(_ root: FolderView) -> (connections: [String: ConnectionView], folders: [String: FolderView]) {
        var connections: [String: ConnectionView] = [:], folders: [String: FolderView] = [:]
        func walk(_ f: FolderView) {
            folders[f.id] = folders[f.id] ?? f
            for c in f.connections where connections[c.id] == nil { connections[c.id] = c }
            f.folders.forEach(walk)
        }
        walk(root)
        return (connections, folders)
    }
    private(set) var treeVersion = 0
    var error: String?
    private(set) var library: Library?
    /// The Personal library; `library` points here while no `.bastion` document is active.
    private(set) var personal: Library?
    /// Open `.bastion` documents, in sidebar order.
    var documents: [OpenDocument] = [] { didSet { DocumentMenuState.shared.refresh() } }
    /// The active document (`nil` = Personal).
    private(set) var activeDocumentId: String? { didSet { DocumentMenuState.shared.refresh() } }
    /// Optional shared SSH config workflow (placeholders, overrides, change detection).
    private(set) var workflow: SshWorkflow?
    /// Set by the screenshot hook to drive the UI (select a connection by name, open a sheet).
    var scriptedSelection: String?
    var scriptedSheet: String?

    /// `BASTION_LIBRARY=<file>` (test builds only, `TestHooks`) points the app at another library (tests and screenshots use
    /// this so they never touch the user's real one). known_hosts and the audit log live next to it.
    static var libraryPath: URL {
        if let custom = TestHooks.libraryOverride {
            let url = URL(fileURLWithPath: custom)
            return isDocumentExtension(url.pathExtension) ? url.deletingLastPathComponent().appendingPathComponent("library.json") : url
        }
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        _ = renameMigration
        let dir = support.appendingPathComponent(AppRename.newName, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("library.json")
    }

    static var dataDir: URL { libraryPath.deletingLastPathComponent() }

    /// The one-time Bastion -> Gantry data folder copy, run on first use of the data folder.
    static let renameMigration: AppRename.Outcome =
        AppRename.migrateDataFolder(in: FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0],
                                   documents: FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0])

    /// The Personal library as an encrypted document (OF-F, owner point 20): `~/Documents/Bastion/
    /// Personal.bastion`, or a `.bastion` `BASTION_LIBRARY` in tests. `nil` keeps the older
    /// `library.json` + credential vault (UI driver tests that point at a `.json` library).
    static var personalDocumentPath: URL? {
        if let custom = TestHooks.libraryOverride {
            let url = URL(fileURLWithPath: custom)
            return isDocumentExtension(url.pathExtension) ? url : nil
        }
        return AppRename.personalDocument(documents: FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0], dataDir: LibraryModel.dataDir,
                                          ext: documentExtension(), legacyExt: legacyDocumentExtension())
    }

    /// The open Personal document (secrets inside it); `nil` in the legacy layout.
    private(set) var personalDocument: PersonalLibrary?
    /// Personal's display name, stored inside its document (owner point 33: renameable).
    var personalName = "Personal"
    /// Set once, when this launch moved the old Personal files into the document.
    var migrationNotice: String?

    /// Open Personal. Any failure to get the key or migrate (a cancelled Keychain prompt included)
    /// falls back to the old files for this launch, quietly for a cancel, and nothing is lost.
    private func openPersonal(context: LAContext? = nil) throws -> Library {
        guard let path = Self.personalDocumentPath else { return try Library.open(path: Self.libraryPath.path) }
        do {
            let key = try LibraryKey.deviceKey(in: Self.dataDir, touchID: SettingsModel().value("security.touch-id-unlock") != "false", context: context)
            let doc = try PersonalLibrary.open(dataDir: Self.dataDir.path, path: path.path, deviceKeyHex: key)
            personalDocument = doc
            personalName = doc.info().name
            if doc.info().locked, !Self.unlockWithMasterPassword(doc) { QuitConfirm.terminateWithoutAsking(); throw KeychainQuiet.LockedPersonal() }
            if let m = doc.migration() {
                migrationNotice = "Your Personal library is now one encrypted file (\(path.path)): \(m.folders) folders, \(m.connections) connections and \(m.credentials) saved logins moved. The old files are kept in \(m.backup ?? "the Gantry folder")."
            }
            return try doc.library()
        } catch {
            // Once Personal is a document, the old files are gone: never fall back to an empty one.
            let migrated = FileManager.default.fileExists(atPath: path.path)
            if KeychainQuiet.isCancel(error) {
                if migrated { throw KeychainQuiet.LockedPersonal() }
            } else if migrated {
                throw error
            } else {
                self.error = "Could not move the Personal library into its file yet; using the previous copy: \(KeychainQuiet.message(error))"
            }
            return try Library.open(path: Self.libraryPath.path)
        }
    }

    /// Personal is not opened yet: launch goes to another document's unlock sheet, and reading
    /// Personal's device key would show Touch ID before it. The sheet's Touch ID opens it with the
    /// same context (`openDeferredPersonal`); after a password unlock it opens when picked.
    private(set) var personalDeferred = false

    init() {
        // Quit waits for library saves still running in the background (`mutate`).
        NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: nil, queue: .main) { _ in
            Self.saveQueue.sync {}
        }
        do {
            workflow = try SshWorkflow.open(dataDir: Self.dataDir.path)
        } catch {
            self.error = "Could not open the library: \(KeychainQuiet.message(error))"
        }
        if Self.shouldDeferPersonal() { personalDeferred = true } else { loadPersonal(context: nil) }
        restoreDocuments()
    }

    /// Open Personal now (launch, or later with the unlock sheet's Touch ID context).
    private func loadPersonal(context: LAContext?) {
        do {
            personal = try openPersonal(context: context)
            library = personal
            tree = library?.tree()
            tasks = library?.tasks() ?? []
        } catch is KeychainQuiet.LockedPersonal {
            self.error = "Personal stays locked because Touch ID was cancelled. Quit and reopen Gantry to unlock it."
        } catch {
            self.error = "Could not open the library: \(KeychainQuiet.message(error))"
        }
    }

    /// Open the deferred Personal. A cancelled Touch ID keeps it closed (quietly) for a retry.
    @discardableResult
    func openDeferredPersonal(context: LAContext?) -> Bool {
        guard personalDeferred else { return personal != nil }
        guard let path = Self.personalDocumentPath else { return false }
        do {
            let key = try LibraryKey.deviceKey(in: Self.dataDir, touchID: SettingsModel().value("security.touch-id-unlock") != "false", context: context)
            let doc = try PersonalLibrary.open(dataDir: Self.dataDir.path, path: path.path, deviceKeyHex: key)
            if doc.info().locked, !Self.unlockWithMasterPassword(doc) { return false }
            personalDocument = doc
            personalName = doc.info().name
            personal = try doc.library()
            personalDeferred = false
            if activeDocumentId == nil { library = personal; reload() }
            return true
        } catch {
            if !KeychainQuiet.isCancel(error) { self.error = "Could not open Personal: \(KeychainQuiet.message(error))" }
            return false
        }
    }

    /// Defer only when all hold: the document gate runs, Personal is already its own encrypted
    /// file and known (no migration this launch), its key needs Touch ID, and the last library
    /// is another document that exists (its unlock sheet comes first).
    private static func shouldDeferPersonal() -> Bool {
        guard DocumentGate.enabled, let personal = personalDocumentPath,
              FileManager.default.fileExists(atPath: personal.path),
              FileManager.default.fileExists(atPath: dataDir.appendingPathComponent("known-documents.json").path),
              LibraryKey.needsPrompt(in: dataDir),
              let last = recentDocuments(dataDir: dataDir.path).first,
              !DocumentGate.samePath(last, personal.path) else { return false }
        return FileManager.default.isReadableFile(atPath: last)
    }

    /// Make `id` (`nil` = Personal) the document the tree and every command work on. A locked
    /// document stays inactive; the caller unlocks it first.
    func activate(_ id: String?) {
        guard let id else {
            if personalDeferred, !openDeferredPersonal(context: nil) { return }
            activeDocumentId = nil
            library = personal
            reload()
            return
        }
        guard let doc = documents.first(where: { $0.id == id }) else { return }
        // A1-FU5: an unknown library opened by path is asked about before its tree is shown.
        if let problem = OriginQuestion.askIfNeeded(doc) { self.error = problem }
        do {
            library = try doc.handle.library()
            activeDocumentId = id
        } catch {
            self.error = "\(error)"
        }
        reload()
    }

    /// Bumped on every change to the library, including settings the tree does not show
    /// (a gateway, keep-alive), so views that derive from them can refresh.
    private(set) var revision = 0 { didSet { tasks = library?.tasks() ?? [] } }

    /// Re-read the tree after the core changed the library itself (import, refresh).
    func reload() {
        tree = library?.tree()
        revision += 1
    }

    /// Built-in and saved tasks for the Application › Tasks folder; re-read on every `revision`
    /// (stored, not computed: the sidebar reads it on every update).
    private(set) var tasks: [TaskView] = []

    /// The first match in tree order, as the tree walk this replaces returned. Reading `tree`
    /// keeps the caller observing it, as the walk did (the index itself is not observed).
    func connection(id: String) -> ConnectionView? { _ = tree; return index.connections[id] }
    /// Every SSH connection, by name (Ansible control host picker).
    var sshConnections: [ConnectionView] {
        _ = tree
        return index.connections.values.filter { $0.protocol == "ssh" }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// The first connection with this display name (UI driver).
    func connection(named name: String) -> ConnectionView? { _ = tree; return index.connections.values.first { $0.name == name } }

    func folder(id: String) -> FolderView? { _ = tree; return index.folders[id] }

    /// The first folder with this display name (UI driver).
    func folder(named name: String) -> FolderView? { _ = tree; return index.folders.values.first { $0.name == name } }

    /// Library saves, in order, off the main thread (a save was 45–56 ms on the main thread per edit at
    /// 5,000 connections, 2026-11-15). The core library is locked per call, so reads stay consistent.
    private static let saveQueue = DispatchQueue(label: "bastion.library-save", qos: .userInitiated)

    /// Apply a change, refresh the tree, and save in the background. Errors are shown, never swallowed.
    func mutate(_ change: (Library) throws -> Void) {
        apply(change) { $0.tree() }
    }

    /// A change that touches only the nodes it returns the ids of (add, rename, delete, move): the
    /// tree is patched with those nodes (`Library.nodeView`) instead of read whole (~50 ms at 5,000
    /// connections). `colours`: the change can alter host colours (a move), so they are re-read.
    func patch(colours: Bool = false, _ change: (Library) throws -> [String]) {
        var touched: [String] = []
        keepColours = !colours
        defer { keepColours = false }
        apply({ touched = try change($0) }) { library in
            guard var patched = self.tree else { return library.tree() }
            for id in touched {
                guard let node = try? library.nodeView(id: id),
                      let next = TreePatch.applying(node, id: id, to: patched) else { return library.tree() }
                patched = next
            }
            return patched
        }
        lastPatch = (treeVersion, touched)
    }

    /// The ids the last `patch` changed and the tree version it made: the outline updates only
    /// their rows when it is the next version it sees.
    @ObservationIgnored private(set) var lastPatch: (version: Int, ids: [String])?

    /// Set while a patch that cannot change host colours replaces the tree.
    @ObservationIgnored private var keepColours = false

    private func apply(_ change: (Library) throws -> Void, read: (Library) -> FolderView) {
        guard let library else { return }
        do {
            try change(library)
        } catch {
            self.error = "\(error)"
            tree = library.tree()
            revision += 1
            return
        }
        tree = read(library)
        revision += 1
        Self.saveQueue.async { [weak self] in
            let failure: String?
            do { try library.save(); failure = nil } catch { failure = "\(error)" }
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard let self else { return }
                    if let failure { self.error = failure }
                    // The document file is written from the saved library, so only after the save.
                    if self.library === library { self.autosaveActiveDocument() }
                }
            }
        }
    }

    /// New items go to the library that is open: Personal writes `library.json` on every change,
    /// and an open document with a file now writes its `.bastion` file too, so nothing added to a
    /// document is lost or mistaken for Personal after a restart (owner feedback 2026-11-07 #7).
    /// A never-saved document keeps waiting for Save As.
    private func autosaveActiveDocument() {
        guard let doc = activeDocument, doc.info.path != nil, !doc.info.locked else { return }
        refreshDocument(doc.id)
        guard documents.first(where: { $0.id == doc.id })?.info.dirty == true else { return }
        saveDocument(doc.id)
    }
}

/// The main window's root: its minimum is the fixed window minimum, answered without measuring the
/// tree. With the window's content-min-size sizing, SwiftUI asked the whole tree for its size at
/// zero on every update (opening a sheet, selecting a folder): `NSHostingView.minSize` was about a
/// third of a New Folder open (Time Profiler, 2026-11-15). Every other proposal goes to the content.
struct WindowRootLayout: Layout {
    static let minSize = CGSize(width: DS.Size.windowMinWidth, height: DS.Size.windowMinHeight)

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let w = proposal.width.map { max($0, Self.minSize.width) } ?? Self.minSize.width
        let h = proposal.height.map { max($0, Self.minSize.height) } ?? Self.minSize.height
        return CGSize(width: w, height: h)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        for view in subviews { view.place(at: bounds.origin, anchor: .topLeading, proposal: ProposedViewSize(bounds.size)) }
    }
}
