import SwiftUI
import BastionCore


/// Three regions: the navigation tree, session tabs, and a collapsible, resizable inspector.
/// Every object action goes through `Commands`; this view only presents what it asks for.
struct ContentView: View {
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @Environment(VaultwardenModel.self) private var vaultwarden
    @Environment(Commands.self) private var commands
    @Environment(SettingsModel.self) private var settings
    @Environment(CredentialsModel.self) private var credentials
    @Environment(AppRouter.self) private var router
    @Environment(WorkspaceModel.self) private var workspaces
    @Environment(ShortcutsModel.self) private var shortcuts
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings
    @State private var restore = SessionRestore.shared
    @State private var gate = DocumentGate.shared
    @State private var sel = LibrarySelection()
    /// The window's content width, read by updateTooNarrow only (not observed).
    @State private var windowWidth = WidthBox()
    /// The inspector's widest width that still leaves the session area its minimum (updateTooNarrow).
    @State private var inspectorMaxNow = DS.Size.inspectorMax
    /// The window can hold the inspector as a column (`inspectorColumnRoom`, updateTooNarrow). Below that
    /// it overlays the sessions as in full screen: as a column the split view's fitting width exceeded
    /// the window, and the split view looped until AppKit aborted (#1104).
    @State private var inspectorColumnFits = true
    /// The inspector draws over the sessions instead of as a column.
    private var inspectorAsOverlay: Bool { fullScreen || !inspectorColumnFits }
    /// Read only outside `body` (actions and handlers): reading it in `body` re-renders the window per click.
    private var selection: String? { sel.id }
    private func select(_ id: String?) { sel.set(id, isConnection: id.flatMap { model.connection(id: $0) } != nil) }
    @State private var realFullScreen = false
    @State private var simulation = FullScreenSimulation.shared
    @State private var dock = AutoDock.shared
    private var fullScreen: Bool { realFullScreen || simulation.isOn }
    @State private var search = ""
    @FocusState private var searchFocused: Bool
    @State private var showingImport = false
    @State private var showingSources = false
    /// The + popover's state, shared with the toolbar by reference (`MainWindowToolbar`).
    @State private var addMenu = AddMenuState()
    @State private var showingAppearance = false
    @State private var showingQuickConnect = false
    @State private var showingPalette = false
    @State private var transcript: TranscriptTarget?
    @State private var showingTaskGridDemo = false
    @State private var showingAnsibleRun = false
    @State private var showingBroadcast = false
    @State private var savingWorkspace = false
    @State private var updateReport: UpdateChecker.Report?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @ObservedObject private var launch = LaunchGate.shared


    /// Replacing a presented alert's item in place can leave SwiftUI showing the new alert with the
    /// old one's button actions (the "Install and Relaunch" click then did nothing). Dismiss first,
    /// then present the next step on a later turn of the run loop.
    @MainActor private func presentUpdateReport(_ report: UpdateChecker.Report) async {
        updateReport = nil
        try? await Task.sleep(for: .milliseconds(350))
        updateReport = report
    }

    var body: some View {
        let _ = RenderCount.hit("ContentView")
        // The columns read whether the library shows; this body does not, so a library toggle does
        // not re-run it (MAC-STALLS).
        LibraryColumns(sel: sel, search: $search, searchFocused: $searchFocused, showingImport: $showingImport,
                       showingQuickConnect: $showingQuickConnect, addMenu: addMenu, demand: inspectorDemand,
                       inspectorAsOverlay: inspectorAsOverlay, inspectorMaxNow: inspectorMaxNow, fullScreen: fullScreen,
                       reduceMotion: reduceMotion, libraryShownChanged: { updateTooNarrow() })
        .overlay(alignment: .trailing) {
            InspectorOverlayLayer(demand: inspectorDemand, asOverlay: inspectorAsOverlay, reduceMotion: reduceMotion,
                                  panel: SelectedInspector(sel: sel, commands: commands, demand: inspectorDemand))
        }
        .overlay(alignment: .leading) {
            // Full-screen auto-dock: the library slides in over the sessions; the column stays hidden.
            if dock.docked && launch.isOpen && gate.isOpen {
                HStack(spacing: 0) {
                    LibrarySidebar(sel: sel, search: $search, commands: commands)
                    Divider()
                }
                .frame(width: DS.Size.sidebarIdeal)
                .frame(maxHeight: .infinity)
                .background(Color(nsColor: .windowBackgroundColor))
                .accessibilityIdentifier("library-dock")
                .transition(reduceMotion ? .opacity : .move(edge: .leading))
            }
        }
        .background(PointerMonitor { x in dock.pointerMoved(x: x, panelWidth: DS.Size.sidebarIdeal, enabled: autoDockEnabled || dock.docked) })
        .background(FullScreenObserver { realFullScreen = $0 })
        // Library + session area + inspector must fit; below that the inspector steps aside
        // (⌥⌘I brings it back without changing the saved choice).
        // Measured on the window: the content can grow past it when the columns do not fit.
        // The width is kept out of view state (a live resize would re-render the window per frame);
        // only the narrow flag changes, and setTooNarrow ignores repeats.
        .background(WindowWidthObserver { windowWidth.value = $0; updateTooNarrow() })
        .background(SidebarWidthWatch(sessions: sessions) { updateTooNarrow() })
        .onChange(of: fullScreen) { _, on in if !on { dock.dismiss() } }
        .animation(reduceMotion ? DS.Motion.reducedFade : DS.Motion.panel, value: dock.docked)
        // The inspector animates only from its toggles (withAnimation): an implicit animation here on
        // `inspectorShown` animated every view in the window, the toolbar's items too, each frame of
        // the slide (owner 2026-11-16: slow, and the toolbar's ">>" overflow flashed).
        .modifier(HiddenWindowTitle())
        .modifier(ChromeTonesProvider())
        .sheet(item: Binding(get: { commands.pluginGateway }, set: { commands.pluginGateway = $0 })) { r in
            PluginGatewaySheet(request: r, close: { commands.pluginGateway = nil })
        }
        .sheet(item: Binding(get: { commands.waking }, set: { if $0 == nil, let w = commands.waking { commands.wakeFinished(w, connect: false) } })) { WakeSheet(wake: $0) }
        .alert("Wake-on-LAN", isPresented: Binding(get: { commands.wakeNotice != nil }, set: { if !$0 { commands.wakeNotice = nil } })) {
            Button("OK") { commands.wakeNotice = nil }
        } message: { Text(commands.wakeNotice ?? "") }
        .sheet(isPresented: Binding(get: { commands.connectRequest != nil }, set: { if !$0 { commands.connectSheetClosed() } })) {
            if let c = commands.connectRequest {
                // Services/Processes/Event Log of an RDP connection sign in over SSH (point 11).
                if c.connection.protocol == "rdp" && c.mode != .system { RdpConnectSheet(connection: c.connection, autoConnect: c.autoConnect, failure: c.failure) }
                else if c.connection.protocol == "vnc" { VncConnectSheet(connection: c.connection, quickLibrary: c.library) }
                else if c.connection.protocol == "web" { WebGatewaySheet(connection: c.connection, quickLibrary: c.library) }
                else if c.connection.protocol == "ftps" { FtpsConnectSheet(connection: c.connection) }
                else { ConnectSheet(connection: c.connection, mode: c.mode, quickLibrary: c.library, layout: c.layout, tunnelId: c.tunnelId, systemView: c.systemView, connectAs: c.connectAs, replacing: c.replacing, filePanelFor: c.filePanelFor, autoConnectAllowed: c.autoConnect) }
            }
        }
        .modifier(WindowPanelHost())
        .sheet(isPresented: $showingPalette) { CommandPaletteView(entries: PaletteCatalog.entries(paletteContext)).closesOnOutsideClick() }
        .modifier(TranscriptSheet(target: $transcript))
        .modifier(RecentlyDeletedHooks(model: model, settings: settings, credentials: credentials))
        .sheet(isPresented: $showingTaskGridDemo) {
            #if BASTION_TEST_HOOKS
            TaskGridDemo()
            #endif
        }
        .sheet(isPresented: $showingAnsibleRun) { AnsibleRunView() }
        .sheet(isPresented: $showingBroadcast) { BroadcastView() }
        .sheet(isPresented: $savingWorkspace) { WorkspaceNameSheet(request: .save) }
        .modifier(TreeItemSheets(commands: commands))
        .modifier(CommandSheets(commands: commands, dynamic: commands.dynamic))
        .sheet(isPresented: $showingAppearance) { AppearanceView().padding(.bottom, DS.Space.s) }
        .sheet(isPresented: $showingImport) { SshImportView() }
        .sheet(isPresented: $showingSources) { SshSourcesView(checkOnAppear: model.scriptedSheet == "sources") }
        // Once the app is idle after launch: the folder dashboard's table setup, off screen.
        .task { try? await Task.sleep(for: .seconds(2)); DashboardPrewarm.run()
            InspectorPrewarm.run(model: model, sessions: sessions, settings: settings, shortcuts: shortcuts, commands: commands) }
        .onAppear {
            commands.selectNode = { [sel, model] id in sel.set(id, isConnection: model.connection(id: id) != nil) }
            // A generated row of a dynamic folder opens Quick Connect with its address.
            commands.dynamic.quickConnect = { [commands, router] address in
                commands.quickConnectPrefill = address
                router.open("quick-connect")
            }
        }
        .onChange(of: commands.deleted) { _, id in
            if id != nil, id == selection { select(nil) }
            credentials.pruneInline(library: model.library)
            commands.tree.prune(library: model.library)
        }
        .onAppear {
            sessions.openTabWindow = { [openWindow] id in openWindow(id: TabWindows.sceneId, value: id) }
            sessions.focusTabWindow = { TabWindows.focus($0) }
            sessions.currentDocumentId = { [model] in model.activeDocument.flatMap { $0.info.protected ? $0.id : nil } }
            sessions.documentLocked = { [model] id in model.documents.first { $0.id == id }?.info.locked ?? true }
            TabPreviews.configure(model: model, credentials: credentials, settings: settings)
            commands.tree.prune(library: model.library)
            if updateChannelConfigured(), settings.value("updates.check-at-launch") == "true" { checkForUpdatesAtLaunch() }
        }
        // Spec §1: restore the last open sessions once the library is loaded, then save the set
        // after every tab change so a crash loses nothing.
        // Behind the start window the library is neither drawn (the gate is opaque) nor read out:
        // no connection name reaches accessibility before a document is unlocked.
        .accessibilityHidden(!gate.isOpen)
        .overlay { if !gate.isOpen { DocumentGateView(gate: gate) } }
        .onAppear { gate.decide(model: model, sessions: sessions, settings: settings) }
        // Spec §5: restore this document's sessions once it is unlocked.
        .task(id: model.library != nil && gate.isOpen) { if gate.isOpen { restore.begin(commands: commands, settings: settings) } }
        .task(id: launch.isOpen && gate.isOpen) {
            if launch.isOpen && gate.isOpen {
                MetalPrewarm.run()
                await SheetPrewarm.run(model: model, credentials: credentials, sessions: sessions)
                FolderDashboardPrewarm.run(commands: commands, sessions: sessions)
                TerminalFontPrewarm.run(family: TerminalFonts.family(settings.value("terminal.font-family")),
                                        size: CGFloat(Int(settings.value("terminal.font-size")) ?? 13))
            }
        }
        // Its own view, so a tab switch does not re-run this body (and rebuild the toolbar).
        .background(OpenSessionsSaver(model: model, restore: restore))
        .onChange(of: restore.error) { _, e in
            if let e { model.error = e; restore.error = nil }
        }
        .onChange(of: sessions.reconnectRequest) { _, id in
            guard let id else { return }
            sessions.reconnectRequest = nil
            commands.run("reconnect", on: id)
        }
        .onChange(of: sessions.connectAsRequest) { _, r in
            guard let r else { return }
            sessions.connectAsRequest = nil
            commands.connectAs(connectionId: r.connectionId, replacing: r.replacing)
        }
        // In its own view: read here, every route set and cleared the request and re-ran this body twice.
        .background(RouteWatch { open($0) })
        .onChange(of: model.scriptedSelection) { _, name in
            guard let name, let tree = model.tree else { return }
            func find(_ f: FolderView) -> String? {
                if f.name == name { return f.id }
                return f.connections.first { $0.name == name }?.id ?? f.folders.lazy.compactMap(find).first
            }
            select(tree.folders.lazy.compactMap(find).first ?? tree.connections.first { $0.name == name }?.id)
        }
        .onChange(of: model.scriptedSheet) { _, sheet in
            showingSources = sheet == "sources"
            showingAppearance = sheet == "appearance"
            addMenu.showing = sheet == "add"
            if let sheet, sheet == "credentials" || sheet.hasPrefix("credentials-") {
                credentials.source = CredentialSource(rawValue: String(sheet.dropFirst("credentials-".count))) ?? .local
                openWindow(id: CredentialManagerView.windowId)
            }
            if sheet == "updates" { Task { updateReport = await UpdateChecker.check() } }
            if sheet == "folder" { commands.run("new-subfolder", on: nil) }
            if sheet == "tasks" { TasksPage.addExamples(model: model); commands.panel = .tasks }
            showingTaskGridDemo = sheet == "task-grid"
            if sheet == "properties", let id = selection { commands.run("properties", on: id) }
            if let p = sheet?.split(separator: "-").last, sheet?.hasPrefix("defaults-") == true {
                commands.editing = .type(protocolName: String(p), label: defaultSettingTypes.first { $0.protocolName == p }?.label ?? "")
            }
            if sheet == "folder-defaults", let f = model.tree?.folders.first {
                commands.editing = .folder(id: f.id, name: f.name)
            }
        }
        .alert(item: $updateReport) { report in
            guard let action = report.action else { return Alert(title: Text(report.title), message: Text(report.message)) }
            return Alert(title: Text(report.title), message: Text(report.message),
                         primaryButton: .default(Text(report.actionTitle)) {
                             Task {
                                 if case .download(_, let version) = action {
                                     await presentUpdateReport(.init(title: "Downloading Gantry \(version)…", message: "You can keep working; Gantry asks before installing."))
                                 }
                                 let next = await UpdateChecker.perform(action)
                                 await presentUpdateReport(next)
                             }
                         },
                         secondaryButton: .cancel(Text("Later")))
        }
        .modifier(MigrationNoticeAlert())
        .overlay(alignment: .bottom) { if !commands.hookGates.isEmpty { HookGateBar(gates: commands.hookGates) } }
        .alert("Error", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK") { model.error = nil }
        } message: { CodedAlert.text("APP", model.error) }
        .alert("Keyboard Shortcuts", isPresented: Binding(get: { shortcuts.error != nil }, set: { if !$0 { shortcuts.error = nil } })) {
            Button("OK") { shortcuts.error = nil }
        } message: { Text(shortcuts.error ?? "") }
        .alert("Workspaces", isPresented: Binding(get: { workspaces.error != nil }, set: { if !$0 { workspaces.error = nil } })) {
            Button("OK") { workspaces.error = nil }
        } message: { Text(workspaces.error ?? "") }
        .alert("Session Error", isPresented: Binding(get: { sessions.error != nil }, set: { if !$0 { sessions.error = nil } })) {
            Button("OK") { sessions.error = nil }
        } message: { CodedAlert.text("SSH", sessions.error) }
    }

    /// Pages and commands named by Settings links (`settings.rs` link targets) and the palette.
    private func open(_ target: String) {
        switch target {
        case "settings": openSettings()
        case let t where t.hasPrefix("settings-search:"):
            settings.pendingQuery = String(t.dropFirst("settings-search:".count))
            openSettings()
        case "quick-connect":
            showingQuickConnect = true
        case "palette": showingPalette = true
        case "workspace-manager": commands.panel = WindowPanel(rawValue: "workspace-manager")
        case "gateway-manager": commands.panel = WindowPanel(rawValue: "gateway-manager")
        case "host-cas": commands.panel = WindowPanel(rawValue: "host-cas")
        case "ssh-agent": commands.panel = .agentKeys
        case "terminal-themes": commands.panel = .themes
        case "snippets": commands.panel = .snippets
        case "tunnel-manager": commands.panel = WindowPanel(rawValue: "tunnel-manager")
        case "home":
            sessions.connectionPage = nil
            sessions.folderPage = nil
            sessions.homeShown = true
        case "activity": commands.panel = .activity
        case "audit-log": commands.panel = .auditLog
        case "plugins": commands.panel = .plugins
        case let t where t.hasPrefix("transcript:"):
            // `transcript:<path>`: the viewer for one file (driver and future links).
            let path = String(t.dropFirst("transcript:".count))
            transcript = TranscriptTarget(path: path, connection: URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent, started: (try? URL(fileURLWithPath: path).resourceValues(forKeys: [.creationDateKey]).creationDate) ?? Date())
        case "export-diagnostics": DiagnosticsExport.run(model.tree) { if let e = $0 { model.error = e } }
        case "recently-deleted": commands.panel = .recentlyDeleted
        case "host-status": commands.panel = .hostStatus
        case "triggers": commands.panel = .triggers
        case "password-generator": commands.panel = WindowPanel(rawValue: "password-generator")
        case "import-connections":
            if let r = LibraryIO.importConnections(model: model) {
                select(r.folderId)
                commands.showImportReport(r)
            }
        case "import-keepass":
            if let url = LibraryIO.chooseKeePassFile() { commands.keepassRequest = KeePassImportSheet.Request(url: url); commands.panel = .keepass }
        case "export-library":
            // The selected folder, else everything.
            if let id = selectedFolderId, let f = model.folder(id: id) {
                commands.exportRequest = ExportSheet.Request(ids: [id], scope: "“\(f.name)”")
            } else {
                commands.exportRequest = ExportSheet.Request(ids: nil, scope: "Library")
            }
            commands.panel = .export
        case "export-ssh-config":
            let folder = selectedFolderId.flatMap { model.folder(id: $0) != nil ? $0 : nil }
            if let r = LibraryIO.exportSshConfig(model: model, ids: folder.map { [$0] }, folderId: folder ?? selection ?? "") {
                commands.showImportReport(r)
            }
        case "export-ansible-inventory":
            let folder = selectedFolderId.flatMap { model.folder(id: $0) != nil ? $0 : nil }
            if let r = LibraryIO.exportAnsibleInventory(model: model, ids: folder.map { [$0] }, folderId: folder ?? selection ?? "") {
                commands.showImportReport(r)
            }
        case "run-on-hosts": commands.panel = .runOnHosts
        case "tasks-page": commands.panel = .tasks
        case "run-ansible": showingAnsibleRun = true
        case "broadcast": showingBroadcast = true
        case "toggle-session-log": sessions.toggleLog()
        case "save-workspace": if !sessions.tabs.isEmpty { savingWorkspace = true }
        case let t where t.hasPrefix("workspace:"): workspaces.open(String(t.dropFirst("workspace:".count)), commands: commands)
        // File › New Connection… In Compact (the default header) there is no + popover to show:
        // the item did nothing (of-b-perf "no popover", census 2026-11-17), so it opens the form.
        case "add" where !HeaderStyle.isCompact(settings): addMenu.showing = true
        case "add", "new-connection":
            // Without animation: an animated column open re-measured the window and every split item on
            // each step, ~100 ms on the main thread against the 50 ms budget (MAC-NEWCONN-STALL).
            var instant = Transaction(); instant.disablesAnimations = true
            withTransaction(instant) { commands.addConnection = ParentTarget(id: selectedFolderId) }
        case "new-folder": commands.run("new-subfolder", on: selectedFolderId)
        case "local-shell": sessions.openLocal()
        case "default-action": if let id = selection { commands.performDefault(on: id) }
        case "focus-search": searchFocused = true
        case "toggle-library":
            // Owner point 25: in a window every toggle pins or hides the real column; the edge dock
            // is a hover preview only. Full screen keeps the dock (the sessions keep their size).
            if fullScreen && (autoDockEnabled || dock.docked) { dock.toggle() } else {
                dock.dismiss()
                let autoHide = libraryAutoHide
                if libraryDisplayed {
                    commands.tree.toggleLibrary(autoHide: autoHide)
                } else {
                    // Opening: the tab strip takes its narrower width first and the toolbar re-tiles
                    // once; the column slides on the next run-loop turn. Started together, the strip
                    // (its own hosting view) shrank only after the slide began, and NSToolbar showed
                    // its ">>" overflow through the open (MAC-LIBRARY-OPEN-OVERFLOW).
                    sessions.libraryWillShow(sidebar: sessions.sidebarWidth)
                    DispatchQueue.main.async { [commands] in commands.tree.toggleLibrary(autoHide: autoHide) }
                }
            }
        case "toggle-inspector":
            let tree = commands.tree
            let toggle = { [reduceMotion] in withAnimation(DS.Motion.spring(reduced: reduceMotion)) { tree.toggleInspector() } }
            // Opening the column: the strip takes its narrower width first, as for the library
            // (MAC-LIBRARY-OPEN-OVERFLOW); left to settle after the slide, NSToolbar flashed its
            // ">>" menu during the open (owner round 4). Full screen and narrow windows show the
            // inspector over the sessions, so the area keeps its width there.
            let opensColumn = !tree.inspectorPresented && !tree.tooNarrowForInspector
                && NSApp.keyWindow?.styleMask.contains(.fullScreen) != true
            if opensColumn {
                sessions.libraryWillShow(sidebar: DS.Size.inspectorIdeal)
                DispatchQueue.main.async { toggle() }
            } else {
                toggle()
            }
        case "toggle-files-panel": toggleFilePanel()
        case "expand-all", "collapse-all": commands.run(target, on: nil)
        case "split-right": Task { await sessions.split(.right) }
        case "split-down": Task { await sessions.split(.down) }
        case "all-tabs": if !sessions.tabs.isEmpty { sessions.showingAllTabs.toggle() }
        case "tab-overview": TabPreviews.shared.showingOverview.toggle()
        case "next-tab", "previous-tab", "next-tab-alt", "previous-tab-alt": sessions.selectNeighbourTab(forward: target.hasPrefix("next"))
        case "find": if sessions.selectedTab?.terminal != nil { sessions.searching = true }
        case "find-next", "find-previous": sessions.find(forward: target == "find-next")
        case "zoom-in", "zoom-out", "zoom-reset": sessions.zoom(target == "zoom-reset" ? nil : (target == "zoom-in" ? 1 : -1))
        case "clear-scrollback": sessions.selectedTab?.terminal?.clearScrollback()
        case "previous-prompt", "next-prompt": _ = sessions.selectedTab?.terminal?.jumpPrompt(forward: target == "next-prompt")
        case "send-break": sessions.sendBreak()
        case "close-pane": sessions.closeFocused()
        case "focus-pane-left": sessions.selectedTab?.focusNeighbour(.left)
        case "focus-pane-right": sessions.selectedTab?.focusNeighbour(.right)
        case "focus-pane-up": sessions.selectedTab?.focusNeighbour(.up)
        case "focus-pane-down": sessions.selectedTab?.focusNeighbour(.down)
        case "next-pane", "previous-pane": sessions.selectedTab?.cycleFocus(forward: target == "next-pane")
        case "keyboard-shortcuts":
            settings.pendingCategory = "keyboard"
            openSettings()
        case "managed-policy":
            settings.pendingCategory = SettingsView.policyPage
            openSettings()
        case let t where t.hasPrefix("tab:"):
            if let n = Int(t.dropFirst(4)), sessions.mainTabs.indices.contains(n - 1) { sessions.selected = sessions.mainTabs[n - 1].id }
        case "ssh-sources": showingSources = true
        case "ssh-import": showingImport = true
        case "lock-credentials": credentials.lockAll(sessions: sessions, vaultwarden: vaultwarden)
        case "personal-master-password": model.editMasterPassword()
        case "check-updates": Task { updateReport = await UpdateChecker.check() }
        case "credential-manager", "vaultwarden":
            credentials.source = target == "vaultwarden" ? .vaultwarden : .local
            openWindow(id: CredentialManagerView.windowId)
            bringToFront(CredentialManagerView.windowId)
        case let t where t.hasPrefix("defaults:"):
            let p = String(t.dropFirst("defaults:".count))
            if let type = defaultSettingTypes.first(where: { $0.protocolName == p }) {
                commands.editing = .type(protocolName: type.protocolName, label: type.label)
            }
        default: model.error = "Nothing handles “\(target)”."
        }
    }

    /// ⇧⌘B: closes the selected SSH tab's file panel, or connects SFTP into it (same login sheet).
    private func toggleFilePanel() {
        guard let tab = sessions.selectedTab, tab.canShowFilePanel else { return }
        if tab.filePanel != nil { return tab.closeFilePanel() }
        guard let id = tab.connectionId, let c = commands.model.connection(id: id) else { return }
        commands.enqueue([ConnectRequest(connection: c, mode: .files, filePanelFor: tab.id)], select: nil)
    }

    /// `updates.check-at-launch`: only an available update interrupts; a failed check is logged
    /// (offline starts would otherwise open an alert every time) and shows on a manual check.
    private func checkForUpdatesAtLaunch() {
        Task {
            let report = await UpdateChecker.check()
            UpdateChecker.lastLaunchReport = report.title
            if report.available { updateReport = report } else { NSLog("Gantry launch update check: %@", report.title) }
        }
    }

    /// What decides whether the inspector shows; observed only by the views it is handed to.
    private var inspectorDemand: InspectorDemand {
        InspectorDemand(isOpen: launch.isOpen && gate.isOpen, commands: commands, sessions: sessions, sel: sel)
    }

    /// Width under which the inspector auto-hides: the room the columns need (see `inspectorColumnRoom`).
    static func narrowWidth(libraryShown: Bool) -> CGFloat {
        (libraryShown ? DS.Size.sidebarMin : 0) + inspectorColumnRoom(inspector: DS.Size.inspectorMin)
    }

    /// What the window must hold for an inspector column of `inspector` pt, library aside. On macOS 26+
    /// the session column extends under the inspector, and the split view counts the inspector twice:
    /// once in the session column's fitting width and once as its own column (measured with the SDK 27
    /// link: fitting width = 233 + library + inspector, plus the inspector column; #1104). Past that the
    /// columns no longer fit the window and the split view loops until AppKit aborts.
    static func inspectorColumnRoom(inspector: CGFloat) -> CGFloat {
        DS.Size.sessionContentMin + 2 * inspector
    }

    private var libraryAutoHide: Bool { LibraryColumns.autoHide(settings) }

    /// The window cannot hold the library (as the user chose it), a usable page and the inspector.
    private func updateTooNarrow() {
        // Without animation: an animated column collapse finishes later on the main queue and resets the split
        // view's sizes after the window already shrank; from 1800 to 600 pt in one resize that looped (#1104).
        var still = Transaction()
        still.disablesAnimations = true
        withTransaction(still) { applyWidth() }
    }

    private func applyWidth() {
        let width = windowWidth.value
        commands.tree.setTooNarrow(width > 0 && width < Self.narrowWidth(libraryShown: commands.tree.libraryShown(autoHide: libraryAutoHide)))
        let fits = width <= 0 || width >= Self.inspectorColumnRoom(inspector: DS.Size.inspectorMin)
        if fits != inspectorColumnFits { inspectorColumnFits = fits }
        // The column's limits change only while it stays: changing them in the same update that removes
        // the column (1800 -> 600 pt in one resize) left the split view mid-change and it looped (of-c-pages).
        guard fits else { return }
        let fit = Self.inspectorMax(window: width, library: libraryDisplayed ? sessions.sidebarWidth : 0)
        if fit != inspectorMaxNow { inspectorMaxNow = fit }
    }

    /// The widest inspector column that still fits (`inspectorColumnRoom`): 330 pt in an 1100 pt window
    /// with the library; a drag to 340 pt there made the split view loop (#1104). Whole 8 pt steps, so a
    /// live resize changes it rarely; never below the inspector's own minimum.
    static func inspectorMax(window: CGFloat, library: CGFloat) -> CGFloat {
        guard window > 0 else { return DS.Size.inspectorMax }
        let room = ((window - library - DS.Size.sessionContentMin) / 2 / 8).rounded(.down) * 8
        return min(DS.Size.inspectorMax, max(DS.Size.inspectorMin, room))
    }

    /// The library column as drawn. When the window is too narrow for library + page + inspector
    /// and the user brought the inspector back, the library steps aside so the three column
    /// minimums never exceed the window (MAC-INSPECTOR-FIT). The narrow check itself keeps using
    /// the user's library choice, so collapsing here does not flip it back.
    private var libraryDisplayed: Bool { LibraryColumns.libraryDisplayed(tree: commands.tree, settings: settings, inspectorAsOverlay: inspectorAsOverlay) }

    /// Full-screen auto-dock applies: full screen, auto-hide and the dock setting on, column hidden.
    private var autoDockEnabled: Bool { LibraryColumns.autoDockEnabled(tree: commands.tree, settings: settings, fullScreen: fullScreen) }

    /// Folder that new items go into: the selected folder, else the root.
    private var selectedFolderId: String? {
        guard let id = selection, model.folder(id: id) != nil else { return nil }
        return id
    }

    private var paletteContext: PaletteCatalog.Context {
        PaletteCatalog.Context(commands: commands, router: router, workspaces: workspaces, settings: settings, shortcuts: shortcuts,
                               selection: selection, select: { select($0) })
    }
}

/// Identifies the folder a sheet adds into; `nil` means the library root.
struct ParentTarget: Identifiable, Equatable {
    let id: String?
    /// Connection type chosen in the Add menu.
    var protocolName: String? = nil
}

/// `searchFocused` needs macOS 15; on 14 the field is still visible in the sidebar.
struct SearchFocus: ViewModifier {
    var focused: FocusState<Bool>.Binding
    func body(content: Content) -> some View {
        if #available(macOS 15, *) { content.searchFocused(focused) } else { content }
    }
}

/// Two-column grid: fixed-width secondary labels, selectable values.
struct InspectorSection: View {
    let rows: [(String, String)]

    var body: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: DS.Space.s, verticalSpacing: DS.Space.xs) {
            ForEach(rows, id: \.0) { label, value in
                GridRow {
                    Text(label).foregroundStyle(.secondary).frame(width: DS.Size.labelColumn, alignment: .leading)
                    Text(value).textSelection(.enabled).lineLimit(2).truncationMode(.middle)
                }
            }
        }
        .font(DS.Font.body)
    }
}

/// One label/control row aligned with `InspectorSection`'s label column.
struct InspectorRow<Content: View>: View {
    let label: String
    @ViewBuilder let content: Content

    init(_ label: String, @ViewBuilder content: () -> Content) {
        self.label = label
        self.content = content()
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: DS.Space.s) {
            Text(label).foregroundStyle(.secondary).frame(width: DS.Size.labelColumn, alignment: .leading)
            content.frame(maxWidth: .infinity, alignment: .leading)
        }
        .font(DS.Font.body)
    }
}

/// Saves the open-session set after every tab change so a crash loses nothing. It reads the tabs
/// and the selection in its own body: read in `ContentView.body`, every tab switch re-ran the
/// window's body and rebuilt its toolbar.
///
/// A dynamic property (the environment), so SwiftUI gives it its own body: a view made only of
/// `let`s is evaluated inline and its reads counted against the parent (nm-23 profile).
private struct OpenSessionsSaver: View {
    @Environment(SessionsModel.self) private var sessions
    let model: LibraryModel
    let restore: SessionRestore

    /// Changes whenever the open-session set would: tab order, mode, splits, group, selection.
    private var key: String {
        sessions.tabs.map { "\($0.id)|\($0.connectionId ?? "")|\($0.mode.rawValue)|\($0.layoutSteps.joined(separator: ","))|\($0.group ?? "")|\($0.ended)" }
            .joined(separator: ";") + "#\(sessions.selected?.uuidString ?? "")"
            + "#" + sessions.windowed.map { "\($0.key)>\($0.value)" }.sorted().joined(separator: ",")
            + "#" + sessions.windowSelected.map { "\($0.key)>\($0.value)" }.sorted().joined(separator: ",")
            + "#\(sessions.windowFramesVersion)"
    }

    var body: some View {
        Color.clear
            .onChange(of: key) { restore.save(SessionRestore.currentSet(sessions) { model.connection(id: $0) != nil }) }
    }
}

/// The inspector for the current selection; reads it in its own body, not the window's.
struct SelectedInspector: View {
    let sel: LibrarySelection
    let commands: Commands
    let demand: InspectorDemand
    var body: some View {
        let _ = RenderCount.hit("SelectedInspector")
        // Only where the column shows: with the column closed the form is the mounted-once overlay
        // (NewConnectionOverlay), and building it here too, in the hidden column, cost a second build.
        if let add = commands.addConnection, demand.column {
            // The New Connection form opens here, not in a sheet: AppKit's sheet attach alone cost
            // ~105 ms on the first open (perf budgets 2026-11-15). Closing it shows the selection again.
            AddConnectionView(parent: add.id, proto: add.protocolName ?? "ssh",
                              close: { [commands] in commands.addConnection = nil })
                .id(add.id.map { $0 + "|" } ?? "|" + (add.protocolName ?? "ssh"))
        } else {
            SelectedInspectorPane(sel: sel, commands: commands)
        }
    }
}

/// The inspector for what is in front. It reads the tab, page and pick in its own body: read in the
/// inspector column's root, every tab opened re-ran that root and the split view re-pushed its columns
/// (MAC-FIRST-SHELL).
private struct SelectedInspectorPane: View {
    let sel: LibrarySelection
    let commands: Commands
    @Environment(SessionsModel.self) private var sessions

    /// Made here, not passed in: with a closure input every window update (a library toggle, a new
    /// tab) re-rendered the inspector, built or hidden (MAC-STALLS).
    private var select: (String) -> Void {
        { [sel, model = commands.model] id in sel.set(id, isConnection: model.connection(id: id) != nil) }
    }

    var body: some View {
        InspectorPane(selection: sessions.connectionPage == nil ? sessions.selectedTab?.connectionId ?? sessions.startPick ?? sel.shownId : sel.shownId, commands: commands, select: select)
    }
}

/// Selecting anything shows the inspector a session hid; observed here so the window's body does not read the selection.
struct SelectionWatch: View {
    let sel: LibrarySelection
    let commands: Commands
    var body: some View {
        // On the selection's own notification, posted as it changes, not `onChange`: the page then
        // changes in the same SwiftUI update as the tree, not in a second pass (MAC-SELECT-SPEED).
        Color.clear.onReceive(NotificationCenter.default.publisher(for: LibrarySelection.changed, object: sel)) { _ in
            commands.tree.showInspectorAgain()
            openPage(sel.current)
        }
        .onAppear {
            // A click on the already-selected connection reopens its page over the service.
            commands.tree.onConnectionClicked = { [sel, sessions] in
                guard sel.isConnection, let id = sel.id else { return }
                if let live = sessions.liveTab(for: id) { sessions.selected = live.id }
                else if sessions.connectionPage != id { sessions.connectionPage = id }
            }
        }
    }

    @Environment(SessionsModel.self) private var sessions

    /// A connection with a live session shows that session straight away; the page is for
    /// connections with none (owner feedback 18, 2026-11-07).
    private func openPage(_ id: String?) {
        if sel.isConnection, let id, let live = sessions.liveTab(for: id) {
            if sessions.selected != live.id { sessions.selected = live.id } else if sessions.connectionPage != nil { sessions.connectionPage = nil }
            return
        }
        let next = sel.isConnection ? id : nil
        if sessions.connectionPage != next { sessions.connectionPage = next }
        // A folder, or the library root, shows its dashboard (DASH-01).
        let folder = sel.isConnection ? nil : id.flatMap { commands.model.folder(id: $0) != nil ? $0 : nil }
        if sessions.folderPage != folder { sessions.folderPage = folder }
    }
}

/// Whether the view on screen shows the inspector by itself (a connection's page or a picked
/// Recent row), and clears the toggle's per-view choice when the tab, page or picked Recent row
/// changes (point 30; a start-page hide no longer hides a later Recent pick).
struct InspectorContextWatch: View {
    let sel: LibrarySelection
    let commands: Commands
    @Environment(SessionsModel.self) private var sessions

    private var allows: Bool {
        if let page = sessions.connectionPage { return sel.isConnection && page == sel.id }
        return sessions.mainTabs.isEmpty && sessions.startPick != nil
    }

    var body: some View {
        Color.clear
            .onChange(of: allows, initial: true) { _, on in commands.tree.inspectorContextAllows = on }
            // As the tab, page, library selection or picked Recent row changes, not in an `onChange`
            // after the update: that cleared it in a second window-wide pass (speed wave 3, first local shell).
            .onAppear { [tree = commands.tree] in sessions.viewChanged = { Self.clearOverride(tree) } }
            .onReceive(NotificationCenter.default.publisher(for: LibrarySelection.changed, object: sel)) { _ in Self.clearOverride(commands.tree) }
    }

    @MainActor private static func clearOverride(_ tree: TreeStateModel) {
        if tree.inspectorOverride != nil { tree.inspectorOverride = nil }
    }
}

/// Hides the inspector when a session opens, as the tab is added (`SessionsModel.tabOpened`): an
/// `onChange` of the tab count set it after the update, in a second window-wide pass (speed wave 3).
struct SessionOpenWatch: View {
    let commands: Commands
    @Environment(SessionsModel.self) private var sessions

    var body: some View {
        Color.clear.onAppear { [tree = commands.tree] in
            sessions.tabOpened = { if !tree.inspectorHiddenBySession { tree.inspectorHiddenBySession = true } }
        }
    }
}

/// The detail column: the empty-library state, or the sessions. Reads the tabs here, not in
/// `ContentView.body`, so opening the first tab or closing the last doesn't rebuild the toolbar.
struct SessionDetail: View {
    let gateOpen: Bool
    let libraryEmpty: Bool
    @Binding var showingImport: Bool
    @Environment(SessionsModel.self) private var sessions
    @Environment(Commands.self) private var commands

    var body: some View {
        let _ = RenderCount.hit("SessionDetail")
        // The session area stays mounted under the empty-library state, as the canvas does under the
        // start page. Swapping one for the other tore the whole area down on every last-tab close and
        // built it again on the next open, and each torn-down copy was kept: its folder dashboard (rows
        // controller, stored settings, notification observers) and observation records, so memory grew
        // with every open-and-close (MAC-MEMORY-GROWTH). Hidden and disabled while the state shows.
        let showsEmpty = libraryEmpty && sessions.tabs.isEmpty
        ZStack {
            if gateOpen {
                SessionTabsView()
                    .overlay { if TabPreviews.shared.showingOverview { TabOverview() } }
                    .opacity(showsEmpty ? 0 : 1)
                    .allowsHitTesting(!showsEmpty)
                    .accessibilityHidden(showsEmpty)
                    .disabled(showsEmpty)
                if showsEmpty {
                    EmptyState(symbol: "server.rack", title: "No connections", message: "Add a host or import your OpenSSH configuration.") {
                        HStack(spacing: DS.Space.xs) {
                            Button("Import SSH Config…") { showingImport = true }.dsSecondaryButton()
                            Button("Add Connection") { commands.run("new-connection", on: nil) }.keyboardShortcut(.defaultAction)
                                .dsPrimaryButton()
                        }
                    }
                    .background(.background)
                }
            }
        }
        // The column's width comes from the split view, never from its content: with the macOS 27 SDK the
        // column extends under the library and the inspector, so its fitting width is content minimum +
        // library + inspector. A tab opening with a sheet up (SessionTitleBar, the toolbar strip) raised the
        // content minimum past `sessionContentMin`, the columns no longer fitted the window, and the split
        // view re-laid out every pass until AppKit aborted (MAC-SFTP-CRASH). Min and max both set: SwiftUI
        // clamps the proposal and does not ask the content.
        .frame(minWidth: DS.Size.sessionContentMin, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity)
        .background { SessionTabsWatch(commands: commands) }
    }
}

/// Follows the tab list for the tab previews and auto-hide. Its own view: read in the session
/// column's root, every tab opened or closed re-ran that root and the split view re-pushed its columns
/// (MAC-FIRST-SHELL).
private struct SessionTabsWatch: View {
    let commands: Commands
    @Environment(SessionsModel.self) private var sessions
    var body: some View {
        Color.clear
            .onChange(of: sessions.tabs.map(\.id)) { TabPreviews.shared.retain(sessions.tabs) }
            // Owner 2026-11-05: auto-hide follows open sessions, not keyboard focus.
            .onChange(of: sessions.tabs.isEmpty, initial: true) { _, empty in commands.tree.setSessionFocused(!empty) }
    }
}

/// A plain holder: writing it does not invalidate the view.
final class WidthBox { var value: CGFloat = 0 }

/// Calls `changed` when the library column's settled width changes; observed here so the window's
/// body does not read it.
private struct SidebarWidthWatch: View {
    let sessions: SessionsModel
    let changed: () -> Void
    var body: some View { Color.clear.onChange(of: sessions.sidebarWidth) { _, _ in changed() } }
}

/// The transcript viewer opened by the `transcript:<path>` route (own modifier: keeps
/// `ContentView.body` within the type checker's limit).
private struct TranscriptSheet: ViewModifier {
    @Binding var target: TranscriptTarget?
    func body(content: Content) -> some View {
        content.sheet(item: $target) { TranscriptView(target: $0) }
    }
}

/// The sheets `Commands` opens, in their own modifier: reading their state in `ContentView`'s body
/// made every open re-run it and re-render the split view (New Folder: 44–70 ms stall per open,
/// perf budgets 2026-11-15). Here an open re-runs only this modifier.
private struct CommandSheets: ViewModifier {
    @Bindable var commands: Commands
    @Bindable var dynamic: DynamicFoldersModel

    func body(content: Content) -> some View {
        content
            .sheet(item: $commands.namingWorkspace) { WorkspaceNameSheet(request: $0) }
            .sheet(item: $commands.editing) { PropertyEditor(target: $0) }
            .sheet(item: $commands.editingTask) { TaskEditorSheet(request: $0) }
            .sheet(item: $commands.runOnTask) { TaskRunOnSheet(task: $0.task, preset: $0.preset, autoStart: $0.autoStart) }
            .sheet(item: $commands.taskHooks) { TaskHooksSheet(connectionId: $0.id ?? "") }
            .sheet(item: $dynamic.editing) { DynamicFolderEditSheet(request: $0, dynamic: dynamic) }
            .sheet(item: $dynamic.trusting) { DynamicFolderTrustSheet(request: $0, dynamic: dynamic) }
    }
}
