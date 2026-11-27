#if BASTION_TEST_HOOKS
import AppKit
import SwiftUI
import BastionCore

/// Verification aid (like `Snapshot`): with `BASTION_UI_SCRIPT=<file>` and `BASTION_SNAPSHOT=hold`, the app
/// runs the script against its own window and writes `ui-log.txt` and the captures (`UIDriverCapture`) to `BASTION_UI_OUT`.
/// Input is delivered as real `NSEvent`s to the window (mouse down/up with click counts, key downs with
/// modifiers), so the outline's own AppKit handling runs; context menus come from the outline's
/// `menu(for:)` and items fire through `NSMenu`; drops go through the outline's drag data source.
/// It cannot move the hardware pointer. Use throwaway libraries only (`BASTION_LIBRARY`).
///
/// One step per line (`#` comments): `click <row>` `doubleclick <row>` `cmdclick <row>`
/// `key <down|up|left|right|return|escape|cmd+backspace|opt+right|…>` `type <text>`
/// `menu <row>` (logs the items) `menu <row> > <item label>` (runs it) `alert <button label>`
/// `drag <row> -> <folder row|Library> [before <row>]` `filter <text>` `dump` `capture <name>` `capture-source <window|views|any>`
/// `appearance <dark|light|system>` `wait <seconds>` `mark` / `measure <label>` (ms since `mark`) `time-select <row>,<row>…` `quit`.
/// `<row>` is a row's visible name; Favorites entries are `★name`.
@MainActor
enum UIDriver {
    /// Models the settings and credential steps act on (set by the app at launch).
    struct Services {
        let settings: SettingsModel
        let autoLock: CredentialAutoLock
        let credentials: CredentialsModel
        let vaultwarden: VaultwardenModel
        let sessions: SessionsModel
        let router: AppRouter
        let workspaces: WorkspaceModel
        let shortcuts: ShortcutsModel
        let themes: ThemesModel
        let snippets: SnippetsModel
    }
    static var services: Services?
    /// A UI-driver run: the app stays in the background (see `AppDelegate`).
    static let isScripted = TestHooks.isScripted

    static func runIfRequested(commands: Commands) {
        let env = ProcessInfo.processInfo.environment
        guard let path = env["BASTION_UI_SCRIPT"], let script = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        let driver = Driver(out: URL(fileURLWithPath: env["BASTION_UI_OUT"] ?? NSTemporaryDirectory()), commands: commands)
        // Never touch the user's clipboard from a test run.
        commands.pasteboard = NSPasteboard(name: .init("dev.bastion.uidriver.clipboard"))
        RdpDesktop.pasteboard = commands.pasteboard
        TerminalClipboard.board = commands.pasteboard
        LogSnippet.board = commands.pasteboard
        Driver.watchActivation()
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.5))
            driver.write("SCREEN \(Driver.screenState)")
            for line in script.split(separator: "\n").map({ $0.trimmingCharacters(in: .whitespaces) })
            where !line.isEmpty && !line.hasPrefix("#") {
                StallWatch.shared.step = line
                await driver.step(line)
            }
            driver.writeActivation()
            driver.flush(wait: true)
        }
    }
}

@MainActor
final class Driver {
    let out: URL
    let commands: Commands
    var log: [String] = []
    var mark = CFAbsoluteTimeGetCurrent()
    let started = CFAbsoluteTimeGetCurrent()

    /// Whether the app held activation for the whole run. Suites that open SwiftUI popovers
    /// (BASTION_UI_FOREGROUND=1) need it: an inactive app closes them at once. While someone uses
    /// the Mac, macOS gives the app activation only briefly; run-all.sh then reports the suite's
    /// failures as a lab need (LAB) when the log ends with `APP-ACTIVE held=false`.
    static var heldActivation = true
    private static var activationTokens: [NSObjectProtocol] = []

    static func watchActivation() {
        activationTokens = [NSApplication.didResignActiveNotification].map {
            NotificationCenter.default.addObserver(forName: $0, object: nil, queue: .main) { _ in
                MainActor.assumeIsolated { heldActivation = false }
            }
        }
    }

    func writeActivation() {
        write("APP-ACTIVE held=\(Self.heldActivation && NSApp.isActive)")
    }

    init(out: URL, commands: Commands) {
        self.out = out
        self.commands = commands
    }

    /// The main window: the one holding the library outline, or, while the document gate is up
    /// (the library is not built then), the visible "Gantry" window that is not a torn-off tab.
    var window: NSWindow? {
        NSApp.windows.first { $0.contentView?.firstSubview(of: KeyOutlineView.self) != nil }
            ?? NSApp.windows.first { $0.isVisible && $0.title == "Gantry" && !TabWindows.windows.values.contains($0) }
    }

    /// A visible window by title, or by scene identifier (`settings`, `credentials`), since
    /// those windows title themselves after the page they show.
    func findWindow(_ name: String) -> NSWindow? {
        let visible = NSApp.windows.filter(\.isVisible)
        if name == "main" { return window }
        let scene = name == "settings" ? "com_apple_SwiftUI_Settings_window" : name
        return visible.first { $0.identifier?.rawValue == scene } ?? visible.first { $0.title == name }
    }
    var outline: KeyOutlineView? { window?.contentView?.firstSubview(of: KeyOutlineView.self) }

    /// Torn-off windows and their tab counts, the main strip, and whether main has a selection.
    static func frameText(_ f: NSRect) -> String { "\(Int(f.minX.rounded())),\(Int(f.minY.rounded())),\(Int(f.width.rounded())),\(Int(f.height.rounded()))" }

    /// W16: why a torn-off window is not frontmost (registered window vs the app's ordered windows).
    static func tabWindowDiag(_ id: UUID?) -> String {
        let reg = id.flatMap { TabWindows.windows[$0] }
        let order = NSApp.orderedWindows.map { "\($0.windowNumber)\($0 === reg ? "*" : ""):\($0.title):v\($0.isVisible ? 1 : 0):l\($0.level.rawValue)" }
        return "reg=\(reg.map { "\($0.windowNumber):v\($0.isVisible ? 1 : 0):l\($0.level.rawValue):occ\($0.occlusionState.contains(.visible) ? 1 : 0)" } ?? "-") active=\(NSApp.isActive) policy=\(NSApp.activationPolicy().rawValue) order=\(order)"
    }

    static func windowSummary(_ s: SessionsModel) -> String {
        let counts = Dictionary(grouping: s.windowed.values, by: { $0 }).values.map(\.count).sorted()
        return "windows=\(counts.count) perWindow=\(counts) strip=\(s.mainTabs.count) of \(s.tabs.count) selectedInMain=\(s.mainTabs.contains { $0.id == s.selected })"
    }

    func write(_ s: String) {
        log.append(String(format: "%8.1f\t%@", (CFAbsoluteTimeGetCurrent() - started) * 1000, s))
        flush()
    }

    /// Serial, so writes land in order; off the main thread so the atomic write's fsync does not
    /// stall the UI (nm-21 profile: it skewed every timed step).
    private static let logQueue = DispatchQueue(label: "bastion.uidriver.log", qos: .utility)

    /// `wait`: block until the file is written (before quit, crash or a deliberate kill).
    func flush(wait: Bool = false) {
        let text = log.joined(separator: "\n") + "\n"
        let url = out.appendingPathComponent("ui-log.txt")
        let save = { try? text.write(to: url, atomically: true, encoding: .utf8) }
        if wait { Self.logQueue.sync { _ = save() } } else { Self.logQueue.async { _ = save() } }
    }

    /// Let SwiftUI and AppKit settle (state propagation, layout) before the next step.
    func settle(_ seconds: Double = 0.25) async {
        try? await Task.sleep(for: .seconds(seconds))
    }

    /// Waits (0.5 s at least, 3 s at most) until every split view's panes keep the same frames for
    /// three polls in a row, so a column show/hide animation has finished. Returns the wait in ms.
    func settleSplitViews() async -> Int {
        let start = CFAbsoluteTimeGetCurrent()
        func frames() -> String {
            (window?.contentView?.allSubviews(of: NSSplitView.self) ?? [])
                .flatMap { $0.arrangedSubviews.map { "\($0.frame.integral)\($0.isHidden)" } }.joined(separator: ";")
        }
        await settle(0.5)
        var last = frames(), stable = 0
        while stable < 3 && CFAbsoluteTimeGetCurrent() - start < 3 {
            await settle(0.1)
            let now = frames()
            stable = now == last ? stable + 1 : 0
            last = now
        }
        return Int((CFAbsoluteTimeGetCurrent() - start) * 1000)
    }

    func step(_ line: String) async {
        let parts = line.split(separator: " ", maxSplits: 1).map(String.init)
        let (cmd, arg) = (parts[0], parts.count > 1 ? parts[1] : "")
        window?.makeKeyAndOrderFront(nil)
        if cmd == "capture-source" { return captureSourceStep(arg) }
        if cmd == "vault-open-race" { return await vaultOpenRaceStep(arg) }
        if cmd.hasPrefix("cred-") { return await credentialStep(cmd, arg) }
        if cmd.hasPrefix("login-") || cmd == "custom-set" { return await loginStep(cmd, arg) }
        if cmd.hasPrefix("bulk-") { return await bulkStep(cmd, arg) }
        if cmd.hasPrefix("deleted") { return await deletedStep(cmd, arg) }
        if cmd.hasPrefix("restore-"), cmd != "restore-plan" { return await restoreStep(cmd, arg) }
        if cmd.hasPrefix("provider-") { return await providerStep(cmd, arg) }
        if cmd.hasPrefix("doc-") { return await documentStep(cmd, arg) }
        if cmd.hasPrefix("dash-") { return await dashboardStep(cmd, arg) }
        if cmd.hasPrefix("audit-") { if await auditStep(cmd, arg) { return } }
        if cmd.hasPrefix("plugins-") || cmd.hasPrefix("plugin-entry-") || cmd.hasPrefix("plugin-") || cmd.hasPrefix("sql-") { if await pluginsStep(cmd, arg) { return } }
        if cmd.hasPrefix("pg-") { if await postgresStep(cmd, arg) { return } }
        if cmd.hasPrefix("transcript-") || cmd.hasPrefix("diag-") { if await transcriptStep(cmd, arg) { return } }
        if cmd.hasPrefix("contrast-"), contrastStep(cmd, arg) { return }
        if cmd == "chrome-tones" { _ = await chromeTonesStep(arg); return }
        if cmd == "chrome-tones-windows" { await chromeTonesWindowsStep(arg); return }
        if cmd == "colour-match" { return await colourMatchStep() }
        if cmd.hasPrefix("activity-") { if await activityStep(cmd, arg) { return } }
        switch cmd {
        case "rdp-nla":
            // Codex R05: whether an RDP connect requires NLA, for a connection setting of `arg` (0/1).
            write("RDP-NLA connection=\(arg) -> \(RdpNla.required(connection: arg == "1"))")
        case "click", "doubleclick", "cmdclick":
            guard let row = row(named: arg) else { return write("FAIL \(line): no row") }
            // Quiet runs (accessory, never activated) leave the window non-key, and NSTableView
            // ignores a mouse-down on a non-key window. Select through the outline instead (the
            // selection notifications and double action run as for a click); foreground runs click.
            if let outline, window?.isKeyWindow == false, QuietLaunch.isOn {
                return await quietClick(cmd, line, row: row, outline: outline)
            }
            click(row: row, count: cmd == "doubleclick" ? 2 : 1, flags: cmd == "cmdclick" ? .command : [])
            await settle()
            // The first event to an inactive window can be taken as activation only: try once more.
            if cmd == "click" && !selectedNames().split(separator: ",").contains(Substring(arg)) {
                click(row: row, count: 1, flags: [])
                await settle()
            }
            // Q12: a click (not a modifier click) must leave its row selected, or the step fails.
            let hit = cmd != "click" || selectedNames().split(separator: ",").contains(Substring(arg))
            write("\(hit ? "" : "FAIL ")\(line) -> selected \(selectedNames())")
        case "select":
            // Select a row through the outline (selection notifications run as for a click); for when
            // the app cannot become active and mouse events only try to activate the window.
            guard let row = row(named: arg), let outline else { return write("FAIL \(line): no row") }
            outline.window?.makeFirstResponder(outline)
            outline.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
            await settle()
            let hit = selectedNames().split(separator: ",").contains(Substring(arg))
            write("\(hit ? "" : "FAIL ")\(line) -> selected \(selectedNames())")
        case "key":
            key(arg)
            await settle()
            write("\(line) -> selected \(selectedNames())")
        case "type":
            for ch in arg { sendKey(String(ch), keyCode: 0, flags: []) }
            await settle(0.1)
            write(line)
        case "menu":
            await menu(arg)
        case "alert":
            await settle(0.3)
            // The alert sheets on the key window, which under quiet launches (app not active) may
            // not be the main window; an app-modal alert has no parent at all.
            let sheets = ([window?.attachedSheet, NSApp.modalWindow] + NSApp.windows.map(\.attachedSheet) + Self.sheetPresentationWindows.map { Optional($0) }).compactMap { $0 }
                + NSApp.windows.filter { $0.isVisible && $0.isSheet == false && $0.level >= .modalPanel }
                + NSApp.windows.filter { $0.isVisible && String(describing: type(of: $0)).contains("Alert") }
            guard let button = sheets.lazy.compactMap({ $0.contentView?.allSubviews(of: NSButton.self).first { $0.title == arg } }).first else {
                // SDK 27: SwiftUI alert buttons are no NSButtons. An accessibility button with that title, else
                // Escape for Cancel (the alert's cancel role answers it).
                if let ax = sheets.lazy.compactMap({ Self.axButton(titled: arg, in: $0) }).first, ax.accessibilityPerformPress() {
                    await settle(0.4)
                    return write(line + " (ax)")
                }
                if arg == "Cancel", let sheet = sheets.first {
                    await pressKey("\u{1b}", in: sheet)
                    await settle(0.4)
                    return write(line + " (key)")
                }
                let shown = sheets.map { w in (w.contentView?.allSubviews(of: NSTextField.self).map(\.stringValue) ?? []) + (w.contentView?.allSubviews(of: NSButton.self).map { "[\($0.title)]" } ?? []) }
                return write("FAIL \(line): no sheet button (windows: \(NSApp.windows.filter(\.isVisible).map { "\(type(of: $0)):\($0.title)" }.joined(separator: ",")); shown: \(shown))")
            }
            button.performClick(nil)
            await settle(0.4)
            write(line)
        case "drag":
            drag(arg)
            await settle(0.4)
        case "filter":
            let t0 = CFAbsoluteTimeGetCurrent()
            guard setFilter(arg) else { return write("FAIL filter: no field") }
            await Task.yield()
            outline?.layoutSubtreeIfNeeded()
            write(String(format: "%@ -> %d visible rows, %.1f ms", line, outline?.numberOfRows ?? -1, (CFAbsoluteTimeGetCurrent() - t0) * 1000))
            await settle(0.2)
        case "dump":
            write("TREE\n" + dump())
        case "capture":
            guard let w = window else { return write("FAIL capture \(arg): no main window") }
            await settle(0.2)
            await capture(w, arg)
        case "setting":
            // `setting <id> <value>`: through the same model the Settings controls bind to.
            guard let sv = UIDriver.services else { return write("FAIL setting: no services") }
            let p = arg.split(separator: " ", maxSplits: 1).map(String.init)
            guard p.count == 2 else { return write("FAIL setting: need id and value") }
            let ok = sv.settings.set(p[0], p[1])
            write("SETTING \(p[0]) = \(sv.settings.value(p[0]))\(ok ? "" : " (rejected: \(sv.settings.error ?? "?"))")")
            sv.settings.error = nil
            await settle(0.3)
        case "setting-get":
            guard let sv = UIDriver.services else { return write("FAIL setting-get") }
            write("SETTING \(arg) = \(sv.settings.value(arg))")
        case "test-vault":
            // A vault with an in-memory key in the throwaway library: never a Keychain item.
            guard let sv = UIDriver.services else { return write("FAIL test-vault") }
            sv.credentials.openEphemeralForTest(sessions: sv.sessions)
            write("VAULT \(vaultState())")
        case "vault-add":
            // `vault-add <name>|<username>|<folder or ->`: a password credential in the open vault
            // (synthetic test value), for Credential Manager captures.
            guard let sv = UIDriver.services else { return write("FAIL vault-add") }
            let p = arg.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard p.count == 3 else { return write("FAIL vault-add: needs <name>|<username>|<folder>") }
            let ok = sv.credentials.mutate { _ = try $0.savePassword(id: nil, name: p[0], folder: p[2] == "-" ? nil : p[2], username: p[1], password: "test-\(p[0])") }
            write(ok ? "VAULT-ADD \(p[0])" : "FAIL vault-add: \(sv.credentials.error ?? "")")
        case "inline-set-test":
            // `inline-set-test <connection>|<username>`: the connection's inline login with the synthetic password
            // `test-<connection>` (B13 suite). Never a real secret.
            let p = arg.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard p.count == 2, let c = nodeId(named: p[0]), let vault = UIDriver.services?.credentials.vault else { return write("FAIL inline-set-test \(arg)") }
            do { try vault.setInlinePassword(connectionId: c, username: p[1], password: "test-\(p[0])"); write("INLINE-SET \(p[0])") }
            catch { write("FAIL inline-set-test \(p[0]): \(error)") }
        case "w8-draft":
            // `w8-draft <connection>`: Properties › Credentials as the editor loads it (W8): the inline
            // username starts from the connection's user; a typed password is saved with that username
            // and the username reads back unchanged. The password is a synthetic test value.
            guard let sv = UIDriver.services, let lib = commands.model.library, let c = nodeId(named: arg),
                  let list = try? lib.propertyValues(id: c) else { return write("FAIL w8-draft \(arg)") }
            let values = Dictionary(list.map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })
            let kind = commands.model.connection(id: c)?.inlineCredential
            let user = kind == nil ? nil : (try? sv.credentials.vault?.inlineFor(connectionId: c))??.username
            let draft = CredentialDraft()
            draft.load(values: values, inlineKind: kind, inlineUser: user)
            let before = draft.username
            draft.mode = .inline; draft.tab = .credential; draft.password = "test-w8"; draft.touch()
            let err = draft.saveInline(connectionId: c, library: lib, credentials: sv.credentials)
            let after = (try? sv.credentials.vault?.inlineFor(connectionId: c))??.username ?? "-"
            let ok = err == nil && !before.isEmpty && after == before
            write("\(ok ? "" : "FAIL ")W8-DRAFT \(arg) prefill=\(before.isEmpty ? "-" : before) saved=\(after)\(err.map { " error=\($0)" } ?? "")")
        case "inline-set-file":
            // `inline-set-file <connection>|<username>|<file>`: the connection's inline login, the password read from a
            // throwaway file (B7-LIVE). The value is never logged.
            let p = arg.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard p.count == 3, let c = nodeId(named: p[0]), let vault = UIDriver.services?.credentials.vault,
                  let pw = try? String(contentsOfFile: p[2], encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines), !pw.isEmpty
            else { return write("FAIL inline-set-file \(p.first ?? "")") }
            do {
                try vault.setInlinePassword(connectionId: c, username: p[1], password: pw)
                write("INLINE-SET \(p[0])")
            } catch { write("FAIL inline-set-file \(p[0]): \(error)") }
        case "idle":
            // Run the auto-lock check as if the user had been idle this many seconds.
            guard let sv = UIDriver.services else { return write("FAIL idle") }
            let locked = sv.autoLock.check(idleSeconds: UInt64(arg) ?? 0)
            write("IDLE \(arg)s auto-lock=\(sv.settings.value("security.auto-lock")) -> \(locked ? "locked" : "not locked"); VAULT \(vaultState())")
        case "local-shell":
            guard let sv = UIDriver.services else { return write("FAIL local-shell") }
            let renders = RenderCount.counts, items = toolbarItemObjects()
            sv.sessions.openLocal()
            await settle(1.0)
            // Which views re-rendered for the new tab (MAC-STALLS): the toolbar's must not.
            write("SHELL tabs=\(sv.sessions.tabs.count) renders \(RenderCount.delta(since: renders)); toolbar items replaced \(items.subtracting(toolbarItemObjects()).count)")
        case "terminal-font":
            // Font size and grid of the visible terminal view (proves `terminal.font-size` applies live).
            guard let v = window?.contentView?.firstSubview(of: TerminalNSView.self) else { return write("FAIL terminal-font: no terminal") }
            write(String(format: "TERMINAL font=%.0fpt grid=%@ frame=%.0fx%.0f", v.fontSize, v.gridDescription, v.frame.width, v.frame.height))
        case "term-state":
            // Font, zoom, cursor, bell and close bookkeeping of the focused terminal and its tab.
            guard let sv = UIDriver.services, let tab = sv.sessions.selectedTab, let v = focusedTerminalView() else { return write("FAIL term-state") }
            write(String(format: "TERM-STATE family=%@ size=%.0fpt ligatures=%@ zoom=%d grid=%@ cursor=%@ bell=%@ bells=%d copy-on-select=%@ panes=%d tabs=%d confirms=%d url=%@ selection=%d search=%@",
                         v.fontFamily, v.fontSize, v.fontChoice.ligatures ? "on" : "off", tab.zoom, v.gridDescription, v.cursorStyle, v.bellStyle,
                         v.bellCount, v.copyOnSelect ? "on" : "off", tab.panes.count, sv.sessions.tabs.count, sv.sessions.closeConfirmations,
                         v.lastOpenedURL ?? "-", v.terminal.selectionText()?.count ?? 0, sv.sessions.searchStatus ?? (sv.sessions.searching ? "open" : "closed")))
        case "term-run":
            // `term-run <command>`: types a command line into the focused terminal and presses Return.
            guard let t = UIDriver.services?.sessions.selectedTab?.terminal else { return write("FAIL \(line)") }
            try? t.write(bytes: Data((arg + "\r").utf8))
            await settle(0.5)
            write("TERM-RUN \(arg)")
        case "term-cmdclick":
            // `term-cmdclick <row> <col>`: ⌘-click a cell; the URL is resolved but no browser opens.
            let p = arg.split(separator: " ").compactMap { Int($0) }
            guard p.count == 2, let v = focusedTerminalView() else { return write("FAIL \(line)") }
            v.openURLs = false
            let at = v.windowPoint(row: p[0], col: p[1])
            for type in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
                if let e = NSEvent.mouseEvent(with: type, location: at, modifierFlags: .command, timestamp: ProcessInfo.processInfo.systemUptime,
                                              windowNumber: v.window?.windowNumber ?? 0, context: nil, eventNumber: 0, clickCount: 1, pressure: 1) {
                    type == .leftMouseDown ? v.mouseDown(with: e) : v.mouseUp(with: e)
                }
            }
            await settle(0.2)
            write("TERM-CMDCLICK \(p[0]),\(p[1]) -> \(v.lastOpenedURL ?? "none")")
        case "term-find":
            // `term-find <query>`: the find bar's query, as typed.
            guard let sv = UIDriver.services else { return write("FAIL term-find") }
            sv.sessions.searchQuery = arg
            await settle(0.2)
            write("TERM-FIND \(arg)")
        case "term-find-option":
            // `term-find-option case|regex on|off`: the find bar's toggles; reports the status after the search.
            let p = arg.split(separator: " ")
            guard let sv = UIDriver.services, p.count == 2 else { return write("FAIL \(line)") }
            if p[0] == "case" { sv.sessions.searchMatchCase = p[1] == "on" } else { sv.sessions.searchRegex = p[1] == "on" }
            await settle(0.3)
            write("TERM-FIND-OPTION \(arg) -> \(sv.sessions.searchStatus ?? "-")")
        case "term-scroll-key":
            // `term-scroll-key shift+pageup|cmd+pageup|cmd+home|cmd+end|cmd+up|cmd+down`: a scrollback key into the
            // focused terminal; reports the top row's text so a scroll is visible.
            let keys: [String: (UInt16, NSEvent.ModifierFlags)] = [
                "shift+pageup": (ScrollKeys.pageUp, .shift), "shift+pagedown": (ScrollKeys.pageDown, .shift),
                "cmd+pageup": (ScrollKeys.pageUp, .command), "cmd+home": (ScrollKeys.home, .command),
                "cmd+end": (ScrollKeys.end, .command), "cmd+up": (ScrollKeys.up, .command), "cmd+down": (ScrollKeys.down, .command)]
            guard let key = keys[arg], let v = focusedTerminalView(), let window = v.window,
                  let e = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: key.1, timestamp: ProcessInfo.processInfo.systemUptime,
                                           windowNumber: window.windowNumber, context: nil, characters: "", charactersIgnoringModifiers: "",
                                           isARepeat: false, keyCode: key.0) else { return write("FAIL \(line)") }
            v.keyDown(with: e)
            await settle(0.3)
            write("TERM-SCROLL-KEY \(arg) -> top row \"\(Self.screenText(v.terminal).split(separator: "\n", omittingEmptySubsequences: false).first.map { $0.trimmingCharacters(in: .whitespaces) } ?? "")\"")
        case "close-answer":
            // `close-answer yes|no|ask`: how the close confirmation answers (ask shows the alert).
            UIDriver.services?.sessions.scriptedCloseAnswer = arg == "ask" ? nil : arg == "yes"
            write("CLOSE-ANSWER \(arg)")
        case "term-select-all":
            guard let v = focusedTerminalView() else { return write("FAIL term-select-all") }
            v.selectAll(nil)
            await settle(0.2)
            write("TERM-SELECT-ALL \(v.terminal.selectionText()?.count ?? 0) characters")
        case "launch-update-check":
            write("UPDATE-CHECK \(UpdateChecker.lastLaunchReport ?? "none")")
        case "settings-open":
            // Settings window latency: from the menu command to a laid-out, displayed window.
            guard let sv = UIDriver.services else { return write("FAIL settings-open") }
            let t0 = CFAbsoluteTimeGetCurrent()
            sv.router.open("settings")
            var w: NSWindow?
            for _ in 0..<200 where w == nil {
                w = findWindow("settings")
                if w == nil { try? await Task.sleep(for: .milliseconds(5)) }
            }
            w?.contentView?.layoutSubtreeIfNeeded()
            w?.displayIfNeeded()
            write(String(format: "MEASURE settings-open %.1f ms (%@)", (CFAbsoluteTimeGetCurrent() - t0) * 1000, w?.title ?? "no window"))
            await settle(0.5)
        case "window-search":
            // Type into the search field of the window titled `<title>|<text>`.
            let p = arg.split(separator: "|", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            guard p.count == 2, let w = findWindow(p[0]),
                  let field = (w.contentView?.superview ?? w.contentView)?.allSubviews(of: NSSearchField.self).first else {
                return write("FAIL window-search \(arg)")
            }
            w.makeKeyAndOrderFront(nil)
            field.stringValue = p[1]
            field.delegate?.controlTextDidChange?(Notification(name: NSControl.textDidChangeNotification, object: field))
            await settle(0.4)
            write("SEARCH \(p[0]): \(p[1])")
        case "settings-category":
            // `settings-category appearance`: show one Settings page (the window must be open).
            guard let sv = UIDriver.services else { return write("FAIL settings-category") }
            sv.settings.pendingCategory = arg
            await settle(0.6)
            write("SETTINGS-CATEGORY \(arg)")
        case "reconnecting-card":
            // The connect sheet's "Reconnecting…" card on its own, at the sheet's width, for fit and captures.
            guard let window else { return write("FAIL reconnecting-card: no window") }
            let host = NSHostingController(rootView: ReconnectingCard(name: arg.isEmpty ? "proxied-sshd" : arg, reconnect: true) {}
                .frame(width: 440, height: 160).uiZoomRoot())
            window.beginSheet(NSWindow(contentViewController: host), completionHandler: nil)
            await settle(0.5)
            write("RECONNECTING-CARD shown")
        case "add-connection":
            // `add-connection telnet`: the Add Connection sheet with that type chosen, as the Add menu opens it (B7).
            commands.addConnection = ParentTarget(id: nil, protocolName: arg.isEmpty ? "ssh" : arg)
            await settle(0.8)
            write("ADD-CONNECTION \(arg) \(UIProbe.frames[Self.newConnectionProbe] == nil ? "no form" : "form shown")")
        case "link-bar":
            // `link-bar telnet`: the bar under a Telnet terminal after a drop, in a sheet at terminal
            // width, without a server (B7 layout fit).
            guard let window else { return write("FAIL link-bar: no window") }
            let host = NSHostingController(rootView: RemoteLinkBarContent(serial: nil, lost: "Connection lost")
                .frame(width: max(320, window.frame.width - 80)).uiZoomRoot())
            window.beginSheet(NSWindow(contentViewController: host), completionHandler: nil)
            await settle(0.5)
            write("LINK-BAR \(arg) shown")
        case "link-bar-close":
            guard let window, let sheet = window.attachedSheet else { return write("FAIL link-bar-close: no sheet") }
            window.endSheet(sheet)
            await settle(0.3)
            write("LINK-BAR closed")
        case "reconnecting-card-close":
            guard let window, let sheet = window.attachedSheet else { return write("FAIL reconnecting-card-close: no sheet") }
            window.endSheet(sheet)
            await settle(0.3)
            write("RECONNECTING-CARD closed")
        case "settings-link":
            // `settings-link <filter>`: filter Settings to one link row, click its button (the
            // lowest SwiftUI button), then report what is in front of the Settings window.
            guard let sv = UIDriver.services, let w = findWindow("settings") else { return write("FAIL settings-link: no Settings window") }
            if w.attachedSheet != nil { sv.settings.pendingSheet = nil; await settle(0.6) }
            sv.settings.pendingQuery = arg
            await settle(0.6)
            // SwiftUI draws Form link rows without an AppKit button: click the first row of the
            // filtered detail pane with a real mouse down and up.
            guard let pane = (w.contentView?.superview ?? w.contentView)?.allSubviews(of: NSView.self)
                .first(where: { String(describing: type(of: $0)).contains("ContainerStyleContext") }) else {
                return write("FAIL settings-link \(arg): no detail pane")
            }
            let r = pane.convert(pane.bounds, to: nil)
            let at = NSPoint(x: r.midX, y: r.maxY - 100)
            for type in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
                if let e = NSEvent.mouseEvent(with: type, location: at, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                              windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1) {
                    NSApp.sendEvent(e)
                }
                await settle(0.05)
            }
            await settle(1.0)
            let front = NSApp.orderedWindows.first { $0.isVisible }
            write("SETTINGS-LINK \(arg) -> settings sheet \(w.attachedSheet != nil ? "shown" : "none"), front window \(front?.title ?? "-"), key \(NSApp.keyWindow?.title ?? "-")")
        case "capture-window":
            // `capture-window <title>|<name>`: any visible window by title.
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            guard p.count == 2, let w = findWindow(p[0]) else {
                return write("FAIL capture-window \(arg)")
            }
            w.makeKeyAndOrderFront(nil)
            await settle(0.3)
            await capture(w, p[1])
        case "agent-add", "agent-remove-all", "agent-status":
            // `agent-add <key file>` (test key), `agent-remove-all`, `agent-status`: the SSH Agent sheet's calls.
            let a = AgentKeysModel.shared
            if cmd == "agent-add", !(await a.add(arg, passphrase: nil)) { return write("FAIL agent-add: \(a.error ?? "")") }
            if cmd == "agent-remove-all" { a.stop() }
            write("AGENT running=\(a.status.running) keys=\(a.status.keys.map { String($0.fingerprint.prefix(13)) }.joined(separator: ","))")
        case "key-tool":
            // `key-tool <generate|inspect|convert> <source|-> <target|-> [comment]`: SSH Agent › Keys sheet, filled
            // in and run once (needs the SSH Agent panel open). Checks the written files: 0600 private, .pub beside.
            let p = arg.split(separator: " ", maxSplits: 3).map(String.init)
            guard p.count >= 3, let mode = KeyToolMode(rawValue: p[0]) else { return write("FAIL \(line): usage") }
            let a = AgentKeysModel.shared
            a.driverKeyToolResult = nil
            a.driverKeyTool = KeyToolRequest(mode: mode, source: p[1] == "-" ? "" : p[1], target: p[2] == "-" ? "" : p[2], comment: p.count > 3 ? p[3] : "")
            for _ in 0..<40 where a.driverKeyToolResult == nil { await settle(0.1) }
            guard let r = a.driverKeyToolResult else { return write("FAIL \(line): the sheet did not run") }
            var files = ""
            if mode != .inspect, p[2] != "-" {
                let perms = (try? FileManager.default.attributesOfItem(atPath: p[2])[.posixPermissions] as? Int) ?? -1
                files = " private=\(String(perms, radix: 8)) pub=\(FileManager.default.fileExists(atPath: p[2] + ".pub"))"
            }
            write("KEYTOOL \(mode.rawValue) \(r)\(files)")
        case "open-window":
            // `open-window credentials-local|credentials-vaultwarden` through the app's own command.
            guard let sv = UIDriver.services else { return write("FAIL open-window") }
            let source = CredentialSource(rawValue: String(arg.dropFirst("credentials-".count))) ?? .local
            sv.credentials.source = source
            commands.model.scriptedSheet = nil
            commands.model.scriptedSheet = source == .local ? "credentials" : "credentials-\(source.rawValue)"
            await settle(0.8)
            write("WINDOWS \(NSApp.windows.filter(\.isVisible).map { "\($0.title) [\($0.identifier?.rawValue ?? "-")]" }.joined(separator: ", "))")
        case "timed-appearance":
            // Theme switch latency: setting change until every window shows the new appearance.
            guard let sv = UIDriver.services else { return write("FAIL timed-appearance") }
            let target: NSAppearance.Name = arg == "light" ? .aqua : .darkAqua
            let t0 = CFAbsoluteTimeGetCurrent()
            sv.settings.set("appearance.mode", arg)
            for _ in 0..<400 where NSApp.windows.contains(where: { $0.isVisible && $0.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) != target }) {
                await Task.yield()
                try? await Task.sleep(for: .milliseconds(1))
            }
            for w in NSApp.windows where w.isVisible { w.contentView?.layoutSubtreeIfNeeded(); w.displayIfNeeded() }
            write(String(format: "MEASURE theme-switch-%@ %.1f ms (%d windows)", arg, (CFAbsoluteTimeGetCurrent() - t0) * 1000, NSApp.windows.filter(\.isVisible).count))
            await settle(0.3)
        case "timed-resize":
            // `timed-resize 1200x800`: main window frame change including layout and display.
            // `timed-resize screen`: the screen's visible area (owner 2026-11-15: suites run once, light,
            // window at screen size), without a full-screen Space so the launch stays in the background.
            let d = arg.split(separator: "x").compactMap { Double($0) }
            guard let window, d.count == 2 || (arg == "screen" && window.screen != nil) else { return write("FAIL timed-resize") }
            let t0 = CFAbsoluteTimeGetCurrent()
            if arg == "screen", let visible = window.screen?.visibleFrame {
                window.setFrame(visible, display: true)
            } else {
                window.setFrame(NSRect(x: window.frame.minX, y: window.frame.maxY - d[1], width: d[0], height: d[1]), display: true)
            }
            window.contentView?.layoutSubtreeIfNeeded()
            window.displayIfNeeded()
            write(String(format: "MEASURE resize-%@ %.1f ms", arg, (CFAbsoluteTimeGetCurrent() - t0) * 1000))
            await settle(0.3)
        case "window-field":
            // `window-field <title>|<placeholder>|<text>`: type into a text field found by its placeholder.
            let p = arg.split(separator: "|", maxSplits: 2).map(String.init)
            guard p.count == 3, let w = findWindow(p[0]) else { return write("FAIL window-field \(arg): no window") }
            let fields = w.contentView?.superview?.allSubviews(of: NSTextField.self) ?? []
            guard let field = fields.first(where: { Self.placeholder(of: $0) == p[1] }) else {
                let seen = fields.map { "\(type(of: $0))[\(Self.placeholder(of: $0) ?? "-")]" }.joined(separator: ", ")
                return write("FAIL window-field \(arg); fields: \(seen)")
            }
            w.makeKeyAndOrderFront(nil)
            w.makeFirstResponder(field)
            field.stringValue = p[2]
            field.currentEditor()?.string = p[2]
            NotificationCenter.default.post(name: NSControl.textDidChangeNotification, object: field)
            field.delegate?.controlTextDidChange?(Notification(name: NSControl.textDidChangeNotification, object: field))
            await settle(0.3)
            write("FIELD \(p[1]) = \(p[2])")
        case "window-button":
            // `window-button <title>|<button title>`: click an AppKit-backed button by its title.
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            guard p.count == 2, let w = findWindow(p[0]),
                  let b = w.contentView?.allSubviews(of: NSButton.self).first(where: { $0.title == p[1] }) else {
                return write("FAIL window-button \(arg)")
            }
            b.performClick(nil)
            await settle(0.5)
            write("BUTTON \(p[1])")
        case "window-row":
            // `window-row <window>|<index>`: real mouse click on a row of that window's first table
            // (the Settings and Credentials sidebars; `sheet` is the topmost sheet, e.g. the property dialog).
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            guard p.count == 2, let w = p[0] == "sheet" ? topSheet : findWindow(p[0]),
                  let table = w.contentView?.allSubviews(of: NSTableView.self).first else {
                return write("FAIL window-row \(arg)")
            }
            // A row index, or the title shown in the row.
            let titles = (0..<table.numberOfRows).map { r in
                (table.rowView(atRow: r, makeIfNecessary: true)?.allSubviews(of: NSTextField.self).map(\.stringValue) ?? []).joined(separator: " ")
            }
            guard let index = Int(p[1]) ?? titles.firstIndex(where: { $0.hasPrefix(p[1]) }), index < table.numberOfRows else {
                return write("FAIL window-row \(arg): rows \(titles)")
            }
            if p[0] != "sheet" { w.makeKeyAndOrderFront(nil) }
            await settle(0.2)
            let rect = table.rect(ofRow: index)
            let point = table.convert(NSPoint(x: rect.midX, y: rect.midY), to: nil)
            let up = NSEvent.mouseEvent(with: .leftMouseUp, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                        windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 0)!
            let down = NSEvent.mouseEvent(with: .leftMouseDown, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                          windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)!
            let upEvent = UncheckedEvent(event: up)
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.03) { NSApp.postEvent(upEvent.event, atStart: false) }
            w.sendEvent(down)
            await settle(0.6)
            // A sheet's SwiftUI sidebar ignores the posted click; select the row as the table would.
            if table.selectedRow != index {
                table.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
                await settle(0.4)
            }
            write("ROW \(p[0]) \(index) -> \(w.title); table selected \(table.selectedRow) of \(table.numberOfRows); responder \(w.firstResponder.map { String(describing: type(of: $0)) } ?? "-")")
        case "window-key":
            // `window-key <window>|return`: a key press delivered to that window's first responder.
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            guard p.count == 2, let w = findWindow(p[0]), let known = Self.keyCodes[p[1]] else { return write("FAIL window-key \(arg)") }
            w.makeKeyAndOrderFront(nil)
            let arrows: NSEvent.ModifierFlags = (123...126).contains(known.code) ? [.numericPad, .function] : []
            let e = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: arrows, timestamp: ProcessInfo.processInfo.systemUptime,
                                     windowNumber: w.windowNumber, context: nil, characters: known.chars,
                                     charactersIgnoringModifiers: known.chars, isARepeat: false, keyCode: known.code)!
            w.sendEvent(e)
            await settle(0.5)
            write("KEY \(p[0]) \(p[1]) -> \(w.title); table selected \(w.contentView?.allSubviews(of: NSTableView.self).first?.selectedRow ?? -9)")
        case "template-save":
            // `template-save <connection>`: Save as Template through the core, as the sheet's Save does (B9).
            // SwiftUI sheet buttons have no AppKit title, so `click Save` cannot reach them.
            guard let id = nodeId(named: arg), let library = commands.model.library else { return write("FAIL template-save \(arg): no connection") }
            do {
                _ = try library.saveAsTemplate(connectionId: id, name: "$Host$ console")
                commands.model.mutate { _ in }
                write("TEMPLATE-SAVE \(arg) templates=\(library.templates().count)")
            } catch { write("FAIL template-save \(arg): \(error)") }
        case "template-list":
            // The Templates list on its own (it also opens from New from Template's Templates… button).
            commands.showingTemplates = true
            await settle(0.6)
            write(line)
        case "template-expect":
            // `template-expect <name>|<host>`: the core holds a template with that name and host (B9-DONE).
            let p = arg.components(separatedBy: "|")
            let all = commands.model.library?.templates() ?? []
            let hit = p.count == 2 && all.contains { $0.name == p[0] && $0.host == p[1] }
            write("\(hit ? "" : "FAIL ")TEMPLATE-EXPECT \(arg) -> " + all.map { "\($0.name)|\($0.host)" }.joined(separator: ", "))
        case "node-host":
            // `node-host <connection>|<host>`: the tree's connection of that name has that host (B9-DONE).
            let p = arg.components(separatedBy: "|")
            func find(_ f: FolderView) -> ConnectionView? {
                f.connections.first { $0.name == p[0] } ?? f.folders.lazy.compactMap(find).first
            }
            let host = p.count == 2 ? commands.model.tree.flatMap(find)?.host : nil
            write("\(host == p.last ? "" : "FAIL ")NODE-HOST \(arg) -> \(host ?? "none")")
        case "ssh-sync-now":
            // The sources sheet's Sync Now action (the same handler its button runs): SwiftUI form buttons
            // are not reachable through AppKit or the accessibility tree in a quiet launch.
            await settle(0.4)
            NotificationCenter.default.post(name: SshSourcesView.syncNowNotification, object: nil)
            await settle(1.5)
            write("SSH-SYNC-NOW")
        case "ssh-state":
            // SSH-CONFIG-SYNC: every connection as `folder/name host port user fav status`, then the
            // sync preview (`changes=<n> synced=<yes|never>`), for the suite to compare line by line.
            func walk(_ f: FolderView, _ path: String) {
                for c in f.connections {
                    write("SSH-STATE \(path)/\(c.name) host=\(c.host) port=\(c.port.map(String.init) ?? "-") user=\(c.username ?? "-") fav=\(c.favorite) status=\(c.sourceStatus ?? "-")")
                }
                for sub in f.folders { walk(sub, path + "/" + sub.name) }
            }
            if let root = commands.model.tree { walk(root, "") }
            let ch = try? commands.model.workflow?.changes()
            write("SSH-STATE changes=\(ch?.hosts.count ?? -1) synced=\(ch?.lastSyncedSecs == nil ? "never" : "yes")")
        case "ssh-user-edit":
            // `ssh-user-edit <connection>`: the user stars the connection (an edit the file knows nothing about).
            func find(_ f: FolderView) -> ConnectionView? { f.connections.first { $0.name == arg } ?? f.folders.lazy.compactMap(find).first }
            guard let c = commands.model.tree.flatMap(find) else { return write("FAIL ssh-user-edit \(arg): no connection") }
            commands.model.mutate { try $0.setFavorite(id: c.id, favorite: true) }
            await settle(0.3)
            write("SSH-USER-EDIT \(arg)")
        case "ssh-user-move":
            // `ssh-user-move <connection>|<folder>`: drag-and-drop's core call, into a new top-level folder.
            let p = arg.components(separatedBy: "|")
            func find(_ f: FolderView) -> ConnectionView? { f.connections.first { $0.name == p[0] } ?? f.folders.lazy.compactMap(find).first }
            guard p.count == 2, let c = commands.model.tree.flatMap(find) else { return write("FAIL ssh-user-move \(arg)") }
            commands.model.mutate { lib in
                let folder = try lib.addFolder(parent: nil, name: p[1])
                try lib.moveNodeBefore(id: c.id, parent: folder, before: nil)
            }
            await settle(0.3)
            write("SSH-USER-MOVE \(arg)")
        case "template-new":
            // New from Template… at the library root, as the Add menu's "From Template…" row opens it (B9).
            commands.newFromTemplate = ParentTarget(id: nil)
            await settle(0.6)
            write(line)
        case "sheet":
            write("SHEET \(window?.attachedSheet.map { "\($0.title.isEmpty ? "untitled" : $0.title) \(Int($0.frame.width))x\(Int($0.frame.height))" } ?? "none")")
        case "close-window":
            findWindow(arg)?.close()
            await settle(0.3)
            write(line)
        case "appearance":
            // For this run only (not persisted): `dark`, `light`, or `system`.
            NSApp.appearance = ["dark": NSAppearance(named: .darkAqua), "light": NSAppearance(named: .aqua)][arg] ?? nil
            await settle(0.5)
            write(line)
        case "touch-env":
            // `touch-env <ENV_VAR>`: create the file that variable names (a test helper's switch).
            guard let path = ProcessInfo.processInfo.environment[arg], FileManager.default.createFile(atPath: path, contents: nil) else {
                return write("FAIL touch-env \(arg)")
            }
            write("TOUCH-ENV \(arg)")
        case "wait":
            await settle(Double(arg) ?? 1)
        case "quiet-check":
            // Quiet launch: accessory policy (no Dock icon), never active, a window still on screen.
            let accessory = NSApp.activationPolicy() == .accessory
            let onScreen = NSApp.windows.contains { $0.isVisible && $0.frame.width > 100 }
            let ok = accessory && !NSApp.isActive && onScreen
            write("\(ok ? "" : "FAIL ")QUIET policy=\(accessory ? "accessory" : "regular") active=\(NSApp.isActive) window=\(onScreen)")
        case "mark":
            mark = CFAbsoluteTimeGetCurrent()
            if !arg.isEmpty { write("MARK \(arg)") }
        case "windows":
            // Every app window (class, title, visible, level): when a sheet or popover check fails.
            write("WINDOWS active=\(NSApp.isActive) key=\(NSApp.keyWindow?.title ?? "-") " + NSApp.windows.map { "\(type(of: $0)):\($0.title)[\($0.isVisible ? "visible" : "hidden") level \($0.level.rawValue)]" }.joined(separator: ", "))
        case "measure":
            write(String(format: "MEASURE %@ %.1f ms", arg, (CFAbsoluteTimeGetCurrent() - mark) * 1000))
        case "frame-absent":
            // A probed view that must not be on screen (the docked file panel once popped out, the
            // tips line once turned off).
            await settle(0.3)
            let shown = UIProbe.frames[arg] != nil || window.flatMap { axFrame(label: arg, in: $0) } != nil
            write("\(shown ? "FAIL " : "")FRAME-ABSENT \(arg) \(shown ? "still shown" : "not shown")")
        case "frame":
            // Where a probed view (`.uiProbe(id)`) or accessibility element sits, from the toolbar's bottom edge.
            guard let window else { return write("FAIL frame \(arg)") }
            let toolbarHeight = window.frame.height - window.contentLayoutRect.height
            if let r = UIProbe.frames[arg] {
                // Add the AppKit content inset of the scroll view the probe sits in (SwiftUI geometry omits it).
                let scroll = window.contentView?.allSubviews(of: NSScrollView.self).last {
                    let x = $0.convert(NSPoint.zero, to: nil).x
                    return r.minX >= x - 1 && r.minX < x + $0.frame.width
                }
                let top = r.minY + (scroll?.contentInsets.top ?? 0) - toolbarHeight
                write(String(format: "FRAME %@ x=%.0f top-below-toolbar=%.0f w=%.0f h=%.0f (window %.0fx%.0f)", arg,
                             r.minX, top, r.width, r.height, window.frame.width, window.frame.height))
            } else if let r = axFrame(label: arg, in: window) {
                let toolbarBottom = window.frame.minY + window.contentLayoutRect.maxY
                write(String(format: "FRAME %@ x=%.0f top-below-toolbar=%.0f w=%.0f h=%.0f (window %.0fx%.0f)", arg,
                             r.minX - window.frame.minX, toolbarBottom - r.maxY, r.width, r.height, window.frame.width, window.frame.height))
            } else {
                write("FAIL frame \(arg)")
            }
            // AppKit content insets SwiftUI geometry cannot see (they shift scroll content further down).
            let insets = window.contentView?.allSubviews(of: NSScrollView.self)
                .map { String(format: "%.0f@x%.0f", $0.contentInsets.top, $0.convert(NSPoint.zero, to: nil).x) } ?? []
            write("FRAME scroll-insets " + insets.joined(separator: " "))
        case "timed-key":
            // Latency of one key press including the layout and display it causes.
            let t0 = CFAbsoluteTimeGetCurrent()
            key(arg)
            window?.contentView?.layoutSubtreeIfNeeded()
            window?.displayIfNeeded()
            write(String(format: "KEY %@ %.1f ms -> %d rows", arg, (CFAbsoluteTimeGetCurrent() - t0) * 1000, outline?.numberOfRows ?? -1))
            await settle(0.2)
        case "timed-menu":
            // Build the context menu and run one item, including the resulting layout and display.
            let t0 = CFAbsoluteTimeGetCurrent()
            await menu(arg, settleAfter: false)
            window?.contentView?.layoutSubtreeIfNeeded()
            window?.displayIfNeeded()
            write(String(format: "TIMED %@ %.1f ms -> %d rows", arg, (CFAbsoluteTimeGetCurrent() - t0) * 1000, outline?.numberOfRows ?? -1))
            await settle(0.3)
        case "bench-filter":
            // The code path the search field drives (filter → rebuild nodes → reload outline), timed.
            guard let c = outline?.coordinator else { return write("FAIL bench-filter") }
            let t0 = CFAbsoluteTimeGetCurrent()
            c.filter = arg
            c.reload(diff: true)
            let t1 = CFAbsoluteTimeGetCurrent()
            window?.contentView?.layoutSubtreeIfNeeded()
            let t2 = CFAbsoluteTimeGetCurrent()
            window?.displayIfNeeded()
            let t3 = CFAbsoluteTimeGetCurrent()
            write(String(format: "FILTER '%@' %.1f ms -> %d rows (build %.1f, data %.1f, data+expand %.1f, reload %.1f, layout %.1f, display %.1f)", arg, (t3 - t0) * 1000,
                         outline?.numberOfRows ?? -1, c.lastBuildMs, c.lastDataMs, c.lastExpandMs, (t1 - t0) * 1000, (t2 - t1) * 1000, (t3 - t2) * 1000))
            // The in-place patch must show exactly the rows a full rebuild shows. The check's own full
            // reload is not a user action: the stall watch skips it.
            let patched = visibleRowIds()
            StallWatch.shared.pause()
            c.reload()
            let rebuilt = visibleRowIds()
            StallWatch.shared.resume()
            if patched != rebuilt { write("FAIL bench-filter '\(arg)': patched \(patched.count) rows, rebuild \(rebuilt.count)") }
            await settle(0.2)
        case "time-select":
            await timeSelect(arg)
        case "page-fit":
            // The connection page's column sits at the session area's leading edge (MAC-PAGE-LEADING,
            // owner 2026-11-16; it was centred, owner point 22) and neither it nor Connect runs under
            // the full-screen inspector, which overlays the area's trailing edge.
            await settle(0.3)
            let f = UIProbe.frames
            guard let area = f["connection-page-area"], let content = f["connection-page-content"], let connect = f["connection-page-connect"] else {
                return write("FAIL page-fit: no connection page")
            }
            let overlay = FullScreenSimulation.shared.isOn && commands.tree.inspectorShown && !commands.tree.inspectorHiddenByWidth ? DS.Size.inspectorIdeal : 0
            let right = area.maxX - overlay
            let lead = content.minX - area.minX
            let ok = connect.maxX <= right + 0.5 && content.maxX <= right + 0.5 && lead >= -0.5 && lead <= Self.pageLeadTolerance
            write(String(format: "%@PAGE-FIT area %.0f-%.0f visible-right %.0f content %.0f-%.0f (lead %.1f) connect-right %.0f",
                         ok ? "" : "FAIL ", area.minX, area.maxX, right, content.minX, content.maxX, lead, connect.maxX))
        case "secret-pasteboard":
            // QA S1: a copied secret is concealed + transient, clears itself, and never clears a later copy.
            let pb = NSPasteboard(name: NSPasteboard.Name("bastion-ui-s1-\(UUID().uuidString)"))
            SecretPasteboard.copy("s1-secret", to: pb, lifetime: .milliseconds(500))
            let marked = pb.types?.contains(NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")) == true
                && pb.types?.contains(NSPasteboard.PasteboardType("org.nspasteboard.TransientType")) == true
            await settle(1.0)
            let cleared = pb.string(forType: .string) == nil
            SecretPasteboard.copy("s1-secret", to: pb, lifetime: .milliseconds(500))
            pb.clearContents(); pb.setString("user-copy", forType: .string)
            await settle(1.0)
            let kept = pb.string(forType: .string) == "user-copy"
            pb.releaseGlobally()
            write("\(marked && cleared && kept ? "" : "FAIL ")SECRET-PASTEBOARD marked=\(marked) cleared=\(cleared) later-copy-kept=\(kept)")
        case "forget-login":
            // `forget-login <row>`: drop the login kept for this run only, as a relaunch does.
            guard let sv = UIDriver.services, let r = row(named: arg), let n = outline?.item(atRow: r) as? OutlineNode,
                  case .connection(let c) = n.kind else { return write("FAIL forget-login \(arg)") }
            sv.credentials.forgetLastLogin(for: c.id)
            write("FORGET-LOGIN \(arg)")
        case "timed-connect":
            await timedConnect(arg)
        case "clipboard":
            write("CLIPBOARD \(commands.pasteboard.string(forType: .string) ?? "<empty>")")
        case "clipboard-set":
            // `clipboard-set <text>`: as if the user copied <text> on this Mac (the driver's private pasteboard).
            commands.pasteboard.clearContents()
            commands.pasteboard.setString(arg, forType: .string)
            await settle(0.5)
            write("CLIPBOARD-SET \(arg)")
        case "clipboard-expect":
            // `clipboard-expect <seconds>|<text>`: until the pasteboard holds <text> (copied on the server).
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            guard p.count == 2 else { return write("FAIL clipboard-expect") }
            let deadline = CFAbsoluteTimeGetCurrent() + (Double(p[0]) ?? 15)
            while commands.pasteboard.string(forType: .string) != p[1] && CFAbsoluteTimeGetCurrent() < deadline { await settle(0.25) }
            let now = commands.pasteboard.string(forType: .string) ?? "<empty>"
            write(now == p[1] ? "CLIPBOARD-EXPECT ok: \(now)" : "FAIL clipboard-expect: \(now)")
        case "desktop-ended":
            // `desktop-ended <seconds>`: until the selected desktop tab shows its Disconnected overlay.
            guard let sv = UIDriver.services, let tab = sv.sessions.selectedTab else { return write("FAIL desktop-ended") }
            let deadline = CFAbsoluteTimeGetCurrent() + (Double(arg) ?? 20)
            while tab.desktopCloseReason == nil && CFAbsoluteTimeGetCurrent() < deadline { await settle(0.3) }
            write(tab.desktopCloseReason.map { "DESKTOP-ENDED \(tab.name): \($0)" } ?? "FAIL desktop-ended: still running")
        case "desktop-reconnect":
            // The overlay's Reconnect button.
            guard let sv = UIDriver.services, let id = sv.sessions.selectedTab?.connectionId else { return write("FAIL desktop-reconnect") }
            sv.sessions.reconnectRequest = id
            await settle(1.0)
            write("DESKTOP-RECONNECT \(id) tabs=\(sv.sessions.tabs.count)")
        case "rdp-state":
            guard let tab = UIDriver.services?.sessions.selectedTab, case .rdp(let r) = tab.content else { return write("FAIL rdp-state: no RDP tab") }
            write("RDP-STATE state=\(r.state()) clipboard=\(r.sharesClipboard()) audioBytes=\(r.audioBytes())")
        case "crash":
            // Spec §1: end like a crash or force-quit (no willTerminate, so no clean-quit mark).
            // Open-session saves run on a queue: the steps before this one expect theirs on disk.
            SessionRestore.waitForSaves()
            write("CRASH")
            flush(wait: true)
            exit(0)
        case "restore-plan":
            let p = SessionRestore.shared.lastPlan
            write("RESTORE-PLAN " + (p.map { "lastExit=\($0.lastExit) restore=\($0.restore) tabs=\($0.tabs.count) autoReconnect=\($0.autoReconnect) missing=\($0.missing)" } ?? "none"))
        case "quit-strict":
            // Like a real ⌘Q: terminate and nothing else (no sheet closing, no forced exit). The suite's limit
            // decides: run.sh prints "exited" when the app quit by itself, "killed after limit" when it did not.
            write("QUIT-STRICT inspector=\(commands.tree.inspectorPresented ? "on" : "off") windows=\(NSApp.windows.filter(\.isVisible).count)")
            flush(wait: true)
            NSApp.terminate(nil)
        case "quit":
            commands.pasteboard.releaseGlobally()
            writeActivation()
            flush(wait: true)
            // AppKit refuses terminate while some sheets are attached (an RDP connect sheet left the
            // run holding the Mac lock): close them first, and exit outright if terminate is refused.
            for w in NSApp.windows { while let sheet = w.attachedSheet { w.endSheet(sheet) } }
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { exit(0) }
            NSApp.terminate(nil)
        case "toolbar":
            // Which toolbar items fit and which the window pushed into the » overflow menu.
            guard let toolbar = window?.toolbar else { return write("FAIL toolbar") }
            let visible = Set((toolbar.visibleItems ?? []).map(\.itemIdentifier))
            let named = toolbar.items.filter { !$0.label.isEmpty || !$0.paletteLabel.isEmpty }
            let label = { (i: NSToolbarItem) in i.label.isEmpty ? i.paletteLabel : i.label }
            write("TOOLBAR \(Int(window?.frame.width ?? 0))pt inspector \(commands.tree.inspectorShown ? "on" : "off") visible: \(named.filter { visible.contains($0.itemIdentifier) }.map(label).joined(separator: ", ")) | overflow: \(named.filter { !visible.contains($0.itemIdentifier) }.map(label).joined(separator: ", "))")
        case "clip-indicator":
            // The » button itself, in every window (full screen moves the toolbar into its own
            // window): `toolbar.visibleItems` said "none" while the owner saw » (round 4, item 16).
            var found: [String] = []
            func scan(_ v: NSView) {
                let name = String(describing: type(of: v))
                // AppKit's own » only; the inspector's "More actions" button (OverflowMenu) is ours.
                if name.contains("Clipped") || (name.hasPrefix("NS") && name.contains("Overflow")) {
                    let f = v.convert(v.bounds, to: nil)
                    var chain: [String] = [], a = v.superview
                    while let p = a, chain.count < 8 { chain.append(String(describing: type(of: p)).prefix(60).description); a = p.superview }
                    found.append("\(name) hidden=\(v.isHiddenOrHasHiddenAncestor) alpha=\(v.alphaValue) x=\(Int(f.minX)) y=\(Int(f.minY)) w=\(Int(f.width)) win=\(type(of: v.window!)) up=\(chain.joined(separator: "<"))")
                }
                v.subviews.forEach(scan)
            }
            for w in NSApp.windows { if let root = w.contentView?.superview { scan(root) } }
            var classes: [String: Int] = [:]
            func all(_ v: NSView) { let n = String(describing: type(of: v)); if n.contains("Toolbar") || n.contains("Clip") || n.contains("Chevron") { classes[n.prefix(50).description, default: 0] += v.isHiddenOrHasHiddenAncestor ? 0 : 1 }; v.subviews.forEach(all) }
            for w in NSApp.windows { if let root = w.contentView?.superview { all(root) } }
            found.append("WINDOWS[\(NSApp.windows.map { "\(type(of: $0)) vis=\($0.isVisible) \(Int($0.frame.minX)),\(Int($0.frame.minY)) \(Int($0.frame.width))x\(Int($0.frame.height))" }.joined(separator: " | "))]")
            found.append("CLASSES[\(classes.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " "))]")
            let shown = found.filter { $0.contains("hidden=false") && !$0.contains("w=0") }
            // What is in it: open it, read the menu, close it.
            var buttons: [NSButton] = []
            func btn(_ v: NSView) { if let b = v as? NSButton, String(describing: type(of: v)).hasPrefix("NS"), String(describing: type(of: v)).contains("Clipped") || String(describing: type(of: v)).contains("Overflow"), !v.isHiddenOrHasHiddenAncestor { buttons.append(b) }; v.subviews.forEach(btn) }
            for w in NSApp.windows { if let root = w.contentView?.superview { btn(root) } }
            if let b = buttons.first {
                final class Box: @unchecked Sendable { var titles: [String] = []; var menu: NSMenu? }
                let box = Box()
                let token = NotificationCenter.default.addObserver(forName: NSMenu.didBeginTrackingNotification, object: nil, queue: .main) { n in
                    guard let m = n.object as? NSMenu else { return }
                    box.titles = m.items.map { $0.isSeparatorItem ? "-" : $0.title }
                    box.menu = m; RunLoop.main.perform(inModes: [.eventTracking, .default]) { MainActor.assumeIsolated { box.menu?.cancelTracking() } }
                }
                b.performClick(nil)
                await settle(0.5)
                NotificationCenter.default.removeObserver(token)
                found.append("MENU[\(box.titles.joined(separator: "|"))] menuProp=\(b.menu?.items.map(\.title) ?? [])")
            }
            write("\(shown.isEmpty ? "" : "FAIL ")CLIP-INDICATOR shown=\(shown.count) all: \(found.joined(separator: "; "))")
        case "no-overflow":
            // Every toolbar item in the bar, none in the » menu: labelled or not (the library
            // picker is an unlabelled SwiftUI item; owner round 2 found it and the inspector in »).
            guard let hidden = overflowItems() else { return write("FAIL no-overflow: no toolbar") }
            write("\(hidden.isEmpty ? "" : "FAIL ")NO-OVERFLOW \(Int(window?.frame.width ?? 0))pt items=\(window?.toolbar?.items.count ?? 0) in »: \(hidden.isEmpty ? "none" : hidden.joined(separator: ", "))")
        case "overflow-watch":
            // `overflow-watch <route>|<ms>`: open the route, then check the » menu on every frame
            // (16 ms) for <ms>; FAIL on any frame with an item in it (owner round 4: a » flash while
            // the inspector opens or closes).
            let p = arg.components(separatedBy: "|")
            guard p.count == 2, let ms = Int(p[1]) else { return write("FAIL overflow-watch \(arg)") }
            guard let sv = UIDriver.services else { return write("FAIL overflow-watch: no services") }
            sv.router.open(p[0])
            var frames = 0, bad: [String] = []
            let clock = ContinuousClock(), end = clock.now + .milliseconds(ms)
            while clock.now < end {
                frames += 1
                if let h = overflowItems(), !h.isEmpty { bad.append("f\(frames):" + h.joined(separator: "+")) }
                try? await Task.sleep(for: .milliseconds(16))
            }
            write("\(bad.isEmpty ? "" : "FAIL ")OVERFLOW-WATCH \(p[0]) frames=\(frames) with »: \(bad.isEmpty ? "none" : bad.prefix(10).joined(separator: " "))")
        case "window-transition":
            // `window-transition zoom|miniaturize|fullscreen|restore-fullscreen|<ms>`: do the window change, then check the
            // » menu and the "old bar" candidates (native tab bar, extra title bar parts) on every frame for <ms>.
            // FAIL on any frame with an item in »; the other states are logged when they change.
            let p = arg.components(separatedBy: "|")
            guard p.count == 2, let ms = Int(p[1]), let w = window else { return write("FAIL window-transition \(arg)") }
            func state() -> String {
                "tabbed=\(w.tabbedWindows?.count ?? 0) tabBar=\(w.tabGroup?.isTabBarVisible == true ? "yes" : "no") toolbar=\(w.toolbar?.isVisible == true ? "yes" : "no") title=\(w.titleVisibility == .visible ? "visible" : "hidden") accessories=\(w.titlebarAccessoryViewControllers.count) full=\(w.styleMask.contains(.fullScreen) ? "yes" : "no")"
            }
            w.collectionBehavior.insert(.fullScreenPrimary)
            switch p[0] {
            case "zoom": w.zoom(nil)
            case "miniaturize": w.miniaturize(nil)
            case "fullscreen": if !w.styleMask.contains(.fullScreen) { w.toggleFullScreen(nil) }
            case "restore-fullscreen": if w.styleMask.contains(.fullScreen) { w.toggleFullScreen(nil) }
            case "deminiaturize": w.deminiaturize(nil)
            default: return write("FAIL window-transition: unknown \(p[0])")
            }
            var frames = 0, bad: [String] = [], states: [String] = [], last = "", badCount = 0, lastBad = 0
            let clock = ContinuousClock(), end = clock.now + .milliseconds(ms)
            while clock.now < end {
                frames += 1
                if let h = overflowItems(), !h.isEmpty {
                    badCount += 1; lastBad = frames
                    if bad.count < 3 {
                        // Name the item by what it holds: the hosting view's type, its controls' labels and its width.
                        let visible = Set((w.toolbar?.visibleItems ?? []).map(\.itemIdentifier))
                        let held = (w.toolbar?.items ?? []).filter { !visible.contains($0.itemIdentifier) && !$0.itemIdentifier.rawValue.contains("Separator") && $0.itemIdentifier != .flexibleSpace && $0.itemIdentifier != .space }
                            .map { item -> String in
                                let v = item.view
                                let labels = v?.allSubviews(of: NSControl.self).compactMap { $0.accessibilityLabel() }.filter { !$0.isEmpty }.prefix(3).joined(separator: "/") ?? "-"
                                return "\(v.map { String(describing: type(of: $0)) } ?? "nil")[\(labels)] w=\(Int(v?.frame.width ?? 0)) min=\(Int(item.minSize.width)) max=\(Int(item.maxSize.width))"
                            }
                        bad.append("f\(frames)@\(Int(w.frame.width)):" + held.joined(separator: " + "))
                    }
                }
                let now = state()
                if now != last { states.append("f\(frames) \(now)"); last = now }
                try? await Task.sleep(for: .milliseconds(8))
            }
            // One display refresh (16 ms, two 8 ms samples) is not visible: the toolbar lays out in the same run loop turn as the
            // window jump, one turn before the strip's new width lands. More than that is the » the owner saw.
            let visibleFlash = badCount > 2
            write("\(visibleFlash ? "FAIL " : "")WINDOW-TRANSITION \(p[0]) frames=\(frames) with »: \(bad.isEmpty ? "none" : "\(badCount) frames, last f\(lastBad), first " + bad.joined(separator: " ")) | states: \(states.joined(separator: "; "))")
        case "screen-video":
            // `screen-video <seconds>|<name>`: record the whole screen in the background (screencapture -v).
            let p = arg.components(separatedBy: "|")
            guard p.count == 2, let secs = Int(p[0]), CaptureCheck.isValidName(p[1]) else { return write("FAIL screen-video \(arg)") }
            let v = Process()
            v.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
            v.arguments = ["-x", "-v", "-V", String(secs), out.appendingPathComponent("\(p[1]).mov").path]
            do { try v.run() } catch { return write("FAIL screen-video: \(error)") }
            await settle(1.0)
            write("SCREEN-VIDEO \(p[1]) \(secs)s")
        case "toolbar-click":
            await toolbarClick(arg)
        case "toolbar-effects":
            write("TOOLBAR-EFFECTS " + toolbarEffects(menu: []))
        case "toolbar-layout":
            write(toolbarLayoutReport())
        case "split-dump":
            write(splitDump())
        case "split-min":
            write(await splitMin(arg))
        case "header-layout":
            write(compactHeaderReport())
        case "header-menu":
            await headerMenu(arg)
        case "header-click":
            await headerClick(arg)
        case "header-search":
            await headerSearch(arg)
        case "sessions-menu":
            write(sessionsMenuPlace())
        case "workspace-places":
            // Owner 2026-11-05: workspaces in the sidebar header and File/Window menus, not the toolbar.
            let inToolbar = (window?.toolbar?.items ?? []).contains { ($0.label + $0.paletteLabel).contains("Workspace") }
            func find(_ v: NSView) -> NSRect? {
                if v.identifier?.rawValue == SidebarWorkspaceMenu.markerId {
                    return v.window?.convertToScreen(v.convert(v.bounds, to: nil))
                }
                for sub in v.subviews { if let r = find(sub) { return r } }
                return nil
            }
            let sidebarFrame = window?.contentView.flatMap(find)
            // In the sidebar: left of the session area, below the title bar.
            let sidebar = sidebarFrame.map { f in window.map { f.maxX < $0.frame.minX + $0.frame.width / 2 } ?? false } ?? false
            let menus = ["File", "Window"].map { t in NSApp.mainMenu?.items.first { $0.title == t }?.submenu?.items.first { $0.title == "Workspaces" }?.submenu?.items.count ?? -1 }
            let topLevel = NSApp.mainMenu?.items.contains { $0.title == "Workspace" } ?? false
            let tall = (sidebarFrame?.height ?? 0) >= DS.Size.minHitTarget
            let ok = !inToolbar && sidebar && tall && menus.allSatisfy { $0 > 0 } && !topLevel
            write("\(ok ? "" : "FAIL ")WORKSPACE-PLACES toolbar=\(inToolbar) sidebar=\(sidebar) file=\(menus[0]) window=\(menus[1]) topLevelMenu=\(topLevel) sidebarHeight=\(Int(sidebarFrame?.height ?? 0))")
        case "inspector":
            commands.tree.setInspectorVisible(arg == "on")
            // Until the column animation ends: a fit check mid-collapse sees the content clipped.
            let ms = await settleSplitViews()
            write("INSPECTOR \(arg) settled=\(ms)ms")
        case "own-icon":
            // `own-icon <connection>|<name or none>`: as a click in the inspector's Icon group; fails
            // unless the tree then reports that own icon (the core refuses names outside its set).
            let p = arg.components(separatedBy: "|")
            func find(_ f: FolderView) -> ConnectionView? {
                f.connections.first { $0.name == p[0] } ?? f.folders.lazy.compactMap(find).first
            }
            guard p.count == 2, let c = commands.model.tree.flatMap(find) else { return write("FAIL \(line): no connection") }
            let want = p[1] == "none" ? nil : p[1]
            commands.model.mutate { try $0.setIcon(id: c.id, icon: want) }
            if let e = commands.model.error { commands.model.error = nil; return write("REFUSED own-icon \(p[1]): \(e)") }
            await settle()
            let got = commands.model.tree.flatMap(find)?.ownIcon
            write("\(got == want ? "" : "FAIL ")OWN-ICON \(p[0]) -> \(got ?? "none")")
        case "custom-props":
            // `custom-props <connection>|<name>=<value>,…`: fails unless the library holds exactly
            // those custom properties for that connection (sorted by name; empty list: none).
            let p = arg.components(separatedBy: "|")
            func find(_ f: FolderView) -> ConnectionView? {
                f.connections.first { $0.name == p[0] } ?? f.folders.lazy.compactMap(find).first
            }
            guard p.count == 2, let c = commands.model.tree.flatMap(find),
                  let props = try? commands.model.library?.customProperties(id: c.id) else { return write("FAIL \(line): no connection") }
            let got = props.map { "\($0.name)=\($0.value)" }.sorted().joined(separator: ",")
            write("\(got == p[1] ? "" : "FAIL ")CUSTOM-PROPS \(p[0]) -> \(got)")
        case "privileged":
            // `privileged <connection>|on|off`: set Privileged infrastructure (UI-01); fails unless the
            // host colour then says privileged (red by default) as asked.
            let p = arg.components(separatedBy: "|")
            func find(_ f: FolderView) -> ConnectionView? {
                f.connections.first { $0.name == p[0] } ?? f.folders.lazy.compactMap(find).first
            }
            guard p.count == 2, let c = commands.model.tree.flatMap(find) else { return write("FAIL \(line): no connection") }
            commands.model.mutate { try $0.setProperty(id: c.id, key: "privileged", value: p[1] == "on" ? "true" : "false") }
            if let e = commands.model.error { commands.model.error = nil; return write("FAIL privileged \(arg): \(e)") }
            await settle()
            let got = HostColors.shared.paint(for: c.id)?.privileged == true ? "on" : "off"
            write("\(got == p[1] ? "" : "FAIL ")PRIVILEGED \(p[0]) -> \(got)")
        case "title-bar-production":
            // `title-bar-production yes|no`: fails unless the selected tab's title bar shows the word
            // "Production" as asked (SessionTitleBar shows it when the host colour is privileged, UI-01).
            await settle(0.5)
            guard let id = UIDriver.services?.sessions.selectedTab?.connectionId else { return write("FAIL \(line): no session tab") }
            let got = HostColors.shared.paint(for: id)?.privileged == true ? "yes" : "no"
            write("\(got == arg ? "" : "FAIL ")TITLE-BAR-PRODUCTION \(arg) -> \(got)")
        case "inspector-expect":
            // `inspector-expect on|off`: fails unless the inspector (column or full-screen overlay) is on screen as expected.
            await settle(0.5)
            let on = commands.tree.inspectorPresented ? "on" : "off"
            write("\(on == arg ? "" : "FAIL ")INSPECTOR-EXPECT \(arg) -> \(on)")
        case "inspector-state":
            // The saved choice, what shows now, and whether full screen draws it as an overlay.
            let full = (window?.styleMask.contains(.fullScreen) ?? false) || FullScreenSimulation.shared.isOn
            write("INSPECTOR-STATE saved=\(commands.tree.inspectorVisible ? "on" : "off") shown=\(commands.tree.inspectorShown ? "on" : "off") fullscreen=\(full ? "on" : "off") overlay=\(full && commands.tree.inspectorShown ? "on" : "off") presented=\(commands.tree.inspectorPresented ? "on" : "off") session-focus=\(commands.tree.sessionFocused ? "yes" : "no") page=\(UIDriver.services?.sessions.connectionPage.flatMap { commands.model.connection(id: $0)?.name } ?? "none") start-pick=\(UIDriver.services?.sessions.startPick.flatMap { commands.model.connection(id: $0)?.name } ?? "none") narrow=\(commands.tree.inspectorHiddenByWidth ? "hidden" : commands.tree.tooNarrowForInspector ? "shown" : "no")")
        case "autodock-state":
            let d = AutoDock.shared
            let lib = UIDriver.services.map { commands.tree.libraryShown(autoHide: $0.settings.value("tree.auto-hide") == "true") } ?? false
            write("AUTODOCK docked=\(d.docked ? "on" : "off") held=\(d.isHeld ? "on" : "off") column=\(lib ? "shown" : "hidden")")
        case "pointer":
            // `pointer <x>`: a real mouse-moved event at window x (mid height), through the event queue.
            guard let w = window, let x = Double(arg) else { return write("FAIL pointer") }
            let pt = NSPoint(x: x, y: (w.contentView?.bounds.height ?? 400) / 2)
            if let e = NSEvent.mouseEvent(with: .mouseMoved, location: pt, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                          windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 0, pressure: 0) {
                NSApp.postEvent(e, atStart: false)
            }
            await settle(0.02)
            write("POINTER \(arg)")
        case "reveal-top":
            // Full screen: a real pointer move to the top edge, as the owner does (round 2, item 16),
            // so macOS drops the menu bar and shows the traffic lights in front of the toolbar.
            // `reveal-top off` moves it back to mid screen. Needs the screen lock.
            guard let screen = window?.screen ?? NSScreen.main else { return write("FAIL reveal-top: no screen") }
            let top = arg != "off"
            let pt = CGPoint(x: screen.frame.midX, y: top ? 1 : screen.frame.height / 2)
            for step in [CGPoint(x: pt.x, y: pt.y + 20), pt] {
                CGWarpMouseCursorPosition(step)
                CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: step, mouseButton: .left)?.post(tap: .cghidEventTap)
                await settle(0.3)
            }
            await settle(1.5)
            write("REVEAL-TOP \(top ? "on" : "off")")
        case "switcher-fit":
            // The library picker sits inside the library column, right of the traffic lights.
            guard let v = DriverEvents.headerViews["library-switcher"]?.view, let w = v.window else { return write("FAIL SWITCHER-FIT: not on screen") }
            let f = v.convert(v.bounds, to: nil)
            let lights = w.standardWindowButton(.zoomButton).map { $0.convert($0.bounds, to: nil).maxX } ?? 0
            let column = UIDriver.services?.sessions.sidebarWidth ?? 0
            // Full screen hides the lights until the pointer reaches the top; then they come back in
            // front of the picker. It must fit the column from the lights' edge either way.
            let ok = lights + f.width <= column + 1 && f.maxX <= column + 1 && f.width >= DS.Size.minHitTarget
            write("\(ok ? "" : "FAIL ")SWITCHER-FIT x=\(Int(f.minX))-\(Int(f.maxX)) lights=\(Int(lights)) column=\(Int(column)) originWithLights=\(Int(LibrarySwitcher.originWithLights)) lightsFS=\(LibrarySwitcher.trafficLightsTrailingX().map { Int($0) } ?? -1)")
        case "first-responder":
            // Which view has keyboard focus, and the system windows it brings (the input-source
            // badge beside a focused text field: owner round 5, the round icon over the corner).
            let r = window?.firstResponder
            let name = r.map { String(describing: type(of: $0)) } ?? "none"
            let frame = (r as? NSView).map { v in let f = v.convert(v.bounds, to: nil); return "\(Int(f.minX)),\(Int(f.minY)) \(Int(f.width))x\(Int(f.height))" } ?? "-"
            let sys = NSApp.windows.filter { String(describing: type(of: $0)).contains("Campo") && $0.isVisible }.map { "\(Int($0.frame.minX)),\(Int($0.frame.minY))" }
            let text = r is NSText || r is NSTextView || (r as? NSView)?.isKind(of: NSTextField.self) == true
            write("FIRST-RESPONDER \(name) text=\(text) at \(frame) badge=\(sys)")
        case "switcher-slack":
            // `switcher-slack <pt>`: the library picker asks for that much more width than the
            // column has, as when the full-screen reveal brings the lights back (0 restores).
            LibrarySwitcher.testSlack = CGFloat(Double(arg) ?? 0)
            UIDriver.services?.sessions.sidebarWidth += 4
            await settle(0.5)
            UIDriver.services?.sessions.sidebarWidth -= 4
            await settle(1)
            write("SWITCHER-SLACK \(arg)")
        case "strip-slack":
            // `strip-slack <pt>`: the strip asks for this much more than the bar has (0 restores).
            SessionTabStrip.testSlack = CGFloat(Double(arg) ?? 0)
            UIDriver.services?.sessions.sessionAreaResized((UIDriver.services?.sessions.sessionAreaWidth ?? 600) + 1)
            await settle(1.0)
            write("STRIP-SLACK \(arg)")
        case "activate":
            // Proof runs only (real hover, tooltips): a regular app in front, as the owner runs it.
            // The quiet launch is an accessory app, and AppKit shows no tool tips for those.
            NSApp.setActivationPolicy(.regular)
            NSApp.activate()
            window?.makeKeyAndOrderFront(nil)
            await settle(1.0)
            write("ACTIVATE active=\(NSApp.isActive ? "yes" : "no")")
        case "hover":
            // `hover <driver frame name>`: the real pointer onto the centre of that control, moved in
            // small steps so AppKit sees it arrive (tool tips, full-screen reveal). Needs the screen lock.
            guard let v = DriverEvents.headerViews[arg]?.view, let w = v.window, let screen = w.screen else { return write("FAIL HOVER \(arg): not on screen") }
            let r = w.convertToScreen(v.convert(v.bounds, to: nil))
            let target = CGPoint(x: r.midX, y: screen.frame.maxY - r.midY)
            for dx in stride(from: 30.0, through: 0, by: -10) {
                let pt = CGPoint(x: target.x - dx, y: target.y)
                CGWarpMouseCursorPosition(pt)
                CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: pt, mouseButton: .left)?.post(tap: .cghidEventTap)
                await settle(0.05)
            }
            await settle(2.5)
            write("HOVER \(arg) at \(Int(target.x)),\(Int(target.y)) tip=\(Self.shownToolTip() ?? "none") trusted=\(AXIsProcessTrusted())")
        case "expand":
            // `expand <row>`: open a library folder (a real key goes to the focused view, which
            // in a foreground run may be a terminal).
            guard let outline, let r = row(named: arg) else { return write("FAIL EXPAND \(arg)") }
            outline.expandItem(outline.item(atRow: r))
            await settle(0.3)
            write("EXPAND \(arg) rows=\(outline.numberOfRows)")
        case "hover-row":
            // `hover-row <name>`: the real pointer onto a library row (its AppKit tool tip).
            guard let outline, let w = outline.window, let screen = w.screen, let r = row(named: arg) else { return write("FAIL HOVER-ROW \(arg)") }
            let rect = w.convertToScreen(outline.convert(outline.rect(ofRow: r), to: nil))
            let target = CGPoint(x: rect.minX + 60, y: screen.frame.maxY - rect.midY)
            for dx in stride(from: 30.0, through: 0, by: -10) {
                let pt = CGPoint(x: target.x - dx, y: target.y)
                CGWarpMouseCursorPosition(pt)
                CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: pt, mouseButton: .left)?.post(tap: .cghidEventTap)
                await settle(0.05)
            }
            await settle(2.5)
            write("HOVER-ROW \(arg) tip=\(Self.shownToolTip() ?? "none")")
        case "screen":
            // `screen <name>`: the whole screen (tool tips and the full-screen menu bar are their own windows).
            guard CaptureCheck.isValidName(arg) else { return write("FAIL screen: bad name") }
            let file = out.appendingPathComponent("\(arg).png").path
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
            p.arguments = ["-x", file]
            do { try p.run(); p.waitUntilExit() } catch { return write("FAIL screen \(arg): \(error)") }
            write("\(FileManager.default.fileExists(atPath: file) ? "" : "FAIL ")SCREEN \(arg)")
        case "tip-hover":
            // `tip-hover <frame>|<shot>`: the pointer moves onto that view through the event queue
            // (as a real move arrives); PASS when AppKit shows a tool tip panel (owner round 4, item 6).
            let p = arg.components(separatedBy: "|")
            guard let v = DriverEvents.headerViews[p[0]]?.view, let w = v.window else { return write("FAIL TIP-HOVER \(p[0]): no view") }
            let f = v.convert(v.bounds, to: nil)
            for pt in [NSPoint(x: f.midX, y: f.maxY + 30), NSPoint(x: f.midX - 1, y: f.midY), NSPoint(x: f.midX, y: f.midY)] {
                if let e = NSEvent.mouseEvent(with: .mouseMoved, location: pt, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                              windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 0, pressure: 0) {
                    NSApp.postEvent(e, atStart: false)
                }
                await settle(0.1)
            }
            await settle(2.5)
            let panel = NSApp.windows.first { String(describing: type(of: $0)).contains("ToolTip") && $0.isVisible }
            if p.count > 1, CaptureCheck.isValidName(p[1]) {
                let shot = Process()
                shot.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
                shot.arguments = ["-x", out.appendingPathComponent("\(p[1]).png").path]
                try? shot.run(); shot.waitUntilExit()
            }
            var chain: [String] = [], h = w.contentView?.superview?.hitTest(w.contentView!.superview!.convert(NSPoint(x: f.midX, y: f.midY), from: nil))
            while let x = h, chain.count < 7 { chain.append(String(describing: type(of: x)).prefix(45).description + (x.toolTip.map { "[\($0)]" } ?? "")); h = x.superview }
            write("\(panel == nil ? "FAIL " : "")TIP-HOVER \(p[0]): \(panel.map { "shown \(Int($0.frame.width))x\(Int($0.frame.height))" } ?? "no tool tip") hit=\(chain.joined(separator: "<"))")
        case "strip-doubleclick":
            // `strip-doubleclick <n>`: a double-click on the n-th main tab through NSApp's event
            // dispatch; the rename field must open (owner round 4, item 5).
            guard let sv = UIDriver.services, let n = Int(arg), n >= 1, n <= sv.sessions.tabs.count,
                  let v = DriverEvents.headerViews["strip-tab-" + sv.sessions.tabs[n - 1].id.uuidString]?.view, let w = v.window
            else { return write("FAIL STRIP-DOUBLECLICK \(arg): no tab view") }
            let f = v.convert(v.bounds, to: nil)
            let pt = NSPoint(x: f.midX - 10, y: f.midY)
            sv.sessions.renamingTab = nil
            for count in [1, 2] {
                for type in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
                    if let e = NSEvent.mouseEvent(with: type, location: pt, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                                  windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: count, pressure: type == .leftMouseDown ? 1 : 0) {
                        NSApp.sendEvent(e)
                    }
                }
                await settle(0.05)
            }
            await settle(0.6)
            let ok = sv.sessions.renamingTab == sv.sessions.tabs[n - 1].id
            write("\(ok ? "" : "FAIL ")STRIP-DOUBLECLICK \(arg): rename \(ok ? "open" : "not open")")
        case "strip-rightclick":
            // `strip-rightclick <n>`: a right-click on the n-th main tab sent through the window's
            // own event dispatch (hit test, toolbar, menu lookup), as a real click is; logs the
            // menu that opens. Owner round 4, item 5: the toolbar's "Icon and Text" menu won.
            let shotName = arg.components(separatedBy: "|").dropFirst().first
            let shotFile = shotName.map { out.appendingPathComponent("\($0).png").path }
            guard let sv = UIDriver.services, let n = Int(arg.components(separatedBy: "|")[0]), n >= 1, n <= sv.sessions.tabs.count,
                  let v = DriverEvents.headerViews["strip-tab-" + sv.sessions.tabs[n - 1].id.uuidString]?.view, let w = v.window
            else { return write("FAIL STRIP-RIGHTCLICK \(arg): no tab view") }
            let f = v.convert(v.bounds, to: nil)
            let pt = NSPoint(x: f.midX - 10, y: f.midY)
            final class Box: @unchecked Sendable { var titles: [String] = []; var menu: NSMenu? }
            let box = Box()
            let token = NotificationCenter.default.addObserver(forName: NSMenu.didBeginTrackingNotification, object: nil, queue: nil) { n in
                guard let m = n.object as? NSMenu else { return }
                box.titles = m.items.map { $0.isSeparatorItem ? "-" : $0.title }
                box.menu = m
                guard let shotFile else {
                    RunLoop.main.perform(inModes: [.eventTracking, .default]) { MainActor.assumeIsolated { box.menu?.cancelTracking() } }
                    return
                }
                // `strip-rightclick <n>|<name>`: a whole-screen capture with the menu open.
                DispatchQueue.global().asyncAfter(deadline: .now() + 0.8) {
                    let shot = Process()
                    shot.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
                    shot.arguments = ["-x", shotFile]
                    try? shot.run(); shot.waitUntilExit()
                    RunLoop.main.perform(inModes: [.eventTracking, .default]) { MainActor.assumeIsolated { box.menu?.cancelTracking() } }
                }
            }
            if let e = NSEvent.mouseEvent(with: .rightMouseDown, location: pt, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                          windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1) {
                NSApp.postEvent(e, atStart: false)
            }
            if let up = NSEvent.mouseEvent(with: .rightMouseUp, location: pt, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                           windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 0) {
                NSApp.postEvent(up, atStart: false)
            }
            await settle(shotFile == nil ? 0.5 : 2.5)
            NotificationCenter.default.removeObserver(token)
            let ok = box.titles.contains("Rename Tab…")
            var chain: [String] = [], h = w.contentView?.superview?.hitTest(w.contentView!.superview!.convert(pt, from: nil))
            let hit = h
            while let x = h, chain.count < 6 { chain.append(String(describing: type(of: x)).prefix(40).description); h = x.superview }
            let own = hit.flatMap { $0.menu(for: NSEvent.mouseEvent(with: .rightMouseDown, location: pt, modifierFlags: [], timestamp: 0, windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)!) }
            write("\(ok ? "" : "FAIL ")STRIP-RIGHTCLICK \(arg): \(box.titles.joined(separator: " | ")) hit=\(chain.joined(separator: "<")) hitMenu=\(own?.items.map(\.title) ?? []) hostMenu=\(HostedTabStrip.StripHost.current.flatMap { $0.anchor(for: NSEvent.mouseEvent(with: .rightMouseDown, location: pt, modifierFlags: [], timestamp: 0, windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)!) }?.makeMenu?().items.count ?? -1) sameWin=\(HostedTabStrip.StripHost.current?.window === w)")
        case "row-menu":
            // `row-menu <row>[|<title>,<title>…]`: the titles of that tree row's right-click menu;
            // FAIL when one of the listed titles is missing.
            let parts = arg.components(separatedBy: "|"), need = parts.count > 1 ? parts[1].components(separatedBy: ",") : []
            guard let outline, let window, let r = row(named: parts[0]) else { return write("FAIL ROW-MENU \(arg)") }
            let rect = outline.rect(ofRow: r)
            let point = outline.convert(NSPoint(x: rect.midX, y: rect.midY), to: nil)
            guard let event = NSEvent.mouseEvent(with: .rightMouseDown, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                                 windowNumber: window.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1),
                  let menu = outline.menu(for: event) else { return write("FAIL ROW-MENU \(arg): no menu") }
            menu.delegate?.menuNeedsUpdate?(menu)
            let titles = menu.items.map { $0.isSeparatorItem ? "-" : $0.title }
            let missing = need.filter { !titles.contains($0) }
            write("\(missing.isEmpty ? "" : "FAIL ")ROW-MENU \(parts[0]): \(titles.joined(separator: " | "))\(missing.isEmpty ? "" : " missing: \(missing.joined(separator: ", "))")")
        case "task-edit-builtin":
            // `task-edit-builtin <task name>|<new name>`: what the editor's Save does for Edit… on a built-in.
            let p = arg.components(separatedBy: "|")
            guard p.count == 2, let lib = commands.model.library, var t = lib.tasks().first(where: { $0.name == p[0] && $0.builtin }) else { return write("FAIL TASK-EDIT \(arg)") }
            t.kind = "custom"; t.name = p[1]
            do { _ = try lib.saveTask(task: t); commands.model.mutate { _ in }; await settle(0.5); write("TASK-EDIT \(p[0]) -> \(p[1])") }
            catch { write("FAIL TASK-EDIT \(error)") }
        case "menu-shot":
            // `menu-shot <row>|<name>`: right-click menu of a library row, shown for real, captured
            // with the screen, then closed with Esc (the menu's tracking loop holds the main thread).
            let p = arg.components(separatedBy: "|")
            guard p.count == 2, CaptureCheck.isValidName(p[1]), let outline, let window, let r = row(named: p[0]) else { return write("FAIL MENU-SHOT \(arg)") }
            let rect = outline.rect(ofRow: r)
            let point = outline.convert(NSPoint(x: rect.midX, y: rect.midY), to: nil)
            guard let event = NSEvent.mouseEvent(with: .rightMouseDown, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                                 windowNumber: window.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1),
                  let menu = outline.menu(for: event) else { return write("FAIL MENU-SHOT \(arg): no menu") }
            let file = out.appendingPathComponent("\(p[1]).png").path
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.2) {
                let shot = Process()
                shot.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
                shot.arguments = ["-x", file]
                try? shot.run(); shot.waitUntilExit()
                CGEvent(keyboardEventSource: nil, virtualKey: 53, keyDown: true)?.post(tap: .cghidEventTap)
                CGEvent(keyboardEventSource: nil, virtualKey: 53, keyDown: false)?.post(tap: .cghidEventTap)
                // The posted Esc can miss the menu (a foreground run left it open until the limit
                // killed the app); close it from the menu's own tracking run loop as well.
                RunLoop.main.perform(inModes: [.eventTracking, .default]) { menu.cancelTracking() }
            }
            NSMenu.popUpContextMenu(menu, with: event, for: outline)
            let titles = menu.items.map { $0.isSeparatorItem ? "—" : $0.title }.joined(separator: " | ")
            write("\(menu.items.isEmpty ? "FAIL " : "")MENU-SHOT \(p[0]): \(titles)")
        case "menubar-shot":
            // `menubar-shot <menu title>|<name>`: a menu bar menu shown for real at the window's top left,
            // captured with the screen, then closed (the tracking loop holds the main thread).
            let p = arg.components(separatedBy: "|")
            guard p.count == 2, CaptureCheck.isValidName(p[1]), let window,
                  let menu = NSApp.mainMenu?.items.first(where: { $0.title == p[0] })?.submenu ?? (["Gantry", "Bastion"].contains(p[0]) ? NSApp.mainMenu?.items.first?.submenu : nil) else { return write("FAIL MENUBAR-SHOT \(arg)") }
            menu.delegate?.menuNeedsUpdate?(menu)
            menu.update()
            let file = out.appendingPathComponent("\(p[1]).png").path
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.2) {
                let shot = Process()
                shot.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
                shot.arguments = ["-x", file]
                try? shot.run(); shot.waitUntilExit()
                RunLoop.main.perform(inModes: [.eventTracking, .default]) { menu.cancelTracking() }
            }
            write("MENUBAR-SHOT \(p[0]): \(menu.items.count) items")
            menu.popUp(positioning: nil, at: NSPoint(x: 20, y: window.contentView?.bounds.height ?? 600), in: window.contentView)
        case "tab-rename-open":
            // `tab-rename-open <index>`: Rename Tab… on the n-th main tab (as its menu item does).
            guard let sv = UIDriver.services, let i = Int(arg), sv.sessions.mainTabs.indices.contains(i) else { return write("FAIL tab-rename-open") }
            sv.sessions.renamingTab = sv.sessions.mainTabs[i].id
            await settle(0.8)
            write("TAB-RENAME-OPEN \(i)")
        case "tab-name-expect":
            // `tab-name-expect <index>|<name>`: the strip shows that name for the n-th main tab.
            let p = arg.components(separatedBy: "|")
            guard p.count == 2, let sv = UIDriver.services, let i = Int(p[0]), sv.sessions.mainTabs.indices.contains(i) else { return write("FAIL tab-name-expect") }
            let got = sv.sessions.mainTabs[i].stripName
            write("\(got == p[1] ? "" : "FAIL ")TAB-NAME \(i) -> \(got)")
        case "home-expect":
            // `home-expect on|off`: the Start page is in front (Home) or not.
            await settle(0.4)
            let on = UIDriver.services?.sessions.homeShown == true ? "on" : "off"
            write("\(on == arg ? "" : "FAIL ")HOME \(on)")
        case "session-menu-tabs":
            // Owner round 2, item 12: the Session menu lists the open tabs (up to nine) by name.
            await settle(0.5)
            // SwiftUI fills a menu bar menu when it opens: ask it to update, as opening does.
            if let m = NSApp.mainMenu?.items.first(where: { $0.title == "Session" })?.submenu { m.delegate?.menuNeedsUpdate?(m); m.update() }
            await settle(0.3)
            guard let menu = NSApp.mainMenu?.items.first(where: { $0.title == "Session" })?.submenu,
                  let sv = UIDriver.services else { return write("FAIL SESSION-MENU-TABS: no menu") }
            let want = sv.sessions.mainTabs.prefix(AppMenus.numberedTabs).map(\.shownName)
            let titles = menu.items.filter { !$0.isHidden }.map(\.title)
            let after = titles.firstIndex(of: "Show Previous Tab (Alternate)").map { Array(titles[($0 + 1)...]).filter { !$0.isEmpty } } ?? []
            let stale = titles.contains { $0.range(of: #"^Show Tab \d"#, options: .regularExpression) != nil }
            let ok = after == want && !stale
            write("\(ok ? "" : "FAIL ")SESSION-MENU-TABS \(after.joined(separator: "|")) want \(want.joined(separator: "|"))")
        case "close-asks":
            // `close-asks yes|no`: closes the selected tab, answering a prompt with Cancel; fails
            // unless a prompt came (yes) or did not (no). Owner round 2, item 14.
            guard let sv = UIDriver.services, let tab = sv.sessions.selectedTab else { return write("FAIL CLOSE-ASKS: no tab") }
            let before = sv.sessions.closeConfirmations
            sv.sessions.scriptedCloseAnswer = false
            sv.sessions.requestClose(tab)
            sv.sessions.scriptedCloseAnswer = nil
            let asked = sv.sessions.closeConfirmations > before
            write("\(asked == (arg == "yes") ? "" : "FAIL ")CLOSE-ASKS asked=\(asked ? "yes" : "no") busy=\(LocalShellActivity.anyShellBusy() ? "yes" : "no")")
        case "autodock-hold":
            // `autodock-hold renaming|dragging on|off`: the outline's hold flags, as rename/drag set them.
            let p = arg.split(separator: " ").map(String.init)
            guard p.count == 2 else { return write("FAIL autodock-hold") }
            if p[0] == "renaming" { AutoDock.shared.renaming = p[1] == "on" } else { AutoDock.shared.dragging = p[1] == "on" }
            write("AUTODOCK-HOLD \(arg)")
        case "fullscreen":
            // `fullscreen on|off`: enter or leave full screen and wait for the transition.
            // `fullscreen sim-on|sim-off`: quiet runs (no full-screen Space) simulate it.
            guard let w = window else { return write("FAIL fullscreen: no window") }
            if arg.hasPrefix("sim-") {
                FullScreenSimulation.shared.isOn = arg == "sim-on"
                await settle(0.8)
                return write("FULLSCREEN \(arg)")
            }
            // Quiet (accessory) runs: the window must opt in to full screen explicitly.
            w.collectionBehavior.insert(.fullScreenPrimary)
            if w.styleMask.contains(.fullScreen) != (arg == "on") { w.toggleFullScreen(nil) }
            for _ in 0..<40 where w.styleMask.contains(.fullScreen) != (arg == "on") { await settle(0.1) }
            await settle(1.0)
            write("\(w.styleMask.contains(.fullScreen) == (arg == "on") ? "" : "FAIL ")FULLSCREEN \(arg)")
        case "library":
            // Library panel: the saved choice, whether it shows now, and the outline's visible width.
            let autoHide = UIDriver.services?.settings.value("tree.auto-hide") == "true"
            let width = outline.map { $0.isHiddenOrHasHiddenAncestor ? 0 : Int($0.visibleRect.width) } ?? 0
            write("LIBRARY saved \(commands.tree.libraryVisible ? "on" : "off") shown \(commands.tree.libraryShown(autoHide: autoHide) ? "on" : "off") session-focus \(commands.tree.sessionFocused ? "yes" : "no") outline-width \(width)")
        case "library-button":
            // A real click on the collapse button at the right end of the library panel's bottom bar.
            var column: NSView? = outline
            while let c = column, !(c.superview is NSSplitView) { column = c.superview }
            guard let column, let window else { return write("FAIL library-button") }
            let r = column.convert(column.bounds, to: nil)
            click(at: NSPoint(x: r.maxX - DS.Space.s - 8, y: r.minY + 12), in: window)
            await settle(0.8)
            write("LIBRARY-BUTTON clicked")
        case "focus-session", "focus-tree":
            // Keyboard focus into the selected session's view, or back to the tree.
            let target: NSView? = cmd == "focus-tree" ? outline
                : window?.contentView?.firstSubview(of: TerminalNSView.self) ?? window?.contentView?.firstSubview(of: RemoteDesktopCanvas.self)
            guard let target else { return write("FAIL \(cmd)") }
            window?.makeFirstResponder(target)
            await settle(0.8)
            write("FOCUS \(cmd == "focus-tree" ? "tree" : "session")")
        case "close-tabs":
            guard let sv = UIDriver.services else { return write("FAIL close-tabs") }
            sv.sessions.tabs.forEach(sv.sessions.close)
            await settle(0.5)
            write("TABS closed")
        case "sheetkey":
            // A key to the open sheet or popover (palette, Quick Connect, name dialog).
            // The New Connection form lives in the inspector: its keys go to the main window.
            let formWindow = commands.addConnection != nil || commands.panel != nil ? window : nil
            guard let w = window?.attachedSheet ?? popover ?? formWindow, let known = Self.keyCodes[arg] else { return write("FAIL sheetkey \(arg)") }
            let arrows: NSEvent.ModifierFlags = (123...126).contains(known.code) ? [.numericPad, .function] : []
            let e = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: arrows, timestamp: ProcessInfo.processInfo.systemUptime,
                                     windowNumber: w.windowNumber, context: nil, characters: known.chars,
                                     charactersIgnoringModifiers: known.chars, isARepeat: false, keyCode: known.code)!
            // Through NSApp so key equivalents (Return = default button, Escape = Cancel) apply.
            w.makeKey()
            deliverKey(e, to: w)
            await settle(0.8)
            write("SHEETKEY \(arg) -> sheet \(window?.attachedSheet != nil ? "shown" : "none"), popover \(popover != nil ? "shown" : "none")"
                  + (formWindow != nil ? ", form \(commands.addConnection != nil || commands.panel != nil ? "shown" : "closed")" : ""))
        case "menuitem":
            // `menuitem <menu> > <item>`: run a menu bar item through NSMenu, as a click on it would.
            let p = arg.components(separatedBy: " > ")
            guard p.count == 2, let menu = NSApp.mainMenu?.items.first(where: { $0.title == p[0] })?.submenu,
                  let index = menu.items.firstIndex(where: { $0.title == p[1] }) else { return write("FAIL menuitem \(arg)") }
            menu.performActionForItem(at: index)
            await settle(0.8)
            write("MENUITEM \(arg) -> sheet \(window?.attachedSheet != nil ? "shown" : "none"), tab \(UIDriver.services?.sessions.selectedTab?.title ?? "-")")
        case "menubar":
            // `menubar <menu title>[ > <submenu>…]`: items with key equivalent and enabled state, after AppKit's own update.
            let path = arg.components(separatedBy: " > ")
            guard let top = NSApp.mainMenu?.items.first(where: { $0.title == path[0] })?.submenu,
                  let menu = path.dropFirst().reduce(Optional(top), { m, t in m?.items.first { $0.title == t }?.submenu })
            else { return write("FAIL menubar \(arg)") }
            // As when the user opens it: the delegate (SwiftUI) refreshes the items, then AppKit validates.
            menu.delegate?.menuNeedsUpdate?(menu)
            menu.delegate?.menuWillOpen?(menu)
            await settle(0.2)
            menu.update()
            menu.delegate?.menuDidClose?(menu)
            write("MENUBAR \(arg): " + menu.items.filter { !$0.isSeparatorItem }.map { i in
                let mods = i.keyEquivalentModifierMask
                let key = (mods.contains(.control) ? "⌃" : "") + (mods.contains(.option) ? "⌥" : "") + (mods.contains(.shift) ? "⇧" : "") + (mods.contains(.command) ? "⌘" : "")
                return "\(i.title)[\(key)\(i.keyEquivalent == "\t" ? "⇥" : i.keyEquivalent == "\r" ? "↩" : i.keyEquivalent)\(i.isEnabled ? "" : " disabled")]"
            }.joined(separator: " "))
        case "last-error":
            // The error the window would show (library, then session), cleared as OK would.
            guard let sv = UIDriver.services else { return write("FAIL last-error") }
            write("LAST-ERROR \(commands.model.error ?? sv.sessions.error ?? "none")")
            commands.model.error = nil
            sv.sessions.error = nil
        case "panel-path":
            // `panel-path <file>`: the next Import/Export panel returns this file without showing.
            // A relative path is in the library's folder.
            LibraryIO.scriptedPanelURL = URL(fileURLWithPath: arg, relativeTo: LibraryModel.dataDir).standardizedFileURL
            write("PANEL-PATH \(arg)")
        case "route":
            // Any `ContentView.open` target, as the palette and menu bar send it.
            guard let sv = UIDriver.services else { return write("FAIL route") }
            sv.router.open(arg)
            await settle(0.6)
            // `add` must show something: the Classic + popover or, in Compact, the New Connection form.
            let addShown = commands.addConnection != nil || NSApp.windows.contains { $0.isVisible && String(describing: type(of: $0)).contains("Popover") }
            write((arg == "add" && !addShown ? "FAIL " : "") + "ROUTE \(arg) -> sheet \(window?.attachedSheet != nil ? "shown" : "none")" + (commands.addConnection != nil ? ", form shown" : "") + (commands.panel != nil ? ", panel shown" : ""))
        case "appkey":
            // Through NSApp, so menu bar key equivalents fire as for a real keystroke.
            appKey(arg)
            await settle(0.6)
            write("APPKEY \(arg) -> sheet \(window?.attachedSheet.map { "shown \(sheetText($0))" } ?? "none"), popover \(popover != nil ? "shown" : "none"), tab \(UIDriver.services?.sessions.selectedTab?.title ?? "-")")
        case "workspaces":
            guard let sv = UIDriver.services else { return write("FAIL workspaces") }
            write("WORKSPACES current=\(sv.workspaces.current?.name ?? "-") " + sv.workspaces.items.map { "\($0.name)[\($0.tabs.count) tabs, layouts \($0.tabs.map { $0.layout.isEmpty ? "1" : $0.layout.joined(separator: " ") }.joined(separator: "; ")), last used \($0.lastUsed.map { _ in "set" } ?? "never")]" }.joined(separator: ", "))
        case "workspace":
            await workspace(arg)
        case "remote-edit":
            // `remote-edit <name>|<appended text>`: open a home-folder file in the editor model, append,
            // save; then a second copy opened before that save must come back as a conflict, and
            // a forced save must replace the server copy with its own text. Logs the round trip.
            guard let b = UIDriver.selectedBrowser else { return write("FAIL remote-edit: no files tab or file panel") }
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            guard p.count == 2, let home = try? b.home() else { return write("FAIL remote-edit \(arg)") }
            let path = home.hasSuffix("/") ? home + p[0] : home + "/" + p[0]
            let first = RemoteEditDocument(browser: b, path: path), stale = RemoteEditDocument(browser: b, path: path)
            await first.load(); await stale.load()
            first.text += p[1]
            let saved = await first.save()
            stale.text += "stale"
            let conflicted = await stale.save() == false && stale.state == .conflict
            let forced = await stale.save(force: true)
            let check = RemoteEditDocument(browser: b, path: path)
            await check.load()
            write(saved && conflicted && forced && check.text.hasSuffix("stale") && !check.text.contains(p[1])
                  ? "REMOTE-EDIT ok saved, conflict caught, forced"
                  : "FAIL remote-edit saved=\(saved) conflict=\(conflicted) forced=\(forced) state=\(first.state) \(stale.state)")
        case "files-list", "files-upload", "files-download":
            // `files-list`, `files-upload <local>|<remote name>`, `files-download <remote name>|<local>` on the
            // selected files tab's home folder, the way the toolbar buttons do after their file panels.
            guard let b = UIDriver.selectedBrowser else { return write("FAIL \(cmd): no files tab or file panel") }
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            let result: Result<String, Error> = await Task.detached {
                Result {
                    let home = try b.home()
                    switch cmd {
                    case "files-upload": return "uploaded \(try b.upload(local: p[0], remote: home + "/" + p[1], overwrite: false)) bytes"
                    case "files-download": return "downloaded \(try b.download(remote: home + "/" + p[0], local: p[1], overwrite: false)) bytes"
                    default: return try b.list(path: home).map { "\($0.name)(\($0.kind) \($0.size))" }.sorted().joined(separator: " ")
                    }
                }
            }.value
            NotificationCenter.default.post(name: .filesRefresh, object: nil)
            await settle(1)
            switch result {
            case .success(let text): write("\(cmd.uppercased()) \(b.protocol()) \(text)")
            case .failure(let e): write("FAIL \(cmd): \(e)")
            }
        case "files-drop", "files-export":
            // `files-drop <local>;<local>` uploads into the open folder the way a Finder drop does;
            // `files-export <name>;<name>|<local folder>` downloads the way Download does. Both recurse.
            guard let tab = UIDriver.services?.sessions.selectedTab, case .files = tab.content else { return write("FAIL \(cmd): no files tab") }
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            let items = p[0].split(separator: ";").map(String.init)
            if cmd == "files-drop" {
                NotificationCenter.default.post(name: .filesDrop, object: items.map { URL(fileURLWithPath: $0) })
            } else {
                guard p.count == 2 else { return write("FAIL files-export: needs <names>|<folder>") }
                NotificationCenter.default.post(name: .filesExport, object: (items, URL(fileURLWithPath: p[1])))
            }
            await settle(3)
            write("\(cmd.uppercased()) posted \(items.count)")
        case "file-panel":
            // `file-panel toggle|left|right|bottom|pop|unpop|size <n>|state` on the selected tab.
            guard let sv = UIDriver.services else { return write("FAIL file-panel: no services") }
            let tab = sv.sessions.selectedTab
            let layout = FilePanelLayout.shared
            let p = arg.split(separator: " ").map(String.init)
            switch p.first ?? "state" {
            case "toggle": sv.router.open("toggle-files-panel")
            case "left", "right", "bottom": layout.move(to: FileDock(rawValue: p[0]) ?? .right)
            case "pop": if let tab { FilePanelWindow.shared.popOut(tab) }
            case "unpop": FilePanelWindow.shared.close()
            case "size": layout.resize(to: CGFloat(Double(p.count > 1 ? p[1] : "") ?? 0), available: window?.frame.width ?? 1000)
            default: break
            }
            await settle(0.8)
            write("FILE-PANEL can=\(tab?.canShowFilePanel ?? false) open=\(tab?.filePanel != nil) dock=\(layout.dock.rawValue) size=\(Int(layout.size)) popped=\(layout.poppedOut) window=\(FilePanelWindow.shared.isOpen)")
        case "transfers", "transfers-rule", "transfers-answer", "transfers-clear":
            // `transfers` lists the open files view's queue; `transfers-rule <ask|replace|replace_if_newer|rename|skip>`
            // sets the rule for new transfers; `transfers-answer <rule>` answers every conflict; `transfers-clear`.
            guard let q = TransferQueueRunner.active else { return write("FAIL \(cmd): no files view") }
            switch cmd {
            case "transfers-rule": q.rule = arg
            case "transfers-answer": for j in q.jobs where j.state == "conflict" { q.answer(j.id, rule: arg) }
            case "transfers-clear": q.clearFinished()
            default: break
            }
            await settle(cmd == "transfers" ? 0.2 : 2)
            write("TRANSFERS rule=\(q.rule) " + q.jobs.map { "\(($0.target as NSString).lastPathComponent):\($0.state)" }.joined(separator: " "))
        case "log-copy", "log-save":
            // `log-copy` copies the selected log view's shown lines; `log-save <folder>` saves them as a snippet there.
            if cmd == "log-save" { LogSnippet.folderOverride = URL(fileURLWithPath: arg) }
            NotificationCenter.default.post(name: cmd == "log-copy" ? .logCopyVisible : .logSaveSnippet, object: nil)
            await settle(0.5)
            let files = cmd == "log-save" ? ((try? FileManager.default.contentsOfDirectory(atPath: arg)) ?? []).sorted() : []
            write(cmd == "log-copy" ? "LOG-COPY \(commands.pasteboard.string(forType: .string)?.count ?? 0) chars" : "LOG-SAVE " + files.joined(separator: " "))
        case "files-edit-append":
            // `files-edit-append <text>` appends a line to the first edited copy, as an editor's save does.
            guard let local = EditLocallyRunner.active?.watched.first?.local, let h = FileHandle(forWritingAtPath: local) else { return write("FAIL files-edit-append: nothing edited") }
            h.seekToEndOfFile(); h.write(Data((arg + "\n").utf8)); try? h.close()
            await settle(4)
            write("FILES-EDIT-APPEND " + (TransferQueueRunner.active?.jobs.map { "\(($0.target as NSString).lastPathComponent):\($0.state)" }.joined(separator: " ") ?? "-"))
        case "files-edit", "files-follow":
            // `files-edit <name>` edits a file of the open folder locally without opening an app, then
            // reports the watched copies; `files-follow on|off|state` toggles Follow Terminal Folder.
            if cmd == "files-follow" {
                if arg == "on" || arg == "off" { UserDefaults.standard.set(arg == "on", forKey: TerminalFolder.followKey) }
                await settle(2.5)
                let cwd = TerminalFolder.current(of: UIDriver.services?.sessions.selectedTab) ?? "-"
                return write("FILES-FOLLOW on=\(UserDefaults.standard.bool(forKey: TerminalFolder.followKey)) cwd=\(cwd)")
            }
            guard let e = EditLocallyRunner.active, let b = UIDriver.selectedBrowser else { return write("FAIL files-edit: no files view") }
            let home: String
            do { home = try await Task.detached { try b.home() }.value } catch { return write("FAIL files-edit: \(error)") }
            e.edit(remote: joinRemote(home, arg), with: b, open: false)
            await settle(2)
            write("FILES-EDIT " + (e.error ?? e.watched.map { "\(($0.local as NSString).lastPathComponent)->\($0.remote)" }.joined(separator: " ")))
        case "files-refresh":
            // Refresh the selected SFTP tab the way its Refresh button does, then report.
            guard let tab = UIDriver.services?.sessions.selectedTab, case .files(let b) = tab.content else { return write("FAIL files-refresh: no files tab") }
            NotificationCenter.default.post(name: .filesRefresh, object: nil)
            await settle(Double(arg) ?? 4)
            write("FILES-REFRESH connected=\(b.isConnected()) reconnects=\(b.reconnects())")
        case "desktop-expect":
            // `desktop-expect <seconds>`: until the selected RDP or VNC tab has drawn a frame.
            guard let sv = UIDriver.services, let tab = sv.sessions.selectedTab else { return write("FAIL desktop-expect: no tab") }
            let deadline = CFAbsoluteTimeGetCurrent() + (Double(arg) ?? 20)
            var size: String?
            while size == nil && CFAbsoluteTimeGetCurrent() < deadline {
                switch tab.content {
                case .rdp(let r): size = r.frame(afterSerial: 0).map { "\($0.width)x\($0.height)" }
                case .vnc(let v): size = v.frame(afterSerial: 0).map { "\($0.width)x\($0.height)" }
                default: return write("FAIL desktop-expect: not a desktop tab")
                }
                if size == nil { await settle(0.3) }
            }
            write(size.map { "DESKTOP \(tab.name) \($0) route=\(tab.gatewayRoute?.summary() ?? "direct")" } ?? "FAIL desktop-expect: no frame (\(tab.desktopCloseReason ?? "still connecting"))")
        case "desktop-fill":
            // `desktop-fill <seconds>`: until the selected desktop's picture is the canvas's size
            // (Fit to tab); FAIL names both sizes. RDP widths are even, so 1 pt of slack.
            guard let sv = UIDriver.services, let tab = sv.sessions.selectedTab,
                  let canvas = window?.contentView?.allSubviews(of: RemoteDesktopCanvas.self).first(where: { $0.window != nil && !$0.isHiddenOrHasHiddenAncestor })
            else { return write("FAIL desktop-fill: no desktop") }
            let deadline = CFAbsoluteTimeGetCurrent() + (Double(arg) ?? 10)
            var last = "none"
            while CFAbsoluteTimeGetCurrent() < deadline {
                let frame: (Int, Int)? = switch tab.content {
                case .rdp(let r): r.frame(afterSerial: 0).map { (Int($0.width), Int($0.height)) }
                case .vnc(let v): v.frame(afterSerial: 0).map { (Int($0.width), Int($0.height)) }
                default: nil
                }
                let view = (Int(canvas.bounds.width), Int(canvas.bounds.height))
                if let f = frame {
                    last = "\(f.0)x\(f.1) view=\(view.0)x\(view.1)"
                    if abs(f.0 - view.0) <= 1, f.1 == view.1 { return write("DESKTOP-FILL \(tab.name) \(last) ok") }
                }
                await settle(0.3)
            }
            write("FAIL desktop-fill \(tab.name) \(last)")
        case "web-text":
            // `web-text <seconds>|<text>`: until the latest web tab's page shows the text.
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            guard p.count == 2, let page = WebPage.latest else { return write("FAIL web-text") }
            let deadline = CFAbsoluteTimeGetCurrent() + (Double(p[0]) ?? 15)
            var found = false
            while !found && CFAbsoluteTimeGetCurrent() < deadline {
                let body = (try? await page.view.evaluateJavaScript("document.body ? document.body.innerText : ''")) as? String ?? ""
                found = body.contains(p[1])
                if !found { await settle(0.3) }
            }
            let route = UIDriver.services?.sessions.tabs.last(where: { if case .web = $0.content { return true } else { return false } })?.gatewayRoute?.summary() ?? "direct"
            write(found ? "WEB-TEXT found \(p[1]) at \(page.address) route=\(route)" : "FAIL web-text \(p[1]) at \(page.address)\(page.failure.map { " failure=\($0)" } ?? "")")
        case "web-fixture":
            // `web-fixture <https base>|<fixture>`: load a built-in B13 page into the latest web tab at that origin,
            // offline (loadHTMLString). Fixtures: login, two-passwords, hidden, iframe (cross-origin frame only).
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            guard p.count == 2, let page = WebPage.latest, let base = URL(string: p[0]), let html = WebAutofillFixtures.html[p[1]] else { return write("FAIL web-fixture \(arg)") }
            page.view.loadHTMLString(html, baseURL: base)
            for _ in 0..<40 { await settle(0.1); if !page.isLoading { break } }
            await settle(0.3)
            write("WEB-FIXTURE \(p[1]) at \(page.currentURL)")
        case "web-fill":
            // `web-fill <connection name>`: one Fill sign-in click for that connection on the latest web tab. The page
            // came from loadHTMLString, which WebKit never marks as secure, so the driver states it is (test builds only;
            // the core's not-secure refusal is covered by core-ffi tests). Reports the notice and what the page holds.
            func named(_ f: FolderView) -> ConnectionView? { f.connections.first { $0.name == arg } ?? f.folders.lazy.compactMap(named).first }
            guard let sv = UIDriver.services, let page = WebPage.latest, let library = commands.model.library,
                  let c = commands.model.tree.flatMap(named) else { return write("FAIL web-fill \(arg)") }
            let keysBefore = (try? await page.view.evaluateJavaScript("Object.keys(window).length")) as? Int ?? -1
            let notice = await WebAutofillRun.fill(page: page, connectionId: c.id, library: library, vault: sv.credentials.vault,
                                                   credentialId: c.effectiveCredentialId, isSecure: true)
            let user = (try? await page.view.evaluateJavaScript("(document.getElementById('u')||{}).value||''")) as? String ?? ""
            let pass = (try? await page.view.evaluateJavaScript("(document.getElementById('p')||{}).value||''")) as? String ?? ""
            let keysAfter = (try? await page.view.evaluateJavaScript("Object.keys(window).length")) as? Int ?? -2
            write("WEB-FILL \(arg) notice=\(notice ?? "filled") user=\(user) pass-length=\(pass.count) new-globals=\(keysAfter - keysBefore)")
        case "web-download":
            // `web-download <seconds>`: until the latest web tab's download finishes or fails.
            guard let page = WebPage.latest else { return write("FAIL web-download: no web tab") }
            let deadline = CFAbsoluteTimeGetCurrent() + (Double(arg) ?? 15)
            while CFAbsoluteTimeGetCurrent() < deadline {
                if case .finished = page.download { break }
                if case .failed = page.download { break }
                await settle(0.2)
            }
            switch page.download {
            case .finished(let url):
                let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int) ?? -1
                write("WEB-DOWNLOAD finished \(url.path) bytes=\(size)")
            case .failed(let reason): write("FAIL web-download: \(reason)")
            case .running(let name): write("FAIL web-download: still running \(name)")
            case nil: write("FAIL web-download: no download started")
            }
        case "tabs":
            guard let sv = UIDriver.services else { return write("FAIL tabs") }
            write("TABS " + sv.sessions.tabs.map { "\($0.title)(\($0.mode.rawValue), \($0.panes.count) panes\($0.layoutSteps.isEmpty ? "" : ": " + $0.layoutSteps.joined(separator: " "))\($0.id == sv.sessions.selected ? ", selected" : ""))" }.joined(separator: " | ") + (sv.sessions.error.map { " ERROR \($0)" } ?? ""))
        case "title-bar":
            // Spec §3: what the session title bar shows for the selected tab.
            guard let sv = UIDriver.services, let tab = sv.sessions.selectedTab, let id = tab.connectionId,
                  let c = commands.model.connection(id: id) else { return write("TITLE-BAR none") }
            write("TITLE-BAR \(SessionLinkState.of(tab).rawValue) \(sessionAddress(user: c.username, host: c.host, port: c.port))")
        case "recents":
            write("RECENTS " + (DriverEvents.recentNames.isEmpty ? "none" : DriverEvents.recentNames.joined(separator: ", ")))
        case "recent":
            let parts = arg.split(separator: " ", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { return write("FAIL recent: want open|remove|pick <name>") }
            NotificationCenter.default.post(name: DriverEvents.recentAction, object: parts)
            await settle(0.8)
            write("RECENT \(arg)")
        case "title-bar-button":
            NotificationCenter.default.post(name: DriverEvents.pressTitleBarButton, object: arg)
            await settle(0.8)
            write("TITLE-BAR-BUTTON \(arg)")
        case "pin-tab":
            // `pin-tab <index>`: pin the tab at that strip index (small icon-only tab on the left).
            guard let sv = UIDriver.services, let i = Int(arg), sv.sessions.tabs.indices.contains(i) else { return write("FAIL pin-tab") }
            sv.sessions.setPinned(sv.sessions.tabs[i], true)
            await settle(0.4)
            write("PINNED \(sv.sessions.tabs.filter(\.pinned).count) first=\(sv.sessions.tabs.first?.pinned == true)")
        case "tab-window", "tab-drop-outside", "tab-drop-inside":
            // Tear-off (TabWindows.swift): `tab-window <i>` is right-click › Move Tab to New Window;
            // `tab-drop-*` end a drag of tab <i> on no drop target, outside every window or over
            // the main window, through the same check a real drag ends in.
            guard let sv = UIDriver.services, let i = Int(arg), sv.sessions.tabs.indices.contains(i) else { return write("FAIL \(cmd)") }
            let s = sv.sessions, tab = s.tabs[i]
            switch cmd {
            case "tab-window": s.moveToWindow(tab)
            case "tab-drop-inside":
                guard let w = window else { return write("FAIL tab-drop-inside: no main window") }
                TabDrag.ended(tab, at: NSPoint(x: w.frame.midX, y: w.frame.midY), sessions: s)
            default:
                let frames = NSApp.windows.filter(\.isVisible).map(\.frame)
                let outside = (NSScreen.screens.flatMap { [NSPoint(x: $0.frame.minX + 5, y: $0.frame.minY + 5),
                                                           NSPoint(x: $0.frame.maxX - 5, y: $0.frame.maxY - 5)] })
                    .first { TabDrag.tearsOff(at: $0, windowFrames: frames) }
                guard let outside else { return write("FAIL tab-drop-outside: windows cover every screen corner") }
                TabDrag.ended(tab, at: outside, sessions: s)
            }
            await settle(1.0)
            let window = s.windowed[tab.id]
            let shown = window.flatMap { TabWindows.windows[$0]?.isVisible } == true
            let want = cmd != "tab-drop-inside"
            write("\((window != nil) == want && shown == want ? "" : "FAIL ")TAB-WINDOW \(cmd) \(Self.windowSummary(s))")
        case "tab-window-frame":
            // B12: `tab-window-frame <i> <x> <y> <w> <h>` moves and sizes tab i's torn-off window
            // (screen points, AppKit bottom-left origin), as a drag and resize would end.
            let n = arg.split(separator: " ").compactMap { Double($0) }
            guard let sv = UIDriver.services, n.count == 5, sv.sessions.tabs.indices.contains(Int(n[0])),
                  let w = sv.sessions.windowed[sv.sessions.tabs[Int(n[0])].id], let win = TabWindows.windows[w] else { return write("FAIL tab-window-frame \(arg)") }
            win.setFrame(NSRect(x: n[1], y: n[2], width: n[3], height: n[4]), display: true)
            NotificationCenter.default.post(name: NSWindow.didEndLiveResizeNotification, object: win)
            await settle(1.0)
            write("TAB-WINDOW-FRAME \(Self.frameText(win.frame))")
        case "tab-windows":
            // B12: per tab its window (main, or w<n> in order of first tab) and each torn-off
            // window's frame, front tab and whether a screen shows enough of it.
            guard let s = UIDriver.services?.sessions else { return write("FAIL tab-windows") }
            var order: [UUID] = []
            let places = s.tabs.map { t -> String in
                guard let w = s.windowed[t.id] else { return "main" }
                if !order.contains(w) { order.append(w) }
                return "w\(order.firstIndex(of: w)! + 1)"
            }
            let frames = order.enumerated().map { i, w -> String in
                guard let win = TabWindows.windows[w], win.isVisible else { return "w\(i + 1)=hidden" }
                let front = s.windowSelected[w].flatMap { f in s.tabs.firstIndex { $0.id == f } }.map(String.init) ?? "-"
                let shown = TabWindows.onScreen(win.frame, screens: TabWindows.visibleScreens) == win.frame
                return "w\(i + 1)=\(Self.frameText(win.frame)) front=\(front) onScreen=\(shown)"
            }
            write("TAB-WINDOWS tabs=\(places.joined(separator: ",")) \(frames.joined(separator: " "))")
        case "tab-window-close":
            // B12: `tab-window-close <i>`: the close button of tab i's torn-off window. Its tabs are
            // closed as closing them one by one would (asking first when they are live).
            guard let sv = UIDriver.services, let i = Int(arg), sv.sessions.tabs.indices.contains(i),
                  let w = sv.sessions.windowed[sv.sessions.tabs[i].id], let win = TabWindows.windows[w] else { return write("FAIL tab-window-close \(arg)") }
            win.performClose(nil)
            await settle(1.0)
            write("TAB-WINDOW-CLOSE \(Self.windowSummary(sv.sessions))")
        case "tab-window-clamp-check":
            // B12: the on-screen rule against fixed screens (no real monitors needed).
            let main = NSRect(x: 0, y: 0, width: 1440, height: 875), left = NSRect(x: -1920, y: 0, width: 1920, height: 1055)
            let cases: [(NSRect, [NSRect], NSRect)] = [
                (NSRect(x: 100, y: 100, width: 800, height: 500), [main], NSRect(x: 100, y: 100, width: 800, height: 500)),
                (NSRect(x: -1500, y: 200, width: 800, height: 500), [main, left], NSRect(x: -1500, y: 200, width: 800, height: 500)),
                (NSRect(x: -1500, y: 200, width: 800, height: 500), [main], NSRect(x: 320, y: 187.5, width: 800, height: 500)),
                (NSRect(x: 1400, y: 100, width: 800, height: 500), [main], NSRect(x: 320, y: 187.5, width: 800, height: 500)),
                (NSRect(x: 1300, y: 100, width: 800, height: 500), [main], NSRect(x: 1300, y: 100, width: 800, height: 500)),
                (NSRect(x: 5000, y: 5000, width: 3000, height: 2000), [main], NSRect(x: 0, y: 0, width: 1440, height: 875)),
            ]
            let bad = cases.enumerated().filter { TabWindows.onScreen($0.element.0, screens: $0.element.1) != $0.element.2 }.map(\.offset)
            write("\(bad.isEmpty ? "" : "FAIL ")TAB-WINDOW-CLAMP cases=\(cases.count) failed=\(bad)")
        case "tab-merge":
            // `tab-merge <i> <j>`: drop tab i on tab j (in whichever window): it joins j's window.
            let ij = arg.split(separator: " ").compactMap { Int($0) }
            guard let sv = UIDriver.services, ij.count == 2, ij.allSatisfy(sv.sessions.tabs.indices.contains) else { return write("FAIL tab-merge") }
            let s = sv.sessions, dragged = s.tabs[ij[0]], target = s.tabs[ij[1]]
            s.dropTab(dragged.id.uuidString, onto: target)
            await settle(1.0)
            let ok = s.windowed[dragged.id] == s.windowed[target.id]
                && (s.windowed[target.id].map { s.windowSelected[$0] == dragged.id } ?? (s.selected == dragged.id))
            write("\(ok ? "" : "FAIL ")TAB-MERGE \(arg) \(Self.windowSummary(s))")
        case "tab-window-back", "tab-window-close":
            // `tab-window-back`: a torn-off window's Move to Main Window; `tab-window-close`: its
            // red button (asks like ⌘W per tab; `close-answer` scripts the answer).
            guard let sv = UIDriver.services, let window = sv.sessions.windowed.values.first,
                  let w = TabWindows.windows[window] else { return write("FAIL \(cmd): no torn-off window") }
            let s = sv.sessions, ids = s.tabs(inWindow: window).map(\.id)
            if cmd == "tab-window-back" { s.windowClosed(window); w.close() } else { w.standardWindowButton(.closeButton)?.performClick(nil) }
            await settle(1.0)
            let back = ids.filter { id in s.tabs.contains { $0.id == id } }
            let bad = w.isVisible || back.contains { s.windowed[$0] != nil }
            write("\(bad ? "FAIL " : "")TAB-WINDOW \(cmd) tabs=\(ids.count) stillOpen=\(back.count) \(Self.windowSummary(s))")
        case "tab-select":
            // `tab-select <i>`: pick tab <i> as All Tabs does; a torn-off one brings its window forward.
            guard let sv = UIDriver.services, let i = Int(arg), sv.sessions.tabs.indices.contains(i) else { return write("FAIL tab-select") }
            let s = sv.sessions, tab = s.tabs[i]
            s.selected = tab.id
            let window = s.windowed[tab.id]
            // Frontmost of the app's windows (key needs the app active, which a loaded Mac may not give).
            // Polled: a loaded Mac can take over half a second to reorder.
            func picked() -> Bool {
                window.map { s.selected != tab.id && NSApp.orderedWindows.first === TabWindows.windows[$0] && s.windowSelected[$0] == tab.id }
                    ?? (s.selected == tab.id)
            }
            await settle(0.5)
            for _ in 0..<25 where !picked() { await settle(0.1) }
            let ok = picked()
            write("\(ok ? "" : "FAIL ")TAB-SELECT \(i) torn=\(window != nil) key=\(NSApp.keyWindow?.title ?? "-") front=\(NSApp.orderedWindows.prefix(3).map { "\(type(of: $0)):\($0.title)" }) mainSel=\(s.selected == tab.id) winSel=\(window.map { s.windowSelected[$0] == tab.id } ?? false) known=\(window.map { TabWindows.windows[$0] != nil } ?? false)\(ok ? "" : " diag=" + Self.tabWindowDiag(window))")
        case "session-shells":
            // `session-shells <n> <connection name|->`: n local shells linked to that library
            // connection ("-": none), named "Terminal k". Each add is timed through the tree's diff (UI-05 A8).
            let parts = arg.split(separator: " ", maxSplits: 1).map(String.init)
            guard let sv = UIDriver.services, parts.count == 2, let n = Int(parts[0]), let c = outline?.coordinator else { return write("FAIL session-shells") }
            let id: String? = parts[1] == "-" ? nil : c.commands.model.tree.flatMap { t in
                func find(_ f: FolderView) -> String? { f.connections.first { $0.name == parts[1] }?.id ?? f.folders.lazy.compactMap(find).first }
                return find(t)
            }
            if parts[1] != "-" && id == nil { return write("FAIL session-shells: no connection \(parts[1])") }
            let reloads = c.fullReloads
            var worst = 0.0
            for k in 0..<n {
                do {
                    let t = try LocalShellAgent.terminal(LocalShellAgent.plan(), cols: 80, rows: 24)
                    sv.sessions.add(TerminalTab(name: "Terminal \(sv.sessions.tabs.count + 1)", content: .terminal(t), connectionId: id))
                } catch { return write("FAIL session-shells \(k): \(error)") }
                await settle(0.05)
                worst = max(worst, c.lastSessionMs)
            }
            await settle(0.5)
            let ok = c.fullReloads == reloads && worst < 50
            write((ok ? "" : "FAIL ") + String(format: "SESSIONS tabs=%d full-reloads=%d worst-diff=%.2f ms", sv.sessions.tabs.count, c.fullReloads - reloads, worst))
        case "session-close":
            // `session-close <title>`: close one tab (no question), timing the tree diff.
            guard let sv = UIDriver.services, let c = outline?.coordinator,
                  let tab = sv.sessions.tabs.first(where: { $0.title == arg }) else { return write("FAIL session-close \(arg)") }
            let reloads = c.fullReloads
            sv.sessions.close(tab)
            await settle(0.2)
            write(String(format: "SESSION-CLOSED %@ full-reloads=%d diff=%.2f ms", arg, c.fullReloads - reloads, c.lastSessionMs))
        case "session-close-all":
            // Close every tab one by one, reporting the slowest tree diff (UI-05 A8).
            guard let sv = UIDriver.services, let c = outline?.coordinator else { return write("FAIL session-close-all") }
            let reloads = c.fullReloads
            var worst = 0.0
            while let tab = sv.sessions.tabs.last {
                sv.sessions.close(tab)
                await settle(0.05)
                worst = max(worst, c.lastSessionMs)
            }
            await settle(0.3)
            let ok = c.fullReloads == reloads && worst < 50
            write((ok ? "" : "FAIL ") + String(format: "SESSIONS-CLOSED tabs=%d full-reloads=%d worst-diff=%.2f ms", sv.sessions.tabs.count, c.fullReloads - reloads, worst))
        case "session-click":
            // `session-click <title>`: click the session row; its tab must become the selected one
            // in its own window (UI-05 A2).
            guard let sv = UIDriver.services, let r = row(named: "●" + arg), let outline,
                  let s = (outline.item(atRow: r) as? OutlineNode)?.session else { return write("FAIL session-click \(arg): no row") }
            outline.window?.makeFirstResponder(outline)
            outline.selectRowIndexes([r], byExtendingSelection: false)
            outline.coordinator?.activateSelection()
            await settle(0.5)
            let window = sv.sessions.windowed[s.tabId]
            let ok = window.map { sv.sessions.windowSelected[$0] == s.tabId } ?? (sv.sessions.selected == s.tabId)
            write("\(ok ? "" : "FAIL ")SESSION-FOCUS \(arg) tab=\(s.tabId.uuidString.prefix(8)) torn=\(window != nil)")
        case "collapse-row":
            // `collapse-row <name>`: collapse through the outline (as the disclosure triangle does).
            guard let r = row(named: arg), let outline, let n = outline.item(atRow: r) else { return write("FAIL collapse-row \(arg)") }
            outline.collapseItem(n)
            write("COLLAPSE \(arg) expanded-now=\(outline.isItemExpanded(n))")
            await settle(0.3)
            write("COLLAPSE \(arg) expanded-after=\(outline.isItemExpanded(n))")
        case "tree-has", "tree-lacks":
            // `tree-has <text>`: some visible tree row (as `dump` writes it, trimmed) equals text.
            let rows = dump().split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "  [selected]", with: "") }
            let found = rows.contains { $0 == arg || $0.dropFirst(2) == arg }
            let ok = found == (cmd == "tree-has")
            write("\(ok ? "" : "FAIL ")\(line)\(ok ? "" : "\nTREE\n" + dump())")
        case "tree-fit":
            // `tree-fit <tag>`: every visible tree row's cell fits (UI-05 layout fit): no dot or icon
            // over the name, no clipped count; a truncated title must carry the full text as tooltip.
            guard let outline else { return write("FAIL tree-fit") }
            let range = outline.rows(in: outline.visibleRect)
            var problems: [String] = []
            for r in range.location..<(range.location + range.length) {
                guard let n = outline.item(atRow: r) as? OutlineNode, !n.isGroup,
                      let cell = outline.view(atColumn: 0, row: r, makeIfNecessary: false) as? OutlineCell else { continue }
                problems += cell.fitProblems().map { "\(name(of: n)): \($0)" }
                if let s = n.session, cell.textField.map({ $0.fittingSize.width > $0.frame.width + 0.5 }) == true,
                   !(cell.toolTip ?? "").contains(s.title) { problems.append("\(name(of: n)): truncated without tooltip") }
            }
            write("\(problems.isEmpty ? "" : "FAIL ")TREE-FIT \(arg) rows=\(range.length) width=\(Int(outline.bounds.width))\(problems.isEmpty ? "" : " " + problems.joined(separator: "; "))")
        case "row-label":
            // `row-label <name>`: a tree row's accessible name and its marker's tooltip (PLUG-03a).
            guard let r = row(named: arg), let cell = outline?.view(atColumn: 0, row: r, makeIfNecessary: true) as? OutlineCell else { return write("FAIL row-label \(arg)") }
            write("ROW-LABEL \(cell.accessibilityLabel() ?? "-") | marker=\(cell.markerText ?? "-")")
        case "session-label":
            // `session-label <title>`: the row's accessible name (UI-05 A11).
            guard let r = row(named: "●" + arg), let cell = outline?.view(atColumn: 0, row: r, makeIfNecessary: true) as? NSView else { return write("FAIL session-label \(arg)") }
            write("SESSION-LABEL \(cell.accessibilityLabel() ?? "-")")
        case "named-shells":
            // `named-shells <title>[|<title>…]`: one local shell per title, named like a connected tab
            // (long-name tab layout-fit). Titles are split on |.
            guard let sv = UIDriver.services, !arg.isEmpty else { return write("FAIL named-shells") }
            for title in arg.split(separator: "|").map(String.init) {
                do {
                    let t = try LocalShellAgent.terminal(LocalShellAgent.plan(), cols: 80, rows: 24)
                    sv.sessions.add(TerminalTab(name: title, content: .terminal(t)))
                } catch { return write("FAIL named-shells: \(error)") }
            }
            await settle(1.0)
            write("SHELLS tabs=\(sv.sessions.tabs.count)")
        case "tab-titles":
            // `tab-titles [full]`: each strip tab's title, laid-out width and full-title width; a tab
            // narrower than its full title is ellipsized. `full`: FAIL when any is (owner 2026-11-16:
            // titles show in full while the bar has room).
            guard let sv = UIDriver.services else { return write("FAIL tab-titles") }
            var cut: [String] = []
            var rows: [String] = []
            for tab in sv.sessions.mainTabs where !tab.pinned {
                guard let frame = DriverEvents.headerFrame("strip-tab-" + tab.id.uuidString) else { continue }
                let shown = frame.width, full = TabButton.contentWidth(tab)
                if shown + 0.5 < full { cut.append(tab.title) }
                rows.append("\(tab.title)=\(Int(shown))/\(Int(full))")
            }
            let head = arg == "full" && !cut.isEmpty ? "FAIL tab-titles ellipsized: \(cut.joined(separator: ", "))" : "TAB-TITLES"
            write("\(head) tabs=\(rows.count) ellipsized=\(cut.count) | \(rows.joined(separator: " "))")
        case "tab-title-expect":
            // `tab-title-expect <text>|name|len:<n>`: the selected tab's name in the strip and in the
            // sidebar's session rows is <text>, its own default name, or <n> characters long.
            guard let sv = UIDriver.services, let tab = sv.sessions.selectedTab else { return write("FAIL tab-title-expect: no tab") }
            let rows = sv.sessions.sessionRows { self.commands.model.connection(id: $0) != nil }
            let row = (rows.other + rows.byConnection.values.joined()).first { $0.tabId == tab.id }?.title ?? "-"
            let want: (String) -> Bool = arg == "name" ? { $0 == tab.name }
                : arg.hasPrefix("len:") ? { $0.count == Int(arg.dropFirst(4)) ?? -1 } : { $0 == arg }
            let ok = want(tab.title) && want(row)
            write("\(ok ? "" : "FAIL ")TAB-TITLE strip='\(tab.title)' sidebar='\(row)' name='\(tab.name)' want=\(arg)")
        case "local-shells":
            // `local-shells <n>`: open n local shells (tab strip overflow tests).
            guard let sv = UIDriver.services, let n = Int(arg) else { return write("FAIL local-shells") }
            let start = Date()
            for _ in 0..<n { sv.sessions.openLocal() }
            await settle(1.0)
            write("SHELLS tabs=\(sv.sessions.tabs.count) ms=\(Int(Date().timeIntervalSince(start) * 1000))")
        case "group-window":
            // `group-window <group index>`: the chip menu's Move Group to New Window.
            guard let s = UIDriver.services?.sessions, let i = Int(arg), s.groups.indices.contains(i) else { return write("FAIL group-window") }
            let gid = s.groups[i].id
            s.moveGroupToWindow(gid)
            await settle(1.0)
            let moved = s.tabs.filter { $0.group == gid }
            let ok = !moved.isEmpty && Set(moved.map { s.windowed[$0.id] }).count == 1 && moved.allSatisfy { s.windowed[$0.id] != nil }
            write("\(ok ? "" : "FAIL ")GROUP-WINDOW tabs=\(moved.count) windows=\(NSApp.windows.filter(\.isVisible).count)")
        case "tab-drop-end":
            // `tab-drop-end <tab index>`: a tab dropped past the last tab (on +) leaves its group.
            guard let s = UIDriver.services?.sessions, let i = Int(arg), s.tabs.indices.contains(i) else { return write("FAIL tab-drop-end") }
            let id = s.tabs[i].id
            s.dropTabAtEnd(id.uuidString)
            await settle(0.4)
            let ok = s.tabs.last?.id == id && s.tabs.last?.group == nil
            write("\(ok ? "" : "FAIL ")TAB-DROP-END last=\(s.tabs.last?.id == id) grouped=\(s.tabs.last?.group != nil)")
        case "strip":
            guard let sv = UIDriver.services else { return write("FAIL strip") }
            let s = sv.sessions
            let groups = s.groups.map { g in "\(g.name):\(g.color):\(g.collapsed ? "collapsed" : "open"):\(s.tabs.filter { $0.group == g.id }.count)" }
            let selected = s.tabs.firstIndex { $0.id == s.selected }.map(String.init) ?? "none"
            write("STRIP tabs=\(s.tabs.count) allTabs=\(s.showingAllTabs) gate=\(LaunchGate.shared.isOpen) menus=\(NSApp.mainMenu?.items.map { "\($0.title):\($0.submenu?.items.count ?? 0)" }.joined(separator: ",") ?? "-") hidden=\(s.tabs.filter(s.isHidden).count) selected=\(selected) groups=[\(groups.joined(separator: ", "))]"
                  + (s.error.map { " ERROR \($0)" } ?? ""))
        case "strip-op":
            // `strip-op {"op": "newGroup", "tabs": [0, 1]}`: a core StripOp with tabs and groups given by index.
            guard let sv = UIDriver.services, var op = (try? JSONSerialization.jsonObject(with: Data(arg.utf8))) as? [String: Any] else {
                return write("FAIL strip-op: bad JSON")
            }
            let s = sv.sessions
            let tabId = { (i: Int) in s.tabs.indices.contains(i) ? s.tabs[i].id.uuidString : "" }
            if let i = op["tab"] as? Int { op["tab"] = tabId(i) }
            if let list = op["tabs"] as? [Int] { op["tabs"] = list.map(tabId) }
            if let i = op["group"] as? Int { op["group"] = s.groups.indices.contains(i) ? s.groups[i].id : "" }
            let start = Date()
            s.error = nil
            s.groupOp(op)
            let ms = Int(Date().timeIntervalSince(start) * 1000)
            await settle(0.4)
            write("STRIP-OP \(op["op"] ?? "?") ms=\(ms)" + (s.error.map { " ERROR \($0)" } ?? ""))
        case "group-edit":
            // `group-edit <i>`: open group <i>'s editor popover on its chip (a click on the chip);
            // `group-edit -` closes it.
            guard let s = UIDriver.services?.sessions else { return write("FAIL group-edit: no sessions") }
            if arg == "-" { s.editingGroup = nil; await settle(0.3); return write("GROUP-EDIT closed") }
            guard let i = Int(arg), s.groups.indices.contains(i) else { return write("FAIL group-edit: no group \(arg)") }
            s.editingGroup = s.groups[i].id
            await settle(0.5)
            write("GROUP-EDIT \(s.groups[i].name.isEmpty ? "unnamed" : s.groups[i].name)")
        case "session-lock":
            // As fast user switching away: posted on NSWorkspace's centre, so the app's own observer runs.
            // (The distributed `com.apple.screenIsLocked` is not posted: other apps would see it too.)
            NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.sessionDidResignActiveNotification, object: NSWorkspace.shared)
            await settle(0.3)
            write("SESSION-LOCK -> \(vaultState())")
        case "vault-confirm":
            // Ask to open the vault with Touch ID confirmation on; the system prompt stays up until `vault-confirm-cancel`.
            guard let sv = UIDriver.services else { return write("FAIL vault-confirm") }
            Task { await sv.credentials.openInBackground(sessions: sv.sessions) }
            await settle(1.5)
            write("VAULT-CONFIRM prompt \(sv.credentials.pendingConfirmation != nil ? "shown" : "not shown") -> \(vaultState())")
        case "vault-confirm-cancel":
            guard let sv = UIDriver.services else { return write("FAIL vault-confirm-cancel") }
            sv.credentials.pendingConfirmation?.invalidate()
            await settle(0.8)
            write("VAULT-CONFIRM-CANCEL -> \(vaultState()); error: \(sv.credentials.error ?? "none")")
        case "web-go", "web-back", "web-forward", "web-state", "web-click":
            // The latest web tab: `web-go <typed address>`, back, forward, `web-click` (first link), state.
            guard let page = WebPage.latest else { return write("FAIL \(cmd): no web tab") }
            switch cmd {
            case "web-go": _ = page.go(arg)
            case "web-back": page.back()
            case "web-forward": page.forward()
            case "web-click": _ = try? await page.view.evaluateJavaScript("document.querySelector('a').click()")
            default: break
            }
            for _ in 0..<40 { await settle(0.1); if !page.isLoading { break } }
            await settle(0.3)
            write("WEB \(cmd) \(arg) -> \(page.address) title=\(page.title) back=\(page.canGoBack) forward=\(page.canGoForward) (webkit \(page.view.backForwardList.backList.count)/\(page.view.backForwardList.forwardList.count)) secure=\(page.isSecure)\(page.failure.map { " failure=\($0)" } ?? "")")
        case "theme":
            // `theme <name>`: select a theme in the open Terminal Themes editor.
            guard let themes = UIDriver.services?.themes, let t = themes.items.first(where: { $0.name == arg }) else { return write("FAIL theme \(arg)") }
            themes.scriptedSelection = t.id
            await settle(0.5)
            write("THEME \(arg) contrast \(String(format: "%.1f", t.contrast)) bundled=\(t.bundled)")
        case "theme-copy":
            // `theme-copy <source name>|<new name>|<background hex>`: duplicate, rename, recolour, save (what the editor's
            // Duplicate, name field, colour well and Save do; the system colour panel itself cannot be scripted).
            let p = arg.split(separator: "|").map(String.init)
            guard p.count == 3, let themes = UIDriver.services?.themes, let src = themes.items.first(where: { $0.name == p[0] }),
                  var t = themes.duplicate(src.id), let bg = UInt32(p[2].trimmingCharacters(in: CharacterSet(charactersIn: "#")), radix: 16) else {
                return write("FAIL theme-copy \(arg)")
            }
            t.name = p[1]
            t.background = bg
            write(themes.save(t) ? "THEME-COPY \(p[1]) = \(t.id)" : "FAIL theme-copy: \(themes.error ?? "?")")
        case "themes":
            guard let themes = UIDriver.services?.themes else { return write("FAIL themes") }
            write("THEMES \(themes.items.count) (\(themes.items.filter { !$0.bundled }.map(\.name).joined(separator: ", ")))")
        case "clipboard-request", "clipboard-allow":
            guard let pane = UIDriver.services?.sessions.selectedTab?.panes.first(where: { $0.clipboardRequest != nil }) else {
                return write("\(cmd.uppercased()) none")
            }
            let text = pane.clipboardRequest ?? ""
            // Allow does what the bar's Allow button does.
            if cmd == "clipboard-allow" { TerminalClipboard.copy(text); pane.clipboardRequest = nil }
            write("\(cmd.uppercased()) \(text.count) chars: \(text)")
        case "log-files":
            // `log-files <text>`: every log under session-logs (v2 nests them by folder), with whether
            // it contains <text>, its mode, header and footer, and any escape code (LOG-CORE-02).
            let dir = LibraryModel.dataDir.appendingPathComponent("session-logs")
            let perms = (try? FileManager.default.attributesOfItem(atPath: dir.path)[.posixPermissions] as? Int).map { String($0, radix: 8) } ?? "?"
            let all = (FileManager.default.enumerator(atPath: dir.path)?.allObjects as? [String] ?? []).filter { SessionLogFiles.isLogName(($0 as NSString).lastPathComponent) }
            write("LOG-FILES dir \(perms) count \(all.count): " + all.sorted().map { f in
                let url = dir.appendingPathComponent(f)
                let body = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
                let mode = (try? FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int).map { String($0, radix: 8) } ?? "?"
                return "\(f) mode \(mode) contains \(arg): \(body.contains(arg)), keystroke-free header: \(body.hasPrefix("# Gantry session log")), end reason: \(body.range(of: "# end reason: [a-z]+", options: .regularExpression).map { String(body[$0].dropFirst(14)) } ?? "none"), escape codes: \(body.contains("\u{1b}"))"
            }.joined(separator: "; "))
        case "snippet-add":
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            guard p.count == 2, let sn = UIDriver.services?.snippets else { return write("FAIL snippet-add") }
            write(sn.put(name: p[0], text: p[1], id: nil) ? "SNIPPET-ADD \(p[0])" : "SNIPPET-ADD refused: \(sn.error ?? "?")")
            sn.error = nil
        case "snippet-send":
            // As the sheet's Send for a one-line snippet.
            guard let sv = UIDriver.services, let s = sv.snippets.items.first(where: { $0.name == arg }) else { return write("FAIL snippet-send \(arg)") }
            // Through the core store's send; a multi-line or multi-tab send is confirmed as the dialog would.
            var r = sv.snippets.send(s, sessions: sv.sessions, confirmed: false)
            let asked = r == .needsConfirm
            if asked { r = sv.snippets.send(s, sessions: sv.sessions, confirmed: true) }
            await settle(0.3)
            guard case .sent(let tabs) = r else { return write("FAIL snippet-send \(arg): \(sv.snippets.error ?? "not sent")") }
            write("SNIPPET-SEND \(arg) tabs=\(tabs)\(asked ? " confirmed" : "")")
        case "snippet-send-vars":
            // As the sheet's Send with Replace $Variables$ on; a refusal is logged with its reason.
            guard let sv = UIDriver.services, let s = sv.snippets.items.first(where: { $0.name == arg }) else { return write("FAIL snippet-send-vars \(arg)") }
            do {
                sv.sessions.sendToFocused(try SnippetVariables.resolve(s.text, sessions: sv.sessions, library: commands.model))
                await settle(0.3)
                write("SNIPPET-SEND-VARS \(arg)")
            } catch {
                write("SNIPPET-SEND-VARS refused: \(error)")
            }
        case "broadcast-all":
            // As the Broadcast sheet with every terminal tab ticked, after its confirmation.
            guard let sv = UIDriver.services else { return write("FAIL broadcast-all") }
            sv.sessions.startBroadcast(Set(sv.sessions.tabs.filter { $0.terminal != nil && !$0.ended }.map(\.id)))
            await settle(0.4)
            write("BROADCAST \(sv.sessions.broadcastTargets.count) sessions")
        case "broadcast-stop":
            UIDriver.services?.sessions.stopBroadcast()
            await settle(0.3)
            write("BROADCAST stopped")
        case "top-alert":
            // A button of the deepest sheet (an alert or confirmation shown over a sheet), by title.
            await settle(0.4)
            // SwiftUI dialog buttons carry no title: `#n` picks the n-th button instead.
            let buttons = topSheet?.contentView?.allSubviews(of: NSButton.self) ?? []
            let indexed = arg.hasPrefix("#") ? Int(arg.dropFirst()).flatMap { $0 < buttons.count ? buttons[$0] : nil } : nil
            guard let b = indexed ?? buttons.first(where: { $0.title == arg }) else {
                return write("FAIL top-alert \(arg): \(topSheet?.contentView?.allSubviews(of: NSButton.self).map(\.title).joined(separator: "|") ?? "no sheet")")
            }
            b.performClick(nil)
            await settle(0.6)
            write("TOP-ALERT \(arg)")
        case "top-secure":
            // `top-secure <ENV_VAR>[|n]`: the n-th (default first) secure field of the deepest sheet, from that file.
            let p = arg.split(separator: "|").map(String.init)
            let index = p.count > 1 ? Int(p[1]) ?? 0 : 0
            guard let dialog = topDialog, let file = ProcessInfo.processInfo.environment[p[0]],
                  let text = try? String(contentsOfFile: file, encoding: .utf8).trimmingCharacters(in: .newlines) else { return write("FAIL top-secure") }
            let fields = dialog.views(of: NSSecureTextField.self)
            guard index < fields.count else { return write("FAIL top-secure") }
            let f = fields[index]
            fill(f, text, in: dialog.window)
            write("TOP-SECURE set")
        case "top-checkbox":
            // The n-th (0-based) checkbox or switch of the deepest sheet, clicked.
            let boxes = topSheet?.contentView?.allSubviews(of: NSButton.self).filter { b in
                b is NSSwitch || (b.cell as? NSButtonCell).map { $0.value(forKey: "buttonType") as? UInt == NSButton.ButtonType.switch.rawValue } == true
            } ?? []
            let switches = topSheet?.contentView?.allSubviews(of: NSSwitch.self) ?? []
            guard let n = Int(arg) else { return write("FAIL top-checkbox") }
            // Checkboxes first, then switches, each in view order.
            let all: [NSControl] = boxes.filter { !($0 is NSSwitch) } + switches
            guard n < all.count else { return write("FAIL top-checkbox \(arg) (\(all.count) boxes)") }
            all[n].performClick(nil)
            await settle(0.4)
            write("TOP-CHECKBOX \(arg)")
        case "exec-ack":
            MultiExecView.scriptedAck = true
            write("EXEC-ACK (chosen at last review: \(MultiExecView.lastChosen.joined(separator: ",")))")
        case "exec-hosts":
            MultiExecView.scriptedHosts = arg.split(separator: ",").map(String.init)
            write("EXEC-HOSTS \(arg)")
        case "exec-results":
            guard let run = MultiExecView.current else { return write("FAIL exec-results: no run") }
            for _ in 0..<120 where !run.isFinished() { await settle(0.5) }
            write("EXEC-RESULTS " + run.results().map { "\($0.host)=\($0.state)/\($0.exit.map(String.init) ?? "-") \($0.stdout.trimmingCharacters(in: .whitespacesAndNewlines))\($0.error.map { " (\($0))" } ?? "")" }.joined(separator: " | "))
        case "ansible-set":
            // `ansible-set key=value`: a field of the Run Ansible sheet, applied when it opens.
            let kv = arg.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            if kv.count == 2 { AnsibleRunView.scripted[kv[0]] = kv[1] }
            write("ANSIBLE-SET \(arg)")
        case "ansible-plan":
            write("ANSIBLE-\(AnsibleRunView.lastPlan)")
        case "ansible-run":
            // Press Run on the open Run Ansible sheet; `ansible-plan` then shows MISSING / STARTED.
            guard let run = AnsibleRunView.runNow else { return write("FAIL ansible-run: no sheet") }
            run()
            write("ANSIBLE-RUN")
        case "ansible-save":
            // Press Save as Task on the open Run Ansible sheet; `ansible-plan` then shows SAVED <runOn> <name>.
            guard let save = AnsibleRunView.saveNow else { return write("FAIL ansible-save: no sheet") }
            save()
            write("ANSIBLE-SAVE")
        case "wait-sheet":
            // `wait-sheet <seconds>`: until a sheet opens on the main window (for example from the CLI).
            let deadline = CFAbsoluteTimeGetCurrent() + (Double(arg) ?? 20)
            // A sheet, or a dialog that opens as a window panel (InWindowPanel).
            func shown() -> Bool { window?.attachedSheet != nil || panelDialog != nil }
            while !shown() && CFAbsoluteTimeGetCurrent() < deadline { await settle(0.2) }
            write(shown() ? "WAIT-SHEET shown" : "FAIL wait-sheet")
        case "tunnel-start":
            // As the Tunnel Manager's Start: the connect sheet of the tunnel's SSH connection, in tunnel mode.
            guard let lib = commands.model.library, let t = (try? lib.findTunnel(key: arg)) ?? nil, let via = commands.model.connection(id: t.viaId) else {
                return write("FAIL tunnel-start \(arg)")
            }
            commands.enqueue([ConnectRequest(connection: via, mode: .tunnel, tunnelId: t.id)], select: nil)
            await settle(0.5)
            write("TUNNEL-START \(arg)")
        case "tunnel-stop":
            guard let sv = UIDriver.services, let lib = commands.model.library, let t = (try? lib.findTunnel(key: arg)) ?? nil else { return write("FAIL tunnel-stop") }
            sv.sessions.runningTunnels[t.id]?.stop()
            sv.sessions.runningTunnels[t.id] = nil
            write("TUNNEL-STOP \(arg)")
        case "tunnel-put":
            // `tunnel-put <name>|<via connection>|<SOCKS port>`: a saved SOCKS tunnel that starts with its connection (PAR-C-MAC).
            let p = arg.split(separator: "|").map(String.init)
            guard p.count == 3, let lib = commands.model.library, let port = UInt16(p[2]),
                  let via = AppIpc.connections(in: commands.model.tree).first(where: { $0.name == p[1] }) else { return write("FAIL \(line)") }
            do {
                _ = try lib.putTunnel(tunnel: TunnelDefView(id: "", name: p[0], viaId: via.id, viaName: via.name, kind: "dynamic", localPort: port,
                                                            host: "", port: 0, summary: "", startWithConnection: true))
                try lib.save(); commands.model.reload(); write("TUNNEL-PUT \(p[0])")
            } catch { write("FAIL \(line): \(errorText(error))") }
        case "connect-key":
            // `connect-key <connection>|<user>|<key file>`: an SSH tab signed in with a lab-only key file (no password is
            // typed); an unknown host key is trusted for this lab run only.
            let p = arg.split(separator: "|").map(String.init)
            guard p.count == 3, let sv = UIDriver.services, let lib = commands.model.library,
                  let c = AppIpc.connections(in: commands.model.tree).first(where: { $0.name == p[0] }) else { return write("FAIL \(line)") }
            let login = SshLogin.keyFile(path: (p[2] as NSString).expandingTildeInPath, passphrase: nil)
            var result = await sv.sessions.connect(library: lib, connectionId: c.id, username: p[1], login: login, trust: nil)
            if case .unknownHost(nil, let fp) = result {
                result = await sv.sessions.connect(library: lib, connectionId: c.id, username: p[1], login: login, trust: fp)
            }
            guard case .connected(.terminal(let t)) = result else { return write("FAIL \(line): \(result)") }
            sv.sessions.add(TerminalTab(name: c.name, content: .terminal(t), connectionId: c.id))
            await settle(1)
            write("CONNECT-KEY \(p[0])")
        case "tab-forwards":
            // Tunnels the core runs on open SSH tabs (`Terminal.forwards()`), as the Tunnel Manager shows them.
            guard let sv = UIDriver.services, let lib = commands.model.library else { return write("FAIL tab-forwards") }
            write("TAB-FORWARDS " + ((try? lib.tunnels()) ?? []).map { t in
                guard let f = sv.sessions.tabForward(t.id, via: t.viaId)?.status else { return "\(t.name) none" }
                return "\(t.name) \(f.running ? "running" : "stopped") port=\(f.port.map(String.init) ?? "-")\(f.lastError.map { " error=\($0)" } ?? "")"
            }.joined(separator: " | "))
        case "tab-forward-stop":
            // The Tunnel Manager's Stop for a tunnel running on its connection's tab.
            guard let sv = UIDriver.services, let lib = commands.model.library, let t = (try? lib.findTunnel(key: arg)) ?? nil else { return write("FAIL \(line)") }
            if let e = sv.sessions.stopTabForward(t.id, via: t.viaId) { return write("FAIL \(line): \(e)") }
            await settle(1.2)
            write("TAB-FORWARD-STOP \(arg)")
        case "tunnels":
            guard let sv = UIDriver.services, let lib = commands.model.library else { return write("FAIL tunnels") }
            write("TUNNELS " + ((try? lib.tunnels()) ?? []).map { t in
                let r = sv.sessions.runningTunnels[t.id]
                return "\(t.name) [\(t.summary) via \(t.viaName)] \(r?.isRunning() == true ? "running, \(r?.connections() ?? 0) connections" : "stopped")"
            }.joined(separator: " | "))
        case "network-change":
            // Simulates a path change (two keys so the first-report rule is passed).
            guard let sv = UIDriver.services else { return write("FAIL network-change") }
            sv.sessions.networkWatch.handle("driver-a")
            sv.sessions.networkWatch.handle("driver-b")
            await settle(0.3)
            write("NETWORK changes=\(sv.sessions.networkWatch.changes)")
        case "system-sleep", "system-wake":
            // Posted on NSWorkspace's centre, so the app's own sleep/wake observers run.
            NSWorkspace.shared.notificationCenter.post(name: cmd == "system-sleep" ? NSWorkspace.willSleepNotification : NSWorkspace.didWakeNotification, object: NSWorkspace.shared)
            await settle(0.3)
            write(line)
        case "term-marks":
            // TERM-MARKS checks. `term-marks tab <i> unread|notice:<prefix>|clear|production|plain [seconds]`:
            // tab i's unread dot, command notice and accent. `term-marks top <text>`: the selected terminal's
            // first visible line starts with <text> (prompt jumps). `term-marks offer <ssh text>|none`,
            // `term-marks save`: the typed-ssh bar of the selected tab, and its Save as Connection.
            guard let sv = UIDriver.services else { return write("FAIL term-marks") }
            let p = arg.split(separator: " ").map(String.init)
            switch p.first {
            case "tab":
                guard p.count >= 3, let i = Int(p[1]), sv.sessions.tabs.indices.contains(i) else { return write("FAIL term-marks \(arg)") }
                let tab = sv.sessions.tabs[i], want = p[2]
                let deadline = CFAbsoluteTimeGetCurrent() + (p.count > 3 ? Double(p[3]) ?? 0 : 0)
                func state() -> Bool {
                    switch want {
                    case "unread": return tab.unread
                    case "clear": return !tab.unread && tab.notice == nil
                    case "production": return HostColors.shared.productionIds.contains(tab.connectionId ?? "") && HostColors.shared.paint(for: tab.connectionId) != nil
                    case "plain": return !HostColors.shared.productionIds.contains(tab.connectionId ?? "")
                    default: return want.hasPrefix("notice:") && (tab.notice ?? "").hasPrefix(String(want.dropFirst(7)).replacingOccurrences(of: "_", with: " "))
                    }
                }
                var ok = state()
                while !ok && CFAbsoluteTimeGetCurrent() < deadline { await settle(0.25); ok = state() }
                write("\(ok ? "" : "FAIL ")TERM-MARKS tab=\(i) want=\(want) unread=\(tab.unread) notice='\(tab.notice ?? "-")' name='\(tab.shownName)'")
            case "top":
                guard let t = sv.sessions.selectedTab?.terminal else { return write("FAIL term-marks top: no terminal") }
                let first = Self.screenText(t).split(separator: "\n", omittingEmptySubsequences: false).first.map(String.init) ?? ""
                let want = p.dropFirst().joined(separator: " ")
                write("\(first.hasPrefix(want) ? "" : "FAIL ")TERM-MARKS top='\(first)' want='\(want)'")
            case "offer":
                let offer = sv.sessions.selectedTab?.panes.lazy.compactMap(\.sshOffer).first
                let want = p.dropFirst().joined(separator: " ")
                let ok = want == "none" ? offer == nil : offer?.text == want
                write("\(ok ? "" : "FAIL ")TERM-MARKS offer='\(offer?.text ?? "none")' want='\(want)'")
            case "save":
                guard let pane = sv.sessions.selectedTab?.panes.first(where: { $0.sshOffer != nil }), let t = pane.sshOffer else { return write("FAIL term-marks save: no offer") }
                TypedSshBar.save(t, pane: pane, model: commands.model)
                await settle(0.8)
                let saved = commands.model.tree?.connections.contains { $0.host == t.host && $0.protocol == "ssh" } ?? false
                write("\(saved ? "" : "FAIL ")TERM-MARKS saved host=\(t.host) user=\(t.user ?? "-") port=\(t.port.map(String.init) ?? "-")")
            default: write("FAIL term-marks \(arg)")
            }
        case "term-expect":
            // `term-expect <seconds> <text>`: wait until the selected terminal's screen shows <text>.
            let p = arg.split(separator: " ", maxSplits: 1).map(String.init)
            guard p.count == 2, let limit = Double(p[0]), let t = UIDriver.services?.sessions.selectedTab?.terminal else { return write("FAIL \(line)") }
            let deadline = CFAbsoluteTimeGetCurrent() + limit
            var seen = false
            while !seen && CFAbsoluteTimeGetCurrent() < deadline {
                seen = Self.screenText(t).contains(p[1])
                if !seen { await settle(0.25) }
            }
            write(seen ? "TERM-EXPECT ok: \(p[1])" : "FAIL term-expect \(p[1]); last lines: \(Self.screenText(t).split(separator: "\n").suffix(4).joined(separator: " / "))")
        case "sysview-expect":
            // `sysview-expect <seconds> <min rows> [text]`: wait until the selected system view tab
            // has refreshed with at least <min rows> rows (after its filter) and [text] in its sample.
            let p = arg.split(separator: " ", maxSplits: 2).map(String.init)
            guard p.count >= 2, let limit = Double(p[0]), let min = Int(p[1]), let tab = UIDriver.services?.sessions.selectedTab,
                  case .system(let system) = tab.content else { return write("FAIL \(line): no system view tab") }
            let deadline = CFAbsoluteTimeGetCurrent() + limit
            func snap() -> SystemViewProbe.Snapshot { SystemViewProbe.latest[ObjectIdentifier(system)] ?? .init() }
            func ok(_ s: SystemViewProbe.Snapshot) -> Bool { s.refreshes > 0 && s.rows >= min && (p.count < 3 || s.sample.contains(p[2])) }
            while !ok(snap()) && CFAbsoluteTimeGetCurrent() < deadline { await settle(0.25) }
            let s = snap()
            let summary = "\(tab.title) [\(system.view()) on \(system.os())]: \(s.rows) rows, \(s.refreshes) refreshes\(s.error.map { ", error \($0)" } ?? "") | \(s.sample.prefix(240))"
            write(ok(s) ? "SYSVIEW ok: \(summary)" : "FAIL sysview-expect \(arg); \(summary)")
        case "sysview-refreshes":
            // The refresh count of every system view tab, to check that hidden tabs do not poll.
            guard let sv = UIDriver.services else { return write("FAIL sysview-refreshes") }
            write("SYSVIEW-REFRESHES " + sv.sessions.tabs.compactMap { t -> String? in
                guard case .system(let s) = t.content else { return nil }
                let p = SystemViewProbe.latest[ObjectIdentifier(s)]
                return "\(t.title)=\(p?.refreshes ?? 0)\(p?.polling == true ? "(polling)" : "")\(t.id == sv.sessions.selected ? "*" : "")"
            }.joined(separator: " "))
        case "task-runon":
            // `task-runon <task name>|folder:<folder name>` or `|hosts:<name>,<name>` or `|saved`:
            // open Run on… for that task with that choice (saved: the remembered one).
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            guard let task = commands.model.tasks.first(where: { $0.name == p.first }) else { return write("FAIL \(line): no task") }
            let spec = p.count > 1 ? p[1] : "saved"
            func ids(_ f: FolderView?) -> [(String, String, Bool)] {
                guard let f else { return [] }
                return [(f.id, f.name, true)] + f.connections.map { ($0.id, $0.name, false) } + f.folders.flatMap(ids)
            }
            let all = ids(commands.model.tree)
            if spec.hasPrefix("folder:") {
                TaskRunOnSheet.scripted = TaskRunOnChoice(folderId: all.first { $0.2 && $0.1 == spec.dropFirst(7) }?.0)
            } else if spec.hasPrefix("tag:") {
                TaskRunOnSheet.scripted = TaskRunOnChoice(tag: String(spec.dropFirst(4)))
            } else if spec.hasPrefix("hosts:") {
                let names = spec.dropFirst(6).split(separator: ",").map(String.init)
                TaskRunOnSheet.scripted = TaskRunOnChoice(hostIds: all.filter { !$0.2 && names.contains($0.1) }.map(\.0))
            } else {
                TaskRunOnSheet.scripted = nil
            }
            TaskRunOnSheet.current = []
            commands.runOnTask = TaskRunOnRequest(task: task)
            await settle(1.0)
            let saved = TaskRunOnChoice.load(taskId: task.id)
            let name = { (id: String) in all.first { $0.0 == id }?.1 ?? id }
            write("TASK-RUNON open \(task.name); remembered folder=\(saved?.folderId.map(name) ?? "-") hosts=\(saved?.hostIds.map(name).joined(separator: ",") ?? "-")")
        case "task-runon-expect":
            // `task-runon-expect <seconds> <count>`: wait until <count> host runs have all finished; list each.
            let p = arg.split(separator: " ").map(String.init)
            guard p.count == 2, let limit = Double(p[0]), let want = Int(p[1]) else { return write("FAIL \(line)") }
            let deadline = CFAbsoluteTimeGetCurrent() + limit
            func ready() -> Bool { TaskRunOnSheet.current.count == want && TaskRunOnSheet.current.allSatisfy(\.isFinished) }
            while !ready() && CFAbsoluteTimeGetCurrent() < deadline { await settle(0.25) }
            TaskRunOnSheet.current.forEach { $0.poll() }
            let rows = TaskRunOnSheet.current.map { "\($0.name)=\($0.state)/\($0.view?.exit.map(String.init) ?? "-")" }.joined(separator: " ")
            let ok = ready() && TaskRunOnSheet.current.allSatisfy { $0.state == "done" }
            write(ok ? "TASK-RUNON-EXPECT ok: \(rows)" : "FAIL task-runon-expect \(arg): \(rows)")
        case "task-expect":
            // `task-expect <seconds> <state> [text]`: wait until the selected task tab reaches <state>
            // (`running`, `done`, `failed`, `timed_out`, `cancelled`) and its output holds [text].
            let p = arg.split(separator: " ", maxSplits: 2).map(String.init)
            guard p.count >= 2, let limit = Double(p[0]), let tab = UIDriver.services?.sessions.selectedTab,
                  case .task(let run) = tab.content else { return write("FAIL \(line): no task tab") }
            let deadline = CFAbsoluteTimeGetCurrent() + limit
            var o = run.output()
            func matches(_ o: TaskRunView) -> Bool {
                o.state == p[1] && (p.count < 3 || (o.stdout + o.stderr + (o.error ?? "")).contains(p[2]))
            }
            while !matches(o) && CFAbsoluteTimeGetCurrent() < deadline {
                await settle(0.25)
                o = run.output()
            }
            let summary = "\(tab.title): \(o.state) exit=\(o.exit.map(String.init) ?? "-") \(o.millis) ms | \(run.display()) | \((o.stdout + o.stderr + (o.error ?? "")).prefix(200).replacingOccurrences(of: "\n", with: " / "))"
            write(matches(o) ? "TASK-EXPECT ok: \(summary)" : "FAIL task-expect \(arg); \(summary)")
        case "term-mouse":
            // `term-mouse <down|drag|up|right|wheelup|wheeldown> <row> <col> [shift]`: a mouse event on the
            // focused terminal, through the view's own handlers.
            let p = arg.split(separator: " ").map(String.init)
            guard p.count >= 3, let r = Int(p[1]), let c = Int(p[2]), let v = focusedTerminalView() else { return write("FAIL \(line)") }
            let flags: NSEvent.ModifierFlags = p.count > 3 && p[3] == "shift" ? .shift : []
            let at = v.windowPoint(row: r, col: c)
            func mouse(_ type: NSEvent.EventType) -> NSEvent {
                NSEvent.mouseEvent(with: type, location: at, modifierFlags: flags, timestamp: ProcessInfo.processInfo.systemUptime,
                                   windowNumber: v.window?.windowNumber ?? 0, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)!
            }
            switch p[0] {
            case "down": v.mouseDown(with: mouse(.leftMouseDown))
            case "drag": v.mouseDragged(with: mouse(.leftMouseDragged))
            case "up": v.mouseUp(with: mouse(.leftMouseUp))
            case "right": v.rightMouseDown(with: mouse(.rightMouseDown)); v.rightMouseUp(with: mouse(.rightMouseUp))
            case "wheelup", "wheeldown":
                let cg = CGEvent(scrollWheelEvent2Source: nil, units: .line, wheelCount: 1, wheel1: p[0] == "wheelup" ? 3 : -3, wheel2: 0, wheel3: 0)!
                cg.location = v.window.map { $0.convertPoint(toScreen: at) } ?? .zero
                cg.flags = flags.contains(.shift) ? .maskShift : []
                v.scrollWheel(with: NSEvent(cgEvent: cg)!)
            default: return write("FAIL \(line)")
            }
            await settle(0.2)
            write("\(line) -> reporting \(v.terminal.mouseReporting())")
        case "term-padding":
            // `term-padding <row>` (UI-03): no text in the padding (background sampled from a blank interior spot);
            // a double-click in the left padding on <row> selects the column-0 word with the accent selection colour.
            guard let r = Int(arg), let v = focusedTerminalView() else { return write("FAIL \(line)") }
            await termPadding(v, row: r)
        case "term-ime":
            // `term-ime <marked> <committed>`: an input method composing <marked>, then committing.
            let p = arg.split(separator: " ", maxSplits: 1).map(String.init)
            guard p.count == 2, let v = focusedTerminalView() else { return write("FAIL \(line)") }
            v.setMarkedText(p[0], selectedRange: NSRange(location: p[0].utf16.count, length: 0), replacementRange: NSRange(location: NSNotFound, length: 0))
            await settle(0.3)
            write("TERM-IME marked \(v.hasMarkedText())")
            await step("capture after-macos-ime-marked-dark")
            v.insertText(p[1], replacementRange: NSRange(location: NSNotFound, length: 0))
            await settle(0.3)
            write("TERM-IME committed, marked \(v.hasMarkedText())")
        case "wait-link":
            // `wait-link <seconds>`: wait until the selected tab's supervised links are all connected.
            guard let limit = Double(arg), let tab = UIDriver.services?.sessions.selectedTab else { return write("FAIL \(line)") }
            let deadline = CFAbsoluteTimeGetCurrent() + limit
            while tab.panes.contains(where: { $0.terminal.linkStatus() != nil }) && CFAbsoluteTimeGetCurrent() < deadline { await settle(0.25) }
            let pending = tab.panes.compactMap { $0.terminal.linkStatus() }
            write(pending.isEmpty ? "WAIT-LINK connected" : "FAIL wait-link: \(pending.joined(separator: ","))")
        case "term-absent":
            // `term-absent <text>`: the selected terminal does not show <text> (after a short settle).
            guard let t = UIDriver.services?.sessions.selectedTab?.terminal else { return write("FAIL \(line)") }
            await settle(1.0)
            write(Self.screenText(t).contains(arg) ? "FAIL term-absent \(arg) is shown" : "TERM-ABSENT ok: \(arg)")
        case "link-status":
            guard let sv = UIDriver.services else { return write("FAIL link-status") }
            write("LINK-STATUS " + sv.sessions.tabs.map { "\($0.title): " + $0.panes.map { p in
                (p.terminal.linkStatus() ?? "connected") + (ReconnectBadge.isReconnecting(p.linkStatus) ? " [badge]" : "")
            }.joined(separator: ",") }.joined(separator: " | "))
        case "sheet-user":
            // `sheet-user <name>`: type into the attached sheet's User field (Connect as…).
            guard let sheet = window?.attachedSheet,
                  let field = sheet.contentView?.allSubviews(of: NSTextField.self).first(where: { $0.isEditable && !($0 is NSSecureTextField) }) else {
                return write("FAIL sheet-user: no field")
            }
            fill(field, arg, in: sheet)
            await settle(0.2)
            write("SHEET-USER \(field.stringValue)")
        case "connect-sheet":
            // Fill the open SSH connect sheet's password from `BASTION_UI_PASSWORD_FILE` and press Connect.
            // `connect-sheet <ENV_VAR>` reads the password file named by that variable instead.
            await connectSheet(passwordFile: ProcessInfo.processInfo.environment[arg.isEmpty ? "BASTION_UI_PASSWORD_FILE" : arg] ?? "")
        case "no-sheet":
            // `no-sheet <seconds>`: a connect went straight in; FAIL when a sheet is still asking.
            let before = UIDriver.services?.sessions.tabs.count ?? 0
            for _ in 0..<Int((Double(arg) ?? 5) * 10) { await settle(0.1) }
            let after = UIDriver.services?.sessions.tabs.count ?? 0
            if let sheet = window?.attachedSheet { write("FAIL NO-SHEET shown: \(sheetText(sheet))") } else { write("NO-SHEET ok tabs \(before)->\(after)") }
        case "capture-sheet", "capture-popover":
            guard let w = cmd == "capture-sheet" ? attachedDialog?.window : popover else { return write("FAIL \(line): none shown") }
            await settle(0.3)
            await capture(w, arg)
        case "shortcuts":
            // Commands whose shortcut differs from the default, and those left unbound by a clash.
            guard let sv = UIDriver.services else { return write("FAIL shortcuts") }
            let changed = sv.shortcuts.items.filter { !$0.isDefault }.map { "\($0.id)=\($0.chord.map(Chords.display) ?? "none")" }
            write("SHORTCUTS changed: \(changed.isEmpty ? "none" : changed.joined(separator: " ")); shadowed: \(sv.shortcuts.shadowed.sorted().joined(separator: " "))")
        case "shortcut-record":
            // `shortcut-record <command label>|<keys>`: real click on that row's recorder in
            // Settings › Keyboard, then a key press through the event queue (as typed).
            await shortcutRecord(arg)
        case "top-field":
            // `top-field <n>|<text>`: type into the n-th (0-based) editable text field of the topmost sheet.
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            let fields = topDialog?.views(of: NSTextField.self).filter { $0.isEditable } ?? []
            guard p.count == 2, let n = Int(p[0]), n < fields.count else { return write("FAIL top-field \(arg) (\(fields.count) fields)") }
            fill(fields[n], p[1], in: topDialog!.window)
            await settle(0.2)
            write("TOP-FIELD \(n) set")
        case "top-button":
            // SwiftUI Form buttons are not titled NSButtons and the in-process accessibility tree is
            // empty without an assistive client, so a button that listens for the driver
            // (ConnectSheet's "Allow for This Host") is asked by name.
            if let b = topDialog?.views(of: NSButton.self).first(where: { $0.title == arg && $0.isEnabled }) {
                b.performClick(nil)
            } else if topDialog != nil {
                NotificationCenter.default.post(name: DriverEvents.pressButton, object: arg)
            } else {
                return write("FAIL top-button \(arg) (no sheet)")
            }
            await settle(0.8)
            write("TOP-BUTTON \(arg)")
        case "top-default":
            let sheet = topSheet
            if let b = topDialog?.views(of: NSButton.self).first(where: { $0.keyEquivalent == "\r" && $0.isEnabled }) {
                b.performClick(nil)
            } else if let sheet {
                // SDK 27: SwiftUI's sheet buttons are no NSButtons (as #1184). The default button by its usual
                // titles through the accessibility tree; Return as the last resort (a focused field can take it).
                var pressed = false
                for title in Self.defaultButtonTitles where !pressed { pressed = await pressSwiftUIButton(title, in: sheet, wait: title == Self.defaultButtonTitles[0]) }
                if !pressed { await pressKey("\r", in: sheet) }
            } else {
                return write("FAIL top-default")
            }
            await settle(0.8)
            // `top-default open|closed` also checks what the sheet did (B9-DONE); no argument only logs it.
            let state = (sheet == nil ? commands.panel != nil : topSheet === sheet) ? "open" : "closed"
            write("\(arg.isEmpty || arg == state ? "" : "FAIL ")TOP-DEFAULT -> \(state == "open" ? "still open" : "closed")")
        case "top-text":
            // Secure fields are never read into the log.
            let texts = topDialog?.views(of: NSTextField.self).filter { !($0 is NSSecureTextField) }.map(\.stringValue).filter { !$0.isEmpty } ?? []
            write("TOP-TEXT " + texts.joined(separator: " | "))
        case "top-capture":
            guard let w = topDialog?.window else { return write("FAIL top-capture: no sheet") }
            await settle(0.3)
            await capture(w, arg)
        case "sheet-segment":
            // `sheet-segment <label>`: pick a segment of the attached sheet's segmented control, or the
            // item with that title in its pop-up (the SSH sheet's Authentication since 2026-11-16).
            if let pop = attachedDialog?.views(of: NSPopUpButton.self).first(where: { $0.item(withTitle: arg) != nil }) {
                pop.selectItem(withTitle: arg)
                if let action = pop.action { NSApp.sendAction(action, to: pop.target, from: pop) }
                await settle(0.5)
                return write("SHEET-SEGMENT \(arg)")
            }
            guard let seg = attachedDialog?.views(of: NSSegmentedControl.self).first(where: { s in (0..<s.segmentCount).contains { s.label(forSegment: $0) == arg } }),
                  let i = (0..<seg.segmentCount).first(where: { seg.label(forSegment: $0) == arg }) else { return write("FAIL sheet-segment \(arg)") }
            seg.selectedSegment = i
            if let action = seg.action { NSApp.sendAction(action, to: seg.target, from: seg) }
            await settle(0.5)
            write("SHEET-SEGMENT \(arg)")
        case "connect-sheet-code":
            // `connect-sheet-code <ENV_VAR>`: the code from that file into the sheet's verification-code field, then Return.
            guard let sheet = window?.attachedSheet, let file = ProcessInfo.processInfo.environment[arg],
                  let code = try? String(contentsOfFile: file, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
                  let field = sheet.contentView?.allSubviews(of: NSTextField.self).last(where: { $0.isEditable && !($0 is NSSecureTextField) }) else {
                return write("FAIL connect-sheet-code")
            }
            fill(field, code, in: sheet)
            await settle(0.3)
            guard let b = sheet.contentView?.allSubviews(of: NSButton.self).first(where: { $0.keyEquivalent == "\r" && $0.isEnabled }) else { return write("FAIL connect-sheet-code: Connect disabled") }
            b.performClick(nil)
            for _ in 0..<100 where window?.attachedSheet === sheet { await settle(0.1) }
            write("CONNECT-SHEET-CODE -> \(window?.attachedSheet === sheet ? "still open" : "closed"), tabs \(UIDriver.services?.sessions.tabs.count ?? 0)")
        case "connect-sheet-hops":
            // Target password from `BASTION_UI_PASSWORD_FILE`, jump hosts' from `BASTION_UI_HOP_PASSWORD_FILE`.
            let env = ProcessInfo.processInfo.environment
            await connectSheetHops("\(env["BASTION_UI_PASSWORD_FILE"] ?? "")|\(env["BASTION_UI_HOP_PASSWORD_FILE"] ?? "")")
        case "sheet-button":
            // `sheet-button <window>|<title>`: a button of the sheet or dialog on that window;
            // `key:<k>` picks it by key equivalent (SwiftUI sheet buttons carry no title).
            // `key:return` / `key:escape` name the default and cancel buttons.
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
                .map { $0.replacingOccurrences(of: "key:return", with: "key:\r").replacingOccurrences(of: "key:escape", with: "key:\u{1b}") }
            let mainPanel = p.first == "main" && window?.attachedSheet == nil ? panelDialog : nil
            guard p.count == 2, let w = p[0] == "main" ? window : findWindow(p[0]),
                  let dialog = w.attachedSheet.map({ DialogTarget(window: $0, frame: nil) }) ?? mainPanel else {
                return write("FAIL sheet-button \(arg)")
            }
            if let b = dialog.views(of: NSButton.self).first(where: { $0.title == p[1] || "key:" + $0.keyEquivalent == p[1] }) {
                b.performClick(nil)
            } else if let sheet = w.attachedSheet, await pressSwiftUIButton(p[1], in: sheet) {
                // SDK 27: SwiftUI sheet buttons are no NSButtons (as #1184).
            } else {
                return write("FAIL sheet-button \(arg); ax: \(Self.axOutline(w.attachedSheet))")
            }
            await settle(0.6)
            write("SHEET-BUTTON \(p[1])")
        case "sheet-popup":
            // `sheet-popup <label>|<option>`: choose an option of the sheet's pop-up button that
            // currently shows `<label>`'s value (the first pop-up when the label is `*`).
            let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
            // With no sheet up, the main window's pop-ups (the connection page's protocol picker).
            let popups = attachedDialog?.views(of: NSPopUpButton.self) ?? window?.contentView?.superview?.allSubviews(of: NSPopUpButton.self) ?? []
            // An empty NSPopUpButton shell can sit beside SwiftUI's own picker on macOS 26+ (#1104).
            if p.count == 2, p[0] == "*" ? popups.isEmpty : !popups.contains(where: { $0.titleOfSelectedItem == p[0] }),
               await chooseAccessiblePopUp(showing: p[0], option: p[1]) {
                await settle(0.5)
                return write("SHEET-POPUP \(p[1]) page-protocol=\(UIDriver.services?.sessions.connectionPage.flatMap { commands.model.connection(id: $0)?.protocol } ?? "none")")
            }
            guard p.count == 2, let popup = p[0] == "*" ? popups.first : popups.first(where: { $0.titleOfSelectedItem == p[0] }),
                  let index = popup.itemTitles.firstIndex(of: p[1]) else {
                // Name what the window has instead, so a toolkit change shows up in the log (SDK 27, #1104).
                let all = attachedDialog?.views(of: NSView.self) ?? window?.contentView?.superview?.allSubviews(of: NSView.self) ?? []
                let like = all.filter(Self.isPopUpLike).map(Self.describeControl)
                let titles = popups.map { $0.titleOfSelectedItem ?? "-" }.joined(separator: ",")
                return write("FAIL sheet-popup \(arg): pop-ups [\(titles)]; pop-up-like: \(like.joined(separator: "; ")); windows: \(Self.windowSummary); ax: \(Self.axOutline(window?.attachedSheet ?? Self.sheetPresentationWindows.first))")
            }
            // As choosing it from the open menu: the item's own action, which SwiftUI's Picker observes.
            popup.menu?.performActionForItem(at: index)
            await settle(0.5)
            write("SHEET-POPUP \(p[1])")
        case "sheet-default", "sheet-cancel":
            // The attached sheet's default (↩) or cancel (⎋) button, as a click on it.
            let key = cmd == "sheet-default" ? "\r" : "\u{1b}"
            if let b = attachedDialog?.views(of: NSButton.self).first(where: { $0.keyEquivalent == key && $0.isEnabled }) {
                b.performClick(nil)
                await settle(0.8)
                return write("\(cmd.uppercased()) -> sheet \(dialogShown)")
            }
            // SDK 27: SwiftUI's sheet buttons are no NSButtons. The window's accessibility default or cancel
            // button first, then the key itself, which SwiftUI's .defaultAction / .cancelAction answer.
            guard let sheet = window?.attachedSheet ?? Self.sheetPresentationWindows.first else {
                // A window panel (InWindowPanel): its .defaultAction / .cancelAction answer the key in the main window.
                // As a real keystroke, through NSApp: the panel holds the keyboard focus (PanelFocus), so
                // its .defaultAction / .cancelAction button and onExitCommand answer.
                if commands.panel != nil, let window,
                   let e = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                            windowNumber: window.windowNumber, context: nil, characters: key,
                                            charactersIgnoringModifiers: key, isARepeat: false, keyCode: key == "\r" ? 36 : 53) {
                    // NSApp offers a key-window keyDown as a key equivalent first; in a background run there
                    // is no key window, so offer it here (a text field in the panel would take Return).
                    window.makeKey()
                    if !window.performKeyEquivalent(with: e) { NSApp.sendEvent(e) }
                    await settle(0.8)
                    return write("\(cmd.uppercased()) -> sheet \(dialogShown) (panel key)")
                }
                return write("FAIL \(cmd): no sheet; windows: \(Self.windowSummary)")
            }
            let axButton = (cmd == "sheet-default" ? sheet.accessibilityDefaultButton() : sheet.accessibilityCancelButton()) as? NSAccessibilityProtocol
            let via: String
            if let axButton, axButton.accessibilityPerformPress() {
                via = "ax"
            } else {
                await pressKey(key, in: sheet)
                via = "key"
            }
            await settle(0.8)
            write("\(cmd.uppercased()) -> sheet \(dialogShown) (\(via))")
        case "sheet-text":
            // Text of the attached sheet's labels, for checking alert and editor wording.
            let texts = attachedDialog?.views(of: NSTextField.self).filter { !($0 is NSSecureTextField) }.map(\.stringValue).filter { !$0.isEmpty } ?? []
            write("SHEET-TEXT " + texts.joined(separator: " | "))
        case "selection-colour":
            // The selected tree row rendered as when the tree has focus (emphasized), its fill
            // sampled beside the text and compared with the accent; works with the app inactive.
            guard let outline, outline.selectedRow >= 0, let row = outline.rowView(atRow: outline.selectedRow, makeIfNecessary: false) as? AccentRowView,
                  let sv = UIDriver.services else { return write("FAIL selection-colour: no selected accent row") }
            let was = row.isEmphasized
            row.isEmphasized = true
            guard let rep = row.bitmapImageRepForCachingDisplay(in: row.bounds) else { return write("FAIL selection-colour: no bitmap") }
            row.cacheDisplay(in: row.bounds, to: rep)
            row.isEmphasized = was
            // Bitmap pixels are backing pixels: a point is `scale` of them.
            let scale = CGFloat(rep.pixelsWide) / max(row.bounds.width, 1)
            let sample = rep.colorAt(x: Int((DS.Size.selectionInset + 4) * scale), y: rep.pixelsHigh / 2)?.usingColorSpace(.sRGB)
            let accent = NSColor(AppearanceSettings.Accent(rawValue: sv.settings.value("appearance.accent"))?.color ?? .accentColor).usingColorSpace(.sRGB)
            func rgb(_ c: NSColor?) -> String { c.map { String(format: "%.2f %.2f %.2f a%.2f", $0.redComponent, $0.greenComponent, $0.blueComponent, $0.alphaComponent) } ?? "-" }
            write("SELECTION-COLOUR \(sv.settings.value("appearance.accent")): row \(rgb(sample)) accent \(rgb(accent))")
        case "capture-settings-sheet":
            guard let sheet = findWindow("settings")?.attachedSheet else { return write("FAIL capture-settings-sheet: none") }
            await settle(0.3)
            await capture(sheet, arg)
        case "split-drag":
            // `split-drag <fraction>`: drag the selected tab's outermost divider to that share with
            // real mouse events (down, drags, up) through the event queue.
            await splitDrag(arg)
        case "palette-type":
            // Type into the focused field of the palette sheet (or Quick Connect popover).
            guard let field = (window?.attachedSheet ?? popover)?.contentView?.allSubviews(of: NSTextField.self).first(where: \.isEditable) else {
                return write("FAIL palette-type: no field")
            }
            let focused = field.currentEditor() != nil
            field.window?.makeFirstResponder(field)
            field.stringValue = arg
            field.currentEditor()?.string = arg
            NotificationCenter.default.post(name: NSControl.textDidChangeNotification, object: field)
            await settle(0.4)
            write("TYPED \(arg) (field \(focused ? "had" : "did not have") focus)")
        default:
            if await perfStep(cmd, arg) { return }
            if await libraryStep(cmd, arg) { return }
            if await fitStep(cmd, arg) { return }
            if await hostsStep(cmd, arg) { return }
            if await fullScreenStep(cmd, arg) { return }
            if await quitStep(cmd, arg) { return }
            if await dialogFrontStep(cmd, arg) { return }
            if await secretClipboardStep(cmd, arg) { return }
            if await testConnectionStep(cmd, arg) { return }
            if await dynamicStep(cmd, arg) { return }
            write("FAIL unknown step \(line)")
        }
    }

    var popover: NSWindow? {
        NSApp.windows.first { $0.isVisible && String(describing: type(of: $0)).contains("Popover") }
    }

    /// Virtual key codes of the US layout, so synthetic keystrokes match physical ones.
    static let usKeyCodes: [Character: UInt16] = [
        "a": 0, "s": 1, "d": 2, "f": 3, "h": 4, "g": 5, "z": 6, "x": 7, "c": 8, "v": 9, "b": 11, "q": 12, "w": 13, "e": 14,
        "r": 15, "y": 16, "t": 17, "1": 18, "2": 19, "3": 20, "4": 21, "6": 22, "5": 23, "9": 25, "7": 26, "8": 28, "0": 29,
        "]": 30, "o": 31, "u": 32, "[": 33, "i": 34, "p": 35, "l": 37, "j": 38, "k": 40, "n": 45, "m": 46, ",": 43,
    ]

    func appKey(_ spec: String) {
        var flags: NSEvent.ModifierFlags = []
        var parts = spec.split(separator: "+").map(String.init)
        let k = parts.removeLast()
        for m in parts {
            switch m {
            case "cmd": flags.insert(.command)
            case "opt": flags.insert(.option)
            case "shift": flags.insert(.shift)
            case "ctrl": flags.insert(.control)
            default: break
            }
        }
        let known = Self.keyCodes[k]
        // A real ⇧-letter keystroke carries the capital letter. (AppKit does not match injected
        // ⇧ events to menu items; scripts run those items with `menuitem` instead.)
        let chars = known?.chars ?? (flags.contains(.shift) ? k.uppercased() : k)
        let target = NSApp.keyWindow ?? window?.attachedSheet ?? window
        guard let e = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: flags, timestamp: ProcessInfo.processInfo.systemUptime,
                                       windowNumber: target?.windowNumber ?? 0, context: nil, characters: chars,
                                       charactersIgnoringModifiers: chars, isARepeat: false,
                                       keyCode: known?.code ?? Self.usKeyCodes[Character(k.lowercased())] ?? 0) else { return }
        deliverKey(e, to: target)
    }

    /// A key-down as NSApp would route it to the key window. Quiet runs have no key window
    /// (NSApp.sendEvent would drop the key), so the window's key equivalents (default button,
    /// Cancel), then the main menu, then the window's first responder get it directly.
    func deliverKey(_ e: NSEvent, to w: NSWindow?) {
        guard let w, NSApp.keyWindow !== w else { return NSApp.sendEvent(e) }
        let command = e.modifierFlags.contains(.command)
        // Key equivalents first for chords and in sheets (Return = default button, Escape = Cancel);
        // a plain key in the main window goes to its first responder (Return opens the selected row).
        if command || w.sheetParent != nil, w.performKeyEquivalent(with: e) { return }
        if command, NSApp.mainMenu?.performKeyEquivalent(with: e) == true { return }
        w.sendEvent(e)
    }

    func shortcutRecord(_ arg: String) async {
        let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
        // SwiftUI builds no accessibility tree without an assistive client and its form buttons
        // carry no title, so scripts filter the page to one command first: its recorder is then
        // the lowest, rightmost form button (Restore Defaults sits in the filter row).
        guard p.count == 2, let w = findWindow("settings") else { return write("FAIL shortcut-record \(arg): no recorder") }
        w.makeKeyAndOrderFront(nil)
        await settle(0.2)
        // SDK 27: SwiftUI buttons are no NSButtons; the recorder is labelled "<command> shortcut".
        if await pressSwiftUIButton("\(p[0]) shortcut", in: w) {
        } else if let button = (w.contentView?.superview ?? w.contentView)?.allSubviews(of: NSButton.self)
                .filter({ String(describing: type(of: $0)).contains("SwiftUI") && !$0.isHidden })
                .map({ ($0, $0.convert($0.bounds, to: nil)) })
                .min(by: { ($0.1.minY, -$0.1.maxX) < ($1.1.minY, -$1.1.maxX) })?.0 {
            button.performClick(nil)
        } else {
            return write("FAIL shortcut-record \(arg): no recorder")
        }
        await settle(0.4)
        // Never send the keys unless the recorder is listening: ⌘Q would otherwise quit.
        guard let shortcuts = UIDriver.services?.shortcuts, shortcuts.isRecording else {
            return write("FAIL shortcut-record \(arg): recorder did not start")
        }
        var flags: NSEvent.ModifierFlags = []
        var parts = p[1].split(separator: "+").map(String.init)
        let k = parts.removeLast()
        for m in parts {
            switch m {
            case "cmd": flags.insert(.command)
            case "opt": flags.insert(.option)
            case "shift": flags.insert(.shift)
            case "ctrl": flags.insert(.control)
            default: break
            }
        }
        let known = Self.keyCodes[k]
        let chars = known?.chars ?? k
        guard let e = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: flags, timestamp: ProcessInfo.processInfo.systemUptime,
                                       windowNumber: w.windowNumber, context: nil, characters: chars, charactersIgnoringModifiers: chars,
                                       isARepeat: false, keyCode: known?.code ?? Self.usKeyCodes[Character(k)] ?? 0) else { return }
        NSApp.postEvent(e, atStart: false)
        await settle(0.8)
        let item = UIDriver.services?.shortcuts.items.first { $0.label == p[0] }
        write("SHORTCUT-RECORD \(p[0]) \(p[1]) -> \(item?.chord.map(Chords.display) ?? "none"); dialog \(w.attachedSheet != nil ? "shown" : "none")")
    }

    /// Left click at a point in window coordinates: down now, up through the event queue.
    func click(at point: NSPoint, in w: NSWindow) {
        let up = NSEvent.mouseEvent(with: .leftMouseUp, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                    windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 0)!
        let down = NSEvent.mouseEvent(with: .leftMouseDown, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                      windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)!
        let upEvent = UncheckedEvent(event: up)
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.03) { NSApp.postEvent(upEvent.event, atStart: false) }
        w.sendEvent(down)
    }

    func splitDrag(_ arg: String) async {
        guard let target = Double(arg), let window, let tab = UIDriver.services?.sessions.selectedTab,
              case .split(let axis, let ratio, _, _)? = tab.root,
              let first = tab.panes.first.flatMap({ pane in window.contentView?.allSubviews(of: TerminalNSView.self).first { $0.terminal === pane.terminal } }),
              let last = tab.panes.last.flatMap({ pane in window.contentView?.allSubviews(of: TerminalNSView.self).first { $0.terminal === pane.terminal } }) else {
            return write("FAIL split-drag: no split")
        }
        // The split's area is the union of its panes; the divider sits after the first side.
        let a = first.convert(first.bounds, to: nil), b = last.convert(last.bounds, to: nil)
        let area = a.union(b)
        let horizontal = axis == .right
        let from = horizontal ? NSPoint(x: a.maxX, y: area.midY) : NSPoint(x: area.midX, y: a.minY)
        let to = horizontal ? NSPoint(x: area.minX + area.width * target, y: area.midY) : NSPoint(x: area.midX, y: area.maxY - area.height * target)
        func event(_ type: NSEvent.EventType, _ p: NSPoint) -> NSEvent {
            NSEvent.mouseEvent(with: type, location: p, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                               windowNumber: window.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: type == .leftMouseUp ? 0 : 1)!
        }
        let before = ratio.value
        NSApp.postEvent(event(.leftMouseDown, from), atStart: false)
        for i in 1...10 {
            let t = CGFloat(i) / 10
            NSApp.postEvent(event(.leftMouseDragged, NSPoint(x: from.x + (to.x - from.x) * t, y: from.y + (to.y - from.y) * t)), atStart: false)
        }
        NSApp.postEvent(event(.leftMouseUp, to), atStart: false)
        await settle(0.8)
        write(String(format: "SPLIT-DRAG %@ ratio %.3f -> %.3f", axis.rawValue, Double(before), Double(ratio.value)))
    }

    /// `workspace save <name>`, `open <name>`, `rename <old>|<new>`, `duplicate <name>`, `delete <name>`.
    func workspace(_ arg: String) async {
        guard let sv = UIDriver.services else { return write("FAIL workspace") }
        let p = arg.split(separator: " ", maxSplits: 1).map(String.init)
        guard p.count == 2 else { return write("FAIL workspace \(arg)") }
        let ws = sv.workspaces
        let id = { (name: String) in ws.items.first { $0.name == name }?.id }
        switch p[0] {
        case "save": ws.saveCurrent(name: p[1], sessions: sv.sessions, model: commands.model)
        case "open": id(p[1]).map { ws.open($0, commands: commands) }
        case "rename":
            let n = p[1].split(separator: "|").map(String.init)
            if n.count == 2, let i = id(n[0]) { ws.rename(i, to: n[1]) }
        case "duplicate": _ = id(p[1]).flatMap(ws.duplicate)
        case "delete": id(p[1]).map(ws.remove)
        default: return write("FAIL workspace \(arg)")
        }
        await settle(0.6)
        write("WORKSPACE \(arg)\(ws.error.map { " -> error: \($0)" } ?? "")")
        ws.error = nil
    }

    func connectSheet(passwordFile: String) async {
        for _ in 0..<40 where window?.attachedSheet == nil { await settle(0.1) }
        guard let sheet = window?.attachedSheet, let root = sheet.contentView?.superview ?? sheet.contentView else {
            // Saved or just-used credentials connect with no sheet (owner feedback 2026-11-07 #2).
            let tabs = UIDriver.services?.sessions.tabs.count ?? 0
            return write(tabs > 0 ? "CONNECT-SHEET -> none (connected directly), tabs \(tabs)" : "FAIL connect-sheet: no sheet")
        }
        guard let password = try? String(contentsOfFile: passwordFile, encoding: .utf8).trimmingCharacters(in: .newlines) else {
            return write("FAIL connect-sheet: password file")
        }
        // The sheet attaches before SwiftUI has built its fields (its logins load off the main thread): wait for the field.
        for _ in 0..<30 where root.allSubviews(of: NSSecureTextField.self).isEmpty { await settle(0.1) }
        guard let field = root.allSubviews(of: NSSecureTextField.self).first else {
            // What the sheet shows instead (labels and buttons), to tell a test that is out of date from an app fault.
            let shown = (root.allSubviews(of: NSTextField.self).map(\.stringValue) + root.allSubviews(of: NSButton.self).map(\.title))
                .filter { !$0.isEmpty }.prefix(12).joined(separator: " | ")
            return write("FAIL connect-sheet: no password field (state \(LoginResolver.sheetState); \(LoginResolver.sheetDetail); shows: \(shown))")
        }
        sheet.makeFirstResponder(field)
        field.stringValue = password
        field.currentEditor()?.string = password
        NotificationCenter.default.post(name: NSControl.textDidChangeNotification, object: field)
        await settle(0.3)
        // Return in the password field, as a person would press it.
        let e = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                 windowNumber: sheet.windowNumber, context: nil, characters: "\r",
                                 charactersIgnoringModifiers: "\r", isARepeat: false, keyCode: 36)!
        sheet.makeKey()
        deliverKey(e, to: sheet)
        for _ in 0..<100 where window?.attachedSheet === sheet { await settle(0.1) }
        write("CONNECT-SHEET -> \(window?.attachedSheet === sheet ? "still open \(sheetText(sheet))" : "closed"), tabs \(UIDriver.services?.sessions.tabs.count ?? 0)")
    }

    static func screenText(_ t: Terminal) -> String { screenText(t.fastScreen()) }

    static func screenText(_ s: TermScreen) -> String {
        let cols = Int(s.cols)
        return stride(from: 0, to: s.cells.count, by: max(cols, 1)).map { start in
            var previous = ""
            return s.cells[start..<min(start + cols, s.cells.count)].map { cell -> String in
                // A wide character's second cell is empty: leave it out so "日本" reads as typed.
                defer { previous = cell.text }
                if cell.text.isEmpty { return Self.isWide(previous) ? "" : " " }
                return cell.text
            }.joined()
        }.joined(separator: "\n")
    }

    /// Roughly East Asian wide: good enough for matching test text, not for layout.
    private static func isWide(_ text: String) -> Bool {
        guard let v = text.unicodeScalars.first?.value else { return false }
        return (0x1100...0x115F).contains(v) || (0x2E80...0xA4CF).contains(v) || (0xAC00...0xD7A3).contains(v)
            || (0xF900...0xFAFF).contains(v) || (0xFE30...0xFE4F).contains(v) || (0xFF00...0xFF60).contains(v)
            || (0xFFE0...0xFFE6).contains(v) || (0x1F300...0x1FAFF).contains(v) || (0x20000...0x3FFFD).contains(v)
    }

    /// The deepest sheet on the main window (a sheet opened from a sheet).
    /// The dialog the sheet commands act on: the attached sheet, or else a manager panel open in
    /// the main window (`InWindowPanel.swift`), limited to the panel's own views.
    /// macOS 26+ SwiftUI draws a menu Picker itself: no NSPopUpButton, only an accessibility element. Finds
    /// the one showing `showing` (any when `*`), presses it, and picks `option` from the menu it opens, as a
    /// click on that item does. False when there is no such element or item.
    /// A SwiftUI sheet button: `key:\r` / `key:\u{1b}` as that key, else the accessibility button with this
    /// title, after asking for the tree once as a client so SwiftUI builds it (#1184).
    /// Titles a sheet's default button carries in this app, most common first (`top-default` on SDK 27).
    static let defaultButtonTitles = ["Save", "OK", "Done", "Create", "Add", "Apply", "Connect"]

    func pressSwiftUIButton(_ name: String, in sheet: NSWindow, wait: Bool = true) async -> Bool {
        if name == "key:\r" || name == "key:\u{1b}" {
            await pressKey(String(name.dropFirst(4)), in: sheet)
            return true
        }
        // `key:<letter>`: SwiftUI's `.keyboardShortcut("<letter>")` is ⌘<letter> (sec-07's Test
        // Connection, ⌘T); its button carries no key equivalent to match (census 2026-11-17).
        if name.hasPrefix("key:"), name.count == 5, let c = name.last, c.isLetter || c.isNumber {
            return await pressCommandKey(String(c), in: sheet)
        }
        if Self.axButton(titled: name, in: sheet) == nil { _ = AXSelfClient.pressPopUp(showing: "\u{0}") }
        for _ in 0..<(wait ? 30 : 1) {
            if let b = Self.dynamicButton(titled: name, in: sheet) { return b.accessibilityPerformPress?() ?? false }
            if wait { await settle(0.1) }
        }
        return false
    }

    /// A button under `root` titled or labelled `title`, by dynamic dispatch (SwiftUI's private element classes).
    static func dynamicButton(titled title: String, in root: Any) -> AnyObject? {
        var queue: [Any] = [root]
        var visited = 0
        while !queue.isEmpty, visited < 3000 {
            let ax = queue.removeFirst() as AnyObject
            visited += 1
            if (ax.accessibilityRole?() ?? nil) == .button,
               [ax.accessibilityTitle?() ?? nil, ax.accessibilityLabel?() ?? nil].contains(title) { return ax }
            queue += ((ax.accessibilityChildren?() ?? nil) ?? [])
        }
        return nil
    }

    /// ⌘`chars` as a key equivalent of `w` (a SwiftUI `.keyboardShortcut` on one of its buttons).
    func pressCommandKey(_ chars: String, in w: NSWindow) async -> Bool {
        guard let e = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: .command, timestamp: ProcessInfo.processInfo.systemUptime,
                                       windowNumber: w.windowNumber, context: nil, characters: chars,
                                       charactersIgnoringModifiers: chars, isARepeat: false, keyCode: 0) else { return false }
        w.makeKey()
        let handled = w.performKeyEquivalent(with: e)
        await settle(0.1)
        return handled
    }

    /// Return or Escape as a key press in `w`, through NSApp so key equivalents apply (as `sheetkey`).
    func pressKey(_ chars: String, in w: NSWindow) async {
        let code: UInt16 = chars == "\r" ? 36 : 53
        guard let e = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                       windowNumber: w.windowNumber, context: nil, characters: chars,
                                       charactersIgnoringModifiers: chars, isARepeat: false, keyCode: code) else { return }
        w.makeKey()
        deliverKey(e, to: w)
    }

    /// A pop-up (or menu) button under `root` showing `showing` (`*`: the first), found by dynamic dispatch:
    /// SwiftUI's elements are private NSObject subclasses that need not cast to NSAccessibilityProtocol.
    static func dynamicPopUp(in root: Any?, showing: String) -> AnyObject? {
        var queue: [Any] = root.map { [$0] } ?? []
        var visited = 0
        while !queue.isEmpty, visited < 3000 {
            let ax = queue.removeFirst() as AnyObject
            visited += 1
            let role = ax.accessibilityRole?() ?? nil
            if role == .popUpButton || role == .menuButton {
                let value = (ax.accessibilityValue?() ?? nil).map { String(describing: $0) }
                let names = [value, ax.accessibilityTitle?() ?? nil, ax.accessibilityLabel?() ?? nil]
                if showing == "*" || names.contains(showing) { return ax }
            }
            queue += ((ax.accessibilityChildren?() ?? nil) ?? [])
        }
        return nil
    }

    /// An accessibility button under `root` whose title or label is `title`.
    static func axButton(titled title: String, in root: Any) -> NSAccessibilityProtocol? {
        var queue: [Any] = [root]
        var visited = 0
        while !queue.isEmpty, visited < 3000 {
            let el = queue.removeFirst()
            visited += 1
            let ax = el as AnyObject
            if (ax.accessibilityRole?() ?? nil) == .button,
               [ax.accessibilityTitle?() ?? nil, ax.accessibilityLabel?() ?? nil].contains(title),
               let e = el as? NSAccessibilityProtocol { return e }
            queue += ((ax.accessibilityChildren?() ?? nil) ?? [])
        }
        return nil
    }

    /// The first `limit` accessibility roles under `root` with their title or value: a failed lookup writes them.
    static func axOutline(_ root: Any?, limit: Int = 40) -> String {
        var queue: [Any] = root.map { [$0] } ?? []
        var out: [String] = []
        var visited = 0
        while !queue.isEmpty, visited < 3000, out.count < limit {
            let ax = queue.removeFirst() as AnyObject
            visited += 1
            let role = (ax.accessibilityRole?() ?? nil)?.rawValue ?? "-"
            let name = (ax.accessibilityTitle?() ?? nil) ?? (ax.accessibilityLabel?() ?? nil) ?? ""
            if role != "AXGroup" && role != "-" { out.append(name.isEmpty ? role : "\(role)=\(name)") }
            queue += ((ax.accessibilityChildren?() ?? nil) ?? [])
        }
        return "\(visited) nodes: " + out.joined(separator: ", ")
    }

    func chooseAccessiblePopUp(showing: String, option: String) async -> Bool {
        let root: Any? = attachedDialog?.window ?? window
        let element = Self.accessiblePopUp(in: root, showing: showing)
        // Without an accessibility client SwiftUI may build no elements: click the probed picker instead.
        let probe = UIProbe.frames["protocol-picker"]
        guard let w = window else { return false }
        final class Flag: @unchecked Sendable { var set = false; var stepDone = false; var ended = false; var menus: [String] = [] }
        let chosen = Flag()
        let token = NotificationCenter.default.addObserver(forName: NSMenu.didBeginTrackingNotification, object: nil, queue: .main) { note in
            // Delivered on the main queue (queue: .main); the menu never leaves it.
            nonisolated(unsafe) let tracked = note.object as? NSMenu
            MainActor.assumeIsolated {
                guard let menu = tracked else { return }
                let index = menu.indexOfItem(withTitle: option)
                guard !chosen.stepDone, !chosen.set else { return }
                if index >= 0 { PickerMenuGuard.titles = Set(menu.items.map(\.title)) }
                chosen.menus.append(menu.items.map(\.title).joined(separator: "/"))
                // A menu left open runs its own event loop under every later step (a resize then crashed in it, #1104).
                guard index >= 0 else { return menu.cancelTrackingWithoutAnimation() }
                // Choose once the menu is up and tracking, as a click on the item would. Closing it from inside this
                // notification (before it showed) left SwiftUI's picker deaf to the next click on macOS 27 (#1104).
                // The timer runs in the common modes, so it fires inside the menu's tracking loop.
                nonisolated(unsafe) let open = menu
                let pick = Timer(timeInterval: 0.15, repeats: false) { _ in
                    MainActor.assumeIsolated {
                        open.performActionForItem(at: index)
                        open.cancelTracking()
                    }
                }
                RunLoop.main.add(pick, forMode: .common)
                chosen.set = true
            }
        }
        PickerMenuGuard.install { [weak self] text in self?.write(text) }
        PickerMenuGuard.stepActive = true
        let endToken = NotificationCenter.default.addObserver(forName: NSMenu.didEndTrackingNotification, object: nil, queue: .main) { _ in
            chosen.ended = true
        }
        defer {
            chosen.stepDone = true
            PickerMenuGuard.stepActive = false
            NotificationCenter.default.removeObserver(token)
            NotificationCenter.default.removeObserver(endToken)
        }
        if let element {
            _ = element.accessibilityPerformPress()
            await settle(0.6)
        } else {
            // SDK 27: SwiftUI builds its accessibility tree only once a client asks. Ask as one; a query of the
            // own process is answered in process on the calling thread, so it runs on main (SwiftUI reads its
            // bindings). Without the accessibility permission the call itself fails, but the tree is built, so
            // look again in process and press.
            let pressed = AXSelfClient.pressPopUp(showing: showing)
            if pressed != "pressed" {
                var woken: AnyObject?
                for _ in 0..<30 where woken == nil {
                    await settle(0.1)
                    woken = Self.dynamicPopUp(in: window?.attachedSheet ?? Self.sheetPresentationWindows.first ?? window, showing: showing)
                }
                if let woken {
                    _ = woken.accessibilityPerformPress?()
                } else {
                    write("SHEET-POPUP-AX \(pressed)")
                }
            }
            for _ in 0..<20 where !chosen.set { await settle(0.1) }
        }
        // A second try: on macOS 27 a click right after the previous pick sometimes opens no menu.
        for attempt in 0..<2 where !chosen.set {
            guard let frame = UIProbe.frames["protocol-picker"], let content = w.contentView else { break }
            // Key if it can be: makeKey does not activate the app, so in a background run the window may stay not key.
            if !w.isKeyWindow { w.makeKey() }
            let local = content.isFlipped ? NSPoint(x: frame.midX, y: frame.midY) : NSPoint(x: frame.midX, y: content.bounds.height - frame.midY)
            let point = content.convert(local, to: nil)
            let up = NSEvent.mouseEvent(with: .leftMouseUp, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                        windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 0)!
            let down = NSEvent.mouseEvent(with: .leftMouseDown, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                          windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)!
            let hit = content.hitTest(local).map { String(describing: type(of: $0)) } ?? "none"
            let upEvent = UncheckedEvent(event: up)
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.03) { NSApp.postEvent(upEvent.event, atStart: false) }
            w.sendEvent(down)
            // SwiftUI may open the menu a little later: wait for it, so it never opens after the observer is gone.
            for _ in 0..<20 where !chosen.set { await settle(0.1) }
            if !chosen.set { write("SHEET-POPUP-TRY ax=\(element != nil) probe=\(Int(frame.minX)),\(Int(frame.minY)) \(Int(frame.width))x\(Int(frame.height)) key=\(w.isKeyWindow) hit=\(hit) try=\(attempt + 1) menus=[\(chosen.menus.joined(separator: " | "))]") }
        }
        if chosen.set {
            for _ in 0..<10 where !chosen.ended { await settle(0.1) }
            write("SHEET-POPUP-MENU ended=\(chosen.ended ? "yes" : "no")")
        }
        return chosen.set
    }

    /// Depth-first through the accessibility tree: a pop-up button (or menu button) whose value is `showing`.
    /// Read through AXTree: a bridged role or title from some elements throws (see AXTree).
    static func accessiblePopUp(in node: Any?, showing: String) -> NSAccessibilityProtocol? {
        AXTree.popUp(in: node, showing: showing) as? NSAccessibilityProtocol
    }

    /// A control that acts as a pop-up menu, whatever its class (sheet-popup diagnostics).
    static func isPopUpLike(_ v: NSView) -> Bool {
        let role = v.accessibilityRole()
        return role == .popUpButton || role == .menuButton || String(describing: type(of: v)).contains("PopUp")
    }

    static func describeControl(_ v: NSView) -> String {
        let title = (v as? NSButton)?.title ?? "-"
        let value = v.accessibilityValue().map { String(describing: $0) } ?? "-"
        return "\(type(of: v)) role=\(v.accessibilityRole()?.rawValue ?? "-") title=\(title) value=\(value)"
    }

    struct DialogTarget {
        let window: NSWindow
        let frame: CGRect?   // the panel's window-space frame (top-left origin); nil for a sheet
        @MainActor func views<T: NSView>(of type: T.Type) -> [T] {
            var all = (frame == nil ? window.contentView : window.contentView?.superview)?.allSubviews(of: type) ?? []
            // SDK 27: the sheet's controls can live in a separate SheetPresentationWindow, not under the
            // attached sheet's content view. Search it when the sheet itself has none.
            if frame == nil, all.isEmpty {
                all = Driver.sheetPresentationWindows.flatMap { ($0.contentView?.superview ?? $0.contentView)?.allSubviews(of: type) ?? [] }
            }
            guard let frame, let content = window.contentView else { return all }
            // In the panel's frame and not covered by it: a view the panel hides (sidebar, toolbar
            // field) is in the frame too, but a hit test at its centre lands on the panel instead.
            // SwiftUI answers a hit on a hosted control with its nearest container view, so the hit
            // may be the view, inside it, or one of its containers, but never the window's root views.
            let root = content.superview ?? content
            return all.filter { v in
                // The visible part: a table taller than its scroll view has its centre out of view.
                guard !v.visibleRect.isEmpty else { return false }
                let r = v.convert(v.visibleRect, to: nil)
                guard frame.contains(CGPoint(x: r.midX, y: content.bounds.height - r.midY)) else { return false }
                guard let hit = root.hitTest(root.convert(CGPoint(x: r.midX, y: r.midY), from: nil)),
                      hit !== root, hit !== content else { return false }
                return hit === v || hit.isDescendant(of: v) || v.isDescendant(of: hit)
            }
        }
    }

    var panelDialog: DialogTarget? {
        guard let window, let panel = commands.panel, let frame = UIProbe.frames[panel.probe] else { return nil }
        return DialogTarget(window: window, frame: frame)
    }

    /// A text field's prompt. Linked against the macOS 27 SDK, SwiftUI may set it as an attributed
    /// placeholder or only on the accessibility element (census 2026-11-17: m3-settings, m6-shortcuts).
    static func placeholder(of field: NSTextField) -> String? {
        field.placeholderString ?? field.placeholderAttributedString?.string
            ?? (field.cell as? NSTextFieldCell)?.placeholderString ?? field.accessibilityPlaceholderValue()
    }

    /// The connection page's column may start this far inside the session area (its normal inset).
    static let pageLeadTolerance: CGFloat = 40

    var attachedDialog: DialogTarget? {
        (window?.attachedSheet ?? Self.sheetPresentationWindows.first).map { DialogTarget(window: $0, frame: nil) } ?? panelDialog
    }

    /// SDK 27 hosts sheet content in visible windows of this private class (seen in the `alert` window list).
    static var sheetPresentationWindows: [NSWindow] {
        NSApp.windows.filter { $0.isVisible && String(describing: type(of: $0)).contains("SheetPresentationWindow") }
    }

    /// Each window's class, visibility and view count: a failed sheet lookup writes it, so the log shows where the controls are.
    static var windowSummary: String {
        NSApp.windows.map { w in
            "\(type(of: w))\(w.isVisible ? "" : "(hidden)"):\(w.contentView?.superview?.allSubviews(of: NSView.self).count ?? 0)"
                + (w.attachedSheet.map { " sheet=\(type(of: $0)):\($0.contentView?.allSubviews(of: NSView.self).count ?? 0)" } ?? "")
        }.joined(separator: ", ")
    }
    var topDialog: DialogTarget? { topSheet.map { DialogTarget(window: $0, frame: nil) } ?? panelDialog }
    var dialogShown: String { window?.attachedSheet != nil ? "shown" : commands.panel != nil ? "panel" : "none" }

    var topSheet: NSWindow? {
        var w = window?.attachedSheet
        while let next = w?.attachedSheet { w = next }
        return w
    }

    func fill(_ field: NSTextField, _ text: String, in sheet: NSWindow) {
        sheet.makeFirstResponder(field)
        field.stringValue = text
        field.currentEditor()?.string = text
        NotificationCenter.default.post(name: NSControl.textDidChangeNotification, object: field)
    }

    func connectSheetHops(_ arg: String) async {
        let files = arg.split(separator: "|").map(String.init)
        for _ in 0..<40 where window?.attachedSheet == nil { await settle(0.1) }
        guard files.count == 2, let sheet = window?.attachedSheet,
              let target = try? String(contentsOfFile: files[0], encoding: .utf8).trimmingCharacters(in: .newlines),
              let hop = try? String(contentsOfFile: files[1], encoding: .utf8).trimmingCharacters(in: .newlines) else {
            return write("FAIL connect-sheet-hops")
        }
        await settle(0.5)
        guard let toggle = sheet.contentView?.allSubviews(of: NSSwitch.self).first else { return write("FAIL connect-sheet-hops: no jump host toggle") }
        toggle.performClick(nil)
        await settle(0.5)
        let secure = sheet.contentView?.allSubviews(of: NSSecureTextField.self) ?? []
        guard secure.count >= 2 else { return write("FAIL connect-sheet-hops: \(secure.count) password fields") }
        fill(secure[0], target, in: sheet)
        for f in secure.dropFirst() { fill(f, hop, in: sheet) }
        await settle(0.3)
        write("CONNECT-SHEET-HOPS \(secure.count - 1) jump host(s)")
        if let b = sheet.contentView?.allSubviews(of: NSButton.self).first(where: { $0.keyEquivalent == "\r" && $0.isEnabled }) {
            b.performClick(nil)
        } else {
            // SDK 27: SwiftUI's Connect is no NSButton and, in the sheet's toolbar, not reached by
            // the accessibility search; Return in a jump-host field does nothing. The password
            // field submits on Return (`onSubmit(submit)`), as a user's Return there does (p0-gateways).
            sheet.makeFirstResponder(secure[0])
            if let editor = secure[0].currentEditor() as? NSTextView {
                editor.insertNewline(nil)
            } else {
                await pressKey("\r", in: sheet)
            }
        }
        for _ in 0..<100 where window?.attachedSheet === sheet { await settle(0.1) }
        write("CONNECT-SHEET -> \(window?.attachedSheet === sheet ? "still open \(sheetText(sheet))" : "closed"), tabs \(UIDriver.services?.sessions.tabs.count ?? 0)")
    }

    /// The non-editable text a sheet shows (its error line when a connect fails), for the log.
    func sheetText(_ sheet: NSWindow) -> String {
        let texts = (sheet.contentView?.allSubviews(of: NSTextField.self) ?? []).filter { !$0.isEditable }.map(\.stringValue)
        let others = NSApp.windows.filter { $0.isVisible && $0 !== sheet && $0 !== window }.map { "\(type(of: $0)):\($0.title)" }
        let child = sheet.attachedSheet.map { " child sheet: " + sheetText($0) } ?? ""
        return "[" + texts.filter { !$0.isEmpty }.joined(separator: " | ").prefix(300) + "]" + child + (others.isEmpty ? "" : " windows: \(others.joined(separator: ", "))")
    }

    func vaultState() -> String {
        guard let sv = UIDriver.services else { return "?" }
        return "local=\(sv.credentials.vault == nil ? "locked" : "open (\(sv.credentials.items.count))") vaultwarden=\(sv.vaultwarden.isUnlocked ? "unlocked" : "locked")"
    }

    // MARK: Rows

    /// Row ids of every outline row, top to bottom, with each row's level.
    func visibleRowIds() -> [String] {
        guard let outline else { return [] }
        return (0..<outline.numberOfRows).map { "\(outline.level(forRow: $0)):" + ((outline.item(atRow: $0) as? OutlineNode)?.rowId ?? "?") }
    }

    func name(of node: OutlineNode) -> String {
        switch node.kind {
        case .group(let t): t
        case .folder(let f): f.name
        case .connection(let c): node.isFavoriteMirror ? "★\(c.name)" : c.name
        case .tasks: "Tasks"
        case .triggers: "Triggers"
        case .task(let t): "⚡\(t.name)"
        case .tool(let tool, let c): "\(c.name)›\(tool.label)"
        case .session(let r, _): "●\(r.title)"
        case .generated(let g): "◇\(g.title)"
        case .pluginItem(let r): "◆\(r.label)"
        }
    }

    func row(named name: String) -> Int? {
        guard let outline else { return nil }
        return (0..<outline.numberOfRows).first { (outline.item(atRow: $0) as? OutlineNode).map(self.name(of:)) == name }
    }

    /// `click` / `cmdclick` / `doubleclick` while quiet: the row selected through the outline (a
    /// Command-click toggles it), a double-click also sends the outline's double action.
    /// The class of AppKit's tool tip window when one is on screen.
    static func shownToolTip() -> String? {
        NSApp.windows.first { $0.isVisible && String(describing: type(of: $0)).contains("ToolTip") }.map { String(describing: type(of: $0)) }
    }

    /// Labels of the toolbar items now in the » menu; nil without a toolbar.
    func overflowItems() -> [String]? {
        guard let toolbar = window?.toolbar else { return nil }
        let visible = Set((toolbar.visibleItems ?? []).map(\.itemIdentifier))
        let spacers: Set<NSToolbarItem.Identifier> = [.flexibleSpace, .space]
        // Spacers and SwiftUI's split-view tracking separators are layout, never a button.
        return toolbar.items.filter { !visible.contains($0.itemIdentifier) && !spacers.contains($0.itemIdentifier)
            && !$0.itemIdentifier.rawValue.contains("Separator") }
            .map { $0.label.isEmpty ? ($0.paletteLabel.isEmpty ? $0.itemIdentifier.rawValue : $0.paletteLabel) : $0.label }
    }

    private func quietClick(_ cmd: String, _ line: String, row: Int, outline: NSOutlineView) async {
        outline.window?.makeFirstResponder(outline)
        if cmd == "cmdclick" {
            var rows = outline.selectedRowIndexes
            if rows.contains(row) { rows.remove(row) } else { rows.insert(row) }
            outline.selectRowIndexes(rows, byExtendingSelection: false)
        } else {
            outline.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
            // The single-click action reads `clickedRow` too; run its connection half here.
            if let n = outline.item(atRow: row) as? OutlineNode, !n.isGroup { commands.tree.connectionClicked() }
        }
        await settle()
        // The double action reads `clickedRow`, which only a real click sets; Return on the
        // selected row runs the same activation (folders toggle, connections run their default).
        if cmd == "doubleclick", let ret = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                                           windowNumber: outline.window?.windowNumber ?? 0, context: nil, characters: "\r",
                                                           charactersIgnoringModifiers: "\r", isARepeat: false, keyCode: 36) {
            outline.keyDown(with: ret)
            await settle()
        }
        let name = (outline.item(atRow: row) as? OutlineNode).map(self.name(of:)) ?? ""
        let hit = cmd != "click" || selectedNames().split(separator: ",").contains(Substring(name))
        write("\(hit ? "" : "FAIL ")\(line) -> selected \(selectedNames()) (quiet: via outline)")
    }

    func selectedNames() -> String {
        guard let outline else { return "-" }
        return outline.selectedRowIndexes.compactMap { (outline.item(atRow: $0) as? OutlineNode).map(name(of:)) }.joined(separator: ",")
    }

    func dump() -> String {
        guard let outline else { return "" }
        return (0..<outline.numberOfRows).compactMap { r -> String? in
            guard let n = outline.item(atRow: r) as? OutlineNode else { return nil }
            let disclosure = n.isGroup || n.isFolder || n.sessionCount > 0 ? (outline.isItemExpanded(n) ? "▾ " : "▸ ") : "  "
            // A session row shows its state; a collapsed connection its session count (UI-05).
            let extra = n.session.map { " (\($0.state.label))" } ?? (n.sessionCount > 0 && !outline.isItemExpanded(n) ? " (\(n.sessionCount))" : "")
            let sel = outline.selectedRowIndexes.contains(r) ? "  [selected]" : ""
            return String(repeating: "    ", count: outline.level(forRow: r)) + disclosure + name(of: n) + extra + sel
        }.joined(separator: "\n")
    }

    // MARK: Events

    func click(row: Int, count: Int, flags: NSEvent.ModifierFlags) {
        guard let outline, let window else { return }
        let rect = outline.rect(ofRow: row)
        let point = outline.convert(NSPoint(x: rect.midX, y: rect.midY), to: nil)
        for n in 1...count {
            let up = NSEvent.mouseEvent(with: .leftMouseUp, location: point, modifierFlags: flags, timestamp: ProcessInfo.processInfo.systemUptime,
                                        windowNumber: window.windowNumber, context: nil, eventNumber: 0, clickCount: n, pressure: 0)!
            let down = NSEvent.mouseEvent(with: .leftMouseDown, location: point, modifierFlags: flags, timestamp: ProcessInfo.processInfo.systemUptime,
                                          windowNumber: window.windowNumber, context: nil, eventNumber: 0, clickCount: n, pressure: 1)!
            // The table's mouse-tracking loop waits for the up event; deliver it shortly after the down,
            // from another thread, as the hardware would (postEvent is thread-safe).
            let upEvent = UncheckedEvent(event: up)
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.03) { NSApp.postEvent(upEvent.event, atStart: false) }
            window.sendEvent(down)
        }
    }

    static let keyCodes: [String: (code: UInt16, chars: String)] = [
        "down": (125, "\u{F701}"), "up": (126, "\u{F700}"), "left": (123, "\u{F702}"), "right": (124, "\u{F703}"),
        "return": (36, "\r"), "escape": (53, "\u{1b}"), "backspace": (51, "\u{7f}"), "tab": (48, "\t"),
    ]

    func key(_ spec: String) {
        var flags: NSEvent.ModifierFlags = []
        var parts = spec.split(separator: "+").map(String.init)
        let k = parts.removeLast()
        for m in parts {
            switch m {
            case "cmd": flags.insert(.command)
            case "opt": flags.insert(.option)
            case "shift": flags.insert(.shift)
            case "ctrl": flags.insert(.control)
            default: break
            }
        }
        guard let known = Self.keyCodes[k] else { return sendKey(k, keyCode: 0, flags: flags) }
        if (123...126).contains(known.code) { flags.formUnion([.numericPad, .function]) }
        sendKey(known.chars, keyCode: known.code, flags: flags)
    }

    /// The terminal view of the selected tab's focused pane.
    func focusedTerminalView() -> TerminalNSView? {
        guard let tab = UIDriver.services?.sessions.selectedTab,
              let pane = tab.panes.first(where: { $0.id == tab.focusedPane }) ?? tab.panes.first else { return nil }
        return window?.contentView?.allSubviews(of: TerminalNSView.self).first { $0.terminal === pane.terminal }
    }

    func sendKey(_ chars: String, keyCode: UInt16, flags: NSEvent.ModifierFlags) {
        guard let window else { return }
        let e = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: flags, timestamp: ProcessInfo.processInfo.systemUptime,
                                 windowNumber: window.windowNumber, context: nil, characters: chars,
                                 charactersIgnoringModifiers: chars, isARepeat: false, keyCode: keyCode)!
        window.sendEvent(e)
    }

    // MARK: Menus

    func menu(_ arg: String, settleAfter: Bool = true) async {
        let parts = arg.components(separatedBy: " > ")
        guard let outline, let window, let r = row(named: parts[0]) else { return write("FAIL menu \(arg): no row") }
        let rect = outline.rect(ofRow: r)
        let point = outline.convert(NSPoint(x: rect.midX, y: rect.midY), to: nil)
        let event = NSEvent.mouseEvent(with: .rightMouseDown, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                       windowNumber: window.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)!
        let t0 = CFAbsoluteTimeGetCurrent()
        // The same calls AppKit makes for a right-click, minus the modal tracking loop.
        guard let menu = outline.menu(for: event) else { return write("FAIL menu \(arg): none") }
        menu.delegate?.menuNeedsUpdate?(menu)
        let ms = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        if parts.count == 1 {
            let items = menu.items.map { $0.isSeparatorItem ? "—" : ($0.isEnabled ? $0.title : "(\($0.title))") }
            return write(String(format: "MENU %@ (%.2f ms): %@", parts[0], ms, items.joined(separator: " | ")))
        }
        guard let index = menu.items.firstIndex(where: { $0.title == parts[1] }) else { return write("FAIL menu \(arg): no item") }
        if let sub = menu.items[index].submenu {
            // `menu <row> > <item> > <choice>`; with no choice, list the submenu (✓ = checked).
            guard parts.count == 3 else {
                return write("SUBMENU \(arg): " + sub.items.map { $0.isSeparatorItem ? "—" : ($0.state == .on ? "✓" : "") + ($0.isEnabled ? $0.title : "(\($0.title))") }.joined(separator: " | "))
            }
            guard let i = sub.items.firstIndex(where: { $0.title == parts[2] }), sub.items[i].isEnabled else { return write("FAIL menu \(arg): no choice") }
            sub.performActionForItem(at: i)
            await settle(0.6)
            return write("menu \(arg) -> sheet \(window.attachedSheet != nil ? "shown" : "none")")
        }
        menu.performActionForItem(at: index)
        guard settleAfter else { return }
        await settle(0.4)
        // Q12: the action must have run on the named row (the context-menu target is selected).
        // Reveal Connection (a session row, UI-05) moves the selection to the parent on purpose.
        let reveal = parts[1] == "Reveal Connection"
        let hit = reveal ? outline.selectedRowIndexes.count == 1 && (outline.item(atRow: outline.selectedRow) as? OutlineNode)?.isLibraryConnection == true
            : selectedNames().split(separator: ",").contains(Substring(parts[0]))
        write("\(hit ? "" : "FAIL ")menu \(arg) -> selected \(selectedNames())")
    }

    // MARK: Drag and drop

    func drag(_ arg: String) {
        guard let outline, let ds = outline.dataSource else { return write("FAIL drag") }
        let parts = arg.components(separatedBy: " -> ")
        guard parts.count == 2, let src = row(named: parts[0]), let id = (outline.item(atRow: src) as? OutlineNode)?.targetId else {
            return write("FAIL drag \(arg): source")
        }
        let dest = parts[1].components(separatedBy: " before ")
        guard let d = row(named: dest[0]), let target = outline.item(atRow: d) as? OutlineNode else { return write("FAIL drag \(arg): target") }
        var index = -1
        if dest.count == 2, let b = row(named: dest[1]), let anchor = outline.item(atRow: b) as? OutlineNode {
            index = target.children.firstIndex { $0 === anchor } ?? -1
        }
        let pb = NSPasteboard(name: .init("dev.bastion.uidriver.\(UUID().uuidString)"))
        defer { pb.releaseGlobally() }
        pb.clearContents()
        let item = NSPasteboardItem()
        item.setString(id, forType: .bastionNode)
        pb.writeObjects([item])
        let info = FakeDrag(pasteboard: pb)
        let op = ds.outlineView?(outline, validateDrop: info, proposedItem: target, proposedChildIndex: index) ?? []
        guard op == .move else { return write("drag \(arg) -> refused") }
        let ok = ds.outlineView?(outline, acceptDrop: info, item: target, childIndex: index) ?? false
        write("drag \(arg) -> \(ok ? "moved" : "refused")")
    }

    func setFilter(_ text: String) -> Bool {
        let fields = NSApp.windows.flatMap { ($0.contentView?.superview ?? $0.contentView)?.allSubviews(of: NSSearchField.self) ?? [] }
        guard let field = fields.first else { return false }
        field.stringValue = text
        // SwiftUI's searchable field listens for text changes.
        NotificationCenter.default.post(name: NSControl.textDidChangeNotification, object: field)
        field.delegate?.controlTextDidChange?(Notification(name: NSControl.textDidChangeNotification, object: field))
        return true
    }

    /// Screen frame of the first accessibility element whose label or title is `label`.
    func axFrame(label: String, in window: NSWindow) -> NSRect? {
        var queue: [Any] = [window]
        var visited = 0
        while !queue.isEmpty, visited < 5000 {
            let el = queue.removeFirst()
            visited += 1
            // Dynamic dispatch: SwiftUI's elements are private NSObject subclasses.
            let ax = el as AnyObject
            let names = [ax.accessibilityLabel?() ?? nil, ax.accessibilityTitle?() ?? nil, ax.accessibilityIdentifier?() ?? nil]
            if names.contains(label), let frame = ax.accessibilityFrame?(), frame.width > 0 { return frame }
            queue += ((ax.accessibilityChildren?() ?? nil) ?? [])
        }
        return nil
    }

    /// Selection latency: click each row and force the resulting SwiftUI update and layout.
    /// `timed-connect <row>`: double-click a connection row and report, in ms from the click,
    /// whether a sheet appeared, when its tab was added and when the terminal first showed text
    /// (owner points 23/26: double-click to first frame of the session).
    func timedConnect(_ name: String) async {
        guard let sv = UIDriver.services, let r = row(named: name), let node = outline?.item(atRow: r) as? OutlineNode,
              case .connection(let c) = node.kind else {
            return write("FAIL timed-connect \(name): no row")
        }
        let id = c.id
        let before = Set(sv.sessions.tabs.map(\.id))
        let t0 = CFAbsoluteTimeGetCurrent()
        if let outline, window?.isKeyWindow == false, QuietLaunch.isOn {
            outline.selectRowIndexes(IndexSet(integer: r), byExtendingSelection: false)
            commands.run("connect-new-tab", on: id)
        } else {
            click(row: r, count: 2, flags: [])
        }
        var sheetAt: Double?, tabAt: Double?, textAt: Double?
        let ms = { (CFAbsoluteTimeGetCurrent() - t0) * 1000 }
        while textAt == nil && ms() < 20_000 {
            if sheetAt == nil, window?.attachedSheet != nil { sheetAt = ms() }
            if let tab = sv.sessions.tabs.first(where: { !before.contains($0.id) && $0.connectionId == id }) {
                if tabAt == nil { tabAt = ms() }
                // A desktop tab (RDP) has no terminal text to wait for.
                if tab.terminal == nil { break }
                if let t = tab.terminal, !Self.screenText(t).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    window?.displayIfNeeded()
                    textAt = ms()
                }
            }
            if sheetAt != nil, tabAt == nil, ms() > 3_000 { break }
            try? await Task.sleep(for: .milliseconds(2))
        }
        let f = { (v: Double?) in v.map { String(format: "%.0f", $0) } ?? "-" }
        write("TIMED-CONNECT \(name) sheet=\(f(sheetAt)) tab=\(f(tabAt)) first-text=\(f(textAt)) ms")
    }

    func timeSelect(_ names: String) async {
        for n in names.split(separator: ",").map(String.init) {
            guard let r = row(named: n) else { continue }
            // The stall report names the select a gap falls in, not just the whole step.
            let whole = StallWatch.shared.step
            StallWatch.shared.step = "\(whole) [\(n)]"
            defer { StallWatch.shared.step = whole }
            let t0 = CFAbsoluteTimeGetCurrent()
            click(row: r, count: 1, flags: [])
            await Task.yield()
            window?.contentView?.layoutSubtreeIfNeeded()
            window?.displayIfNeeded()
            write(String(format: "SELECT %@ %.1f ms", n, (CFAbsoluteTimeGetCurrent() - t0) * 1000))
            await settle(0.15)
        }
    }
}

private struct UncheckedEvent: @unchecked Sendable { let event: NSEvent }

/// Minimal dragging info: the outline's data source only reads the pasteboard.
/// For the rest of a driver run: closes a picker menu that SwiftUI presents outside a sheet-popup step. On macOS 27
/// the synthesized click can leave a presentation queued that opens seconds later, and a resize inside that menu's
/// tracking loop crashed (#1104). Logged, never silent.
@MainActor private enum PickerMenuGuard {
    static var titles: Set<String> = []
    static var stepActive = false
    private static var token: NSObjectProtocol?

    static func install(log: @escaping @MainActor (String) -> Void) {
        guard token == nil else { return }
        token = NotificationCenter.default.addObserver(forName: NSMenu.didBeginTrackingNotification, object: nil, queue: .main) { note in
            nonisolated(unsafe) let tracked = note.object as? NSMenu
            MainActor.assumeIsolated {
                guard !stepActive, let menu = tracked, !titles.isEmpty, Set(menu.items.map(\.title)) == titles else { return }
                menu.cancelTrackingWithoutAnimation()
                log("SHEET-POPUP-LATE closed a picker menu opened outside its step")
            }
        }
    }
}

@MainActor private final class FakeDrag: NSObject, @preconcurrency NSDraggingInfo {
    let draggingPasteboard: NSPasteboard
    init(pasteboard: NSPasteboard) { draggingPasteboard = pasteboard }
    var draggingDestinationWindow: NSWindow? { nil }
    var draggingSourceOperationMask: NSDragOperation { .move }
    var draggingLocation: NSPoint { .zero }
    var draggedImageLocation: NSPoint { .zero }
    var draggedImage: NSImage? { nil }
    var draggingSource: Any? { nil }
    var draggingSequenceNumber: Int { 0 }
    var draggingFormation: NSDraggingFormation = .default
    var animatesToDestination = false
    var numberOfValidItemsForDrop = 1
    var springLoadingHighlight: NSSpringLoadingHighlight { .none }
    func slideDraggedImage(to screenPoint: NSPoint) {}
    func enumerateDraggingItems(options: NSDraggingItemEnumerationOptions = [], for view: NSView?, classes: [AnyClass],
                                searchOptions: [NSPasteboard.ReadingOptionKey: Any] = [:],
                                using block: (NSDraggingItem, Int, UnsafeMutablePointer<ObjCBool>) -> Void) {}
    func resetSpringLoading() {}
}


extension UIDriver {
    /// The selected files tab's browser, else the selected tab's file panel.
    static var selectedBrowser: FilesBrowser? {
        guard let tab = services?.sessions.selectedTab else { return nil }
        if case .files(let b) = tab.content { return b }
        return tab.filePanel
    }
}


/// The app's own accessibility tree through the AX client API, as VoiceOver sees it (SDK 27 test hook).
/// Main thread only: the own process answers in process, and SwiftUI reads its state while answering.
@MainActor enum AXSelfClient {
    private static let maxNodes = 4000

    static func pressPopUp(showing: String) -> String {
        let app = AXUIElementCreateApplication(getpid())
        AXUIElementSetMessagingTimeout(app, 3)
        var queue: [AXUIElement] = [app]
        var visited = 0
        var roles: [String] = []
        while !queue.isEmpty, visited < maxNodes {
            let e = queue.removeFirst()
            visited += 1
            let role = string(e, kAXRoleAttribute) ?? "-"
            if role == kAXPopUpButtonRole || role == kAXMenuButtonRole {
                let names = [string(e, kAXValueAttribute), string(e, kAXTitleAttribute), string(e, kAXDescriptionAttribute)]
                roles.append("\(role)=\(names.compactMap { $0 }.joined(separator: "/"))")
                if showing == "*" || names.contains(showing) {
                    return AXUIElementPerformAction(e, kAXPressAction as CFString) == .success ? "pressed" : "press failed"
                }
            }
            var children: CFTypeRef?
            if AXUIElementCopyAttributeValue(e, kAXChildrenAttribute as CFString, &children) == .success, let list = children as? [AXUIElement] {
                queue += list
            }
        }
        return "none of \(visited) nodes (trusted=\(AXIsProcessTrusted())) pop-ups: \(roles.joined(separator: ", "))"
    }

    private static func string(_ e: AXUIElement, _ attribute: String) -> String? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(e, attribute as CFString, &value) == .success, let value else { return nil }
        return value as? String ?? (CFGetTypeID(value) == CFStringGetTypeID() ? (value as! String) : nil)
    }
}

#endif
