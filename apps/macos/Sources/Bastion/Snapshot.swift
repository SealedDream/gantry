#if BASTION_TEST_HOOKS
import AppKit
import BastionCore
import BastionRdp

/// Verification aid: with `BASTION_SNAPSHOT=<dir>` set, the app renders its own main window to
/// `<dir>/light.png` and `<dir>/dark.png` (via `cacheDisplay`, no screen-recording permission
/// needed) and quits. Has no effect otherwise.
///
/// `BASTION_SNAPSHOT=hold` runs the scripting below but skips the capture and stays open, for the
/// UI driver's own captures (`UIDriverCapture`).
///
/// Optional scripted session before the capture (test servers only; use with `BASTION_LIBRARY`
/// pointing at a throwaway library whose directory holds a pre-seeded known_hosts):
/// - `BASTION_SNAPSHOT_CONNECT=<connection name>` and `BASTION_SNAPSHOT_KEY=<private key file>`
///   open an SSH terminal tab through the normal connect path (strict host keys).
/// - `BASTION_SNAPSHOT_RDP=<connection name>` and `BASTION_SNAPSHOT_PASSWORD_FILE=<file>` open an RDP tab
///   (certificate must already be pinned in the library directory's rdp_certificates.json).
///   `BASTION_SNAPSHOT_TYPE` then types into the remote desktop as key presses.
/// - `BASTION_SNAPSHOT_WEB=<connection name>` opens a web tab for it.
/// - `BASTION_SNAPSHOT_VNC=<connection name>` opens a VNC tab (`BASTION_SNAPSHOT_PASSWORD_FILE` if the
///   server asks for a password); `BASTION_SNAPSHOT_TYPE` types into it as keysyms.
/// - `BASTION_SNAPSHOT_CREDENTIAL=<name>` with `BASTION_SNAPSHOT_SELECT=<connection>` and `BASTION_SNAPSHOT_PASSWORD_FILE`
///   stores a vault password credential under that name (the connection's user), assigns it to the connection and,
///   when `BASTION_SNAPSHOT_CONNECT` names the same connection without `BASTION_SNAPSHOT_KEY`, connects through the vault.
///   `BASTION_SNAPSHOT_SHEET=updates` runs Check for Updates (with `BASTION_UPDATE_URL`) and shows its alert.
///   `BASTION_SNAPSHOT_SHEET=credentials` opens the Credentials manager (`=credentials-vaultwarden` on its Vaultwarden pane).
/// - `BASTION_SNAPSHOT_VAULTWARDEN=<server url>,<e-mail>` with `BASTION_SNAPSHOT_VAULTWARDEN_PASSWORD_FILE` unlocks a (local test)
///   Vaultwarden; `BASTION_SNAPSHOT_VAULTWARDEN_ITEM=<item name>` assigns that item to the `BASTION_SNAPSHOT_CONNECT` /
///   `BASTION_SNAPSHOT_SELECT` connection, and `BASTION_SNAPSHOT_CONNECT` then connects through it. For a two-step account,
///   `BASTION_SNAPSHOT_VAULTWARDEN_CODE=<6 digits>` answers the code prompt; without it the pane is left on the prompt.
/// - `BASTION_SNAPSHOT_FILES=1` opens an SFTP files tab for that connection instead of a terminal.
/// - `BASTION_SNAPSHOT_LOCAL=1` opens a local shell tab instead.
/// - `BASTION_SNAPSHOT_SPLIT=right,down` splits the tab's focused pane once per entry (as ⌘D / ⇧⌘D).
///   `BASTION_SNAPSHOT_SPLIT_RATIO=<0.1…0.9>` then sets the outermost divider (as a drag would);
///   `BASTION_SNAPSHOT_FOCUS=left|right|up|down` moves focus once (as ⌥⌘arrow).
/// - `BASTION_SNAPSHOT_TYPE=<text>` is typed into the tab, into every pane when split (`\n` becomes Return).
/// - `BASTION_SNAPSHOT_SELECT_ROW=<n>` line-selects row n of the terminal; `BASTION_SNAPSHOT_SEARCH=<regex>`
///   highlights the newest match.
/// - `BASTION_SNAPSHOT_SELECT=<connection name>` selects it in the sidebar (inspector visible).
/// - `BASTION_SNAPSHOT_SEED=1` fills an empty (throwaway) library with a small demo tree first.
/// - `BASTION_SNAPSHOT_ACCENT=<accent>` / `BASTION_SNAPSHOT_DENSITY=<density>` set the appearance (persisted);
///   `BASTION_SNAPSHOT_TERMINAL_THEME=<preset id>` sets the terminal colours (persisted).
/// - `BASTION_SNAPSHOT_SHEET=properties` opens the property editor for the selection; `=defaults-ssh`
///   (or another type) its Default Settings; `=folder-defaults` the first folder's defaults;
///   `=appearance` the Appearance page; `=add` the Add menu (a popover, captured in the main window).
/// - `BASTION_SNAPSHOT_SHEET=folder` opens New folder; `=sources` opens SSH Config Sources and runs Check for Changes;
///   an attached sheet is written as `<appearance>-sheet.png`.
enum Snapshot {
    @MainActor static func runIfRequested(model: LibraryModel, sessions: SessionsModel, appearance: AppearanceSettings,
                                           credentials: CredentialsModel, vaultwarden: VaultwardenModel,
                                           commands: Commands) {
        let env = ProcessInfo.processInfo.environment
        guard let dir = env["BASTION_SNAPSHOT"] else { return }
        Task { @MainActor in
            if env["BASTION_SNAPSHOT_SEED"] == "1" { seed(model) }
            // `BASTION_SNAPSHOT_IMPORT=<file>`: File › Import Connections of that file first.
            if let file = env["BASTION_SNAPSHOT_IMPORT"], let lib = model.library {
                _ = try? lib.importFile(path: file)
                model.mutate { _ in }
            }
            if let accent = env["BASTION_SNAPSHOT_ACCENT"].flatMap(AppearanceSettings.Accent.init) { appearance.accent = accent }
            if let density = env["BASTION_SNAPSHOT_DENSITY"].flatMap(AppearanceSettings.Density.init) { appearance.density = density }
            if let colors = env["BASTION_SNAPSHOT_TERMINAL_THEME"] { appearance.terminalTheme = colors }
            seedCredential(env: env, model: model, sessions: sessions, credentials: credentials)
            await unlockVaultwarden(env: env, model: model, vaultwarden: vaultwarden)
            await openScriptedSession(env: env, model: model, sessions: sessions)
            model.scriptedSelection = env["BASTION_SNAPSHOT_SELECT"]
            model.scriptedSheet = env["BASTION_SNAPSHOT_SHEET"]
            // `hold` scripts the window and leaves it open for the UI driver, which takes its own captures.
            if dir == "hold" { return UIDriver.runIfRequested(commands: commands) }
            try? await Task.sleep(for: .seconds(2))
            capture(["light": .aqua, "dark": .darkAqua].sorted { $0.key > $1.key }, to: URL(fileURLWithPath: dir))
        }
    }

    /// Test data only: `BASTION_SNAPSHOT_PASSWORD_FILE` holds a lab password, never a real one.
    /// Test servers only: the password file holds a throwaway lab account's master password.
    @MainActor private static func unlockVaultwarden(env: [String: String], model: LibraryModel, vaultwarden: VaultwardenModel) async {
        guard let spec = env["BASTION_SNAPSHOT_VAULTWARDEN"], let file = env["BASTION_SNAPSHOT_VAULTWARDEN_PASSWORD_FILE"],
              let password = (try? String(contentsOfFile: file, encoding: .utf8))?.trimmingCharacters(in: .newlines)
        else { return }
        let parts = spec.split(separator: ",", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { return }
        vaultwarden.serverUrl = parts[0]
        vaultwarden.email = parts[1]
        var unlocked = await vaultwarden.unlock(password: password)
        // Two-step accounts: without BASTION_SNAPSHOT_VAULTWARDEN_CODE the pane stays on the code prompt.
        if !unlocked, vaultwarden.needsCode, let code = env["BASTION_SNAPSHOT_VAULTWARDEN_CODE"] {
            unlocked = await vaultwarden.unlock(password: password, code: code)
        }
        guard unlocked else { return }
        if let itemName = env["BASTION_SNAPSHOT_VAULTWARDEN_ITEM"],
           let target = env["BASTION_SNAPSHOT_CONNECT"] ?? env["BASTION_SNAPSHOT_SELECT"],
           let tree = model.tree, let conn = find(target, in: tree),
           let item = vaultwarden.items.first(where: { $0.name == itemName }) {
            model.mutate { try $0.setVaultwardenItem(connectionId: conn.id, itemId: item.id) }
        }
    }

    @MainActor private static func seedCredential(env: [String: String], model: LibraryModel, sessions: SessionsModel,
                                                  credentials: CredentialsModel) {
        guard let name = env["BASTION_SNAPSHOT_CREDENTIAL"],
              let target = env["BASTION_SNAPSHOT_CONNECT"] ?? env["BASTION_SNAPSHOT_SELECT"],
              let file = env["BASTION_SNAPSHOT_PASSWORD_FILE"],
              let password = (try? String(contentsOfFile: file, encoding: .utf8))?.trimmingCharacters(in: .newlines),
              let tree = model.tree, let conn = find(target, in: tree), let vault = credentials.open(sessions: sessions)
        else { return }
        let existing = vault.list().first { $0.name == name }?.id
        var id: String?
        credentials.mutate { id = try $0.savePassword(id: existing, name: name, folder: "Lab", username: conn.username ?? "", password: password) }
        model.mutate { try $0.setCredential(connectionId: conn.id, credentialId: id) }
    }

    @MainActor private static func openScriptedSession(env: [String: String], model: LibraryModel, sessions: SessionsModel) async {
        if env["BASTION_SNAPSHOT_LOCAL"] == "1" {
            sessions.openLocal()
        } else if let name = env["BASTION_SNAPSHOT_RDP"], let tree = model.tree, let conn = find(name, in: tree) {
            await openRdp(conn, passwordFile: env["BASTION_SNAPSHOT_PASSWORD_FILE"], sessions: sessions)
        } else if let name = env["BASTION_SNAPSHOT_WEB"], let tree = model.tree, let conn = find(name, in: tree) {
            if let url = WebTarget.url(host: conn.host, port: conn.port) { sessions.add(TerminalTab(name: conn.name, content: .web(url), connectionId: conn.id)) }
            else { sessions.error = "\(conn.name): only http and https addresses can be opened." }
        } else if let name = env["BASTION_SNAPSHOT_VNC"], let tree = model.tree, let conn = find(name, in: tree) {
            let password = env["BASTION_SNAPSHOT_PASSWORD_FILE"].flatMap { try? String(contentsOfFile: $0, encoding: .utf8) }?
                .trimmingCharacters(in: .newlines)
            switch await sessions.connectVnc(host: conn.host, port: conn.port ?? VncDefaults.port, password: password) {
            case .connected(let viewer): sessions.add(TerminalTab(name: conn.name, content: .vnc(viewer), connectionId: conn.id))
            case .failed(let message): sessions.error = message
            }
        } else if let name = env["BASTION_SNAPSHOT_CONNECT"], env["BASTION_SNAPSHOT_KEY"] == nil, env["BASTION_SNAPSHOT_VAULTWARDEN_ITEM"] != nil,
                  let library = model.library, let tree = model.tree, let conn = find(name, in: tree), let item = conn.vaultwardenItem {
            switch await sessions.connect(library: library, connectionId: conn.id, username: "", login: .vaultwarden(itemId: item),
                                          trust: nil, mode: .terminal) {
            case .connected(let content): sessions.add(TerminalTab(name: conn.name, content: content, connectionId: conn.id))
            case .unknownHost(let hop, let fp): sessions.error = "Unknown host key \(fp) on \(hop ?? conn.host)"
            case .needsCode: sessions.error = "The server asks for a verification code"
            case .tunnel: break
            case .weakAlgorithms(let message, _, _): sessions.error = message
            case .failed(let message): sessions.error = message
            }
        } else if let name = env["BASTION_SNAPSHOT_CONNECT"], env["BASTION_SNAPSHOT_KEY"] == nil,
                  let library = model.library, let tree = model.tree, let conn = find(name, in: tree), let cred = conn.credentialId {
            switch await sessions.connect(library: library, connectionId: conn.id, username: "", login: .vault(credentialId: cred),
                                          trust: nil, mode: .terminal) {
            case .connected(let content): sessions.add(TerminalTab(name: conn.name, content: content, connectionId: conn.id))
            case .unknownHost(let hop, let fp): sessions.error = "Unknown host key \(fp) on \(hop ?? conn.host)"
            case .needsCode: sessions.error = "The server asks for a verification code"
            case .tunnel: break
            case .weakAlgorithms(let message, _, _): sessions.error = message
            case .failed(let message): sessions.error = message
            }
        } else if let name = env["BASTION_SNAPSHOT_CONNECT"], let key = env["BASTION_SNAPSHOT_KEY"],
                  let library = model.library, let tree = model.tree, let conn = find(name, in: tree) {
            switch await sessions.connect(library: library, connectionId: conn.id, username: conn.username ?? "",
                                          login: .keyFile(path: key, passphrase: nil), trust: nil,
                                          mode: env["BASTION_SNAPSHOT_FILES"] == "1" ? .files : .terminal) {
            case .connected(let content): sessions.add(TerminalTab(name: conn.name, content: content, connectionId: conn.id))
            case .unknownHost(let hop, let fp): sessions.error = "Unknown host key \(fp) on \(hop ?? conn.host)"
            case .needsCode: sessions.error = "The server asks for a verification code"
            case .tunnel: break
            case .weakAlgorithms(let message, _, _): sessions.error = message
            case .failed(let message): sessions.error = message
            }
        }
        for axis in (env["BASTION_SNAPSHOT_SPLIT"] ?? "").split(separator: ",").compactMap({ SplitAxis(rawValue: String($0)) }) {
            await sessions.split(axis)
        }
        if let ratio = env["BASTION_SNAPSHOT_SPLIT_RATIO"].flatMap(Double.init),
           case .split(_, let r, _, _)? = sessions.tabs.last?.root {
            r.value = min(SplitRatio.range.upperBound, max(SplitRatio.range.lowerBound, CGFloat(ratio)))
        }
        if let dir = env["BASTION_SNAPSHOT_FOCUS"] {
            let map: [String: PaneDirection] = ["left": .left, "right": .right, "up": .up, "down": .down]
            if let d = map[dir] { sessions.tabs.last?.focusNeighbour(d) }
        }
        if let text = env["BASTION_SNAPSHOT_TYPE"], case .rdp(let session)? = sessions.tabs.last?.content {
            try? await Task.sleep(for: .seconds(2))
            typeRdp(text, into: session)
            return
        }
        if let text = env["BASTION_SNAPSHOT_TYPE"], case .vnc(let viewer)? = sessions.tabs.last?.content {
            try? await Task.sleep(for: .seconds(2))
            for scalar in text.replacingOccurrences(of: "\\n", with: "\n").unicodeScalars {
                guard let keysym = VncKeysyms.keysym(for: scalar) else { continue }
                viewer.key(keysym: keysym, down: true)
                viewer.key(keysym: keysym, down: false)
            }
            return
        }
        guard let text = env["BASTION_SNAPSHOT_TYPE"], let tab = sessions.tabs.last, let terminal = tab.terminal else { return }
        try? await Task.sleep(for: .seconds(1))
        for pane in tab.panes {
            try? pane.terminal.write(bytes: Data(text.replacingOccurrences(of: "\\n", with: "\r").utf8))
        }
        try? await Task.sleep(for: .seconds(1))
        if let row = env["BASTION_SNAPSHOT_SELECT_ROW"].flatMap(UInt16.init) { terminal.selectStart(row: row, col: 0, clicks: 3) }
        if let pattern = env["BASTION_SNAPSHOT_SEARCH"] { _ = try? terminal.search(pattern: pattern, forward: false) }
    }

    @MainActor private static func openRdp(_ conn: ConnectionView, passwordFile: String?, sessions: SessionsModel) async {
        let password = passwordFile.flatMap { try? String(contentsOfFile: $0, encoding: .utf8) }?
            .trimmingCharacters(in: .newlines) ?? ""
        let port = conn.port ?? RdpDefaults.port
        let pin = RdpCertificatePins(dataDir: LibraryModel.dataDir).pin("\(conn.host):\(port)")
        let target = RdpTarget(host: conn.host, port: port, username: conn.username ?? "", domain: nil,
                               width: UInt16(DesktopFit.fallbackSize.width), height: UInt16(DesktopFit.fallbackSize.height), trustedFingerprint: pin, nlaOnly: false, viaLoopbackPort: nil,
                               clipboard: false, sharedFolder: nil, audio: false)
        switch await sessions.connectRdp(target: target, password: password) {
        case .connected(let session): sessions.add(TerminalTab(name: conn.name, content: .rdp(session), connectionId: conn.id))
        case .unknownCertificate(let fp): sessions.error = "Unknown certificate \(fp) on \(conn.host)"
        case .failed(let message): sessions.error = message
        }
    }

    /// Types letters, digits, space, `\n` and US-layout punctuation (shifted ones with Left Shift)
    /// as set-1 scancodes.
    private static func typeRdp(_ text: String, into session: RdpSession) {
        let leftShift: UInt8 = 0x2A
        let rows: [(String, String, UInt8)] = [("1234567890-=", "!@#$%^&*()_+", 0x02), ("qwertyuiop[]", "QWERTYUIOP{}", 0x10),
                                               ("asdfghjkl;'`", "ASDFGHJKL:\"~", 0x1E), ("zxcvbnm,./", "ZXCVBNM<>?", 0x2C)]
        var codes: [Character: (UInt8, Bool)] = [" ": (0x39, false), "\\": (0x2B, false), "|": (0x2B, true), "\n": (0x1C, false)]
        for (plain, shifted, first) in rows {
            for (i, (p, s)) in zip(plain, shifted).enumerated() {
                codes[p] = (first + UInt8(i), false)
                codes[s] = (first + UInt8(i), true)
            }
        }
        for c in text.replacingOccurrences(of: "\\n", with: "\n") {
            guard let (code, shift) = codes[c] else { continue }
            if shift { session.key(scancode: leftShift, extended: false, down: true) }
            session.key(scancode: code, extended: false, down: true)
            session.key(scancode: code, extended: false, down: false)
            if shift { session.key(scancode: leftShift, extended: false, down: false) }
        }
    }

    /// Demo tree for screenshots; only touches a library that is still empty.
    @MainActor private static func seed(_ model: LibraryModel) {
        guard let tree = model.tree, tree.folders.isEmpty, tree.connections.isEmpty else { return }
        model.mutate { lib in
            let prod = try lib.addFolder(parent: nil, name: "Production")
            let staging = try lib.addFolder(parent: nil, name: "Staging")
            let web = try lib.addConnection(parent: prod, name: "web-01", protocol: "ssh", host: "10.0.1.11", port: nil, username: nil)
            try lib.setFavorite(id: web, favorite: true)
            _ = try lib.addConnection(parent: prod, name: "db-primary", protocol: "ssh", host: "10.0.1.20", port: 2222, username: "postgres")
            _ = try lib.addConnection(parent: staging, name: "stage-app", protocol: "ssh", host: "stage.internal", port: nil, username: "deploy")
            let win = try lib.addConnection(parent: nil, name: "build-win", protocol: "rdp", host: "build-win.lan", port: nil, username: nil)
            _ = try lib.addConnection(parent: nil, name: "build-vnc", protocol: "vnc", host: "build-vnc.lan", port: nil, username: nil)
            try lib.setProperty(id: prod, key: "username", value: "deploy")
            try lib.setProperty(id: prod, key: "keepalive_secs", value: "30")
            try lib.setTypeDefault(protocolName: "ssh", key: "keepalive_secs", value: "60")
            try lib.setFavorite(id: win, favorite: true)
        }
    }

    private static func find(_ name: String, in f: FolderView) -> ConnectionView? {
        f.connections.first { $0.name == name } ?? f.folders.lazy.compactMap { find(name, in: $0) }.first
    }

    @MainActor private static func write(_ window: NSWindow?, to url: URL) {
        guard let window else { return }
        // A window-server image of our own window includes sidebar and inspector contents,
        // which `cacheDisplay` leaves blank; it needs no screen-recording permission.
        if let image = windowImage(window.windowNumber) {
            try? NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])?.write(to: url)
            return
        }
        guard let view = window.contentView?.superview, let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: url)
    }

    /// `CGWindowListCreateImage`, looked up at run time because newer SDKs mark it unavailable.
    static func windowImage(_ number: Int) -> CGImage? {
        typealias Fn = @convention(c) (CGRect, UInt32, UInt32, UInt32) -> Unmanaged<CGImage>?
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "CGWindowListCreateImage") else { return nil }
        let fn = unsafeBitCast(sym, to: Fn.self)
        // .optionIncludingWindow = 1 << 3, .boundsIgnoreFraming = 1 << 0, .bestResolution = 1 << 3
        return fn(.null, 1 << 3, UInt32(number), (1 << 0) | (1 << 3))?.takeRetainedValue()
    }

    /// One appearance per step, each given time to re-render before capture.
    @MainActor private static func capture(_ queue: [(key: String, value: NSAppearance.Name)], to dir: URL) {
        guard let (name, appearance) = queue.first else {
            // An open sheet would block termination.
            for w in NSApp.windows { if let sheet = w.attachedSheet { w.endSheet(sheet) } }
            return QuitConfirm.terminateWithoutAsking()
        }
        NSApp.appearance = NSAppearance(named: appearance)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            let main = NSApp.windows.first { $0.isVisible && $0.sheetParent == nil }
            write(main, to: dir.appendingPathComponent("\(name).png"))
            if let sheet = main?.attachedSheet { write(sheet, to: dir.appendingPathComponent("\(name)-sheet.png")) }
            capture(Array(queue.dropFirst()), to: dir)
        }
    }
}
#endif
