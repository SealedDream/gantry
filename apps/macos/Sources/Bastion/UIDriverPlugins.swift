#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for the Plugins page (PLUG-06a part 1). Reads the same core calls the page uses.
extension Driver {
    /// Helpers running at `plugin-helpers mark`.
    static var helperMark = 0

    /// Running `bastion-plugin-host` processes (the end-to-end proof that the helper starts and stops with the view).
    static func helperCount() -> Int {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        p.arguments = ["-x", "bastion-plugin-host"]
        let pipe = Pipe()
        p.standardOutput = pipe
        do { try p.run() } catch { return -1 }
        p.waitUntilExit()
        let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return out.split(separator: "\n").count
    }

    /// Handles one of these steps; false when `cmd` is not one.
    func pluginsStep(_ cmd: String, _ arg: String) async -> Bool {
        switch cmd {
        case "plugins-tab":
            NotificationCenter.default.post(name: PluginsView.selectTab, object: arg)
            await settle()
            write("PLUGINS-TAB \(arg) sheet=\(window?.attachedSheet != nil)")
        case "plugins-state":
            let dir = LibraryModel.dataDir.path
            let installed = (try? pluginsInstalled(dataDir: dir).count).map(String.init) ?? "error"
            let updates = (try? pluginsUpdates(dataDir: dir).count).map(String.init) ?? "error"
            write("PLUGINS-STATE installed=\(installed) updates=\(updates) sheet=\(window?.attachedSheet != nil)")
        case "plugins-refresh":
            let outcome = (try? pluginsRefresh(dataDir: LibraryModel.dataDir.path, mirror: PluginsPage.mirror)) ?? "error"
            write("PLUGINS-REFRESH \(PluginsText.catalogueText(outcome))")
        case "plugins-install":
            // `plugins-install <file.bastionplugin>`: installs it unverified, as the page's Install button would after its confirmation.
            let path = arg.hasPrefix("/") ? arg : LibraryModel.dataDir.appendingPathComponent(arg).path
            let r = Result { try pluginInstallFile(dataDir: LibraryModel.dataDir.path, path: path, allowUnverified: true) }
            switch r {
            case .success(let id): write("PLUGINS-INSTALL ok id=\(id)")
            case .failure(let e): write("FAIL plugins-install: \(e)")
            }
        case "plugins-install-signed":
            // `plugins-install-signed <file.bastionplugin>`: as the owner does, signature required.
            let path = (arg as NSString).expandingTildeInPath
            switch Result(catching: { try pluginInstallFile(dataDir: LibraryModel.dataDir.path, path: path, allowUnverified: false) }) {
            case .success(let id): PluginEntries.reload(); write("PLUGINS-INSTALL-SIGNED ok id=\(id)")
            case .failure(let e): write("FAIL plugins-install-signed: \(e.userMessage)")
            }
        case "plugin-props-state":
            // `plugin-props-state key=value|key=value`: FAIL unless the open property dialog shows each pair.
            await settle(0.3)
            let state = PropertyEditorDriver.state
            let missing = arg.split(separator: "|").map(String.init).filter { pair in
                let kv = pair.split(separator: "=", maxSplits: 1).map(String.init)
                return kv.count != 2 || state[kv[0]] != kv[1]
            }
            let shown = state.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: "|")
            write("\(missing.isEmpty ? "" : "FAIL ")PROPS-STATE \(shown)\(missing.isEmpty ? "" : " (expected \(missing.joined(separator: "|")))")")
        case "plugins-install-refused":
            // `plugins-install-refused <file.bastionplugin>`: the install must fail, with the setting on.
            let path = arg.hasPrefix("/") ? arg : LibraryModel.dataDir.appendingPathComponent(arg).path
            let r = Result { try pluginInstallFile(dataDir: LibraryModel.dataDir.path, path: path, allowUnverified: true) }
            switch r {
            case .success(let kind): write("FAIL plugins-install-refused: \(kind)")
            case .failure(let e): write("PLUGINS-INSTALL-REFUSED \(e.userMessage)")
            }
        case "plugins-tier":
            // `plugins-tier <id>`: the installed tier the core derived from the signatures (PLUG-12).
            let p = (try? pluginsInstalled(dataDir: LibraryModel.dataDir.path))?.first { $0.id == arg }
            write(p.map { "PLUGINS-TIER \($0.id) \($0.tier) \($0.version)" } ?? "FAIL plugins-tier: \(arg) not installed")
        case "plugins-open":
            PluginViewWindow.show(pluginId: arg, unverified: true)
            await settle()
            write("PLUGINS-OPEN \(arg) helpers=\(Self.helperCount())")
        case "plugins-view":
            // Waits (up to 15 s) for the view to draw, then writes the node count and kinds.
            var tries = 0
            while tries < 60, (PluginViewWindow.model(for: arg)?.nodes.isEmpty ?? true), PluginViewWindow.model(for: arg)?.ended == nil {
                try? await Task.sleep(nanoseconds: 250_000_000); tries += 1
            }
            guard let m = PluginViewWindow.model(for: arg) else { write("FAIL plugins-view: no tab for \(arg)"); break }
            let kinds = Dictionary(grouping: m.nodes, by: { $0.kind }).map { "\($0.key)=\($0.value.count)" }.sorted().joined(separator: ",")
            write("PLUGINS-VIEW \(arg) nodes=\(m.nodes.count) ended=\(m.ended ?? "none") kinds=\(kinds) helpers=\(Self.helperCount())")
        case "plugins-open-close":
            // Closes the window at once, while the open is still starting; the helper must not stay.
            PluginViewWindow.show(pluginId: arg, unverified: true)
            PluginViewWindow.close(pluginId: arg)
            var seen = 0
            for _ in 0..<32 { try? await Task.sleep(nanoseconds: 250_000_000); seen = max(seen, Self.helperCount()) }
            write("PLUGINS-OPEN-CLOSE \(arg) helpers=\(Self.helperCount()) peak=\(seen)")
        case "plugins-close":
            PluginViewWindow.close(pluginId: arg)
            var tries = 0
            while tries < 40, Self.helperCount() > 0 { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            write("PLUGINS-CLOSE \(arg) helpers=\(Self.helperCount())")
        case "plugin-entry-add", "plugin-entry-row", "plugin-entry-open", "plugin-entry-tls", "plugin-entry-close", "plugin-open-sheet", "plugin-open-go",
             "plugin-entry-trust", "plugin-select", "plugin-press", "plugin-open-answer", "plugin-rows", "plugin-connect-paths",
             "plugin-banner", "plugin-banner-trust", "plugin-token-login", "plugin-rows-count", "plugin-select-match",
             "plugin-sidebar-wait", "plugin-sidebar-activate", "plugin-sidebar-sheet", "plugin-sidebar-open-answer", "plugin-helpers",
             "plugin-confirm-wording", "plugin-tree", "plugin-tree-menu", "plugin-confirm-answer", "plugin-select-many", "plugin-menu",
             "plugin-save-sheet", "plugin-save-answer", "plugin-sidebar-menu", "plugin-sidebar-save-answer",
             "plugin-key-login", "plugin-known-host", "plugin-tree-shown":
            await pluginEntryStep(cmd, arg)
        case "sql-editor", "sql-type", "sql-complete", "sql-key", "sql-run", "sql-comment", "sql-role":
            await sqlStep(cmd, arg)
        default: return false
        }
        return true
    }

    /// PLUG-PVE-01: library entries of plugin connection types. Arguments are space separated;
    /// `<name>` is the entry's display name (no spaces).
    private func pluginEntryStep(_ cmd: String, _ arg: String) async {
        let a = arg.split(separator: " ").map(String.init)
        let model = commands.model
        func entry(_ name: String) -> ConnectionView? { model.connection(named: name) }
        switch cmd {
        case "plugin-entry-add":
            // `plugin-entry-add <type id> <name> <host> [port] [folder=<name>]` (folder name: no spaces)
            PluginEntries.reload()
            let folderName = a.first { $0.hasPrefix("folder=") }.map { String($0.dropFirst(7)) }
            let a = a.filter { !$0.hasPrefix("folder=") }
            guard a.count >= 3 else { return write("FAIL plugin-entry-add: args") }
            var parent: String?
            if let folderName {
                guard let f = model.folder(named: folderName) else { return write("FAIL plugin-entry-add: no folder \(folderName)") }
                parent = f.id
            }
            model.mutate {
                let id = try $0.addPluginConnection(dataDir: LibraryModel.dataDir.path, parent: parent, name: a[1], host: a[2], typeId: a[0])
                if a.count > 3 { try $0.setProperty(id: id, key: "port", value: a[3]) }
            }
            await settle()
            write(entry(a[1]) == nil ? "FAIL plugin-entry-add: \(model.error ?? "not added")" : "PLUGIN-ENTRY-ADD \(a[1]) types=\(PluginEntries.types.map(\.id).joined(separator: ","))")
        case "plugin-entry-row":
            guard let c = entry(a[0]) else { return write("FAIL plugin-entry-row: no \(a[0])") }
            write("PLUGIN-ENTRY-ROW \(c.name) type=\(PluginEntries.type(of: c)?.name ?? "none") unavailable=\(PluginEntries.unavailable(c) ?? "none")")
        case "plugin-entry-open":
            // Opens it as a double-click would and waits (up to 25 s) for the view or its end.
            guard let c = entry(a[0]) else { return write("FAIL plugin-entry-open: no \(a[0])") }
            commands.performDefault(on: c.id)
            let key = "entry:\(c.id)"
            var tries = 0
            func m() -> PluginViewModel? { PluginViewWindow.model(for: key) }
            // The status: the first label, banner or progress node (its id differs per plugin).
            func label() -> String { (m()?.nodes.first { ["label", "banner", "progress"].contains($0.kind) }).map { "\($0.kind):\(($0.value as? String) ?? (($0.value as? [String: Any])?["text"] as? String) ?? "")" } ?? "none" }
            while tries < 100, m()?.ended == nil, m()?.nodes.isEmpty ?? true || label().hasPrefix("progress") || label() == "label:Loading" || label() == "label:Refreshing" {
                try? await Task.sleep(nanoseconds: 250_000_000); tries += 1
            }
            guard let model = m() else { return write("FAIL plugin-entry-open: no tab") }
            // `plugin-entry-open <name> drawn`: the plugin must have drawn and still run (PLUG-12).
            if a.count > 1, a[1] == "drawn", model.nodes.isEmpty || model.ended != nil {
                return write("FAIL plugin-entry-open: not drawn, ended=\(model.ended ?? "none") nodes=\(model.nodes.count)")
            }
            let kinds = Dictionary(grouping: model.nodes, by: { $0.kind }).map { "\($0.key)=\($0.value.count)" }.sorted().joined(separator: ",")
            write("PLUGIN-ENTRY-OPEN \(c.name) selected=\(commands.sessions.selectedTab?.name ?? "none") kinds=\(kinds) status=\(label()) ended=\(model.ended ?? "none") helpers=\(Self.helperCount())")
        case "plugin-entry-tls":
            // `plugin-entry-tls <name> [verify-full | pinned <pin>]`: sets it when given, then prints it.
            guard let c = entry(a[0]), let lib = model.library else { return write("FAIL plugin-entry-tls: no \(a[0])") }
            if a.count > 1 { model.mutate { try $0.setPluginEntryTls(id: c.id, mode: a[1], pinSha256: a.count > 2 ? a[2] : nil) } }
            let t = try? lib.pluginEntryTls(id: c.id)
            write("PLUGIN-ENTRY-TLS \(c.name) mode=\(t?.mode ?? "error") pin=\(t?.pinSha256.map(PluginEntryTlsRow.short) ?? "none")")
        case "plugin-open-sheet":
            // `plugin-open-sheet <name> <reported 0|1> <entry route> [label]`: shows the open sheet
            // (plugin API 1.2) for the entry's open tab as the core's `open-request` update draws it.
            // The core's own checks and its ignoring of an answer it did not ask for are proven in
            // core/tests/plugin_hostile_tests.rs; this proves the sheet's layout.
            guard a.count >= 3, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)") else { return write("FAIL plugin-open-sheet: no open tab") }
            m.apply(["type": "open-request", "request": 9_000, "plugin": m.pluginId, "entry": ["id": c.id, "name": c.name], "protocol": "ssh",
                     "host": "10.20.30.40", "port": 22, "label": a.count > 3 ? a[3...].joined(separator: " ") : "web-01 (Ubuntu 24.04)",
                     "reported": a[1] == "1", "route": "entry", "entry_route": a[2]])
            await settle()
            write("PLUGIN-OPEN-SHEET \(c.name) shown=\(m.openRequest != nil) sheet=\(window?.attachedSheet != nil)")
        case "plugin-open-go":
            // `plugin-open-go <name> <protocol> <host> <port>`: the core's go-ahead after a yes; the app
            // opens the connection through its normal connect path (the connect sheet asks to sign in).
            guard a.count >= 4, let c = entry(a[0]), let lib = model.library, let port = Int(a[3]) else { return write("FAIL plugin-open-go: args") }
            let before = commands.sessions.tabs.count
            PluginViewWindow.openConnection?(PluginViewModel.OpenGo(proto: a[1], host: a[2], port: port, label: "guest", viaEntryRoute: true,
                                                                    checkResolved: false, loopbackOk: false, saveAsEntry: false), c.id, lib)
            var tries = 0
            while tries < 20, window?.attachedSheet == nil, commands.sessions.tabs.count == before { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            write("PLUGIN-OPEN-GO \(a[1])://\(a[2]):\(a[3]) sheet=\(window?.attachedSheet != nil) tabs=\(commands.sessions.tabs.count - before) error=\(model.error ?? "none")")
        case "plugin-entry-trust":
            // `plugin-entry-trust <name>`: reads the server's certificate as Trust Server Certificate…
            // does, and pins it (the test stands in for the user's comparison).
            guard let c = entry(a[0]) else { return write("FAIL plugin-entry-trust: no \(a[0])") }
            let host = c.host, port = c.port ?? PluginEntries.type(of: c)?.defaultPort ?? 443
            let result = await Task.detached { Result { try pluginCertificateProbe(host: host, port: port) } }.value
            guard case .success(let pin) = result else { return write("FAIL plugin-entry-trust: \(c.name) certificate not read") }
            model.mutate { try $0.setPluginEntryTls(id: c.id, mode: "pinned", pinSha256: pin) }
            write("PLUGIN-ENTRY-TRUST \(c.name) pin=\(PluginEntryTlsRow.short(pin))")
        case "plugin-banner":
            // `plugin-banner <name> trust=shown|none`: waits (up to 10 s) for a banner; FAIL unless its
            // Trust Certificate… button is (or is not) shown.
            guard a.count == 2, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)") else { return write("FAIL plugin-banner: args or no tab") }
            func banner() -> String? { (m.nodes.first { $0.kind == "banner" }?.value as? [String: Any])?["text"] as? String }
            var tries = 0
            while tries < 40, banner() == nil, a[1] == "trust=shown" { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            let shown = banner().map(PluginBanner.isCertificateRefusal) ?? false
            let state = "trust=\(shown ? "shown" : "none")"
            write("\(state == a[1] ? "" : "FAIL ")PLUGIN-BANNER \(c.name) \(state) text=\(banner() ?? "none")")
        case "plugin-banner-trust":
            // `plugin-banner-trust <name>`: presses the banner's Trust Certificate… and answers Trust
            // (the test stands in for the user's comparison); waits (up to 25 s) for the view to reopen.
            guard let c = entry(a[0]), let old = PluginViewWindow.model(for: "entry:\(c.id)") else { return write("FAIL plugin-banner-trust: no tab") }
            PluginCertificateTrust.scriptedAnswer = true
            PluginViewWindow.trustCertificate?(old)
            var tries = 0
            func now() -> PluginViewModel? { PluginViewWindow.model(for: "entry:\(c.id)") }
            while tries < 100, now() === old || (now()?.nodes.isEmpty ?? true) { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            let pin = (try? model.library?.pluginEntryTls(id: c.id)).flatMap { $0 }?.pinSha256
            let ok = now() !== old && now() != nil && pin != nil
            write("\(ok ? "" : "FAIL ")PLUGIN-BANNER-TRUST \(c.name) reopened=\(now() !== old) pin=\(pin.map(PluginEntryTlsRow.short) ?? "none")")
        case "plugin-token-login":
            // `plugin-token-login <name> <json file>`: the entry's login from an API-token file
            // (`full-tokenid`, `value`), read at run time. Nothing of it is written to the log.
            guard a.count == 2, let c = entry(a[0]), let vault = UIDriver.services?.credentials.vault else { return write("FAIL plugin-token-login: no entry or vault locked") }
            let file = (a[1] as NSString).expandingTildeInPath
            guard let data = FileManager.default.contents(atPath: file),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let user = json["full-tokenid"] as? String, let secret = json["value"] as? String, !secret.isEmpty else {
                return write("FAIL plugin-token-login: token file not readable")
            }
            do {
                try vault.setInlinePassword(connectionId: c.id, username: user, password: secret)
                model.mutate { try $0.setInlineMarker(connectionId: c.id, kind: "password") }
                write("PLUGIN-TOKEN-LOGIN \(c.name)")
            } catch { write("FAIL plugin-token-login: \(errorText(error))") }
        case "plugin-rows-count":
            // `plugin-rows-count <name> <table node> <n>|>=<n>`: FAIL unless the table has exactly n rows, or at least n
            // (waits up to 15 s). `>=` is for live hosts whose lists change (docker-live volumes: 4, then 12, 2026-11-26).
            let atLeast = a.count == 3 && a[2].hasPrefix(">=")
            guard a.count == 3, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)"), let node = Int(a[1]),
                  let n = Int(atLeast ? String(a[2].dropFirst(2)) : a[2]) else { return write("FAIL plugin-rows-count: args or no tab") }
            func ok(_ count: Int) -> Bool { atLeast ? count >= n : count == n }
            var tries = 0
            while tries < 60, !ok((m.rows[node] ?? []).count) { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            let count = (m.rows[node] ?? []).count
            write("\(ok(count) ? "" : "FAIL ")PLUGIN-ROWS-COUNT \(c.name) count=\(count) expected=\(a[2])")
        case "plugin-select-match":
            // `plugin-select-match <name> <table node> <text>[|<text>…]`: selects the first row with a cell equal to one
            // of the texts (a status cell also matches `tone:<tone>`, for example `tone:good` for a running guest).
            // Alternatives let one script cover packs that show a running guest differently: a Status column
            // ("running", Proxmox 0.3) or a state dot on the name (`tone:good`, 0.5) (pve-live, 2026-11-26).
            guard a.count == 3, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)"), let node = Int(a[1]) else { return write("FAIL plugin-select-match: args or no tab") }
            let wanted = Set(a[2].split(separator: "|").map(String.init))
            guard let i = (m.rows[node] ?? []).firstIndex(where: { $0.contains { c in wanted.contains(PluginCellView.text(c)) || ((c as? [String: Any])?["tone"] as? String).map { wanted.contains("tone:\($0)") } == true } }) else { return write("FAIL plugin-select-match: no row with \(a[2])") }
            m.selectRows(node: node, [i])
            await settle()
            write("PLUGIN-SELECT-MATCH \(c.name) row=\(i)")
        case "plugin-rows":
            // `plugin-rows <name> <table node>`: the table's rows as the app drew them.
            guard a.count == 2, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)"), let node = Int(a[1]) else { return write("FAIL plugin-rows: args or no tab") }
            var tries = 0
            while tries < 40, (m.rows[node] ?? []).isEmpty { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            let rows = (m.rows[node] ?? []).map { r in r.map(PluginCellView.driverText).joined(separator: "|") }
            write("PLUGIN-ROWS \(c.name) count=\(rows.count) keys=\((m.rowKeys[node] ?? []).joined(separator: ",")) first=\(rows.first ?? "none")")
        case "plugin-key-login":
            // `plugin-key-login <name> <user> <key file>`: the entry's own SSH key login, read from a lab-only key file at run
            // time (never printed), as Properties > Login > SSH key saves it (PLUG-DOCKER-01).
            guard a.count == 3, let c = entry(a[0]), let vault = UIDriver.services?.credentials.vault,
                  let key = try? String(contentsOfFile: (a[2] as NSString).expandingTildeInPath, encoding: .utf8) else { return write("FAIL plugin-key-login: entry, vault or key file") }
            do {
                try vault.setInlineKey(connectionId: c.id, username: a[1], privateKey: key, passphrase: nil)
                model.mutate { try $0.setInlineMarker(connectionId: c.id, kind: "ssh-key") }
                write("PLUGIN-KEY-LOGIN \(a[0])")
            } catch { write("FAIL plugin-key-login: \(errorText(error))") }
        case "plugin-known-host":
            // `plugin-known-host <host> <type> <base64>`: a public host key line in this run's known_hosts (port 22).
            guard a.count == 3 else { return write("FAIL plugin-known-host: args") }
            let url = LibraryModel.dataDir.appendingPathComponent("known_hosts")
            let old = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            do {
                try (old + "\(a[0]) \(a[1]) \(a[2])\n").write(to: url, atomically: true, encoding: .utf8)
                write("PLUGIN-KNOWN-HOST \(a[0])")
            } catch { write("FAIL plugin-known-host: \(errorText(error))") }
        case "plugin-tree-shown":
            // `plugin-tree-shown <name> <tree node> <key,key…> [seconds]`: waits for the tree's root items as the view holds
            // them, WITHOUT asking (plugin-tree asks, which hides a tree the app never reloads; docker02).
            guard a.count >= 3, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)"), let node = Int(a[1]) else { return write("FAIL plugin-tree-shown: args or no tab") }
            let key = PluginViewModel.childKey(node, nil)
            let want = a[2].split(separator: ",").map(String.init)
            let limit = (a.count > 3 ? Int(a[3]) : nil) ?? 45
            var keys: [String] = []
            for _ in 0..<(limit * 4) {
                keys = (m.children[key] ?? []).map { ($0["label"] as? String) ?? "" } + (m.children[key] ?? []).map { ($0["key"] as? String) ?? "" }
                if want.allSatisfy({ keys.contains($0) }) { break }
                try? await Task.sleep(nanoseconds: 250_000_000)
            }
            let missing = want.filter { !keys.contains($0) }
            write("\(missing.isEmpty ? "" : "FAIL ")PLUGIN-TREE-SHOWN \(c.name) count=\((m.children[key] ?? []).count) missing=\(missing.joined(separator: ","))")
        case "plugin-tree":
            // `plugin-tree <name> <tree node> <parent key|-> [key,key…]`: asks the plugin for children as an expand
            // does; FAIL unless each key is there. Prints the keys and each item's menu ids.
            guard a.count >= 3, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)"), let node = Int(a[1]) else { return write("FAIL plugin-tree: args or no tab") }
            let parent = a[2] == "-" ? nil : a[2]
            let key = PluginViewModel.childKey(node, parent)
            m.askChildren(node: node, parent: parent)
            let want = a.count > 3 ? a[3].split(separator: ",").map(String.init) : []
            func missingKeys() -> [String] {
                let keys = (m.children[key] ?? []).map { $0["key"] as? String ?? "" }
                return want.filter { !keys.contains($0) }
            }
            // A re-list is first answered from the cached children, before the plugin's refreshed answer (pve-snap-live
            // missed gantry-1 right after Take, PVE-SNAP). With keys to find, wait for them too, up to 20 s.
            var tries = 0
            while tries < 80, m.childRefusals[key] == nil, m.children[key] == nil || !missingKeys().isEmpty {
                try? await Task.sleep(nanoseconds: 250_000_000); tries += 1
            }
            let items = m.children[key] ?? []
            let missing = missingKeys()
            let menus = items.prefix(8).map { i in "\(i["key"] as? String ?? ""):" + ((i["menu"] as? [[String: Any]]) ?? []).map { $0["id"] as? String ?? "" }.joined(separator: "+") }
            write("\(m.children[key] == nil || !missing.isEmpty ? "FAIL " : "")PLUGIN-TREE \(c.name) parent=\(a[2]) count=\(items.count) missing=\(missing.joined(separator: ",")) menus=\(menus.joined(separator: " ")) refusal=\(m.childRefusals[key] ?? "none")")
        case "plugin-tree-menu":
            // `plugin-tree-menu <name> <tree node> <key> <item>`: a tree item's context-menu entry, as a click
            // does; waits (up to 10 s) for the plugin's confirmation and prints its text, or the status.
            guard a.count == 4, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)"), let node = Int(a[1]) else { return write("FAIL plugin-tree-menu: args or no tab") }
            m.input(node: node, ["kind": "menu", "key": a[2], "item": a[3]])
            var tries = 0
            while tries < 40, m.confirm == nil, !m.nodes.contains(where: { $0.kind == "banner" }) { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            await settle()
            let banner = m.nodes.first { $0.kind == "banner" }.map { (($0.value as? [String: Any])?["text"] as? String) ?? "" } ?? "none"
            write("PLUGIN-TREE-MENU \(c.name) item=\(a[3]) confirm=\(m.confirm?.text ?? "none") alert=\(window?.attachedSheet != nil || NSApp.modalWindow != nil) banner=\(banner)")
        case "plugin-confirm-answer":
            // `plugin-confirm-answer <name> yes|no`: answers the plugin's pending confirmation.
            guard a.count == 2, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)"), let pending = m.confirm else { return write("FAIL plugin-confirm-answer: args, no tab or no confirmation") }
            m.answer(pending, confirmed: a[1] == "yes")
            await settle(1)
            write("PLUGIN-CONFIRM-ANSWER \(c.name) \(a[1])")
        case "plugin-select":
            // `plugin-select <name> <table node> <row index>`: selects a row as a click would.
            guard a.count == 3, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)"), let node = Int(a[1]), let i = Int(a[2]) else { return write("FAIL plugin-select: args or no tab") }
            m.selectRows(node: node, [i])
            await settle()
            write("PLUGIN-SELECT \(c.name) key=\(i < (m.rowKeys[node] ?? []).count ? m.rowKeys[node]![i] : "none")")
        case "plugin-press":
            // `plugin-press <name> <button node>`: presses a plugin button and waits (up to 10 s) for an
            // open sheet or a changed status.
            guard a.count == 2, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)"), let node = Int(a[1]) else { return write("FAIL plugin-press: args or no tab") }
            // A banner (a refusal) first, else the first label (the dashboard's summary).
            func status() -> String { (m.nodes.first { $0.kind == "banner" } ?? m.nodes.first { $0.kind == "label" }).map { "\($0.kind):\(($0.value as? String) ?? (($0.value as? [String: Any])?["text"] as? String) ?? "")" } ?? "none" }
            let before = status()
            m.input(node: node, ["kind": "pressed"])
            var tries = 0
            while tries < 40, m.openRequest == nil, m.libraryRequest == nil, status() == before || status().hasPrefix("progress") { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            await settle()
            if let r = m.openRequest {
                write("PLUGIN-PRESS \(c.name) open=\(r.proto)://\(r.host):\(r.port) reported=\(r.reported) label=\(r.label) sheet=\(window?.attachedSheet != nil)")
            } else {
                write("PLUGIN-PRESS \(c.name) open=none status=\(status())")
            }
        case "plugin-connect-paths":
            // `plugin-connect-paths <name>` (select the row first): presses the toolbar Connect icon,
            // then runs the Connect and Connect in New Tab actions (menus, context menu). Each must
            // open or select the plugin tab, never a protocol session or its error.
            guard let c = entry(a[0]) else { return write("FAIL plugin-connect-paths: no \(a[0])") }
            var results: [String] = []
            for path in ["toolbar", "connect", "connect-new-tab"] {
                if let t = PluginViewWindow.tab(for: "entry:\(c.id)") { commands.sessions.close(t) }
                var tries = 0
                while tries < 40, Self.helperCount() > 0 { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
                let before = commands.sessions.tabs.count
                if path == "toolbar" {
                    // A real click on the Connect icon segment, through the window's event path.
                    guard let window, let (control, rect) = toolbarControl("Connect") else { results.append("toolbar=no-control"); continue }
                    click(at: NSPoint(x: control is NSSegmentedControl ? rect.minX + 14 : rect.midX, y: rect.midY), in: window)
                } else {
                    commands.run(path, on: c.id)
                }
                tries = 0
                while tries < 20, PluginViewWindow.tab(for: "entry:\(c.id)") == nil { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
                let plugin = PluginViewWindow.tab(for: "entry:\(c.id)") != nil
                let other = commands.sessions.tabs.count - before - (plugin ? 1 : 0)
                results.append("\(path)=\(plugin && other == 0 ? "plugin-tab" : "wrong(plugin=\(plugin),other=\(other))")")
            }
            let ok = results.allSatisfy { $0.hasSuffix("=plugin-tab") } && model.error == nil
            write("\(ok ? "" : "FAIL ")PLUGIN-CONNECT-PATHS \(c.name) \(results.joined(separator: " ")) error=\(model.error ?? "none")")
        case "plugin-open-answer":
            // `plugin-open-answer <name> <0|1>`: answers the open sheet (1 opens through the normal connect path).
            guard a.count == 2, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)"), let r = m.openRequest else { return write("FAIL plugin-open-answer: no sheet") }
            m.answerOpen(r, accept: a[1] == "1", route: r.route, saveAsEntry: false)
            await settle()
            write("PLUGIN-OPEN-ANSWER \(c.name) accept=\(a[1]) sheet=\(m.openRequest != nil)")
        case "plugin-select-many":
            // `plugin-select-many <name> <table node> <i,j,…>`: selects several rows (Shift/Cmd-click).
            guard a.count == 3, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)"), let node = Int(a[1]) else { return write("FAIL plugin-select-many: args or no tab") }
            m.selectRows(node: node, Set(a[2].split(separator: ",").compactMap { Int($0) }))
            await settle()
            write("PLUGIN-SELECT-MANY \(c.name) rows=\(a[2])")
        case "plugin-menu":
            // `plugin-menu <name> <tree node> <key> <item>`: a tree item's menu choice in the plugin tab.
            guard a.count == 4, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)"), let node = Int(a[1]) else { return write("FAIL plugin-menu: args or no tab") }
            m.input(node: node, ["kind": "menu", "key": a[2], "item": a[3]])
            await settle()
            write("PLUGIN-MENU \(c.name) \(a[2]) \(a[3])")
        case "plugin-save-sheet":
            // `plugin-save-sheet <name> [count]`: the Save as Connection sheet is up (within 15 s); lists its rows.
            guard let c = entry(a.first ?? ""), let m = PluginViewWindow.model(for: "entry:\(c.id)") else { return write("FAIL plugin-save-sheet: no tab") }
            var tries = 0
            while tries < 60, m.libraryRequest == nil { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            guard let r = m.libraryRequest else { return write("FAIL PLUGIN-SAVE-SHEET \(c.name) none") }
            await settle()
            let rows = r.items.map { "\($0.label)|\($0.proto)|\($0.host ?? "-")|\($0.osHint ?? "-")" }.joined(separator: " ")
            let ok = a.count < 2 || Int(a[1]) == r.items.count
            write("\(ok ? "" : "FAIL ")PLUGIN-SAVE-SHEET \(c.name) count=\(r.items.count) sheet=\(window?.attachedSheet != nil) rows=\(rows)")
        case "plugin-save-answer":
            // `plugin-save-answer <name> <folder|-|new name> [credential name]`: answers the sheet as the user would.
            guard a.count >= 2, let c = entry(a[0]), let m = PluginViewWindow.model(for: "entry:\(c.id)"), m.libraryRequest != nil,
                  let answer = PluginSaveConnectionsSheet.current else { return write("FAIL plugin-save-answer: no sheet") }
            answer(a[1], a.count > 2 ? a[2] : nil)
            var tries = 0
            while tries < 40, m.libraryRequest != nil { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            await settle()
            func find(_ f: FolderView) -> FolderView? { f.name == a[1] ? f : f.folders.lazy.compactMap(find).first }
            let folder = a[1] == "-" ? model.tree : model.tree.flatMap { $0.folders.lazy.compactMap(find).first }
            let saved = folder?.connections.map { "\($0.name)|\($0.protocol)|\($0.host)" }.joined(separator: " ") ?? "none"
            write("\(m.libraryRequest == nil ? "" : "FAIL ")PLUGIN-SAVE-ANSWER \(c.name) folder=\(a[1]) saved=\(saved)")
        case "plugin-sidebar-menu":
            // `plugin-sidebar-menu <label> <item id>`: a plugin tree row's menu choice in the library sidebar.
            func walk(_ list: [PluginSidebarRow]) -> PluginSidebarRow? { list.lazy.compactMap { $0.label == a.first ? $0 : walk($0.children) }.first }
            guard a.count == 2, let r = commands.pluginSidebar.rows.byEntry.values.lazy.compactMap(walk).first,
                  let item = r.menu.first(where: { $0.id == a[1] }) else { return write("FAIL plugin-sidebar-menu: no row or item") }
            commands.pluginSidebar.choose(item, on: r)
            var tries = 0
            while tries < 60, commands.pluginSidebar.libraryRequestOwner == nil, commands.pluginSidebar.openRequestOwner == nil { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            await settle()
            let lr = commands.pluginSidebar.libraryRequestOwner?.libraryRequest
            write("PLUGIN-SIDEBAR-MENU \(a[0]) \(a[1]) save-sheet=\(lr.map { $0.items.map { "\($0.label)|\($0.proto)|\($0.host ?? "-")|\($0.osHint ?? "-")" }.joined(separator: " ") } ?? "none")")
        case "plugin-sidebar-save-answer":
            // `plugin-sidebar-save-answer <folder|-|new name>`: answers the sidebar's Save as Connection sheet.
            guard commands.pluginSidebar.libraryRequestOwner != nil, let answer = PluginSaveConnectionsSheet.current else { return write("FAIL plugin-sidebar-save-answer: no sheet") }
            answer(arg, nil)
            var tries = 0
            while tries < 40, commands.pluginSidebar.libraryRequestOwner != nil { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            await settle()
            func find(_ f: FolderView) -> FolderView? { f.name == arg ? f : f.folders.lazy.compactMap(find).first }
            let folder = arg == "-" ? model.tree : model.tree.flatMap { $0.folders.lazy.compactMap(find).first }
            write("\(commands.pluginSidebar.libraryRequestOwner == nil ? "" : "FAIL ")PLUGIN-SIDEBAR-SAVE-ANSWER \(arg) saved=\(folder?.connections.map { "\($0.name)|\($0.protocol)|\($0.host)" }.joined(separator: " ") ?? "none")")
        case "plugin-sidebar-wait":
            // `plugin-sidebar-wait <label>`: a plugin tree row (`◆label`) shows in the library within 30 s.
            var tries = 0
            while tries < 120, row(named: "◆" + arg) == nil { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            write("\(row(named: "◆" + arg) == nil ? "FAIL " : "")PLUGIN-SIDEBAR-WAIT \(arg)")
        case "plugin-sidebar-activate":
            // `sidebar-activate <row>`: Return / double-click on a library row (the plugin's `open` item).
            guard let outline, let r = row(named: arg), let node = outline.item(atRow: r) as? OutlineNode,
                  let c = outline.delegate as? LibraryOutline.Coordinator else { return write("FAIL SIDEBAR-ACTIVATE \(arg)") }
            c.activate(node)
            await settle(0.5)
            write("SIDEBAR-ACTIVATE \(arg)")
        case "plugin-sidebar-sheet":
            // `plugin-sidebar-sheet <proto://host:port>`: the open sheet a sidebar tree asked for shows that destination.
            var tries = 0
            while tries < 60, commands.pluginSidebar.openRequestOwner?.openRequest == nil { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            guard let r = commands.pluginSidebar.openRequestOwner?.openRequest else { return write("FAIL PLUGIN-SIDEBAR-SHEET none") }
            let dest = "\(r.proto)://\(r.host):\(r.port)"
            write("\(dest == arg ? "" : "FAIL ")PLUGIN-SIDEBAR-SHEET \(dest) label=\(r.label) reported=\(r.reported)")
        case "plugin-sidebar-open-answer":
            commands.pluginSidebar.answerOpen(accept: arg == "1", route: commands.pluginSidebar.openRequestOwner?.openRequest?.route ?? "entry", saveAsEntry: false)
            await settle()
            write("PLUGIN-SIDEBAR-OPEN-ANSWER accept=\(arg) sheet=\(commands.pluginSidebar.openRequestOwner != nil)")
        case "plugin-helpers":
            // `plugin-helpers mark`: remember how many helpers run now (other processes on the machine may run
            // some); `plugin-helpers +n`: exactly mark + n run (waits up to 10 s for it).
            if arg == "mark" { Self.helperMark = Self.helperCount(); return write("PLUGIN-HELPERS mark=\(Self.helperMark)") }
            let want = Self.helperMark + (Int(arg.replacingOccurrences(of: "+", with: "")) ?? 0)
            var tries = 0
            while tries < 40, Self.helperCount() != want { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            write("\(Self.helperCount() == want ? "" : "FAIL ")PLUGIN-HELPERS \(Self.helperCount())")
        case "plugin-confirm-wording":
            // A mock `confirm` update (as the core sends one) through the view model: the alert's title and its text.
            // `plugin-confirm-wording <kind>|<environment>|<title>|<entry line>`.
            let p = arg.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard p.count == 4 else { return write("FAIL plugin-confirm-wording: kind|environment|title|entry") }
            let m = PluginViewModel(pluginId: "com.example.mock")
            m.apply(["type": "confirm", "request": 1, "kind": p[0], "text": "Suspend web?", "entry": ["name": "vc-mock", "environment": p[1]]])
            let title = m.confirm?.title ?? "", entry = m.confirm?.entry ?? ""
            write("\(title == p[2] && entry == p[3] ? "" : "FAIL ")PLUGIN-CONFIRM-WORDING title='\(title)' entry='\(entry)'")
        case "plugin-entry-close":
            guard let c = entry(a[0]) else { return write("FAIL plugin-entry-close: no \(a[0])") }
            if let t = PluginViewWindow.tab(for: "entry:\(c.id)") { commands.sessions.close(t) }
            var tries = 0
            while tries < 40, Self.helperCount() > 0 { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            write("PLUGIN-ENTRY-CLOSE \(c.name) helpers=\(Self.helperCount())")
        default: break
        }
    }

    /// PLUG-06c: drives the plugin code editor (`SqlEditorController.current`).
    private func sqlStep(_ cmd: String, _ arg: String) async {
        var tries = 0
        while tries < 60, SqlEditorController.current == nil { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
        guard let e = SqlEditorController.current else { return write("FAIL \(cmd): no code editor") }
        let tv = e.textView
        switch cmd {
        case "sql-editor":
            tv.window?.makeFirstResponder(tv)
            write("SQL-EDITOR chars=\((tv.string as NSString).length) editable=\(tv.isEditable) focused=\(tv.window?.firstResponder === tv)")
        case "sql-type":
            // Typed one character at a time, as keys would arrive. `\n` in the argument is a return.
            tv.window?.makeFirstResponder(tv)
            for ch in arg.replacingOccurrences(of: "\\n", with: "\n") {
                if ch == "\n" { tv.insertNewline(nil) } else { tv.insertText(String(ch), replacementRange: tv.selectedRange()) }
            }
            await settle()
            write("SQL-TYPE chars=\((tv.string as NSString).length) popup=\(e.popupVisible)")
        case "sql-complete":
            if arg != "wait" { e.requestCompletions(explicit: true) }
            var n = 0
            while n < 40, !e.popupVisible { try? await Task.sleep(nanoseconds: 125_000_000); n += 1 }
            let labels = e.shown.map(\.label).joined(separator: ",")
            write(e.popupVisible ? "SQL-COMPLETE shown=\(labels) selected=\(e.selected)" : "FAIL sql-complete: no popup")
        case "sql-key":
            let sel: Selector = switch arg {
            case "down": #selector(NSResponder.moveDown(_:))
            case "up": #selector(NSResponder.moveUp(_:))
            case "escape": #selector(NSResponder.cancelOperation(_:))
            default: #selector(NSResponder.insertNewline(_:))
            }
            let handled = e.handle(sel)
            await settle()
            write("SQL-KEY \(arg) handled=\(handled) popup=\(e.popupVisible) selected=\(e.selected)")
        case "sql-run":
            e.run()
            var n = 0
            func label() -> String? { PluginViewWindow.model(for: arg)?.nodes.first { $0.id == 2 }?.value as? String }
            while n < 40, label()?.hasPrefix("Ran") != true { try? await Task.sleep(nanoseconds: 125_000_000); n += 1 }
            write(label()?.hasPrefix("Ran") == true ? "SQL-RUN \(label() ?? "")" : "FAIL sql-run: \(label() ?? "no label") message=\(PluginViewWindow.model(for: arg)?.message ?? "none") ended=\(PluginViewWindow.model(for: arg)?.ended ?? "none")")
        case "sql-comment":
            tv.setSelectedRange(NSRange(location: 0, length: 0))
            e.toggleComment()
            write("SQL-COMMENT first-line=\((tv.string as NSString).substring(to: min(20, (tv.string as NSString).length)).components(separatedBy: "\n")[0])")
        case "sql-role":
            // `sql-role <word>`: the role drawn at the first occurrence of <word>.
            let r = (tv.string as NSString).range(of: arg)
            write(r.location == NSNotFound ? "FAIL sql-role: \(arg) not found" : "SQL-ROLE \(arg)=\(e.role(at: r.location))")
        default: break
        }
    }
}
#endif
