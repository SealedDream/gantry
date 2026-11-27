#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for PostgreSQL through the plugin (PLUG-08 Mac). `<name>` is an entry's
/// display name (no spaces). Results are printed as text:
/// `pg-field <name> <key> <value>` set a plugin field (Database) as the New Connection form does
/// `pg-login <name> <user>` the entry's own login, password from `BASTION_UI_PASSWORD_FILE` (never logged)
/// `pg-gateway-set <name>` gateway `Jump` (127.0.0.1:2223, user tester) on the entry
/// `pg-open <name>` the default action; prints whether the gateway sign-in sheet is up
/// `pg-gateway-connect <name>` what the sheet's Connect does, password from `BASTION_UI_HOP_PASSWORD_FILE`
/// (the gateway's key is trusted when asked); waits for the entry's tab and prints its route
/// `pg-run <name>` run the SQL editor's text in the entry's tab; prints the status line and result rows
/// `pg-cmd-return <name>` a real ⌘↩ through NSApp.sendEvent (menus included) with the SQL editor focused and the
/// entry selected in the library: the query must run (the status line changes) and the tab stays the entry's
/// `pg-library-cmd-return <name>` ⌘↩ with the library focused on the entry: Connect must open the entry's tab
extension Driver {
    func postgresStep(_ cmd: String, _ arg: String) async -> Bool {
        let a = arg.split(separator: " ").map(String.init)
        let model = commands.model
        switch cmd {
        case "pg-field":
            guard a.count == 3, let c = model.connection(named: a[0]) else { write("FAIL pg-field: args"); return true }
            model.mutate { try $0.setPluginField(dataDir: LibraryModel.dataDir.path, id: c.id, key: a[1], value: a[2]) }
            write(model.error == nil ? "PG-FIELD \(a[0]) \(a[1])" : "FAIL pg-field: \(model.error ?? "")")
        case "pg-login":
            guard a.count == 2, let c = model.connection(named: a[0]), let vault = UIDriver.services?.credentials.vault else { write("FAIL pg-login: no entry or vault locked"); return true }
            guard let file = ProcessInfo.processInfo.environment["BASTION_UI_PASSWORD_FILE"],
                  let password = try? String(contentsOfFile: file, encoding: .utf8).trimmingCharacters(in: .newlines), !password.isEmpty else {
                write("FAIL pg-login: BASTION_UI_PASSWORD_FILE not readable"); return true
            }
            do {
                try vault.setInlinePassword(connectionId: c.id, username: a[1], password: password)
                model.mutate { try $0.setInlineMarker(connectionId: c.id, kind: "password") }
                write("PG-LOGIN \(a[0])")
            } catch { write("FAIL pg-login: \(errorText(error))") }
        case "pg-gateway-set":
            guard let c = model.connection(named: a.first ?? ""), let lib = model.library else { write("FAIL pg-gateway-set: no entry"); return true }
            do {
                let gw = try lib.gateways().first { $0.name == "Jump" }?.id
                    ?? lib.addGateway(gateway: GatewayInputView(name: "Jump", host: "127.0.0.1", port: 2223, username: "tester", notes: ""))
                model.mutate { try $0.setProperty(id: c.id, key: "gateway_id", value: gw) }
                let hop = try lib.gatewayRoute(connectionId: c.id)
                write("PG-GATEWAY-SET \(c.name) hop=\(hop?.key ?? "none")")
            } catch { write("FAIL pg-gateway-set: \(errorText(error))") }
        case "pg-open":
            guard let c = model.connection(named: a.first ?? "") else { write("FAIL pg-open: no entry"); return true }
            commands.performDefault(on: c.id)
            await settle(0.6)
            write("PG-OPEN \(c.name) sheet=\(commands.pluginGateway != nil) tab=\(PluginViewWindow.tab(for: "entry:\(c.id)") != nil)")
        case "pg-gateway-connect":
            guard let c = model.connection(named: a.first ?? ""), let lib = model.library, let type = PluginEntries.type(of: c) else { write("FAIL pg-gateway-connect: no entry"); return true }
            guard let file = ProcessInfo.processInfo.environment["BASTION_UI_HOP_PASSWORD_FILE"],
                  let password = try? String(contentsOfFile: file, encoding: .utf8).trimmingCharacters(in: .newlines) else { write("FAIL pg-gateway-connect: no password file"); return true }
            commands.pluginGateway = nil
            await settle(0.4)
            let login = GatewayLogin(library: lib, connectionId: c.id)
            login.password = password
            var outcome = await login.open(sessions: commands.sessions, library: lib, connectionId: c.id)
            if case .needsTrust = outcome {
                login.trust()
                login.password = password
                outcome = await login.open(sessions: commands.sessions, library: lib, connectionId: c.id)
            }
            guard case .via(let port) = outcome else { write("FAIL pg-gateway-connect: \(outcome)"); return true }
            PluginViewWindow.show(entry: c, type: type, library: lib, credentials: UIDriver.services?.credentials,
                                  via: .forward(port: port, target: c.host), route: login.handOff())
            var tries = 0
            func m() -> PluginViewModel? { PluginViewWindow.model(for: "entry:\(c.id)") }
            while tries < 60, m()?.nodes.isEmpty ?? true, m()?.ended == nil { try? await Task.sleep(nanoseconds: 250_000_000); tries += 1 }
            let running = m()?.gatewayRoute?.isRunning() == true
            write((running && m()?.ended == nil ? "" : "FAIL ") + "PG-GATEWAY-CONNECT \(c.name) forward=\(running) nodes=\(m()?.nodes.count ?? 0) ended=\(m()?.ended ?? "none")")
        case "pg-run":
            guard let c = model.connection(named: a.first ?? ""), let m = PluginViewWindow.model(for: "entry:\(c.id)") else { write("FAIL pg-run: no tab"); return true }
            guard let e = SqlEditorController.current else { write("FAIL pg-run: no code editor"); return true }
            func status() -> String {
                // Node 33 is STATUS in plugins/official/postgres/src/lib.rs.
                guard let node = m.nodes.first(where: { $0.id == 33 }) else { return "" }
                if let text = node.value as? String { return text }
                let dict = node.value as? [String: Any]
                return dict?["text"] as? String ?? ""
            }
            let before = status()
            e.run()
            var n = 0
            while n < 120, status() == before || status().hasPrefix("Running") { try? await Task.sleep(nanoseconds: 250_000_000); n += 1 }
            // The grid's rows (PLUG-08 Mac review): the first result table that has any.
            var drawn = 0
            for _ in 0..<40 {
                drawn = m.nodes.filter { $0.kind == "table" }.compactMap { m.rows[$0.id]?.count }.max() ?? 0
                if drawn > 0 { break }
                try? await Task.sleep(nanoseconds: 125_000_000)
            }
            let first = m.nodes.filter { $0.kind == "table" }.compactMap { m.rows[$0.id]?.first }.first.map { $0.map { $0.map { "\($0)" } ?? "NULL" }.joined(separator: "|") } ?? "none"
            write((drawn > 0 ? "" : "FAIL ") + "PG-ROWS \(c.name) rows=\(drawn) first=\(first) banner=\(m.message ?? "none")")
            write((status().hasPrefix("Ran") || status().contains("row") ? "" : "FAIL ") + "PG-RUN \(c.name) status=\(status()) ended=\(m.ended ?? "none") message=\(m.message ?? "none")")
        case "pg-cmd-return":
            guard let c = model.connection(named: a.first ?? ""), let m = PluginViewWindow.model(for: "entry:\(c.id)") else { write("FAIL pg-cmd-return: no tab"); return true }
            guard let e = SqlEditorController.current, let w = e.textView.window else { write("FAIL pg-cmd-return: no code editor"); return true }
            func status() -> String {
                guard let node = m.nodes.first(where: { $0.id == 33 }) else { return "" } // STATUS in the plugin's lib.rs
                return (node.value as? String) ?? ((node.value as? [String: Any])?["text"] as? String) ?? ""
            }
            // Another query than pg-run's, so a run changes the status line ("1 rows").
            w.makeFirstResponder(e.textView)
            e.textView.selectAll(nil)
            e.textView.insertText("select id from hosts where id = 1", replacementRange: e.textView.selectedRange())
            let before = status()
            let focused = w.firstResponder === e.textView
            cmdReturn(in: w)
            var n = 0
            while n < 120, status() == before || status().hasPrefix("Running") { try? await Task.sleep(nanoseconds: 250_000_000); n += 1 }
            let ran = status() != before
            write((ran ? "" : "FAIL ") + "PG-CMD-RETURN \(c.name) status=\(status()) selected=\(commands.sessions.selectedTab?.name ?? "none") responder=\(w.firstResponder.map { String(describing: type(of: $0)) } ?? "none") responderWasEditor=\(focused) keyWindow=\(w.isKeyWindow)")
        case "pg-library-cmd-return":
            guard let c = model.connection(named: a.first ?? ""), let outline, let w = outline.window else { write("FAIL pg-library-cmd-return: no entry or library"); return true }
            let key = "entry:\(c.id)"
            w.makeFirstResponder(outline)
            cmdReturn(in: w)
            var n = 0
            while n < 100, PluginViewWindow.model(for: key) == nil { try? await Task.sleep(nanoseconds: 250_000_000); n += 1 }
            write((PluginViewWindow.model(for: key) == nil ? "FAIL " : "") + "LIBRARY-CMD-RETURN \(c.name) selected=\(commands.sessions.selectedTab?.name ?? "none")")
        default:
            return await postgresLiveStep(cmd, a)
        }
        return true
    }
}
extension Driver {
    /// ⌘↩ as the keyboard sends it: key equivalents go to the window's views, then the main menu, before keyDown.
    func cmdReturn(in w: NSWindow) {
        guard let e = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: .command, timestamp: ProcessInfo.processInfo.systemUptime,
                                       windowNumber: w.windowNumber, context: nil, characters: "\r", charactersIgnoringModifiers: "\r",
                                       isARepeat: false, keyCode: 36) else { return }
        // Quiet launches leave the window not key, and NSApp only offers key equivalents to the key window's views; so
        // when it is not key, the same order by hand: the window's views first, then the main menu.
        if w.isKeyWindow { NSApp.sendEvent(e); return }
        if !w.performKeyEquivalent(with: e) { _ = NSApp.mainMenu?.performKeyEquivalent(with: e) }
    }
}
#endif
