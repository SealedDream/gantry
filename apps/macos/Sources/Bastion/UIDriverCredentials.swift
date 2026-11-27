#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for the Credentials section. Each acts through `CredentialTreeActions`, the
/// same calls the section's menus make, then logs the tree so scripts can check ids and placement:
/// `cred-add <name>` (test password, never a real one) `cred-folder <name> [in <folder>]`
/// `cred-rename <old> -> <new>` `cred-move <name> -> <folder|top>` `cred-assign <name> -> <connection>`
/// `cred-effective <connection> [= <expected>]` `cred-picker <connection> [= <rows>]` `cred-unassign <node>` `cred-expect <tree>` `cred-delete <name>` (shows the in-use sheet when used) `cred-tree`.
/// The tree view itself: `cred-ui-select <name|none>` `cred-ui-expanded <folder> = yes|no`
/// `cred-ui-new-folder` `cred-ui-type <text>` `cred-ui-drop <name> -> <folder|top>`.
extension Driver {
    func credentialStep(_ cmd: String, _ arg: String) async {
        guard let c = UIDriver.services?.credentials, c.vault != nil else { return write("FAIL \(cmd): vault locked") }
        typealias Act = CredentialTreeActions
        let pair = arg.components(separatedBy: " -> ")
        if cmd.hasPrefix("cred-ui-") { await showCredentialTree() }
        switch cmd {
        case "cred-add":
            c.mutate { _ = try $0.savePassword(id: nil, name: arg, folder: nil, username: "tester", password: "ui-driver-test") }
        case "cred-folder":
            let p = arg.components(separatedBy: " in ")
            let parent = p.count > 1 ? Act.named(c, p[1])?.id : nil
            if Act.newFolder(c, name: p[0], parent: parent) == nil { return write("FAIL cred-folder \(arg): \(c.error ?? "")") }
        case "cred-rename":
            guard pair.count == 2, let it = Act.named(c, pair[0]) else { return write("FAIL cred-rename \(arg)") }
            Act.rename(c, it.id, to: pair[1])
        case "cred-move":
            guard pair.count == 2, let it = Act.named(c, pair[0]) else { return write("FAIL cred-move \(arg)") }
            let target = pair[1] == "top" ? nil : Act.named(c, pair[1])?.id
            if pair[1] != "top" && target == nil { return write("FAIL cred-move \(arg): no folder") }
            Act.move(c, it.id, to: target)
        case "cred-assign":
            guard pair.count == 2, let it = Act.named(c, pair[0]), let lib = commands.model.library,
                  let node = nodeId(named: pair[1]) else { return write("FAIL cred-assign \(arg)") }
            c.mutate { try $0.assignCredential(library: lib, nodeId: node, credentialId: it.id) }
            commands.model.reload()
        case "cred-effective":
            // `cred-effective <connection> = <expected>`: FAIL unless it resolves to that text.
            let want = arg.components(separatedBy: " = ")
            guard let lib = commands.model.library, let node = nodeId(named: want[0]), let v = c.vault else { return write("FAIL cred-effective \(arg)") }
            let e = try? v.effectiveCredential(library: lib, connectionId: node)
            let name = e.flatMap { eff in Act.item(c, eff.credentialId)?.name } ?? "none"
            let got = "\(name)\(e?.inherited == true ? " (inherited)" : "")"
            let ok = want.count < 2 || want[1] == got
            return write("\(ok ? "" : "FAIL ")CRED-EFFECTIVE \(want[0]) = \(got)")
        case "cred-picker":
            // `cred-picker <connection> = <rows>`: the inspector picker's rows, Inherit first.
            let want = arg.components(separatedBy: " = ")
            guard let lib = commands.model.library, let node = nodeId(named: want[0]), let v = c.vault else { return write("FAIL cred-picker \(arg)") }
            let own = connectionCredential(node)
            let eff = own == nil ? (try? v.effectiveCredential(library: lib, connectionId: node)) ?? nil : nil
            let inherit = CredentialPickerGroup.inheritLabel(eff.flatMap { Act.item(c, $0.credentialId)?.name })
            let got = CredentialPickerGroup.text(CredentialPickerGroup.build(c.tree), inherit: inherit)
            let ok = want.count < 2 || want[1] == got
            return write("\(ok ? "" : "FAIL ")CRED-PICKER \(want[0]) = \(got)")
        case "cred-unassign":
            guard let lib = commands.model.library, let node = nodeId(named: arg) else { return write("FAIL cred-unassign \(arg)") }
            c.mutate { try $0.assignCredential(library: lib, nodeId: node, credentialId: nil) }
            commands.model.reload()
        case "cred-expect":
            // `cred-expect <tree text>`: FAIL unless the logged tree equals it.
            let got = credentialTreeText(c)
            return write(got == arg ? "CRED-EXPECT ok" : "FAIL cred-expect: \(got)")
        case "cred-delete":
            guard let it = Act.named(c, arg) else { return write("FAIL cred-delete \(arg)") }
            if let inUse = Act.delete(c, library: commands.model.library, it.id) {
                c.pendingInUse = inUse
                await settle(0.6)
                return write("CRED-IN-USE \(inUse.name): " + inUse.users.map { ($0.path + [$0.name]).joined(separator: "/") }.joined(separator: ", "))
            }
        case "cred-ui-select":
            // `cred-ui-select <name>|none`: a click on that row (a folder also opens or closes), or on empty space.
            guard let tree = CredentialOutline.Coordinator.current else { return write("FAIL cred-ui-select: no tree") }
            if arg == "none" { tree.handleClick(nil) } else {
                guard let it = Act.named(c, arg), let n = tree.node(it.id) else { return write("FAIL cred-ui-select \(arg)") }
                tree.handleClick(n)
            }
            await settle(0.4)
            return write("CRED-UI-SELECTED \(tree.parent?.selection.flatMap { Act.item(c, $0)?.name } ?? "none")")
        case "cred-ui-expanded":
            // `cred-ui-expanded <folder> = yes|no`
            let want = arg.components(separatedBy: " = ")
            guard let tree = CredentialOutline.Coordinator.current, let it = Act.named(c, want[0]) else { return write("FAIL cred-ui-expanded \(arg)") }
            let got = tree.isExpanded(it.id) ? "yes" : "no"
            return write("\(want.count < 2 || want[1] == got ? "" : "FAIL ")CRED-UI-EXPANDED \(want[0]) = \(got)")
        case "cred-ui-new-folder":
            // The + menu's New Folder: into the selected folder, then the name is edited in place.
            guard let tree = CredentialOutline.Coordinator.current else { return write("FAIL cred-ui-new-folder: no tree") }
            guard let id = Act.newFolder(c, parent: Act.targetFolder(c, selection: tree.parent?.selection)) else {
                return write("FAIL cred-ui-new-folder: \(c.error ?? "")")
            }
            await settle(0.4)
            tree.beginRename(id)
            await settle(0.3)
            if tree.renameField?.currentEditor() == nil { return write("FAIL cred-ui-new-folder: name not editable") }
        case "cred-ui-type":
            // `cred-ui-type <text>`: types into the row being renamed and presses Return.
            guard let tree = CredentialOutline.Coordinator.current, let field = tree.renameField,
                  let editor = field.currentEditor() as? NSTextView else { return write("FAIL cred-ui-type: no field in edit") }
            editor.insertText(arg, replacementRange: editor.selectedRange())
            editor.doCommand(by: #selector(NSResponder.insertNewline(_:)))
        case "cred-ui-drop":
            // `cred-ui-drop <name> -> <folder|top>`: the drop the outline accepts at that target.
            guard pair.count == 2, let tree = CredentialOutline.Coordinator.current, let it = Act.named(c, pair[0]) else { return write("FAIL cred-ui-drop \(arg)") }
            let target = pair[1] == "top" ? nil : Act.named(c, pair[1])
            if pair[1] != "top" && target == nil { return write("FAIL cred-ui-drop \(arg): no target") }
            let folder = CredentialOutline.Coordinator.dropFolder(target.flatMap { tree.node($0.id) })
            if !tree.move([it.id], to: folder) { return write("CRED-UI-DROP refused") }
        case "cred-tree":
            break
        default:
            return write("FAIL \(cmd): unknown")
        }
        if let e = c.error { c.error = nil; return write("CRED-ERROR \(e)") }
        await settle(0.3)
        write("CRED-TREE " + credentialTreeText(c))
    }

    /// Opens the Credentials section (the tree exists only while it is open) and waits up to 3 s for the tree.
    private func showCredentialTree() async {
        UserDefaults.standard.set(true, forKey: "sidebar.credentials.expanded")
        for _ in 0..<30 where CredentialOutline.Coordinator.current?.outline == nil { await settle(0.1) }
    }

    /// `Folder/{child,…}` with credentials as `name(kind)`, folders first; no secrets, no ids.
    private func credentialTreeText(_ c: CredentialsModel) -> String {
        func text(_ nodes: [CredentialNode]) -> String {
            nodes.map { n in
                n.item.isFolder ? "\(n.item.name)/{\(text(n.children ?? []))}" : "\(n.item.name)(\(n.item.kind))"
            }.joined(separator: ",")
        }
        return text(CredentialNode.build(c.tree))
    }

    private func connectionCredential(_ id: String) -> String? {
        func find(_ f: FolderView) -> ConnectionView? {
            f.connections.first { $0.id == id } ?? f.folders.lazy.compactMap(find).first
        }
        return commands.model.tree.flatMap(find)?.credentialId
    }

    /// Library node (connection or folder) id by visible name.
    func nodeId(named name: String) -> String? {
        func find(_ f: FolderView) -> String? {
            if f.name == name { return f.id }
            if let c = f.connections.first(where: { $0.name == name }) { return c.id }
            return f.folders.lazy.compactMap(find).first
        }
        return commands.model.tree.flatMap(find)
    }
}

/// External provider steps (1Password, KeePass, Vault) through `ExternalProviders`, the model the
/// Credential Manager panes use: `provider-open <kind> [<op path | kdbx path | vault url>] [secret <test secret>]`
/// `provider-check <kind> <item> = <ok|notFound|authFailed>` `provider-status <kind> = <text>` `provider-lock-all`.
extension Driver {
    func providerStep(_ cmd: String, _ arg: String) async {
        let p = ExternalProviders.shared
        let words = arg.split(separator: " ", maxSplits: 1).map(String.init)
        guard let kind = ExternalProviders.Kind(rawValue: words.first ?? "") ?? (cmd == "provider-lock-all" ? .onepassword : nil) else {
            return write("FAIL \(cmd): unknown provider \(arg)")
        }
        let rest = words.count > 1 ? words[1] : ""
        switch cmd {
        case "provider-open":
            let parts = rest.components(separatedBy: " secret ")
            let location = parts[0].trimmingCharacters(in: .whitespaces)
            switch kind {
            case .onepassword: p.config.opPath = location
            case .keepass: p.config.keepassPath = location
            case .hcvault: p.config.vaultUrl = location
            }
            let ok = await p.open(kind, secret: parts.count > 1 ? parts[1] : nil, keyFile: nil)
            write(ok ? "PROVIDER-OPEN \(kind.rawValue) \(p.status(kind))" : "FAIL provider-open: \(p.error ?? "")")
        case "provider-check":
            let q = rest.components(separatedBy: " = ")
            guard q.count == 2 else { return write("FAIL provider-check: <kind> <item> = <result>") }
            let got = (await p.check(kind, item: q[0])).map { "\($0)" } ?? "error \(p.error ?? "")"
            write(got == q[1] ? "PROVIDER-CHECK ok" : "FAIL provider-check \(q[0]): \(got)")
        case "provider-status":
            let got = p.status(kind)
            write(rest.isEmpty || rest == "= \(got)" ? "PROVIDER-STATUS \(kind.rawValue) \(got)" : "FAIL provider-status: \(got)")
        case "provider-lock-all":
            guard let sv = UIDriver.services else { return write("FAIL provider-lock-all") }
            sv.credentials.lockAll(sessions: sv.sessions, vaultwarden: sv.vaultwarden)
            write("PROVIDER-LOCKED " + ExternalProviders.Kind.allCases.map { "\($0.rawValue)=\(p.status($0))" }.joined(separator: " "))
        default:
            write("FAIL unknown step \(cmd)")
        }
    }
}

/// Codex M03: `vault-open-race lock|nolock` holds a background vault read open, optionally runs
/// Lock Credentials while it waits, then releases it and logs whether the vault ended up open.
/// The read opens an in-memory-key test vault (no Keychain item).
extension Driver {
    func vaultOpenRaceStep(_ arg: String) async {
        guard let sv = UIDriver.services else { return write("FAIL vault-open-race: no services") }
        let c = sv.credentials
        c.lock()
        let (gate, release) = AsyncStream<Void>.makeStream()
        let path = CredentialsModel.vaultPath.appendingPathExtension("race-\(arg)-\(UUID().uuidString)").path
        let original = c.readVault
        c.readVault = { _ in
            for await _ in gate { break }
            return try CredentialVault.openEphemeral(path: path)
        }
        defer { c.readVault = original }
        let open = Task { await c.openInBackground(sessions: sv.sessions) }
        await settle(0.2)
        if arg == "lock" { c.lockAll(sessions: sv.sessions, vaultwarden: sv.vaultwarden) }
        release.yield()
        release.finish()
        await open.value
        write("VAULT-RACE \(arg) vault=\(c.vault == nil ? "locked" : "open")\(c.error.map { " error=\($0)" } ?? "")")
        c.lock()
        try? FileManager.default.removeItem(atPath: path)
    }
}
#endif
