#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for saved logins (A1-NM-01). Each acts through `LoginResolver`, the calls the
/// connect paths and the Logins list make. No step logs or returns a secret.
/// `login-list <connection> [rdp] [= <rows>]` the core's list, `label` or `label [offered]`, joined by ` | `
/// `login-add|login-default|login-remove <credential> -> <connection>` the Logins list buttons
/// `login-save <name>|<username>|<ENV_VAR>` a password credential whose password is in the file $ENV_VAR
/// `login-sheet [= <state>]` the open connect sheet's login state · `login-pick <label or name|typed>` · `login-keep on|off`
/// `login-connect` the SSH sheet's Connect button
/// `login-forget <connection>` removes the connection's own saved secret (a typed sign-in is kept as one)
/// `login-release <credential> -> <connection> = ok|refused` whether the core hands that password to that connection
/// `login-remembered <connection> = none|typed|vault` the login kept for this run
/// `login-drop <credential> -> <folder or connection>` a credential row dropped on the library tree (a folder asks
///   first: answered yes); `login-drop-cancel` the same with the question answered Cancel
/// `login-tool <services|processes|eventlog> -> <connection>` opens that tool of the connection
/// `login-page <page id>` a page of the open property editor · `login-typed [= plain=<a>,<b> secure=filled|empty]` the top sheet's plain fields and whether each secure field is filled.
extension Driver {
    func loginStep(_ cmd: String, _ arg: String) async {
        guard let sv = UIDriver.services else { return write("FAIL \(cmd): no services") }
        let c = sv.credentials
        let want = arg.components(separatedBy: " = ")
        let pair = want[0].components(separatedBy: " -> ")
        // `login-sheet = <state>` and `login-typed = <state>` have nothing before the `=`. (Until the
        // review of #807 these two compared nothing: the expected text was never read.)
        let expected = arg.hasPrefix("= ") ? String(arg.dropFirst(2)) : nil
        switch cmd {
        case "login-sheet":
            for _ in 0..<40 where window?.attachedSheet == nil { await settle(0.1) }
            guard window?.attachedSheet != nil else { return write("FAIL login-sheet: no sheet") }
            await settle(0.6)
            let got = LoginResolver.sheetState
            return write("\(expected == nil || expected == got ? "" : "FAIL ")LOGIN-SHEET \(got)")
        case "login-typed":
            // Whether each secure field holds something: a typed secret, or its length, is never logged.
            let fields = topSheet?.contentView?.allSubviews(of: NSTextField.self).filter { $0.isEditable } ?? []
            let secure = fields.filter { $0 is NSSecureTextField }.map { $0.stringValue.isEmpty ? "empty" : "filled" }.joined(separator: ",")
            let plain = fields.filter { !($0 is NSSecureTextField) }.map(\.stringValue).joined(separator: ",")
            return write("\(expected == nil || expected == "plain=\(plain) secure=\(secure)" ? "" : "FAIL ")LOGIN-TYPED plain=\(plain) secure=\(secure)")
        case "login-pick", "login-keep", "login-page", "login-connect", "custom-set":
            guard window?.attachedSheet != nil else { return write("FAIL \(cmd): no sheet") }
            NotificationCenter.default.post(name: DriverEvents.pressButton, object: "\(cmd):\(arg)")
            await settle(0.5)
            return write("\(cmd.uppercased()) \(arg)" + (cmd == "login-page" || cmd == "custom-set" ? "" : " -> \(LoginResolver.sheetState)"))
        case "login-tool":
            // `login-tool <services|processes|eventlog> -> <connection>`: as the connection's tool command.
            guard pair.count == 2, let tool = ConnectionTool(rawValue: pair[0]), let node = loginNode(named: pair[1]),
                  let conn = commands.model.connection(id: node), ConnectionTool.applies(to: conn) else { return write("FAIL login-tool \(arg)") }
            commands.openTool(tool, on: conn)
            await settle(0.6)
            return write("LOGIN-TOOL \(arg)")
        case "login-remembered":
            guard let node = loginNode(named: want[0]) else { return write("FAIL login-remembered \(arg)") }
            let got = switch c.lastLogin(for: node)?.login {
            case nil: "none"
            case .vault: "vault"
            default: "typed"
            }
            return write("\(want.count < 2 || want[1] == got ? "" : "FAIL ")LOGIN-REMEMBERED \(want[0]) = \(got)")
        default: break
        }
        guard let vault = c.vault, let library = commands.model.library else { return write("FAIL \(cmd): vault locked") }
        switch cmd {
        case "login-list":
            let rdp = want[0].hasSuffix(" rdp")
            let name = rdp ? String(want[0].dropLast(4)) : want[0]
            guard let node = loginNode(named: name) else { return write("FAIL login-list \(arg): no connection") }
            let got: String
            do {
                got = try LoginResolver.offers(for: node, library: library, vault: vault, passwordsOnly: rdp)
                    .map { "\($0.label)\($0.autoUse ? "" : " [offered]")" }.joined(separator: " | ")
            } catch {
                return write("FAIL login-list \(arg): \(errorText(error))")
            }
            let shown = got.isEmpty ? "none" : got
            write("\(want.count < 2 || want[1] == shown ? "" : "FAIL ")LOGIN-LIST \(want[0]) = \(shown)")
        case "login-add", "login-default", "login-remove":
            guard pair.count == 2, let cred = CredentialTreeActions.named(c, pair[0]), let node = loginNode(named: pair[1]) else {
                return write("FAIL \(cmd) \(arg)")
            }
            LoginResolver.change(node, model: commands.model, credentials: c) { v, lib in
                switch cmd {
                case "login-add": try v.addLogin(library: lib, connectionId: node, credentialId: cred.id)
                case "login-default": try v.setDefaultLogin(library: lib, connectionId: node, credentialId: cred.id)
                default: _ = try v.removeLogin(library: lib, connectionId: node, credentialId: cred.id)
                }
            }
            if let e = commands.model.error { commands.model.error = nil; return write("FAIL \(cmd) \(arg): \(e)") }
            write("\(cmd.uppercased()) \(arg)")
        case "login-save":
            let p = arg.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard p.count == 3, let file = ProcessInfo.processInfo.environment[p[2]],
                  let password = try? String(contentsOfFile: file, encoding: .utf8).trimmingCharacters(in: .newlines) else {
                return write("FAIL login-save: needs <name>|<username>|<ENV_VAR naming a password file>")
            }
            let ok = c.mutate { _ = try $0.savePassword(id: nil, name: p[0], folder: nil, username: p[1], password: password) }
            write(ok ? "LOGIN-SAVE \(p[0])" : "FAIL login-save: \(c.error ?? "")")
        case "login-forget":
            // As Properties › Credentials › "Ask when connecting": the connection's own secret and its
            // marker go, and the login remembered for this run. For suites that run the app several
            // times on one folder: a typed sign-in is otherwise sealed in a test vault the next run cannot open.
            guard let node = loginNode(named: arg) else { return write("FAIL login-forget \(arg): no connection") }
            do {
                _ = try vault.removeInline(connectionId: node)
                try vault.save()
            } catch { return write("FAIL login-forget \(arg): \(errorText(error))") }
            commands.model.mutate { try $0.setInlineMarker(connectionId: node, kind: nil) }
            c.forgetLastLogin(for: node)
            if let e = commands.model.error { commands.model.error = nil; return write("FAIL login-forget \(arg): \(e)") }
            write("LOGIN-FORGET \(arg)")
        case "login-release":
            guard pair.count == 2, let cred = CredentialTreeActions.named(c, pair[0]), let node = loginNode(named: pair[1]) else {
                return write("FAIL login-release \(arg)")
            }
            // Only whether the core released it is logged; the password is dropped here.
            let got = (try? vault.releaseLogin(library: library, connectionId: node, credentialId: cred.id)) != nil ? "ok" : "refused"
            write("\(want.count < 2 || want[1] == got ? "" : "FAIL ")LOGIN-RELEASE \(want[0]) = \(got)")
        case "login-drop", "login-drop-cancel":
            // On a folder the app asks first: `login-drop` answers yes, `login-drop-cancel` answers Cancel.
            LoginResolver.scriptedFolderLogin = cmd == "login-drop"
            await loginDrop(pair, arg, credentials: c)
            LoginResolver.scriptedFolderLogin = nil
        default:
            write("FAIL \(cmd): unknown")
        }
    }

    /// The outline's own drop handlers with a credential id on the pasteboard, as the Credentials
    /// section's rows put it there (`.draggable(node.id)`: plain text).
    private func loginDrop(_ pair: [String], _ arg: String, credentials c: CredentialsModel) async {
        guard pair.count == 2, let cred = CredentialTreeActions.named(c, pair[0]), let outline, let ds = outline.dataSource,
              let r = row(named: pair[1]), let target = outline.item(atRow: r) as? OutlineNode else {
            return write("FAIL login-drop \(arg)")
        }
        let pb = NSPasteboard(name: .init("dev.bastion.uidriver.\(UUID().uuidString)"))
        defer { pb.releaseGlobally() }
        pb.clearContents()
        pb.setString(cred.id, forType: .string)
        let info = CredentialDrag(pasteboard: pb)
        let op = ds.outlineView?(outline, validateDrop: info, proposedItem: target, proposedChildIndex: NSOutlineViewDropOnItemIndex) ?? []
        guard op == .link else { return write("LOGIN-DROP \(arg) -> refused") }
        let ok = ds.outlineView?(outline, acceptDrop: info, item: target, childIndex: NSOutlineViewDropOnItemIndex) ?? false
        await settle(0.3)
        write("LOGIN-DROP \(arg) -> \(ok ? "assigned" : "refused")")
    }

    /// Library node (connection or folder) id by visible name.
    private func loginNode(named name: String) -> String? {
        func find(_ f: FolderView) -> String? {
            if f.name == name { return f.id }
            if let c = f.connections.first(where: { $0.name == name }) { return c.id }
            return f.folders.lazy.compactMap(find).first
        }
        return commands.model.tree.flatMap(find)
    }
}

/// Minimal dragging info: the outline's data source only reads the pasteboard.
@MainActor private final class CredentialDrag: NSObject, @preconcurrency NSDraggingInfo {
    let draggingPasteboard: NSPasteboard
    init(pasteboard: NSPasteboard) { draggingPasteboard = pasteboard }
    var draggingDestinationWindow: NSWindow? { nil }
    var draggingSourceOperationMask: NSDragOperation { .link }
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
#endif
