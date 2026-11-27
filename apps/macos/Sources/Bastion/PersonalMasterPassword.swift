import AppKit
import BastionCore

/// The optional master password for the Personal document (OF-F). Without one, the one
/// Keychain device key opens Personal with no prompt; with one, Bastion asks for it at launch.
extension LibraryModel {
    func editMasterPassword() {
        guard let doc = personalDocument else {
            error = "Personal is still in the previous layout; reopen Gantry to move it into its encrypted file first."
            return
        }
        let has = doc.info().hasMasterPassword
        let alert = NSAlert()
        alert.messageText = has ? "Change or remove the Personal master password" : "Set a Personal master password"
        alert.informativeText = "Optional. With a master password Gantry asks for it each time it opens Personal; without one, this Mac's Keychain opens it. A forgotten master password cannot be recovered."
        let first = NSSecureTextField(frame: NSRect(x: 0, y: 30, width: 260, height: 24))
        first.placeholderString = "New password (8+ characters)"
        let second = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        second.placeholderString = "Repeat"
        let box = NSView(frame: NSRect(x: 0, y: 0, width: 260, height: 54))
        box.addSubview(first); box.addSubview(second)
        alert.accessoryView = box
        alert.addButton(withTitle: has ? "Change" : "Set")
        alert.addButton(withTitle: "Cancel")
        if has { alert.addButton(withTitle: "Remove Master Password") }
        switch alert.runModalInFront() {
        case .alertFirstButtonReturn:
            guard first.stringValue == second.stringValue else { error = "The two passwords differ; nothing changed."; return }
            do { try doc.setMasterPassword(password: first.stringValue) } catch { self.error = KeychainQuiet.message(error) }
        case .alertThirdButtonReturn:
            do { try doc.removeMasterPassword() } catch { self.error = KeychainQuiet.message(error) }
        default: break
        }
    }

    /// Launch: ask for the master password until it opens or the user gives up (then Personal
    /// stays locked for this launch; nothing is changed).
    static func unlockWithMasterPassword(_ doc: PersonalLibrary) -> Bool {
        while doc.info().locked {
            let alert = NSAlert()
            alert.messageText = "Unlock Personal"
            alert.informativeText = "Enter the Personal master password."
            let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
            alert.accessoryView = field
            alert.addButton(withTitle: "Unlock")
            alert.addButton(withTitle: "Quit Gantry")
            alert.window.initialFirstResponder = field
            guard alert.runModalInFront() == .alertFirstButtonReturn else { return false }
            try? doc.unlock(password: field.stringValue)
        }
        return true
    }
}
