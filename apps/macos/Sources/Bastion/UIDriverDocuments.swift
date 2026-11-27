#if BASTION_TEST_HOOKS
import AppKit
import Foundation
import BastionCore

/// UI driver steps for spec §5 (document-first launch), run with `BASTION_UI_DOCUMENT_GATE=1`.
/// Test passwords only. `doc-gate` logs the gate; `doc-create <path>|<name>|<password>` creates,
/// protects, saves and opens a document; `doc-password <pw>` types it on the Unlock screen and
/// presses Unlock; `doc-lock` (⌘L) `doc-idle <secs>` `doc-screenlock` `doc-sleep` run the lock
/// paths; `doc-export-key` tries the wrapped-key export (refused under a password-only policy).
extension Driver {
    func documentStep(_ cmd: String, _ arg: String) async {
        let gate = DocumentGate.shared
        guard let model = gate.model else { return write("FAIL \(cmd): gate not ready") }
        switch cmd {
        case "doc-gate":
            break
        case "doc-modal":
            // Any app-modal dialog or extra sheet open now (the Welcome form is neither).
            let modal = NSApp.modalWindow != nil || NSApp.windows.contains { $0.isVisible && $0 is NSPanel && $0.title.isEmpty && $0.level == .modalPanel }
            return write("\(modal ? "FAIL " : "")DOC-MODAL \(modal ? "shown" : "none") sheet=\(window?.attachedSheet != nil ? "shown" : "none")")
        case "doc-create":
            let p = arg.components(separatedBy: "|")
            guard p.count == 3 else { return write("FAIL doc-create: needs <path>|<name>|<password>") }
            do {
                let h = try BastionDocument.create(name: p[1], dataDir: LibraryModel.dataDir.path)
                // An empty password: an unprotected document (LIB-01's restart suite).
                if !p[2].isEmpty { try h.setPassword(password: p[2]) }
                try h.saveAs(path: p[0])
                _ = model.adopt(h)
                gate.showUnlock(path: p[0])
            } catch { return write("FAIL doc-create: \(errorText(error))") }
        case "doc-password":
            gate.password = arg
            gate.unlockWithPassword()
        case "doc-lock":
            model.lockDocument()
        case "doc-tab-gates":
            // Codex M04: each tab's document and whether its cover is up, in whichever window.
            guard let s = UIDriver.services?.sessions else { return write("FAIL doc-tab-gates") }
            await settle(0.5)
            let rows = s.tabs.map { t in "\(s.windowed[t.id] == nil ? "main" : "detached"):\(t.documentId == nil ? "personal" : "doc"):\(s.isDocumentLocked(t) ? "covered" : "live")" }
            write("DOC-TAB-GATES \(rows.joined(separator: ","))")
        case "doc-idle", "doc-screenlock", "doc-sleep":
            let reason = DocumentAutoLock.shared.check(idleSecs: UInt64(arg) ?? 0, screenLocked: cmd == "doc-screenlock", asleep: cmd == "doc-sleep")
            write("DOC-AUTOLOCK \(cmd) \(arg) minutes=\(DocumentAutoLock.shared.minutes) -> \(reason ?? "not locked")")
        case "doc-states":
            // Codex M02: every open document and whether it is locked, active one marked with *.
            write("DOC-STATES " + model.documents.map { "\($0.info.name)\($0.id == model.activeDocument?.id ? "*" : ""):\($0.info.locked ? "locked" : "open")" }.joined(separator: ","))
        case "doc-answer":
            // Queue the next Open/Save panel answer (`-` = Cancel).
            DocumentDialogs.scripted.append(arg == "-" ? "" : arg)
            return write("DOC-ANSWER \(arg)")
        case "doc-form":
            // `doc-form <path>|<name>|<password>|<touchid 0/1>`: fill the Welcome form and press Create….
            let p = arg.components(separatedBy: "|")
            guard p.count == 4 else { return write("FAIL doc-form: needs <path>|<name>|<password>|<touchid>") }
            DocumentDialogs.scripted.append(p[0])
            var form = DocumentGate.NewDocument()
            form.name = p[1]; form.password = p[2]; form.confirm = p[2]; form.touchID = p[3] == "1"
            if let e = gate.create(form) { write("DOC-FORM error=\(e)") }
        case "doc-rename":
            // `doc-rename <personal|active|name of an open document>|<new name>` (owner point 33).
            let p = arg.components(separatedBy: "|")
            guard p.count == 2 else { return write("FAIL doc-rename: needs <which>|<new name>") }
            DocumentDialogs.scripted.append(p[1] == "-" ? "" : p[1])
            switch p[0] {
            case "personal": model.renameDocument(personal: true)
            case "active": model.renameDocument()
            default:
                guard let d = model.documents.first(where: { $0.info.name == p[0] }) else { return write("FAIL doc-rename: no document \(p[0])") }
                model.renameDocument(d.id)
            }
        case "doc-names":
            // `doc-names <personal>,<doc>,…`: the names the sidebar strip shows, in order.
            await settle(0.3)
            let names = ([model.personalName] + model.documents.map(\.info.name)).joined(separator: ",")
            return write("\(arg.isEmpty || arg == names ? "" : "FAIL ")DOC-NAMES \(names)\(arg.isEmpty ? "" : " want=\(arg)")")
        case "doc-rename-fit":
            // Layout fit: the Rename alert with a short, a long and a very long current name keeps
            // the name field, both buttons and the title inside the alert at every size.
            for name in ["P", String(repeating: "Project X ", count: 6), String(repeating: "W", count: 200)] {
                let (a, f) = DocumentDialogs.renameAlert(current: name)
                a.layout()
                let win = a.window.contentView?.bounds ?? .zero
                let field = f.convert(f.bounds, to: a.window.contentView)
                let buttons = a.buttons.map { $0.convert($0.bounds, to: a.window.contentView) }
                let fits = win.contains(field) && buttons.allSatisfy { win.contains($0) } && field.width >= 200
                let overlap = buttons.contains { $0.intersects(field) }
                write("\(fits && !overlap ? "" : "FAIL ")DOC-RENAME-FIT len=\(name.count) window=\(Int(win.width))x\(Int(win.height)) field=\(Int(field.minX)),\(Int(field.minY)) \(Int(field.width))x\(Int(field.height)) buttons=\(buttons.map { "\(Int($0.minX)),\(Int($0.minY))" }.joined(separator: "/")) overlap=\(overlap)")
                a.window.orderOut(nil)
            }
            return
        case "doc-new": model.newDocument()
        case "doc-open": model.openDocument(url: URL(fileURLWithPath: arg))
        case "doc-make-foreign":
            // A1-FU5: `doc-make-foreign <path>|<name>`: an unprotected library made "on another device"
            // (a scratch data folder), so this Mac's record does not know its id. Not opened here.
            let p = arg.components(separatedBy: "|")
            guard p.count == 2 else { return write("FAIL doc-make-foreign: needs <path>|<name>") }
            let other = FileManager.default.temporaryDirectory.appendingPathComponent("bastion-foreign-\(UUID().uuidString)")
            do {
                try FileManager.default.createDirectory(at: other, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: other) }
                let h = try BastionDocument.create(name: p[1], dataDir: other.path)
                try h.saveAs(path: p[0])
                _ = try? h.lock()
            } catch { return write("FAIL doc-make-foreign: \(errorText(error))") }
            return write("DOC-FOREIGN \(p[1])")
        case "doc-origin":
            // A1-FU5: `doc-origin <name>|<known|unknown>`: what the core says about an open document.
            let p = arg.components(separatedBy: "|")
            guard p.count == 2, let d = model.documents.first(where: { $0.info.name == p[0] }) else { return write("FAIL doc-origin: no document \(arg)") }
            let got = d.handle.origin() == .known ? "known" : "unknown"
            return write("\(got == p[1] ? "" : "FAIL ")DOC-ORIGIN \(p[0]) \(got) want=\(p[1])")
        case "doc-open-panel": model.openDocument()
        case "doc-close": model.closeDocument()
        case "doc-save": _ = await model.saveDocument()?.value
        case "doc-personal": gate.openPersonal()
        case "doc-show":
            // LIB-01: `doc-show <personal|name>`: the sidebar switcher, a choice by hand.
            if arg == "personal" { model.select(nil) } else {
                guard let d = model.documents.first(where: { $0.info.name == arg }) else { return write("FAIL doc-show: no document \(arg)") }
                model.select(d.id)
            }
        case "doc-shown":
            // LIB-01: `doc-shown <personal|name>`: the library on screen.
            await settle(0.3)
            let shown = model.activeDocument?.info.name ?? "personal"
            return write("\(shown == arg ? "" : "FAIL ")DOC-SHOWN \(shown) phase=\(gate.phase) want=\(arg)")
        case "doc-cancel-create": gate.cancelCreate()
        case "doc-remove-missing": gate.dismissMissing()
        case "doc-locate": if let m = gate.missing { DocumentDialogs.scripted.append(arg); gate.locate(m) }
        case "doc-add-folder":
            // An edit to the active document (makes it dirty), saved by doc-save.
            model.mutate { _ = try $0.addFolder(parent: nil, name: arg.isEmpty ? "Added" : arg) }
        case "doc-focus":
            // File › New Document…'s focus request: the Name field has focus and all its text selected.
            await settle(0.5)
            let editor = NSApp.windows.lazy.compactMap { $0.firstResponder as? NSTextView }.first
            let field = editor?.delegate as? NSTextField
            let all = editor.map { $0.selectedRange().length == ($0.string as NSString).length && $0.string.count > 0 } ?? false
            let ok = field?.placeholderString == "Name" && all
            return write("\(ok ? "" : "FAIL ")DOC-FOCUS field=\(field?.placeholderString ?? "-") selectedAll=\(all) request=\(gate.createFocusRequest)")
        case "doc-kill-write":
            // `doc-kill-write <file name>`: the next save of that file crashes half-way through the write.
            write("DOC-KILL-WRITE \(arg)")
            flush(wait: true)
            setenv("BASTION_TEST_KILL_DURING_WRITE", arg, 1)
            _ = await model.saveDocument()?.value
            return write("FAIL doc-kill-write: the save finished")
        case "doc-tmp":
            // Temp files a crashed write left next to the documents in <dir>.
            let left = (try? FileManager.default.contentsOfDirectory(atPath: arg))?.filter { $0.hasSuffix(".tmp") } ?? []
            return write("DOC-TMP \(left.count)")
        case "doc-file":
            // `doc-file <delete|readonly|writable|corrupt|move:<dest>> <path>`: change the file under the app.
            let p = arg.split(separator: " ", maxSplits: 1).map(String.init)
            guard p.count == 2 else { return write("FAIL doc-file") }
            let fm = FileManager.default
            do {
                switch p[0] {
                case "delete": try fm.removeItem(atPath: p[1])
                case "readonly": try fm.setAttributes([.posixPermissions: 0o400], ofItemAtPath: p[1])
                case "writable": try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: p[1])
                case "corrupt": try Data("not a bastion document".utf8).write(to: URL(fileURLWithPath: p[1]))
                default:
                    guard p[0].hasPrefix("move:") else { return write("FAIL doc-file \(p[0])") }
                    try fm.moveItem(atPath: p[1], toPath: String(p[0].dropFirst(5)))
                }
            } catch { return write("FAIL doc-file \(arg): \(error.localizedDescription)") }
            return write("DOC-FILE \(arg)")
        case "doc-disk":
            // On-disk state of <path>: exists, readable, size, unprotected (plain JSON) or not, and Recents.
            let fm = FileManager.default
            let size = (try? fm.attributesOfItem(atPath: arg)[.size] as? Int) ?? -1
            let head = (try? FileHandle(forReadingFrom: URL(fileURLWithPath: arg)).readData(ofLength: 64)).map { String(decoding: $0, as: UTF8.self) } ?? ""
            let inRecents = recentDocuments(dataDir: LibraryModel.dataDir.path).contains(arg)
            return write("DOC-DISK \((arg as NSString).lastPathComponent) exists=\(fm.fileExists(atPath: arg)) readable=\(fm.isReadableFile(atPath: arg)) size=\(size) head=\(head.prefix(12).replacingOccurrences(of: "\n", with: " ")) recents=\(inRecents)")
        case "doc-start-fit":
            // `doc-start-fit <name>`: layout-fit of the SwiftUI start window from its controls' own frames
            // (StartWindowFit): inside the window, icon buttons and rows ≥ 24 pt, no overlaps.
            await settle(0.4)
            guard let w = window, let content = w.contentView else { return write("FAIL doc-start-fit: no window") }
            let r = StartWindowFit.problems(size: content.bounds.size)
            r.list.forEach { write("FAIL START-FIT \(arg) \(Int(w.frame.width))x\(Int(w.frame.height)) \($0)") }
            if !r.list.isEmpty { await capture(w, "start-fit-\(arg)") }
            let none = r.checked == 0 ? "FAIL " : ""
            return write("\(none)START-FIT \(arg) \(Int(w.frame.width))x\(Int(w.frame.height)) controls=\(r.checked) \(r.list.isEmpty ? "ok" : "\(r.list.count) problems")")
        case "doc-export-key":
            guard let doc = model.activeDocument ?? model.signedInDocument else { return write("FAIL doc-export-key: no active document") }
            do { _ = try doc.handle.exportWrappedKey(); write("DOC-EXPORT-KEY allowed") } catch { write("DOC-EXPORT-KEY refused: \(errorText(error))") }
        default:
            return write("FAIL \(cmd): unknown")
        }
        await settle()
        write("DOC-GATE " + gateState(gate, model))
    }

    private func gateState(_ gate: DocumentGate, _ model: LibraryModel) -> String {
        let phase: String
        switch gate.phase {
        case .deciding: phase = "deciding"
        case .welcome: phase = "welcome"
        case .open: phase = "open \(model.activeName)"
        case .unlock: phase = "unlock \(gate.unlockingDocument?.info.name ?? "?")"
        }
        let touchID = gate.unlockingDocument.map(gate.touchIDReady) ?? false
        let missing = gate.missing.map { ($0.path as NSString).lastPathComponent } ?? "-"
        let docs = model.documents.map { "\($0.info.name)\($0.info.locked ? ":locked" : "")" }.joined(separator: ",")
        let menu = DocumentMenuState.shared
        let extra = " menu=\(menu.libraryShown ? "lib" : "-")\(menu.documentActive ? "+doc" : "")\(menu.canLock ? "+lock" : "") missing=\(missing) cancel=\(gate.canCancelCreate) docs=[\(docs)] error=\(model.error ?? "-")"
        return "phase=\(phase) failures=\(gate.failures) wait=\(gate.waitSecs) problem=\(gate.problem ?? "-") "
            + "biometricAllowed=\(gate.biometricAllowed) touchIdButton=\(touchID) recents=\(gate.recents.count) sessions=\(UIDriver.services?.sessions.tabs.count ?? -1)" + extra
    }
}
#endif
