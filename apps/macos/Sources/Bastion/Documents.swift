import AppKit
import LocalAuthentication
import SwiftUI
import UniformTypeIdentifiers
import BastionCore

/// Royal TS-style documents. The Personal library (`library.json`) is always open; any number of
/// `.bastion` documents (core `docfile`, bridged as `BastionDocument`) sit beside it as top-level
/// nodes. Selecting one makes its library the app's `model.library`, so the tree, inspector,
/// properties, importers and connects all work on it unchanged. A protected document opens
/// locked; unlocking takes its password or Touch ID (a wrapped key in a Touch ID-only Keychain
/// item, `DocumentKeychain`). Lock Credentials, idle auto-lock and screen lock
/// lock every protected document (`DocumentLock`). The list of open documents survives restarts
/// (`open-documents.json`, paths only); the system Open Recent list gets every opened file.
struct OpenDocument: Identifiable {
    let id: String
    let handle: BastionDocument
    var info: DocumentInfoView
}

extension Notification.Name {
    /// Posted by the app delegate for a `.bastion` file opened from Finder.
    static let bastionOpenDocument = Notification.Name("BastionOpenDocument")
}

/// Serial background saves per document (H05). Each save waits for the previous one of the same
/// document, so saves never overlap or reorder; `generation` tells a completion whether a newer
/// save was queued after it.
@MainActor
enum DocumentSaves {
    private static var tails: [String: (generation: Int, task: Task<Bool, Never>)] = [:]

    static func enqueue(_ id: String, handle: BastionDocument, done: @escaping @MainActor (Int, String?) -> Void) -> Task<Bool, Never> {
        let previous = tails[id]
        let generation = (previous?.generation ?? 0) + 1
        let task = Task<Bool, Never> { @MainActor in
            _ = await previous?.task.value
            let failure: String? = await Task.detached(priority: .userInitiated) {
                do { try handle.save(); return nil } catch { return errorText(error) }
            }.value
            done(generation, failure)
            if tails[id]?.generation == generation { tails[id] = nil }
            return failure == nil
        }
        tails[id] = (generation, task)
        return task
    }

    static func isLatest(_ id: String, _ generation: Int) -> Bool {
        (tails[id]?.generation ?? generation) == generation
    }
}

/// Hooks the credential auto-lock calls without knowing about documents.
@MainActor
enum DocumentLock {
    static var lockAll: () -> Void = {}
    static var anyUnlocked: () -> Bool = { false }
}

@MainActor
extension LibraryModel {
    private static var openDocumentsFile: URL { dataDir.appendingPathComponent("open-documents.json") }
    static var documentType: UTType { UTType(filenameExtension: documentExtension()) ?? .json }

    var activeDocument: OpenDocument? { documents.first { $0.id == activeDocumentId } }
    var activeName: String { activeDocument?.info.name ?? personalName }

    /// Reopen the documents that were open at the last quit (protected ones locked).
    func restoreDocuments() {
        DocumentLock.lockAll = { [weak self] in self?.lockAllDocuments() }
        DocumentLock.anyUnlocked = { [weak self] in self?.documents.contains { $0.info.protected && !$0.info.locked } ?? false }
        NotificationCenter.default.addObserver(forName: .bastionOpenDocument, object: nil, queue: .main) { [weak self] note in
            guard let url = note.object as? URL else { return }
            MainActor.assumeIsolated { self?.openDocument(url: url) }
        }
        let paths = (try? Data(contentsOf: Self.openDocumentsFile)).flatMap { try? JSONDecoder().decode([String].self, from: $0) } ?? []
        // A1-FU5: once, before the restore, Personal, Recents and these paths become known.
        if let problem = OriginQuestion.migrate(dataDir: Self.dataDir.path, personalId: personalDocument?.info().id, restorePaths: paths) {
            self.error = problem
        }
        for path in paths where FileManager.default.fileExists(atPath: path) {
            do { try adopt(BastionDocument.reopen(path: path, dataDir: Self.dataDir.path)) } catch { self.error = "Could not reopen \(path): \(error)" }
        }
    }

    private func persistOpenDocuments() {
        let paths = documents.compactMap { $0.info.path }
        do {
            try JSONEncoder().encode(paths).write(to: Self.openDocumentsFile, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: Self.openDocumentsFile.path)
        } catch {
            self.error = "Could not remember the open documents: \(error)"
        }
    }

    @discardableResult
    func adopt(_ handle: BastionDocument) -> String {
        let info = handle.info()
        if let existing = documents.first(where: { $0.id == info.id }) { return existing.id }
        documents.append(OpenDocument(id: info.id, handle: handle, info: info))
        if let path = info.path { NSDocumentController.shared.noteNewRecentDocumentURL(URL(fileURLWithPath: path)) }
        persistOpenDocuments()
        return info.id
    }

    func refreshDocument(_ id: String) {
        guard let i = documents.firstIndex(where: { $0.id == id }) else { return }
        documents[i].info = documents[i].handle.info()
    }

    private func document(_ id: String?) -> OpenDocument? {
        documents.first { $0.id == (id ?? activeDocumentId) }
    }

    // MARK: File menu

    func newDocument() {
        // With the document gate, the Welcome create form (name, password, Touch ID) is the one create UI.
        if DocumentGate.enabled { return DocumentGate.shared.showCreate() }
        guard let name = DocumentDialogs.ask(title: "New Document", message: "A document holds its own folders, connections and, when protected, credentials.",
                                             field: "Name", initial: "Untitled") else { return }
        do {
            let id = adopt(try BastionDocument.create(name: name, dataDir: Self.dataDir.path))
            activate(id)
        } catch { self.error = "\(error)" }
    }

    func openDocument(url: URL? = nil) {
        guard let url = url ?? DocumentDialogs.chooseOpen(title: "Open Document") else { return }
        // With the gate: its Unlock screen (or the moved/deleted notice), not a password dialog.
        if DocumentGate.enabled { return DocumentGate.shared.showUnlock(path: url.path) }
        do {
            let id = adopt(try BastionDocument.open(path: url.path, dataDir: Self.dataDir.path))
            select(id)
        } catch { self.error = "Could not open \(url.lastPathComponent): \(error)" }
    }

    /// Select a document node: unlock first when needed, then make it active. A choice by hand, so
    /// the shown library heads Recents and the next launch opens it (LIB-01); locks never come here.
    func select(_ id: String?) {
        guard let id else {
            activate(nil)
            personalDocument?.noteShown()
            return
        }
        guard let doc = document(id) else { return }
        if doc.info.locked {
            unlock(id) { [weak self] ok in
                guard ok else { return }
                self?.activate(id)
                doc.handle.noteOpened()
            }
        } else {
            activate(id)
            doc.handle.noteOpened()
        }
    }

    /// Save in the background (H05): the core's lock, backup, encryption and durable replace run
    /// off the main actor, one save at a time per document. The result publishes on the main
    /// actor; only the newest queued save refreshes the document's state. The task's value is
    /// whether the save succeeded (nil when nothing was queued).
    @discardableResult
    func saveDocument(_ id: String? = nil) -> Task<Bool, Never>? {
        guard let doc = document(id) else {
            mutate { _ in } // Personal saves on every change; this just reports a failed save.
            return nil
        }
        guard doc.info.path != nil else { saveDocumentAs(doc.id); return nil }
        return DocumentSaves.enqueue(doc.id, handle: doc.handle) { [weak self] generation, failure in
            if let failure { self?.error = failure }
            if DocumentSaves.isLatest(doc.id, generation) { self?.refreshDocument(doc.id) }
        }
    }

    func saveDocumentAs(_ id: String? = nil) {
        guard let doc = document(id) else { return }
        guard let url = DocumentDialogs.chooseSave(title: "Save Document As", name: doc.info.name) else { return }
        do { try doc.handle.saveAs(path: url.path) } catch { self.error = "\(error)" }
        refreshDocument(doc.id)
        if let path = document(doc.id)?.info.path { NSDocumentController.shared.noteNewRecentDocumentURL(URL(fileURLWithPath: path)) }
        persistOpenDocuments()
    }

    func closeDocument(_ id: String? = nil) {
        guard let doc = document(id) else { return }
        if doc.info.dirty && !doc.info.locked {
            switch DocumentDialogs.confirmClose(name: doc.info.name) {
            case .save:
                guard let save = saveDocument(doc.id) else { return }
                Task { @MainActor in
                    guard await save.value, self.document(doc.id)?.info.dirty != true else { return }
                    self.finishClose(doc)
                }
                return
            case .discard: break
            case .cancel: return
            }
        }
        finishClose(doc)
    }

    private func finishClose(_ doc: OpenDocument) {
        OriginQuestion.forget(doc.id)
        _ = try? doc.handle.lock()
        documents.removeAll { $0.id == doc.id }
        if activeDocumentId == doc.id { activate(nil) }
        persistOpenDocuments()
    }

    // MARK: Lock state

    func lockDocument(_ id: String? = nil) {
        guard let doc = document(id) ?? (id == nil ? signedInDocument : nil), doc.info.protected, !doc.info.locked else { return }
        do { _ = try doc.handle.lock() } catch { self.error = "Could not lock \(doc.info.name): \(error)" }
        refreshDocument(doc.id)
        let wasActive = activeDocumentId == doc.id
        guard wasActive || doc.id == DocumentGate.shared.signedInId else { return }
        if wasActive { activate(nil) }
        DocumentGate.shared.documentLocked(path: doc.info.path, returnToPersonal: !wasActive)
    }

    /// The document signed in to at launch while the Personal library is shown (⌘L locks it).
    var signedInDocument: OpenDocument? {
        guard activeDocumentId == nil, let id = DocumentGate.shared.signedInId else { return nil }
        return documents.first { $0.id == id }
    }

    func lockAllDocuments() {
        for doc in documents where doc.info.protected && !doc.info.locked { lockDocument(doc.id) }
    }

    /// Touch ID first when it is set up, then the password (always available as the fallback).
    func unlock(_ id: String, done: @escaping @MainActor (Bool) -> Void) {
        guard let doc = document(id) else { done(false); return }
        guard DocumentTouchID.available, DocumentTouchID.hasCopy(doc.id) else { done(unlockByPassword(doc)); return }
        Task { @MainActor in
            // Spec §5: the key sealed for Touch ID on this Mac; Cancel → password.
            if let context = await DocumentTouchID.authenticate(name: doc.info.name) {
                do {
                    if try DocumentTouchID.unlock(doc.handle, context: context) {
                        refreshDocument(id)
                        done(true)
                        return
                    }
                } catch {
                    if !KeychainQuiet.isCancel(error) { self.error = errorText(error) }
                }
            }
            done(unlockByPassword(doc))
        }
    }

    /// Ask until the password is right or the user cancels.
    private func unlockByPassword(_ doc: OpenDocument) -> Bool {
        var problem: String?
        while let pw = DocumentDialogs.askPassword(name: doc.info.name, problem: problem) {
            do {
                try doc.handle.unlock(password: pw)
                refreshDocument(doc.id)
                return true
            } catch { problem = errorText(error) }
        }
        return false
    }

    // MARK: Rename

    /// Rename a document (`nil` = Personal; no id = the active one). Only the name stored inside
    /// the .bastion file changes, never the file, so the device key and Recents keep working.
    func renameDocument(_ id: String? = nil, personal: Bool = false) {
        let target = personal ? nil : (id.flatMap(document) ?? (id == nil ? activeDocument : nil))
        guard let doc = target else { return renamePersonal() }
        if doc.info.locked {
            unlock(doc.id) { [weak self] ok in if ok { self?.renameDocument(doc.id) } }
            return
        }
        guard let name = DocumentDialogs.rename(current: doc.info.name), name != doc.info.name else { return }
        do {
            try doc.handle.rename(name: name)
            if doc.handle.info().path != nil { try doc.handle.save() }
        } catch { self.error = "Could not rename \(doc.info.name): \(errorText(error))" }
        refreshDocument(doc.id)
        if activeDocumentId == doc.id { activate(doc.id) }
        DocumentMenuState.shared.refresh()
    }

    private func renamePersonal() {
        guard let personal = personalDocument else {
            self.error = "Personal can be renamed once it is stored as a document."
            return
        }
        guard let name = DocumentDialogs.rename(current: personalName), name != personalName else { return }
        do {
            try personal.rename(name: name)
            personalName = personal.info().name
        } catch { self.error = "Could not rename \(personalName): \(errorText(error))" }
        DocumentMenuState.shared.refresh()
    }

    // MARK: Properties

    func showProperties(_ id: String? = nil) {
        guard let doc = document(id) else {
            DocumentDialogs.inform(personalName, "The Personal library is always open and saves on every change. Its credentials live in the app's credential vault (Keychain-wrapped). To share it, use File › Export Document.")
            return
        }
        if doc.info.locked {
            unlock(doc.id) { [weak self] ok in if ok { self?.showProperties(doc.id) } }
            return
        }
        guard let change = DocumentDialogs.properties(info: doc.info) else { return }
        do {
            if change.name != doc.info.name { try doc.handle.rename(name: change.name) }
            if !change.protected && doc.info.protected {
                try doc.handle.setPassword(password: nil)
            } else if change.protected, let pw = change.password {
                try doc.handle.setPassword(password: pw)
            }
            if change.protected && change.biometric != DocumentTouchID.hasCopy(doc.id) {
                // Spec §5: the Keychain holds only the wrapped key, readable after Touch ID.
                if change.biometric {
                    try DocumentTouchID.save(doc.handle)
                } else {
                    DocumentTouchID.forget(doc.id)
                    try doc.handle.setBiometric(on: false)
                }
            }
            if doc.handle.info().path != nil { try doc.handle.save() }
        } catch {
            self.error = errorText(error)
        }
        refreshDocument(doc.id)
        if activeDocumentId == doc.id { activate(doc.id) }
    }

    // MARK: Export / import

    /// Export the active document (or the `ids` selected in it) to a new `.bastion` file.
    func exportDocument(ids: [String]? = nil) {
        let doc = activeDocument
        let canIncludeSecrets = doc.map { $0.info.protected && $0.info.credentials > 0 } ?? false
        guard let choice = DocumentDialogs.export(source: activeName, selectionCount: ids?.count, canIncludeSecrets: canIncludeSecrets) else { return }
        guard let url = DocumentDialogs.chooseSave(title: "Export Document", name: "\(activeName) Export") else { return }
        let name = url.deletingPathExtension().lastPathComponent
        do {
            let v: DocumentExportView
            if let doc {
                v = try doc.handle.exportTo(path: url.path, ids: ids, name: name, includeSecrets: choice.includeSecrets, password: choice.password)
            } else if let personal {
                v = try exportLibraryDocument(library: personal, path: url.path, ids: ids, name: name, password: choice.password, dataDir: Self.dataDir.path)
            } else { return }
            let stripped = v.strippedFields.isEmpty ? "" : "\n\nLeft out as possibly secret: " + v.strippedFields.prefix(5).joined(separator: ", ")
            DocumentDialogs.inform("Exported \(v.connections) connection\(v.connections == 1 ? "" : "s")",
                                   "To \(url.lastPathComponent)\(v.protected ? " (password protected)" : ""). Credentials included: \(v.credentials); references without secrets: \(v.credentialRefs - min(v.credentialRefs, v.credentials)).\(stripped)")
        } catch { self.error = errorText(error) }
    }

    /// Import a `.bastion` document into the active document, after a preview.
    func importDocument() {
        guard let url = DocumentDialogs.chooseOpen(title: "Import Document") else { return }
        var password: String?
        func run(_ apply: Bool) throws -> DocumentImportView {
            if let doc = activeDocument { return try doc.handle.importDocument(path: url.path, password: password, apply: apply) }
            guard let personal else { throw CocoaError(.fileReadUnknown) }
            return try importDocumentIntoLibrary(library: personal, path: url.path, password: password, apply: apply, dataDir: Self.dataDir.path)
        }
        var preview: DocumentImportView?
        var problem: String?
        repeat {
            do { preview = try run(false) } catch {
                let text = errorText(error)
                // H10: decide on the stable code, not the English message.
                guard case FfiError.Failed(_, "vault_locked")? = error as? FfiError else { self.error = text; return }
                guard let pw = DocumentDialogs.askPassword(name: url.deletingPathExtension().lastPathComponent, problem: problem) else { return }
                password = pw
                problem = text
            }
        } while preview == nil
        guard let preview else { return }
        guard preview.connections > 0 else {
            DocumentDialogs.inform("Nothing new to import", "Every connection in “\(preview.sourceName)” is already in “\(activeName)”.")
            return
        }
        guard DocumentDialogs.confirmImport(preview, into: activeName) else { return }
        do {
            _ = try run(true)
            if let id = activeDocumentId { refreshDocument(id) }
            reload()
        } catch { self.error = errorText(error) }
    }
}

// MARK: - Dialogs

/// Native AppKit dialogs for documents. UI test runs set `scripted` answers instead.
@MainActor
enum DocumentDialogs {
    /// UI test runs: answers consumed in order instead of showing a dialog or panel, read from
    /// the file `BASTION_UI_DOCUMENT_ANSWERS` names (one answer per line; `-` = cancel).
    static var scripted: [String] = {
        guard TestHooks.isScripted,
              let file = TestHooks.env("BASTION_UI_DOCUMENT_ANSWERS"),
              let text = try? String(contentsOfFile: file, encoding: .utf8) else { return [] }
        return text.components(separatedBy: "\n").filter { !$0.isEmpty }.map { $0 == "-" ? "" : $0 }
    }()

    private static func next() -> String? {
        scripted.isEmpty ? nil : scripted.removeFirst()
    }

    /// The next scripted answer (UI driver runs only), for dialogs outside this type.
    static func nextScripted() -> String? { next() }

    static func chooseOpen(title: String) -> URL? {
        if let s = next() { return s.isEmpty ? nil : URL(fileURLWithPath: s) }
        let panel = NSOpenPanel()
        panel.title = title
        panel.allowedContentTypes = [LibraryModel.documentType] + (UTType(filenameExtension: legacyDocumentExtension()).map { [$0] } ?? [])
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func chooseSave(title: String, name: String) -> URL? {
        if let s = next() { return s.isEmpty ? nil : URL(fileURLWithPath: s) }
        let panel = NSSavePanel()
        panel.title = title
        panel.nameFieldStringValue = "\(name).\(documentExtension())"
        panel.allowedContentTypes = [LibraryModel.documentType]
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func chooseFolder(title: String, start: URL) -> URL? {
        if let s = next() { return s.isEmpty ? nil : URL(fileURLWithPath: s, isDirectory: true) }
        let panel = NSOpenPanel()
        panel.title = title
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.directoryURL = start
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func inform(_ title: String, _ message: String) {
        if TestHooks.isScripted {
            print("DOCUMENT-INFO \(title): \(message)")
            return
        }
        let a = NSAlert()
        a.messageText = title
        a.informativeText = message
        a.runModalInFront()
    }

    private static func stack(_ views: [NSView]) -> NSStackView {
        let s = NSStackView(views: views)
        s.orientation = .vertical
        s.alignment = .leading
        s.spacing = 8
        s.frame = NSRect(x: 0, y: 0, width: 300, height: CGFloat(views.count) * 30)
        views.forEach { $0.widthAnchor.constraint(equalToConstant: 300).isActive = true }
        return s
    }

    private static func field(_ placeholder: String, secure: Bool = false, value: String = "") -> NSTextField {
        let f: NSTextField = secure ? NSSecureTextField() : NSTextField()
        f.placeholderString = placeholder
        f.stringValue = value
        f.setAccessibilityLabel(placeholder)
        return f
    }

    static func ask(title: String, message: String, field label: String, initial: String) -> String? {
        if let s = next() { return s.isEmpty ? nil : s }
        let a = NSAlert()
        a.messageText = title
        a.informativeText = message
        let f = field(label, value: initial)
        f.frame = NSRect(x: 0, y: 0, width: 300, height: 24)
        a.accessoryView = f
        a.addButton(withTitle: "Create")
        a.addButton(withTitle: "Cancel")
        a.window.initialFirstResponder = f
        guard a.runModalInFront() == .alertFirstButtonReturn else { return nil }
        return f.stringValue.trimmingCharacters(in: .whitespaces).nilIfEmpty
    }

    /// The Rename Document alert and its name field, built apart so the layout-fit test can
    /// measure it without running it modally.
    static func renameAlert(current: String) -> (NSAlert, NSTextField) {
        let a = NSAlert()
        a.messageText = "Rename “\(current)”"
        a.informativeText = "The new name is stored inside the document. Its file, Touch ID and Recents are unchanged."
        let f = field("Name", value: current)
        f.setAccessibilityIdentifier("document-rename-field")
        f.lineBreakMode = .byTruncatingMiddle
        f.cell?.isScrollable = true
        f.frame = NSRect(x: 0, y: 0, width: 300, height: 24)
        a.accessoryView = f
        a.addButton(withTitle: "Rename")
        a.addButton(withTitle: "Cancel")
        a.window.initialFirstResponder = f
        return (a, f)
    }

    /// The new name, trimmed; nil on Cancel or an empty name.
    static func rename(current: String) -> String? {
        if let s = next() { return s.isEmpty ? nil : s }
        let (a, f) = renameAlert(current: current)
        guard a.runModalInFront() == .alertFirstButtonReturn else { return nil }
        return f.stringValue.trimmingCharacters(in: .whitespaces).nilIfEmpty
    }

    static func askPassword(name: String, problem: String?) -> String? {
        if let s = next() { return s.isEmpty ? nil : s }
        let a = NSAlert()
        a.messageText = "Unlock “\(name)”"
        a.informativeText = problem ?? "Enter the document password."
        let f = field("Document password", secure: true)
        f.frame = NSRect(x: 0, y: 0, width: 300, height: 24)
        a.accessoryView = f
        a.addButton(withTitle: "Unlock")
        a.addButton(withTitle: "Cancel")
        a.window.initialFirstResponder = f
        return a.runModalInFront() == .alertFirstButtonReturn ? f.stringValue : nil
    }

    enum CloseChoice { case save, discard, cancel }

    static func confirmClose(name: String) -> CloseChoice {
        if let s = next() { return s == "save" ? .save : s == "discard" ? .discard : .cancel }
        let a = NSAlert()
        a.messageText = "Save changes to “\(name)” before closing?"
        a.informativeText = "This document has never been saved."
        a.addButton(withTitle: "Save…")
        a.addButton(withTitle: "Cancel")
        a.addButton(withTitle: "Don’t Save")
        switch a.runModalInFront() {
        case .alertFirstButtonReturn: return .save
        case .alertThirdButtonReturn: return .discard
        default: return .cancel
        }
    }

    struct PropertiesChange {
        var name: String
        var protected: Bool
        /// A new password (nil keeps the current one).
        var password: String?
        var biometric: Bool
    }

    /// Scripted form: `name|protected(0/1)|password|biometric(0/1)`.
    static func properties(info: DocumentInfoView) -> PropertiesChange? {
        if let s = next() {
            let p = s.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard p.count == 4 else { return nil }
            return PropertiesChange(name: p[0], protected: p[1] == "1", password: p[2].isEmpty ? nil : p[2], biometric: p[3] == "1")
        }
        while true {
            let a = NSAlert()
            a.messageText = "Document Properties"
            a.informativeText = [info.path ?? "Not saved yet", "Format version \(info.loadedVersion == 0 ? "0 (library.json)" : "\(info.loadedVersion)")",
                                 info.protected ? "\(info.credentials) credential\(info.credentials == 1 ? "" : "s") stored in the document" : "Unprotected: credentials are referenced, never stored"].joined(separator: "\n")
            let name = field("Name", value: info.name)
            let protect = NSButton(checkboxWithTitle: "Protect with a password (encrypts the whole file)", target: nil, action: nil)
            protect.state = info.protected ? .on : .off
            let pw = field(info.protected ? "New password (leave empty to keep)" : "Password (8+ characters)", secure: true)
            let confirm = field("Confirm password", secure: true)
            let touch = NSButton(checkboxWithTitle: "Unlock with Touch ID (password stays as fallback)", target: nil, action: nil)
            touch.state = DocumentTouchID.hasCopy(info.id) ? .on : .off
            a.accessoryView = stack([name, protect, pw, confirm, touch])
            a.addButton(withTitle: "Save")
            a.addButton(withTitle: "Cancel")
            guard a.runModalInFront() == .alertFirstButtonReturn else { return nil }
            let isProtected = protect.state == .on
            let newPw = pw.stringValue.isEmpty ? nil : pw.stringValue
            if isProtected && newPw != confirm.stringValue.nilIfEmpty {
                inform("Passwords do not match", "Type the same password in both fields.")
                continue
            }
            if isProtected && !info.protected && newPw == nil {
                inform("Password required", "Choose a password to protect this document.")
                continue
            }
            return PropertiesChange(name: name.stringValue, protected: isProtected, password: isProtected ? newPw : nil,
                                    biometric: isProtected && touch.state == .on)
        }
    }

    struct ExportChoice {
        var includeSecrets: Bool
        var password: String?
    }

    /// Scripted form: `secrets(0/1)|password`.
    static func export(source: String, selectionCount: Int?, canIncludeSecrets: Bool) -> ExportChoice? {
        if let s = next() {
            let p = s.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard p.count == 2 else { return nil }
            return ExportChoice(includeSecrets: p[0] == "1", password: p[1].isEmpty ? nil : p[1])
        }
        while true {
            let a = NSAlert()
            a.messageText = "Export \(selectionCount.map { "\($0) selected item\($0 == 1 ? "" : "s")" } ?? "“\(source)”")"
            a.informativeText = "Writes a .bastion document you can share. Secrets are stripped unless you include them; a file with secrets is always password protected."
            let secrets = NSButton(checkboxWithTitle: "Include credentials (secrets)", target: nil, action: nil)
            secrets.isEnabled = canIncludeSecrets
            let pw = field("Password for the exported file (optional)", secure: true)
            let confirm = field("Confirm password", secure: true)
            a.accessoryView = stack([secrets, pw, confirm])
            a.addButton(withTitle: "Export…")
            a.addButton(withTitle: "Cancel")
            guard a.runModalInFront() == .alertFirstButtonReturn else { return nil }
            let password = pw.stringValue.nilIfEmpty
            if password != confirm.stringValue.nilIfEmpty { inform("Passwords do not match", "Type the same password in both fields."); continue }
            if secrets.state == .on && password == nil { inform("Password required", "A file that carries credentials must be password protected."); continue }
            return ExportChoice(includeSecrets: secrets.state == .on, password: password)
        }
    }

    static func confirmImport(_ p: DocumentImportView, into target: String) -> Bool {
        if let s = next() { return s == "yes" }
        let a = NSAlert()
        a.messageText = "Import \(p.connections) connection\(p.connections == 1 ? "" : "s") from “\(p.sourceName)” into “\(target)”?"
        var lines = ["They go into a new folder “Imported \(p.sourceName)”."]
        if !p.duplicates.isEmpty { lines.append("Skipped as already present: " + p.duplicates.prefix(8).joined(separator: ", ") + (p.duplicates.count > 8 ? "…" : "")) }
        if p.credentials > 0 { lines.append("\(p.credentials) credential\(p.credentials == 1 ? "" : "s") will be stored in this document.") }
        if p.credentialsDropped > 0 { lines.append("\(p.credentialsDropped) credential\(p.credentialsDropped == 1 ? "" : "s") left out: \(target) has no password, so it can only reference credentials.") }
        a.informativeText = lines.joined(separator: "\n\n")
        a.addButton(withTitle: "Import")
        a.addButton(withTitle: "Cancel")
        return a.runModalInFront() == .alertFirstButtonReturn
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}

// MARK: - Sidebar

/// The document nodes above the tree: Personal, then each open `.bastion` document with its
/// lock state. Click selects (unlocking first); the context menu has the document commands.
struct DocumentStrip: View {
    @Environment(LibraryModel.self) private var model
    @Environment(SettingsModel.self) private var settings
    private var compactAlone: Bool { HeaderStyle.isCompact(settings) && model.documents.isEmpty }

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            // Compact header: the title-bar switcher names the library; the rows stay only while
            // documents are open (they carry lock state and per-document actions).
            if !compactAlone {
            row(id: nil, name: model.personalName, symbol: "person.crop.circle", lock: nil, dirty: false)
            }
            ForEach(model.documents) { d in
                row(id: d.id, name: d.info.name, symbol: "doc.text",
                    lock: d.info.protected ? (d.info.locked ? "lock.fill" : "lock.open") : nil, dirty: d.info.dirty)
            }
            SidebarWorkspaceMenu()
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .overlay(alignment: .bottom) { Divider() }
    }

    private func row(id: String?, name: String, symbol: String, lock: String?, dirty: Bool) -> some View {
        let active = model.activeDocumentId == id
        return Button { model.select(id) } label: {
            HStack(spacing: 6) {
                Image(systemName: symbol).frame(width: 16)
                Text(dirty ? "\(name) — Edited" : name).lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 4)
                if let lock { Image(systemName: lock).foregroundStyle(.secondary).help(lock == "lock.fill" ? "Locked" : "Unlocked") }
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 3)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(active ? Color.accentColor.opacity(0.18) : .clear, in: RoundedRectangle(cornerRadius: 5))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Document \(name)\(lock == "lock.fill" ? ", locked" : "")")
        .contextMenu { menu(id: id, lock: lock) }
    }

    @ViewBuilder
    private func menu(id: String?, lock: String?) -> some View {
        if let id {
            if lock == "lock.fill" {
                Button("Unlock…") { model.select(id) }
            } else if lock != nil {
                Button("Lock Document") { model.lockDocument(id) }
            }
            Button("Save Document") { model.saveDocument(id) }
            Button("Save Document As…") { model.saveDocumentAs(id) }
            Divider()
            Button("Rename…") { model.renameDocument(id) }
            Button("Document Properties…") { model.showProperties(id) }
            Divider()
            Button("Close Document") { model.closeDocument(id) }
        } else {
            Button("Rename…") { model.renameDocument(personal: true) }
            Button("Document Properties…") { model.showProperties(nil) }
        }
    }
}

// MARK: - Menus

/// File menu document commands (after New Connection…). ⌘O and ⌘S follow the Mac convention;
/// ⌘N stays New Connection, so New Document is ⌥⌘N.
struct DocumentMenus: SwiftUI.Commands {
    let model: LibraryModel
    @ObservedObject var gate = LaunchGate.shared
    /// Menu commands do not track `@Observable` models: this mirror republishes what they need.
    @ObservedObject var state = DocumentMenuState.shared

    private var libraryShown: Bool { state.libraryShown }
    private var documentActive: Bool { state.documentActive }

    var body: some SwiftUI.Commands {
        let _ = RenderCount.hit("DocumentMenus")
        CommandGroup(after: .newItem) {
            Divider()
            Button("New Document…") { model.newDocument() }.keyboardShortcut("n", modifiers: [.command, .option])
            Button("Open Document…") { model.openDocument() }.keyboardShortcut("o")
            Menu("Open Recent Document") {
                ForEach(state.recents, id: \.self) { path in
                    Button((path as NSString).lastPathComponent) { model.openDocument(url: URL(fileURLWithPath: path)) }
                }
            }
            Button("Save Document") { model.saveDocument() }.keyboardShortcut("s").disabled(!documentActive)
            Button("Save Document As…") { model.saveDocumentAs() }.keyboardShortcut("s", modifiers: [.command, .option, .shift]).disabled(!documentActive)
            Button("Close Document") { model.closeDocument() }.disabled(!documentActive)
            Divider()
            Button("Export Document…") { model.exportDocument() }.disabled(!documentActive)
            Button("Import Document…") { model.importDocument() }.disabled(!libraryShown)
            Divider()
            Button("Rename Document…") { model.renameDocument() }.disabled(!libraryShown)
            Button("Document Properties…") { model.showProperties() }.disabled(!documentActive)
            // ⌥⌘L: ⌘L is Quick Connect (core shortcut list), which nm-fit found shadowed this.
            Button("Lock Document") { model.lockDocument() }.keyboardShortcut("l", modifiers: [.command, .option])
                .disabled(!state.canLock)
        }
    }
}

/// What the File menu's document items depend on, published for `DocumentMenus` (SwiftUI menu
/// commands re-render from `ObservableObject`s only). Refreshed when the gate phase or the open
/// documents change.
@MainActor
final class DocumentMenuState: ObservableObject {
    static let shared = DocumentMenuState()
    /// The main window shows the library (not Welcome or Unlock).
    @Published private(set) var libraryShown = true
    /// An open document is active (not the Personal library): Save, Close, Export, Properties apply.
    @Published private(set) var documentActive = false
    @Published private(set) var canLock = false
    @Published private(set) var recents: [String] = []

    func refresh() {
        let gate = DocumentGate.shared
        let doc = gate.model.flatMap { $0.activeDocument ?? $0.signedInDocument }
        let shown = !DocumentGate.enabled || gate.phase == .open
        libraryShown = shown
        documentActive = shown && gate.model?.activeDocument != nil
        canLock = shown && (doc.map { $0.info.protected && !$0.info.locked } ?? false)
        recents = recentDocuments(dataDir: LibraryModel.dataDir.path)
    }
}

/// True for the document extension and the pre-rename one (`.gantry`, `.bastion`).
func isDocumentExtension(_ ext: String) -> Bool {
    let e = ext.lowercased()
    return e == documentExtension() || e == legacyDocumentExtension()
}
