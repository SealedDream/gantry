import AppKit
import BastionCore

/// One saved login the core offers a connection (`CredentialVault.loginCandidates`). No secret.
struct LoginOffer: Identifiable, Equatable {
    let credentialId: String
    let name: String
    let username: String
    /// `password` or `ssh-key`.
    let kind: String
    /// `default`, `connection`, `named`, `inherited` or `same-host` (the core's words).
    let source: String
    let sourceName: String
    /// The connection's own or inherited login: connect with it without asking. False for a
    /// login saved for another connection, which is offered until the user confirms it
    /// (owner decision D1).
    let autoUse: Bool

    var id: String { credentialId }
    /// Set on the connection itself (its default or one of its other logins): removable there.
    var isOwn: Bool { source == "default" || source == "connection" }

    /// Where it comes from, in the words Native Windows uses.
    var origin: String {
        switch source {
        case "default": "Default"
        case "connection": "This connection"
        case "named": "Named by this connection"
        case "inherited": sourceName.isEmpty ? "Inherited" : "From \(sourceName)"
        case "same-host": "Saved for \(sourceName)"
        default: source
        }
    }

    /// `appuser  ·  Saved for K8s SSH`.
    var label: String { "\(username.isEmpty ? name : username)  ·  \(origin)" }

    init(_ v: LoginCandidateView) {
        credentialId = v.credentialId
        name = v.name
        username = v.username
        kind = v.kind
        source = v.source
        sourceName = v.sourceName
        autoUse = v.autoUse
    }
}

/// Which saved login a connection uses is the core's answer (`bastion_core::logins`), shared with
/// the other apps: SSH, RDP and Services / Processes / Event Log all ask here (A1-NM-01). The
/// app never picks between a credential id and a credential name itself.
@MainActor
enum LoginResolver {
    /// The connection, or a folder above it, sets a login. Read without the vault, and used only
    /// to decide whether opening the vault (which may prompt) is worth it.
    static func hasAssignment(_ c: ConnectionView) -> Bool {
        c.effectiveCredentialId != nil || c.effectiveCredentialName != nil
    }

    /// The core's list, best first. `passwordsOnly` for RDP, which cannot use an SSH key.
    static func offers(for connectionId: String, library: Library, vault: CredentialVault, passwordsOnly: Bool) throws -> [LoginOffer] {
        try vault.loginCandidates(library: library, connectionId: connectionId, passwordsOnly: passwordsOnly).map(LoginOffer.init)
    }

    /// Opens the vault when that cannot prompt or the connection sets a login, then asks the
    /// core. Empty when the vault stays locked or nothing is saved; a failure is reported.
    static func resolve(_ c: ConnectionView, library: Library, credentials: CredentialsModel, sessions: SessionsModel,
                        passwordsOnly: Bool) async -> [LoginOffer] {
        if credentials.vault == nil, hasAssignment(c) || credentials.opensWithoutPrompt {
            await credentials.openInBackground(sessions: sessions)
        }
        guard let vault = credentials.vault else { return [] }
        do {
            return try offers(for: c.id, library: library, vault: vault, passwordsOnly: passwordsOnly)
        } catch {
            sessions.error = "\(c.name): saved logins could not be read: \(errorText(error))"
            return []
        }
    }

    /// Before any sheet: would the best login connect without asking? With the vault locked the
    /// answer is whether a login is assigned at all; the attempt then opens the vault and asks.
    static func mayAutoConnect(_ c: ConnectionView, credentials: CredentialsModel, passwordsOnly: Bool) -> Bool {
        guard let vault = credentials.vault, let library = credentials.currentLibrary() else { return hasAssignment(c) }
        return (try? offers(for: c.id, library: library, vault: vault, passwordsOnly: passwordsOnly))?.first?.autoUse == true
    }

    /// A login confirmed earlier in this run is reused only while the core still offers it.
    static func stillOffered(_ credentialId: String, to c: ConnectionView, credentials: CredentialsModel, passwordsOnly: Bool) -> Bool {
        guard let vault = credentials.vault, let library = credentials.currentLibrary() else { return false }
        return (try? offers(for: c.id, library: library, vault: vault, passwordsOnly: passwordsOnly))?.contains { $0.credentialId == credentialId } == true
    }

    /// "Use this login for <connection> from now on": it joins the connection's own logins and
    /// becomes the default, so the next open needs no sheet.
    static func keep(_ credentialId: String, for c: ConnectionView, model: LibraryModel, credentials: CredentialsModel) {
        let hadDefault = c.credentialId != nil
        change(c.id, model: model, credentials: credentials) { vault, library in
            try vault.addLogin(library: library, connectionId: c.id, credentialId: credentialId)
            if hadDefault { try vault.setDefaultLogin(library: library, connectionId: c.id, credentialId: credentialId) }
        }
    }

    /// One edit of a connection's logins (Add, Remove, Make Default), saved with the library.
    /// The login remembered from an earlier connect this run would win over the new list: drop it.
    static func change(_ connectionId: String, model: LibraryModel, credentials: CredentialsModel,
                       _ edit: (CredentialVault, Library) throws -> Void) {
        guard let vault = credentials.vault else {
            model.error = "Saved logins are locked. Unlock them in Credentials, then try again."
            return
        }
        model.mutate { try edit(vault, $0) }
        credentials.forgetLastLogin(for: connectionId)
    }

    /// The sheet's login state for the UI driver (`login-sheet`): labels only, never a secret.
    static func sheetText(offers: [LoginOffer], selected: String?, keep: Bool?) -> String {
        let rows = offers.map { "\($0.label)\($0.autoUse ? "" : " [offered]")" }.joined(separator: " | ")
        let chosen = offers.first { $0.credentialId == selected }?.label ?? (selected == nil ? "typed" : "other")
        return "selected=\(chosen); keep=\(keep.map { $0 ? "on" : "off" } ?? "hidden"); rows=\(rows)"
    }

    /// A credential dropped on a folder becomes the login of every connection under it that has
    /// none of its own, and those then sign in with it without asking: one drop, so it asks first.
    static func confirmFolderLogin(credential: String, folder: String) -> Bool {
        if let answer = scriptedFolderLogin { return answer }
        let alert = NSAlert()
        alert.messageText = "Use “\(credential)” for every connection in “\(folder)”?"
        alert.informativeText = "Connections in this folder that have no login of their own will sign in with it without asking. You can change this in the folder’s Properties › Credentials."
        alert.addButton(withTitle: "Use for Folder")
        alert.addButton(withTitle: "Cancel")
        return alert.runModalInFront() == .alertFirstButtonReturn
    }

    /// Answer the UI driver gives instead of showing the alert (nil shows it).
    static var scriptedFolderLogin: Bool?

    /// Last state a connect sheet published, read by the UI driver only.
    static var sheetState = ""
    /// The sheet's method and progress, read by the UI driver's failure lines only.
    static var sheetDetail = ""
}
