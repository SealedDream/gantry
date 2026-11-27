import SwiftUI
import WebKit
import BastionCore

// B13 web sign-in autofill (docs/plans/B13-WEB-AUTOFILL.md). The core decides (exact https origin, top
// frame, secure page, the connection's switch, policy) and builds the script; this file only shows the
// button and runs the script once, in a private content world the page's own scripts cannot see.

extension WebPage {
    /// The content world the fill script runs in: page scripts cannot read its variables or patch what it calls.
    static let autofillWorld = WKContentWorld.world(name: "bastion-autofill")

    /// Run the core's fill script in the top frame. Returns the script's status word
    /// (`filled`, `no-form`, `many-password-fields`, `origin-changed`) or nil when it could not run.
    func runAutofill(_ script: String) async -> String? {
        await withCheckedContinuation { done in
            view.evaluateJavaScript(script, in: nil, in: Self.autofillWorld) { result in
                done.resume(returning: (try? result.get()) as? String)
            }
        }
    }

    /// The top frame's address now, for the core's origin check.
    var currentURL: String { view.url?.absoluteString ?? "" }
}

/// "Fill sign-in": shown only when the connection's switch is on and policy allows it.
struct WebAutofillButton: View {
    let page: WebPage
    let connectionId: String
    @Environment(LibraryModel.self) private var model
    @Environment(CredentialsModel.self) private var credentials
    @State private var notice: String?

    var body: some View {
        if offered {
            Button("Fill sign-in", systemImage: "key.fill") { Task { await fill() } }
                .help("Fill this connection's saved login (only on its exact https address)")
                .accessibilityIdentifier("web.fillSignIn")
                .popover(isPresented: Binding(get: { notice != nil }, set: { if !$0 { notice = nil } })) {
                    Text(notice ?? "").font(DS.Font.caption).padding(DS.Space.s).frame(maxWidth: 320)
                        .accessibilityIdentifier("web.fillSignIn.notice")
                }
        }
    }

    private var offered: Bool {
        guard let library = model.library else { return false }
        return (try? webAutofillOffered(library: library, connectionId: connectionId)) ?? false
    }

    private func fill() async {
        guard let library = model.library else { return }
        notice = await WebAutofillRun.fill(page: page, connectionId: connectionId, library: library, vault: credentials.vault,
                                           credentialId: model.connection(id: connectionId)?.effectiveCredentialId, isSecure: page.isSecure)
    }
}

/// One "Fill sign-in" click: ask the core, run its script, and say what happened (nil = filled).
@MainActor
enum WebAutofillRun {
    static func fill(page: WebPage, connectionId: String, library: Library, vault: CredentialVault?, credentialId: String?, isSecure: Bool) async -> String? {
        guard let vault else { return "Unlock the vault to fill the sign-in." }
        let decision: WebAutofill
        do {
            decision = try vault.webAutofill(library: library, connectionId: connectionId, credentialId: credentialId,
                                             pageUrl: page.currentURL, isMainFrame: true, isSecure: isSecure)
        } catch {
            return errorText(error)
        }
        guard let script = decision.script else { return decision.message }
        switch await page.runAutofill(script) {
        case "filled": return nil
        case "no-form": return "No sign-in form found."
        case "many-password-fields": return "Not filled: this page has more than one password field."
        case "origin-changed": return "Not filled: the page changed address."
        default: return "Not filled: the page did not accept it."
        }
    }
}

#if BASTION_TEST_HOOKS
/// Offline pages for the B13 UI suite (`web-fixture`). Field ids `u` and `p` are what `web-fill` reads back.
enum WebAutofillFixtures {
    static let html: [String: String] = [
        "login": #"<html><body><form><input id="u" type="text"><input id="p" type="password"><button>Sign in</button></form></body></html>"#,
        "two-passwords": #"<html><body><form><input id="u" type="text"><input id="p" type="password"><input type="password"></form></body></html>"#,
        "hidden": #"<html><body><form><input id="u" type="text" style="display:none"><input id="p" type="password" style="display:none"></form></body></html>"#,
        "iframe": #"<html><body><iframe srcdoc="<input id='p' type='password'>" sandbox></iframe><input id="u" type="text"></body></html>"#,
    ]
}
#endif
