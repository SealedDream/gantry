//! Web sign-in autofill over UniFFI (B13): the one place a web connection's saved password
//! leaves the vault for a page. The core decides (`bastion_core::webautofill::check`), releases
//! the connection's own or inherited password login (the same rule as `rdp_login_for`), audits
//! every attempt, and hands back only the script to run in the top frame.
use std::sync::Arc;

use bastion_core::audit::Outcome;
use bastion_core::webautofill::{self, PageState, Refusal};

use crate::credentials::CredentialVault;
use crate::{parse_id, FfiResult};

/// What "Fill sign-in" may do now. With `script` set, run it in the top frame; otherwise show
/// `message` (never contains a secret).
#[derive(uniffi::Record)]
pub struct WebAutofill {
    /// The fill script, holding the user name and password as JS string literals. Run once, then drop.
    pub script: Option<String>,
    /// `ok`, or the refusal code (`policy`, `off`, `not-https`, `not-secure`, `sub-frame`,
    /// `user-info`, `bad-address`, `origin-mismatch`, `no-credential`).
    pub code: String,
    pub message: String,
}

/// Whether to show the Fill sign-in button for this connection: policy allows it and the
/// connection's (inherited) switch is on. A broken managed policy hides it. The click still goes
/// through `CredentialVault::web_autofill`, which checks everything again.
#[uniffi::export]
pub fn web_autofill_offered(library: Arc<crate::Library>, connection_id: String) -> FfiResult<bool> {
    let forbids = crate::policy::effective().map_or(true, |p| p.forbid_web_autofill);
    let c = library.resolve(parse_id(&connection_id)?)?;
    Ok(!forbids && c.settings.web_autofill == Some(true))
}

#[uniffi::export]
impl CredentialVault {
    /// Decide and, when allowed, build the fill script for the page the user is looking at.
    /// `credential_id` is the connection's effective credential (as for `rdp_login_for`).
    /// A broken managed policy forbids. Every call is audited with the page origin and outcome.
    pub fn web_autofill(
        &self,
        library: Arc<crate::Library>,
        connection_id: String,
        credential_id: Option<String>,
        page_url: String,
        is_main_frame: bool,
        is_secure: bool,
    ) -> FfiResult<WebAutofill> {
        let id = parse_id(&connection_id)?;
        let connection = library.resolve(id)?;
        let forbids = crate::policy::effective().map_or(true, |p| p.forbid_web_autofill);
        let saved = webautofill::saved_url(&connection.host, connection.settings.port);
        let page = PageState { url: &page_url, is_main_frame, is_secure };
        let audit_origin = webautofill::audit_origin(&page_url);
        let in_page = saved.as_ref().map(webautofill::script_origin).unwrap_or_default();
        let origin = match webautofill::check(forbids, connection.settings.web_autofill == Some(true), saved.as_ref(), &page) {
            Ok(origin) => origin,
            Err(refusal) => return self.refuse_web(&connection_id, &audit_origin, refusal),
        };
        let Some((username, password)) = self.password_login_for(&library, id, credential_id)? else {
            return self.refuse_web(&connection_id, &audit_origin, Refusal::NoCredential);
        };
        self.audit_web("credential.release.web", &connection_id, Outcome::Success, &origin, "ok")?;
        // The password and the script are wiped in Rust when dropped (T27.9); the one copy UniFFI
        // hands to Swift cannot be (T23, accepted).
        let script = webautofill::fill_script(&in_page, &username, &password);
        Ok(WebAutofill { script: Some(script.as_str().to_owned()), code: "ok".into(), message: String::new() })
    }
}

impl CredentialVault {
    fn refuse_web(&self, connection_id: &str, origin: &str, refusal: Refusal) -> FfiResult<WebAutofill> {
        self.audit_web("web.autofill.refused", connection_id, Outcome::Denied, origin, refusal.code())?;
        Ok(WebAutofill { script: None, code: refusal.code().into(), message: refusal.reason() })
    }
}

#[cfg(test)]
mod tests {
    //! Generated data only; the password is `pw-made-up`. Nothing reaches a network.
    use super::*;
    use crate::Library;

    struct Bench {
        dir: tempfile::TempDir,
        lib: Arc<Library>,
        vault: Arc<CredentialVault>,
        id: String,
    }

    fn bench(host: &str, switch: Option<&str>) -> Bench {
        let dir = tempfile::tempdir().unwrap();
        let lib = Arc::new(Library::open(dir.path().join("library.json").display().to_string()).unwrap());
        let vault = Arc::new(CredentialVault::open_ephemeral(dir.path().join("c.vault").display().to_string()).unwrap());
        let id = lib.add_connection(None, "Admin".into(), "web".into(), host.into(), None, None).unwrap();
        lib.set_property(id.clone(), "web_autofill".into(), switch.map(str::to_string)).unwrap();
        vault.set_inline_password(id.clone(), "ops".into(), "pw-made-up".into()).unwrap();
        Bench { dir, lib, vault, id }
    }

    impl Bench {
        fn fill(&self, page: &str, main: bool, secure: bool) -> WebAutofill {
            self.vault.web_autofill(self.lib.clone(), self.id.clone(), None, page.into(), main, secure).unwrap()
        }
        fn audit(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("audit.jsonl")).unwrap_or_default()
        }
    }

    #[test]
    fn off_by_default_and_on_fills_the_exact_origin() {
        let b = bench("https://admin.example.com/login", None);
        assert!(!web_autofill_offered(b.lib.clone(), b.id.clone()).unwrap());
        assert_eq!(b.fill("https://admin.example.com/login", true, true).code, "off");

        let b = bench("https://admin.example.com/login", Some("true"));
        assert!(web_autofill_offered(b.lib.clone(), b.id.clone()).unwrap());
        let r = b.fill("https://admin.example.com/login?next=/x", true, true);
        assert_eq!(r.code, "ok");
        let script = r.script.unwrap();
        assert!(script.contains("\"pw-made-up\"") && script.contains("\"ops\"") && script.contains("\"https://admin.example.com\""));
    }

    #[test]
    fn refusals_are_audited_without_secrets_or_paths() {
        let b = bench("https://admin.example.com", Some("true"));
        assert_eq!(b.fill("https://admin.example.com.evil.net/login?token=abc", true, true).code, "origin-mismatch");
        assert_eq!(b.fill("https://admin.example.com/", false, true).code, "sub-frame");
        assert_eq!(b.fill("https://admin.example.com/", true, false).code, "not-secure");
        assert_eq!(b.fill("http://admin.example.com/", true, true).code, "not-https");
        assert_eq!(b.fill("https://admin.example.com/", true, true).code, "ok");
        let audit = b.audit();
        assert_eq!(audit.matches("web.autofill.refused").count(), 4);
        assert_eq!(audit.matches("credential.release.web").count(), 1);
        assert!(!audit.contains("pw-made-up") && !audit.contains("token=abc") && !audit.contains("/login"), "{audit}");
        assert!(audit.contains("https://admin.example.com.evil.net"));
    }

    #[test]
    fn no_saved_password_is_refused() {
        let b = bench("https://admin.example.com", Some("true"));
        b.vault.remove_inline(b.id.clone()).unwrap();
        let r = b.fill("https://admin.example.com/", true, true);
        assert_eq!((r.code.as_str(), r.script.is_none()), ("no-credential", true));
    }

    #[test]
    fn the_switch_is_inherited_from_a_folder() {
        let b = bench("https://admin.example.com", None);
        let folder = b.lib.add_folder(None, "Web".into()).unwrap();
        b.lib.set_property(folder.clone(), "web_autofill".into(), Some("true".into())).unwrap();
        let id = b.lib.add_connection(Some(folder), "Inner".into(), "web".into(), "https://inner.example".into(), None, None).unwrap();
        assert!(web_autofill_offered(b.lib.clone(), id).unwrap());
    }
}
