//! Test Connection for the connection dialog (core `probe`): runs on the I/O runtime, never on
//! the caller's thread, and can be cancelled. The login is the dialog's unsaved one, held in
//! memory for this test only; a saved (vault) login is read only for a saved connection that
//! may use it without asking (A1-CORE-01-FU3). One audit line per test: host, port and result, no secrets.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bastion_core::audit::{AuditLog, Category, Outcome};
use bastion_core::logins::{normalize_host, LoginPurpose};
use bastion_core::model::Protocol;
use bastion_core::probe::{self, ProbeHop, ProbeReport, ProbeRequest, StepStatus};
use bastion_core::ssh::SshAuth;
use bastion_core::vault::{CredentialKind, Secret};

use crate::terminal::{SessionManager, SshLogin, RUNTIME};
use crate::{parse_id, CredentialVault, FfiError, FfiResult, Library, VaultwardenSession};

/// Per-step connect and read limit (owner spec: 3 s).
const STEP_TIMEOUT: Duration = Duration::from_secs(3);

/// What the dialog holds right now (not what is saved).
#[derive(uniffi::Record)]
pub struct ProbeInput {
    /// `ssh`, `sftp`, `scp`, `rdp`, `vnc`, …
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// `None` when no credential is entered: the test stops before the login.
    pub login: Option<SshLogin>,
    pub jumps: Vec<ProbeJump>,
    /// A private key pasted into the dialog and not saved yet; replaces `login` when set.
    pub pasted_key: Option<String>,
    pub pasted_key_passphrase: Option<String>,
    /// The saved connection the dialog edits; `None` for an entry that is not saved yet.
    pub connection_id: Option<String>,
    /// The host-key fingerprint the user confirmed for this test, taken from an earlier report's
    /// `needs_host_key_confirmation`. Used for this test only; nothing is stored.
    #[uniffi(default = None)]
    pub trusted_fingerprint: Option<String>,
}

/// A jump host with its own login.
#[derive(uniffi::Record)]
pub struct ProbeJump {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub login: SshLogin,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct ProbeStepView {
    /// `dns`, `tcp`, `handshake`, `host_key`, `jump_host`, `login`.
    pub kind: String,
    /// `ok`, `warn`, `failed`, `skipped`.
    pub status: String,
    pub detail: String,
    pub fix: Option<String>,
    pub millis: u64,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct ProbeReportView {
    pub ok: bool,
    pub cancelled: bool,
    pub steps: Vec<ProbeStepView>,
    /// The target's host key is unknown and the login would send a password, so the login was
    /// not tried. Show this SHA-256 fingerprint; if the user confirms it, test again with it in
    /// `ProbeInput::trusted_fingerprint`.
    pub needs_host_key_confirmation: Option<String>,
    /// Why the target's host-key step failed: `changed` (a known host showed another key) or
    /// `known_hosts_unreadable`. `None` when that step did not fail.
    pub host_key_failure: Option<String>,
}

/// A running test. `wait` blocks until it ends (call it off the main thread); `cancel` stops it
/// at once and `wait` then returns a report with `cancelled` set.
#[derive(uniffi::Object)]
pub struct ProbeTask {
    task: Mutex<Option<tokio::task::JoinHandle<ProbeReport>>>,
    abort: tokio::task::AbortHandle,
    done: Mutex<Option<ProbeReportView>>,
}

#[uniffi::export]
impl ProbeTask {
    pub fn wait(&self) -> ProbeReportView {
        let mut done = self.done.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(r) = done.clone() {
            return r;
        }
        let handle = self.task.lock().unwrap_or_else(|e| e.into_inner()).take();
        let report = match handle.map(|h| RUNTIME.block_on(h)) {
            Some(Ok(r)) => view(&r),
            _ => ProbeReportView { ok: false, cancelled: true, steps: Vec::new(), needs_host_key_confirmation: None, host_key_failure: None },
        };
        *done = Some(report.clone());
        report
    }

    pub fn cancel(&self) {
        self.abort.abort();
    }
}

#[uniffi::export]
impl SessionManager {
    /// Start testing what the dialog holds. A protocol the policy blocks fails here, before any
    /// network use.
    ///
    /// A saved (vault) login, for the target or a jump host, is read only for a saved
    /// connection (`library` and `input.connection_id`) that may use it without asking: its
    /// own inline secret, or its own or inherited login (A1-CORE-01-FU3). Every login is
    /// checked before any is read. Typed, key-file, agent, Vaultwarden and provider logins are
    /// not saved credentials and are not checked.
    pub fn test_connection(&self, library: Option<Arc<Library>>, input: ProbeInput) -> FfiResult<Arc<ProbeTask>> {
        let (data_dir, vault, vw) = self.probe_context();
        // A type this app does not know (the row of an entry kept from a newer Bastion or a
        // plugin) gets the core's fixed text, not a parse error.
        let protocol = Protocol::for_request(&input.protocol)?;
        crate::policy::effective()?.check_protocol(protocol)?;
        // A pasted key replaces the target's login, which is then never read.
        let pasted = input.pasted_key.as_deref().is_some_and(|k| !k.trim().is_empty());
        let target_login = input.login.as_ref().filter(|_| !pasted);
        let saved = SavedEntry { library: library.as_deref(), connection_id: input.connection_id.as_deref(), vault: vault.as_deref() };
        let mut any_saved = false;
        for login in target_login.into_iter().chain(input.jumps.iter().map(|j| &j.login)) {
            any_saved |= saved.check(login)?;
        }
        // A saved secret goes only where the saved connection goes: the dialog may hold an
        // edited host, port or jump chain, which gets a typed password instead.
        if any_saved {
            saved.check_route(&data_dir, protocol, &input.host, input.port, &input.username, &input.jumps)?;
        }
        let auth = match input.pasted_key.filter(|k| !k.trim().is_empty()) {
            Some(pem) => Some(SshAuth::KeyPem { pem: Secret::new(pem), passphrase: input.pasted_key_passphrase.filter(|p| !p.is_empty()).map(Secret::new) }),
            None => input.login.map(|l| auth_for(l, vault.as_deref(), vw.as_deref())).transpose()?,
        };
        let jumps = input
            .jumps
            .into_iter()
            .map(|j| Ok(ProbeHop { host: j.host, port: j.port, username: j.username, auth: auth_for(j.login, vault.as_deref(), vw.as_deref())? }))
            .collect::<FfiResult<Vec<_>>>()?;
        let (host, port) = (input.host.clone(), input.port);
        let req = ProbeRequest { protocol, host: input.host, port, username: input.username, auth, jumps, known_hosts: data_dir.join("known_hosts"), timeout: STEP_TIMEOUT, trusted_fingerprint: input.trusted_fingerprint.filter(|f| !f.is_empty()) };
        let task = RUNTIME.spawn(async move {
            let report = probe::run(req).await;
            audit(&data_dir, &host, port, &report);
            report
        });
        let abort = task.abort_handle();
        Ok(Arc::new(ProbeTask { task: Mutex::new(Some(task)), abort, done: Mutex::new(None) }))
    }
}

/// A saved login could not be tested because the entry is not saved yet (or the app passed no
/// library): there is no connection to ask the login rule about.
pub(crate) const NEEDS_SAVED_CONNECTION: &str = "save the connection before testing it with a saved login, or type the password";

/// A saved login could not be tested because the dialog's host, port or jump hosts are not the
/// saved connection's (edited, or not yet saved). Fixed text: no host or credential name.
pub(crate) const ROUTE_DIFFERS: &str = "the host, port or jump hosts differ from the saved connection: save the changes, or type the password to test them";

/// The saved connection a test runs for, if any, and the open vault.
struct SavedEntry<'a> {
    library: Option<&'a Library>,
    connection_id: Option<&'a str>,
    vault: Option<&'a CredentialVault>,
}

impl SavedEntry<'_> {
    /// Refuse a saved (vault) login this connection may not use without asking. Reads no
    /// secret. `true` when the login is a saved one (and allowed).
    fn check(&self, login: &SshLogin) -> FfiResult<bool> {
        let SshLogin::Vault { credential_id } = login else { return Ok(false) };
        let vault = self.vault.ok_or_else(|| FfiError::failed("the credential vault is not open".into()))?;
        let (Some(library), Some(connection_id)) = (self.library, self.connection_id) else {
            return Err(FfiError::failed(NEEDS_SAVED_CONNECTION.into()));
        };
        if !vault.may_use_unasked(library, parse_id(connection_id)?, parse_id(credential_id)?, LoginPurpose::Any)? {
            return Err(FfiError::failed(crate::credtree::NOT_OFFERED.into()));
        }
        Ok(true)
    }

    /// Refuse unless the dialled host, port and jump chain (each hop's host, port and user) are the saved connection's, as a
    /// real connect resolves them (SSH-config workflow, then the gateway as the first hop).
    /// Called only after `check` allowed a saved login, so the library and id are present.
    fn check_route(&self, data_dir: &std::path::Path, protocol: Protocol, host: &str, port: u16, target_user: &str, jumps: &[ProbeJump]) -> FfiResult<()> {
        let (Some(library), Some(connection_id)) = (self.library, self.connection_id) else {
            return Err(FfiError::failed(NEEDS_SAVED_CONNECTION.into()));
        };
        let mut conn = library.resolve(parse_id(connection_id)?)?;
        let mut username = String::new();
        let saved_jumps = crate::workflow::prepare_connection(data_dir, library, &mut conn, &mut username).map_err(|_| FfiError::failed(ROUTE_DIFFERS.into()))?;
        let same = |h: &str, p: u16, saved_host: &str, saved_port: Option<u16>, fallback: u16| normalize_host(h) == normalize_host(saved_host) && p == saved_port.unwrap_or(fallback);
        let target_same = same(host, port, &conn.host, conn.settings.port, protocol.default_port().unwrap_or(22));
        // A hop without a user (saved or sent) logs in as the target's user, as a real connect does.
        let hop_user = |saved: &str, target: &str| if saved.trim().is_empty() { target.trim().to_string() } else { saved.trim().to_string() };
        let hops_same = jumps.len() == saved_jumps.len() && jumps.iter().zip(&saved_jumps).all(|(j, s)| same(&j.host, j.port, &s.conn.host, s.conn.settings.port, 22) && hop_user(&j.username, target_user) == hop_user(&s.username, target_user));
        if target_same && hops_same {
            Ok(())
        } else {
            Err(FfiError::failed(ROUTE_DIFFERS.into()))
        }
    }
}

/// The secret for a login, in memory only. Vault and Vaultwarden secrets are read inside the core.
fn auth_for(login: SshLogin, vault: Option<&CredentialVault>, vw: Option<&VaultwardenSession>) -> FfiResult<SshAuth> {
    Ok(match login {
        SshLogin::Password { password } => SshAuth::Password(Secret::new(password)),
        SshLogin::PasswordAndCode { password, code } => SshAuth::PasswordAndCode { password: Secret::new(password), code: Secret::new(code) },
        SshLogin::KeyFile { path, passphrase } => SshAuth::KeyFile { path: PathBuf::from(path), passphrase: passphrase.filter(|p| !p.is_empty()).map(Secret::new) },
        SshLogin::Agent => SshAuth::Agent { socket: None },
        SshLogin::Vault { credential_id } => {
            let vault = vault.ok_or_else(|| FfiError::failed("the credential vault is not open".into()))?;
            match vault.secret_for(&credential_id)?.0 {
                CredentialKind::Password { password, .. } => SshAuth::Password(password),
                CredentialKind::SshKey { private_key, .. } => SshAuth::KeyPem { pem: private_key, passphrase: None },
            }
        }
        SshLogin::Vaultwarden { item_id } => {
            let vw = vw.ok_or_else(|| FfiError::failed("Vaultwarden is not set up".into()))?;
            SshAuth::Password(vw.secret_for(&item_id)?.0)
        }
        SshLogin::Provider { reference } => SshAuth::Password(crate::providers::resolve(&reference)?),
    })
}

fn audit(data_dir: &std::path::Path, host: &str, port: u16, report: &ProbeReport) {
    let outcome = report.audit_outcome();
    let details = BTreeMap::from([("port".to_string(), port.to_string()), ("result".to_string(), report.summary())]);
    if let Err(e) = AuditLog::open(data_dir.join("audit.jsonl")).and_then(|mut log| log.record(Category::Connection, "connection.test", Some(host), outcome, details)) {
        eprintln!("bastion: audit log write failed for connection.test: {e}");
    }
}

pub(crate) fn view(r: &ProbeReport) -> ProbeReportView {
    let name = |v: Result<serde_json::Value, _>| v.ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
    ProbeReportView {
        ok: r.ok,
        cancelled: false,
        needs_host_key_confirmation: r.needs_host_key_confirmation.clone(),
        host_key_failure: r.host_key_failure.map(|k| name(serde_json::to_value(k))),
        steps: r
            .steps
            .iter()
            .map(|s| ProbeStepView {
                kind: name(serde_json::to_value(s.kind)),
                status: match s.status {
                    StepStatus::Ok => "ok",
                    StepStatus::Warn => "warn",
                    StepStatus::Failed => "failed",
                    StepStatus::Skipped => "skipped",
                }
                .into(),
                detail: s.detail.clone(),
                fix: s.fix.clone(),
                millis: s.millis,
            })
            .collect(),
    }
}

#[cfg(test)]
#[path = "a1_fu3_tests.rs"]
mod a1_fu3_tests;

#[cfg(test)]
#[path = "a1_nm01_jump_tests.rs"]
mod a1_nm01_jump_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use bastion_core::probe::{ProbeStep, StepKind};

    #[test]
    fn the_view_carries_the_fingerprint_waiting_for_confirmation() {
        let step = ProbeStep { kind: StepKind::Login, status: StepStatus::Skipped, detail: "Not tested: confirm the host key first".into(), fix: None, millis: 0 };
        let report = ProbeReport { ok: true, steps: vec![step], needs_host_key_confirmation: Some("SHA256:abc".into()), host_key_failure: None };
        let v = view(&report);
        assert_eq!(v.needs_host_key_confirmation.as_deref(), Some("SHA256:abc"));
        assert_eq!((v.steps[0].kind.as_str(), v.steps[0].status.as_str()), ("login", "skipped"));
        let done = ProbeReport { ok: true, steps: Vec::new(), needs_host_key_confirmation: None, host_key_failure: None };
        assert_eq!(view(&done).needs_host_key_confirmation, None);
        assert_eq!(view(&done).host_key_failure, None);
    }

    #[test]
    fn the_view_names_why_the_host_key_step_failed() {
        use bastion_core::probe::HostKeyFailure;
        for (kind, text) in [(HostKeyFailure::Changed, "changed"), (HostKeyFailure::KnownHostsUnreadable, "known_hosts_unreadable")] {
            let report = ProbeReport { ok: false, steps: Vec::new(), needs_host_key_confirmation: None, host_key_failure: Some(kind) };
            assert_eq!(view(&report).host_key_failure.as_deref(), Some(text));
        }
    }
}
