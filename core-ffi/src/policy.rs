//! The effective security policy: the core default tightened by the administrator's managed
//! policy file (core `Policy::load_managed` + `with_managed`), loaded once per process. A managed
//! file that exists but is unreadable, wrongly owned or invalid fails closed: every connect is
//! refused with the reason until it is fixed. Frontends only read it (`policy_state`).
use std::sync::OnceLock;

use bastion_core::model::Protocol;
use bastion_core::policy::{managed_policy_path, Policy};
use bastion_core::CoreError;

use crate::{FfiError, FfiResult};

struct Loaded {
    policy: Result<Policy, String>,
    /// The administrator's file alone (None: no file, or it is broken), for limits that apply
    /// only when managed, such as the whole-vault inactivity lock (TM-03).
    managed: Option<Policy>,
    source: Option<String>,
}

fn loaded() -> &'static Loaded {
    static L: OnceLock<Loaded> = OnceLock::new();
    L.get_or_init(|| {
        // UI test runs only: a policy file in the test directory, without the root-owner check.
        let test = std::env::var_os("BASTION_UI_SCRIPT").and(std::env::var_os("BASTION_UI_POLICY")).map(std::path::PathBuf::from);
        let (path, managed) = match test {
            Some(p) => {
                let m = std::fs::read(&p).map_err(CoreError::from).and_then(|b| Policy::parse_managed(&b)).map(Some);
                (p, m)
            }
            None => {
                let p = managed_policy_path();
                let m = Policy::load_managed(&p);
                (p, m)
            }
        };
        let source = Some(path.display().to_string());
        match managed {
            Ok(None) => Loaded { policy: Ok(Policy::default()), managed: None, source: None },
            Ok(Some(m)) => Loaded { policy: Ok(Policy::default().with_managed(&m)), managed: Some(m), source },
            Err(e) => Loaded {
                managed: None,
                policy: Err(format!("the managed policy at {} cannot be used ({e}); connections are blocked until it is fixed", path.display())),
                source,
            },
        }
    })
}

/// The policy connects use; an error means the managed policy is broken (fail closed).
pub(crate) fn effective() -> bastion_core::Result<Policy> {
    loaded().policy.clone().map_err(CoreError::PolicyDenied)
}

/// Idle minutes while the managed policy cannot be read: lock quickly until it is fixed (F08).
pub(crate) const BROKEN_POLICY_AUTO_LOCK_MINUTES: u32 = 1;

/// The policy for a document security decision: same fail-closed rule as connects (F08).
pub(crate) fn effective_for_documents() -> bastion_core::Result<Policy> {
    effective()
}

/// The managed inactivity limit for the whole vault and providers, in seconds: the
/// administrator's `inactivity_lock_secs`, or the short fail-closed limit while the managed
/// policy is broken (F08). `None`: only the user's own setting applies.
pub(crate) fn managed_inactivity_secs() -> Option<u64> {
    let l = loaded();
    match &l.policy {
        Err(_) => Some(u64::from(BROKEN_POLICY_AUTO_LOCK_MINUTES) * 60),
        Ok(_) => l.managed.as_ref().and_then(|m| m.inactivity_lock_secs),
    }
}

/// Display-only uses (menus, lease limits) where a broken policy already blocks every connect.
pub(crate) fn effective_or_default() -> Policy {
    loaded().policy.clone().unwrap_or_default()
}

fn protocol_name(p: &Protocol) -> String {
    p.as_str().to_string()
}

#[derive(uniffi::Record)]
pub struct PolicyView {
    /// Where an administrator places the managed policy on this platform.
    pub managed_path: String,
    /// The file in force, if any.
    pub source: Option<String>,
    /// Why the managed policy cannot be used (every connect is refused while set).
    pub error: Option<String>,
    pub denied_protocols: Vec<String>,
    pub allowed_legacy: Vec<String>,
    pub forbid_legacy: bool,
    pub allow_cross_customer_credentials: bool,
    pub bulk_confirm_threshold: u32,
    pub inactivity_lock_secs: Option<u64>,
    pub allow_session_recording: bool,
    pub lock_credentials_on_os_lock: bool,
    pub forbid_osc52_write: bool,
    pub forbid_web_autofill: bool,
    pub require_rdp_nla: bool,
    pub forbid_weak_ssh_algorithms: bool,
    /// Longest document auto-lock in minutes, when the policy caps it.
    pub document_auto_lock_max_minutes: Option<u32>,
    /// Documents unlock with their password only.
    pub password_only_document_unlock: bool,
    /// Longest reuse of a remembered login in minutes, when the policy limits it (0: no limit).
    pub session_login_reuse_minutes: u32,
}

/// What Settings shows about the policy in force (read-only; nothing here can change it).
#[uniffi::export]
pub fn policy_state() -> PolicyView {
    let l = loaded();
    let p = l.policy.clone().unwrap_or_default();
    PolicyView {
        managed_path: managed_policy_path().display().to_string(),
        source: l.source.clone(),
        error: l.policy.as_ref().err().cloned(),
        denied_protocols: p.denied_protocols.iter().map(protocol_name).collect(),
        allowed_legacy: p.allowed_legacy.iter().map(protocol_name).collect(),
        forbid_legacy: p.forbid_legacy,
        allow_cross_customer_credentials: p.allow_cross_customer_credentials,
        bulk_confirm_threshold: u32::try_from(p.bulk_confirm_threshold).unwrap_or(u32::MAX),
        inactivity_lock_secs: p.inactivity_lock_secs,
        allow_session_recording: p.allow_session_recording,
        lock_credentials_on_os_lock: p.lock_credentials_on_os_lock,
        forbid_osc52_write: p.forbid_osc52_write,
        forbid_web_autofill: p.forbid_web_autofill,
        require_rdp_nla: p.require_rdp_nla,
        forbid_weak_ssh_algorithms: p.forbid_weak_ssh_algorithms,
        document_auto_lock_max_minutes: p.document_auto_lock_max_minutes,
        password_only_document_unlock: p.password_only_document_unlock,
        session_login_reuse_minutes: p.session_login_reuse_minutes,
    }
}

/// Reuse minutes while the managed policy cannot be read: the shortest limit until it is fixed.
const BROKEN_POLICY_LOGIN_REUSE_MINUTES: u32 = 1;

/// The reuse time in force for a remembered login, in minutes (0 = until Lock or quit):
/// `user_minutes` (the `security.session-login-reuse-minutes` value) under the managed
/// `session_login_reuse_minutes`; the smaller non-zero one wins. Pass the result to
/// `remembered_login_usable`.
#[uniffi::export]
pub fn session_login_reuse_minutes(user_minutes: u32) -> u32 {
    session_login_reuse_minutes_under(user_minutes, &effective())
}

/// A broken managed policy never means "no limit": it means the shortest one.
fn session_login_reuse_minutes_under(user_minutes: u32, policy: &bastion_core::Result<Policy>) -> u32 {
    let max = policy.as_ref().map_or(BROKEN_POLICY_LOGIN_REUSE_MINUTES, |p| p.session_login_reuse_minutes);
    bastion_core::policy::effective_session_login_reuse_minutes(user_minutes, max)
}

/// Whether the app may still reuse the login it remembers for a connection: `remembered_at` is
/// the time of the last successful sign-in with it and `now` the current time (seconds, same
/// clock), `minutes` the value of `session_login_reuse_minutes`. False: forget the remembered
/// login and resolve the connection's logins again. Takes no secret and keeps nothing.
#[uniffi::export]
pub fn remembered_login_usable(remembered_at: u64, now: u64, minutes: u32) -> bool {
    bastion_core::policy::remembered_login_usable(remembered_at, now, minutes)
}

/// Protocol gate for connect paths that have no core orchestrator (RDP, VNC, web): an error is
/// the reason the protocol is refused.
#[uniffi::export]
pub fn policy_check_protocol(protocol: String) -> FfiResult<()> {
    let p: Protocol = serde_json::from_value(serde_json::Value::String(protocol.to_lowercase()))
        .map_err(|_| FfiError::failed(format!("unknown protocol `{protocol}`")))?;
    Ok(effective()?.check_protocol(p)?)
}

/// Whether credentials lock when the OS session locks, for the `security.lock-on-screen-lock`
/// value: the user's choice OR the managed `lock_credentials_on_os_lock`, and yes while the
/// managed policy cannot be read (TM-04).
#[uniffi::export]
pub fn lock_on_os_lock_due(user_value: String) -> bool {
    lock_on_os_lock_due_under(&user_value, &effective())
}

fn lock_on_os_lock_due_under(user_value: &str, policy: &bastion_core::Result<Policy>) -> bool {
    bastion_core::policy::lock_on_os_lock(user_value != "false", policy)
}

#[cfg(test)]
mod os_lock_tests {
    use super::*;

    /// TM-04: the setting value as the Mac handler passes it, under every policy state.
    #[test]
    fn forced_or_broken_policy_overrides_the_user_setting() {
        let forced = Ok(Policy { lock_credentials_on_os_lock: true, ..Policy::default() });
        let broken = Err(CoreError::PolicyDenied("broken".into()));
        for value in ["true", "false", ""] {
            assert!(lock_on_os_lock_due_under(value, &forced), "{value}");
            assert!(lock_on_os_lock_due_under(value, &broken), "{value}");
        }
        assert!(!lock_on_os_lock_due_under("false", &Ok(Policy::default())));
        assert!(lock_on_os_lock_due_under("true", &Ok(Policy::default())));
    }
}

#[cfg(test)]
mod session_login_tests {
    use super::*;

    fn managed(minutes: u32) -> bastion_core::Result<Policy> {
        Ok(Policy { session_login_reuse_minutes: minutes, ..Policy::default() })
    }

    /// A1-CORE-02: the user's value under the policy in force, in every policy state.
    #[test]
    fn session_login_reuse_is_the_smaller_non_zero_value() {
        assert_eq!(session_login_reuse_minutes_under(0, &managed(0)), 0, "default: until Lock or quit");
        assert_eq!(session_login_reuse_minutes_under(30, &managed(0)), 30);
        assert_eq!(session_login_reuse_minutes_under(60, &managed(10)), 10, "managed maximum wins");
        assert_eq!(session_login_reuse_minutes_under(0, &managed(10)), 10, "user 0 under a maximum of 10");
        assert_eq!(session_login_reuse_minutes_under(5, &managed(10)), 5);
    }

    /// A managed policy that cannot be read gives the shortest limit, never "no limit".
    #[test]
    fn a_broken_policy_gives_the_shortest_session_login_reuse() {
        let broken = Err(CoreError::PolicyDenied("broken".into()));
        for user in [0, 1, 5, 1440, u32::MAX] {
            assert_eq!(session_login_reuse_minutes_under(user, &broken), BROKEN_POLICY_LOGIN_REUSE_MINUTES, "{user}");
        }
    }

    /// The exported helper is the core rule: usable below the limit, refused at it, refused
    /// when the clock went backwards, always usable with no limit.
    #[test]
    fn remembered_login_usable_follows_the_core_rule() {
        let at = 1_700_000_000;
        assert!(remembered_login_usable(at, at + 4 * 60 + 59, 5));
        assert!(!remembered_login_usable(at, at + 5 * 60, 5));
        assert!(!remembered_login_usable(at, at - 1, 5));
        assert!(remembered_login_usable(at, at + 1_000_000, 0));
    }

    /// The policy view the apps read carries the value; in this process there is no managed
    /// policy, so it is 0 and the user's own value is what applies.
    #[test]
    fn policy_view_carries_the_session_login_reuse_value() {
        if std::env::var_os("BASTION_UI_POLICY").is_some() || managed_policy_path().exists() {
            return;
        }
        assert_eq!(policy_state().session_login_reuse_minutes, 0);
        assert_eq!(session_login_reuse_minutes(0), 0);
        assert_eq!(session_login_reuse_minutes(20), 20);
    }
}
