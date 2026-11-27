//! Security regression and negative tests. Each finding from the 2026-11-01 review has a test.
use std::collections::BTreeMap;
use std::time::Duration;

use bastion_core::audit::{self, AuditLog, Category, Outcome};
use bastion_core::model::{Connection, Document, Protocol};
use bastion_core::policy::{Action, Classification, Environment, Policy};
use bastion_core::session::{Lifecycle, ReconnectPolicy, SessionState};
use bastion_core::store::Store;
use bastion_core::vars::Variables;
use bastion_core::vault::Vault;
use bastion_core::CoreError;

// F1: environment exfiltration through task substitution.
#[test]
fn f1_env_variables_require_allowlist() {
    std::env::set_var("BASTION_TEST_CLOUD_SECRET", "AKIA-very-secret");
    let mut v = Variables::default();
    assert!(v.substitute("echo $ENV:BASTION_TEST_CLOUD_SECRET$", false).is_err());
    v.allow_env("BASTION_TEST_CLOUD_SECRET");
    assert_eq!(v.substitute("$ENV:BASTION_TEST_CLOUD_SECRET$", false).unwrap(), "AKIA-very-secret");
}

// F2: atomic save must not follow a planted file at the old predictable temp name, and
// backups must be private.
#[cfg(unix)]
#[test]
fn f2_save_ignores_planted_temp_file_and_backups_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("d.json");
    let decoy = dir.path().join("victim");
    std::fs::write(&decoy, "untouched").unwrap();
    std::os::unix::fs::symlink(&decoy, dir.path().join("d.tmp")).unwrap();
    let store = Store::new(&path);
    let v1 = store.save(&Document::new("D")).unwrap();
    store.save(&v1).unwrap();
    assert_eq!(std::fs::read_to_string(&decoy).unwrap(), "untouched");
    let mode = std::fs::metadata(store.backups_dir()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let leftovers = std::fs::read_dir(dir.path()).unwrap().filter(|e| {
        let n = e.as_ref().unwrap().file_name().to_string_lossy().to_string();
        n.ends_with(".tmp") && n != "d.tmp"
    });
    assert_eq!(leftovers.count(), 0, "no temp files may be left behind");
}

// F3: crafted vault with hostile KDF parameters is rejected before any expensive work.
#[test]
fn f3_vault_rejects_out_of_range_kdf_parameters() {
    let sealed = Vault::default().seal("pw").unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
    for (field, value) in [("m_cost", u32::MAX), ("m_cost", 8), ("t_cost", 1000), ("t_cost", 1)] {
        let mut j = json.clone();
        j[field] = value.into();
        let started = std::time::Instant::now();
        let err = Vault::open(&serde_json::to_vec(&j).unwrap(), "pw").err().unwrap();
        assert!(matches!(err, CoreError::Corrupt(_)), "{field}={value}: {err:?}");
        assert!(started.elapsed() < Duration::from_millis(200));
    }
    json["ciphertext"][0] = (json["ciphertext"][0].as_u64().unwrap() ^ 1).into();
    assert!(matches!(Vault::open(&serde_json::to_vec(&json).unwrap(), "pw"), Err(CoreError::VaultAuth)), "tampered ciphertext");
}

#[test]
fn legacy_protocols_are_disabled_by_default() {
    let p = Policy::default();
    assert!(matches!(p.check_protocol(Protocol::Telnet), Err(CoreError::PolicyDenied(_))));
    assert!(matches!(p.check_protocol(Protocol::Ftp), Err(CoreError::PolicyDenied(_))));
    assert!(p.check_protocol(Protocol::Ftps).is_ok());
    assert!(p.check_protocol(Protocol::Ssh).is_ok());
    let mut accepted = Policy::default();
    accepted.allowed_legacy.insert(Protocol::Telnet);
    assert!(accepted.check_protocol(Protocol::Telnet).is_ok());
}

#[test]
fn managed_policy_can_only_tighten() {
    let mut user = Policy::default();
    user.allowed_legacy.insert(Protocol::Telnet);
    user.allow_cross_customer_credentials = true;
    user.inactivity_lock_secs = None;
    user.allow_session_recording = true;
    let managed = Policy { forbid_legacy: true, inactivity_lock_secs: Some(300), ..Policy::default() };
    let eff = user.with_managed(&managed);
    assert!(eff.check_protocol(Protocol::Telnet).is_err());
    assert!(!eff.allow_cross_customer_credentials);
    assert_eq!(eff.inactivity_lock_secs, Some(300));
    assert!(!eff.allow_session_recording);
}

#[test]
fn managed_policy_can_force_os_lock_osc52_and_nla_but_never_relax_them() {
    let user = Policy::default();
    assert!(!user.lock_credentials_on_os_lock && !user.forbid_osc52_write && !user.require_rdp_nla);
    let managed = Policy::parse_managed(br#"{"lock_credentials_on_os_lock": true, "forbid_osc52_write": true, "require_rdp_nla": true}"#).unwrap();
    let eff = user.with_managed(&managed);
    assert!(eff.lock_credentials_on_os_lock && eff.forbid_osc52_write && eff.require_rdp_nla);
    // A managed file that leaves them out keeps whatever is stricter.
    let strict_user = Policy { lock_credentials_on_os_lock: true, forbid_osc52_write: true, require_rdp_nla: true, ..Policy::default() };
    let eff = strict_user.with_managed(&Policy::parse_managed(b"{}").unwrap());
    assert!(eff.lock_credentials_on_os_lock && eff.forbid_osc52_write && eff.require_rdp_nla);
}

fn conn(customer: Option<&str>, env: Environment) -> Connection {
    let mut c = Connection::new("x", Protocol::Ssh, "h");
    c.classification = Classification { environment: env, customer: customer.map(str::to_string), ..Default::default() };
    c
}

#[test]
fn credentials_do_not_cross_customer_boundaries() {
    let p = Policy::default();
    assert!(p.check_credential_scope(Some("acme"), &conn(Some("acme"), Environment::Production)).is_ok());
    assert!(matches!(p.check_credential_scope(Some("acme"), &conn(Some("globex"), Environment::Test)), Err(CoreError::PolicyDenied(_))));
    assert!(p.check_credential_scope(Some("acme"), &conn(None, Environment::Test)).is_err());
    assert!(p.check_credential_scope(None, &conn(Some("globex"), Environment::Test)).is_ok(), "unscoped personal credentials stay usable");
}

#[test]
fn destructive_and_sensitive_actions_need_confirmation() {
    let p = Policy::default();
    let prod = Classification { environment: Environment::Production, ..Default::default() };
    let dev = Classification { environment: Environment::Development, ..Default::default() };
    for a in [Action::ForcePowerOff, Action::DeleteVm, Action::SnapshotRevert, Action::StorageDelete] {
        assert!(p.requires_confirmation(a, &dev), "{a:?}");
    }
    assert!(p.requires_confirmation(Action::RunCommand, &prod));
    assert!(!p.requires_confirmation(Action::RunCommand, &dev));
    assert!(p.requires_confirmation(Action::BulkCommand { hosts: 5 }, &dev));
    assert!(!p.requires_confirmation(Action::Connect, &prod), "routine low-risk actions are not interrupted");
}

#[test]
fn audit_log_redacts_secrets_and_detects_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&path).unwrap();
    let mut d = BTreeMap::new();
    d.insert("api_token".to_string(), "PVEAPIToken=root@pam!x=zq-tok-value".to_string());
    d.insert("Password".to_string(), "hunter2".to_string());
    d.insert("host".to_string(), "pve1".to_string());
    log.record(Category::HypervisorAction, "vm.stop", Some("pve1/101"), Outcome::Success, d).unwrap();
    log.record(Category::Connection, "ssh.connect", Some("web-1"), Outcome::Failure, BTreeMap::new()).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("hunter2") && !text.contains("zq-tok-value"), "{text}");
    assert!(text.contains("pve1"));
    audit::verify(&path).unwrap();

    // Reopening continues the chain.
    AuditLog::open(&path).unwrap().record(Category::AppLock, "unlock", None, Outcome::Success, BTreeMap::new()).unwrap();
    audit::verify(&path).unwrap();

    let lines: Vec<&str> = text.lines().collect();
    std::fs::write(&path, format!("{}\n", lines[1])).unwrap();
    assert!(matches!(audit::verify(&path), Err(CoreError::Corrupt(_))), "deleting a record must be detected");
    std::fs::write(&path, text.replace("vm.stop", "vm.start")).unwrap();
    assert!(audit::verify(&path).is_err(), "editing a record must be detected");
    assert!(AuditLog::open(&path).is_err(), "a broken chain must not be silently extended");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p2 = dir.path().join("a2.jsonl");
        AuditLog::open(&p2).unwrap().record(Category::AppLock, "lock", None, Outcome::Success, BTreeMap::new()).unwrap();
        assert_eq!(std::fs::metadata(&p2).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn session_lifecycle_rejects_illegal_transitions() {
    let mut s = Lifecycle::default();
    assert!(s.transition(SessionState::Connected).is_err(), "cannot skip authentication");
    for st in [SessionState::Connecting, SessionState::Authenticating, SessionState::Connected,
               SessionState::Reconnecting { attempt: 1 }, SessionState::Authenticating, SessionState::Connected,
               SessionState::Disconnecting, SessionState::Closed] {
        s.transition(st).unwrap();
    }
    assert_eq!(s.history().len(), 9);
    assert!(s.transition(SessionState::Connected).is_err());
}

#[test]
fn reconnect_backoff_is_bounded_and_never_retries_auth_failures() {
    let p = ReconnectPolicy { enabled: true, max_attempts: 6, initial: Duration::from_secs(1), max_delay: Duration::from_secs(10) };
    let delays: Vec<_> = (1..=7).map(|a| p.delay(a, false)).collect();
    assert_eq!(delays[0], Some(Duration::from_secs(1)));
    assert_eq!(delays[3], Some(Duration::from_secs(8)));
    assert_eq!(delays[4], Some(Duration::from_secs(10)));
    assert_eq!(delays[6], None);
    assert_eq!(p.delay(1, true), None);
    assert_eq!(ReconnectPolicy::default().delay(1, false), None, "a bare policy stays off; connections turn it on from their settings");
}

#[test]
fn managed_policy_parses_strictly_and_only_tightens() {
    use bastion_core::policy::Policy;
    let managed = Policy::parse_managed(br#"{"denied_protocols":["rdp"],"forbid_legacy":true,"bulk_confirm_threshold":1}"#).unwrap();
    assert!(managed.confirm_sensitive_writes, "missing fields keep their defaults");
    let mut user = Policy::default();
    user.allowed_legacy.insert(bastion_core::model::Protocol::Telnet);
    let eff = user.with_managed(&managed);
    assert!(eff.check_protocol(bastion_core::model::Protocol::Rdp).is_err());
    assert!(eff.check_protocol(bastion_core::model::Protocol::Telnet).is_err());
    assert!(eff.check_protocol(bastion_core::model::Protocol::Ssh).is_ok());
    assert_eq!(eff.bulk_confirm_threshold, 1);
    assert!(Policy::parse_managed(br#"{"denied_protocol":["rdp"]}"#).is_err(), "a misspelt key is an error, not ignored");
    assert!(Policy::parse_managed(&vec![b' '; 70 * 1024]).is_err());
}

#[cfg(unix)]
#[test]
fn managed_policy_file_must_be_root_owned() {
    use bastion_core::policy::Policy;
    let dir = std::env::temp_dir().join(format!("bastion-policy-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("policy.json");
    assert_eq!(Policy::load_managed(&path).unwrap(), None);
    std::fs::write(&path, br#"{"denied_protocols":["rdp"]}"#).unwrap();
    // Written by this (non-root) test user: refused, so callers fail closed.
    let r = Policy::load_managed(&path);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(r.is_err());
}

#[cfg(windows)]
#[test]
fn managed_policy_file_must_be_admin_controlled() {
    use bastion_core::policy::Policy;
    use std::process::Command;
    let dir = std::env::temp_dir().join(format!("bastion-policy-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("policy.json");
    assert_eq!(Policy::load_managed(&path).unwrap(), None);
    std::fs::write(&path, br#"{"denied_protocols":["rdp"]}"#).unwrap();
    // Inherits the user's temp-folder DACL (user has full control): refused.
    let r = Policy::load_managed(&path);
    assert!(r.is_err(), "user-writable policy must be refused");

    // Lock file and folder down to SYSTEM + Administrators (needs an elevated admin; skipped otherwise).
    let lock = |p: &std::path::Path| {
        let run = |args: &[&str]| Command::new("icacls").arg(p).args(args).status().map(|s| s.success()).unwrap_or(false);
        // icacls takes one operation per call.
        run(&["/setowner", "*S-1-5-32-544", "/q"]) && run(&["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "/q"])
    };
    if lock(&dir) && lock(&path) {
        let ok = Policy::load_managed(&path);
        // A user write grant added back must be refused again.
        let user = bastion_core::winacl::current_user_sid().unwrap();
        Command::new("icacls").arg(&path).args(["/grant", &format!("*{user}:W"), "/q"]).status().unwrap();
        let loosened = Policy::load_managed(&path);
        Command::new("icacls").arg(&dir).args(["/reset", "/t", "/q"]).status().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(ok.unwrap().unwrap().denied_protocols.len() == 1, "admin-only policy loads");
        assert!(loosened.is_err(), "user write grant must be refused");
    } else {
        eprintln!("not elevated: skipped the admin-owned half");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(windows)]
#[test]
fn admin_only_violation_rules() {
    use bastion_core::winacl::{admin_only_violation, Ace, DaclReport};
    let ace = |t: u8, f: u8, m: u32, s: &str| Ace { ace_type: t, flags: f, mask: m, sid: s.into() };
    let rep = |aces| DaclReport { protected: true, aces };
    let admins = "S-1-5-32-544";
    let read = 0x1200A9;
    assert!(admin_only_violation(admins, &rep(vec![ace(0, 0, 0x1F01FF, "S-1-5-18"), ace(0, 0, read, "S-1-5-32-545")])).is_none());
    assert!(admin_only_violation("S-1-5-21-1-2-3-1001", &rep(vec![])).is_some(), "user owner");
    assert!(admin_only_violation(admins, &rep(vec![ace(0, 0, 0x2, "S-1-5-32-545")])).is_some(), "Users write");
    assert!(admin_only_violation(admins, &rep(vec![ace(0, 0, 0x4_0000, "S-1-1-0")])).is_some(), "Everyone WRITE_DAC");
    assert!(admin_only_violation(admins, &rep(vec![ace(1, 0, 0x1F01FF, "S-1-1-0")])).is_none(), "deny entries are fine");
    assert!(admin_only_violation(admins, &rep(vec![ace(0, 0x8 | 0x3, 0x1F01FF, "S-1-3-0")])).is_none(), "inherit-only CREATOR OWNER");
    assert!(admin_only_violation(admins, &rep(vec![ace(5, 0, 0x2, "S-1-5-32-545")])).is_some(), "object ACEs fail closed");
}

/// Codex C09: two independently opened writers (and concurrent threads) on one audit log must
/// keep a single valid chain; before, each cached its own predecessor hash and forked it.
#[test]
fn independent_audit_writers_keep_one_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut a = AuditLog::open(&path).unwrap();
    let mut b = AuditLog::open(&path).unwrap();
    a.record(Category::Connection, "a1", None, Outcome::Success, BTreeMap::new()).unwrap();
    b.record(Category::Connection, "b1", None, Outcome::Success, BTreeMap::new()).unwrap();
    a.record(Category::Connection, "a2", None, Outcome::Success, BTreeMap::new()).unwrap();
    audit::verify(&path).expect("interleaved writers keep the chain valid");

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let p = path.clone();
            std::thread::spawn(move || {
                let mut log = AuditLog::open(&p).unwrap();
                for n in 0..10 {
                    log.record(Category::Task, &format!("t{i}-{n}"), None, Outcome::Success, BTreeMap::new()).unwrap();
                }
            })
        })
        .collect();
    handles.into_iter().for_each(|h| h.join().unwrap());
    audit::verify(&path).expect("concurrent writers keep the chain valid");
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 83);
}
