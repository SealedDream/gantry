//! A1-CORE-01-FU3 through the C ABI (v99), called the way the Windows app calls it: the saved RDP
//! login, Test Connection and the gateway route hand out a saved credential only as the shared
//! login rule allows. These are unit tests because an ephemeral vault (no OS key store) cannot be
//! opened through the C ABI. Nothing reaches a server; every secret is `pw-<user>`.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};
use std::sync::Arc;

use bastion_ffi::{CredentialVault, GatewayInputView, Library, SessionManager};
use serde_json::Value;

use crate::credentials::{bastion_credentials_rdp_login_json, BastionCredentials};
use crate::credtree::bastion_credentials_edit_login;
use crate::gateway::bastion_gateway_route_open;
use crate::probe::{bastion_probe_free, bastion_probe_start, bastion_probe_wait_json};
use crate::session::{BastionSessionManager, CONNECT_FAILED, LOGIN_AGENT, LOGIN_KEY_FILE, LOGIN_PASSWORD, LOGIN_VAULT};
use crate::{bastion_string_free, BastionLibrary};

const NOT_OFFERED: &str = "that login is not offered for this connection";
const NEEDS_SAVED: &str = "save the connection before testing it with a saved login";
const GATEWAY_REFUSAL: &str = "a gateway does not take a saved login";
const ROUTE_DIFFERS: &str = "differ from the saved connection";

struct Bench {
    dir: tempfile::TempDir,
    v: BastionCredentials,
    lib: BastionLibrary,
    m: BastionSessionManager,
}

fn bench() -> Bench {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(CredentialVault::open_ephemeral(dir.path().join("c.vault").to_string_lossy().into_owned()).unwrap());
    let lib = Arc::new(Library::open(dir.path().join("lib.json").to_string_lossy().into_owned()).unwrap());
    let manager = SessionManager::new(dir.path().join("data").to_string_lossy().into_owned()).unwrap();
    manager.set_vault(vault.clone());
    Bench { dir, v: BastionCredentials(vault), lib: BastionLibrary(lib), m: BastionSessionManager(manager) }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> String {
    assert!(!p.is_null(), "expected a string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    s
}

fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// The text an app shows for a refusal: no secret and no credential name in it.
fn clean(message: String, expect: &str) {
    assert!(message.contains(expect), "{message}");
    assert!(!message.contains("pw-"), "{message}");
    for user in ["dba", "admin", "stranger"] {
        assert!(!message.contains(&format!("{user} login")), "{message}");
    }
}

impl Bench {
    fn folder(&self, name: &str) -> String {
        self.lib.0.add_folder(None, name.into()).unwrap()
    }

    fn add(&self, parent: &str, name: &str, protocol: &str, host: &str) -> String {
        self.lib.0.add_connection(Some(parent.into()), name.into(), protocol.into(), host.into(), None, None).unwrap()
    }

    fn password(&self, user: &str) -> String {
        self.v.0.save_password(None, format!("{user} login"), None, user.into(), format!("pw-{user}")).unwrap()
    }

    /// "Use this login" through the C ABI (op 0: add).
    fn assign(&self, connection: &str, credential: &str) {
        unsafe { assert_eq!(bastion_credentials_edit_login(&self.v, &self.lib, c(connection).as_ptr(), c(credential).as_ptr(), 0, null_mut()), 0) }
    }

    /// The JSON of `bastion_credentials_rdp_login_json`, or the error text.
    fn rdp(&self, connection: &str, credential: Option<&str>) -> Result<Value, String> {
        let credential = credential.map(c);
        unsafe {
            let mut err = null_mut();
            let out = bastion_credentials_rdp_login_json(&self.v, &self.lib, c(connection).as_ptr(), credential.as_ref().map_or(null(), |c| c.as_ptr()), &mut err);
            if out.is_null() {
                return Err(take(err));
            }
            Ok(serde_json::from_str(&take(out)).unwrap())
        }
    }

    /// Start a test of a closed port on this computer; the report, or the start error.
    fn probe(&self, with_lib: bool, extra: &str) -> Result<Value, String> {
        self.probe_port(with_lib, closed_port(), extra)
    }

    /// The same, of `127.0.0.1:port`.
    fn probe_port(&self, with_lib: bool, port: u16, extra: &str) -> Result<Value, String> {
        let input = c(&format!(r#"{{"protocol":"ssh","host":"127.0.0.1","port":{port},"username":"tester"{extra}}}"#));
        unsafe {
            let mut err = null_mut();
            let p = bastion_probe_start(&self.m, if with_lib { &self.lib } else { null() }, input.as_ptr(), &mut err);
            if p.is_null() {
                return Err(take(err));
            }
            let report = take(bastion_probe_wait_json(p, null_mut()));
            bastion_probe_free(p);
            assert!(!report.contains("pw-"), "{report}");
            Ok(serde_json::from_str(&report).unwrap())
        }
    }

    fn tests_started(&self) -> usize {
        std::fs::read_to_string(self.dir.path().join("data").join("audit.jsonl")).unwrap_or_default().matches("connection.test").count()
    }

    /// Open the gateway route of `connection`; the outcome code and the error text.
    fn route(&self, connection: &str, kind: i32, secret: Option<&str>, key_path: Option<&str>) -> (i32, String) {
        let (secret, key_path) = (secret.map(c), key_path.map(c));
        unsafe {
            let (mut outcome, mut fingerprint, mut err) = (-1, null_mut(), null_mut());
            let r = bastion_gateway_route_open(
                &self.m,
                &self.lib,
                c(connection).as_ptr(),
                c("hop").as_ptr(),
                kind,
                secret.as_ref().map_or(null(), |s| s.as_ptr()),
                key_path.as_ref().map_or(null(), |s| s.as_ptr()),
                null(),
                &mut outcome,
                &mut fingerprint,
                &mut err,
            );
            assert!(r.is_null() && fingerprint.is_null(), "nothing listens on the gateway's port");
            (outcome, take(err))
        }
    }
}

fn vault_login(credential: &str) -> String {
    format!(r#"{{"kind":{LOGIN_VAULT},"secret":"{credential}"}}"#)
}

fn dialled(report: Value) {
    assert_eq!(report["ok"], false);
    assert!(report["steps"].as_array().unwrap().iter().any(|s| s["kind"] == "tcp" && s["status"] == "failed"), "{report}");
}

#[test]
fn rdp_login_json_returns_own_logins_and_refuses_the_rest() {
    let b = bench();
    let (acme, globex) = (b.folder("Acme"), b.folder("Globex"));
    let ssh = b.add(&acme, "acme ssh", "ssh", "10.0.0.5");
    let rdp = b.add(&acme, "acme desktop", "rdp", "10.0.0.5");
    let other = b.add(&globex, "globex desktop", "rdp", "10.0.0.5");
    let forward_a = b.add(&acme, "forward 3390", "rdp", "127.0.0.1");
    let forward_b = b.add(&acme, "forward 3391", "rdp", "127.0.0.1");
    let (dba, admin, stranger) = (b.password("dba"), b.password("admin"), b.password("stranger"));
    b.assign(&ssh, &dba);
    b.assign(&rdp, &admin);
    b.assign(&forward_a, &admin);
    b.lib.0.set_property(globex, "credential_id".into(), Some(stranger.clone())).unwrap();

    assert_eq!(b.rdp(&rdp, None).unwrap(), Value::Null);
    let own = b.rdp(&rdp, Some(&admin)).unwrap();
    assert_eq!((own["username"].as_str(), own["password"].as_str()), (Some("admin"), Some("pw-admin")), "assigned");
    let inherited = b.rdp(&other, Some(&stranger)).unwrap();
    assert_eq!(inherited["username"], "stranger", "inherited from its folder");

    clean(b.rdp(&other, Some(&admin)).unwrap_err(), NOT_OFFERED); // another top-level folder
    clean(b.rdp(&forward_b, Some(&admin)).unwrap_err(), NOT_OFFERED); // another loopback connection
    clean(b.rdp(&rdp, Some(&stranger)).unwrap_err(), NOT_OFFERED); // not offered at all
    clean(b.rdp(&rdp, Some(&dba)).unwrap_err(), NOT_OFFERED); // only offered (same machine)
    let log = std::fs::read_to_string(b.dir.path().join("audit.jsonl")).unwrap();
    assert_eq!(log.matches("credential.release.rdp").count(), 2, "a refusal releases nothing");

    b.v.0.set_inline_password(rdp.clone(), "inline".into(), "pw-inline".into()).unwrap();
    assert_eq!(b.rdp(&rdp, Some(&stranger)).unwrap()["username"], "inline", "its own inline password comes first");
    unsafe {
        let mut err = null_mut();
        assert!(bastion_credentials_rdp_login_json(&b.v, null(), c(&rdp).as_ptr(), null(), &mut err).is_null());
        assert!(take(err).contains("library handle is NULL"));
    }
}

#[test]
fn probe_start_checks_saved_logins_with_and_without_a_library() {
    let b = bench();
    let (acme, globex) = (b.folder("Acme"), b.folder("Globex"));
    let conn = b.add(&acme, "acme db", "ssh", "10.0.0.5");
    let twin = b.add(&acme, "acme files", "sftp", "10.0.0.5");
    let other = b.add(&globex, "globex db", "ssh", "10.0.0.5");
    let (dba, stranger) = (b.password("dba"), b.password("stranger"));
    b.assign(&conn, &dba);
    b.v.0.set_inline_password(twin.clone(), "inline".into(), "pw-inline".into()).unwrap();
    let saved = |connection: &str, credential: &str| format!(r#","connection_id":"{connection}","login":{}"#, vault_login(credential));
    let hop = |credential: &str| format!(r#"{{"host":"127.0.0.1","port":{},"username":"hop","login":{}}}"#, closed_port(), vault_login(credential));

    // Refused before anything is read or dialled.
    clean(b.probe(true, &saved(&other, &dba)).unwrap_err(), NOT_OFFERED);
    clean(b.probe(true, &saved(&conn, &stranger)).unwrap_err(), NOT_OFFERED);
    clean(b.probe(true, &saved(&twin, &dba)).unwrap_err(), NOT_OFFERED); // only offered
    clean(b.probe(true, &saved(&conn, &twin)).unwrap_err(), NOT_OFFERED); // another connection's inline secret
    clean(b.probe(true, &format!(r#","connection_id":"{conn}","login":{{"kind":{LOGIN_PASSWORD},"secret":"typed"}},"jumps":[{}]"#, hop(&stranger))).unwrap_err(), NOT_OFFERED);
    // No library, or an entry that is not saved yet: a saved login cannot be tested.
    clean(b.probe(false, &saved(&conn, &dba)).unwrap_err(), NEEDS_SAVED);
    clean(b.probe(true, &format!(r#","login":{}"#, vault_login(&dba))).unwrap_err(), NEEDS_SAVED);
    clean(b.probe(true, &format!(r#","connection_id":null,"login":{}"#, vault_login(&dba))).unwrap_err(), NEEDS_SAVED);
    clean(b.probe(false, &format!(r#","jumps":[{}]"#, hop(&dba))).unwrap_err(), NEEDS_SAVED);
    assert_eq!(b.tests_started(), 0);

    // Allowed: its own login and its own inline secret, dialled at the saved host and port.
    let port = closed_port();
    let local = b.add(&acme, "local db", "ssh", "127.0.0.1");
    b.lib.0.set_property(local.clone(), "port".into(), Some(port.to_string())).unwrap();
    b.assign(&local, &dba);
    dialled(b.probe_port(true, port, &saved(&local, &dba)).unwrap());
    b.v.0.set_inline_password(local.clone(), "inline".into(), "pw-inline".into()).unwrap();
    dialled(b.probe_port(true, port, &saved(&local, &local)).unwrap());
    // Review of #846: not at an edited port, and not through a hop the saved connection lacks.
    clean(b.probe(true, &saved(&local, &dba)).unwrap_err(), ROUTE_DIFFERS);
    clean(b.probe_port(true, port, &format!(r#"{},"jumps":[{}]"#, saved(&local, &dba), hop(&dba))).unwrap_err(), ROUTE_DIFFERS);
    // Anything typed goes where the user typed.
    for with_lib in [true, false] {
        dialled(b.probe(with_lib, &format!(r#","login":{{"kind":{LOGIN_PASSWORD},"secret":"typed"}}"#)).unwrap());
        dialled(b.probe(with_lib, &format!(r#","login":{{"kind":{LOGIN_AGENT}}}"#)).unwrap());
        dialled(b.probe(with_lib, "").unwrap());
    }
}

#[test]
fn gateway_route_open_refuses_a_vault_login_and_dials_with_the_others() {
    let b = bench();
    let lab = b.folder("Lab");
    let conn = b.add(&lab, "desktop", "rdp", "10.0.0.9");
    let gateway = GatewayInputView { name: "Jump".into(), host: "127.0.0.1".into(), port: Some(closed_port()), username: Some("hop".into()), notes: String::new() };
    let gateway = b.lib.0.add_gateway(gateway).unwrap();
    b.lib.0.set_property(conn.clone(), "gateway_id".into(), Some(gateway)).unwrap();
    let (admin, stranger) = (b.password("admin"), b.password("stranger"));
    b.assign(&conn, &admin);

    for credential in [&admin, &stranger] {
        let (outcome, message) = b.route(&conn, LOGIN_VAULT, Some(credential), None);
        assert_eq!(outcome, CONNECT_FAILED);
        assert!(!message.contains(credential.as_str()), "{message}");
        clean(message, GATEWAY_REFUSAL);
    }
    for (kind, secret, key_path) in [(LOGIN_PASSWORD, Some("typed"), None), (LOGIN_KEY_FILE, None, Some("/nonexistent/id_ed25519")), (LOGIN_AGENT, None, None)] {
        let (outcome, message) = b.route(&conn, kind, secret, key_path);
        assert_eq!(outcome, CONNECT_FAILED, "nothing listens there");
        assert!(!message.contains(GATEWAY_REFUSAL) && !message.contains("not offered"), "{message}");
    }
}
