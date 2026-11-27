//! Test Connection over the C ABI, driven the way a P/Invoke host does. Offline cases always run;
//! the login against bastion-sshd (127.0.0.1:2222) runs with BASTION_SSH_TEST=1.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;

use bastion_cabi::*;

const SECRET: &str = "probe-cabi-secret-7d1e";

unsafe fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    bastion_string_free(p);
    Some(s)
}

unsafe fn manager(dir: &tempfile::TempDir) -> *mut BastionSessionManager {
    let d = CString::new(dir.path().to_str().unwrap()).unwrap();
    let m = bastion_session_manager_new(d.as_ptr(), null_mut());
    assert!(!m.is_null());
    m
}

unsafe fn run(m: *const BastionSessionManager, json: &str) -> serde_json::Value {
    let input = CString::new(json).unwrap();
    let mut err = null_mut();
    let p = bastion_probe_start(m, std::ptr::null(), input.as_ptr(), &mut err);
    assert!(!p.is_null(), "{:?}", take(err));
    let out = take(bastion_probe_wait_json(p, null_mut())).unwrap();
    bastion_probe_free(p);
    assert!(!out.contains(SECRET), "a secret leaked into the report");
    serde_json::from_str(&out).unwrap()
}

#[test]
fn refused_port_is_named_and_bad_input_never_echoes_the_secret() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let m = manager(&dir);
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let r = run(m, &format!(r#"{{"protocol":"ssh","host":"127.0.0.1","port":{port},"username":"tester","login":{{"kind":0,"secret":"{SECRET}"}}}}"#));
        assert_eq!(r["ok"], false);
        let tcp = r["steps"].as_array().unwrap().iter().find(|s| s["kind"] == "tcp").unwrap();
        assert_eq!(tcp["status"], "failed");
        assert_eq!(tcp["detail"], format!("Port {port} refused on 127.0.0.1 (nothing listening)"));
        assert!(tcp["fix"].is_string());

        let bad = CString::new(format!(r#"{{"protocol":"ssh","secret":"{SECRET}""#)).unwrap();
        let mut err = null_mut();
        assert!(bastion_probe_start(m, std::ptr::null(), bad.as_ptr(), &mut err).is_null());
        let msg = take(err).unwrap();
        assert!(!msg.contains(SECRET), "{msg}");
        // The audit log has one line for the test, without the secret.
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert_eq!(log.matches("connection.test").count(), 1);
        assert!(!log.contains(SECRET));
        bastion_session_manager_free(m);
    }
}

#[test]
fn cancel_returns_at_once() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let m = manager(&dir);
        let input = CString::new(r#"{"protocol":"ssh","host":"10.255.255.1","port":22}"#).unwrap();
        let p = bastion_probe_start(m, std::ptr::null(), input.as_ptr(), null_mut());
        let t = std::time::Instant::now();
        bastion_probe_cancel(p);
        let r: serde_json::Value = serde_json::from_str(&take(bastion_probe_wait_json(p, null_mut())).unwrap()).unwrap();
        assert_eq!(r["cancelled"], true);
        assert!(t.elapsed() < std::time::Duration::from_millis(500));
        bastion_probe_free(p);
        bastion_session_manager_free(m);
    }
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn password_login_against_the_test_server() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_SSH_TEST").is_err() {
        return eprintln!("SKIPPED: set BASTION_SSH_TEST=1 with bastion-sshd running");
    }
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let m = manager(&dir);
        // SEC-07: a new key first comes back for the user to confirm; only then is the password tried.
        let first = run(m, r#"{"protocol":"ssh","host":"127.0.0.1","port":2222,"username":"tester","login":{"kind":0,"secret":"test-pass-123"}}"#);
        let shown = first["needs_host_key_confirmation"].as_str().expect("a new key waits for the user").to_string();
        let r = run(m, &format!(r#"{{"protocol":"ssh","host":"127.0.0.1","port":2222,"username":"tester","login":{{"kind":0,"secret":"test-pass-123"}},"trusted_fingerprint":"{shown}"}}"#));
        assert!(r["needs_host_key_confirmation"].is_null(), "{r}");
        assert_eq!(r["ok"], true, "{r}");
        let kinds: Vec<_> = r["steps"].as_array().unwrap().iter().map(|s| s["kind"].as_str().unwrap().to_string()).collect();
        assert_eq!(kinds, ["dns", "tcp", "handshake", "host_key", "login"]);
        assert!(!dir.path().join("known_hosts").exists(), "a test never trusts a key");
        bastion_session_manager_free(m);
    }
}
