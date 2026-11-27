//! SEC-07 over the C ABI: Test Connection never sends a password to a host whose key nobody
//! confirmed. The two fields travel in the probe JSON of `bastion_probe_start` /
//! `bastion_probe_wait_json`, driven here the way the Windows app's P/Invoke does.
//!
//! An in-process russh server records every authentication request it receives, so "no login
//! attempt" is checked on the server side. No network and no Docker fixture: these always run.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bastion_cabi::*;
use bastion_core::ssh::fingerprint;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::PrivateKey;
use russh::server::{self, Auth};
use serde_json::{json, Value};

const USER: &str = "tester";
const PASSWORD: &str = "lab-only-not-a-real-password";
const NOT_TESTED: &str = "Not tested: confirm the host key first";
/// A valid ed25519 public key that no server here uses: a "changed" known_hosts entry.
const OTHER_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

/// Every authentication request the server received, by method name.
type Seen = Arc<Mutex<Vec<&'static str>>>;

struct Lab(Seen);

impl Lab {
    fn saw(&self, method: &'static str) {
        self.0.lock().unwrap().push(method);
    }
}

impl server::Handler for Lab {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        self.saw("none");
        Ok(Auth::reject())
    }
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.saw("password");
        Ok(if user == USER && password == PASSWORD { Auth::Accept } else { Auth::reject() })
    }
    async fn auth_keyboard_interactive<'a>(&'a mut self, _user: &str, _submethods: &str, _response: Option<server::Response<'a>>) -> Result<Auth, Self::Error> {
        self.saw("keyboard-interactive");
        Ok(Auth::reject())
    }
}

/// An SSH server on a free loopback port, with the runtime that keeps it alive.
struct Server {
    _runtime: tokio::runtime::Runtime,
    port: u16,
    fingerprint: String,
    seen: Seen,
}

impl Server {
    fn start(seed: u8) -> Server {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        let key = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&[seed; 32])), "").unwrap();
        let print = fingerprint(key.public_key());
        let config = Arc::new(server::Config { keys: vec![key], auth_rejection_time: Duration::ZERO, ..Default::default() });
        let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Seen = Arc::default();
        let record = seen.clone();
        runtime.spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let (config, seen) = (config.clone(), record.clone());
                tokio::spawn(async move {
                    if let Ok(s) = server::run_stream(config, sock, Lab(seen)).await {
                        let _ = s.await;
                    }
                });
            }
        });
        Server { _runtime: runtime, port, fingerprint: print, seen }
    }

    fn attempts(&self) -> Vec<&'static str> {
        self.seen.lock().unwrap().clone()
    }

    /// The probe JSON the Windows app sends: a typed password, and what the user confirmed (if anything).
    fn request(&self, trusted: Option<&str>) -> String {
        let mut input = json!({"protocol": "ssh", "host": "127.0.0.1", "port": self.port, "username": USER, "login": {"kind": LOGIN_PASSWORD, "secret": PASSWORD}});
        if let Some(t) = trusted {
            input["trusted_fingerprint"] = json!(t);
        }
        input.to_string()
    }
}

unsafe fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    bastion_string_free(p);
    Some(s)
}

/// One test through the C ABI, in a data folder of its own.
struct Host {
    dir: tempfile::TempDir,
    m: *mut BastionSessionManager,
}

impl Host {
    fn new() -> Host {
        let dir = tempfile::tempdir().unwrap();
        let d = CString::new(dir.path().to_str().unwrap()).unwrap();
        let m = unsafe { bastion_session_manager_new(d.as_ptr(), null_mut()) };
        assert!(!m.is_null());
        Host { dir, m }
    }

    fn known_hosts(&self) -> std::path::PathBuf {
        self.dir.path().join("known_hosts")
    }

    fn test(&self, input: &str) -> Value {
        unsafe {
            let input = CString::new(input).unwrap();
            let mut err = null_mut();
            let p = bastion_probe_start(self.m, std::ptr::null(), input.as_ptr(), &mut err);
            assert!(!p.is_null(), "{:?}", take(err));
            let out = take(bastion_probe_wait_json(p, null_mut())).unwrap();
            bastion_probe_free(p);
            assert!(!out.contains(PASSWORD), "a secret leaked into the report");
            serde_json::from_str(&out).unwrap()
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        unsafe { bastion_session_manager_free(self.m) };
    }
}

fn step<'a>(report: &'a Value, kind: &str) -> &'a Value {
    report["steps"].as_array().unwrap().iter().find(|s| s["kind"] == kind).unwrap_or_else(|| panic!("no {kind} step in {report}"))
}

#[test]
fn unknown_key_returns_the_fingerprint_and_sends_no_login() {
    let server = Server::start(41);
    let host = Host::new();

    let report = host.test(&server.request(None));

    assert_eq!(report["needs_host_key_confirmation"], server.fingerprint.as_str(), "{report}");
    assert_eq!(step(&report, "login")["status"], "skipped");
    assert_eq!(step(&report, "login")["detail"], NOT_TESTED);
    assert_eq!(step(&report, "host_key")["status"], "warn");
    assert!(server.attempts().is_empty(), "the server saw {:?}", server.attempts());
    assert!(!host.known_hosts().exists(), "a test never stores a key");
    assert!(report["host_key_failure"].is_null(), "SEC-07-FU1: a new key is not a failure: {report}");
}

#[test]
fn the_confirmed_fingerprint_lets_the_second_test_log_in() {
    let server = Server::start(42);
    let host = Host::new();
    let first = host.test(&server.request(None));
    let shown = first["needs_host_key_confirmation"].as_str().expect("the first test waits").to_string();
    assert!(server.attempts().is_empty());

    let second = host.test(&server.request(Some(&shown)));

    assert!(second["needs_host_key_confirmation"].is_null(), "{second}");
    assert_eq!(second["ok"], true, "{second}");
    assert_eq!(step(&second, "login")["status"], "ok");
    assert!(server.attempts().contains(&"password"), "the server saw {:?}", server.attempts());
    assert!(!host.known_hosts().exists(), "confirming for a test stores nothing");
}

#[test]
fn a_wrong_or_empty_fingerprint_does_not_log_in() {
    let server = Server::start(43);
    let host = Host::new();

    for trusted in ["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ""] {
        let report = host.test(&server.request(Some(trusted)));

        assert_eq!(report["needs_host_key_confirmation"], server.fingerprint.as_str(), "trusted {trusted:?}: {report}");
        assert_eq!(step(&report, "login")["status"], "skipped");
    }
    assert!(server.attempts().is_empty(), "the server saw {:?}", server.attempts());
    assert!(!host.known_hosts().exists());
}

#[test]
fn a_changed_key_fails_hard_and_cannot_be_confirmed() {
    let server = Server::start(44);
    let host = Host::new();
    let line = format!("[127.0.0.1]:{} {OTHER_KEY}\n", server.port);
    std::fs::write(host.known_hosts(), &line).unwrap();

    // Also with the server's own fingerprint "confirmed": a changed key is never overridden by a test.
    for trusted in [None, Some(server.fingerprint.as_str())] {
        let report = host.test(&server.request(trusted));

        assert_eq!(report["ok"], false, "{report}");
        assert!(report["needs_host_key_confirmation"].is_null(), "{report}");
        assert_eq!(step(&report, "host_key")["status"], "failed");
        assert_eq!(report["host_key_failure"], "changed", "SEC-07-FU1: {report}");
        assert_eq!(step(&report, "login")["status"], "skipped");
    }
    assert!(server.attempts().is_empty(), "the server saw {:?}", server.attempts());
    assert_eq!(std::fs::read_to_string(host.known_hosts()).unwrap(), line, "known_hosts is untouched");
}

/// CORE-SEC-LOWS: the wire value the Windows app matches on for a known_hosts it cannot read.
/// A folder in place of the file makes the read fail the same way on macOS and Windows.
#[test]
fn an_unreadable_known_hosts_fails_with_its_own_wire_value_and_sends_no_login() {
    let server = Server::start(45);
    let host = Host::new();
    std::fs::create_dir(host.known_hosts()).unwrap();

    let report = host.test(&server.request(Some(&server.fingerprint)));

    assert_eq!(report["ok"], false, "{report}");
    assert_eq!(report["host_key_failure"], "known_hosts_unreadable", "{report}");
    assert!(report["needs_host_key_confirmation"].is_null(), "{report}");
    assert!(server.attempts().is_empty(), "the server saw {:?}", server.attempts());
}
