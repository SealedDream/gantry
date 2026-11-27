//! The ABI v60 SSH agent: serves vault keys on a private socket and asks before signing.
#![cfg(unix)]
use std::ffi::{c_char, c_void, CStr, CString};
use std::os::unix::fs::PermissionsExt;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU32, Ordering};

use bastion_cabi::*;
use russh::keys::agent::client::AgentClient;
use serde_json::{json, Value};

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> String {
    assert!(!p.is_null());
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    bastion_string_free(p);
    s
}

fn private_dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

unsafe fn new_key() -> String {
    let mut err = null_mut();
    let out: Value = serde_json::from_str(&take(bastion_keys_generate_json(c("agent-test").as_ptr(), std::ptr::null(), &mut err))).unwrap();
    out["private_openssh"].as_str().unwrap().to_string()
}

static ASKED: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn refuse(_ctx: *mut c_void, _comment: *const c_char, _fp: *const c_char) -> i32 {
    ASKED.fetch_add(1, Ordering::SeqCst);
    0
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

#[test]
fn agent_serves_keys_and_removes_socket_when_freed() {
    let d = private_dir();
    let sock = d.path().join("agent.sock");
    unsafe {
        let keys = json!([{ "key": new_key() }]).to_string();
        let mut err = null_mut();
        let a = bastion_agent_start(c(sock.to_str().unwrap()).as_ptr(), c(&keys).as_ptr(), None, null_mut(), &mut err);
        assert!(!a.is_null(), "{}", take(err));
        assert_eq!(take(bastion_agent_socket(a)), sock.to_str().unwrap());
        let ids = runtime().block_on(async {
            let mut client = AgentClient::connect_uds(&sock).await.unwrap();
            client.request_identities().await.unwrap()
        });
        assert_eq!(ids.len(), 1);
        bastion_agent_free(a);
        assert!(!sock.exists());
    }
}

#[test]
fn confirm_callback_can_refuse_a_signature() {
    let d = private_dir();
    let sock = d.path().join("agent.sock");
    unsafe {
        let keys = json!([{ "key": new_key(), "passphrase": null }]).to_string();
        let mut err = null_mut();
        let a = bastion_agent_start(c(sock.to_str().unwrap()).as_ptr(), c(&keys).as_ptr(), Some(refuse), null_mut(), &mut err);
        assert!(!a.is_null(), "{}", take(err));
        let signed = runtime().block_on(async {
            let mut client = AgentClient::connect_uds(&sock).await.unwrap();
            let id = client.request_identities().await.unwrap().remove(0);
            client.sign_request(&id, None, b"data".to_vec()).await
        });
        assert!(signed.is_err());
        assert_eq!(ASKED.load(Ordering::SeqCst), 1);
        bastion_agent_free(a);
    }
}

#[test]
fn bad_input_is_an_error_not_a_crash() {
    let d = private_dir();
    let sock = d.path().join("agent.sock");
    unsafe {
        let mut err = null_mut();
        let a = bastion_agent_start(c(sock.to_str().unwrap()).as_ptr(), c("not json").as_ptr(), None, null_mut(), &mut err);
        assert!(a.is_null());
        assert!(take(err).contains("keys_json"));
        let a = bastion_agent_start(c(sock.to_str().unwrap()).as_ptr(), c(r#"[{"key":"garbage"}]"#).as_ptr(), None, null_mut(), &mut err);
        assert!(a.is_null());
        assert!(!take(err).is_empty());
        assert!(bastion_agent_socket(std::ptr::null()).is_null());
        bastion_agent_free(null_mut());
    }
}

/// Blocks in the confirm callback until RELEASE, recording when it starts and ends.
static STARTED: AtomicU32 = AtomicU32::new(0);
static RELEASE: AtomicU32 = AtomicU32::new(0);
static ENDED: AtomicU32 = AtomicU32::new(0);
static STOPPED: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn blocking(_ctx: *mut c_void, _comment: *const c_char, _fp: *const c_char) -> i32 {
    STARTED.fetch_add(1, Ordering::SeqCst);
    while RELEASE.load(Ordering::SeqCst) == 0 {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    ENDED.fetch_add(1, Ordering::SeqCst);
    0
}

unsafe extern "C" fn on_stopped(_ctx: *mut c_void) {
    // The callback must have finished before completion is reported.
    STOPPED.store(1 + ENDED.load(Ordering::SeqCst), Ordering::SeqCst);
}

fn wait_for(flag: &AtomicU32) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while flag.load(Ordering::SeqCst) == 0 {
        assert!(std::time::Instant::now() < deadline, "timed out");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// F02: free waits for a running confirm callback; stop returns at once and reports completion
/// only after the callback returned. One test, because the flags are shared statics.
#[test]
fn stopping_waits_for_a_running_confirm_callback() {
    for use_stop in [false, true] {
        for f in [&STARTED, &RELEASE, &ENDED, &STOPPED] {
            f.store(0, Ordering::SeqCst);
        }
        let d = private_dir();
        let sock = d.path().join("agent.sock");
        let keys = json!([{ "key": unsafe { new_key() } }]).to_string();
        let mut err = null_mut();
        let a = unsafe { bastion_agent_start(c(sock.to_str().unwrap()).as_ptr(), c(&keys).as_ptr(), Some(blocking), null_mut(), &mut err) };
        assert!(!a.is_null());
        let s = sock.clone();
        let signer = std::thread::spawn(move || {
            runtime().block_on(async {
                let mut client = AgentClient::connect_uds(&s).await.unwrap();
                let id = client.request_identities().await.unwrap().remove(0);
                let _ = client.sign_request(&id, None, b"data".to_vec()).await;
            })
        });
        wait_for(&STARTED);
        let a = a as usize;
        let stopper = std::thread::spawn(move || unsafe {
            if use_stop {
                bastion_agent_stop(a as *mut BastionAgent, Some(on_stopped), null_mut());
            } else {
                bastion_agent_free(a as *mut BastionAgent);
            }
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        if use_stop {
            assert!(stopper.is_finished(), "stop must not block");
            assert_eq!(STOPPED.load(Ordering::SeqCst), 0, "completion reported while the callback runs");
        } else {
            assert!(!stopper.is_finished(), "free returned while the callback was still running");
        }
        RELEASE.store(1, Ordering::SeqCst);
        stopper.join().unwrap();
        if use_stop {
            wait_for(&STOPPED);
            assert_eq!(STOPPED.load(Ordering::SeqCst), 2, "completion came after the callback ended");
        } else {
            assert_eq!(ENDED.load(Ordering::SeqCst), 1);
        }
        let _ = signer.join();
        assert!(!sock.exists());
    }
}
