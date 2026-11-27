//! Multi-host exec over the C ABI (ABI 73), as the Windows app uses it. The real-server test needs
//! `BASTION_SSH_TEST=1` with bastion-jump on 127.0.0.1:2223 (docs/TESTING.md).
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use bastion_cabi::*;
use serde_json::Value;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    Some(s)
}

unsafe fn json(p: *mut c_char) -> Value {
    serde_json::from_str(&take(p).expect("a JSON string")).unwrap()
}

unsafe fn open(dir: &std::path::Path) -> (*mut BastionLibrary, *mut BastionSessionManager) {
    let mut err = null_mut();
    let lib = bastion_library_open(c(dir.join("library.json").to_str().unwrap()).as_ptr(), &mut err);
    let mgr = bastion_session_manager_new(c(dir.to_str().unwrap()).as_ptr(), &mut err);
    assert!(!lib.is_null() && !mgr.is_null());
    (lib, mgr)
}

unsafe fn add(lib: *mut BastionLibrary, name: &str, protocol: &str, host: &str, port: i32) -> String {
    let mut err = null_mut();
    take(bastion_library_add_connection(lib, null(), c(name).as_ptr(), c(protocol).as_ptr(), c(host).as_ptr(), port, c("tester").as_ptr(), &mut err)).unwrap()
}

#[test]
fn abi_version_is_at_least_73() {
    assert!(bastion_abi_version() >= 73);
}

#[test]
fn the_review_refuses_bad_plans_and_new_needs_the_production_ack() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let (lib, mgr) = open(d.path());
        let a = add(lib, "a", "ssh", "10.0.0.1", 22);
        let rdp = add(lib, "desk", "rdp", "10.0.0.2", 3389);
        let ids = |v: &[&str]| c(&serde_json::to_string(v).unwrap());
        let review = |list: &CString, cmd: &str, n: u32| {
            let mut err = null_mut();
            let r = bastion_multiexec_review_json(lib, list.as_ptr(), c(cmd).as_ptr(), n, &mut err);
            (if r.is_null() { None } else { Some(json(r)) }, take(err))
        };
        let (ok, _) = review(&ids(&[&a]), "uptime", 4);
        assert_eq!(ok.unwrap()["needsProductionAck"], false);
        for (list, cmd, n) in [(ids(&[&a]), "", 4), (ids(&[&a]), "a\nb", 4), (ids(&[]), "uptime", 4), (ids(&[&a]), "uptime", 0), (ids(&[&a]), "uptime", 17), (ids(&[&rdp]), "uptime", 1)] {
            let (r, e) = review(&list, cmd, n);
            assert!(r.is_none() && e.is_some(), "{cmd:?} x{n} should be refused");
        }
        let mut err = null_mut();
        assert!(bastion_multiexec_review_json(lib, c("not json").as_ptr(), c("uptime").as_ptr(), 1, &mut err).is_null());
        assert!(take(err).unwrap().contains("JSON array"));

        // A production host must be acknowledged.
        let mut err = null_mut();
        assert_eq!(bastion_library_set_property(lib, c(&a).as_ptr(), c("environment").as_ptr(), c("production").as_ptr(), &mut err), 0, "{:?}", take(err));
        let (r, _) = review(&ids(&[&a]), "uptime", 1);
        assert_eq!(r.unwrap()["needsProductionAck"], true);
        let mut err = null_mut();
        let x = bastion_multiexec_new(mgr, lib, ids(&[&a]).as_ptr(), c("uptime").as_ptr(), 1, null(), LOGIN_AGENT, null(), null(), 0, &mut err);
        assert!(x.is_null());
        assert!(take(err).unwrap().contains("sensitive"));
        let mut err = null_mut();
        let x = bastion_multiexec_new(mgr, lib, ids(&[&a]).as_ptr(), c("uptime").as_ptr(), 1, null(), LOGIN_AGENT, null(), null(), 1, &mut err);
        assert!(!x.is_null(), "{:?}", take(err));
        let st = json(bastion_multiexec_results_json(x, &mut err));
        assert_eq!(st["hosts"][0]["state"], "waiting");
        assert_eq!(bastion_multiexec_cancel(x, &mut err), 0);
        bastion_multiexec_free(x);

        assert!(bastion_multiexec_results_json(null(), &mut err).is_null());
        take(err);
        let mut err = null_mut();
        assert_eq!(bastion_multiexec_run(null(), &mut err), -1);
        take(err);
        bastion_multiexec_free(null_mut());
        bastion_session_manager_free(mgr);
        bastion_library_free(lib);
    }
}

/// Trust bastion-jump's key the way the app does: one connect reports it, the retry pins it.
unsafe fn trust(mgr: *mut BastionSessionManager, lib: *mut BastionLibrary, id: &str) {
    let (mut outcome, mut fp, mut hop, mut err) = (-1, null_mut(), null_mut(), null_mut());
    let t = bastion_session_connect_ssh(mgr, lib, c(id).as_ptr(), c("tester").as_ptr(), LOGIN_PASSWORD, c("test-pass-123").as_ptr(), null(), null(), null(), 80, 24, &mut outcome, &mut fp, &mut hop, &mut err);
    assert!(t.is_null() && outcome == CONNECT_HOST_KEY_UNKNOWN);
    take(err);
    take(hop);
    let fp = c(&take(fp).unwrap());
    let mut err = null_mut();
    let t = bastion_session_connect_ssh(mgr, lib, c(id).as_ptr(), c("tester").as_ptr(), LOGIN_PASSWORD, c("test-pass-123").as_ptr(), null(), fp.as_ptr(), null(), 80, 24, &mut outcome, &mut null_mut(), &mut null_mut(), &mut err);
    assert_eq!(outcome, CONNECT_OK, "{:?}", take(err));
    bastion_terminal_free(t);
}

unsafe fn wait(x: *mut BastionMultiExec) -> Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let mut err = null_mut();
        let st = json(bastion_multiexec_results_json(x, &mut err));
        if st["finished"] == true {
            return st;
        }
        assert!(Instant::now() < deadline, "timed out: {st}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn runs_on_a_real_host_reports_unknown_keys_as_failures_and_retries() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_SSH_TEST").is_err() {
        eprintln!("SKIPPED runs_on_a_real_host_reports_unknown_keys_as_failures_and_retries: set BASTION_SSH_TEST=1");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let (lib, mgr) = open(d.path());
        let jump = add(lib, "jump", "ssh", "127.0.0.1", 2223);
        // Same server under another name: its key is not in known_hosts for "localhost", so it must fail, not prompt.
        let unknown = add(lib, "unknown", "ssh", "localhost", 2223);
        trust(mgr, lib, &jump);
        let ids = c(&serde_json::to_string(&[&jump, &unknown]).unwrap());
        let mut err = null_mut();
        let x = bastion_multiexec_new(mgr, lib, ids.as_ptr(), c("echo mx-$((6*7)); exit 3").as_ptr(), 2, c("tester").as_ptr(), LOGIN_PASSWORD, c("test-pass-123").as_ptr(), null(), 0, &mut err);
        assert!(!x.is_null(), "{:?}", take(err));
        assert_eq!(bastion_multiexec_run(x, &mut err), 0);
        let st = wait(x);
        let h = &st["hosts"];
        assert_eq!((h[0]["state"].as_str(), h[0]["exit"].as_u64(), h[0]["stdout"].as_str().map(str::trim)), (Some("done"), Some(3), Some("mx-42")), "{st}");
        assert_eq!(h[1]["state"], "failed", "{st}");
        assert!(h[1]["error"].as_str().unwrap().contains("host key"), "{st}");
        let csv = take(bastion_multiexec_export(x, c("csv").as_ptr(), &mut err)).unwrap();
        assert_eq!(csv.lines().count(), 3, "{csv}");
        let mut err = null_mut();
        assert!(bastion_multiexec_export(x, c("xml").as_ptr(), &mut err).is_null());
        take(err);
        let mut err = null_mut();
        assert_eq!(bastion_multiexec_retry_failed(x, &mut err), 0);
        let st = wait(x);
        assert_eq!(st["hosts"][0]["state"], "done", "the non-zero exit is retried and runs again: {st}");
        bastion_multiexec_free(x);
        bastion_session_manager_free(mgr);
        bastion_library_free(lib);
    }
}
