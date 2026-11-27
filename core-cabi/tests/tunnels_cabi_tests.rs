//! Saved tunnels on their own SSH connection over the C ABI (ABI 72), as the Windows Tunnel
//! Manager uses them. The real-server test needs `BASTION_SSH_TEST=1` with bastion-jump on
//! 127.0.0.1:2223 (docs/TESTING.md).
use std::ffi::{c_char, CStr, CString};
use std::io::Read;
use std::ptr::{null, null_mut};
use std::time::Duration;

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

struct Started {
    tunnel: *mut BastionTunnel,
    outcome: i32,
    fingerprint: Option<String>,
    err: Option<String>,
}

unsafe fn start(mgr: *const BastionSessionManager, lib: *const BastionLibrary, id: &str, port_login: (&str, &str), trust: Option<&str>) -> Started {
    let (mut outcome, mut fp, mut hop, mut err) = (-42, null_mut(), null_mut(), null_mut());
    let trust = trust.map(c);
    let tunnel = bastion_tunnel_start(
        mgr, lib, c(id).as_ptr(), c(port_login.0).as_ptr(), LOGIN_PASSWORD, c(port_login.1).as_ptr(), null(), null(),
        trust.as_ref().map_or(null(), |s| s.as_ptr()), null(), null(), &mut outcome, &mut fp, &mut hop, &mut err,
    );
    take(hop);
    Started { tunnel, outcome, fingerprint: take(fp), err: take(err) }
}

#[test]
fn abi_version_is_at_least_72() {
    assert!(bastion_abi_version() >= 72);
}

#[test]
fn bad_handles_and_unknown_tunnels_fail_cleanly() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let mgr = bastion_session_manager_new(c(d.path().to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null() && !mgr.is_null());

        let s = start(mgr, lib, "not-a-uuid", ("u", "p"), None);
        assert!(s.tunnel.is_null());
        assert_eq!(s.outcome, CONNECT_FAILED);
        assert!(s.err.is_some());

        let s = start(mgr, lib, "6f2b8f3e-0000-4000-8000-000000000000", ("u", "p"), None);
        assert!(s.tunnel.is_null() && s.outcome == CONNECT_FAILED, "{:?}", s.err);

        let s = start(null(), lib, "x", ("u", "p"), None);
        assert!(s.tunnel.is_null() && s.err.unwrap().contains("NULL"));

        let mut err = null_mut();
        assert!(bastion_tunnel_status_json(null(), &mut err).is_null());
        assert!(take(err).unwrap().contains("NULL"));
        let mut err = null_mut();
        assert_eq!(bastion_tunnel_stop(null(), &mut err), -1);
        take(err);
        bastion_tunnel_free(null_mut());

        bastion_session_manager_free(mgr);
        bastion_library_free(lib);
    }
}

#[test]
fn an_unreachable_ssh_host_fails_without_a_handle() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        // Port 1 on loopback: nothing listens there, so the dial is refused at once.
        let via = take(bastion_library_add_connection(lib, null(), c("down").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), 1, c("u").as_ptr(), &mut err)).unwrap();
        let id = take(bastion_library_put_tunnel_json(lib, c(&format!(r#"{{"name":"T","viaId":"{via}","kind":"dynamic","localPort":18091}}"#)).as_ptr(), &mut err)).unwrap();
        let mgr = bastion_session_manager_new(c(d.path().to_str().unwrap()).as_ptr(), &mut err);
        let s = start(mgr, lib, &id, ("u", "p"), None);
        assert!(s.tunnel.is_null());
        assert_eq!(s.outcome, CONNECT_FAILED, "{:?}", s.err);
        assert!(std::net::TcpStream::connect(("127.0.0.1", 18091)).is_err(), "no listener may be left behind");
        bastion_session_manager_free(mgr);
        bastion_library_free(lib);
    }
}

fn banner(port: u16) -> String {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn a_saved_local_tunnel_starts_forwards_and_stops_against_a_real_server() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_SSH_TEST").is_err() {
        eprintln!("SKIPPED a_saved_local_tunnel_starts_forwards_and_stops_against_a_real_server: set BASTION_SSH_TEST=1");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let jump = take(bastion_library_add_connection(lib, null(), c("jump").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), 2223, c("tester").as_ptr(), &mut err)).unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let body = format!(r#"{{"name":"Target","viaId":"{jump}","kind":"local","localPort":{port},"host":"target","port":2222}}"#);
        let id = take(bastion_library_put_tunnel_json(lib, c(&body).as_ptr(), &mut err)).unwrap();
        let mgr = bastion_session_manager_new(c(d.path().to_str().unwrap()).as_ptr(), &mut err);

        // Unknown host key: no handle, the fingerprint is handed back for verification.
        let first = start(mgr, lib, &id, ("tester", "test-pass-123"), None);
        assert!(first.tunnel.is_null());
        assert_eq!(first.outcome, CONNECT_HOST_KEY_UNKNOWN);
        let fp = first.fingerprint.expect("fingerprint");

        let wrong = start(mgr, lib, &id, ("tester", "wrong"), Some(&fp));
        assert!(wrong.tunnel.is_null());
        assert_eq!(wrong.outcome, CONNECT_AUTH_FAILED);

        let ok = start(mgr, lib, &id, ("tester", "test-pass-123"), Some(&fp));
        assert_eq!(ok.outcome, CONNECT_OK, "{:?}", ok.err);
        assert!(banner(port).starts_with("SSH-2.0-"));
        std::thread::sleep(Duration::from_millis(200));
        let st = json(bastion_tunnel_status_json(ok.tunnel, &mut err));
        assert_eq!(st["running"], true, "{st}");
        assert!(st["connections"].as_u64().unwrap() >= 1, "{st}");
        assert!(st["summary"].as_str().unwrap().contains(&port.to_string()), "{st}");

        // A second start of the same tunnel cannot take the port.
        let busy = start(mgr, lib, &id, ("tester", "test-pass-123"), Some(&fp));
        assert!(busy.tunnel.is_null());
        assert_eq!(busy.outcome, CONNECT_FAILED);

        assert_eq!(bastion_tunnel_stop(ok.tunnel, &mut err), 0);
        assert_eq!(json(bastion_tunnel_status_json(ok.tunnel, &mut err))["running"], false);
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
        bastion_tunnel_free(ok.tunnel);
        bastion_session_manager_free(mgr);
        bastion_library_free(lib);
    }
}
