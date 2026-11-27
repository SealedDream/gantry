//! Port-forward manager over the C ABI (ABI 65), as the Windows app uses it. The real-server test
//! needs `BASTION_SSH_TEST=1` with bastion-jump on 127.0.0.1:2223 (docs/TESTING.md).
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

#[test]
fn start_with_connection_round_trips_and_local_terminals_have_no_tunnels() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let ssh = take(bastion_library_add_connection(lib, null(), c("jump").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), 22, null(), &mut err)).unwrap();
        let body = format!(r#"{{"name":"Auto","viaId":"{ssh}","kind":"dynamic","localPort":18081,"startWithConnection":true}}"#);
        let id = take(bastion_library_put_tunnel_json(lib, c(&body).as_ptr(), &mut err)).unwrap();
        take(bastion_library_put_tunnel_json(lib, c(&format!(r#"{{"name":"Manual","viaId":"{ssh}","kind":"dynamic","localPort":18082}}"#)).as_ptr(), &mut err)).unwrap();
        let list = json(bastion_library_tunnels_json(lib, &mut err));
        let by_name = |n: &str| list.as_array().unwrap().iter().find(|t| t["name"] == n).unwrap().clone();
        assert_eq!(by_name("Auto")["startWithConnection"], true);
        assert_eq!(by_name("Auto")["id"], id.as_str());
        assert_eq!(by_name("Manual")["startWithConnection"], false);

        let t = bastion_terminal_local_shell(80, 24, &mut err);
        assert!(!t.is_null());
        assert_eq!(json(bastion_terminal_forwards_json(t, &mut err)), Value::Array(vec![]));
        let ids = c(&format!(r#"["{id}"]"#));
        assert!(bastion_terminal_start_forwards_json(t, lib, ids.as_ptr(), &mut err).is_null());
        assert!(take(err).unwrap().contains("SSH"));
        let mut err = null_mut();
        assert_eq!(bastion_terminal_stop_forward(t, c(&id).as_ptr(), &mut err), -1);
        take(err);
        let mut err = null_mut();
        assert!(bastion_terminal_start_forwards_json(t, lib, c("not json").as_ptr(), &mut err).is_null());
        take(err);
        assert!(bastion_terminal_forwards_json(null(), &mut null_mut()).is_null());
        bastion_terminal_free(t);
        bastion_library_free(lib);
    }
}

fn banner(port: u64) -> String {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port as u16)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn tunnels_start_with_the_connection_and_stop_on_request_against_a_real_server() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_SSH_TEST").is_err() {
        eprintln!("SKIPPED tunnels_start_with_the_connection_and_stop_on_request_against_a_real_server: set BASTION_SSH_TEST=1");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let jump = take(bastion_library_add_connection(lib, null(), c("jump").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), 2223, c("tester").as_ptr(), &mut err)).unwrap();
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let auto = format!(r#"{{"name":"Target","viaId":"{jump}","kind":"local","localPort":{free},"host":"target","port":2222,"startWithConnection":true}}"#);
        let auto_id = take(bastion_library_put_tunnel_json(lib, c(&auto).as_ptr(), &mut err)).unwrap();
        let socks_port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let manual = format!(r#"{{"name":"Socks","viaId":"{jump}","kind":"dynamic","localPort":{socks_port}}}"#);
        let manual_id = take(bastion_library_put_tunnel_json(lib, c(&manual).as_ptr(), &mut err)).unwrap();
        let mgr = bastion_session_manager_new(c(d.path().to_str().unwrap()).as_ptr(), &mut err);

        let connect = |trust: Option<&CString>| {
            let (mut outcome, mut fp, mut hop, mut err) = (-42, null_mut(), null_mut(), null_mut());
            let t = bastion_session_connect_ssh(mgr, lib, c(&jump).as_ptr(), c("tester").as_ptr(), LOGIN_PASSWORD, c("test-pass-123").as_ptr(), null(), trust.map_or(null(), |s| s.as_ptr()), null(), 80, 24, &mut outcome, &mut fp, &mut hop, &mut err);
            take(hop);
            take(err);
            (t, outcome, take(fp))
        };
        let (t, outcome, fp) = connect(None);
        assert!(t.is_null() && outcome == CONNECT_HOST_KEY_UNKNOWN);
        let (t, outcome, _) = connect(Some(&c(&fp.unwrap())));
        assert_eq!(outcome, CONNECT_OK);

        // The start-with-connection tunnel is already running; the manual one is not listed.
        let st = json(bastion_terminal_forwards_json(t, &mut err));
        assert_eq!(st.as_array().unwrap().len(), 1, "{st}");
        assert_eq!(st[0]["id"], auto_id.as_str());
        assert_eq!(st[0]["running"], true, "{st}");
        assert!(banner(st[0]["port"].as_u64().unwrap()).starts_with("SSH-2.0-"));
        std::thread::sleep(Duration::from_millis(300));
        let st = json(bastion_terminal_forwards_json(t, &mut err));
        assert!(st[0]["bytesDown"].as_u64().unwrap() > 0, "{st}");

        let started = json(bastion_terminal_start_forwards_json(t, lib, c(&format!(r#"["{manual_id}"]"#)).as_ptr(), &mut err));
        assert_eq!(started.as_array().unwrap().len(), 2, "{started}");
        assert_eq!(bastion_terminal_stop_forward(t, c(&manual_id).as_ptr(), &mut err), 0);
        let st = json(bastion_terminal_forwards_json(t, &mut err));
        let socks = st.as_array().unwrap().iter().find(|s| s["id"] == manual_id.as_str()).unwrap();
        assert_eq!(socks["running"], false);
        assert!(std::net::TcpStream::connect(("127.0.0.1", socks_port)).is_err());

        bastion_terminal_free(t);
        bastion_session_manager_free(mgr);
        bastion_library_free(lib);
    }
}
