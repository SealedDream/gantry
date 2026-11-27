//! VNC through the C ABI: refused ports and NULL handles without a server, and a real-server round trip with
//! `BASTION_VNC_TEST=host:port:password` (apps/windows/tests/vnc-test-setup.sh starts x11vnc in WSL).
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;

unsafe fn take_err(err: *mut c_char) -> String {
    assert!(!err.is_null(), "an error message");
    let s = CStr::from_ptr(err).to_string_lossy().into_owned();
    bastion_string_free(err);
    s
}

#[test]
fn null_handles_are_harmless() {
    unsafe {
        assert_eq!(bastion_vnc_is_closed(null()), 1);
        assert!(bastion_vnc_close_reason(null()).is_null());
        let (mut w, mut h, mut s) = (0, 0, 0);
        assert_eq!(bastion_vnc_frame(null(), 0, null_mut(), 0, &mut w, &mut h, &mut s), -2);
        bastion_vnc_mouse_move(null(), 1, 1);
        bastion_vnc_key(null(), 0x61, 1);
        bastion_vnc_resize(null(), 1024, 768);
        bastion_vnc_close(null());
        bastion_vnc_free(null_mut());
        let mut out = null_mut();
        let mut err = null_mut();
        assert_eq!(bastion_vnc_connect(null(), 5900, null(), &mut out, &mut err), -1);
        assert!(out.is_null());
        assert!(take_err(err).contains("host"));
    }
}

#[test]
fn refused_port_is_an_error() {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let host = CString::new("127.0.0.1").unwrap();
    unsafe {
        let mut out = null_mut();
        let mut err = null_mut();
        assert_eq!(bastion_vnc_connect(host.as_ptr(), port, null(), &mut out, &mut err), -1);
        assert!(out.is_null());
        take_err(err);
    }
}

/// Poll `cond` until it holds or the deadline passes (observable readiness, not a fixed sleep).
fn eventually(mut cond: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    cond()
}

#[ignore = "live: needs BASTION_VNC_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn real_server_round_trip() {
    assert!(std::env::var_os("BASTION_VNC_TEST").is_some(), "live test run without BASTION_VNC_TEST: start the fixture (docs/TESTING.md)");
    let Ok(spec) = std::env::var("BASTION_VNC_TEST") else { return };
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    let host = CString::new(parts[0]).unwrap();
    let port: u16 = parts[1].parse().unwrap();
    let pw = CString::new(parts[2]).unwrap();
    unsafe {
        let mut out = null_mut();
        let mut err = null_mut();
        let wrong = CString::new("wrong-pw").unwrap();
        let rc = bastion_vnc_connect(host.as_ptr(), port, wrong.as_ptr(), &mut out, &mut err);
        let text = take_err(err);
        assert_eq!(rc, CONNECT_AUTH_FAILED, "{text}");

        let mut err = null_mut();
        assert_eq!(bastion_vnc_connect(host.as_ptr(), port, pw.as_ptr(), &mut out, &mut err), 0, "{:?}", (!err.is_null()).then(|| take_err(err)));
        // H14: wait for the first frame instead of a fixed two seconds.
        let (mut w, mut h, mut serial) = (0u16, 0u16, 0u64);
        assert!(
            eventually(|| bastion_vnc_frame(out, 0, null_mut(), 0, &mut w, &mut h, &mut serial) == -1 && w > 0 && h > 0),
            "no frame from the server"
        );
        assert_eq!(bastion_vnc_is_closed(out), 0);
        let mut buf = vec![0u8; w as usize * h as usize * 4];
        assert_eq!(bastion_vnc_frame(out, 0, buf.as_mut_ptr(), buf.len(), &mut w, &mut h, &mut serial), 1);
        assert!(serial > 0 && buf.iter().any(|&b| b != 0), "blank desktop");
        bastion_vnc_mouse_move(out, 10, 10);
        bastion_vnc_mouse_button(out, 0, 1);
        bastion_vnc_mouse_button(out, 0, 0);
        bastion_vnc_key(out, 0x61, 1);
        bastion_vnc_key(out, 0x61, 0);
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert_eq!(bastion_vnc_is_closed(out), 0, "input broke the session");
        bastion_vnc_close(out);
        assert!(eventually(|| bastion_vnc_is_closed(out) == 1), "close did not take effect");
        bastion_vnc_free(out);
    }
}
