//! Host status dashboard over the C ABI (ABI 68), as the Windows app uses it. Loopback only.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use bastion_cabi::*;
use serde_json::Value;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> String {
    assert!(!p.is_null(), "expected a string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    s
}

unsafe fn snapshot(h: *const BastionHostStatus) -> Value {
    let mut err = null_mut();
    serde_json::from_str(&take(bastion_host_status_snapshot_json(h, &mut err))).unwrap()
}

#[test]
fn opted_in_hosts_are_checked_only_while_visible() {
    let up = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = up.local_addr().unwrap().port();
    let down_port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let add = |name: &str, port: u16| take(bastion_library_add_connection(lib, null(), c(name).as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), i32::from(port), null(), &mut null_mut()));
        let a = add("alive", up_port);
        let b = add("dead", down_port);
        add("not opted in", up_port);
        for id in [&a, &b] {
            assert_eq!(bastion_library_set_property(lib, c(id).as_ptr(), c("host_status").as_ptr(), c("true").as_ptr(), &mut err), 0);
        }

        let h = bastion_host_status_new(30);
        assert_eq!(bastion_host_status_load(h, lib, &mut err), 2);
        // Hidden: listed, never checked, even on refresh.
        bastion_host_status_check_now(h);
        std::thread::sleep(Duration::from_millis(150));
        let s = snapshot(h);
        assert_eq!(s.as_array().unwrap().len(), 2);
        assert!(s.as_array().unwrap().iter().all(|r| r["state"] == "unknown" && r["checkedAt"].is_null()), "{s}");

        bastion_host_status_set_visible(h, 1);
        let start = Instant::now();
        let s = loop {
            let s = snapshot(h);
            if s.as_array().unwrap().iter().all(|r| r["state"] != "unknown") || start.elapsed() > Duration::from_secs(5) {
                break s;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let by = |n: &str| s.as_array().unwrap().iter().find(|r| r["name"] == n).unwrap().clone();
        assert_eq!(by("alive")["state"], "up", "{s}");
        assert!(by("alive")["latencyMs"].is_u64());
        assert_eq!((by("dead")["state"].as_str(), by("dead")["error"].as_str()), (Some("down"), Some("refused")));
        bastion_host_status_set_visible(h, 0);

        // Null handles are errors, not crashes.
        assert_eq!(bastion_host_status_load(null(), lib, &mut err), -1);
        take(err);
        bastion_host_status_set_visible(null(), 1);
        bastion_host_status_check_now(null());
        assert!(bastion_host_status_snapshot_json(null(), &mut null_mut()).is_null());
        bastion_host_status_free(h);
        bastion_host_status_free(null_mut());
        bastion_library_free(lib);
    }
    drop(up);
}
