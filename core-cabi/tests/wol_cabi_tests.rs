//! Wake-on-LAN through the C ABI: plan, validation, inheritance, the wait before connect and cancel.
use std::ffi::{c_char, CStr, CString};
use std::net::TcpListener;
use std::ptr::{null, null_mut};

use bastion_cabi::wol::*;
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

unsafe fn set(lib: *const BastionLibrary, id: &str, key: &str, value: &str) -> Result<(), String> {
    let mut err = null_mut();
    if bastion_library_set_property(lib, c(id).as_ptr(), c(key).as_ptr(), c(value).as_ptr(), &mut err) == 0 {
        Ok(())
    } else {
        Err(take(err))
    }
}

unsafe fn plan(lib: *const BastionLibrary, id: &str) -> Value {
    let mut err = null_mut();
    serde_json::from_str(&take(bastion_library_wol_plan_json(lib, c(id).as_ptr(), &mut err))).unwrap()
}

#[test]
fn plan_validates_inherits_and_hides_the_password() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(dir.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let folder = take(bastion_library_add_folder(lib, null(), c("Office").as_ptr(), &mut err));
        let pc = take(bastion_library_add_connection(lib, c(&folder).as_ptr(), c("pc").as_ptr(), c("rdp").as_ptr(), c("127.0.0.1").as_ptr(), -1, null(), &mut err));

        assert_eq!(plan(lib, &pc), Value::Null, "no MAC, no Wake");
        assert!(bastion_library_wake(lib, c(&pc).as_ptr(), &mut err) == -1 && take(err).contains("MAC"));
        assert_eq!(bastion_library_wake_before_connect(lib, c(&pc).as_ptr(), null(), null_mut(), &mut err), WAKE_NOT_NEEDED);

        assert!(set(lib, &pc, "wol_mac", "ff:ff:ff:ff:ff:ff").unwrap_err().contains("MAC"));
        assert!(set(lib, &folder, "wol_broadcast", "8.8.8.255").unwrap_err().contains("local network"));
        set(lib, &pc, "wol_mac", "00:11:22:33:44:55").unwrap();
        set(lib, &folder, "wol_broadcast", "192.168.1.0/24").unwrap();
        set(lib, &folder, "wol_secureon", "01:23:45:67:89:ab").unwrap();
        let p = plan(lib, &pc);
        assert_eq!((p["mac"].as_str(), p["broadcast"].as_str(), p["port"].as_u64()), (Some("00:11:22:33:44:55"), Some("192.168.1.255"), Some(9)));
        assert_eq!((p["has_secureon"].as_bool(), p["before_connect"].as_bool(), p["check_port"].as_u64()), (Some(true), Some(false), Some(3389)));
        assert!(!p.to_string().contains("89:ab"), "password never leaves the core");
        assert_eq!(bastion_library_wake_before_connect(lib, c(&pc).as_ptr(), null(), null_mut(), &mut err), WAKE_NOT_NEEDED, "option off");
        bastion_library_free(lib);
    }
}

#[test]
fn wait_before_connect_reports_up_and_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let up = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = up.local_addr().unwrap().port().to_string();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(dir.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let pc = take(bastion_library_add_connection(lib, null(), c("pc").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), -1, null(), &mut err));
        for (k, v) in [("wol_mac", "00:11:22:33:44:55"), ("wol_before_connect", "true"), ("wol_wait_secs", "5"), ("port", port.as_str())] {
            set(lib, &pc, k, v).unwrap();
        }
        let mut after = u64::MAX;
        let r = bastion_library_wake_before_connect(lib, c(&pc).as_ptr(), null(), &mut after, &mut err);
        if r == -1 {
            // No broadcast route in some sandboxes: the send itself must be what failed.
            assert!(take(err).contains("could not send"));
        } else {
            assert_eq!(r, WAKE_UP);
            assert!(after < 5_000);
            let token = bastion_wake_cancel_new();
            bastion_wake_cancel(token);
            drop(up);
            assert_eq!(bastion_library_wake_before_connect(lib, c(&pc).as_ptr(), token, null_mut(), &mut err), WAKE_CANCELLED);
            bastion_wake_cancel_free(token);
        }
        bastion_library_free(lib);
    }
}
