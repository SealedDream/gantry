//! Connection history (inspector footer) over the C ABI.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

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

#[test]
fn footer_lines_round_trip_and_bad_input_sets_err() {
    let d = tempfile::tempdir().unwrap();
    let dir = c(d.path().to_str().unwrap());
    let id = c(&uuid::Uuid::new_v4().to_string());
    unsafe {
        let mut err = null_mut();
        let get = |e: &mut *mut c_char| -> Value { serde_json::from_str(&take(bastion_connection_history_json(dir.as_ptr(), id.as_ptr(), e))).unwrap() };
        assert_eq!(get(&mut err), serde_json::json!({ "lastConnectedAt": null, "lastUser": null, "lastResult": null }));

        assert_eq!(bastion_connection_history_success(dir.as_ptr(), id.as_ptr(), c("alice").as_ptr(), &mut err), 0);
        let v = get(&mut err);
        assert_eq!((v["lastUser"].as_str(), v["lastResult"].as_str()), (Some("alice"), Some("OK")));
        assert!(v["lastConnectedAt"].as_u64().unwrap() > 1_700_000_000);

        assert_eq!(bastion_connection_history_failure(dir.as_ptr(), id.as_ptr(), c("auth failed: password=hunter2\nmore").as_ptr(), &mut err), 0);
        let v = get(&mut err);
        assert_eq!(v["lastResult"], "Failed (details hidden)");
        assert_eq!(v["lastUser"], "alice", "last connected kept");

        assert_eq!(bastion_connection_history_success(dir.as_ptr(), id.as_ptr(), null(), &mut err), 0, "VNC has no user");
        assert_eq!(get(&mut err)["lastUser"], Value::Null);

        assert_eq!(bastion_connection_history_forget(dir.as_ptr(), id.as_ptr(), &mut err), 0);
        assert_eq!(get(&mut err)["lastResult"], Value::Null);

        assert_eq!(bastion_connection_history_success(dir.as_ptr(), c("not-a-uuid").as_ptr(), null(), &mut err), -1);
        assert!(!err.is_null());
        bastion_string_free(err);
    }
}
