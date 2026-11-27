//! Session restore after a crash and start page recents over the C ABI (ABI 80).
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use serde_json::{json, Value};

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

#[test]
fn crash_then_clean_quit_and_recents() {
    let d = tempfile::tempdir().unwrap();
    let dir = c(d.path().to_str().unwrap());
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let a = take(bastion_library_add_connection(lib, null(), c("web").as_ptr(), c("ssh").as_ptr(), c("192.0.2.7").as_ptr(), 2222, c("appuser").as_ptr(), &mut err)).unwrap();
        let begin = |e: &mut *mut c_char, on: i32| -> Value { serde_json::from_str(&take(bastion_open_sessions_begin_json(lib, dir.as_ptr(), on, e)).unwrap()).unwrap() };

        assert_eq!(begin(&mut err, 1)["lastExit"], "none");
        let set = json!({ "tabs": [{ "connection": a, "mode": "terminal", "cwd": "/srv" }], "selected": 0 }).to_string();
        assert_eq!(bastion_open_sessions_save(dir.as_ptr(), c(&set).as_ptr(), &mut err), 0);

        let plan = begin(&mut err, 0);
        assert_eq!((plan["lastExit"].as_str(), plan["restore"].as_bool(), plan["autoReconnect"].as_bool()), (Some("crash"), Some(true), Some(false)), "D15: after a crash the tabs come back and wait for the user");
        assert_eq!(plan["tabs"][0]["cwd"], "/srv");

        assert_eq!(bastion_open_sessions_mark_clean_quit(dir.as_ptr(), &mut err), 0);
        let plan = begin(&mut err, 0);
        assert_eq!((plan["lastExit"].as_str(), plan["restore"].as_bool()), (Some("clean"), Some(false)));

        assert_eq!(bastion_open_sessions_save(dir.as_ptr(), c("{bad").as_ptr(), &mut err), -1);
        assert!(take(err).unwrap().contains("invalid open-session set"));
        err = null_mut();

        assert_eq!(bastion_connection_history_success(dir.as_ptr(), c(&a).as_ptr(), c("appuser").as_ptr(), &mut err), 0);
        let rows: Value = serde_json::from_str(&take(bastion_recent_sessions_json(lib, dir.as_ptr(), 10, &mut err)).unwrap()).unwrap();
        assert_eq!((rows[0]["host"].as_str(), rows[0]["port"].as_u64(), rows[0]["user"].as_str(), rows[0]["protocol"].as_str()), (Some("192.0.2.7"), Some(2222), Some("appuser"), Some("ssh")));
        assert_eq!(bastion_connection_history_forget(dir.as_ptr(), c(&a).as_ptr(), &mut err), 0);
        assert_eq!(take(bastion_recent_sessions_json(lib, dir.as_ptr(), 10, &mut err)).unwrap(), "[]");

        assert!(take(bastion_recent_sessions_json(null(), dir.as_ptr(), 10, &mut err)).is_none());
        assert!(take(err).unwrap().contains("NULL"));
        bastion_library_free(lib);
    }
}
