//! B10 over the C ABI: trash, list, live ids, restore, purge, as a P/Invoke caller drives it.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::restore::*;
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

unsafe fn json(p: *mut c_char) -> Value {
    serde_json::from_str(&take(p)).unwrap()
}

#[test]
fn trash_restore_and_purge_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let mut err: *mut c_char = null_mut();
        let lib = bastion_library_open(c(dir.path().join("lib.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let folder = take(bastion_library_add_folder(lib, null(), c("Web").as_ptr(), &mut err));
        let conn = take(bastion_library_add_connection(lib, c(&folder).as_ptr(), c("A").as_ptr(), c("ssh").as_ptr(), c("a.lab").as_ptr(), -1, null(), &mut err));

        assert_eq!(json(bastion_library_trash(lib, c(&folder).as_ptr(), 1_000, 30, &mut err)), serde_json::json!([]));
        let deleted = json(bastion_library_deleted_json(lib, &mut err));
        assert_eq!(deleted[0]["id"], folder.as_str());
        assert_eq!(deleted[0]["kind"], "folder");
        assert_eq!(deleted[0]["connectionCount"], 1);
        assert_eq!(json(bastion_library_live_connection_ids_json(lib, &mut err)), serde_json::json!([conn]));

        let r = json(bastion_library_restore(lib, c(&folder).as_ptr(), &mut err));
        assert_eq!(r["landedIn"], Value::Null);
        assert_eq!(r["atRootBecauseParentMissing"], false);
        assert_eq!(json(bastion_library_deleted_json(lib, &mut err)), serde_json::json!([]));

        bastion_library_trash(lib, c(&conn).as_ptr(), 1_000, 7, &mut err);
        assert_eq!(json(bastion_library_purge_deleted(lib, 1_000 + 6 * 86_400, 7, &mut err)), serde_json::json!([]));
        assert_eq!(json(bastion_library_purge_deleted(lib, 1_000 + 7 * 86_400, 7, &mut err)), serde_json::json!([conn]));
        assert_eq!(json(bastion_library_live_connection_ids_json(lib, &mut err)), serde_json::json!([]));

        // Restore of an unknown id fails with an error string and NULL.
        assert!(bastion_library_restore(lib, c(&conn).as_ptr(), &mut err).is_null());
        assert!(!take(err).is_empty());
        bastion_library_free(lib);
    }
}
