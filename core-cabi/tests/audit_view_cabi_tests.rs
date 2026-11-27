//! The Audit Log page over the C ABI (ABI 123): read and verify, read-only.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;

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

#[test]
fn read_and_verify_a_real_log() {
    let dir = tempfile::tempdir().unwrap();
    let mut log = bastion_core::audit::AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
    for a in ["first", "second", "third"] {
        log.record(bastion_core::audit::Category::Connection, a, Some("lab"), bastion_core::audit::Outcome::Success, Default::default()).unwrap();
    }
    let d = c(dir.path().to_str().unwrap());
    unsafe {
        let page: Value = serde_json::from_str(&take(bastion_audit_read_json(d.as_ptr(), 0, 2, null_mut())).unwrap()).unwrap();
        assert_eq!(page["total"], 3);
        assert_eq!(page["records"][0]["action"], "third");
        assert_eq!(page["records"].as_array().unwrap().len(), 2);
        let check: Value = serde_json::from_str(&take(bastion_audit_verify_json(d.as_ptr(), null_mut())).unwrap()).unwrap();
        assert_eq!(check, serde_json::json!({"intact": true, "records": 3, "changedAt": null}));
    }
    let path = dir.path().join("audit.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replacen("second", "SECOND", 1)).unwrap();
    unsafe {
        let check: Value = serde_json::from_str(&take(bastion_audit_verify_json(d.as_ptr(), null_mut())).unwrap()).unwrap();
        assert_eq!(check["intact"], false);
        assert_eq!(check["changedAt"], 3);
    }
}

#[test]
fn a_null_data_dir_is_refused() {
    unsafe {
        let mut err = null_mut();
        assert!(bastion_audit_read_json(std::ptr::null(), 0, 10, &mut err).is_null());
        assert!(take(err).unwrap().contains("data_dir"));
    }
}
