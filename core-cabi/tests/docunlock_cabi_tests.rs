//! Document-first launch over the C ABI (ABI 81): back-off, state folder, recent details, auto-lock.
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

const PW: &[u8] = b"document password";

#[test]
fn back_off_state_dir_and_recent_details() {
    let d = tempfile::tempdir().unwrap();
    let dir = c(d.path().to_str().unwrap());
    let path = c(d.path().join("Work.bastion").to_str().unwrap());
    unsafe {
        let mut err = null_mut();
        let doc = bastion_document_create(c("Work").as_ptr(), dir.as_ptr(), &mut err);
        assert_eq!(bastion_document_set_password(doc, PW.as_ptr(), PW.len(), &mut err), 0);
        assert_eq!(bastion_document_save(doc, path.as_ptr(), &mut err), 0);
        bastion_document_free(doc);

        let doc = bastion_document_open(path.as_ptr(), dir.as_ptr(), &mut err);
        let rows: Value = serde_json::from_str(&take(bastion_documents_recent_details_json(dir.as_ptr(), &mut err)).unwrap()).unwrap();
        assert_eq!((rows[0]["name"].as_str(), rows[0]["present"].as_bool(), rows[0]["protected"].as_bool()), (Some("Work"), Some(true), Some(true)));
        assert!(rows[0]["lastOpenedAt"].as_u64().unwrap() > 1_700_000_000);

        let bad = b"wrong password";
        for _ in 0..5 {
            assert_eq!(bastion_document_unlock(doc, bad.as_ptr(), bad.len(), &mut err), -1);
            take(err);
            err = null_mut();
        }
        let s: Value = serde_json::from_str(&take(bastion_document_unlock_status_json(doc, &mut err)).unwrap()).unwrap();
        assert_eq!(s["failures"], 5);
        assert!(s["waitSecs"].as_u64().unwrap() > 25);
        // Even the right password waits.
        assert_eq!(bastion_document_unlock(doc, PW.as_ptr(), PW.len(), &mut err), -1);
        assert!(take(err).unwrap().contains("try again"));
        err = null_mut();

        let state = take(bastion_document_state_dir(doc, &mut err)).unwrap();
        assert!(std::path::Path::new(&state).is_dir() && state.contains("documents"));
        bastion_document_free(doc);
    }
    assert_eq!(bastion_document_auto_lock_due(15, 900, 0, 0, 0), 1);
    assert_eq!(bastion_document_auto_lock_due(15, 10, 1, 0, 0), 2);
    assert_eq!(bastion_document_auto_lock_due(15, 10, 0, 1, 0), 3);
    assert_eq!(bastion_document_auto_lock_due(0, 99_999, 0, 0, 0), 0);
    assert_eq!(bastion_effective_auto_lock_minutes(0, 10), 10);
    assert_eq!(bastion_effective_auto_lock_minutes(0, 0), 0);
}

#[test]
fn without_a_managed_policy_biometrics_are_allowed_and_minutes_pass_through() {
    assert_eq!(bastion_document_biometric_unlock_allowed(), 1);
    assert_eq!(bastion_document_auto_lock_minutes(15), 15);
    assert_eq!(bastion_document_auto_lock_minutes(0), 0);
}
