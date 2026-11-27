//! H10: document failures carry a stable class through the C ABI, so hosts decide on a code
//! instead of the English message.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;

use bastion_cabi::*;

fn last_code() -> String {
    unsafe { CStr::from_ptr(bastion_last_error_code()) }.to_string_lossy().into_owned()
}

#[test]
fn corrupt_document_reports_its_code_and_success_clears_it() {
    let d = tempfile::tempdir().unwrap();
    let bad = d.path().join("bad.bastion");
    std::fs::write(&bad, b"not a bastion document").unwrap();
    let path = CString::new(bad.to_str().unwrap()).unwrap();
    let data = CString::new(d.path().to_str().unwrap()).unwrap();
    let mut err: *mut c_char = null_mut();
    unsafe {
        let h = bastion_document_open(path.as_ptr(), data.as_ptr(), &mut err);
        assert!(h.is_null());
        assert!(!err.is_null(), "message still given");
        bastion_string_free(err);
    }
    assert_eq!(last_code(), "corrupt");

    let name = CString::new("Fresh").unwrap();
    let mut err: *mut c_char = null_mut();
    unsafe {
        let h = bastion_document_create(name.as_ptr(), data.as_ptr(), &mut err);
        assert!(!h.is_null());
        assert_eq!(last_code(), "", "a successful call clears the code");
        // A NULL argument is a bridge-level failure with no finer class.
        assert!(bastion_document_open(std::ptr::null(), data.as_ptr(), &mut err).is_null());
        bastion_string_free(err);
        assert_eq!(last_code(), "other");
        bastion_document_free(h);
    }
}
