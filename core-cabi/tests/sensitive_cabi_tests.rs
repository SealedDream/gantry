//! Per-connection sensitive lookup (ABI 77), for the Windows broadcast confirmation.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::wol::bastion_library_connection_sensitive;
use bastion_cabi::*;

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
fn abi_version_is_at_least_77() {
    assert!(bastion_abi_version() >= 77);
}

#[test]
fn each_classification_makes_a_connection_sensitive() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        for (key, value) in [("environment", "production"), ("customer_sensitive", "true"), ("privileged", "true")] {
            let id = take(bastion_library_add_connection(lib, null(), c(key).as_ptr(), c("ssh").as_ptr(), c("10.0.0.1").as_ptr(), 22, null(), &mut err)).unwrap();
            let mut err = null_mut();
            assert_eq!(bastion_library_connection_sensitive(lib, c(&id).as_ptr(), &mut err), 0, "{key}: plain host is not sensitive");
            assert_eq!(bastion_library_set_property(lib, c(&id).as_ptr(), c(key).as_ptr(), c(value).as_ptr(), &mut err), 0, "{:?}", take(err));
            assert_eq!(bastion_library_connection_sensitive(lib, c(&id).as_ptr(), &mut err), 1, "{key}={value}");
        }
        let mut err = null_mut();
        assert_eq!(bastion_library_connection_sensitive(lib, c("00000000-0000-0000-0000-000000000000").as_ptr(), &mut err), -1);
        assert!(take(err).is_some());
        let mut err = null_mut();
        assert_eq!(bastion_library_connection_sensitive(lib, null(), &mut err), -1);
        assert!(take(err).is_some());
        bastion_library_free(lib);
    }
}
