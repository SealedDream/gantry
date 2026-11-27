//! Password generator and `$Name$` variables through the C ABI (26).
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::textgen::*;
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
fn abi_version_includes_26() {
    assert!(bastion_abi_version() >= 26);
}

#[test]
fn generates_passwords_of_the_asked_length_and_rates_them() {
    unsafe {
        let mut err = null_mut();
        let pw = take(bastion_generate_password(24, &mut err));
        assert_eq!(pw.chars().count(), 24);
        assert!(bastion_password_strength_bits(c(&pw).as_ptr()) > 100.0);
        assert!(bastion_password_strength_bits(c("abc").as_ptr()) < bastion_password_strength_bits(c(&pw).as_ptr()));
        assert_eq!(bastion_password_strength_bits(null()), 0.0);
        assert!(bastion_generate_password(4, &mut err).is_null(), "too short refused");
        assert!(take(err).contains("12"));
    }
}

#[test]
fn substitutes_plain_variables_and_refuses_secrets() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(dir.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let id = take(bastion_library_add_connection(lib, null(), c("lab").as_ptr(), c("ssh").as_ptr(), c("lab.example").as_ptr(), 2222, c("me").as_ptr(), &mut err));
        let vars: Value = serde_json::from_str(&take(bastion_library_variables_json(lib, c(&id).as_ptr(), &mut err))).unwrap();
        assert!(vars["plain"].as_array().unwrap().iter().any(|v| v["name"] == "Host" && v["value"] == "lab.example"));
        assert!(vars["secret"].as_array().unwrap().iter().any(|v| v == "Password"));
        let out = take(bastion_library_substitute(lib, c(&id).as_ptr(), c("ssh $Username$@$Host$ -p $Port$ $$5").as_ptr(), &mut err));
        assert_eq!(out, "ssh me@lab.example -p 2222 $5");
        assert!(bastion_library_substitute(lib, c(&id).as_ptr(), c("echo $Password$").as_ptr(), &mut err).is_null());
        assert!(!take(err).contains('\0'));
        assert!(bastion_library_substitute(lib, c(&id).as_ptr(), c("$Nope$").as_ptr(), &mut err).is_null());
        assert!(take(err).contains("unknown"));
        bastion_library_free(lib);
    }
}
