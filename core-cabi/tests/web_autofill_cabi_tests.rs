//! B13 over the C ABI, as the Windows web tab calls it. The full fill (vault release, audit
//! contents) is covered in core-ffi `webautofill::tests`; this checks the wrappers and the JSON.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use serde_json::Value;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn json(p: *mut c_char) -> Value {
    assert!(!p.is_null(), "expected a string");
    let v = serde_json::from_str(CStr::from_ptr(p).to_str().unwrap()).unwrap();
    bastion_string_free(p);
    v
}

#[test]
fn offered_follows_the_switch_and_refusals_come_back_as_json() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let mut err: *mut c_char = null_mut();
        let lib = bastion_library_open(c(dir.path().join("lib.json").to_str().unwrap()).as_ptr(), &mut err);
        let v = ephemeral_handle_for_tests(dir.path().join("c.vault").to_str().unwrap()).unwrap();
        let id_ptr = bastion_library_add_connection(lib, null(), c("Admin").as_ptr(), c("web").as_ptr(), c("https://admin.example.com").as_ptr(), -1, null(), &mut err);
        let id = CStr::from_ptr(id_ptr).to_str().unwrap().to_string();
        bastion_string_free(id_ptr);

        assert_eq!(bastion_web_autofill_offered(lib, c(&id).as_ptr(), &mut err), 0, "off by default");
        let off = json(bastion_credentials_web_autofill_json(v, lib, c(&id).as_ptr(), null(), c("https://admin.example.com/").as_ptr(), 1, 1, &mut err));
        assert_eq!((off["code"].as_str(), off["script"].is_null()), (Some("off"), true));

        assert_eq!(bastion_library_set_property(lib, c(&id).as_ptr(), c("web_autofill").as_ptr(), c("true").as_ptr(), &mut err), 0);
        assert_eq!(bastion_web_autofill_offered(lib, c(&id).as_ptr(), &mut err), 1);
        let evil = json(bastion_credentials_web_autofill_json(v, lib, c(&id).as_ptr(), null(), c("https://admin.example.com.evil.net/").as_ptr(), 1, 1, &mut err));
        assert_eq!(evil["code"], "origin-mismatch");
        assert!(evil["message"].as_str().unwrap().contains("admin.example.com.evil.net"));
        let frame = json(bastion_credentials_web_autofill_json(v, lib, c(&id).as_ptr(), null(), c("https://admin.example.com/").as_ptr(), 0, 1, &mut err));
        assert_eq!(frame["code"], "sub-frame");
        let none = json(bastion_credentials_web_autofill_json(v, lib, c(&id).as_ptr(), null(), c("https://admin.example.com/").as_ptr(), 1, 1, &mut err));
        assert_eq!((none["code"].as_str(), none["script"].is_null()), (Some("no-credential"), true));

        assert_eq!(bastion_web_autofill_offered(lib, c("not-an-id").as_ptr(), &mut err), -1);
        assert!(!err.is_null());
        bastion_string_free(err);
        bastion_credentials_free(v);
        bastion_library_free(lib);
    }
}
