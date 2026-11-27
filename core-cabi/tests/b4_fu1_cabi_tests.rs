//! B4-FOLDER-CONNECT-ALL-FU1 over the C ABI (ABI 109): Connect All applies the managed policy.
//! A type the policy forbids lands in `skippedBlocked` and is not counted. Its own test binary:
//! the effective policy is loaded once per process, here from the UI-test policy file.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::credentials::ephemeral_handle_for_tests;
use bastion_cabi::*;
use serde_json::{json, Value};

const DEFAULT_PORT: i32 = -1;

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
fn a_type_the_managed_policy_forbids_is_skipped_as_blocked() {
    unsafe {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("policy.json");
        std::fs::write(&policy, json!({ "denied_protocols": ["rdp"] }).to_string()).unwrap();
        // Read once, before the first policy use in this process (the only test in this binary).
        std::env::set_var("BASTION_UI_SCRIPT", "1");
        std::env::set_var("BASTION_UI_POLICY", &policy);

        let mut err = null_mut();
        let lib = bastion_library_open(c(dir.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let vault = ephemeral_handle_for_tests(dir.path().join("c.vault").to_str().unwrap()).unwrap();
        let cred = take(bastion_credentials_save_password(vault, null(), c("ops").as_ptr(), null(), c("root").as_ptr(), b"x".as_ptr(), 1, &mut err));
        let folder = take(bastion_library_add_folder(lib, null(), c("Prod").as_ptr(), &mut err));
        let add = |name: &str, protocol: &str, host: &str| {
            let mut err = null_mut();
            let id = take(bastion_library_add_connection(lib, c(&folder).as_ptr(), c(name).as_ptr(), c(protocol).as_ptr(), c(host).as_ptr(), DEFAULT_PORT, null(), &mut err));
            assert_eq!(bastion_library_set_credential(lib, c(&id).as_ptr(), c(&cred).as_ptr(), &mut err), 0);
            id
        };
        let ssh = add("ssh", "ssh", "a.example");
        let rdp = add("rdp", "rdp", "b.example");

        let p = bastion_credentials_plan_connect_all_json(vault, lib, c(&folder).as_ptr(), null(), &mut err);
        assert!(err.is_null());
        let plan: Value = serde_json::from_str(&take(p)).unwrap();

        assert_eq!(plan["ready"], json!([ssh]));
        assert_eq!(plan["skippedBlocked"], json!([rdp]));
        assert_eq!(plan["needsLogin"], json!([]));
        assert_eq!(plan["toConnect"], 1, "a blocked connection is not counted");

        bastion_credentials_free(vault);
        bastion_library_free(lib);
    }
}
