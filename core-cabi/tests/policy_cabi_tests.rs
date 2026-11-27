//! The managed policy through the C ABI. The core loads it once per process, so this file holds one test: a
//! test policy (`BASTION_UI_SCRIPT` + `BASTION_UI_POLICY`, the core's UI-test hook without the owner check)
//! that denies RDP must refuse RDP, allow SSH and show in the state JSON.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;

use bastion_cabi::*;

unsafe fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    bastion_string_free(p);
    Some(s)
}

fn check(protocol: &str) -> Result<(), String> {
    let p = CString::new(protocol).unwrap();
    let mut err = null_mut();
    let rc = unsafe { bastion_policy_check_protocol(p.as_ptr(), &mut err) };
    if rc == 0 { Ok(()) } else { Err(unsafe { take(err) }.expect("an error message")) }
}

#[test]
fn managed_policy_denies_rdp_and_reports_it() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("policy.json");
    std::fs::write(&file, br#"{"denied_protocols":["rdp"],"forbid_osc52_write":true,"session_login_reuse_minutes":10}"#).unwrap();
    std::env::set_var("BASTION_UI_SCRIPT", "1");
    std::env::set_var("BASTION_UI_POLICY", &file);

    let state: serde_json::Value = serde_json::from_str(&unsafe { take(bastion_policy_state_json()) }.unwrap()).unwrap();
    assert_eq!(state["source"], file.display().to_string());
    assert!(state["error"].is_null());
    assert_eq!(state["deniedProtocols"], serde_json::json!(["rdp"]));
    assert_eq!(state["forbidOsc52Write"], true);
    assert_eq!(state["sessionLoginReuseMinutes"], 10, "A1-CORE-02: the managed maximum is in the view Windows reads");
    assert!(state["managedPath"].as_str().unwrap().ends_with("policy.json"));

    // ABI 105: the user's value under the managed maximum of 10, and the helper.
    assert_eq!(bastion_session_login_reuse_minutes(0), 10, "user 0 (until Lock) under a maximum of 10");
    assert_eq!(bastion_session_login_reuse_minutes(60), 10, "the managed maximum wins");
    assert_eq!(bastion_session_login_reuse_minutes(5), 5, "the user's shorter value stays");
    let at = 1_700_000_000;
    assert_eq!(bastion_remembered_login_usable(at, at + 4 * 60 + 59, 5), 1);
    assert_eq!(bastion_remembered_login_usable(at, at + 5 * 60, 5), 0);
    assert_eq!(bastion_remembered_login_usable(at, at - 1, 5), 0, "clock went backwards");
    assert_eq!(bastion_remembered_login_usable(at, at + 1_000_000, 0), 1, "0: until Lock or quit");

    let refused = check("rdp").unwrap_err();
    assert!(refused.to_lowercase().contains("rdp"), "{refused}");
    check("ssh").unwrap();
    check("web").unwrap();
    assert!(check("gopher").unwrap_err().contains("unknown protocol"));
    let mut err = null_mut();
    assert_eq!(unsafe { bastion_policy_check_protocol(std::ptr::null(), &mut err) }, -1);
    assert!(unsafe { take(err) }.unwrap().contains("required"));
}
