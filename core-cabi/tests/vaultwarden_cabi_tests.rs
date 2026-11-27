//! Vaultwarden through the C ABI. Offline: a fresh session is locked, refuses bad input without
//! remembering anything, and item assignments round-trip through the library JSON. Live (set
//! `BASTION_VAULTWARDEN_TEST=<url>,<email>,<password>` for an account with at least one login
//! item, e.g. seeded by core's `BASTION_VAULTWARDEN_SEED=1` test): unlock, list, re-sync, lock,
//! and a wrong password reported as `VAULTWARDEN_AUTH_FAILED`.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

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

unsafe fn open(dir: &std::path::Path) -> *mut BastionVaultwarden {
    let mut err = null_mut();
    let v = bastion_vaultwarden_open(c(dir.to_str().unwrap()).as_ptr(), &mut err);
    assert!(!v.is_null() && err.is_null());
    v
}

unsafe fn unlock(v: *const BastionVaultwarden, url: &str, email: &str, pw: &str) -> (i32, Option<Value>, String) {
    let (mut outcome, mut err) = (-1, null_mut());
    let json = bastion_vaultwarden_unlock(v, c(url).as_ptr(), c(email).as_ptr(), pw.as_ptr(), pw.len(), null(), &mut outcome, &mut err);
    let value = (!json.is_null()).then(|| serde_json::from_str(&take(json)).unwrap());
    let message = if err.is_null() { String::new() } else { take(err) };
    (outcome, value, message)
}

#[test]
fn a_new_session_is_locked_and_bad_input_is_refused_without_remembering() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let v = open(dir.path());
        assert_eq!(bastion_vaultwarden_is_unlocked(v), 0);
        let mut err = null_mut();
        let items: Value = serde_json::from_str(&take(bastion_vaultwarden_items_json(v, &mut err))).unwrap();
        assert_eq!(items, serde_json::json!({ "items": [], "skipped": 0 }));

        let (outcome, items, message) = unlock(v, "http://vault.example.com", "a@b.c", "pw");
        assert_eq!((outcome, items.is_none()), (VAULTWARDEN_FAILED, true), "plain http off loopback refused: {message}");
        let (outcome, _, message) = unlock(v, "https://vault.example.com", "a@b.c", "");
        assert_eq!(outcome, VAULTWARDEN_FAILED);
        assert!(message.contains("required"), "{message}");

        let config: Value = serde_json::from_str(&take(bastion_vaultwarden_config_json(v, &mut err))).unwrap();
        assert!(config["serverUrl"].is_null() && config["email"].is_null(), "a failed unlock remembers nothing");
        assert!(!dir.path().join("vaultwarden.json").exists());

        assert!(bastion_vaultwarden_resync(v, &mut err).is_null(), "re-sync needs an unlock first");
        assert!(take(err).contains("locked"));
        bastion_vaultwarden_lock(v);
        bastion_vaultwarden_free(v);
    }
}

#[test]
fn null_handles_fail_cleanly() {
    unsafe {
        let mut err = null_mut();
        assert!(bastion_vaultwarden_items_json(null(), &mut err).is_null());
        assert!(take(err).contains("NULL"));
        assert_eq!(bastion_vaultwarden_is_unlocked(null()), 0);
        bastion_vaultwarden_lock(null());
        bastion_vaultwarden_free(null_mut());
        let mut outcome = -1;
        assert!(bastion_vaultwarden_unlock(null(), c("https://x").as_ptr(), c("a@b.c").as_ptr(), null(), 0, null(), &mut outcome, &mut err).is_null());
        assert_eq!(outcome, VAULTWARDEN_FAILED);
        take(err);
        assert_eq!(bastion_session_set_vaultwarden(null(), null(), &mut err), -1);
        take(err);
    }
}

#[test]
fn item_assignment_round_trips_through_the_library() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("library.json");
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(path.to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let id = take(bastion_library_add_connection(lib, null(), c("web").as_ptr(), c("ssh").as_ptr(), c("web.example").as_ptr(), -1, null(), &mut err));
        assert_eq!(bastion_library_set_vaultwarden_item(lib, c(&id).as_ptr(), c("item-123").as_ptr(), &mut err), 0, "set failed");
        assert_eq!(bastion_library_save(lib, &mut err), 0);
        bastion_library_free(lib);

        let lib = bastion_library_open(c(path.to_str().unwrap()).as_ptr(), &mut err);
        let tree: Value = serde_json::from_str(&take(bastion_library_tree_json(lib, &mut err))).unwrap();
        assert_eq!(tree["connections"][0]["vaultwardenItem"], "item-123", "kept across a reopen");
        assert_eq!(bastion_library_set_vaultwarden_item(lib, c(&id).as_ptr(), null(), &mut err), 0);
        let tree: Value = serde_json::from_str(&take(bastion_library_tree_json(lib, &mut err))).unwrap();
        assert!(tree["connections"][0]["vaultwardenItem"].is_null(), "cleared");
        assert_eq!(bastion_library_set_vaultwarden_item(lib, c("not-an-id").as_ptr(), c("x").as_ptr(), &mut err), -1);
        take(err);
        bastion_library_free(lib);
    }
}

#[ignore = "live: needs BASTION_VAULTWARDEN_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn live_unlock_list_resync_and_lock() {
    assert!(std::env::var_os("BASTION_VAULTWARDEN_TEST").is_some(), "live test run without BASTION_VAULTWARDEN_TEST: start the fixture (docs/TESTING.md)");
    let Ok(spec) = std::env::var("BASTION_VAULTWARDEN_TEST") else {
        eprintln!("SKIPPED live_unlock_list_resync_and_lock: set BASTION_VAULTWARDEN_TEST=url,email,password");
        return;
    };
    let parts: Vec<&str> = spec.splitn(3, ',').collect();
    let (url, email, pw) = (parts[0], parts[1], parts[2]);
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let v = open(dir.path());
        let (outcome, _, message) = unlock(v, url, email, "definitely-not-the-password");
        assert_eq!(outcome, VAULTWARDEN_AUTH_FAILED, "wrong password: {message}");
        assert_eq!(bastion_vaultwarden_is_unlocked(v), 0);

        let (outcome, items, message) = unlock(v, url, email, pw);
        assert_eq!(outcome, VAULTWARDEN_OK, "{message}");
        let items = items.unwrap();
        let list = items["items"].as_array().unwrap();
        assert!(!list.is_empty(), "the account needs at least one login item");
        assert!(list.iter().all(|i| i["id"].is_string() && i["name"].is_string()));
        assert!(!items.to_string().contains(pw), "no secret in the listing");
        assert_eq!(bastion_vaultwarden_is_unlocked(v), 1);

        let mut err = null_mut();
        let config: Value = serde_json::from_str(&take(bastion_vaultwarden_config_json(v, &mut err))).unwrap();
        assert_eq!((config["serverUrl"].as_str(), config["email"].as_str()), (Some(url), Some(email)));
        let saved = std::fs::read_to_string(dir.path().join("vaultwarden.json")).unwrap();
        assert!(!saved.contains(pw), "the master password is never written");

        let again: Value = serde_json::from_str(&take(bastion_vaultwarden_resync(v, &mut err))).unwrap();
        assert_eq!(again["items"].as_array().unwrap().len(), list.len());

        bastion_vaultwarden_lock(v);
        assert_eq!(bastion_vaultwarden_is_unlocked(v), 0);
        assert!(bastion_vaultwarden_resync(v, &mut err).is_null(), "locked: the refresh token is gone");
        take(err);
        bastion_vaultwarden_free(v);
    }
}
