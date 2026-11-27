//! External providers through the C ABI, offline: a synthetic KeePass file (unlock, list,
//! check without revealing, lock), Vault and 1Password argument checks.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use keepass::db::fields;
use keepass::{Database, DatabaseKey};
use serde_json::Value;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> Value {
    assert!(!p.is_null(), "expected a string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    serde_json::from_str(&s).unwrap()
}

fn kdbx(dir: &std::path::Path) -> (std::path::PathBuf, String) {
    let mut db = Database::new();
    let id;
    {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "router");
        e.set_unprotected(fields::USERNAME, "admin");
        e.set_protected(fields::PASSWORD, "kp-pass");
        id = e.id().uuid().to_string();
    }
    let path = dir.join("lab.kdbx");
    db.save(&mut std::fs::File::create(&path).unwrap(), DatabaseKey::new().with_password("master")).unwrap();
    (path, id)
}

#[test]
fn keepass_unlock_list_check_and_lock() {
    let d = tempfile::tempdir().unwrap();
    let (path, id) = kdbx(d.path());
    let mut err = null_mut();
    unsafe {
        let p = bastion_provider_open_keepass(c(path.to_str().unwrap()).as_ptr(), &mut err);
        assert!(!p.is_null() && err.is_null());
        assert_eq!(take(bastion_provider_status_json(p, &mut err))["status"], "locked");
        let wrong = b"nope";
        assert_eq!(bastion_provider_unlock(p, wrong.as_ptr(), wrong.len(), null(), &mut err), PROVIDER_AUTH_FAILED);
        let pw = b"master";
        assert_eq!(bastion_provider_unlock(p, pw.as_ptr(), pw.len(), null(), &mut err), PROVIDER_OK);
        let st = take(bastion_provider_status_json(p, &mut err));
        assert_eq!((st["id"].as_str(), st["status"].as_str()), (Some("keepass"), Some("available")));
        let items = take(bastion_provider_items_json(p, &mut err));
        assert_eq!(items["items"][0]["title"], "router");
        assert_eq!(items["items"][0]["username"], "admin");
        assert!(!items.to_string().contains("kp-pass"), "listing never carries secrets");
        assert_eq!(bastion_provider_check_item(p, c(&id).as_ptr(), &mut err), PROVIDER_OK);
        assert_eq!(bastion_provider_check_item(p, c(&format!("{id}#url")).as_ptr(), &mut err), PROVIDER_NOT_FOUND);
        bastion_provider_lock(p);
        assert_eq!(bastion_provider_check_item(p, c(&id).as_ptr(), &mut err), PROVIDER_AUTH_FAILED);
        bastion_provider_free(p);
    }
}

#[test]
fn bad_arguments_are_refused() {
    let mut err = null_mut();
    unsafe {
        assert!(bastion_provider_open_hcvault(c("http://vault.example.com").as_ptr(), 2, null(), &mut err).is_null(), "plain http off loopback");
        assert!(!err.is_null());
        bastion_string_free(err);
        err = null_mut();
        assert!(bastion_provider_open_hcvault(c("https://vault.example.com").as_ptr(), 3, null(), &mut err).is_null());
        bastion_string_free(err);
        err = null_mut();
        let v = bastion_provider_open_hcvault(c("https://vault.example.com").as_ptr(), 2, null(), &mut err);
        assert!(!v.is_null());
        assert_eq!(bastion_provider_unlock(v, null(), 0, null(), &mut err), -1, "a token is required");
        bastion_string_free(err);
        err = null_mut();
        assert_eq!(take(bastion_provider_items_json(v, &mut err))["items"], serde_json::json!([]));
        bastion_provider_free(v);
        assert!(bastion_provider_open_onepassword(c("/nonexistent/op").as_ptr(), null(), &mut err).is_null());
        bastion_string_free(err);
        err = null_mut();
        assert_eq!(bastion_provider_check_item(null(), c("x").as_ptr(), &mut err), -1);
        bastion_string_free(err);
    }
}
