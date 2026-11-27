//! B8 KeePass import through the C ABI, with the real platform key store (DPAPI on Windows).
//! The preview carries no secret; the import lands in the sealed vault.
#![cfg(windows)]
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use keepass::db::fields;
use keepass::{Database, DatabaseKey};
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

/// Synthetic KDBX4 file with one entry in "Lab".
fn fixture(dir: &std::path::Path) -> std::path::PathBuf {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut lab = root.add_group();
        lab.name = "Lab".into();
        let mut e = lab.add_entry();
        e.set_unprotected(fields::TITLE, "lab sshd");
        e.set_unprotected(fields::USERNAME, "root");
        e.set_protected(fields::PASSWORD, "kp-s3cret");
    }
    let path = dir.join("Lab.kdbx");
    db.save(&mut std::fs::File::create(&path).unwrap(), DatabaseKey::new().with_password("master")).unwrap();
    path
}

#[test]
fn keepass_preview_and_import() {
    let dir = tempfile::tempdir().unwrap();
    let kdbx = fixture(dir.path());
    let kp = c(kdbx.to_str().unwrap());
    let pw = "master";
    unsafe {
        let mut err = null_mut();
        let v = bastion_credentials_open(c(dir.path().join("credentials.vault").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!v.is_null());
        let json = take(bastion_credentials_keepass_preview_json(v, kp.as_ptr(), pw.as_ptr(), pw.len(), null(), &mut err));
        assert!(!json.contains("kp-s3cret"), "secret in preview: {json}");
        let p: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(p["rows"][0]["status"], "new");
        let r: Value = serde_json::from_str(&take(bastion_credentials_keepass_import_json(v, kp.as_ptr(), pw.as_ptr(), pw.len(), null(), c("skip").as_ptr(), &mut err))).unwrap();
        assert_eq!(r["added"], 1);
        let bad = bastion_credentials_keepass_import_json(v, kp.as_ptr(), b"x".as_ptr(), 1, null(), c("skip").as_ptr(), &mut err);
        assert!(bad.is_null() && !err.is_null());
        bastion_string_free(err);
        bastion_credentials_free(v);
    }
}
