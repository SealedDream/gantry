//! The credential vault through the C ABI, with the real platform key store (DPAPI on Windows).
//! Checks that secrets go in, never come back out, survive a reopen, and can be assigned.
#![cfg(windows)]
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

unsafe fn open(path: &std::path::Path) -> *mut BastionCredentials {
    let mut err = null_mut();
    let v = bastion_credentials_open(c(path.to_str().unwrap()).as_ptr(), &mut err);
    assert!(!v.is_null(), "open failed: {}", if err.is_null() { String::new() } else { take(err) });
    v
}

unsafe fn list(v: *const BastionCredentials) -> Value {
    let mut err = null_mut();
    serde_json::from_str(&take(bastion_credentials_list_json(v, &mut err))).unwrap()
}

unsafe fn save_pw(v: *const BastionCredentials, id: Option<&str>, name: &str, pw: &str, err: &mut *mut c_char) -> *mut c_char {
    let id = id.map(c);
    bastion_credentials_save_password(v, id.as_ref().map_or(null(), |s| s.as_ptr()), c(name).as_ptr(), c("Acme").as_ptr(), c("root").as_ptr(), pw.as_ptr(), pw.len(), err)
}

#[test]
fn secrets_go_in_and_never_come_out() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.vault");
    unsafe {
        let v = open(&path);
        let mut err = null_mut();
        let id = take(save_pw(v, None, "db admin", "s3cret-pw", &mut err));
        assert!(err.is_null());
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAkey-material\n-----END OPENSSH PRIVATE KEY-----\n";
        let kid = take(bastion_credentials_save_ssh_key(v, null(), c("deploy key").as_ptr(), null(), c("deploy").as_ptr(), key.as_ptr(), key.len(), &mut err));
        assert_eq!(bastion_credentials_save(v, &mut err), 0);

        let json = take(bastion_credentials_list_json(v, &mut err));
        assert!(!json.contains("s3cret-pw") && !json.contains("key-material"), "a secret came back out: {json}");
        let l: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(l.as_array().unwrap().len(), 2);
        assert_eq!(l[0]["name"], "db admin");
        assert_eq!(l[0]["kind"], "password");
        assert_eq!(l[1]["kind"], "ssh-key");

        // On disk: sealed vault, DPAPI-wrapped key, neither holds a secret in clear text.
        let raw = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("s3cret-pw"));
        let keys: Vec<_> = std::fs::read_dir(dir.path().join("vault-key")).unwrap().collect();
        assert_eq!(keys.len(), 1, "one DPAPI key blob per vault");
        bastion_credentials_free(v);

        // Reopen: the same DPAPI key unwraps the vault; an update with an empty secret keeps it.
        let v = open(&path);
        assert_eq!(list(v).as_array().unwrap().len(), 2);
        take(save_pw(v, Some(&id), "DB admin", "", &mut err));
        assert!(err.is_null());
        assert_eq!(bastion_credentials_remove(v, c(&kid).as_ptr(), &mut err), 0);
        assert_eq!(list(v)[0]["name"], "DB admin");
        assert_eq!(bastion_credentials_remove(v, c(&kid).as_ptr(), &mut err), -1);
        take(err);
        bastion_credentials_free(v);
    }
}

#[test]
fn invalid_input_is_an_error_not_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let v = open(&dir.path().join("credentials.vault"));
        let mut err = null_mut();
        assert!(save_pw(v, None, " ", "pw", &mut err).is_null());
        assert!(take(err).contains("name"));
        assert!(save_pw(v, None, "n", "", &mut err).is_null());
        assert!(take(err).contains("password"));
        let enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        assert!(bastion_credentials_save_ssh_key(v, null(), c("k").as_ptr(), null(), c("u").as_ptr(), enc.as_ptr(), enc.len(), &mut err).is_null());
        take(err);
        let bad = [0xffu8, 0xfe];
        assert!(bastion_credentials_save_password(v, null(), c("n").as_ptr(), null(), c("u").as_ptr(), bad.as_ptr(), 2, &mut err).is_null());
        assert!(take(err).contains("UTF-8"));
        assert!(bastion_credentials_list_json(null(), &mut err).is_null());
        take(err);
        bastion_credentials_free(v);
        bastion_credentials_free(null_mut());
    }
}

#[test]
fn a_credential_is_assigned_to_a_connection() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let v = open(&dir.path().join("credentials.vault"));
        let mut err = null_mut();
        let cred = take(save_pw(v, None, "admin", "pw", &mut err));
        let lib = bastion_library_open(c(dir.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let conn = take(bastion_library_add_connection(lib, null(), c("web").as_ptr(), c("ssh").as_ptr(), c("web.example").as_ptr(), -1, null(), &mut err));
        assert_eq!(bastion_library_set_credential(lib, c(&conn).as_ptr(), c(&cred).as_ptr(), &mut err), 0);
        let tree: Value = serde_json::from_str(&take(bastion_library_tree_json(lib, &mut err))).unwrap();
        assert_eq!(tree["connections"][0]["credentialId"], cred.as_str());
        assert_eq!(bastion_library_set_credential(lib, c(&conn).as_ptr(), null(), &mut err), 0);
        let tree: Value = serde_json::from_str(&take(bastion_library_tree_json(lib, &mut err))).unwrap();
        assert!(tree["connections"][0]["credentialId"].is_null());
        assert_eq!(bastion_library_set_credential(lib, c("not-a-uuid").as_ptr(), null(), &mut err), -1);
        take(err);
        bastion_library_free(lib);
        bastion_credentials_free(v);
    }
}

unsafe fn import(v: *const BastionCredentials, id: Option<&str>, file: &std::path::Path, pass: &str, err: &mut *mut c_char) -> *mut c_char {
    let id = id.map(c);
    let path = c(file.to_str().unwrap());
    bastion_credentials_import_key_file(
        v, id.as_ref().map_or(null(), |s| s.as_ptr()), c("imported").as_ptr(), null(), c("deploy").as_ptr(), path.as_ptr(),
        if pass.is_empty() { null() } else { pass.as_ptr() }, pass.len(), err,
    )
}

#[test]
fn a_key_file_is_imported_and_decrypted_in_the_core() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.vault");
    unsafe {
        let v = open(&path);
        let mut err = null_mut();
        let plain = take(import(v, None, &fixtures.join("import_plain_ed25519"), "", &mut err));

        // An encrypted key: no passphrase and a wrong one are refused and store nothing.
        let enc = fixtures.join("import_encrypted_ed25519");
        assert!(import(v, None, &enc, "", &mut err).is_null());
        assert!(take(err).contains("passphrase"));
        assert!(import(v, None, &enc, "wrong", &mut err).is_null());
        assert!(take(err).contains("passphrase"));
        assert_eq!(list(v).as_array().unwrap().len(), 1);
        // The right one replaces the key of the existing credential (edit), still one entry.
        let same = take(import(v, Some(&plain), &enc, "fixture-pass", &mut err));
        assert_eq!(same, plain);
        assert_eq!(list(v).as_array().unwrap().len(), 1);

        // Not a key, and a missing file: errors, not crashes.
        let junk = dir.path().join("junk.txt");
        std::fs::write(&junk, "hello").unwrap();
        assert!(import(v, None, &junk, "", &mut err).is_null());
        assert!(take(err).contains("not a private key"));
        assert!(import(v, None, &dir.path().join("missing"), "", &mut err).is_null());
        take(err);
        assert_eq!(bastion_credentials_save(v, &mut err), 0);
        bastion_credentials_free(v);
    }
    // Stored decrypted, without the passphrase, and only in the sealed vault.
    let vault = bastion_ffi::CredentialVault::open(path.to_str().unwrap().to_string()).unwrap();
    let id = vault.list()[0].id.clone();
    let bastion_core::vault::CredentialKind::SshKey { private_key, passphrase, .. } = vault.secret_for(&id).unwrap().0 else { panic!("not a key") };
    assert!(passphrase.is_none(), "the passphrase is not kept");
    let key = private_key.expose();
    assert!(key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") && !key.contains("ENCRYPTED"));
    assert!(russh::keys::decode_secret_key(key, None).is_ok(), "the stored key opens without a passphrase");
    assert!(!String::from_utf8_lossy(&std::fs::read(&path).unwrap()).contains("OPENSSH PRIVATE KEY"));
}
