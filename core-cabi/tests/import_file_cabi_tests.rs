//! Connection-file import over the C ABI (ABI 76), as the Windows app uses it: PuTTY `.reg`,
//! Royal TS `.json` and RDCMan `.rdg` from `tests/fixtures/import`; passwords are never imported.
use std::ffi::{c_char, CStr, CString};
use std::path::PathBuf;
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use serde_json::Value;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/import").join(name).to_string_lossy().into_owned()
}

unsafe fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    Some(s)
}

unsafe fn import(lib: *mut BastionLibrary, name: &str) -> Result<Value, String> {
    let mut err = null_mut();
    let r = bastion_library_import_file_json(lib, c(&fixture(name)).as_ptr(), &mut err);
    match take(r) {
        Some(j) => Ok(serde_json::from_str(&j).unwrap()),
        None => Err(take(err).unwrap_or_default()),
    }
}

#[test]
fn abi_version_is_at_least_76() {
    assert!(bastion_abi_version() >= 76);
}

#[test]
fn putty_royal_and_rdcman_files_land_in_their_own_folders_without_passwords() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let putty = import(lib, "sessions.reg").unwrap();
        assert_eq!((putty["format"].as_str(), putty["connections"].as_u64()), (Some("PuTTY sessions"), Some(2)), "{putty}");
        let royal = import(lib, "royal.json").unwrap();
        assert_eq!(royal["connections"], 2, "{royal}");
        assert!(royal["skipped"].as_array().unwrap().iter().any(|s| s.as_str().unwrap().to_lowercase().contains("password") || s.as_str().unwrap().contains("Credential")), "{royal}");
        let rdg = import(lib, "lab.rdg").unwrap();
        assert_eq!(rdg["connections"], 1, "{rdg}");
        assert_eq!(bastion_library_save(lib, &mut err), 0);

        // Three new top-level folders, and no secret from any file reached the library on disk.
        let saved = std::fs::read_to_string(d.path().join("library.json")).unwrap();
        assert!(!saved.contains("not-a-real-secret") && !saved.contains("AQAAANCMnd8BFdER"), "a password was imported");
        for (folder, host) in [(&putty, "web.example.com"), (&royal, "web.prod"), (&rdg, "srv1.example.com")] {
            assert!(folder["folder"].as_str().is_some_and(|f| saved.contains(f)), "folder saved");
            assert!(saved.contains(host), "{host} imported");
        }
        bastion_library_free(lib);
    }
}

#[test]
fn unknown_types_empty_files_and_bad_arguments_are_refused() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(import(lib, "notes.txt").unwrap_err().contains(".rdg"), "names the supported types");
        let empty = import(lib, "empty.csv").unwrap_err();
        assert!(empty.contains("no connections") || empty.to_lowercase().contains("csv"), "{empty}");
        assert!(import(lib, "missing.reg").is_err());
        let mut err = null_mut();
        assert!(bastion_library_import_file_json(null(), c("x.csv").as_ptr(), &mut err).is_null());
        take(err);
        let mut err = null_mut();
        assert!(bastion_library_import_file_json(lib, null(), &mut err).is_null());
        take(err);
        bastion_library_free(lib);
    }
}

#[test]
fn mremoteng_xml_imports_without_passwords_and_lists_skipped() {
    assert!(bastion_abi_version() >= 119);
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let r = import(lib, "confCons.xml").unwrap();
        assert_eq!((r["format"].as_str(), r["connections"].as_u64()), (Some("mRemoteNG"), Some(5)), "{r}");
        let skipped: Vec<&str> = r["skipped"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
        assert_eq!(skipped.len(), 6, "{r}");
        assert!(skipped.iter().any(|s| s.contains("RAW")) && skipped.iter().any(|s| s.contains("password not imported")), "{r}");
        assert_eq!(bastion_library_save(lib, &mut err), 0);
        let saved = std::fs::read_to_string(d.path().join("library.json")).unwrap();
        assert!(!saved.contains("secret-cipher") && !saved.contains("calc.exe"), "a password or script field was imported");
        assert!(saved.contains("dc01.corp.lan"));
        bastion_library_free(lib);
    }
}
