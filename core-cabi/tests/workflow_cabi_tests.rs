//! Inspector data through the C ABI: notes saved with the library, and the effective values and
//! personal overrides of a host imported from an OpenSSH config (the Windows inspector's Network
//! section and its Personal Overrides dialog).
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

/// A library with one manual connection and one host imported from a config that needs a placeholder.
unsafe fn fixture(dir: &std::path::Path) -> (*mut BastionLibrary, String, String, String) {
    let ssh = dir.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("config"), "Host build\n  HostName build.corp.example\n  User <your-user>\n  Port 2200\n").unwrap();
    let root = ssh.to_str().unwrap().to_string();
    let mut err = null_mut();
    let lib = bastion_library_open(c(dir.join("library.json").to_str().unwrap()).as_ptr(), &mut err);
    let manual = take(bastion_library_add_connection(lib, null(), c("lab").as_ptr(), c("ssh").as_ptr(), c("lab.example").as_ptr(), -1, c("me").as_ptr(), &mut err));
    let scan: Value = serde_json::from_str(&take(bastion_ssh_scan_json(c(&root).as_ptr(), null(), &mut err))).unwrap();
    let ids = serde_json::to_string(&[scan["hosts"][0]["identity"].as_str().unwrap()]).unwrap();
    assert_eq!(bastion_library_import_ssh_hosts(lib, c(&root).as_ptr(), null(), c(&ids).as_ptr(), &mut err), 1);
    let tree: Value = serde_json::from_str(&take(bastion_library_tree_json(lib, &mut err))).unwrap();
    let imported = find(&tree, "build.corp.example").expect("imported connection");
    (lib, manual, imported, root)
}

fn find(folder: &Value, host: &str) -> Option<String> {
    for conn in folder["connections"].as_array().into_iter().flatten() {
        if conn["host"] == host {
            return conn["id"].as_str().map(str::to_string);
        }
    }
    folder["folders"].as_array().into_iter().flatten().find_map(|f| find(f, host))
}

#[test]
fn notes_round_trip_through_save_and_reopen() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let (lib, manual, _, _) = fixture(d.path());
        let mut err = null_mut();
        assert_eq!(take(bastion_library_notes(lib, c(&manual).as_ptr(), &mut err)), "");
        assert_eq!(bastion_library_set_notes(lib, c(&manual).as_ptr(), c("Patch window: Sunday 02:00\nOn call: ops").as_ptr(), &mut err), 0);
        assert_eq!(bastion_library_save(lib, &mut err), 0);
        bastion_library_free(lib);
        let again = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert_eq!(take(bastion_library_notes(again, c(&manual).as_ptr(), &mut err)), "Patch window: Sunday 02:00\nOn call: ops");
        assert!(bastion_library_notes(again, c("not-an-id").as_ptr(), &mut err).is_null());
        take(err);
        bastion_library_free(again);
    }
}

#[test]
fn effective_values_are_null_for_manual_connections() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let (lib, manual, _, _) = fixture(d.path());
        let mut err = null_mut();
        let data = c(d.path().to_str().unwrap());
        assert_eq!(take(bastion_ssh_effective_json(data.as_ptr(), lib, c(&manual).as_ptr(), &mut err)), "null");
        bastion_library_free(lib);
    }
}

#[test]
fn overrides_change_the_effective_values_and_blank_means_source() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let (lib, _, imported, _) = fixture(d.path());
        let mut err = null_mut();
        let data = c(d.path().to_str().unwrap());
        let eff: Value = serde_json::from_str(&take(bastion_ssh_effective_json(data.as_ptr(), lib, c(&imported).as_ptr(), &mut err))).unwrap();
        assert_eq!((eff["hostname"].as_str(), eff["port"].as_u64()), (Some("build.corp.example"), Some(2200)), "{eff}");
        assert_eq!(eff["unresolved"][0], "your-user", "the placeholder still needs an answer: {eff}");
        let identity = eff["identity"].as_str().unwrap().to_string();

        let empty: Value = serde_json::from_str(&take(bastion_ssh_override_json(data.as_ptr(), c(&identity).as_ptr(), &mut err))).unwrap();
        assert!(empty["port"].is_null() && empty["user"].is_null(), "{empty}");

        let set = r#"{"user":"","hostname":"build-2.corp.example","port":2201,"identityFile":"  ","proxyJump":null,"placeholders":{"your-user":"mo","unused":" "}}"#;
        assert_eq!(bastion_ssh_set_override(data.as_ptr(), c(&identity).as_ptr(), c(set).as_ptr(), &mut err), 0);
        let eff: Value = serde_json::from_str(&take(bastion_ssh_effective_json(data.as_ptr(), lib, c(&imported).as_ptr(), &mut err))).unwrap();
        assert_eq!((eff["hostname"].as_str(), eff["port"].as_u64(), eff["user"].as_str()), (Some("build-2.corp.example"), Some(2201), Some("mo")), "{eff}");
        assert!(eff["unresolved"].as_array().unwrap().is_empty(), "{eff}");
        let back: Value = serde_json::from_str(&take(bastion_ssh_override_json(data.as_ptr(), c(&identity).as_ptr(), &mut err))).unwrap();
        assert!(back["user"].is_null() && back["identityFile"].is_null(), "blank strings are not stored: {back}");
        assert_eq!(back["placeholders"], serde_json::json!({ "your-user": "mo" }));
        assert!(d.path().join("ssh-workflow.json").is_file(), "saved at once");

        for bad in [r#"{"port":0}"#, r#"{"port":70000}"#, r#"{"port":"22"}"#, "not json", r#"{"placeholders":[1]}"#] {
            assert_eq!(bastion_ssh_set_override(data.as_ptr(), c(&identity).as_ptr(), c(bad).as_ptr(), &mut err), -1, "{bad}");
            take(err);
        }
        let still: Value = serde_json::from_str(&take(bastion_ssh_override_json(data.as_ptr(), c(&identity).as_ptr(), &mut err))).unwrap();
        assert_eq!(still["port"], 2201, "a refused change keeps the saved overrides");
        bastion_library_free(lib);
    }
}
