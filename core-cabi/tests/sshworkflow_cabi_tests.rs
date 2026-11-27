//! The shared-config workflow through the C ABI (89): settings, placeholders, import with a
//! baseline, then a refresh preview after the config changes and applying it.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;

use bastion_cabi::*;
use serde_json::{json, Value};

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> String {
    assert!(!p.is_null(), "expected a string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    s
}

unsafe fn changes(data: &CString) -> Value {
    let mut err = null_mut();
    serde_json::from_str(&take(bastion_ssh_workflow_changes_json(data.as_ptr(), &mut err))).unwrap()
}

#[test]
fn import_then_preview_and_apply_a_refresh() {
    let d = tempfile::tempdir().unwrap();
    let ssh = d.path().join("ssh");
    std::fs::create_dir_all(ssh.join("config.d")).unwrap();
    std::fs::write(ssh.join("config"), "Host web-1\n  HostName web-1.acme.example\n  User <your-user>\n  Port 22\n\nHost old\n  HostName old.acme.example\n").unwrap();
    let data = c(d.path().join("data").to_str().unwrap());
    unsafe {
        let mut err = null_mut();
        let mut settings: Value = serde_json::from_str(&take(bastion_ssh_workflow_settings_json(data.as_ptr(), &mut err))).unwrap();
        settings["sshDir"] = ssh.to_str().unwrap().into();
        settings["changeDetection"] = true.into();
        assert_eq!(bastion_ssh_workflow_set_settings(data.as_ptr(), c(&settings.to_string()).as_ptr(), &mut err), 0);
        let back: Value = serde_json::from_str(&take(bastion_ssh_workflow_settings_json(data.as_ptr(), &mut err))).unwrap();
        assert_eq!(back["sshDir"], ssh.to_str().unwrap());
        assert_eq!(bastion_ssh_workflow_set_settings(data.as_ptr(), c("{\"sshDir\":null}").as_ptr(), &mut err), -1, "every flag is required");
        bastion_string_free(err);
        let mut err = null_mut();

        let ph: Value = serde_json::from_str(&take(bastion_ssh_workflow_placeholders_json(data.as_ptr(), &mut err))).unwrap();
        assert_eq!(ph["used"]["your-user"], 1, "{ph}");
        assert_eq!(bastion_ssh_workflow_set_placeholder(data.as_ptr(), c("your-user").as_ptr(), c("alice").as_ptr(), &mut err), 0);
        assert_eq!(bastion_ssh_workflow_set_placeholder(data.as_ptr(), c("your-user").as_ptr(), c("a\nHost evil").as_ptr(), &mut err), -1, "no injection");
        bastion_string_free(err);
        let mut err = null_mut();
        let ph: Value = serde_json::from_str(&take(bastion_ssh_workflow_placeholders_json(data.as_ptr(), &mut err))).unwrap();
        assert_eq!(ph["values"]["your-user"], "alice");

        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let scan: Value = serde_json::from_str(&take(bastion_ssh_scan_json(c(ssh.to_str().unwrap()).as_ptr(), std::ptr::null(), &mut err))).unwrap();
        let ids: Vec<Value> = scan["hosts"].as_array().unwrap().iter().map(|h| h["identity"].clone()).collect();
        assert_eq!(ids.len(), 2);
        assert_eq!(bastion_ssh_workflow_import_hosts(data.as_ptr(), lib, c(&json!(ids).to_string()).as_ptr(), &mut err), 2);
        let none = changes(&data);
        assert_eq!(none["hasBaseline"], true);
        assert!(none["hosts"].as_array().unwrap().is_empty(), "{none}");

        // The team pushes a new config: web-1 moves port, old is gone, db is new.
        std::fs::write(ssh.join("config"), "Host web-1\n  HostName web-1.acme.example\n  User <your-user>\n  Port 2222\n").unwrap();
        std::fs::write(ssh.join("config.d/db"), "Host db\n  HostName db.acme.example\n").unwrap();
        let ch = changes(&data);
        let kind = |alias: &str| ch["hosts"].as_array().unwrap().iter().find(|h| h["alias"] == alias).map(|h| h["kind"].clone());
        assert_eq!((kind("web-1"), kind("old"), kind("db")), (Some("changed".into()), Some("removed".into()), Some("added".into())), "{ch}");
        let web = ch["hosts"].as_array().unwrap().iter().find(|h| h["alias"] == "web-1").unwrap();
        assert!(web["fields"].as_array().unwrap().iter().any(|f| f["new"] == "2222"), "{web}");

        let r: Value = serde_json::from_str(&take(bastion_ssh_workflow_apply_refresh_json(data.as_ptr(), lib, 1, &mut err))).unwrap();
        assert_eq!((r["added"].as_u64(), r["updated"].as_u64(), r["markedRemoved"].as_u64()), (Some(1), Some(1), Some(1)), "{r}");
        assert!(changes(&data)["hosts"].as_array().unwrap().is_empty(), "new baseline after apply");
        let tree = take(bastion_library_tree_json(lib, &mut err));
        assert!(tree.contains("db.acme.example") && tree.contains("2222"), "{tree}");
        bastion_library_free(lib);
    }
}
