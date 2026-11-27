//! OpenSSH config scan and import through the C ABI: a user config dir plus a separate system file,
//! as the Windows app reads `%USERPROFILE%\.ssh` and `C:\ProgramData\ssh\ssh_config`.
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

fn fixture() -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let user = dir.path().join("user/.ssh");
    let system = dir.path().join("ProgramData/ssh");
    std::fs::create_dir_all(user.join("config.d")).unwrap();
    std::fs::create_dir_all(&system).unwrap();
    std::fs::write(user.join("config"), "Host web-1\n  HostName web-1.acme.example\n  User ops\n  Port 2222\n\nHost *\n  ServerAliveInterval 30\n").unwrap();
    std::fs::write(user.join("config.d/globex"), "Host erp\n  HostName erp.globex.example\n  ProxyJump bastion\n").unwrap();
    std::fs::write(system.join("ssh_config"), "Host build\n  HostName build.corp.example\n  User <your-user>\n").unwrap();
    let root = user.to_str().unwrap().to_string();
    let sys = system.join("ssh_config").to_str().unwrap().to_string();
    (dir, root, sys)
}

unsafe fn scan(root: &str, extra: Option<&str>) -> Value {
    let mut err = null_mut();
    let e = extra.map(c);
    serde_json::from_str(&take(bastion_ssh_scan_json(c(root).as_ptr(), e.as_ref().map_or(null(), |s| s.as_ptr()), &mut err))).unwrap()
}

#[test]
fn scan_reads_user_config_config_d_and_the_system_file() {
    let (_d, root, sys) = fixture();
    unsafe {
        let only_user = scan(&root, None);
        assert_eq!(only_user["hosts"].as_array().unwrap().len(), 2, "{only_user}");
        let all = scan(&root, Some(&sys));
        let aliases: Vec<&str> = all["hosts"].as_array().unwrap().iter().map(|h| h["alias"].as_str().unwrap()).collect();
        assert!(aliases.contains(&"web-1") && aliases.contains(&"erp") && aliases.contains(&"build"), "{aliases:?}");
        let web = all["hosts"].as_array().unwrap().iter().find(|h| h["alias"] == "web-1").unwrap();
        assert_eq!((web["port"].as_u64(), web["user"].as_str()), (Some(2222), Some("ops")));
        let build = all["hosts"].as_array().unwrap().iter().find(|h| h["alias"] == "build").unwrap();
        assert_eq!(build["placeholders"][0], "your-user");
        assert_eq!(all["hosts"].as_array().unwrap().iter().find(|h| h["alias"] == "erp").unwrap()["proxyJump"], "bastion");
        // A missing system file is simply skipped.
        assert_eq!(scan(&root, Some("C:\\nope\\ssh_config"))["hosts"].as_array().unwrap().len(), 2);
    }
}

#[test]
fn import_adds_chosen_hosts_once() {
    let (d, root, sys) = fixture();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let all = scan(&root, Some(&sys));
        let ids: Vec<&str> = all["hosts"].as_array().unwrap().iter().filter(|h| h["alias"] != "erp").map(|h| h["identity"].as_str().unwrap()).collect();
        let ids = serde_json::to_string(&ids).unwrap();
        assert_eq!(bastion_library_import_ssh_hosts(lib, c(&root).as_ptr(), c(&sys).as_ptr(), c(&ids).as_ptr(), &mut err), 2);
        assert_eq!(bastion_library_import_ssh_hosts(lib, c(&root).as_ptr(), c(&sys).as_ptr(), c(&ids).as_ptr(), &mut err), 0, "re-import must dedupe");
        let tree = take(bastion_library_tree_json(lib, &mut err));
        assert!(tree.contains("web-1.acme.example") && tree.contains("build.corp.example") && !tree.contains("erp.globex"), "{tree}");
        assert!(tree.contains("\"imported\":true"));
        assert_eq!(bastion_library_import_ssh_hosts(lib, c(&root).as_ptr(), null(), c("not json").as_ptr(), &mut err), -1);
        assert!(take(err).contains("JSON"));
        bastion_library_free(lib);
    }
}

#[test]
fn export_writes_an_owner_only_config_that_imports_back_to_the_same_hosts() {
    let (d, root, sys) = fixture();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let ids: Vec<String> = scan(&root, Some(&sys))["hosts"].as_array().unwrap().iter().map(|h| h["identity"].as_str().unwrap().to_string()).collect();
        let ids = serde_json::to_string(&ids).unwrap();
        assert_eq!(bastion_library_import_ssh_hosts(lib, c(&root).as_ptr(), c(&sys).as_ptr(), c(&ids).as_ptr(), &mut err), 3);

        let out_dir = d.path().join("export");
        std::fs::create_dir_all(out_dir.join("config.d")).unwrap();
        let out = out_dir.join("config");
        let v: Value = serde_json::from_str(&take(bastion_library_export_ssh_config_json(lib, c(out.to_str().unwrap()).as_ptr(), null(), &mut err))).unwrap();
        assert_eq!(v["exported"], 3);
        assert_eq!(v["skipped"].as_array().unwrap().len(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let back = scan(out_dir.to_str().unwrap(), None);
        let summary = |v: &Value| {
            let mut s: Vec<String> = v["hosts"].as_array().unwrap().iter().map(|h| format!("{} {} {} {} {}", h["alias"], h["hostname"], h["user"], h["port"], h["proxyJump"])).collect();
            s.sort();
            s
        };
        // `Host *`'s keep-alive is not in the summary; the effective values are.
        assert_eq!(summary(&back), summary(&scan(&root, Some(&sys))));

        assert!(bastion_library_export_ssh_config_json(lib, c(out.to_str().unwrap()).as_ptr(), c("{").as_ptr(), &mut err).is_null());
        assert!(!err.is_null());
        bastion_string_free(err);
        bastion_library_free(lib);
    }
}

#[test]
fn portable_export_previews_then_writes_a_secret_free_bastion_export() {
    let (d, root, sys) = fixture();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let ids: Vec<String> = scan(&root, Some(&sys))["hosts"].as_array().unwrap().iter().map(|h| h["identity"].as_str().unwrap().to_string()).collect();
        assert_eq!(bastion_library_import_ssh_hosts(lib, c(&root).as_ptr(), c(&sys).as_ptr(), c(&serde_json::to_string(&ids).unwrap()).as_ptr(), &mut err), 3);

        let p: Value = serde_json::from_str(&take(bastion_library_export_preview_json(lib, null(), &mut err))).unwrap();
        assert_eq!(p["connections"], 3);
        assert!(p["folders"].as_u64().unwrap() >= 1);
        assert!(p["strippedFields"].is_array());
        assert!(p["credentialRefs"].is_u64());

        let out = d.path().join("library.bastion-export.json");
        assert_eq!(bastion_library_export_portable(lib, c(out.to_str().unwrap()).as_ptr(), null(), &mut err), 0);
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("\"format\": \"bastion-export\""));
        assert!(text.contains("web-1.acme.example"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
        }

        // Bad selections fail with an error and write nothing.
        assert!(bastion_library_export_preview_json(lib, c("{").as_ptr(), &mut err).is_null());
        assert!(!err.is_null());
        bastion_string_free(err);
        err = null_mut();
        let none = d.path().join("none.json");
        assert_eq!(bastion_library_export_portable(lib, c(none.to_str().unwrap()).as_ptr(), c("{").as_ptr(), &mut err), -1);
        assert!(!err.is_null() && !none.exists());
        bastion_string_free(err);
        bastion_library_free(lib);
    }
}
