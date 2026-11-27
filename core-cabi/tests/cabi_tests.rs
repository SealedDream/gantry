//! Drives the C ABI exactly as a P/Invoke caller does: raw pointers, JSON out, error strings.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use serde_json::Value;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Take ownership of a returned string and free it.
unsafe fn take(p: *mut c_char) -> String {
    assert!(!p.is_null(), "expected a string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    s
}

unsafe fn open(path: &std::path::Path) -> *mut BastionLibrary {
    let mut err: *mut c_char = null_mut();
    let lib = bastion_library_open(c(path.to_str().unwrap()).as_ptr(), &mut err);
    assert!(!lib.is_null(), "open failed: {}", if err.is_null() { String::new() } else { take(err) });
    assert!(err.is_null());
    lib
}

unsafe fn tree(lib: *const BastionLibrary) -> Value {
    let mut err = null_mut();
    serde_json::from_str(&take(bastion_library_tree_json(lib, &mut err))).unwrap()
}

#[test]
fn abi_version_is_stable() {
    // Each additive surface bumps it: 3 SSH sessions, 4 credentials, 5 OpenSSH import, 6 properties, 7 vault logins, ..., 12 SFTP, 13 VNC, 14 Vaultwarden, 15 tree registry, 16 settings, shortcuts, palette, layouts, 17 notes and SSH overrides, 18 accents and density metrics, ... 25 OSC 52, 26 generator and variables, 27 documents, 28 bell and clear scrollback, 29 Test Connection, 30 recent usernames, 31 WSL details and local shells, 32 tab groups, 33 SSH algorithms, 34 SSH config export, 35 tab groups, 36 connection history, 37 web tunnels, 38 Credentials section (merged after 53), 39 key manager (merged after 57), 45 file panel (merged after 53), 53 split panes and broadcast, 54 log snippet export, 57 palette connections, 58 session logging, 59 remote editor (merged after 61), 60 SSH agent, 61 workspace create and restore plan, 62 auto-reconnect, 63 credential providers, 64 command snippets, 65 port-forward manager (merged after 66), 66 per-host colours, 67 Mosh and tmux attach, 70 SFTP delete, 68 host status (merged after 71), 69 triggers (merged after 71), 71 Wake-on-LAN, 72 tunnels, 73 multi-host exec, 77 sensitive lookup, 78 database client, ..., 111 plugin broker, 112 SSH import forwards, 118 tab previews, 119 mRemoteNG import, 120 plugins folder and catalogue, 121 custom properties, 122 item icon, 123 audit log, 124 terminal wake, 125 bulk host colours, 126 bulk edit, 127 KeePass import, 128 task hooks, 129 VNC resize, 130 dynamic folders, 133 pty foreground (shell pid), 134 reconnect carry-over, 135 task ask labels, 136 PLUG-06c highlight and completions, 137 plugin view sessions, 138 session log v2; hosts check this against ExpectedAbiVersion.
    assert_eq!(bastion_abi_version(), 149);
}

#[test]
fn add_list_save_reload_remove_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("library.json");
    unsafe {
        let lib = open(&path);
        let mut err = null_mut();
        let folder = take(bastion_library_add_folder(lib, null(), c("Acme").as_ptr(), &mut err));
        let web = take(bastion_library_add_connection(lib, c(&folder).as_ptr(), c("web-1").as_ptr(), c("ssh").as_ptr(), c("web.acme.example").as_ptr(), 2222, c("ops").as_ptr(), &mut err));
        // Protocol default port and no username; empty parent string means root.
        let db = take(bastion_library_add_connection(lib, c("").as_ptr(), c("db-1").as_ptr(), c("RDP").as_ptr(), c("10.0.0.5").as_ptr(), -1, null(), &mut err));
        assert!(err.is_null());

        let t = tree(lib);
        assert_eq!(t["folders"][0]["name"], "Acme");
        let conn = &t["folders"][0]["connections"][0];
        assert_eq!((conn["id"].as_str(), conn["port"].as_u64(), conn["username"].as_str(), conn["protocol"].as_str()), (Some(web.as_str()), Some(2222), Some("ops"), Some("ssh")));
        let root_conn = &t["connections"][0];
        assert_eq!((root_conn["id"].as_str(), root_conn["protocol"].as_str()), (Some(db.as_str()), Some("rdp")));
        assert!(root_conn["port"].is_null() && root_conn["username"].is_null());

        assert_eq!(bastion_library_save(lib, &mut err), 0);
        bastion_library_free(lib);

        // A fresh handle sees what was saved.
        let lib = open(&path);
        assert_eq!(tree(lib)["folders"][0]["connections"][0]["name"], "web-1");
        assert_eq!(bastion_library_remove(lib, c(&folder).as_ptr(), &mut err), 0);
        assert!(tree(lib)["folders"].as_array().unwrap().is_empty(), "removing a folder removes its contents");
        assert_eq!(bastion_library_save(lib, &mut err), 0);
        bastion_library_free(lib);
        assert!(tree(open(&path))["folders"].as_array().unwrap().is_empty());
    }
}

#[test]
fn errors_are_reported_not_thrown() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let lib = open(&dir.path().join("l.json"));
        let mut err = null_mut();

        assert_eq!(bastion_library_remove(lib, c("not-a-uuid").as_ptr(), &mut err), -1);
        assert!(take(err).contains("invalid id"));

        err = null_mut();
        let id = bastion_library_add_connection(lib, null(), c("x").as_ptr(), c("gopher").as_ptr(), c("h").as_ptr(), -1, null(), &mut err);
        assert!(id.is_null());
        assert!(take(err).contains("unknown protocol"));

        err = null_mut();
        assert!(bastion_library_add_connection(lib, null(), c("x").as_ptr(), c("ssh").as_ptr(), c("h").as_ptr(), 70000, null(), &mut err).is_null());
        assert!(take(err).contains("out of range"));

        err = null_mut();
        assert!(bastion_library_add_folder(lib, null(), null(), &mut err).is_null());
        assert!(take(err).contains("name is required"));

        err = null_mut();
        assert!(bastion_library_add_folder(lib, c("00000000-0000-0000-0000-000000000000").as_ptr(), c("orphan").as_ptr(), &mut err).is_null());
        assert!(!take(err).is_empty(), "unknown parent must fail");

        // NULL handle and NULL err pointer are tolerated.
        err = null_mut();
        assert!(bastion_library_tree_json(null(), &mut err).is_null());
        assert!(take(err).contains("NULL"));
        assert_eq!(bastion_library_save(null(), null_mut()), -1);
        bastion_library_free(null_mut());
        bastion_string_free(null_mut());
        bastion_library_free(lib);
    }
}

#[test]
fn opening_a_corrupt_library_is_an_error_not_a_reset() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("library.json");
    std::fs::write(&path, b"{ not json").unwrap();
    unsafe {
        let mut err = null_mut();
        assert!(bastion_library_open(c(path.to_str().unwrap()).as_ptr(), &mut err).is_null());
        assert!(!take(err).is_empty());
        assert!(bastion_library_open(null(), &mut err).is_null());
        assert!(take(err).contains("path is required"));
    }
    assert_eq!(std::fs::read(&path).unwrap(), b"{ not json", "a failed open must not touch the file");
}

#[test]
fn non_ascii_names_survive_the_utf8_boundary() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let lib = open(&dir.path().join("l.json"));
        let mut err = null_mut();
        take(bastion_library_add_folder(lib, null(), c("日本 – Ünïcode").as_ptr(), &mut err));
        assert_eq!(tree(lib)["folders"][0]["name"], "日本 – Ünïcode");
        bastion_library_free(lib);
    }
}

unsafe fn err_text(err: *mut c_char) -> String {
    assert!(!err.is_null(), "expected an error");
    take(err)
}

#[test]
fn transfer_queue_round_trip() {
    unsafe {
        let q = bastion_transfers_new(1);
        let mut err = null_mut();
        let a = bastion_transfers_add(q, c("upload").as_ptr(), c("/l/a.txt").as_ptr(), c("/r/a.txt").as_ptr(), 100, c("rename").as_ptr(), &mut err);
        let b = bastion_transfers_add(q, c("download").as_ptr(), c("/r/b").as_ptr(), c("/l/b").as_ptr(), 10, c("ask").as_ptr(), &mut err);
        assert!(a > 0 && b > a && err.is_null());
        assert_eq!(bastion_transfers_add(q, c("sideways").as_ptr(), c("/a").as_ptr(), c("/b").as_ptr(), 1, c("ask").as_ptr(), &mut err), 0);
        assert!(err_text(err).contains("direction"));
        err = null_mut();

        let job: Value = serde_json::from_str(&take(bastion_transfers_start_next(q, &mut err))).unwrap();
        assert_eq!((job["id"].as_u64(), job["state"].as_str()), (Some(a), Some("running")));
        assert!(bastion_transfers_start_next(q, &mut err).is_null(), "one slot");

        let r: Value = serde_json::from_str(&take(bastion_transfers_resolve(q, a, c(r#"{"exists":true,"target_modified":null,"source_modified":null}"#).as_ptr(), c(r#"["/r/a (1).txt"]"#).as_ptr(), &mut err))).unwrap();
        assert_eq!(r, serde_json::json!({"action":"copy","target":"/r/a (2).txt","replace":false}));
        assert!(bastion_transfers_resolve(q, a, c("not json").as_ptr(), null(), &mut err).is_null());
        assert!(err_text(err).contains("target info"));
        err = null_mut();

        assert_eq!(bastion_transfers_progress(q, a, 50, 1000, &mut err), 0);
        let state: Value = serde_json::from_str(&take(bastion_transfers_json(q, &mut err))).unwrap();
        assert_eq!(state["jobs"][0]["speed"], 50.0);
        assert_eq!(state["jobs"][0]["eta"], 1);
        assert_eq!(state["summary"]["active"], 1);

        assert_eq!(bastion_transfers_update(q, a, c("fail").as_ptr(), c("connection reset").as_ptr(), &mut err), 0);
        assert_eq!(bastion_transfers_update(q, a, c("retry").as_ptr(), null(), &mut err), 0);
        assert_eq!(bastion_transfers_update(q, a, c("resume").as_ptr(), null(), &mut err), -1, "not paused");
        assert!(err_text(err).contains("not paused"));
        err = null_mut();
        assert_eq!(bastion_transfers_update(q, 999, c("cancel").as_ptr(), null(), &mut err), -1);
        err_text(err);
        err = null_mut();
        assert_eq!(bastion_transfers_update(q, b, c("bogus").as_ptr(), null(), &mut err), -1);
        err_text(err);
        err = null_mut();

        assert_eq!(bastion_transfers_update(q, a, c("finish").as_ptr(), null(), &mut err), 0);
        bastion_transfers_clear_finished(q);
        let state: Value = serde_json::from_str(&take(bastion_transfers_json(q, &mut err))).unwrap();
        assert_eq!(state["jobs"].as_array().unwrap().len(), 1);
        bastion_transfers_free(q);
        bastion_transfers_free(null_mut());
        assert!(bastion_transfers_json(null(), &mut err).is_null());
        err_text(err);
    }
}

#[test]
fn osc7_and_follow_folder_hook() {
    unsafe {
        assert_eq!(take(bastion_osc7_path(c("file://h/srv/my%20app").as_ptr())), "/srv/my app");
        assert!(bastion_osc7_path(c("file://h/../etc").as_ptr()).is_null());
        assert!(bastion_osc7_path(null()).is_null());
        assert!(take(bastion_follow_folder_hook(c("bash").as_ptr())).contains("]7;"));
        assert!(bastion_follow_folder_hook(c("fish").as_ptr()).is_null());
    }
}

#[test]
fn edit_locally_paths_and_watcher() {
    unsafe {
        let base = tempfile::tempdir().unwrap();
        let mut err = null_mut();
        let path = take(bastion_edit_local_path(c(base.path().to_str().unwrap()).as_ptr(), c("s1").as_ptr(), c("/etc/hosts").as_ptr(), &mut err));
        assert!(path.ends_with("hosts") && path.contains("edit-locally"));
        assert!(bastion_edit_local_path(c(base.path().to_str().unwrap()).as_ptr(), c("../x").as_ptr(), c("/etc/hosts").as_ptr(), &mut err).is_null());
        err_text(err);
        err = null_mut();

        std::fs::write(&path, "127.0.0.1 a").unwrap();
        let w = bastion_edit_watcher_new();
        assert_eq!(bastion_edit_watcher_watch(w, c(&path).as_ptr(), c("/etc/hosts").as_ptr(), &mut err), 0);
        std::fs::write(&path, "127.0.0.1 b").unwrap();
        let polled: Value = serde_json::from_str(&take(bastion_edit_watcher_poll(w, &mut err))).unwrap();
        assert_eq!(polled["changed"][0]["remote"], "/etc/hosts");
        assert_eq!(bastion_edit_watcher_watch(w, c(&path).as_ptr(), null(), &mut err), 0);
        std::fs::write(&path, "changed again").unwrap();
        let polled: Value = serde_json::from_str(&take(bastion_edit_watcher_poll(w, &mut err))).unwrap();
        assert!(polled["changed"].as_array().unwrap().is_empty(), "unwatched");
        assert_eq!(bastion_edit_watcher_watch(w, c("/no/such/file").as_ptr(), c("/x").as_ptr(), &mut err), -1);
        err_text(err);
        bastion_edit_watcher_free(w);
    }
}

#[test]
fn key_manager_generates_and_converts() {
    unsafe {
        let mut err = std::ptr::null_mut();
        let comment = CString::new("cabi").unwrap();
        let pass = CString::new("pw").unwrap();
        let out = bastion_keys_generate_json(comment.as_ptr(), pass.as_ptr(), &mut err);
        assert!(!out.is_null());
        let v: serde_json::Value = serde_json::from_str(CStr::from_ptr(out).to_str().unwrap()).unwrap();
        bastion_string_free(out);
        assert_eq!(v["algorithm"], "ssh-ed25519");
        let private = CString::new(v["private_openssh"].as_str().unwrap()).unwrap();
        let none = bastion_keys_inspect_json(private.as_ptr(), std::ptr::null(), &mut err);
        assert!(none.is_null() && !err.is_null());
        bastion_string_free(err);
        err = std::ptr::null_mut();
        let plain = bastion_keys_convert_json(private.as_ptr(), pass.as_ptr(), std::ptr::null(), std::ptr::null(), &mut err);
        let c: serde_json::Value = serde_json::from_str(CStr::from_ptr(plain).to_str().unwrap()).unwrap();
        bastion_string_free(plain);
        assert_eq!(c["fingerprint"], v["fingerprint"]);
        assert_eq!(c["comment"], "cabi");
    }
}

/// H09: the C tree carries the same credential/username projection as UniFFI's `ConnectionView`.
#[test]
fn tree_connection_json_matches_the_uniffi_connection_view() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let lib = open(&dir.path().join("library.json"));
        let mut err = null_mut();
        take(bastion_library_add_connection(lib, c("").as_ptr(), c("web-1").as_ptr(), c("ssh").as_ptr(), c("web").as_ptr(), 22, c("ops").as_ptr(), &mut err));
        let conn = tree(lib)["connections"][0].clone();
        let keys: std::collections::BTreeSet<&str> = conn.as_object().unwrap().keys().map(String::as_str).collect();
        let expected = [
            "id", "name", "protocol", "host", "port", "username", "group", "credentialId", "vaultwardenItem", "sourceStatus", "imported", "favorite", "icon", "iconLabel",
            "effectiveCredentialId", "effectiveCredentialName", "credentialSource", "credentialFrom", "effectiveUsername", "inlineCredential", "hasTools", "unavailable", "ownIcon", "tags",
        ];
        assert_eq!(keys, expected.into_iter().collect());
        assert_eq!(conn["effectiveUsername"], "ops");
        assert!(conn["credentialSource"].is_null() && conn["inlineCredential"].is_null());
        bastion_library_free(lib);
    }
}

#[test]
fn tags_is_production_reads_a_json_array() {
    let yes = std::ffi::CString::new(r#"["web","Prod"]"#).unwrap();
    let no = std::ffi::CString::new(r#"["preprod"]"#).unwrap();
    let bad = std::ffi::CString::new("not json").unwrap();
    unsafe {
        assert_eq!(bastion_tags_is_production(yes.as_ptr()), 1);
        assert_eq!(bastion_tags_is_production(no.as_ptr()), 0);
        assert_eq!(bastion_tags_is_production(bad.as_ptr()), 0);
        assert_eq!(bastion_tags_is_production(std::ptr::null()), 0);
    }
}
