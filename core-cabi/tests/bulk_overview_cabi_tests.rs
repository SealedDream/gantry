//! Connect All plan and folder overview over the C ABI (ABI 97): the same data the Mac bridge
//! returns (`core-ffi/src/bulk.rs`, `core-ffi/src/overview.rs`). Hermetic: an ephemeral vault,
//! no OS key store, so it runs on every platform.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::credentials::ephemeral_handle_for_tests;
use bastion_cabi::*;
use serde_json::{json, Value};

const SECRET: &str = "hunter2-do-not-show";
const UNKNOWN_ID: &str = "00000000-0000-4000-8000-000000000001";
/// Not UTF-8, NUL-terminated.
const BAD_UTF8: &[u8] = b"\xff\xfe\0";
const DEFAULT_PORT: i32 = -1;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> String {
    assert!(!p.is_null(), "expected a string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    s
}

unsafe fn json_of(p: *mut c_char) -> Value {
    serde_json::from_str(&take(p)).unwrap()
}

unsafe fn code() -> String {
    CStr::from_ptr(bastion_last_error_code()).to_str().unwrap().to_string()
}

/// Folder "Prod" with `ssh` (saved login, port 2222), `telnet`, and subfolder "Web" holding
/// `rdp` on the same host as `ssh` (no login of its own) and `open` (saved login).
struct Fixture {
    dir: tempfile::TempDir,
    lib: *mut BastionLibrary,
    vault: *mut BastionCredentials,
    folder: String,
    sub: String,
    ssh: String,
    rdp: String,
    open: String,
    telnet: String,
    outside: String,
}

impl Fixture {
    unsafe fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut err = null_mut();
        let lib = bastion_library_open(c(dir.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let vault = ephemeral_handle_for_tests(dir.path().join("c.vault").to_str().unwrap()).unwrap();
        let cred = take(bastion_credentials_save_password(vault, null(), c("ops").as_ptr(), null(), c("root").as_ptr(), SECRET.as_ptr(), SECRET.len(), &mut err));

        let folder = take(bastion_library_add_folder(lib, null(), c("Prod").as_ptr(), &mut err));
        let sub = take(bastion_library_add_folder(lib, c(&folder).as_ptr(), c("Web").as_ptr(), &mut err));
        let add = |parent: Option<&str>, name: &str, protocol: &str, host: &str, port: i32, login: bool| {
            let parent = parent.map(c);
            let mut err = null_mut();
            let id = take(bastion_library_add_connection(lib, parent.as_ref().map_or(null(), |p| p.as_ptr()), c(name).as_ptr(), c(protocol).as_ptr(), c(host).as_ptr(), port, null(), &mut err));
            if login {
                assert_eq!(bastion_library_set_credential(lib, c(&id).as_ptr(), c(&cred).as_ptr(), &mut err), 0);
            }
            id
        };
        let ssh = add(Some(&folder), "ssh", "ssh", "host.example", 2222, true);
        let telnet = add(Some(&folder), "telnet", "telnet", "old.example", DEFAULT_PORT, false);
        let rdp = add(Some(&sub), "rdp", "rdp", "host.example", DEFAULT_PORT, false);
        let open = add(Some(&sub), "open", "ssh", "open.example", DEFAULT_PORT, true);
        let outside = add(None, "outside", "ssh", "out.example", DEFAULT_PORT, true);
        Fixture { dir, lib, vault, folder, sub, ssh, rdp, open, telnet, outside }
    }

    unsafe fn plan(&self, folder: Option<&str>, open_ids: Option<&str>, err: &mut *mut c_char) -> *mut c_char {
        let (folder, open_ids) = (folder.map(c), open_ids.map(c));
        bastion_credentials_plan_connect_all_json(self.vault, self.lib, folder.as_ref().map_or(null(), |s| s.as_ptr()), open_ids.as_ref().map_or(null(), |s| s.as_ptr()), err)
    }

    unsafe fn overview(&self, with_vault: bool, with_history: bool, folder: &str, deep: bool, err: &mut *mut c_char) -> *mut c_char {
        let data_dir = c(self.dir.path().to_str().unwrap());
        bastion_library_folder_overview_json(self.lib, if with_vault { self.vault } else { null() }, if with_history { data_dir.as_ptr() } else { null() }, c(folder).as_ptr(), i32::from(deep), err)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        unsafe {
            bastion_credentials_free(self.vault);
            bastion_library_free(self.lib);
        }
    }
}

fn row<'a>(rows: &'a Value, id: &str) -> &'a Value {
    rows.as_array().unwrap().iter().find(|r| r["id"] == id).expect("row")
}

#[test]
fn the_plan_sorts_every_connection_into_one_list() {
    unsafe {
        let f = Fixture::new();
        let mut err = null_mut();
        let open_ids = json!([f.open]).to_string();

        let plan = json_of(f.plan(Some(&f.folder), Some(&open_ids), &mut err));

        assert!(err.is_null());
        assert_eq!(
            plan,
            json!({
                "ready": [f.ssh], "needsLogin": [f.rdp], "skippedOpen": [f.open], "skippedUnsupported": [f.telnet], "skippedBlocked": [],
                "toConnect": 2, "needsConfirmation": false,
            })
        );
        assert!(!plan.to_string().contains(SECRET));
    }
}

#[test]
fn a_login_that_would_only_be_offered_is_never_ready() {
    unsafe {
        let f = Fixture::new();
        let mut err = null_mut();

        // `rdp` has no login of its own; `ssh` on the same host has one, which is only offered.
        let plan = json_of(f.plan(Some(&f.folder), None, &mut err));
        let rows = json_of(f.overview(true, false, &f.folder, true, &mut err));

        assert!(plan["needsLogin"].as_array().unwrap().contains(&json!(f.rdp)));
        assert!(!plan["ready"].as_array().unwrap().contains(&json!(f.rdp)), "an offered login was planned as usable");
        let offered = row(&rows, &f.rdp);
        assert_eq!((offered["login"].as_str(), offered["loginFrom"].as_str()), (Some("offered"), Some("ssh")));
    }
}

#[test]
fn no_folder_id_plans_the_whole_library() {
    unsafe {
        let f = Fixture::new();
        let mut err = null_mut();

        let plan = json_of(f.plan(None, None, &mut err));

        let ready = plan["ready"].as_array().unwrap();
        assert!(ready.contains(&json!(f.outside)) && ready.contains(&json!(f.open)) && ready.contains(&json!(f.ssh)));
        assert_eq!(plan["toConnect"], 4);
    }
}

#[test]
fn the_plan_refuses_a_missing_vault_bad_pointers_and_unknown_ids() {
    unsafe {
        let f = Fixture::new();
        let mut err = null_mut();
        let folder = c(&f.folder);

        // Missing vault: no plan at all, so nothing can be opened without the login check.
        assert!(bastion_credentials_plan_connect_all_json(null(), f.lib, folder.as_ptr(), null(), &mut err).is_null());
        assert!(take(err).contains("credentials handle is NULL"));
        assert!(bastion_credentials_plan_connect_all_json(f.vault, null(), folder.as_ptr(), null(), &mut err).is_null());
        assert!(take(err).contains("library handle is NULL"));

        assert!(bastion_credentials_plan_connect_all_json(f.vault, f.lib, BAD_UTF8.as_ptr().cast(), null(), &mut err).is_null());
        assert!(take(err).contains("not valid UTF-8"));
        assert!(bastion_credentials_plan_connect_all_json(f.vault, f.lib, folder.as_ptr(), BAD_UTF8.as_ptr().cast(), &mut err).is_null());
        assert!(take(err).contains("not valid UTF-8"));

        assert!(f.plan(Some(UNKNOWN_ID), None, &mut err).is_null(), "unknown folder");
        assert_eq!(code(), "not_found");
        take(err);
        assert!(f.plan(Some(&f.ssh), None, &mut err).is_null(), "a connection is not a folder");
        take(err);
        assert!(f.plan(Some("nonsense"), None, &mut err).is_null());
        take(err);
        for bad in [r#"["nonsense"]"#, r#"{"a":1}"#, "[1]", "not json"] {
            assert!(f.plan(Some(&f.folder), Some(bad), &mut err).is_null(), "open ids {bad}");
            take(err);
        }
        // A NULL `err` is allowed and a failure still returns NULL.
        assert!(bastion_credentials_plan_connect_all_json(null(), null(), null(), null(), null_mut()).is_null());
    }
}

#[test]
fn the_overview_lists_rows_with_login_state_history_and_no_secret() {
    unsafe {
        let f = Fixture::new();
        let mut err = null_mut();
        assert_eq!(bastion_connection_history_success(c(f.dir.path().to_str().unwrap()).as_ptr(), c(&f.ssh).as_ptr(), c("root").as_ptr(), &mut err), 0);

        let rows = json_of(f.overview(true, true, &f.folder, false, &mut err));

        assert!(err.is_null());
        let shape: Vec<(&str, &str)> = rows.as_array().unwrap().iter().map(|r| (r["kind"].as_str().unwrap(), r["name"].as_str().unwrap())).collect();
        assert_eq!(shape, [("connection", "ssh"), ("connection", "telnet"), ("folder", "Web")]);
        let ssh = row(&rows, &f.ssh);
        assert_eq!((ssh["address"].as_str(), ssh["protocol"].as_str(), ssh["typeLabel"].as_str()), (Some("host.example:2222"), Some("ssh"), Some("SSH Terminal")));
        assert_eq!((ssh["login"].as_str(), &ssh["loginFrom"], ssh["lastResult"].as_str()), (Some("saved"), &Value::Null, Some("OK")));
        assert!(ssh["lastConnectedAt"].as_u64().is_some());
        assert_eq!((ssh["icon"]["id"].as_str(), ssh["favorite"].as_bool(), ssh["folderPath"].as_array().map(Vec::len)), (Some("ssh"), Some(false), Some(0)));
        assert!(ssh["icon"]["label"].is_string() && ssh["icon"]["tint"].is_string() && ssh["tags"].is_array());
        let folder = row(&rows, &f.sub);
        assert_eq!((&folder["protocol"], folder["icon"]["id"].as_str(), folder["login"].as_str(), folder["address"].as_str()), (&Value::Null, Some("folder"), Some("none"), Some("")));
        // Every row has exactly the fields of the Mac bridge's `OverviewRowView`.
        let mut keys: Vec<&str> = ssh.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["address", "favorite", "folderPath", "hostColor", "icon", "id", "kind", "lastConnectedAt", "lastResult", "login", "loginFrom", "name", "protocol", "tags", "typeLabel", "username"]);
        assert!(!rows.to_string().contains(SECRET));
    }
}

#[test]
fn the_overview_with_subfolders_lists_connections_with_their_folder_path() {
    unsafe {
        let f = Fixture::new();
        let mut err = null_mut();

        let rows = json_of(f.overview(true, false, &f.folder, true, &mut err));

        let names: Vec<&str> = rows.as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap()).collect();
        assert_eq!(names.len(), 4, "connections only: {names:?}");
        assert!(rows.as_array().unwrap().iter().all(|r| r["kind"] == "connection"));
        assert_eq!(row(&rows, &f.rdp)["folderPath"], json!(["Web"]));
        assert_eq!(row(&rows, &f.ssh)["lastResult"], Value::Null, "no data dir: no history");
    }
}

#[test]
fn without_a_vault_the_overview_reads_the_library_alone_and_offers_nothing() {
    unsafe {
        let f = Fixture::new();
        let mut err = null_mut();

        let rows = json_of(f.overview(false, false, &f.folder, true, &mut err));

        assert!(err.is_null());
        assert_eq!(row(&rows, &f.ssh)["login"], "saved");
        assert_eq!((row(&rows, &f.rdp)["login"].as_str(), &row(&rows, &f.rdp)["loginFrom"]), (Some("none"), &Value::Null));
    }
}

#[test]
fn the_overview_refuses_bad_pointers_and_unknown_folders() {
    unsafe {
        let f = Fixture::new();
        let mut err = null_mut();
        let folder = c(&f.folder);

        assert!(bastion_library_folder_overview_json(null(), f.vault, null(), folder.as_ptr(), 0, &mut err).is_null());
        assert!(take(err).contains("library handle is NULL"));
        assert!(bastion_library_folder_overview_json(f.lib, f.vault, null(), null(), 0, &mut err).is_null());
        assert!(take(err).contains("folder id is required"));
        assert!(bastion_library_folder_overview_json(f.lib, f.vault, null(), BAD_UTF8.as_ptr().cast(), 0, &mut err).is_null());
        assert!(take(err).contains("not valid UTF-8"));
        assert!(bastion_library_folder_overview_json(f.lib, f.vault, BAD_UTF8.as_ptr().cast(), folder.as_ptr(), 0, &mut err).is_null());
        assert!(take(err).contains("not valid UTF-8"));

        assert!(f.overview(true, false, UNKNOWN_ID, false, &mut err).is_null(), "unknown folder");
        assert_eq!(code(), "not_found");
        take(err);
        assert!(f.overview(true, false, &f.ssh, false, &mut err).is_null(), "a connection is not a folder");
        take(err);
        assert!(f.overview(true, false, "not-an-id", false, &mut err).is_null());
        take(err);
        assert!(bastion_library_folder_overview_json(null(), null(), null(), null(), 0, null_mut()).is_null());
    }
}
