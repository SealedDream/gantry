//! The property editor surface through the C ABI: schema, values with their source, inheritance
//! from folder and type defaults, validation, and the affected-connections preview.
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

unsafe fn json(p: *mut c_char) -> Value {
    serde_json::from_str(&take(p)).unwrap()
}

fn find<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.as_array().unwrap().iter().find(|x| x["key"] == key).unwrap_or_else(|| panic!("no {key} in {v}"))
}

unsafe fn set(lib: *const BastionLibrary, id: &str, key: &str, value: Option<&str>) -> Result<(), String> {
    let mut err = null_mut();
    let v = value.map(c);
    if bastion_library_set_property(lib, c(id).as_ptr(), c(key).as_ptr(), v.as_ref().map_or(null(), |s| s.as_ptr()), &mut err) == 0 {
        Ok(())
    } else {
        Err(take(err))
    }
}

#[test]
fn schema_only_lists_what_the_core_honours() {
    unsafe {
        let mut err = null_mut();
        let ssh = json(bastion_property_schema_json(c("ssh").as_ptr(), 0, &mut err));
        let keys: Vec<&str> = ssh.as_array().unwrap().iter().map(|d| d["key"].as_str().unwrap()).collect();
        assert_eq!(keys, ["name", "host", "port", "username", "credential_id", "credential_name", "keepalive_secs", "auto_reconnect", "gateway_id", "terminal_theme", "terminal_font_family", "terminal_font_size", "terminal_ligatures", "session_log", "session_log_folder", "session_log_keep_days", "terminal.osc52_write", "ssh_algorithms", "ssh.transport", "ssh.tmux", "ssh.tmux_session", "wol_mac", "wol_broadcast", "wol_port", "wol_secureon", "wol_before_connect", "wol_wait_secs", "host_status", "no_preview", "tab_group_color", "host_color", "environment", "customer_sensitive", "privileged", "notes", "tags"]);
        let rdp = json(bastion_property_schema_json(c("rdp").as_ptr(), 0, &mut err));
        assert!(!rdp.to_string().contains("keepalive"), "keep-alive is SSH only");
        let folder = json(bastion_property_schema_json(null(), 1, &mut err));
        assert!(folder.as_array().unwrap().iter().all(|d| d["inheritable"] == true));
        assert!(bastion_property_schema_json(c("gopher").as_ptr(), 0, &mut err).is_null());
        assert!(take(err).contains("unknown protocol"));
    }
}

#[test]
fn values_inherit_from_folder_then_type_default_and_validate() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(dir.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let folder = take(bastion_library_add_folder(lib, null(), c("Acme").as_ptr(), &mut err));
        let web = take(bastion_library_add_connection(lib, c(&folder).as_ptr(), c("web").as_ptr(), c("ssh").as_ptr(), c("web.acme").as_ptr(), -1, null(), &mut err));

        // Built-in port, nothing else set.
        let v = json(bastion_library_property_values_json(lib, c(&web).as_ptr(), &mut err));
        assert_eq!((find(&v, "port")["effective"].as_str(), find(&v, "port")["source"].as_str()), (Some("22"), Some("builtin")));

        // Type default, then a folder default nearer, then the connection's own value.
        assert_eq!(bastion_library_set_type_default(lib, c("ssh").as_ptr(), c("username").as_ptr(), c("ops").as_ptr(), &mut err), 0);
        let v = json(bastion_library_property_values_json(lib, c(&web).as_ptr(), &mut err));
        assert_eq!((find(&v, "username")["effective"].as_str(), find(&v, "username")["source"].as_str()), (Some("ops"), Some("typedefault")));
        set(lib, &folder, "username", Some("acme-ops")).unwrap();
        let v = json(bastion_library_property_values_json(lib, c(&web).as_ptr(), &mut err));
        assert_eq!((find(&v, "username")["effective"].as_str(), find(&v, "username")["source"].as_str(), find(&v, "username")["from"].as_str()), (Some("acme-ops"), Some("inherited"), Some("Acme")));
        let affected = json(bastion_library_affected_by_default_json(lib, c(&folder).as_ptr(), null(), c("username").as_ptr(), &mut err));
        assert_eq!(affected, serde_json::json!(["web"]));
        set(lib, &web, "username", Some("me")).unwrap();
        let v = json(bastion_library_property_values_json(lib, c(&web).as_ptr(), &mut err));
        assert_eq!(find(&v, "username")["source"], "own");
        assert_eq!(json(bastion_library_affected_by_default_json(lib, c(&folder).as_ptr(), null(), c("username").as_ptr(), &mut err)), serde_json::json!([]));
        // Blank resets to inherited.
        set(lib, &web, "username", Some("  ")).unwrap();
        let v = json(bastion_library_property_values_json(lib, c(&web).as_ptr(), &mut err));
        assert_eq!(find(&v, "username")["source"], "inherited");

        // The folder's own Default Settings view.
        let fv = json(bastion_library_property_values_json(lib, c(&folder).as_ptr(), &mut err));
        assert_eq!(find(&fv, "username")["own"], "acme-ops");
        let tv = json(bastion_library_type_default_values_json(lib, c("ssh").as_ptr(), &mut err));
        assert_eq!(find(&tv, "username")["own"], "ops");

        // Other fields and validation.
        set(lib, &web, "keepalive_secs", Some("30")).unwrap();
        set(lib, &web, "notes", Some("line 1\nline 2")).unwrap();
        set(lib, &web, "host", Some("web2.acme")).unwrap();
        assert!(set(lib, &web, "port", Some("0")).unwrap_err().contains("Port"));
        assert!(set(lib, &web, "keepalive_secs", Some("999999")).unwrap_err().contains("Keep-alive"));
        assert!(set(lib, &web, "nope", Some("x")).is_err());
        assert_eq!(bastion_library_set_type_default(lib, c("ssh").as_ptr(), c("notes").as_ptr(), c("x").as_ptr(), &mut err), -1);
        take(err);
        let tree = take(bastion_library_tree_json(lib, &mut err));
        assert!(tree.contains("web2.acme"), "{tree}");
        assert_eq!(bastion_library_save(lib, &mut err), 0);
        bastion_library_free(lib);
    }
}

#[test]
fn ssh_algorithms_inherit_validate_and_allow_for_host() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(dir.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let folder = take(bastion_library_add_folder(lib, null(), c("Legacy").as_ptr(), &mut err));
        let old = take(bastion_library_add_connection(lib, c(&folder).as_ptr(), c("old").as_ptr(), c("ssh").as_ptr(), c("old.lan").as_ptr(), -1, null(), &mut err));

        set(lib, &folder, "ssh_algorithms", Some(r#"{"ciphers":"aes256-ctr"}"#)).unwrap();
        let v = json(bastion_library_property_values_json(lib, c(&old).as_ptr(), &mut err));
        assert_eq!(find(&v, "ssh_algorithms")["source"], "inherited");
        assert_eq!(find(&v, "ssh_algorithms")["from"], "Legacy");
        assert!(set(lib, &old, "ssh_algorithms", Some(r#"{"ciphers":"none"}"#)).unwrap_err().contains("no usable cipher"));
        assert!(set(lib, &old, "ssh_algorithms", Some("not json")).is_err());

        // Only weak, implemented names can be allowed.
        assert_eq!(bastion_library_allow_weak_algorithms(lib, c(&old).as_ptr(), c("cipher").as_ptr(), c(r#"["aes256-ctr"]"#).as_ptr(), &mut err), -1);
        take(err);
        assert_eq!(bastion_library_allow_weak_algorithms(lib, c(&old).as_ptr(), c("cipher").as_ptr(), c(r#"["aes128-cbc"]"#).as_ptr(), &mut err), 0);
        let v = json(bastion_library_property_values_json(lib, c(&old).as_ptr(), &mut err));
        let own: Value = serde_json::from_str(find(&v, "ssh_algorithms")["own"].as_str().unwrap()).unwrap();
        assert_eq!(own["allow_weak"], true);

        let p = json(bastion_ssh_algorithms_preview_json(c(own.to_string().as_str()).as_ptr(), &mut err));
        assert_eq!(p["ciphers"], serde_json::json!(["aes256-ctr", "aes128-cbc"]));
        assert_eq!(p["weakEnabled"], serde_json::json!(["aes128-cbc"]));
        assert!(p["catalogue"]["kex"].as_array().unwrap().iter().any(|a| a["weak"] == true));
        assert!(p["unsupported"].to_string().contains("umac-64@openssh.com"));
        let d = json(bastion_ssh_algorithms_preview_json(null(), &mut err));
        assert!(d["weakEnabled"].as_array().unwrap().is_empty() && d["error"].is_null());
        bastion_library_free(lib);
    }
}

#[test]
fn host_colour_is_validated_inherited_and_derived() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(dir.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let folder = take(bastion_library_add_folder(lib, null(), c("Prod").as_ptr(), &mut err));
        let web = take(bastion_library_add_connection(lib, c(&folder).as_ptr(), c("web").as_ptr(), c("ssh").as_ptr(), c("web.prod").as_ptr(), -1, null(), &mut err));

        assert_eq!(json(bastion_library_host_color_json(lib, c(&web).as_ptr(), &mut err)), Value::Null);
        assert!(set(lib, &folder, "host_color", Some("blurple")).unwrap_err().contains("not a colour"));

        set(lib, &folder, "host_color", Some("Red")).unwrap();
        let hc = json(bastion_library_host_color_json(lib, c(&web).as_ptr(), &mut err));
        assert_eq!((hc["accent"].as_str(), hc["text"].as_str(), hc["tint"].as_str()), (Some("#d64545"), Some("#000000"), Some("#d645452e")));
        // UI-01: nearest preset, privileged flag and text-safe tones.
        assert_eq!((hc["named"].as_str(), hc["privileged"].as_bool()), (Some("Red"), Some(false)));
        for k in ["fgLight", "bgLight", "fgDark", "bgDark"] { assert!(hc[k].as_str().is_some_and(|v| v.len() == 7), "{k}"); }
        let v = json(bastion_library_property_values_json(lib, c(&web).as_ptr(), &mut err));
        assert_eq!((find(&v, "host_color")["effective"].as_str(), find(&v, "host_color")["source"].as_str()), (Some("#d64545"), Some("inherited")));

        set(lib, &web, "host_color", Some("#FE0")).unwrap();
        let hc = json(bastion_library_host_color_json(lib, c(&web).as_ptr(), &mut err));
        assert_eq!((hc["accent"].as_str(), hc["text"].as_str()), (Some("#ffee00"), Some("#000000")));

        set(lib, &web, "host_color", None).unwrap();
        assert_eq!(json(bastion_library_host_color_json(lib, c(&web).as_ptr(), &mut err))["accent"], "#d64545");
        // The bulk call (one tree pass) gives the same colour, and leaves out uncoloured connections.
        let plain = take(bastion_library_add_connection(lib, null(), c("plain").as_ptr(), c("ssh").as_ptr(), c("p").as_ptr(), -1, null(), &mut err));
        let all = json(bastion_library_host_colors_json(lib, &mut err));
        assert_eq!(all[&web], json(bastion_library_host_color_json(lib, c(&web).as_ptr(), &mut err)));
        assert!(all.get(&plain).is_none());
        // UI-01: the coloured folder is listed too (the tree tints its icon).
        assert_eq!(all[&folder]["accent"], "#d64545");
        assert_eq!(all.as_object().unwrap().len(), 2);
        assert!(bastion_library_host_color_json(lib, c("not-an-id").as_ptr(), &mut err).is_null());
        take(err);
        bastion_library_free(lib);
    }
}

#[test]
fn mosh_and_tmux_settings_validate_and_mosh_refuses_gateways() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(dir.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let web = take(bastion_library_add_connection(lib, null(), c("web").as_ptr(), c("ssh").as_ptr(), c("web.example").as_ptr(), -1, null(), &mut err));
        assert!(set(lib, &web, "ssh.tmux", Some("always")).is_err());
        assert!(set(lib, &web, "ssh.tmux_session", Some("a:b")).unwrap_err().contains("tmux session"));
        set(lib, &web, "ssh.tmux", Some("attach")).unwrap();
        set(lib, &web, "ssh.tmux_session", Some("ops")).unwrap();
        let v = json(bastion_library_property_values_json(lib, c(&web).as_ptr(), &mut err));
        assert_eq!(find(&v, "ssh.tmux")["effective"].as_str(), Some("attach"));

        // Transport is still SSH: Mosh refuses to open it.
        assert!(bastion_terminal_open_mosh(lib, c(&web).as_ptr(), 80, 24, &mut err).is_null());
        assert!(take(err).contains("does not use Mosh"));
        set(lib, &web, "ssh.transport", Some("mosh")).unwrap();
        let mut err = null_mut();
        let t = bastion_terminal_open_mosh(lib, c(&web).as_ptr(), 0, 24, &mut err);
        assert!(t.is_null(), "zero size refused");
        take(err);
        bastion_library_free(lib);
    }
}

#[test]
fn session_log_inherits_from_folder_and_a_connection_override_turns_it_off() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(dir.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let folder = take(bastion_library_add_folder(lib, null(), c("Logged").as_ptr(), &mut err));
        let web = take(bastion_library_add_connection(lib, c(&folder).as_ptr(), c("web").as_ptr(), c("ssh").as_ptr(), c("web.acme").as_ptr(), -1, null(), &mut err));
        let db = take(bastion_library_add_connection(lib, c(&folder).as_ptr(), c("db").as_ptr(), c("ssh").as_ptr(), c("db.acme").as_ptr(), -1, null(), &mut err));

        // Off by default.
        assert_eq!(bastion_library_session_log(lib, c(&web).as_ptr(), &mut err), 0);
        // On for the folder: both children inherit it.
        set(lib, &folder, "session_log", Some("true")).unwrap();
        assert_eq!(bastion_library_session_log(lib, c(&web).as_ptr(), &mut err), 1);
        assert_eq!(bastion_library_session_log(lib, c(&db).as_ptr(), &mut err), 1);
        // A connection override turns it off for that child only.
        set(lib, &db, "session_log", Some("false")).unwrap();
        assert_eq!(bastion_library_session_log(lib, c(&db).as_ptr(), &mut err), 0);
        assert_eq!(bastion_library_session_log(lib, c(&web).as_ptr(), &mut err), 1);

        // Unknown or malformed ids and a NULL handle report -1 with a message.
        assert_eq!(bastion_library_session_log(lib, c("not-a-uuid").as_ptr(), &mut err), -1);
        assert!(!take(err).is_empty());
        err = null_mut();
        assert_eq!(bastion_library_session_log(lib, c("00000000-0000-0000-0000-000000000000").as_ptr(), &mut err), -1);
        assert!(!take(err).is_empty());
        err = null_mut();
        assert_eq!(bastion_library_session_log(null(), c(&web).as_ptr(), &mut err), -1);
        assert!(!take(err).is_empty());
        bastion_library_free(lib);
    }
}
