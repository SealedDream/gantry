//! The ABI 16 surface: settings registry and file, keyboard shortcuts, palette ranking, workspace split
//! layouts and Add to Workspace, Quick Connect and property options, driven as the WinUI P/Invoke layer does.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use serde_json::Value;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    bastion_string_free(p);
    Some(s)
}

unsafe fn json(p: *mut c_char, err: *mut c_char) -> Value {
    serde_json::from_str(&take(p).unwrap_or_else(|| panic!("{:?}", take(err)))).unwrap()
}

#[test]
fn settings_registry_search_and_file() {
    unsafe {
        let mut err = null_mut();
        let links = c(r#"["keyboard-shortcuts","credential-manager"]"#);
        let cats = json(bastion_setting_categories_json(links.as_ptr(), &mut err), err);
        assert!(cats.as_array().unwrap().iter().any(|c| c["id"] == "keyboard" && c["icon"] == "keyboard"));
        let defs = json(bastion_setting_definitions_json(links.as_ptr(), &mut err), err);
        let size = defs.as_array().unwrap().iter().find(|d| d["id"] == "terminal.font-size").unwrap();
        assert_eq!((size["kind"].as_str(), size["min"].as_i64(), size["max"].as_i64()), (Some("integer"), Some(9), Some(24)));
        assert!(defs.as_array().unwrap().iter().all(|d| d["link"] != "vaultwarden"), "unhandled links are hidden");
        let none = json(bastion_setting_categories_json(null(), &mut err), err);
        assert!(!none.as_array().unwrap().iter().any(|c| c["id"] == "keyboard"), "a category with only unhandled links is hidden");
        let hits = json(bastion_settings_search_json(c("hotkey").as_ptr(), links.as_ptr(), &mut err), err);
        assert_eq!(hits, serde_json::json!(["keyboard.shortcuts"]));
        assert_eq!(bastion_settings_auto_lock_due(c("off").as_ptr(), 1_000_000), 0);

        let dir = tempfile::tempdir().unwrap();
        let path = c(dir.path().join("settings.json").to_str().unwrap());
        let s = bastion_settings_open(path.as_ptr(), &mut err);
        assert!(!s.is_null());
        assert_eq!(bastion_settings_set(s, c("terminal.font-size").as_ptr(), c("15").as_ptr(), &mut err), 0);
        assert_eq!(bastion_settings_set(s, c("terminal.font-size").as_ptr(), c("99").as_ptr(), &mut err), -1);
        assert!(take(err).is_some(), "an out-of-range value is refused");
        bastion_settings_free(s);
        let again = bastion_settings_open(path.as_ptr(), &mut err);
        assert_eq!(take(bastion_settings_get(again, c("terminal.font-size").as_ptr(), &mut err)).unwrap(), "15");
        assert!(take(bastion_settings_get(again, c("no.such").as_ptr(), &mut err)).is_none());
        assert!(take(err).is_some());
        bastion_settings_free(again);
        std::fs::write(dir.path().join("settings.json"), "{").unwrap();
        assert!(bastion_settings_open(path.as_ptr(), &mut err).is_null(), "a damaged file is an error, not a silent reset");
        assert!(take(err).is_some());
    }
}

#[test]
fn shortcuts_on_windows_record_conflict_replace_and_reset() {
    unsafe {
        let mut err = null_mut();
        let dir = tempfile::tempdir().unwrap();
        let path = c(dir.path().join("shortcuts.json").to_str().unwrap());
        let win = c("windows");
        let s = bastion_shortcuts_open(path.as_ptr(), &mut err);
        assert!(!s.is_null());
        let list = json(bastion_shortcuts_list_json(s, win.as_ptr(), &mut err), err);
        let qc = list.as_array().unwrap().iter().find(|v| v["id"] == "quick-connect").unwrap();
        assert_eq!(qc["chord"], qc["defaultChord"]);
        assert_eq!(qc["isDefault"], true);
        let split = list.as_array().unwrap().iter().find(|v| v["id"] == "split-right").unwrap()["chord"].as_str().unwrap().to_string();

        let clash = json(bastion_shortcuts_conflict_json(s, c("quick-connect").as_ptr(), c(&split).as_ptr(), win.as_ptr(), &mut err), err);
        assert_eq!(clash["commandId"], "split-right");
        assert_eq!(json(bastion_shortcuts_conflict_json(s, c("quick-connect").as_ptr(), c("primary+alt+shift+9").as_ptr(), win.as_ptr(), &mut err), err), Value::Null);
        assert!(take(bastion_shortcuts_conflict_json(s, c("quick-connect").as_ptr(), c("ctrl+").as_ptr(), win.as_ptr(), &mut err)).is_none());
        assert!(take(err).is_some(), "a chord that does not parse is an error");

        assert_eq!(bastion_shortcuts_set(s, c("quick-connect").as_ptr(), c(&split).as_ptr(), win.as_ptr(), 0, &mut err), -1, "taken without replace");
        assert!(take(err).is_some());
        assert_eq!(bastion_shortcuts_set(s, c("quick-connect").as_ptr(), c(&split).as_ptr(), win.as_ptr(), 1, &mut err), 0, "{:?}", take(err));
        assert_eq!(bastion_shortcuts_set(s, c("palette").as_ptr(), null(), win.as_ptr(), 0, &mut err), 0);
        bastion_shortcuts_free(s);

        let s = bastion_shortcuts_open(path.as_ptr(), &mut err);
        let list = json(bastion_shortcuts_list_json(s, win.as_ptr(), &mut err), err);
        let get = |id: &str| list.as_array().unwrap().iter().find(|v| v["id"] == id).unwrap().clone();
        assert_eq!(get("quick-connect")["chord"].as_str(), Some(split.as_str()));
        assert_eq!(get("split-right")["chord"], Value::Null, "replace took it");
        assert_eq!(get("palette")["chord"], Value::Null);
        assert_eq!(json(bastion_shortcuts_shadowed_json(s, win.as_ptr(), &mut err), err), serde_json::json!([]));
        assert_eq!(bastion_shortcuts_reset(s, c("palette").as_ptr(), &mut err), 0);
        assert_eq!(bastion_shortcuts_reset(s, null(), &mut err), 0);
        let list = json(bastion_shortcuts_list_json(s, win.as_ptr(), &mut err), err);
        assert!(list.as_array().unwrap().iter().all(|v| v["isDefault"] == true));
        assert!(take(bastion_shortcuts_list_json(s, c("linux").as_ptr(), &mut err)).is_none());
        assert!(take(err).is_some());
        bastion_shortcuts_free(s);
        let hits = json(bastion_shortcuts_search_json(c("palette").as_ptr(), &mut err), err);
        assert!(hits.as_array().unwrap().iter().any(|v| v == "palette"));
    }
}

#[test]
fn palette_ranks_with_the_core_and_refuses_unknown_kinds() {
    unsafe {
        let mut err = null_mut();
        let entries = c(r#"[{"kind":"connection","title":"docker-sshd","detail":"SSH"},{"kind":"command","title":"Quick Connect…"}]"#);
        let p = bastion_palette_new(entries.as_ptr(), &mut err);
        assert!(!p.is_null());
        assert_eq!(json(bastion_palette_rank_json(p, c("qc").as_ptr(), 10, &mut err), err), serde_json::json!([1]));
        assert_eq!(json(bastion_palette_rank_json(p, c("docker").as_ptr(), 10, &mut err), err), serde_json::json!([0]));
        bastion_palette_free(p);
        assert!(bastion_palette_new(c(r#"[{"kind":"vm","title":"x"}]"#).as_ptr(), &mut err).is_null());
        assert!(take(err).is_some());
    }
}

const A: &str = "6f1c3c58-3d7c-4f43-9d0e-2b6a4f1f0a01";
const B: &str = "6f1c3c58-3d7c-4f43-9d0e-2b6a4f1f0a02";

#[test]
fn workspace_layouts_add_rename_duplicate() {
    unsafe {
        let mut err = null_mut();
        let tmp = tempfile::tempdir().unwrap();
        let dir = c(&tmp.path().to_string_lossy());
        let tabs = format!(r#"[{{"connection":"{A}","mode":"terminal","layout":["right:0.62","leaf","down","leaf","leaf"]}},{{"connection":"{B}","mode":"files"}}]"#);
        let saved = json(bastion_workspace_save_layout(dir.as_ptr(), c("Ops").as_ptr(), c(&tabs).as_ptr(), 1, &mut err), err);
        let id = saved["id"].as_str().unwrap().to_string();
        assert!(saved["lastUsed"].is_i64());
        let all = json(bastion_workspaces_json(dir.as_ptr(), &mut err), err);
        assert_eq!(all[0]["tabs"][0]["layout"], serde_json::json!(["right:0.620", "leaf", "down:0.500", "leaf", "leaf"]));
        assert_eq!(all[0]["tabs"][1]["layout"], serde_json::json!([]));
        assert_eq!(all[0]["selected"], 1);

        let again = json(bastion_workspace_save_layout(dir.as_ptr(), c("OPS").as_ptr(), c(&format!(r#"[{{"connection":"{A}","layout":["down:0.01","leaf","leaf"]}}]"#)).as_ptr(), 0, &mut err), err);
        assert_eq!(again["id"], id.as_str(), "Save Current Layout keeps the workspace");
        assert_eq!(again["tabs"][0]["layout"][0], "down:0.100", "ratios are clamped");
        assert!(take(bastion_workspace_save_layout(dir.as_ptr(), c("x").as_ptr(), c(&format!(r#"[{{"connection":"{A}","layout":["right","leaf"]}}]"#)).as_ptr(), 0, &mut err)).is_none());
        assert!(take(err).is_some(), "a broken layout is refused");

        let added = json(bastion_workspace_add_tab(dir.as_ptr(), c(&id).as_ptr(), c(&format!(r#"{{"connection":"{B}","mode":"terminal"}}"#)).as_ptr(), &mut err), err);
        assert_eq!(added["tabs"].as_array().unwrap().len(), 2);
        assert!(take(bastion_workspace_add_tab(dir.as_ptr(), c(&id).as_ptr(), c(&format!(r#"{{"connection":"{B}"}}"#)).as_ptr(), &mut err)).is_none());
        assert!(take(err).unwrap().contains("already opens"));

        assert_eq!(bastion_workspace_rename(dir.as_ptr(), c(&id).as_ptr(), c("On-call").as_ptr(), &mut err), 0);
        let copy = json(bastion_workspace_duplicate(dir.as_ptr(), c(&id).as_ptr(), &mut err), err);
        assert_eq!(copy["name"], "On-call copy");
        assert_eq!(bastion_workspace_rename(dir.as_ptr(), copy["id"].as_str().map(c).unwrap().as_ptr(), c("on-call").as_ptr(), &mut err), -1, "names stay unique");
        assert!(take(err).is_some());
        assert_eq!(bastion_workspace_mark_used(dir.as_ptr(), copy["id"].as_str().map(c).unwrap().as_ptr(), &mut err), 0);
        let names: Vec<String> = json(bastion_workspaces_json(dir.as_ptr(), &mut err), err).as_array().unwrap().iter().map(|w| w["name"].as_str().unwrap().to_string()).collect();
        assert_eq!(names, ["On-call", "On-call copy"]);
    }
}

#[test]
fn quick_connect_library_and_property_options() {
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_quick_connect(c("ops@10.0.0.5:2222").as_ptr(), &mut err);
        assert!(!lib.is_null(), "{:?}", take(err));
        let tree = json(bastion_library_tree_json(lib, &mut err), err);
        let conn = &tree["connections"][0];
        assert_eq!((conn["host"].as_str(), conn["port"].as_i64(), conn["username"].as_str()), (Some("10.0.0.5"), Some(2222), Some("ops")));
        assert_eq!(bastion_library_save(lib, &mut err), -1, "a Quick Connect library is never written");
        assert!(take(err).is_some());
        bastion_library_free(lib);
        assert!(bastion_library_quick_connect(c("").as_ptr(), &mut err).is_null());
        assert!(take(err).is_some());

        let schema = json(bastion_property_schema_json(c("rdp").as_ptr(), 0, &mut err), err);
        let env = schema.as_array().unwrap().iter().find(|d| d["key"] == "environment").unwrap();
        assert_eq!((env["kind"].as_str(), env["category"].as_str()), (Some("choice"), Some("Security")));
        assert_eq!(env["options"][4]["id"], "production");
        assert_eq!(schema.as_array().unwrap().iter().find(|d| d["key"] == "privileged").unwrap()["kind"], "toggle");
    }
}
