//! The ABI 15 tree and menu surface, driven as the WinUI host's P/Invoke layer does.
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

#[test]
fn menus_moves_and_tokens_over_the_c_abi() {
    unsafe {
        let dir = tempfile::tempdir().unwrap();
        let mut err: *mut c_char = null_mut();
        let lib = bastion_library_open(c(dir.path().join("lib.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let prod = take(bastion_library_add_folder(lib, null(), c("Prod").as_ptr(), &mut err));
        let lab = take(bastion_library_add_folder(lib, null(), c("Lab").as_ptr(), &mut err));
        let web = take(bastion_library_add_connection(lib, c(&prod).as_ptr(), c("web").as_ptr(), c("ssh").as_ptr(), c("10.0.0.5").as_ptr(), 2222, c("ops").as_ptr(), &mut err));
        let db = take(bastion_library_add_connection(lib, c(&prod).as_ptr(), c("db").as_ptr(), c("rdp").as_ptr(), c("db.lan").as_ptr(), -1, null(), &mut err));

        let all = take(bastion_action_ids_json());
        let sessions = format!(r#"{{"connected":["{web}"]}}"#);
        let menu: Value = serde_json::from_str(&take(bastion_library_menu_json(lib, c(&web).as_ptr(), c(&sessions).as_ptr(), c(&all).as_ptr(), &mut err))).unwrap();
        assert!(err.is_null());
        assert_eq!(menu[0]["label"], "Show Session");
        assert!(menu.as_array().unwrap().iter().any(|i| i["id"] == "disconnect" && i["enabled"] == true));
        let only: Value = serde_json::from_str(&take(bastion_library_menu_json(lib, c(&db).as_ptr(), null(), c(r#"["connect","delete"]"#).as_ptr(), &mut err))).unwrap();
        assert_eq!(only.as_array().unwrap().iter().map(|i| i["id"].as_str().unwrap()).collect::<Vec<_>>(), ["connect", "delete"]);

        assert_eq!(bastion_library_move_before(lib, c(&db).as_ptr(), c(&prod).as_ptr(), c(&web).as_ptr(), &mut err), 0);
        assert_eq!(bastion_library_move_before(lib, c(&prod).as_ptr(), c(&prod).as_ptr(), null(), &mut err), -1, "folder into itself");
        assert!(take(err).contains("itself"));
        err = null_mut();
        assert_eq!(bastion_library_rename(lib, c(&lab).as_ptr(), c("Lab 2").as_ptr(), &mut err), 0);
        let copy = take(bastion_library_duplicate(lib, c(&prod).as_ptr(), &mut err));
        assert_ne!(copy, prod);
        assert_eq!(bastion_library_sort(lib, null(), 0, &mut err), 0);
        let tree: Value = serde_json::from_str(&take(bastion_library_tree_json(lib, &mut err))).unwrap();
        let names: Vec<&str> = tree["folders"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["Lab 2", "Prod", "Prod (copy)"]);
        assert_eq!(tree["folders"][1]["connections"][0]["name"], "db", "db moved before web");
        assert_eq!(take(bastion_library_copy_text(lib, c(&web).as_ptr(), 1, &mut err)), "ssh -p 2222 ops@10.0.0.5");

        let icons: Value = serde_json::from_str(&take(bastion_icons_json())).unwrap();
        assert!(icons.as_array().unwrap().iter().any(|i| i["id"] == "rdp" && i["label"] == "Remote Desktop (RDP)"));
        let dark: Value = serde_json::from_str(&take(bastion_theme_colors_json(1))).unwrap();
        assert!(dark["icon.terminal"].as_str().unwrap().starts_with('#'));
        bastion_library_free(lib);
    }
}

#[test]
fn tree_state_and_favorites_persist_over_the_c_abi() {
    unsafe {
        let dir = tempfile::tempdir().unwrap();
        let mut err: *mut c_char = null_mut();
        let lib = bastion_library_open(c(dir.path().join("lib.json").to_str().unwrap()).as_ptr(), &mut err);
        let prod = take(bastion_library_add_folder(lib, null(), c("Prod").as_ptr(), &mut err));
        let eu = take(bastion_library_add_folder(lib, c(&prod).as_ptr(), c("EU").as_ptr(), &mut err));
        let lab = take(bastion_library_add_folder(lib, null(), c("Lab").as_ptr(), &mut err));
        let web = take(bastion_library_add_connection(lib, c(&eu).as_ptr(), c("web").as_ptr(), c("ssh").as_ptr(), c("h").as_ptr(), -1, null(), &mut err));
        assert_eq!(bastion_library_set_favorite(lib, c(&web).as_ptr(), 1, &mut err), 0);
        let tree: Value = serde_json::from_str(&take(bastion_library_tree_json(lib, &mut err))).unwrap();
        assert_eq!(tree["folders"][0]["folders"][0]["connections"][0]["favorite"], true);
        assert_eq!(bastion_library_set_favorite(lib, c("not-an-id").as_ptr(), 1, &mut err), -1);
        drop(take(err));
        err = null_mut();

        let path = c(dir.path().join("ui-state.json").to_str().unwrap());
        let st = bastion_tree_state_open(path.as_ptr(), &mut err);
        assert!(!st.is_null() && err.is_null());
        assert_eq!(take(bastion_tree_state_expanded_json(st, &mut err)), "[]");
        assert_eq!(bastion_tree_state_set_expanded(st, c(&lab).as_ptr(), 1, &mut err), 0);
        assert_eq!(bastion_tree_state_set_subtree(st, lib, c(&prod).as_ptr(), 1, &mut err), 0);
        assert_eq!(bastion_tree_state_set_inspector_visible(st, 0, &mut err), 0);
        bastion_tree_state_free(st);

        // Reopened: the same state, read from disk.
        let st = bastion_tree_state_open(path.as_ptr(), &mut err);
        let mut ids: Vec<String> = serde_json::from_str(&take(bastion_tree_state_expanded_json(st, &mut err))).unwrap();
        ids.sort();
        let mut want = vec![prod.clone(), eu.clone(), lab.clone()];
        want.sort();
        assert_eq!(ids, want);
        assert_eq!(bastion_tree_state_inspector_visible(st), 0);
        assert_eq!(bastion_tree_state_set_subtree(st, lib, null(), 0, &mut err), 0, "Collapse All on the root");
        assert_eq!(take(bastion_tree_state_expanded_json(st, &mut err)), "[]");
        assert_eq!(bastion_tree_state_set_expanded(st, c(&lab).as_ptr(), 1, &mut err), 0);
        assert_eq!(bastion_library_remove(lib, c(&lab).as_ptr(), &mut err), 0);
        assert_eq!(bastion_tree_state_prune(st, lib, &mut err), 0);
        assert_eq!(take(bastion_tree_state_expanded_json(st, &mut err)), "[]", "deleted folders are forgotten");
        assert_eq!(bastion_tree_state_set_expanded(st, c("bad").as_ptr(), 1, &mut err), -1);
        drop(take(err));
        assert_eq!(bastion_tree_state_inspector_visible(null()), 1, "NULL handle: default, no crash");
        bastion_tree_state_free(st);
        bastion_library_free(lib);
    }
}

#[test]
fn tree_json_carries_the_core_icon_and_its_full_name() {
    unsafe {
        let dir = tempfile::tempdir().unwrap();
        let mut err: *mut c_char = null_mut();
        let lib = bastion_library_open(c(dir.path().join("lib.json").to_str().unwrap()).as_ptr(), &mut err);
        for (name, protocol) in [("ssh-1", "ssh"), ("rdp-1", "rdp"), ("vnc-1", "vnc"), ("web-1", "web")] {
            take(bastion_library_add_connection(lib, null(), c(name).as_ptr(), c(protocol).as_ptr(), c("h.example").as_ptr(), -1, null(), &mut err));
        }
        let tree: Value = serde_json::from_str(&take(bastion_library_tree_json(lib, &mut err))).unwrap();
        let icons: Value = serde_json::from_str(&take(bastion_icons_json())).unwrap();
        let known: Vec<&str> = icons.as_array().unwrap().iter().map(|i| i["id"].as_str().unwrap()).collect();
        for conn in tree["connections"].as_array().unwrap() {
            let icon = conn["icon"].as_str().expect("icon id");
            assert!(known.contains(&icon), "{icon} is a registry icon");
            assert!(conn["iconLabel"].as_str().is_some_and(|l| !l.is_empty()), "full name for the tooltip");
        }
        let distinct: std::collections::HashSet<_> = tree["connections"].as_array().unwrap().iter().map(|c| c["icon"].as_str().unwrap().to_string()).collect();
        assert_eq!(distinct.len(), 4, "each protocol has its own icon");
        bastion_library_free(lib);
    }
}

#[test]
fn accents_and_density_metrics_come_from_the_core() {
    unsafe {
        let accents: Value = serde_json::from_str(&take(bastion_theme_accents_json())).unwrap();
        assert_eq!(accents.as_object().unwrap().len(), 6, "{accents}");
        assert_eq!(accents["electric"], "#2E6BFF");
        let m = |d: &str| -> Value { serde_json::from_str(&take(bastion_theme_metrics_json(c(d).as_ptr()))).unwrap() };
        assert_eq!(m("comfortable")["treeRow"], 26.0);
        assert!(m("compact")["treeRow"].as_f64() < m("comfortable")["treeRow"].as_f64() && m("comfortable")["treeRow"].as_f64() < m("spacious")["treeRow"].as_f64());
        assert_eq!(m("bogus"), m("comfortable"), "an unknown id is comfortable");
        let null: Value = serde_json::from_str(&take(bastion_theme_metrics_json(std::ptr::null()))).unwrap();
        assert_eq!(null, m("comfortable"));
    }
}
