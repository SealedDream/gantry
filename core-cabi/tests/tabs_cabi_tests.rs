//! The ABI v32 tab-group surface: strip operations, folder auto-grouping with the inherited
//! "Tab group colour", and workspaces saved and listed with their groups.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use serde_json::{json, Value};

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

unsafe fn ok(p: *mut c_char, err: *mut c_char) -> Value {
    let out = take(p).unwrap_or_else(|| panic!("{:?}", take(err)));
    serde_json::from_str(&out).unwrap()
}

const T: [&str; 3] = ["6f1c3c58-3d7c-4f43-9d0e-2b6a4f1f0b01", "6f1c3c58-3d7c-4f43-9d0e-2b6a4f1f0b02", "6f1c3c58-3d7c-4f43-9d0e-2b6a4f1f0b03"];

#[test]
fn colours_and_strip_operations() {
    unsafe {
        let colors = ok(bastion_tab_group_colors_json(), null_mut());
        assert_eq!(colors.as_array().unwrap().len(), 8);
        let strip = json!({ "tabs": T.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>() });
        let mut err = null_mut();
        let op = json!({ "op": "newGroup", "tabs": [T[0], T[2]], "name": "Ops", "color": "green" });
        let out = ok(bastion_tab_strip_apply_json(c(&strip.to_string()).as_ptr(), c(&op.to_string()).as_ptr(), &mut err), err);
        let s = &out["strip"];
        assert_eq!(s["tabs"].as_array().unwrap().iter().map(|t| t["id"].as_str().unwrap()).collect::<Vec<_>>(), [T[0], T[2], T[1]]);
        assert_eq!((s["groups"][0]["name"].as_str(), s["groups"][0]["color"].as_str()), (Some("Ops"), Some("green")));
        let close = json!({ "op": "closeGroup", "group": s["groups"][0]["id"] });
        let out = ok(bastion_tab_strip_apply_json(c(&s.to_string()).as_ptr(), c(&close.to_string()).as_ptr(), &mut err), err);
        assert_eq!(out["closed"], json!([T[0], T[2]]));

        let p = bastion_tab_strip_apply_json(c(&strip.to_string()).as_ptr(), c(r#"{"op":"explode"}"#).as_ptr(), &mut err);
        assert!(p.is_null());
        assert!(take(err).unwrap().contains("invalid tab operation"));
    }
}

#[test]
fn auto_group_uses_the_folder_name_and_inherited_colour() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(dir.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let parent = take(bastion_library_add_folder(lib, null(), c("Customers").as_ptr(), &mut err)).unwrap();
        let acme = take(bastion_library_add_folder(lib, c(&parent).as_ptr(), c("Acme").as_ptr(), &mut err)).unwrap();
        let conns: Vec<String> = ["a", "b"]
            .iter()
            .map(|n| take(bastion_library_add_connection(lib, c(&acme).as_ptr(), c(n).as_ptr(), c("ssh").as_ptr(), c("h").as_ptr(), -1, null(), &mut err)).unwrap())
            .collect();
        assert_eq!(bastion_library_set_property(lib, c(&parent).as_ptr(), c("tab_group_color").as_ptr(), c("pink").as_ptr(), &mut err), 0);
        let strip = json!({ "tabs": [{ "id": T[0], "connection": conns[0] }, { "id": T[1], "connection": conns[1] }] });
        let out = ok(bastion_tab_strip_auto_group_json(lib, c(&strip.to_string()).as_ptr(), 1, &mut err), err);
        assert_eq!((out["groups"][0]["name"].as_str(), out["groups"][0]["color"].as_str()), (Some("Acme"), Some("pink")));
        let off = ok(bastion_tab_strip_auto_group_json(lib, c(&out.to_string()).as_ptr(), 0, &mut err), err);
        assert_eq!(off["groups"], json!([]));

        // Saved with the workspace and listed back after reopening the file.
        let data = c(&dir.path().to_string_lossy());
        let tabs: Vec<Value> = out["tabs"].as_array().unwrap().iter().map(|t| json!({ "connection": t["connection"], "mode": "terminal", "group": t["group"] })).collect();
        let saved = ok(
            bastion_workspace_save_grouped_layout(data.as_ptr(), c("Acme").as_ptr(), c(&Value::Array(tabs).to_string()).as_ptr(), c(&out["groups"].to_string()).as_ptr(), 0, &mut err),
            err,
        );
        assert_eq!(saved["tabs"][1]["group"], out["groups"][0]["id"]);
        let listed = ok(bastion_workspaces_json(data.as_ptr(), &mut err), err);
        assert_eq!(listed[0]["groups"], out["groups"]);
        bastion_library_free(lib);
    }
}
