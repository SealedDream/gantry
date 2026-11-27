//! The ABI v10 workspace surface: save, list, replace by name, remove, and the refusals.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;

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

unsafe fn list(dir: &CString) -> Value {
    let mut err = null_mut();
    let json = take(bastion_workspaces_json(dir.as_ptr(), &mut err)).unwrap_or_else(|| panic!("{:?}", take(err)));
    serde_json::from_str(&json).unwrap()
}

const A: &str = "6f1c3c58-3d7c-4f43-9d0e-2b6a4f1f0a01";
const B: &str = "6f1c3c58-3d7c-4f43-9d0e-2b6a4f1f0a02";

#[test]
fn save_list_replace_and_remove() {
    unsafe {
        let tmp = tempfile::tempdir().unwrap();
        let dir = c(&tmp.path().to_string_lossy());
        assert_eq!(list(&dir), Value::Array(vec![]), "no file yet is an empty list");

        let mut err = null_mut();
        let id = take(bastion_workspace_save(dir.as_ptr(), c("Acme on-call").as_ptr(), c(&format!(r#"["{A}","{B}"]"#)).as_ptr(), 1, &mut err)).unwrap_or_else(|| panic!("{:?}", take(err)));
        let all = list(&dir);
        assert_eq!(all[0]["id"], id.as_str());
        assert_eq!(all[0]["name"], "Acme on-call");
        assert_eq!(all[0]["selected"], 1);
        assert_eq!(all[0]["tabs"][1]["connection"], B);
        assert_eq!(all[0]["tabs"][0]["mode"], "terminal");

        // The file holds ids and names only.
        let raw = std::fs::read_to_string(tmp.path().join("workspaces.json")).unwrap();
        assert!(!raw.contains("password") && !raw.contains("host"), "{raw}");

        // Same name (any case) replaces; `selected` is clamped to the tabs there are.
        let id2 = take(bastion_workspace_save(dir.as_ptr(), c("ACME ON-CALL").as_ptr(), c(&format!(r#"["{A}"]"#)).as_ptr(), 9, null_mut())).unwrap();
        let all = list(&dir);
        assert_eq!(all.as_array().unwrap().len(), 1);
        assert_eq!(all[0]["selected"], 0);

        assert_eq!(bastion_workspace_remove(dir.as_ptr(), c(&id).as_ptr(), &mut err), -1, "the replaced id is gone");
        assert!(take(err).is_some());
        assert_eq!(bastion_workspace_remove(dir.as_ptr(), c(&id2).as_ptr(), &mut err), 0, "{:?}", take(err));
        assert_eq!(list(&dir), Value::Array(vec![]));
    }
}

#[test]
fn bad_input_is_refused() {
    unsafe {
        let tmp = tempfile::tempdir().unwrap();
        let dir = c(&tmp.path().to_string_lossy());
        let many: Vec<String> = (0..257).map(|_| A.to_string()).collect();
        for (name, ids, what) in [
            ("  ", format!(r#"["{A}"]"#), "name"),
            ("x", "not json".to_string(), "JSON array"),
            ("x", r#"["web-1.example.com"]"#.to_string(), "not a connection id"),
            ("x", serde_json::to_string(&many).unwrap(), "at most 256"),
        ] {
            let mut err = null_mut();
            assert!(bastion_workspace_save(dir.as_ptr(), c(name).as_ptr(), c(&ids).as_ptr(), 0, &mut err).is_null(), "{what}");
            let msg = take(err).unwrap();
            assert!(msg.contains(what), "{what}: {msg}");
        }
        let mut err = null_mut();
        assert!(bastion_workspaces_json(c("").as_ptr(), &mut err).is_null());
        assert!(take(err).is_some());
        // A corrupt file is an error, not silently replaced.
        std::fs::write(tmp.path().join("workspaces.json"), b"{nope").unwrap();
        assert!(bastion_workspaces_json(dir.as_ptr(), &mut err).is_null());
        assert!(take(err).is_some());
    }
}

#[test]
fn files_mode_tabs_round_trip() {
    unsafe {
        let tmp = tempfile::tempdir().unwrap();
        let dir = c(&tmp.path().to_string_lossy());
        let tabs = format!(r#"["{A}",{{"connection":"{B}","mode":"files"}},{{"connection":"{A}"}}]"#);
        let mut err = null_mut();
        take(bastion_workspace_save(dir.as_ptr(), c("Mixed").as_ptr(), c(&tabs).as_ptr(), 1, &mut err)).unwrap_or_else(|| panic!("{:?}", take(err)));
        let all = list(&dir);
        let modes: Vec<_> = all[0]["tabs"].as_array().unwrap().iter().map(|t| t["mode"].as_str().unwrap().to_string()).collect();
        assert_eq!(modes, ["terminal", "files", "terminal"]);
        assert_eq!(all[0]["tabs"][1]["connection"], B);
        for bad in [format!(r#"[{{"connection":"{A}","mode":"web"}}]"#), r#"[{"mode":"files"}]"#.to_string(), "[7]".to_string()] {
            assert!(bastion_workspace_save(dir.as_ptr(), c("Bad").as_ptr(), c(&bad).as_ptr(), 0, &mut err).is_null(), "{bad}");
            take(err);
        }
    }
}

#[test]
fn create_refuses_duplicates_and_restore_plan_skips_open_and_deleted() {
    unsafe {
        let tmp = tempfile::tempdir().unwrap();
        let dir = c(&tmp.path().to_string_lossy());
        let mut err = null_mut();
        let tabs = c(&format!(r#"["{A}",{{"connection":"{B}","mode":"files"}}]"#));
        let id = take(bastion_workspace_create(dir.as_ptr(), c("Ops").as_ptr(), tabs.as_ptr(), &mut err)).unwrap_or_else(|| panic!("{:?}", take(err)));
        assert!(bastion_workspace_create(dir.as_ptr(), c("ops").as_ptr(), tabs.as_ptr(), &mut err).is_null());
        assert!(take(err).unwrap().contains("already exists"));

        let mut err = null_mut();
        let plan = take(bastion_workspace_restore_plan_json(dir.as_ptr(), c(&id).as_ptr(), c(&format!(r#"["{A}"]"#)).as_ptr(), c("[]").as_ptr(), &mut err)).unwrap_or_else(|| panic!("{:?}", take(err)));
        let plan: Value = serde_json::from_str(&plan).unwrap();
        assert_eq!(plan["missing"], 1, "B was deleted");
        assert_eq!(plan["open"].as_array().unwrap().len(), 1);
        assert_eq!(plan["open"][0]["connection"], A);
        assert_eq!(plan["select"]["connection"], A);

        let open = c(&format!(r#"["{A}"]"#));
        let plan = take(bastion_workspace_restore_plan_json(dir.as_ptr(), c(&id).as_ptr(), open.as_ptr(), open.as_ptr(), &mut err)).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&plan).unwrap()["open"], Value::Array(vec![]), "already-open tab is not reopened");
    }
}
