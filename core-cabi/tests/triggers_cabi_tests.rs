//! Triggers over the C ABI (ABI 69), as the Windows app uses them.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use bastion_cabi::*;
use serde_json::Value;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    Some(s)
}

#[test]
fn save_list_export_import_and_bad_input() {
    let d = tempfile::tempdir().unwrap();
    let path = c(d.path().join("triggers.json").to_str().unwrap());
    let other = c(d.path().join("other.json").to_str().unwrap());
    unsafe {
        let mut err = null_mut();
        let id = take(bastion_triggers_save_json(path.as_ptr(), c(r#"{"name":"Errors","pattern":"ERROR","highlight":{"fg":16711680,"bold":true}}"#).as_ptr(), &mut err)).expect("saved");
        take(bastion_triggers_save_json(path.as_ptr(), c(r#"{"name":"Done","pattern":"finished","notify":true}"#).as_ptr(), &mut err)).unwrap();
        let list: Value = serde_json::from_str(&take(bastion_triggers_list_json(path.as_ptr(), &mut err)).unwrap()).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 2);
        assert_eq!(list[0]["id"], id.as_str());
        assert_eq!(list[0]["highlight"]["fg"], 16711680);
        assert_eq!(list[1]["enabled"], true);

        let exported = take(bastion_triggers_export_json(path.as_ptr(), &mut err)).unwrap();
        assert_eq!(bastion_triggers_import_json(other.as_ptr(), c(&exported).as_ptr(), &mut err), 2);
        assert_eq!(bastion_triggers_import_json(other.as_ptr(), c(&exported).as_ptr(), &mut err), 2);
        let again: Value = serde_json::from_str(&take(bastion_triggers_list_json(other.as_ptr(), &mut err)).unwrap()).unwrap();
        assert_eq!(again, list, "import twice = same list");

        for bad in [r#"{"name":"x","pattern":"("}"#, r#"{"name":"x","pattern":".*","notify":true}"#, "not json", r#"{"name":"x","pattern":"y"}"#] {
            let mut err = null_mut();
            assert!(bastion_triggers_save_json(path.as_ptr(), c(bad).as_ptr(), &mut err).is_null(), "{bad}");
            assert!(take(err).is_some());
        }
        let mut err = null_mut();
        assert_eq!(bastion_triggers_import_json(other.as_ptr(), c("{\"triggers\":[{}]}").as_ptr(), &mut err), -1);
        take(err);
        let mut err = null_mut();
        assert_eq!(bastion_triggers_remove(path.as_ptr(), c(&id).as_ptr(), &mut err), 0);
        assert_eq!(bastion_triggers_remove(path.as_ptr(), c(&id).as_ptr(), &mut err), -1);
        take(err);
        assert!(bastion_triggers_list_json(null(), &mut null_mut()).is_null());
    }
}

#[cfg(unix)]
#[test]
fn a_terminal_highlights_and_notifies() {
    let d = tempfile::tempdir().unwrap();
    let path = c(d.path().join("triggers.json").to_str().unwrap());
    unsafe {
        let mut err = null_mut();
        take(bastion_triggers_save_json(path.as_ptr(), c(r#"{"name":"Errors","pattern":"ERROR","highlight":{"bg":255},"notify":true}"#).as_ptr(), &mut err)).unwrap();
        let args = c(r#"["-c","sleep 0.3; echo build ERROR now; sleep 5"]"#);
        let t = bastion_terminal_spawn(c("/bin/sh").as_ptr(), args.as_ptr(), 40, 5, &mut err);
        assert!(!t.is_null());
        assert_eq!(bastion_terminal_set_triggers(t, path.as_ptr(), &mut err), 0);
        let deadline = Instant::now() + Duration::from_secs(10);
        let events = loop {
            let ev: Value = serde_json::from_str(&take(bastion_terminal_take_trigger_events_json(t, &mut err)).unwrap()).unwrap();
            if !ev.as_array().unwrap().is_empty() || Instant::now() > deadline {
                break ev;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(events[0]["name"], "Errors");
        assert_eq!(events[0]["line"], "build ERROR now");
        let s = bastion_terminal_screen(t, &mut err);
        assert!(!s.is_null());
        let screen = &*s;
        let cells = std::slice::from_raw_parts(screen.cells, screen.cols as usize * screen.rows as usize);
        let row = (0..screen.rows as usize).find(|r| cells[r * screen.cols as usize + 6].bg == 255).expect("a highlighted row");
        assert_ne!(cells[row * screen.cols as usize + 5].bg, 255, "space before ERROR");
        bastion_screen_free(s);
        assert_eq!(bastion_terminal_set_triggers(t, null(), &mut err), 0);
        let mut err = null_mut();
        std::fs::write(d.path().join("triggers.json"), b"broken").unwrap();
        assert_eq!(bastion_terminal_set_triggers(t, path.as_ptr(), &mut err), -1);
        take(err);
        bastion_terminal_free(t);
    }
}
