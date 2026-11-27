//! Terminal themes through the C ABI (88): list, duplicate, edit with refusals and a contrast
//! warning, remove, and applying a user theme to a live terminal.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;
use std::time::{Duration, Instant};

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

unsafe fn list(dir: &CString) -> Vec<Value> {
    let mut err = null_mut();
    serde_json::from_str(&take(bastion_termthemes_list_json(dir.as_ptr(), &mut err))).unwrap()
}

unsafe fn put(dir: &CString, theme: &Value) -> Result<Value, String> {
    let mut err = null_mut();
    let r = bastion_termthemes_put(dir.as_ptr(), c(&theme.to_string()).as_ptr(), &mut err);
    if r.is_null() {
        Err(take(err))
    } else {
        Ok(serde_json::from_str(&take(r)).unwrap())
    }
}

#[test]
fn bundled_and_custom_themes_round_trip_with_refusals() {
    let d = tempfile::tempdir().unwrap();
    let dir = c(d.path().to_str().unwrap());
    unsafe {
        let all = list(&dir);
        assert_eq!(all.len(), 13, "13 bundled themes, no custom yet");
        assert!(all.iter().all(|t| t["bundled"] == true && t["ansi"].as_array().unwrap().len() == 16));
        assert_eq!(all[0]["id"], "bastion-dark");
        assert!(all[0]["foreground"].as_str().unwrap().starts_with('#'));

        let mut err = null_mut();
        let mut theme: Value = serde_json::from_str(&take(bastion_termthemes_duplicate(dir.as_ptr(), c("dracula").as_ptr(), &mut err))).unwrap();
        assert_eq!(theme["name"], "Dracula copy");
        assert_eq!(theme["bundled"], false);
        assert!(theme["id"].as_str().unwrap().starts_with("custom-"));
        assert_eq!(list(&dir).len(), 14);

        theme["name"] = "Mine".into();
        theme["ansi"][1] = "#ff0000".into();
        assert_eq!(put(&dir, &theme).unwrap()["warning"], Value::Null, "Dracula's contrast is fine");
        let saved = list(&dir).into_iter().find(|t| t["id"] == theme["id"]).unwrap();
        assert_eq!(saved["name"], "Mine");
        assert_eq!(saved["ansi"][1], "#ff0000");

        let mut faint = theme.clone();
        faint["foreground"] = "#2a2b37".into();
        let warning = put(&dir, &faint).unwrap()["warning"].as_str().unwrap().to_string();
        assert!(warning.contains("contrast"), "{warning}");

        for (k, bad) in [("foreground", "red"), ("background", "#12345"), ("background", "#gggggg")] {
            let mut b = theme.clone();
            b[k] = bad.into();
            assert!(put(&dir, &b).unwrap_err().contains("colour"), "{k}={bad}");
        }
        let mut short = theme.clone();
        short["ansi"].as_array_mut().unwrap().pop();
        assert!(put(&dir, &short).unwrap_err().contains("16"));
        let mut bundled = theme.clone();
        bundled["id"] = "nord".into();
        assert!(put(&dir, &bundled).is_err(), "bundled ids are read-only");
        let mut taken = theme.clone();
        taken["name"] = "Nord".into();
        assert!(put(&dir, &taken).unwrap_err().contains("already exists"));

        assert_eq!(bastion_termthemes_remove(dir.as_ptr(), c("nord").as_ptr(), &mut err), -1);
        assert!(take(err).contains("Bundled"));
        let mut err = null_mut();
        assert_eq!(bastion_termthemes_remove(dir.as_ptr(), c(theme["id"].as_str().unwrap()).as_ptr(), &mut err), 0);
        assert_eq!(list(&dir).len(), 13);
    }
}

#[test]
fn a_damaged_store_is_an_error_not_replaced() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("terminal-themes.json"), b"{not json").unwrap();
    let dir = c(d.path().to_str().unwrap());
    unsafe {
        let mut err = null_mut();
        assert!(bastion_termthemes_list_json(dir.as_ptr(), &mut err).is_null());
        assert!(take(err).contains("terminal-themes.json"));
    }
    assert_eq!(std::fs::read(d.path().join("terminal-themes.json")).unwrap(), b"{not json");
}

#[test]
fn a_user_theme_is_applied_to_a_terminal_and_a_deleted_one_falls_back() {
    let d = tempfile::tempdir().unwrap();
    let dir = c(d.path().to_str().unwrap());
    unsafe {
        let mut err = null_mut();
        let mut theme: Value = serde_json::from_str(&take(bastion_termthemes_duplicate(dir.as_ptr(), c("nord").as_ptr(), &mut err))).unwrap();
        theme["background"] = "#102030".into();
        put(&dir, &theme).unwrap();
        let (prog, args) = if cfg!(windows) { ("cmd.exe", r#"["/c","ping -n 6 127.0.0.1 >nul"]"#) } else { ("/bin/sh", r#"["-c","sleep 5"]"#) };
        let t = bastion_terminal_spawn(c(prog).as_ptr(), c(args).as_ptr(), 80, 24, &mut err);
        assert!(!t.is_null(), "spawn failed");
        let id = c(theme["id"].as_str().unwrap());
        assert_eq!(bastion_terminal_set_theme_in(t, dir.as_ptr(), id.as_ptr(), &mut err), 0);
        assert_eq!(bastion_terminal_background(t), 0x102030);
        assert_eq!(bastion_termthemes_remove(dir.as_ptr(), id.as_ptr(), &mut err), 0);
        assert_eq!(bastion_terminal_set_theme_in(t, dir.as_ptr(), id.as_ptr(), &mut err), 0);
        let deadline = Instant::now() + Duration::from_secs(1);
        while bastion_terminal_background(t) == 0x102030 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_ne!(bastion_terminal_background(t), 0x102030, "deleted theme falls back to Bastion Dark");
        assert_eq!(bastion_terminal_set_theme_in(std::ptr::null(), dir.as_ptr(), id.as_ptr(), &mut err), -1);
        bastion_string_free(err);
        bastion_terminal_free(t);
    }
}
