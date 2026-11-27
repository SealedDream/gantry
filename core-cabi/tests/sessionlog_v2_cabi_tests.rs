//! Session log v2 (LOG-CORE-02) through the C ABI: plan, planned start on a real shell, state,
//! finish with hash, and retention.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};
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

#[test]
fn planned_log_lands_under_its_folder_with_header_footer_and_hash() {
    let d = tempfile::tempdir().unwrap();
    let data = d.path().to_str().unwrap().to_string();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let id = take(bastion_library_add_connection(lib, null(), c("web 01").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), 22, null(), &mut null_mut()));

        let plan: Value = serde_json::from_str(&take(bastion_session_log_plan_json(lib, c(&id).as_ptr(), c(&data).as_ptr(), c("Bastion test").as_ptr(), c("1.0").as_ptr(), 0, &mut err))).unwrap();
        let root = d.path().join("session-logs");
        assert_eq!(plan["root"], root.to_str().unwrap());
        assert!(plan["path"].as_str().unwrap().starts_with(root.join("web-01").to_str().unwrap()), "{plan}");
        assert!(plan["header"].as_str().unwrap().starts_with("# Gantry session log\n# name: web 01\n"));

        let t = bastion_terminal_local_shell(80, 24, &mut err);
        assert!(!t.is_null());
        let state: Value = serde_json::from_str(&take(bastion_terminal_log_state_json(t, &mut err))).unwrap();
        assert_eq!(state["state"], "off");
        assert!(bastion_terminal_finish_log(t, null(), &mut err).is_null() && err.is_null(), "nothing to finish");
        let path = take(bastion_terminal_start_planned_log(t, lib, c(&id).as_ptr(), c(&data).as_ptr(), c("Bastion test").as_ptr(), c("1.0").as_ptr(), 60, &mut err));
        let state: Value = serde_json::from_str(&take(bastion_terminal_log_state_json(t, &mut err))).unwrap();
        assert_eq!(state["state"], "active");
        assert_eq!(state["path"], path.as_str());
        let cmd = if cfg!(windows) { "echo logged-%COMPUTERNAME:~0,0%ok\r" } else { "echo logged-$((40+2))\r" };
        let bytes = cmd.as_bytes();
        assert_eq!(bastion_terminal_write(t, bytes.as_ptr(), bytes.len(), &mut err), 0);
        let expect = if cfg!(windows) { "logged-ok" } else { "logged-42" };
        let start = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(100));
            if std::fs::read_to_string(&path).is_ok_and(|t| t.contains(expect)) || start.elapsed() > Duration::from_secs(10) {
                break;
            }
        }
        let hash = take(bastion_terminal_finish_log(t, c("user closed the tab").as_ptr(), &mut err));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(expect), "{text}");
        assert!(text.ends_with("# end reason: user closed the tab\n"), "{text}");
        assert_eq!(hash.len(), 64);
        let state: Value = serde_json::from_str(&take(bastion_terminal_log_state_json(t, &mut err))).unwrap();
        assert_eq!(state["state"], "off");

        let r: Value = serde_json::from_str(&take(bastion_purge_session_logs_json(lib, null(), c(&data).as_ptr(), &mut err))).unwrap();
        assert_eq!(r["deleted_files"], 0, "defaults keep everything");
        assert!(std::path::Path::new(&path).exists());

        bastion_terminal_close(t);
        bastion_terminal_free(t);
        bastion_library_free(lib);
    }
}
