//! Saved tasks over the C ABI (ABI 92), as the Windows Tasks section uses them.
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

unsafe fn json(p: *mut c_char) -> Value {
    serde_json::from_str(&take(p).expect("a JSON string")).unwrap()
}

#[test]
fn tasks_list_save_favorite_hook_and_remove() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let builtins = json(bastion_tasks_json(lib, &mut err));
        let n = builtins.as_array().unwrap().len();
        assert!(n >= 4 && builtins.as_array().unwrap().iter().all(|t| t["builtin"] == true));

        let id = take(bastion_tasks_save_json(lib, c(r#"{"name":"Uptime","program":"uptime","args":["-p"],"runOn":"ssh","timeoutSecs":20}"#).as_ptr(), &mut err)).unwrap();
        let all = json(bastion_tasks_json(lib, &mut err));
        let mine = all.as_array().unwrap().iter().find(|t| t["id"] == id.as_str()).unwrap();
        assert_eq!((mine["runOn"].as_str(), mine["timeoutSecs"].as_u64(), mine["builtin"].as_bool()), (Some("ssh"), Some(20), Some(false)));

        assert_eq!(bastion_tasks_set_favorite(lib, c(&id).as_ptr(), 1, &mut err), 0);
        let ping = builtins[0]["id"].as_str().unwrap().to_string();
        assert_eq!(bastion_tasks_set_favorite(lib, c(&ping).as_ptr(), 1, &mut err), 0);
        let all = json(bastion_tasks_json(lib, &mut err));
        assert!(all.as_array().unwrap().iter().filter(|t| t["favorite"] == true).count() == 2);

        // A built-in task cannot be saved over; an empty name is refused.
        assert!(bastion_tasks_save_json(lib, c(r#"{"name":"","program":"x"}"#).as_ptr(), &mut err).is_null());
        assert!(take(err).is_some());
        err = null_mut();

        let conn = take(bastion_library_add_connection(lib, null(), c("web").as_ptr(), c("ssh").as_ptr(), c("10.0.0.5").as_ptr(), 22, c("tester").as_ptr(), &mut err)).unwrap();
        let hooks = format!(r#"[{{"taskId":"{id}","when":"after_connect"}}]"#);
        assert_eq!(bastion_task_set_hooks_json(lib, c(&conn).as_ptr(), c(&hooks).as_ptr(), &mut err), 0);
        assert_eq!(json(bastion_task_hooks_json(lib, c(&conn).as_ptr(), &mut err))[0]["when"], "after_connect");

        let review = json(bastion_task_review_json(lib, c(&id).as_ptr(), c(&conn).as_ptr(), &mut err));
        assert!(review["display"].as_str().unwrap().contains("uptime"));

        assert_eq!(bastion_tasks_remove(lib, c(&id).as_ptr(), &mut err), 0);
        assert_eq!(json(bastion_tasks_json(lib, &mut err)).as_array().unwrap().len(), n);
        assert!(json(bastion_task_hooks_json(lib, c(&conn).as_ptr(), &mut err)).as_array().unwrap().is_empty());
        bastion_library_free(lib);
    }
}

#[test]
fn a_tcp_check_task_runs_and_reports_output() {
    let d = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let mgr = bastion_session_manager_new(c(d.path().to_str().unwrap()).as_ptr(), &mut err);
        let conn = take(bastion_library_add_connection(lib, null(), c("local").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), i32::from(port), c("tester").as_ptr(), &mut err)).unwrap();
        let tasks = json(bastion_tasks_json(lib, &mut err));
        let tcp = tasks.as_array().unwrap().iter().find(|t| t["kind"] == "tcp_check").unwrap()["id"].as_str().unwrap().to_string();
        let run = bastion_task_run_start(mgr, lib, c(&tcp).as_ptr(), c(&conn).as_ptr(), null(), 0, null(), null(), 0, &mut err);
        assert!(!run.is_null(), "{:?}", take(err));
        let t0 = Instant::now();
        let out = loop {
            let o = json(bastion_task_run_output_json(run, &mut err));
            if o["finished"] == true || t0.elapsed() > Duration::from_secs(10) {
                break o;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(out["state"], "done", "{out}");
        assert_eq!(out["exit"], 0);
        assert_eq!(bastion_task_run_cancel(run, &mut err), 0);
        bastion_task_run_free(run);
        assert!(bastion_task_run_output_json(null(), &mut err).is_null());
        take(err);
        bastion_session_manager_free(mgr);
        bastion_library_free(lib);
    }
}

/// B5: resolved hooks come with the trust rule; a local custom task runs as a hook only after `bastion_task_trust`.
#[test]
fn resolved_hooks_follow_the_trust_rule() {
    let d = tempfile::tempdir().unwrap();
    let data = c(d.path().to_str().unwrap());
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let id = take(bastion_tasks_save_json(lib, c(r#"{"name":"Notify","program":"notify","runOn":"local"}"#).as_ptr(), &mut err)).unwrap();
        let conn = take(bastion_library_add_connection(lib, null(), c("web").as_ptr(), c("ssh").as_ptr(), c("10.0.0.5").as_ptr(), 22, c("tester").as_ptr(), &mut err)).unwrap();
        let hooks = format!(r#"[{{"taskId":"{id}","when":"after_disconnect"}}]"#);
        assert_eq!(bastion_task_set_hooks_json(lib, c(&conn).as_ptr(), c(&hooks).as_ptr(), &mut err), 0);

        let rows = json(bastion_task_resolved_hooks_json(lib, c(&conn).as_ptr(), c("after_disconnect").as_ptr(), data.as_ptr(), &mut err));
        let row = &rows.as_array().unwrap()[0];
        assert_eq!((row["hook"]["taskId"].as_str(), row["ownerId"].as_str()), (Some(id.as_str()), Some(conn.as_str())));
        assert_eq!((row["runnable"].as_bool(), row["untrusted"].as_bool()), (Some(false), Some(true)), "not saved by the user here yet");
        let other = json(bastion_task_resolved_hooks_json(lib, c(&conn).as_ptr(), c("after_connect").as_ptr(), data.as_ptr(), &mut err));
        assert!(other.as_array().unwrap().is_empty());

        assert_eq!(bastion_task_trust(lib, c(&id).as_ptr(), data.as_ptr(), &mut err), 0);
        let rows = json(bastion_task_resolved_hooks_json(lib, c(&conn).as_ptr(), c("after_disconnect").as_ptr(), data.as_ptr(), &mut err));
        assert_eq!((rows[0]["runnable"].as_bool(), rows[0]["untrusted"].as_bool()), (Some(true), Some(false)));

        assert!(bastion_task_resolved_hooks_json(lib, c(&conn).as_ptr(), c("sometime").as_ptr(), data.as_ptr(), &mut err).is_null());
        assert!(take(err).is_some());
        err = null_mut();
        assert_eq!(bastion_task_trust(lib, c("not-a-task").as_ptr(), data.as_ptr(), &mut err), -1);
        assert!(take(err).is_some());
        bastion_library_free(lib);
    }
}
