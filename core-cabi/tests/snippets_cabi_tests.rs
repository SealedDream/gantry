//! Command snippets through the C ABI: store round trip and refusals, then sends to real local
//! shells, where multi-line or multi-tab sends need `confirmed` and land in the audit log.
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

unsafe fn put(dir: &CString, name: &str, text: &str, id: Option<&str>) -> Result<String, String> {
    let mut err = null_mut();
    let id = id.map(c);
    let r = bastion_snippet_put(dir.as_ptr(), c(name).as_ptr(), c(text).as_ptr(), id.as_ref().map_or(null(), |i| i.as_ptr()), &mut err);
    if r.is_null() {
        Err(take(err))
    } else {
        Ok(take(r))
    }
}

unsafe fn list(dir: &CString, q: &str) -> Vec<Value> {
    let mut err = null_mut();
    serde_json::from_str::<Vec<Value>>(&take(bastion_snippets_json(dir.as_ptr(), c(q).as_ptr(), &mut err))).unwrap()
}

#[test]
fn store_round_trip_and_refusals() {
    let d = tempfile::tempdir().unwrap();
    let dir = c(d.path().to_str().unwrap());
    unsafe {
        assert!(list(&dir, "").is_empty());
        let a = put(&dir, "restart nginx", "sudo systemctl restart nginx", None).unwrap();
        put(&dir, "disk", "df -h\ndu -sh *", None).unwrap();
        assert!(put(&dir, "Disk", "df", None).unwrap_err().contains("already exists"));
        assert!(put(&dir, "login", "sshpass -p hunter2 ssh x", None).unwrap_err().contains("secret"));
        assert!(put(&dir, "", "x", None).is_err());
        let all = list(&dir, "");
        assert_eq!(all.iter().map(|s| s["name"].as_str().unwrap()).collect::<Vec<_>>(), vec!["disk", "restart nginx"]);
        assert_eq!((all[0]["multiline"].as_bool(), all[0]["lines"].as_u64()), (Some(true), Some(2)));
        assert_eq!(list(&dir, "NGINX").len(), 1);
        assert_eq!(put(&dir, "restart nginx", "sudo systemctl reload nginx", Some(&a)).unwrap(), a);
        assert_eq!(list(&dir, "reload")[0]["id"], a.as_str());
        let mut err = null_mut();
        assert_eq!(bastion_snippet_remove(dir.as_ptr(), c(&a).as_ptr(), &mut err), 0);
        assert_eq!(bastion_snippet_remove(dir.as_ptr(), c(&a).as_ptr(), &mut err), -1);
        bastion_string_free(err);
        assert_eq!(list(&dir, "").len(), 1);
    }
}

#[test]
fn sends_need_confirmation_when_risky() {
    let d = tempfile::tempdir().unwrap();
    let dir = c(d.path().to_str().unwrap());
    unsafe {
        let one = put(&dir, "hello", "echo hi", None).unwrap();
        let multi = put(&dir, "two", "echo a\necho b", None).unwrap();
        let mut err = null_mut();
        let t1 = bastion_terminal_local_shell(80, 24, &mut err);
        let t2 = bastion_terminal_local_shell(80, 24, &mut err);
        assert!(!t1.is_null() && !t2.is_null());
        let both = [t1 as *const BastionTerminal, t2 as *const BastionTerminal];
        let send = |id: &str, n: usize, confirmed: i32| {
            let mut err = null_mut();
            let r = bastion_snippet_send(dir.as_ptr(), c(id).as_ptr(), both.as_ptr(), n, confirmed, null(), &mut err);
            if !err.is_null() {
                bastion_string_free(err);
            }
            r
        };
        assert_eq!(send(&one, 1, 0), 1, "one line to one tab needs no confirmation");
        assert_eq!(send(&multi, 1, 0), SNIPPET_NEEDS_CONFIRM);
        assert_eq!(send(&one, 2, 0), SNIPPET_NEEDS_CONFIRM);
        assert_eq!(send(&one, 2, 1), 2);
        assert_eq!(send("missing", 1, 1), -1);
        assert_eq!(send(&one, 0, 1), -1);
        assert_eq!(send(&one, SNIPPET_MAX_TARGETS + 1, 1), -1);
        bastion_terminal_free(t1);
        bastion_terminal_free(t2);
    }
}
