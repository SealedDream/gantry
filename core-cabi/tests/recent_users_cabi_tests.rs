//! Recent usernames over the C ABI, driven the way a P/Invoke host does.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;

use bastion_cabi::*;

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

#[test]
fn record_list_forget() {
    let d = tempfile::tempdir().unwrap();
    let dir = c(d.path().to_str().unwrap());
    unsafe {
        let mut err = null_mut();
        assert_eq!(bastion_recent_username_record(dir.as_ptr(), c("srv").as_ptr(), 22, c("alice").as_ptr(), &mut err), 0);
        assert_eq!(bastion_recent_username_record(dir.as_ptr(), c("srv").as_ptr(), 22, c("root").as_ptr(), &mut err), 0);
        let list = take(bastion_recent_usernames_json(dir.as_ptr(), c("SRV").as_ptr(), 22, &mut err)).unwrap();
        assert_eq!(list, r#"["root","alice"]"#);
        assert_eq!(take(bastion_recent_usernames_json(dir.as_ptr(), c("srv").as_ptr(), 0, &mut err)).unwrap(), "[]");
        assert_eq!(bastion_recent_username_record(dir.as_ptr(), c("srv").as_ptr(), 22, c("bad user").as_ptr(), &mut err), -1);
        assert!(take(err).unwrap().contains("username"));
        let mut err = null_mut();
        assert_eq!(bastion_recent_username_record(dir.as_ptr(), c("srv").as_ptr(), 70000, c("x").as_ptr(), &mut err), -1);
        take(err);
        let mut err = null_mut();
        assert_eq!(bastion_recent_username_forget(dir.as_ptr(), c("srv").as_ptr(), 22, null_mut(), &mut err), 0);
        assert_eq!(take(bastion_recent_usernames_json(dir.as_ptr(), c("srv").as_ptr(), 22, &mut err)).unwrap(), "[]");
    }
}
