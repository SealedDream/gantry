//! Log snippet export through the C boundary, as a P/Invoke caller drives it.
use std::ffi::{CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;

unsafe fn take(p: *mut std::ffi::c_char) -> String {
    assert!(!p.is_null());
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    bastion_string_free(p);
    s
}

#[test]
fn clean_strips_escapes_only_when_asked() {
    unsafe {
        let raw = CString::new("\x1b[31mred\x1b[0m  \r\n").unwrap();
        let mut err = null_mut();
        assert_eq!(take(bastion_log_snippet_clean(raw.as_ptr(), 1, &mut err)), "red");
        assert_eq!(take(bastion_log_snippet_clean(raw.as_ptr(), 0, &mut err)), "\x1b[31mred\x1b[0m");
        assert!(bastion_log_snippet_clean(null(), 1, &mut err).is_null());
        assert!(take(err).contains("text"));
    }
}

#[test]
fn export_writes_header_and_text_and_reports_errors() {
    unsafe {
        let dir = tempfile::tempdir().unwrap();
        let cdir = CString::new(dir.path().to_str().unwrap()).unwrap();
        let name = CString::new("db-1").unwrap();
        let header = CString::new("db-1 at 2026-11-04 10:00").unwrap();
        let text = CString::new("\x1b[1mERROR\x1b[0m disk full\n").unwrap();
        let mut err = null_mut();
        let path = take(bastion_log_snippet_export(cdir.as_ptr(), name.as_ptr(), header.as_ptr(), text.as_ptr(), 1, &mut err));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "db-1 at 2026-11-04 10:00\nERROR disk full\n");
        let second = take(bastion_log_snippet_export(cdir.as_ptr(), name.as_ptr(), null(), text.as_ptr(), 1, &mut err));
        assert!(second.ends_with("db-1-2.log"), "{second}");
        let empty = CString::new("  \n").unwrap();
        assert!(bastion_log_snippet_export(cdir.as_ptr(), name.as_ptr(), null(), empty.as_ptr(), 1, &mut err).is_null());
        assert!(take(err).contains("empty"));
    }
}
