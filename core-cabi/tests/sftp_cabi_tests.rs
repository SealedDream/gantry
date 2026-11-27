//! SFTP through the C ABI without a server: NULL handles and local terminals are refused cleanly.
//! The real-server round trip lives in `session_cabi_tests.rs` (BASTION_SSH_TEST=1).
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;

unsafe fn take_err(err: *mut c_char) -> String {
    assert!(!err.is_null(), "an error message");
    let s = CStr::from_ptr(err).to_string_lossy().into_owned();
    bastion_string_free(err);
    s
}

#[test]
fn null_handles_are_errors_not_crashes() {
    unsafe {
        let mut err: *mut c_char = null_mut();
        assert!(bastion_terminal_open_sftp(null(), &mut err).is_null());
        assert!(take_err(err).contains("NULL"));
        let p = CString::new("/").unwrap();
        assert!(bastion_sftp_home(null(), &mut err).is_null());
        take_err(err);
        assert!(bastion_sftp_list_json(null(), p.as_ptr(), &mut err).is_null());
        take_err(err);
        assert_eq!(bastion_sftp_download(null(), p.as_ptr(), p.as_ptr(), 0, &mut err), -1);
        take_err(err);
        assert_eq!(bastion_sftp_upload(null(), p.as_ptr(), p.as_ptr(), 0, &mut err), -1);
        take_err(err);
        assert_eq!(bastion_sftp_mkdir(null(), p.as_ptr(), &mut err), -1);
        take_err(err);
        assert_eq!(bastion_sftp_rename(null(), p.as_ptr(), p.as_ptr(), &mut err), -1);
        take_err(err);
        assert_eq!(bastion_sftp_remove(null(), p.as_ptr(), 1, &mut err), -1);
        take_err(err);
        assert!(bastion_sftp_edit_open(null(), p.as_ptr(), &mut err).is_null());
        take_err(err);
        assert!(bastion_sftp_edit_save(null(), p.as_ptr(), p.as_ptr(), null(), 0, &mut err).is_null());
        take_err(err);
        bastion_sftp_free(null_mut());
    }
}

#[test]
fn a_local_terminal_has_no_sftp() {
    unsafe {
        let mut err: *mut c_char = null_mut();
        let t = bastion_terminal_local_shell(80, 24, &mut err);
        assert!(!t.is_null());
        assert!(bastion_terminal_open_sftp(t, &mut err).is_null());
        assert!(take_err(err).contains("SSH"));
        assert_eq!(bastion_terminal_is_alive(t), 1);
        bastion_terminal_free(t);
    }
}
