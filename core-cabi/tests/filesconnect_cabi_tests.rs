//! Files-only connections over the C ABI (ABI 87): SFTP/SCP dialled over SSH and FTPS sign-in
//! open the same browser handle the terminal Files panel uses. Error paths always run; the real
//! server path needs the test sshd (`BASTION_SSH_TEST=1`, 127.0.0.1:2223, tester / test-pass-123).
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

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

unsafe fn setup(d: &tempfile::TempDir) -> (*mut BastionLibrary, *mut BastionSessionManager) {
    let mut err = null_mut();
    let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
    let mgr = bastion_session_manager_new(c(d.path().to_str().unwrap()).as_ptr(), &mut err);
    assert!(!lib.is_null() && !mgr.is_null());
    (lib, mgr)
}

unsafe fn add(lib: *mut BastionLibrary, name: &str, protocol: &str, port: i32) -> String {
    let mut err = null_mut();
    take(bastion_library_add_connection(lib, null(), c(name).as_ptr(), c(protocol).as_ptr(), c("127.0.0.1").as_ptr(), port, c("tester").as_ptr(), &mut err)).unwrap()
}

unsafe fn files(mgr: *mut BastionSessionManager, lib: *mut BastionLibrary, id: &str, trust: Option<&str>) -> (*mut BastionSftp, i32, Option<String>, Option<String>) {
    let (mut outcome, mut fp, mut hop, mut err) = (-42, null_mut(), null_mut(), null_mut());
    let t = trust.map(c);
    let s = bastion_session_connect_files(
        mgr, lib, c(id).as_ptr(), c("tester").as_ptr(), LOGIN_PASSWORD, c("test-pass-123").as_ptr(), null(), null(), t.as_ref().map_or(null(), |s| s.as_ptr()), null(), null(),
        &mut outcome, &mut fp, &mut hop, &mut err,
    );
    take(hop);
    (s, outcome, take(fp), take(err))
}

#[test]
fn ftps_refuses_a_connection_that_is_not_ftps_and_reports_failure() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let (lib, mgr) = setup(&d);
        let id = add(lib, "box", "ssh", 2223);
        let (mut outcome, mut fp, mut err) = (-42, null_mut(), null_mut());
        let s = bastion_session_connect_ftps(mgr, lib, c(&id).as_ptr(), null(), c("pw").as_ptr(), null(), &mut outcome, &mut fp, &mut err);
        assert!(s.is_null());
        assert_eq!(outcome, CONNECT_FAILED);
        assert!(take(fp).is_none());
        assert!(take(err).unwrap().contains("is not an FTPS connection"));
        bastion_session_manager_free(mgr);
        bastion_library_free(lib);
    }
}

#[test]
fn files_connection_to_an_unknown_id_fails_without_a_handle() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let (lib, mgr) = setup(&d);
        let (s, outcome, fp, err) = files(mgr, lib, "00000000-0000-0000-0000-000000000000", None);
        assert!(s.is_null() && outcome == CONNECT_FAILED && fp.is_none());
        assert!(err.is_some());
        bastion_session_manager_free(mgr);
        bastion_library_free(lib);
    }
}

#[test]
fn sftp_and_scp_connections_open_a_browser_after_the_host_key_is_trusted() {
    if std::env::var("BASTION_SSH_TEST").is_err() {
        eprintln!("SKIPPED sftp_and_scp_connections_open_a_browser_after_the_host_key_is_trusted: set BASTION_SSH_TEST=1");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let (lib, mgr) = setup(&d);
        for protocol in ["sftp", "scp"] {
            let id = add(lib, protocol, protocol, 2223);
            let (s, outcome, fp, first_err) = files(mgr, lib, &id, None);
            // The first dial of each connection may already find the key trusted by the previous one.
            let s = if outcome == CONNECT_HOST_KEY_UNKNOWN {
                assert!(s.is_null());
                let (s, outcome, _, err) = files(mgr, lib, &id, fp.as_deref());
                assert_eq!(outcome, CONNECT_OK, "{protocol}: {err:?}");
                s
            } else {
                assert_eq!(outcome, CONNECT_OK, "{protocol}: {first_err:?}");
                s
            };
            assert!(!s.is_null());
            let mut err = null_mut();
            let home = take(bastion_sftp_home(s, &mut err)).unwrap();
            let list: Value = serde_json::from_str(&take(bastion_sftp_list_json(s, c(&home).as_ptr(), &mut err)).unwrap()).unwrap();
            assert!(list.is_array(), "{protocol}: {list}");
            bastion_sftp_free(s);
        }
        bastion_session_manager_free(mgr);
        bastion_library_free(lib);
    }
}
