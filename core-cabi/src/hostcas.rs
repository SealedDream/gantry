//! SSH host certificate authorities over the C ABI (ABI v20): the `@cert-authority` lines of the
//! session manager's known_hosts. Public keys only; nothing here carries a secret.
//!
//! Adding a CA is an explicit trust decision the host makes after the user checks the key; the
//! core validates the patterns and key and refuses duplicates.
use std::ffi::c_char;

use bastion_ffi::HostCaView;
use serde_json::{json, Value};

use crate::session::{manager, BastionSessionManager};
use crate::{guarded, required, set_ok, to_c};

fn view(v: &HostCaView) -> Value {
    json!({ "patterns": v.patterns, "fingerprint": v.fingerprint, "algorithm": v.algorithm, "comment": v.comment })
}

/// JSON array of `{patterns, fingerprint, algorithm, comment}`. Free with `bastion_string_free`.
///
/// # Safety
/// `m` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_host_cas_json(m: *const BastionSessionManager, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let list: Vec<Value> = manager(m)?.host_cas().iter().map(view).collect();
        Ok(to_c(Value::Array(list).to_string()))
    })
}

/// Trust `public_key` (one OpenSSH public key line) to sign host certificates for `patterns`.
/// Returns the new entry as JSON, or NULL and sets `*err`.
///
/// # Safety
/// `m` live; strings valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_host_ca_add(m: *const BastionSessionManager, patterns: *const c_char, public_key: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let v = manager(m)?.add_host_ca(required(patterns, "patterns")?, required(public_key, "public_key")?).map_err(|e| e.to_string())?;
        Ok(to_c(view(&v).to_string()))
    })
}

/// Remove the CA line with these `patterns` and `fingerprint`. 0 / -1.
///
/// # Safety
/// `m` live; strings valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_host_ca_remove(m: *const BastionSessionManager, patterns: *const c_char, fingerprint: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        manager(m)?.remove_host_ca(required(patterns, "patterns")?, required(fingerprint, "fingerprint")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};
    use std::ptr::null_mut;

    use super::*;
    use crate::session::{bastion_session_manager_free, bastion_session_manager_new};

    unsafe fn take(p: *mut c_char) -> String {
        assert!(!p.is_null());
        let s = CStr::from_ptr(p).to_string_lossy().into_owned();
        crate::bastion_string_free(p);
        s
    }

    #[test]
    fn add_list_remove_and_reject_bad_input() {
        let dir = std::env::temp_dir().join(format!("bastion-cabi-ca-{}", uuid::Uuid::new_v4()));
        let d = CString::new(dir.to_string_lossy().as_ref()).unwrap();
        let ca = CString::new(include_str!("../../core/tests/fixtures/hostcert/ca.pub")).unwrap();
        let pat = CString::new("*.lab").unwrap();
        unsafe {
            let m = bastion_session_manager_new(d.as_ptr(), null_mut());
            assert_eq!(take(bastion_host_cas_json(m, null_mut())), "[]");
            let added: Value = serde_json::from_str(&take(bastion_host_ca_add(m, pat.as_ptr(), ca.as_ptr(), null_mut()))).unwrap();
            let fp = added["fingerprint"].as_str().unwrap().to_string();
            assert!(fp.starts_with("SHA256:"));
            let mut err = null_mut();
            assert!(bastion_host_ca_add(m, pat.as_ptr(), ca.as_ptr(), &mut err).is_null(), "duplicate refused");
            assert!(!take(err).is_empty());
            let spaced = CString::new("a b").unwrap();
            let mut err = null_mut();
            assert!(bastion_host_ca_add(m, spaced.as_ptr(), ca.as_ptr(), &mut err).is_null());
            take(err);
            let bad = CString::new("not a key").unwrap();
            let mut err = null_mut();
            assert!(bastion_host_ca_add(m, pat.as_ptr(), bad.as_ptr(), &mut err).is_null());
            take(err);
            let list: Value = serde_json::from_str(&take(bastion_host_cas_json(m, null_mut()))).unwrap();
            assert_eq!(list.as_array().unwrap().len(), 1);
            let fpc = CString::new(fp).unwrap();
            assert_eq!(bastion_host_ca_remove(m, pat.as_ptr(), fpc.as_ptr(), null_mut()), 0);
            assert_eq!(take(bastion_host_cas_json(m, null_mut())), "[]");
            bastion_session_manager_free(m);
        }
        std::fs::remove_dir_all(dir).ok();
    }
}
