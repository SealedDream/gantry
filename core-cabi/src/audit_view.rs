//! The Audit Log page over the C ABI (ABI 123):
//! the two calls of `bastion_ffi::audit_view`, with the same JSON. Read-only: nothing here
//! writes to or deletes from the audit log.
use std::ffi::c_char;
use std::ptr::null_mut;

use crate::{coded, guarded, required, to_c};

/// One page of audit records, newest first (`limit` capped at 500), as
/// `{"total":n,"records":[…]}`. Free with `bastion_string_free`; NULL on error.
///
/// # Safety
/// `data_dir` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_audit_read_json(data_dir: *const c_char, offset: u32, limit: u32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = bastion_ffi::audit_read_json(required(data_dir, "data_dir")?.to_string(), offset, limit).map_err(coded)?;
        Ok(to_c(out))
    })
}

/// The hash chain: `{"intact":bool,"records":n,"changedAt":n|null}`. Free with
/// `bastion_string_free`; NULL on error.
///
/// # Safety
/// `data_dir` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_audit_verify_json(data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = bastion_ffi::audit_verify_json(required(data_dir, "data_dir")?.to_string()).map_err(coded)?;
        Ok(to_c(out))
    })
}
