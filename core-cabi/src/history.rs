//! Connection history for the inspector footer over the C ABI: "Last connected: <time> as
//! <user>" and "Last result: OK / <short error>". Owner-only file in the data directory, no secrets.
use std::ffi::c_char;
use std::ptr::null_mut;

use serde_json::json;

use crate::{guarded, optional, required, set_ok, to_c};

/// JSON `{lastConnectedAt, lastUser, lastResult}`: Unix seconds (format locally) or null; the
/// user or null; "OK", a short error, or null before the first attempt.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_connection_history_json(data_dir: *const c_char, connection_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let h = bastion_ffi::connection_history(required(data_dir, "data_dir")?, required(connection_id, "connection_id")?).map_err(|e| e.to_string())?;
        Ok(to_c(json!({ "lastConnectedAt": h.last_connected_at, "lastUser": h.last_user, "lastResult": h.last_result }).to_string()))
    })
}

/// Record a successful connect now (`user` NULL when the protocol has none). Returns 0 or -1.
///
/// # Safety
/// Strings valid NUL-terminated (`user` may be NULL); `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_connection_history_success(data_dir: *const c_char, connection_id: *const c_char, user: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        bastion_ffi::record_connection_success(required(data_dir, "data_dir")?, required(connection_id, "connection_id")?, optional(user, "user")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Record a failed attempt now; `error` is cut to one short secret-free line. Returns 0 or -1.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_connection_history_failure(data_dir: *const c_char, connection_id: *const c_char, error: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        bastion_ffi::record_connection_failure(required(data_dir, "data_dir")?, required(connection_id, "connection_id")?, required(error, "error")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Forget a connection's history (call when it is deleted). Returns 0 or -1.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_connection_history_forget(data_dir: *const c_char, connection_id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        bastion_ffi::forget_connection_history(required(data_dir, "data_dir")?, required(connection_id, "connection_id")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}
