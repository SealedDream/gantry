//! Recent usernames per host over the C ABI (v30), for "Connect as…" / "Reconnect as…": the same
//! `core::recent_users` file the Mac app uses. Usernames only; no secret crosses this surface.
//! `port` <= 0 means "no port" (the host alone is the key).
use std::ffi::c_char;
use std::ptr::null_mut;

use crate::{guarded, optional, required, to_c};

fn port(p: i32) -> Result<Option<u16>, String> {
    if p <= 0 {
        return Ok(None);
    }
    u16::try_from(p).map(Some).map_err(|_| format!("port {p} is out of range"))
}

/// Suggestions for a host, newest first, as a JSON array of strings.
///
/// # Safety
/// `data_dir`, `host` valid NUL-terminated; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_recent_usernames_json(data_dir: *const c_char, host: *const c_char, port_: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let v = bastion_ffi::recent_usernames(required(data_dir, "data_dir")?, required(host, "host")?, port(port_)?).map_err(|e| e.to_string())?;
        Ok(to_c(serde_json::to_string(&v).map_err(|e| e.to_string())?))
    })
}

/// Remember `username` for a host (newest first). Returns 0, or -1 with `err` set.
///
/// # Safety
/// As [`bastion_recent_usernames_json`]; `username` valid NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn bastion_recent_username_record(data_dir: *const c_char, host: *const c_char, port_: i32, username: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        bastion_ffi::record_recent_username(required(data_dir, "data_dir")?, required(host, "host")?, port(port_)?, required(username, "username")?).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Forget one suggestion, or all of them for the host when `username` is NULL. Returns 0 or -1.
///
/// # Safety
/// As [`bastion_recent_usernames_json`]; `username` NULL or valid NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn bastion_recent_username_forget(data_dir: *const c_char, host: *const c_char, port_: i32, username: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        bastion_ffi::forget_recent_username(required(data_dir, "data_dir")?, required(host, "host")?, port(port_)?, optional(username, "username")?).map_err(|e| e.to_string())?;
        Ok(0)
    })
}
