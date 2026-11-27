//! Wake-on-LAN over the C ABI (ABI 71). Settings are properties set with
//! `bastion_library_set_property` (`wol_mac`, `wol_broadcast`, `wol_port`, `wol_secureon`,
//! `wol_before_connect`, `wol_wait_secs`). Nothing is sent unless one of these calls is made.
use std::ffi::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::{WakeCancel, WakeResult};
use serde_json::{json, Value};

use crate::{guarded, required, to_c, BastionLibrary};

/// `bastion_library_wake_before_connect` results (negative is an error, see `err`).
pub const WAKE_NOT_NEEDED: i32 = 0;
pub const WAKE_UP: i32 = 1;
pub const WAKE_TIMED_OUT: i32 = 2;
pub const WAKE_CANCELLED: i32 = 3;

/// Opaque cancel token for a running wait.
pub struct BastionWakeCancel(Arc<WakeCancel>);

unsafe fn library<'a>(lib: *const BastionLibrary) -> Result<&'a bastion_ffi::Library, String> {
    lib.as_ref().map(|l| &*l.0).ok_or_else(|| "library handle is NULL".to_string())
}

/// The connection's wake plan as JSON `{mac,broadcast,port,has_secureon,before_connect,wait_secs,host,check_port}`,
/// or `null` when no MAC is set (hide or disable Wake). The SecureOn password is never returned.
///
/// # Safety
/// `lib` live; `id` valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_wol_plan_json(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let p = library(lib)?.wol_plan(required(id, "id")?).map_err(|e| e.to_string())?;
        let v = p.map_or(Value::Null, |p| {
            json!({ "mac": p.mac, "broadcast": p.broadcast, "port": p.port, "has_secureon": p.has_secureon,
                    "before_connect": p.before_connect, "wait_secs": p.wait_secs, "host": p.host, "check_port": p.check_port })
        });
        Ok(to_c(v.to_string()))
    })
}

/// Wake action: send the magic packet now. 0, or -1 with `err` (no MAC, bad setting, send failed).
///
/// # Safety
/// `lib` live; `id` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_wake(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        library(lib)?.wake(required(id, "id")?).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// A new cancel token. Free with `bastion_wake_cancel_free`.
#[no_mangle]
pub extern "C" fn bastion_wake_cancel_new() -> *mut BastionWakeCancel {
    Box::into_raw(Box::new(BastionWakeCancel(WakeCancel::new())))
}

/// Ask a running `bastion_library_wake_before_connect` to stop (any thread).
///
/// # Safety
/// `c` NULL or from `bastion_wake_cancel_new` and not freed.
#[no_mangle]
pub unsafe extern "C" fn bastion_wake_cancel(c: *const BastionWakeCancel) {
    if let Some(c) = c.as_ref() {
        c.0.cancel();
    }
}

/// # Safety
/// `c` NULL or from `bastion_wake_cancel_new`, not used by a running wait, freed once.
#[no_mangle]
pub unsafe extern "C" fn bastion_wake_cancel_free(c: *mut BastionWakeCancel) {
    if !c.is_null() {
        drop(Box::from_raw(c));
    }
}

/// Before a connect: when "Wake before connect" is on, wake the host and wait (≤ 300 s) for it.
/// Blocking: call off the UI thread. Returns `WAKE_NOT_NEEDED`, `WAKE_UP` (`after_ms` set when
/// not NULL), `WAKE_TIMED_OUT` or `WAKE_CANCELLED`; -1 with `err` on failure. `cancel` may be NULL.
///
/// # Safety
/// `lib` live; `id` valid NUL-terminated; `cancel` NULL or live; `after_ms` NULL or writable;
/// `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_wake_before_connect(
    lib: *const BastionLibrary,
    id: *const c_char,
    cancel: *const BastionWakeCancel,
    after_ms: *mut u64,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, -1, || {
        let token = cancel.as_ref().map_or_else(WakeCancel::new, |c| c.0.clone());
        let r = library(lib)?.wake_before_connect(required(id, "id")?, token).map_err(|e| e.to_string())?;
        Ok(match r {
            WakeResult::NotNeeded => WAKE_NOT_NEEDED,
            WakeResult::Up { after_ms: ms } => {
                if let Some(out) = after_ms.as_mut() {
                    *out = ms;
                }
                WAKE_UP
            }
            WakeResult::TimedOut => WAKE_TIMED_OUT,
            WakeResult::Cancelled => WAKE_CANCELLED,
        })
    })
}

/// Whether the connection is sensitive (production, customer-sensitive or privileged
/// infrastructure), for the broadcast / multi-exec confirmation (ABI 77). 1 or 0, or -1 with `err`
/// (unknown id).
///
/// # Safety
/// `lib` live; `id` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_connection_sensitive(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || Ok(library(lib)?.connection_sensitive(required(id, "id")?.to_string()).map_err(|e| e.to_string())? as i32))
}
