//! Session restore after a crash and the start page's recent sessions over the C ABI (ABI 80).
//! The open-session set is saved on every tab change; at launch `bastion_open_sessions_begin_json`
//! says whether the last run crashed or quit cleanly and which tabs to reopen. No secrets.
use std::ffi::c_char;
use std::ptr::null_mut;

use crate::{guarded, library, required, set_ok, to_c, BastionLibrary};

/// Save the open-session set after any change. `set_json`:
/// `{"tabs":[{"connection","mode":"terminal|files","layout"?,"group"?,"cwd"?}],"selected":0,"groups":[…]}`.
/// The write is atomic. Returns 0 or -1.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_open_sessions_save(data_dir: *const c_char, set_json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        bastion_ffi::open_sessions_save(required(data_dir, "data_dir")?, required(set_json, "set_json")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Mark a clean quit; call after the last save. Returns 0 or -1.
///
/// # Safety
/// `data_dir` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_open_sessions_mark_clean_quit(data_dir: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        bastion_ffi::open_sessions_mark_clean_quit(required(data_dir, "data_dir")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Call once at launch. `restore_on_launch` is the `session.restore-on-launch` setting (non-zero
/// = on). Returns the plan JSON
/// `{"lastExit":"none|clean|crash","restore","tabs":[…],"selected"?,"groups","missing","autoReconnect"}`;
/// open `tabs` with auto-reconnect on when `autoReconnect`. Free with `bastion_string_free`.
///
/// # Safety
/// `lib` from `bastion_library_open`; `data_dir` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_open_sessions_begin_json(lib: *const BastionLibrary, data_dir: *const c_char, restore_on_launch: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = library(lib)?.open_sessions_begin(required(data_dir, "data_dir")?, restore_on_launch != 0).map_err(|e| e.to_string())?;
        Ok(to_c(out))
    })
}

/// Start page "Recent sessions", most recent first, at most `limit` (capped at 200):
/// `[{"connection","name","host","port","user","protocol","lastConnectedAt","lastError"}]`.
/// "Remove from recents" is `bastion_connection_history_forget`. Free with `bastion_string_free`.
///
/// # Safety
/// `lib` from `bastion_library_open`; `data_dir` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_recent_sessions_json(lib: *const BastionLibrary, data_dir: *const c_char, limit: u32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = library(lib)?.recent_sessions_json(required(data_dir, "data_dir")?, limit).map_err(|e| e.to_string())?;
        Ok(to_c(out))
    })
}
