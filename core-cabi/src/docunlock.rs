//! Document-first launch over the C ABI (ABI 81): unlock back-off status, the wrapped document
//! key for a biometry-protected key store item, each document's state folder, recent document
//! details and auto-lock decisions. `bastion_document_unlock` (password) now applies the
//! back-off: five wrong passwords start a 30 s wait that doubles.
use std::ffi::c_char;
use std::ptr::null_mut;

use serde_json::json;
use zeroize::Zeroizing;

use crate::documents::{doc, BastionDocumentHandle};
use crate::{guarded, required, set_ok, to_c};

/// `{"failures","waitSecs"}` for the Unlock screen. Free with `bastion_string_free`.
///
/// # Safety
/// `d` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_unlock_status_json(d: *const BastionDocumentHandle, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let s = doc(d)?.unlock_status();
        Ok(to_c(json!({ "failures": s.failures, "waitSecs": s.wait_secs }).to_string()))
    })
}

/// The unlocked document key wrapped for this device (hex); keep it behind biometrics.
/// Free with `bastion_string_free` (it is not secret on its own, but clear it after storing).
///
/// # Safety
/// `d` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_export_wrapped_key(d: *const BastionDocumentHandle, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(doc(d)?.export_wrapped_key().map_err(|e| e.to_string())?)))
}

/// Unlock with a blob from `bastion_document_export_wrapped_key`. Returns 0 or -1.
///
/// # Safety
/// `d` live; `wrapped` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_unlock_wrapped_key(d: *const BastionDocumentHandle, wrapped: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let w = Zeroizing::new(required(wrapped, "wrapped")?);
        doc(d)?.unlock_wrapped_key(w.to_string()).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// This document's own state folder: the `data_dir` for `bastion_open_sessions_*`,
/// `bastion_recent_sessions_json` and `bastion_connection_history_*`. Free with `bastion_string_free`.
///
/// # Safety
/// `d` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_state_dir(d: *const BastionDocumentHandle, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(doc(d)?.state_dir().map_err(|e| e.to_string())?)))
}

/// Recent documents with details, newest first:
/// `[{"path","name","id","present","protected","biometric","lastOpenedAt","connectionCount"}]`
/// (`connectionCount` since ABI 145, null when never recorded). Free with `bastion_string_free`.
///
/// # Safety
/// `data_dir` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_documents_recent_details_json(data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(bastion_ffi::recent_document_details(required(data_dir, "data_dir")?).map_err(|e| e.to_string())?)))
}

/// Remove `path` from Recent documents (the file is not touched). ABI 145.
///
/// # Safety
/// `data_dir` and `path` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_documents_forget_recent(data_dir: *const c_char, path: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        bastion_ffi::forget_recent_document(required(data_dir, "data_dir")?, required(path, "path")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Auto-lock decision: 0 = keep open, 1 = idle, 2 = screen locked, 3 = sleep. `minutes` from
/// `bastion_effective_auto_lock_minutes`; flags non-zero = true.
#[no_mangle]
pub extern "C" fn bastion_document_auto_lock_due(minutes: u32, idle_secs: u64, screen_locked: i32, asleep: i32, remember_until_quit: i32) -> i32 {
    match bastion_ffi::document_auto_lock_due(minutes, idle_secs, screen_locked != 0, asleep != 0, remember_until_quit != 0).as_deref() {
        Some("idle") => 1,
        Some("screenLocked") => 2,
        Some("sleep") => 3,
        _ => 0,
    }
}

/// Idle minutes in force: the user's value (0 = never) capped by a policy maximum (0 = none).
#[no_mangle]
pub extern "C" fn bastion_effective_auto_lock_minutes(user_minutes: u32, policy_max: u32) -> u32 {
    bastion_ffi::effective_auto_lock_minutes(user_minutes, (policy_max > 0).then_some(policy_max))
}

/// Idle minutes in force under the managed policy (`document_auto_lock_max_minutes` caps the
/// user's `document.auto-lock-minutes`, 0 = never).
#[no_mangle]
pub extern "C" fn bastion_document_auto_lock_minutes(user_minutes: u32) -> u32 {
    bastion_ffi::document_auto_lock_minutes(user_minutes)
}

/// 1 when biometric document unlock is allowed, 0 when the managed policy requires the password.
#[no_mangle]
pub extern "C" fn bastion_document_biometric_unlock_allowed() -> i32 {
    i32::from(bastion_ffi::document_biometric_unlock_allowed())
}
