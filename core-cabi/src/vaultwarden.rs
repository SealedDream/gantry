//! Vaultwarden over the C ABI: the same `bastion_ffi::VaultwardenSession` the macOS app uses.
//!
//! The master password goes in only, as a caller-owned byte buffer the caller zeroes after the
//! call, and lives inside the core for the duration of the unlock. Item passwords never come
//! back out: the listing carries ids, names and usernames, and an SSH connect reads the secret
//! inside the core ([`crate::LOGIN_VAULTWARDEN`] after [`bastion_session_set_vaultwarden`]).
use std::ffi::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::{FfiError, VaultwardenItemView, VaultwardenSession};
use serde_json::json;

use crate::{guarded, optional, required, set_ok, to_c, BastionLibrary, BastionSessionManager};

/// `outcome` of [`bastion_vaultwarden_unlock`]: unlocked, the items are returned.
pub const VAULTWARDEN_OK: i32 = 0;
/// The account uses two-step login: ask for the authenticator code and unlock again with it.
pub const VAULTWARDEN_TWO_FACTOR: i32 = 1;
/// The e-mail or master password was refused.
pub const VAULTWARDEN_AUTH_FAILED: i32 = 2;
/// Anything else (unreachable server, plain http off loopback, …); `*err` says what.
pub const VAULTWARDEN_FAILED: i32 = 3;

/// Opaque handle for one Vaultwarden session (one per data directory).
pub struct BastionVaultwarden(pub(crate) Arc<VaultwardenSession>);

/// # Safety
/// `v` must be NULL or a live handle from [`bastion_vaultwarden_open`].
unsafe fn session<'a>(v: *const BastionVaultwarden) -> Result<&'a VaultwardenSession, String> {
    v.as_ref().map(|v| &*v.0).ok_or_else(|| "Vaultwarden handle is NULL".to_string())
}

fn items_json(s: &VaultwardenSession, items: Vec<VaultwardenItemView>) -> String {
    let items: Vec<_> = items.into_iter().map(|i| json!({ "id": i.id, "name": i.name, "username": i.username })).collect();
    json!({ "items": items, "skipped": s.skipped() }).to_string()
}

/// Open the Vaultwarden session for `data_dir` (where `vaultwarden.json` keeps the server URL,
/// e-mail and device id). It starts locked. Returns NULL and sets `*err` on failure.
///
/// # Safety
/// `data_dir` a valid NUL-terminated string; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_vaultwarden_open(data_dir: *const c_char, err: *mut *mut c_char) -> *mut BastionVaultwarden {
    guarded(err, null_mut(), || {
        let dir = required(data_dir, "data_dir")?;
        Ok(Box::into_raw(Box::new(BastionVaultwarden(Arc::new(VaultwardenSession::new(dir))))))
    })
}

/// Release a handle (locking it first). NULL is ignored.
///
/// # Safety
/// `v` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_vaultwarden_free(v: *mut BastionVaultwarden) {
    if !v.is_null() {
        let v = Box::from_raw(v);
        v.0.lock();
    }
}

/// The remembered server URL and e-mail as JSON: `{"serverUrl":…,"email":…}` (each may be null).
///
/// # Safety
/// `v` live; `err` NULL or writable. Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_vaultwarden_config_json(v: *const BastionVaultwarden, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let c = session(v)?.config();
        Ok(to_c(json!({ "serverUrl": c.server_url, "email": c.email }).to_string()))
    })
}

/// Log in and sync (blocking network I/O: call off the UI thread). `master_password` is
/// `password_len` UTF-8 bytes the caller zeroes afterwards; `totp` is NULL until
/// [`VAULTWARDEN_TWO_FACTOR`] asked for the authenticator code.
///
/// Returns `{"items":[{id,name,username}],"skipped":n}` and writes [`VAULTWARDEN_OK`] to
/// `outcome`, or returns NULL and writes another `VAULTWARDEN_*` value (with `*err` set).
///
/// # Safety
/// Strings valid NUL-terminated (`totp` may be NULL); `master_password` NULL or `password_len`
/// readable bytes; `v` live; `outcome` NULL or writable; `err` NULL or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_vaultwarden_unlock(
    v: *const BastionVaultwarden,
    server_url: *const c_char,
    email: *const c_char,
    master_password: *const u8,
    password_len: usize,
    totp: *const c_char,
    outcome: *mut i32,
    err: *mut *mut c_char,
) -> *mut c_char {
    let mut kind = VAULTWARDEN_FAILED;
    let result = guarded(err, null_mut(), || {
        let s = session(v)?;
        let (url, mail, code) = (required(server_url, "server_url")?, required(email, "email")?, optional(totp, "totp")?);
        let password = if master_password.is_null() || password_len == 0 {
            String::new()
        } else {
            let bytes = std::slice::from_raw_parts(master_password, password_len);
            std::str::from_utf8(bytes).map(str::to_string).map_err(|_| "master password is not valid UTF-8".to_string())?
        };
        match s.unlock(url, mail, password, code) {
            Ok(items) => {
                kind = VAULTWARDEN_OK;
                Ok(to_c(items_json(s, items)))
            }
            Err(e) => {
                kind = match e {
                    FfiError::TwoFactorRequired => VAULTWARDEN_TWO_FACTOR,
                    FfiError::AuthFailed => VAULTWARDEN_AUTH_FAILED,
                    _ => VAULTWARDEN_FAILED,
                };
                Err(e.to_string())
            }
        }
    });
    if !outcome.is_null() {
        *outcome = kind;
    }
    result
}

/// Fetch the items again with the in-memory refresh token (no master password, no code).
/// Same JSON as [`bastion_vaultwarden_unlock`]; NULL with `*err` when locked or refused.
///
/// # Safety
/// `v` live; `err` NULL or writable. Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_vaultwarden_resync(v: *const BastionVaultwarden, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let s = session(v)?;
        let items = s.resync().map_err(|e| e.to_string())?;
        Ok(to_c(items_json(s, items)))
    })
}

/// The items of the current unlock (empty when locked), same JSON as [`bastion_vaultwarden_unlock`].
///
/// # Safety
/// `v` live; `err` NULL or writable. Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_vaultwarden_items_json(v: *const BastionVaultwarden, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let s = session(v)?;
        Ok(to_c(items_json(s, s.items())))
    })
}

/// 1 when unlocked, 0 when locked or `v` is NULL.
///
/// # Safety
/// `v` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_vaultwarden_is_unlocked(v: *const BastionVaultwarden) -> i32 {
    session(v).map(|s| i32::from(s.is_unlocked())).unwrap_or(0)
}

/// Forget the items, the refresh token and the account key. NULL is ignored.
///
/// # Safety
/// `v` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_vaultwarden_lock(v: *const BastionVaultwarden) {
    if let Ok(s) = session(v) {
        s.lock();
    }
}

/// Let [`crate::LOGIN_VAULTWARDEN`] connects read from this Vaultwarden session. The session
/// stays shared with the caller's handle; secrets never cross back. 0 / -1.
///
/// # Safety
/// `m` and `v` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_session_set_vaultwarden(m: *const BastionSessionManager, v: *const BastionVaultwarden, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let v = v.as_ref().ok_or_else(|| "Vaultwarden handle is NULL".to_string())?;
        let m = m.as_ref().ok_or_else(|| "session manager handle is NULL".to_string())?;
        m.0.set_vaultwarden(v.0.clone());
        set_ok()
    })
}

/// Assign a Vaultwarden item to a connection, or clear it with `item_id` NULL/empty. The id is
/// not a secret; it is kept in the connection's metadata. Call `bastion_library_save` afterwards.
/// 0 / -1.
///
/// # Safety
/// Strings valid NUL-terminated (`item_id` may be NULL); `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_set_vaultwarden_item(lib: *const BastionLibrary, connection_id: *const c_char, item_id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let conn = required(connection_id, "connection id")?;
        let item = optional(item_id, "item id")?;
        crate::library(lib)?.set_vaultwarden_item(conn, item).map_err(|e| e.to_string())?;
        set_ok()
    })
}
