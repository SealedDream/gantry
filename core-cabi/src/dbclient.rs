//! DEPRECATED (PLUG-11, owner 2026-11-23): Native Mac and Native Windows no longer use this; the PostgreSQL
//! plugin replaces it. Kept only for the paused Tauri app. Fixes only; remove with the Tauri page and `tokio-postgres`.
//! Database client step 1 over the C ABI (ABI 78): run PostgreSQL queries through a Bastion
//! tunnel. Stateless: each call connects, runs the SQL and disconnects. See `bastion_core::dbclient`.
use std::ffi::c_char;
use std::ptr::null_mut;

use bastion_core::dbclient::{run_query, DbQuery};

use crate::{guarded, required, to_c};

/// Run one query. `request_json`:
/// `{host, port?=5432, user, password?, database?=user, sql, via?, maxRows?=1000, readOnly?=true, timeoutSecs?=30}`
/// where `via` is `{"kind":"direct"}` (loopback hosts only), `{"kind":"forward","port":N}` (a
/// running `-L` tunnel's local port) or `{"kind":"socks","port":N}` (a running `-D` tunnel; the
/// SSH server resolves `host`). Unknown fields are an error.
///
/// Returns `{statements:[{columns:[..], rows:[[text|null,..]], truncated, rowCount}], elapsedMs}`,
/// or NULL with `*err` set (bad request, tunnel not running, login or SQL error, time limit). The
/// password is never echoed. Blocking: call off the UI thread.
///
/// # Safety
/// `request_json` valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_db_query_json(request_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let raw = required(request_json, "request_json")?;
        let q: DbQuery = serde_json::from_str(&raw).map_err(|e| format!("Database request is not valid: {e}"))?;
        drop(raw);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
        let r = rt.block_on(run_query(&q)).map_err(|e| e.to_string())?;
        serde_json::to_string(&r).map(to_c).map_err(|e| e.to_string())
    })
}
