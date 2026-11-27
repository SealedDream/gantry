//! Host status dashboard over the C ABI (ABI 68). Opt in per connection or folder with the
//! inheritable `host_status` property. The checker starts hidden and does nothing (no timer, no
//! socket) until `bastion_host_status_set_visible(h, 1)`; set it back to 0 when the view hides.
use std::ffi::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::HostStatusDashboard;
use serde_json::json;

use crate::{guarded, library, to_c, BastionLibrary};

/// Opaque handle for the dashboard's checker.
pub struct BastionHostStatus(Arc<HostStatusDashboard>);

unsafe fn dash<'a>(h: *const BastionHostStatus) -> Result<&'a Arc<HostStatusDashboard>, String> {
    h.as_ref().map(|h| &h.0).ok_or_else(|| "host status handle is NULL".to_string())
}

/// A hidden checker that runs every `interval_secs` (clamped to 30–3600) while visible. Free with
/// `bastion_host_status_free`.
#[no_mangle]
pub extern "C" fn bastion_host_status_new(interval_secs: u32) -> *mut BastionHostStatus {
    Box::into_raw(Box::new(BastionHostStatus(HostStatusDashboard::new(interval_secs))))
}

/// # Safety
/// `h` NULL or from `bastion_host_status_new`, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_host_status_free(h: *mut BastionHostStatus) {
    if !h.is_null() {
        drop(Box::from_raw(h));
    }
}

/// Take the opted-in connections from the library (call again after edits). Returns how many,
/// or -1 with `*err` set.
///
/// # Safety
/// `h` and `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_host_status_load(h: *const BastionHostStatus, lib: *const BastionLibrary, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let n = dash(h)?.load(library(lib)?).map_err(|e| e.to_string())?;
        Ok(i32::try_from(n).unwrap_or(i32::MAX))
    })
}

/// 1 while the dashboard is on screen (checks at once, then every interval), 0 when hidden.
///
/// # Safety
/// `h` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_host_status_set_visible(h: *const BastionHostStatus, visible: i32) {
    if let Ok(d) = dash(h) {
        d.set_visible(visible != 0);
    }
}

/// # Safety
/// `h` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_host_status_set_interval(h: *const BastionHostStatus, interval_secs: u32) {
    if let Ok(d) = dash(h) {
        d.set_interval(interval_secs);
    }
}

/// Refresh now; has no effect while hidden.
///
/// # Safety
/// `h` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_host_status_check_now(h: *const BastionHostStatus) {
    if let Ok(d) = dash(h) {
        d.check_now();
    }
}

/// JSON array of `{id, name, state, latencyMs, error, checkedAt, changedAt}`; `state` is
/// `unknown`, `up`, `down` or `skipped` (behind a jump host or gateway); times are Unix seconds.
///
/// # Safety
/// `h` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_host_status_snapshot_json(h: *const BastionHostStatus, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let rows: Vec<_> = dash(h)?
            .snapshot()
            .into_iter()
            .map(|s| json!({ "id": s.id, "name": s.name, "state": s.state, "latencyMs": s.latency_ms, "error": s.error, "checkedAt": s.checked_at, "changedAt": s.changed_at }))
            .collect();
        Ok(to_c(serde_json::Value::Array(rows).to_string()))
    })
}
