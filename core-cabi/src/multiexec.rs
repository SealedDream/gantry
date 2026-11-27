//! Multi-host exec over the C ABI (ABI 73), as the Windows app uses it: one approved single-line
//! command on several saved SSH connections, 1 to 16 at a time. Wraps `bastion_ffi::MultiExec`
//! without policy of its own: the core review refuses bad plans, production hosts need an explicit
//! acknowledgement, host keys are strict (an unknown key fails that host, never a prompt) and the
//! audit log records the host count and command length, never the command.
use std::ffi::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::{HostResultView, MultiExec};
use serde_json::json;

use crate::session::{login_from, BastionSessionManager};
use crate::{guarded, library, optional, required, set_ok, to_c, BastionLibrary};

/// Opaque handle for one multi-host run. Free with [`bastion_multiexec_free`].
pub struct BastionMultiExec(Arc<MultiExec>);

unsafe fn exec<'a>(x: *const BastionMultiExec) -> Result<&'a MultiExec, String> {
    x.as_ref().map(|x| &*x.0).ok_or_else(|| "multi-exec handle is NULL".to_string())
}

fn ids_from(json: String) -> Result<Vec<String>, String> {
    serde_json::from_str(&json).map_err(|_| "connection_ids_json must be a JSON array of connection ids".to_string())
}

/// Review a plan without running it: JSON `{sensitive: [names], needsProductionAck}`, or NULL with
/// `*err` set when the core refuses it (empty or multi-line command, no hosts, a non-SSH host,
/// concurrency outside 1 to 16).
///
/// # Safety
/// `lib` live; strings valid NUL-terminated UTF-8; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_multiexec_review_json(
    lib: *const BastionLibrary,
    connection_ids_json: *const c_char,
    command: *const c_char,
    concurrency: u32,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let ids = ids_from(required(connection_ids_json, "connection_ids_json")?)?;
        let r = bastion_ffi::review_exec(library(lib)?, ids, required(command, "command")?, concurrency).map_err(|e| e.to_string())?;
        Ok(to_c(json!({ "sensitive": r.sensitive, "needsProductionAck": r.needs_production_ack }).to_string()))
    })
}

/// Prepare a run (reviewed as [`bastion_multiexec_review_json`]); nothing connects until
/// [`bastion_multiexec_run`]. `production_ack` must be non-zero when the review asked for it.
/// `login_kind`, `password` and `key_path` are as for `bastion_session_connect_ssh` (every host
/// uses this login; an empty `username` uses each connection's own). Zero `password` after.
///
/// # Safety
/// `m` and `lib` live; strings NULL (where allowed) or valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_multiexec_new(
    m: *const BastionSessionManager,
    lib: *const BastionLibrary,
    connection_ids_json: *const c_char,
    command: *const c_char,
    concurrency: u32,
    username: *const c_char,
    login_kind: i32,
    password: *const c_char,
    key_path: *const c_char,
    production_ack: i32,
    err: *mut *mut c_char,
) -> *mut BastionMultiExec {
    guarded(err, null_mut(), || {
        let manager = m.as_ref().map(|m| m.0.clone()).ok_or_else(|| "session manager handle is NULL".to_string())?;
        let ids = ids_from(required(connection_ids_json, "connection_ids_json")?)?;
        let login = login_from(login_kind, optional(password, "password")?, optional(key_path, "key_path")?, None)?;
        let user = optional(username, "username")?.unwrap_or_default();
        let x = MultiExec::new(manager, library(lib)?, ids, required(command, "command")?, concurrency, user, login, production_ack != 0)
            .map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionMultiExec(x))))
    })
}

/// Start every host (again) in the background. Returns 0, or -1 with `*err` set.
///
/// # Safety
/// `x` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_multiexec_run(x: *const BastionMultiExec, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        exec(x)?.run();
        set_ok()
    })
}

/// Run again the hosts that failed, were cancelled or exited non-zero. Returns 0, or -1 with `*err` set.
///
/// # Safety
/// `x` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_multiexec_retry_failed(x: *const BastionMultiExec, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        exec(x)?.retry_failed();
        set_ok()
    })
}

/// Stop starting hosts; running ones finish (or time out) and are reported. Returns 0, or -1.
///
/// # Safety
/// `x` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_multiexec_cancel(x: *const BastionMultiExec, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        exec(x)?.cancel();
        set_ok()
    })
}

fn result_json(r: &HostResultView) -> serde_json::Value {
    json!({ "host": r.host, "state": r.state, "exit": r.exit, "stdout": r.stdout, "stderr": r.stderr, "error": r.error, "millis": r.millis })
}

/// Progress: JSON `{finished, hosts: [{host, state, exit, stdout, stderr, error, millis}]}` in plan
/// order; `state` is `waiting`, `running`, `done`, `failed` or `cancelled`.
///
/// # Safety
/// `x` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_multiexec_results_json(x: *const BastionMultiExec, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let x = exec(x)?;
        let hosts: Vec<_> = x.results().iter().map(result_json).collect();
        Ok(to_c(json!({ "finished": x.is_finished(), "hosts": hosts }).to_string()))
    })
}

/// The results as `json` or `csv` text, for copying.
///
/// # Safety
/// `x` live; `format` valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_multiexec_export(x: *const BastionMultiExec, format: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(exec(x)?.export(required(format, "format")?).map_err(|e| e.to_string())?)))
}

/// Cancel and free a run. Hosts already running finish in the background. NULL is ignored.
///
/// # Safety
/// `x` NULL or a handle from [`bastion_multiexec_new`] not yet freed.
#[no_mangle]
pub unsafe extern "C" fn bastion_multiexec_free(x: *mut BastionMultiExec) {
    if !x.is_null() {
        let x = Box::from_raw(x);
        x.0.cancel();
    }
}
