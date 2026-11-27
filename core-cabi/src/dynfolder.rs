//! Dynamic folders (B15) over the C ABI, as Native Windows uses them. Forwards to `bastion_ffi`,
//! so policy, the trust rule, caps and audit records stay in the core.
//!
//! `user_enabled` is the user's own switch from the app's settings (0 or 1); a managed
//! `forbid_dynamic_folders` always wins.
//!
//! Run JSON: `{finished, state, items, skipped, error, exit, millis}`; `state` is `running`,
//! `done`, `failed`, `timed_out` or `cancelled`. Item: `{id, name, protocol, host, port,
//! username, credentialName, notes, path}`.
use std::ffi::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::{DynamicFolderRun, DynamicRunView, GeneratedItemView, SessionManager};
use serde_json::{json, Value};

use crate::session::BastionSessionManager;
use crate::{guarded, handle, library, optional, required, set_ok, to_c, BastionLibrary};

/// Opaque handle for one Refresh. Free with [`bastion_dynamic_folder_run_free`].
pub struct BastionDynamicFolderRun(Arc<DynamicFolderRun>);

unsafe fn run<'a>(r: *const BastionDynamicFolderRun) -> Result<&'a Arc<DynamicFolderRun>, String> {
    r.as_ref().map(|r| &r.0).ok_or_else(|| "dynamic folder run handle is NULL".to_string())
}

unsafe fn mgr(m: *const BastionSessionManager) -> Result<Arc<SessionManager>, String> {
    m.as_ref().map(|m| m.0.clone()).ok_or_else(|| "session manager handle is NULL".to_string())
}

fn item_json(i: &GeneratedItemView) -> Value {
    json!({ "id": i.id, "name": i.name, "protocol": i.protocol, "host": i.host, "port": i.port, "username": i.username,
            "credentialName": i.credential_name, "notes": i.notes, "path": i.path })
}

fn run_json(o: &DynamicRunView, finished: bool) -> Value {
    json!({ "finished": finished, "state": o.state, "items": o.items.iter().map(item_json).collect::<Vec<_>>(), "skipped": o.skipped,
            "error": o.error, "exit": o.exit, "millis": o.millis })
}

/// 1 when dynamic folders may be shown (no managed ban), else 0.
#[no_mangle]
pub extern "C" fn bastion_dynamic_folders_allowed() -> i32 {
    i32::from(bastion_ffi::dynamic_folders_allowed())
}

/// The task id bound to a folder as a JSON string, or JSON `null`.
///
/// # Safety
/// `lib` live; `folder_id` valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_dynamic_folder_task_json(lib: *const BastionLibrary, folder_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let t = handle(lib)?.dynamic_folder_task(required(folder_id, "folder_id")?).map_err(|e| e.to_string())?;
        Ok(to_c(json!(t).to_string()))
    })
}

/// Bind a folder to a task (`task_id`), or make it plain (`task_id` NULL or empty). Returns 0, or
/// -1 with `*err` (feature off, task not eligible, unknown folder).
///
/// # Safety
/// `lib` live; strings NULL (where allowed) or valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_dynamic_folder_set_task(lib: *const BastionLibrary, folder_id: *const c_char, task_id: *const c_char, user_enabled: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.set_dynamic_folder_task(required(folder_id, "folder_id")?, optional(task_id, "task_id")?, user_enabled != 0).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Tasks that may feed a dynamic folder: `[{id, name}]`.
///
/// # Safety
/// `lib` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_dynamic_folder_task_choices_json(lib: *const BastionLibrary, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let list: Vec<Value> = handle(lib)?.dynamic_folder_task_choices().into_iter().map(|p| json!({ "id": p[0], "name": p[1] })).collect();
        Ok(to_c(Value::Array(list).to_string()))
    })
}

/// The consent sheet: `{taskId, taskName, program, args, timeoutSecs, trusted, sha256, warnings}`.
/// An error when the trust file is damaged.
///
/// # Safety
/// `m` and `lib` live; `folder_id` valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_dynamic_folder_review_json(m: *const BastionSessionManager, lib: *const BastionLibrary, folder_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let r = bastion_ffi::dynamic_folder_review(mgr(m)?, library(lib)?, required(folder_id, "folder_id")?).map_err(|e| e.to_string())?;
        Ok(to_c(json!({ "taskId": r.task_id, "taskName": r.task_name, "program": r.program, "args": r.args, "timeoutSecs": r.timeout_secs, "trusted": r.trusted, "sha256": r.sha256, "warnings": r.warnings }).to_string()))
    })
}

/// Trust the folder's task on this computer. Only from the user's "Trust and run";
/// `reviewed_sha256` is the review's `sha256` (refused if the task changed since, or the feature
/// is off). Returns 0, or -1 with `*err`.
///
/// # Safety
/// `m` and `lib` live; strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_dynamic_folder_trust(m: *const BastionSessionManager, lib: *const BastionLibrary, folder_id: *const c_char, reviewed_sha256: *const c_char, user_enabled: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        bastion_ffi::dynamic_folder_trust(mgr(m)?, library(lib)?, required(folder_id, "folder_id")?, required(reviewed_sha256, "reviewed_sha256")?, user_enabled != 0).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Remove the trust of the folder's task. Returns 1 when removed, 0 when none was set, -1 on error.
///
/// # Safety
/// `m` and `lib` live; `folder_id` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_dynamic_folder_revoke(m: *const BastionSessionManager, lib: *const BastionLibrary, folder_id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let removed = bastion_ffi::dynamic_folder_revoke(mgr(m)?, library(lib)?, required(folder_id, "folder_id")?).map_err(|e| e.to_string())?;
        Ok(i32::from(removed))
    })
}

/// Start a Refresh in the background. NULL with `*err` when refused (policy, task, path, trust).
///
/// # Safety
/// `m` and `lib` live; `folder_id` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_dynamic_folder_run_start(m: *const BastionSessionManager, lib: *const BastionLibrary, folder_id: *const c_char, user_enabled: i32, err: *mut *mut c_char) -> *mut BastionDynamicFolderRun {
    guarded(err, null_mut(), || {
        let r = DynamicFolderRun::start(mgr(m)?, library(lib)?, required(folder_id, "folder_id")?, user_enabled != 0).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionDynamicFolderRun(r))))
    })
}

/// Progress and result as run JSON (see the module text).
///
/// # Safety
/// `r` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_dynamic_folder_run_output_json(r: *const BastionDynamicFolderRun, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let r = run(r)?;
        Ok(to_c(run_json(&r.output(), r.is_finished()).to_string()))
    })
}

/// Stop the program and everything it started. Returns 0, or -1.
///
/// # Safety
/// `r` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_dynamic_folder_run_cancel(r: *const BastionDynamicFolderRun, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        run(r)?.cancel();
        set_ok()
    })
}

/// Copy a finished run's items into the folder as ordinary connections. Returns the count, or -1.
///
/// # Safety
/// `lib` and `r` live; `folder_id` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_dynamic_folder_make_permanent(lib: *const BastionLibrary, folder_id: *const c_char, r: *const BastionDynamicFolderRun, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let n = handle(lib)?.dynamic_folder_make_permanent(required(folder_id, "folder_id")?, run(r)?.clone()).map_err(|e| e.to_string())?;
        i32::try_from(n).map_err(|_| "too many items".to_string())
    })
}

/// Release a run handle. A run still going is cancelled (its process tree killed) and audited.
///
/// # Safety
/// `r` NULL or a handle from [`bastion_dynamic_folder_run_start`] not yet freed.
#[no_mangle]
pub unsafe extern "C" fn bastion_dynamic_folder_run_free(r: *mut BastionDynamicFolderRun) {
    if !r.is_null() {
        drop(Box::from_raw(r));
    }
}
