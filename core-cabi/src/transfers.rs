//! File-panel model over the C ABI: the transfer queue, OSC 7 paths and edit-locally watching.
//!
//! The queue is state only; the host's worker copies bytes with `bastion_sftp_upload` /
//! `_download` (or the SCP fallback) and reports back. Handles are thread-safe (internally locked).
//! Additive in ABI 45.
use std::ffi::c_char;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use bastion_core::filepanel::{self, EditWatcher};
use bastion_core::transfer_queue::{Direction, Overwrite, TargetInfo, TransferQueue};
use serde_json::json;

use crate::{guarded, optional_text, required, set_ok, to_c};

/// Opaque transfer queue.
pub struct BastionTransfers(Mutex<TransferQueue>);
/// Opaque edit-locally watcher.
pub struct BastionEditWatcher(Mutex<EditWatcher>);

unsafe fn queue<'a>(q: *const BastionTransfers) -> Result<MutexGuard<'a, TransferQueue>, String> {
    let q = q.as_ref().ok_or_else(|| "transfers handle is NULL".to_string())?;
    Ok(q.0.lock().unwrap_or_else(|p| p.into_inner()))
}

unsafe fn watcher<'a>(w: *const BastionEditWatcher) -> Result<MutexGuard<'a, EditWatcher>, String> {
    let w = w.as_ref().ok_or_else(|| "edit watcher handle is NULL".to_string())?;
    Ok(w.0.lock().unwrap_or_else(|p| p.into_inner()))
}

fn parse<T: serde::de::DeserializeOwned>(text: &str, what: &str) -> Result<T, String> {
    serde_json::from_value(serde_json::Value::String(text.to_string())).map_err(|_| format!("unknown {what} '{text}'"))
}

/// A queue running up to `parallel` jobs at once (clamped to 1..=8). Free with [`bastion_transfers_free`].
#[no_mangle]
pub extern "C" fn bastion_transfers_new(parallel: u32) -> *mut BastionTransfers {
    Box::into_raw(Box::new(BastionTransfers(Mutex::new(TransferQueue::new(parallel as usize)))))
}

/// # Safety
/// `q` NULL or a handle from [`bastion_transfers_new`], not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_transfers_free(q: *mut BastionTransfers) {
    if !q.is_null() {
        drop(Box::from_raw(q));
    }
}

/// Queue a job. `direction` "upload"|"download"; `overwrite` "ask"|"replace"|"skip"|"replace_if_newer"|"rename".
/// Returns the job id (> 0), or 0 and sets `*err`.
///
/// # Safety
/// `q` live; strings valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_transfers_add(
    q: *const BastionTransfers,
    direction: *const c_char,
    source: *const c_char,
    target: *const c_char,
    total: u64,
    overwrite: *const c_char,
    err: *mut *mut c_char,
) -> u64 {
    guarded(err, 0, || {
        let direction: Direction = parse(&required(direction, "direction")?, "direction")?;
        let overwrite: Overwrite = parse(&required(overwrite, "overwrite")?, "overwrite rule")?;
        queue(q)?.add(direction, &required(source, "source")?, &required(target, "target")?, total, overwrite).map_err(|e| e.to_string())
    })
}

/// Start the oldest queued job if a slot is free: the job as JSON, or NULL when none can start.
/// Free with [`crate::bastion_string_free`].
///
/// # Safety
/// `q` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_transfers_start_next(q: *const BastionTransfers, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        Ok(match queue(q)?.start_next() {
            Some(job) => to_c(serde_json::to_string(&job).map_err(|e| e.to_string())?),
            None => std::ptr::null_mut(),
        })
    })
}

/// Apply the job's overwrite rule. `info_json` is `{"exists", "target_modified", "source_modified"}`
/// (Unix seconds or null); `taken_json` NULL or a JSON array of paths already used (for "rename").
/// Returns `{"action":"copy","target","replace"}`, `{"action":"skip"}` or `{"action":"ask"}`.
///
/// # Safety
/// `q` live; strings valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_transfers_resolve(
    q: *const BastionTransfers,
    id: u64,
    info_json: *const c_char,
    taken_json: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let info: TargetInfo = serde_json::from_str(&required(info_json, "info")?).map_err(|e| format!("bad target info: {e}"))?;
        let taken: Vec<String> = if taken_json.is_null() {
            Vec::new()
        } else {
            serde_json::from_str(&required(taken_json, "taken")?).map_err(|e| format!("bad taken list: {e}"))?
        };
        let r = queue(q)?.resolve(id, info, |c| taken.iter().any(|t| t == c)).map_err(|e| e.to_string())?;
        Ok(to_c(serde_json::to_string(&r).map_err(|e| e.to_string())?))
    })
}

/// Report `done` bytes copied in total, `elapsed_ms` after the previous report. 0, or -1 with `*err`.
///
/// # Safety
/// `q` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_transfers_progress(q: *const BastionTransfers, id: u64, done: u64, elapsed_ms: u64, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        queue(q)?.progress(id, done, Duration::from_millis(elapsed_ms)).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Change a job: `action` "finish"|"fail"|"pause"|"resume"|"retry"|"cancel", or a conflict answer
/// "replace"|"skip"|"replace_if_newer"|"rename". `detail` is the error text for "fail" (else NULL).
/// 0, or -1 with `*err` (unknown id, or the action does not fit the job's state).
///
/// # Safety
/// `q` live; `action` valid UTF-8; `detail` NULL or valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_transfers_update(q: *const BastionTransfers, id: u64, action: *const c_char, detail: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let action = required(action, "action")?;
        let detail = if detail.is_null() { "transfer failed".to_string() } else { required(detail, "detail")? };
        let mut q = queue(q)?;
        let result = match action.as_str() {
            "finish" => q.finish(id),
            "fail" => q.fail(id, &detail),
            "pause" => q.pause(id),
            "resume" => q.resume(id),
            "retry" => q.retry(id),
            "cancel" => q.cancel(id),
            other => q.answer_conflict(id, parse(other, "action")?),
        };
        result.map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Drop finished jobs (failed ones stay for retry).
///
/// # Safety
/// `q` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_transfers_clear_finished(q: *const BastionTransfers) {
    if let Ok(mut q) = queue(q) {
        q.clear_finished();
    }
}

/// `{"jobs":[{id, direction, source, target, overwrite, state, total, done, speed, eta, attempts, error}],
/// "summary":{active, queued, failed, total, done, speed}}`. Free with [`crate::bastion_string_free`].
///
/// # Safety
/// `q` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_transfers_json(q: *const BastionTransfers, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let q = queue(q)?;
        Ok(to_c(json!({ "jobs": q.jobs(), "summary": q.summary() }).to_string()))
    })
}

/// The directory in an OSC 7 payload (`file://host/path`), or NULL when it is not a safe absolute path.
///
/// # Safety
/// `payload` NULL or valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn bastion_osc7_path(payload: *const c_char) -> *mut c_char {
    guarded(std::ptr::null_mut(), std::ptr::null_mut(), || Ok(optional_text(filepanel::parse_osc7(&required(payload, "payload")?))))
}

/// Shell line ("bash"|"zsh") that makes the shell announce its folder with OSC 7, or NULL.
///
/// # Safety
/// `shell` NULL or valid NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn bastion_follow_folder_hook(shell: *const c_char) -> *mut c_char {
    guarded(std::ptr::null_mut(), std::ptr::null_mut(), || {
        Ok(optional_text(filepanel::follow_cd_command(&required(shell, "shell")?).map(str::to_string)))
    })
}

/// Local path for an edit-locally copy: `<base>/edit-locally/<session>/<remote file name>`, folder
/// created owner-only; never escapes the folder. Free with [`crate::bastion_string_free`].
///
/// # Safety
/// Strings valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_edit_local_path(base: *const c_char, session: *const c_char, remote: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let dir = filepanel::edit_dir(Path::new(&required(base, "base")?), &required(session, "session")?).map_err(|e| e.to_string())?;
        let path = filepanel::edit_path(&dir, &required(remote, "remote")?).map_err(|e| e.to_string())?;
        Ok(to_c(path.to_string_lossy().into_owned()))
    })
}

/// An edit-locally watcher. Free with [`bastion_edit_watcher_free`].
#[no_mangle]
pub extern "C" fn bastion_edit_watcher_new() -> *mut BastionEditWatcher {
    Box::into_raw(Box::new(BastionEditWatcher(Mutex::new(EditWatcher::new()))))
}

/// # Safety
/// `w` NULL or a handle from [`bastion_edit_watcher_new`], not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_edit_watcher_free(w: *mut BastionEditWatcher) {
    if !w.is_null() {
        drop(Box::from_raw(w));
    }
}

/// Watch the just-downloaded `local` copy of `remote` (refused over 64 MiB); with `remote` NULL,
/// stop watching `local`. 0, or -1 with `*err`.
///
/// # Safety
/// `w` live; `local` valid UTF-8; `remote` NULL or valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_edit_watcher_watch(w: *const BastionEditWatcher, local: *const c_char, remote: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let local = required(local, "local")?;
        let mut w = watcher(w)?;
        if remote.is_null() {
            w.unwatch(Path::new(&local));
        } else {
            w.watch(Path::new(&local), &required(remote, "remote")?).map_err(|e| e.to_string())?;
        }
        set_ok()
    })
}

/// Copies saved since the last poll: `{"changed":[{"local","remote"}], "gone":[{"local","remote"}]}`.
/// The host queues an upload for each changed copy; gone copies are no longer watched.
///
/// # Safety
/// `w` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_edit_watcher_poll(w: *const BastionEditWatcher, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let (changed, gone) = watcher(w)?.poll();
        Ok(to_c(json!({ "changed": changed, "gone": gone }).to_string()))
    })
}
