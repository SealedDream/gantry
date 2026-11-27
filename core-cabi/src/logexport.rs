//! Log snippet export over the C ABI: clean selected terminal text and write it to a new
//! owner-only `.log` file. Additive in ABI 54.
use std::ffi::c_char;
use std::path::Path;
use std::ptr::null_mut;

use bastion_core::logexport;

use crate::terminal::{term, BastionTerminal};
use crate::{guarded, library, optional, required, to_c, BastionLibrary};

/// Plain text of `text` (escapes stripped when `strip_ansi` is non-zero, trailing blanks trimmed).
/// Free with `bastion_string_free`.
///
/// # Safety
/// `text` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_log_snippet_clean(text: *const c_char, strip_ansi: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(logexport::clean_snippet(&required(text, "text")?, strip_ansi != 0))))
}

/// Write `header` (NULL for none) and the cleaned `text` to a new owner-only `<name>.log` in
/// `dir` (`-2`, `-3` … when taken; never overwrites). Returns the path written.
/// Free with `bastion_string_free`.
///
/// # Safety
/// Strings valid NUL-terminated (`header` may be NULL); `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_log_snippet_export(dir: *const c_char, name: *const c_char, header: *const c_char, text: *const c_char, strip_ansi: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let header = optional(header, "header")?.unwrap_or_default();
        let path = logexport::export_snippet(Path::new(&required(dir, "dir")?), &required(name, "name")?, &header, &required(text, "text")?, strip_ansi != 0).map_err(|e| e.to_string())?;
        Ok(to_c(path.to_string_lossy().into_owned()))
    })
}

/// Export the terminal's current selection the same way. Fails when nothing is selected.
///
/// # Safety
/// `t` live; strings valid NUL-terminated (`header` may be NULL); `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_export_selection(t: *const BastionTerminal, dir: *const c_char, name: *const c_char, header: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let text = term(t)?.selection_text().ok_or("nothing is selected")?;
        let header = optional(header, "header")?.unwrap_or_default();
        let path = logexport::export_snippet(Path::new(&required(dir, "dir")?), &required(name, "name")?, &header, &text, true).map_err(|e| e.to_string())?;
        Ok(to_c(path.to_string_lossy().into_owned()))
    })
}

/// Start logging this terminal's output to a new owner-only file in `dir` (created owner-only)
/// named after `label`. Rotates at `max_bytes` (0 = 10 MB, at least 4096) keeping `keep` older
/// files; answers echoed after password/passphrase/token prompts are always redacted. Returns
/// the path. Additive in ABI 58. Free with `bastion_string_free`.
///
/// # Safety
/// `t` live; strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_start_log(t: *const BastionTerminal, dir: *const c_char, label: *const c_char, max_bytes: u64, keep: u32, strip_ansi: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let max_bytes = if max_bytes == 0 { bastion_core::sessionlog::DEFAULT_MAX_BYTES } else { max_bytes };
        let path = term(t)?.start_log_with(required(dir, "dir")?, required(label, "label")?, max_bytes, keep, strip_ansi != 0).map_err(|e| e.to_string())?;
        Ok(to_c(path))
    })
}

/// Stop logging (flushes any partial line). No-op when not logging.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_stop_log(t: *const BastionTerminal) {
    guarded(null_mut(), (), || Ok(term(t)?.stop_log()))
}

/// 1 while logging, 0 otherwise.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_is_logging(t: *const BastionTerminal) -> i32 {
    guarded(null_mut(), 0, || Ok(term(t)?.is_logging() as i32))
}

// Session log v2 (LOG-CORE-02).

fn plan_json(p: &bastion_ffi::SessionLogPlanView) -> String {
    serde_json::json!({ "root": p.root, "path": p.path, "header": p.header, "timestamps": p.timestamps }).to_string()
}

/// Where and how a session of `connection_id` would be logged, as JSON
/// `{"root","path","header","timestamps"}`. `data_dir` holds `settings.json` and the default
/// `session-logs` root; `app` and `version` go into the header; `utc_offset_minutes` is the local
/// time's offset. Free with `bastion_string_free`.
///
/// # Safety
/// `lib` live; strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_session_log_plan_json(lib: *const BastionLibrary, connection_id: *const c_char, data_dir: *const c_char, app: *const c_char, version: *const c_char, utc_offset_minutes: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let p = library(lib)?
            .session_log_plan(required(connection_id, "connection_id")?, required(data_dir, "data_dir")?, required(app, "app")?, required(version, "version")?, utc_offset_minutes)
            .map_err(|e| e.to_string())?;
        Ok(to_c(plan_json(&p)))
    })
}

/// Start the planned session log for a saved connection on terminal `t` (see
/// `bastion_session_log_plan_json`). Returns the file used. Free with `bastion_string_free`.
///
/// # Safety
/// `t` and `lib` live; strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_start_planned_log(t: *const BastionTerminal, lib: *const BastionLibrary, connection_id: *const c_char, data_dir: *const c_char, app: *const c_char, version: *const c_char, utc_offset_minutes: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let path = term(t)?
            .start_planned_log(library(lib)?, required(connection_id, "connection_id")?, required(data_dir, "data_dir")?, required(app, "app")?, required(version, "version")?, utc_offset_minutes)
            .map_err(|e| e.to_string())?;
        Ok(to_c(path))
    })
}

/// The terminal's session log state as JSON `{"state":"off"|"active"|"stopped","path","reason"}`.
/// Free with `bastion_string_free`.
///
/// # Safety
/// `t` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_log_state_json(t: *const BastionTerminal, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let s = term(t)?.log_state();
        Ok(to_c(serde_json::json!({ "state": s.state, "path": s.path, "reason": s.reason }).to_string()))
    })
}

/// Stop the session log with `reason` for the footer (NULL or empty: `unknown`). Returns the
/// file's SHA-256 (hex), or NULL with `err` unset when no log was running. Free with
/// `bastion_string_free`.
///
/// # Safety
/// `t` live; `reason` NULL or valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_finish_log(t: *const BastionTerminal, reason: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let reason = optional(reason, "reason")?.unwrap_or_default();
        Ok(term(t)?.finish_log(reason).map_err(|e| e.to_string())?.map_or(null_mut(), to_c))
    })
}

/// Apply the session log retention settings under `root` (NULL or empty: the default root in
/// `data_dir`), with each folder's `session_log_keep_days` from `lib` (NULL: settings only).
/// Returns JSON `{"deleted_files","freed_bytes","removed_folders"}`. Free with
/// `bastion_string_free`.
///
/// # Safety
/// Strings valid NUL-terminated (`root` may be NULL); `lib` NULL or live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_purge_session_logs_json(lib: *const BastionLibrary, root: *const c_char, data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let (root, data_dir) = (optional(root, "root")?.unwrap_or_default(), required(data_dir, "data_dir")?);
        let r = if lib.is_null() { bastion_ffi::purge_session_logs(root, data_dir) } else { library(lib)?.purge_session_logs(root, data_dir) }.map_err(|e| e.to_string())?;
        Ok(to_c(serde_json::json!({ "deleted_files": r.deleted_files, "freed_bytes": r.freed_bytes, "removed_folders": r.removed_folders }).to_string()))
    })
}
