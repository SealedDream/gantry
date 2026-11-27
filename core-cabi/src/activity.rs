//! Session history (the activity store) over the C ABI (ABI 103): the seven calls of
//! `bastion_ffi::activity`, with the same JSON. Metadata only: no secrets, no keystrokes, no
//! session content.
//!
//! The store keeps one handle per data directory for the life of the process (inside
//! `bastion_ffi`): it knows which sessions are open and holds the lock that tells other
//! instances this run is alive. With the setting `logging.activity-enabled` off,
//! `bastion_activity_begin` still returns an id and the other calls do nothing for it.
//!
//! Lifecycle: at launch, off the UI thread, call `bastion_activity_purge` and
//! `bastion_activity_close_orphans`. Sessions opened with `bastion_session_connect*` (SSH
//! terminals, SFTP, SCP, FTPS) are recorded by the core: do not begin them here as well. For
//! the others (RDP, VNC, …) call `bastion_activity_begin` when the connect starts,
//! `bastion_activity_event` for what happens inside, and `bastion_activity_end` once.
//!
//! Every call can touch the disk and the first write of a run can wait up to two seconds for
//! another instance: call them off the UI thread. Error messages never repeat the input;
//! `bastion_last_error_code` gives `invalid` for bad input and `not_found` for an unknown or
//! already ended session.
use std::ffi::c_char;
use std::ptr::null_mut;

use crate::{coded, guarded, required, set_ok, to_c};

/// Record the start of a session; returns its session id (free with `bastion_string_free`) or
/// NULL. `start_json`: `{"connectionId","connectionName","folderPath":[{"id","name"}],
/// "protocol","host","port"?,"username"?,"route":[names],
/// "loginSource":"own|inherited|same-host|typed|agent|key","startedAt"?,
/// "app":"native-mac|native-windows|tauri","appVersion","deviceName"}`. `folderPath` is root
/// first; `startedAt` (Unix milliseconds) defaults to now.
///
/// Never pass a secret: there is no field for one, and a URL given as `host` is cut down to
/// its host and port. **Never pass a bare `user:password` as `host`**: it is not stored where
/// it can be told from a host and a port, but a password of digits only cannot be told from a
/// port.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_activity_begin(data_dir: *const c_char, start_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let id = bastion_ffi::activity_begin(required(data_dir, "data_dir")?, required(start_json, "start_json")?).map_err(coded)?;
        Ok(to_c(id))
    })
}

/// Record an event of an open session, now. `kind`: `reconnect`, `host_key`, `certificate`,
/// `resize`, `clipboard`, `shared_folder`, `file_transfer`, `tunnel`, `task`, `snippet`,
/// `broadcast`, `session_log` or `trigger`. `details_json`: a flat object of short strings,
/// numbers or booleans, metadata only (direction, size, name, exit code): never clipboard,
/// file or terminal content. A key the kind does not list is dropped. Returns 0 or -1.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_activity_event(data_dir: *const c_char, session_id: *const c_char, kind: *const c_char, details_json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        bastion_ffi::activity_event(required(data_dir, "data_dir")?, required(session_id, "session_id")?, required(kind, "kind")?, required(details_json, "details_json")?).map_err(coded)?;
        set_ok()
    })
}

/// Record the end of a session, once. `end_json`: `{"connectedAt"?,"endedAt"?,
/// "endReason":"closed_by_user|remote_closed|network_lost|auth_failed|host_key|timeout|app_quit|failed",
/// "reconnects"?,"transcriptPath"?,"transcriptSha256"?}`. `endedAt` defaults to now; leave
/// `connectedAt` out when the session never connected. Returns 0 or -1.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_activity_end(data_dir: *const c_char, session_id: *const c_char, end_json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        bastion_ffi::activity_end(required(data_dir, "data_dir")?, required(session_id, "session_id")?, required(end_json, "end_json")?).map_err(coded)?;
        set_ok()
    })
}

/// One page of sessions, newest first, as a JSON array. `filter_json`: `{"connection"?,
/// "folder"?,"from"?,"to"?,"protocol"?,"user"?,"result"?:"ok|failed|open"}` (`{}` for all);
/// `folder` includes subfolders. `limit` is capped at 500. Each item: the fields of the start,
/// `sessionId`, `open`, and once ended `connectedAt`, `endedAt`, `durationMs`, `endReason`,
/// `reconnects`, `transcriptPath`, `transcriptSha256`. Free with `bastion_string_free`.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_activity_query_json(data_dir: *const c_char, filter_json: *const c_char, offset: u32, limit: u32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = bastion_ffi::activity_query_json(required(data_dir, "data_dir")?, required(filter_json, "filter_json")?, offset, limit).map_err(coded)?;
        Ok(to_c(out))
    })
}

/// The events of one session, oldest first: `[{"at","kind","details":{…}}]`. Free with
/// `bastion_string_free`.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_activity_events_json(data_dir: *const c_char, session_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = bastion_ffi::activity_events_json(required(data_dir, "data_dir")?, required(session_id, "session_id")?).map_err(coded)?;
        Ok(to_c(out))
    })
}

/// Delete history older than the "Keep session history for" setting
/// (`logging.activity-retention-days`; 0 keeps it for ever). Returns the number of monthly
/// files deleted, or -1. Call at launch, off the UI thread.
///
/// # Safety
/// `data_dir` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_activity_purge(data_dir: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let deleted = bastion_ffi::activity_purge(required(data_dir, "data_dir")?).map_err(coded)?;
        Ok(i32::try_from(deleted).unwrap_or(i32::MAX))
    })
}

/// Close sessions an earlier run left open (crash, power loss, quit with sessions open) as
/// `app_crashed`. Returns how many, or -1. Call once at launch, off the UI thread: it can wait
/// up to two seconds for another instance. When that instance is stopped or hung the sweep is
/// skipped (0) and the next start does it; that is not a failure to show the user.
///
/// # Safety
/// `data_dir` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_activity_close_orphans(data_dir: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let closed = bastion_ffi::activity_close_orphans(required(data_dir, "data_dir")?).map_err(coded)?;
        Ok(i32::try_from(closed).unwrap_or(i32::MAX))
    })
}
