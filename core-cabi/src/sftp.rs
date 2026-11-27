//! SFTP over the C ABI: a file browser on the SSH connection of an open terminal (no new login).
//!
//! Every call blocks on the network, so hosts call them off the UI thread. One handle may be used
//! from one thread at a time; free it with [`bastion_sftp_free`] (the SSH connection stays open for
//! its terminal).
use std::ffi::c_char;
use std::sync::Arc;

use bastion_ffi::FilesBrowser as SftpBrowser;
use serde_json::json;

use crate::{guarded, required, set_ok, to_c, BastionTerminal};

/// Opaque handle for one SFTP browser.
pub struct BastionSftp(pub(crate) Arc<SftpBrowser>);

unsafe fn sftp<'a>(s: *const BastionSftp) -> Result<&'a SftpBrowser, String> {
    s.as_ref().map(|s| &*s.0).ok_or_else(|| "sftp handle is NULL".to_string())
}

/// Open an SFTP browser on the SSH connection behind terminal `t`. Fails for a local terminal or
/// when the server has no SFTP subsystem. Returns NULL and sets `*err` on failure.
///
/// # Safety
/// `t` a live terminal handle; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_open_sftp(t: *const BastionTerminal, err: *mut *mut c_char) -> *mut BastionSftp {
    guarded(err, std::ptr::null_mut(), || {
        let t = t.as_ref().ok_or_else(|| "terminal handle is NULL".to_string())?;
        let b = t.shared().open_sftp().map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionSftp(b))))
    })
}

/// The remote home directory (the server's canonical `.`). Free with [`crate::bastion_string_free`].
///
/// # Safety
/// `s` a live handle; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_sftp_home(s: *const BastionSftp, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || Ok(to_c(sftp(s)?.home().map_err(|e| e.to_string())?)))
}

/// Entries of the remote directory `path` as a JSON array of
/// `{"name", "kind" ("file"|"dir"|"symlink"|"other"), "size", "modified" (Unix seconds or null), "permissions" (or null)}`,
/// without `.` and `..`. Free with [`crate::bastion_string_free`].
///
/// # Safety
/// `s` a live handle; `path` valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_sftp_list_json(s: *const BastionSftp, path: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let entries = sftp(s)?.list(required(path, "path")?).map_err(|e| e.to_string())?;
        let value: Vec<_> = entries
            .into_iter()
            .filter(|e| e.name != "." && e.name != "..")
            .map(|e| json!({ "name": e.name, "kind": e.kind, "size": e.size, "modified": e.modified, "permissions": e.permissions }))
            .collect();
        Ok(to_c(serde_json::Value::Array(value).to_string()))
    })
}

/// Download `remote` to the local file `local`. An existing local file is refused unless
/// `overwrite` is 1. Returns the bytes copied, or -1 and sets `*err`.
///
/// # Safety
/// `s` a live handle; strings valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_sftp_download(s: *const BastionSftp, remote: *const c_char, local: *const c_char, overwrite: u8, err: *mut *mut c_char) -> i64 {
    guarded(err, -1, || {
        let n = sftp(s)?.download(required(remote, "remote")?, required(local, "local")?, overwrite != 0).map_err(|e| e.to_string())?;
        Ok(n as i64)
    })
}

/// Upload the local file `local` to `remote`. An existing remote file is refused unless
/// `overwrite` is 1. Returns the bytes copied, or -1 and sets `*err`.
///
/// # Safety
/// `s` a live handle; strings valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_sftp_upload(s: *const BastionSftp, local: *const c_char, remote: *const c_char, overwrite: u8, err: *mut *mut c_char) -> i64 {
    guarded(err, -1, || {
        let n = sftp(s)?.upload(required(local, "local")?, required(remote, "remote")?, overwrite != 0).map_err(|e| e.to_string())?;
        Ok(n as i64)
    })
}

/// Store the bytes copied so far into `*progress` (an 8-byte aligned u64 the host polls).
unsafe fn progress_cell<'a>(progress: *mut u64) -> Option<&'a std::sync::atomic::AtomicU64> {
    if progress.is_null() || progress as usize % std::mem::align_of::<std::sync::atomic::AtomicU64>() != 0 {
        return None;
    }
    Some(&*(progress as *const std::sync::atomic::AtomicU64))
}

/// `bastion_sftp_download` that also writes the bytes received so far to `*progress` while it
/// runs (after every chunk over SFTP; once at the end over SCP and FTPS). The host reads it from
/// another thread. `progress` may be NULL; an unaligned pointer is ignored.
///
/// # Safety
/// As `bastion_sftp_download`; `progress` NULL or an 8-byte aligned u64 that outlives the call.
#[no_mangle]
pub unsafe extern "C" fn bastion_sftp_download_progress(s: *const BastionSftp, remote: *const c_char, local: *const c_char, overwrite: u8, progress: *mut u64, err: *mut *mut c_char) -> i64 {
    let cell = progress_cell(progress);
    guarded(err, -1, || {
        let report = |n: u64| { if let Some(c) = cell { c.store(n, std::sync::atomic::Ordering::Relaxed) } };
        let n = sftp(s)?.download_progress(&required(remote, "remote")?, &required(local, "local")?, overwrite != 0, &report).map_err(|e| e.to_string())?;
        Ok(n as i64)
    })
}

/// `bastion_sftp_upload` with byte progress in `*progress`, as `bastion_sftp_download_progress`.
///
/// # Safety
/// As `bastion_sftp_upload`; `progress` NULL or an 8-byte aligned u64 that outlives the call.
#[no_mangle]
pub unsafe extern "C" fn bastion_sftp_upload_progress(s: *const BastionSftp, local: *const c_char, remote: *const c_char, overwrite: u8, progress: *mut u64, err: *mut *mut c_char) -> i64 {
    let cell = progress_cell(progress);
    guarded(err, -1, || {
        let report = |n: u64| { if let Some(c) = cell { c.store(n, std::sync::atomic::Ordering::Relaxed) } };
        let n = sftp(s)?.upload_progress(&required(local, "local")?, &required(remote, "remote")?, overwrite != 0, &report).map_err(|e| e.to_string())?;
        Ok(n as i64)
    })
}

/// Create the remote directory `path`. Returns 0, or -1 and sets `*err`.
///
/// # Safety
/// `s` a live handle; `path` valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_sftp_mkdir(s: *const BastionSftp, path: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        sftp(s)?.mkdir(required(path, "path")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Rename or move the remote entry `from` to `to`. Returns 0, or -1 and sets `*err`.
///
/// # Safety
/// `s` a live handle; strings valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_sftp_rename(s: *const BastionSftp, from: *const c_char, to: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        sftp(s)?.rename(required(from, "from")?, required(to, "to")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Delete the remote `path`: a file or link when `is_dir` is 0, else a folder with everything in
/// it. Refuses the root and paths ending in `.`/`..`. Returns the entries removed, or -1 and sets
/// `*err` (ABI 70).
///
/// # Safety
/// `s` a live handle; `path` valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_sftp_remove(s: *const BastionSftp, path: *const c_char, is_dir: u8, err: *mut *mut c_char) -> i64 {
    guarded(err, -1, || {
        let n = sftp(s)?.remove(required(path, "path")?, is_dir != 0).map_err(|e| e.to_string())?;
        Ok(n as i64)
    })
}

/// Release the browser. NULL is ignored; the SSH connection stays open for its terminal.
///
/// # Safety
/// `s` NULL or a live handle not in use by another thread; not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_sftp_free(s: *mut BastionSftp) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}

/// Open a remote text file for editing (SFTP only). JSON `{text, fingerprint}`; keep the
/// fingerprint for `bastion_sftp_edit_save`. Additive in ABI 59. Free with `bastion_string_free`.
///
/// # Safety
/// `s` a live handle; `path` valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_sftp_edit_open(s: *const BastionSftp, path: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || Ok(to_c(sftp(s)?.edit_open(required(path, "path")?).map_err(|e| e.to_string())?)))
}

/// Save `text` to `path` unless the server copy changed since `fingerprint_json` (NULL for a new
/// file; `force` non-zero overwrites anyway). JSON `{saved: true, fingerprint}` or
/// `{saved: false, current}` (nothing written). Free with `bastion_string_free`.
///
/// # Safety
/// `s` a live handle; strings valid NUL-terminated UTF-8 (`fingerprint_json` may be NULL); `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_sftp_edit_save(s: *const BastionSftp, path: *const c_char, text: *const c_char, fingerprint_json: *const c_char, force: u8, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let out = sftp(s)?.edit_save(required(path, "path")?, required(text, "text")?, crate::optional(fingerprint_json, "fingerprint_json")?, force != 0).map_err(|e| e.to_string())?;
        Ok(to_c(out))
    })
}
