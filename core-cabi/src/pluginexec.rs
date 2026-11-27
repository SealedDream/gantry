//! Plugin `exec` (plugin API 1.5; `docs/specs/plugins.md`, section 19) over the C ABI, as the
//! Windows app uses it. Wraps `bastion_ffi::SessionManager::plugin_exec` and
//! `Library::plugin_exec_terminal_library`; see `core-ffi/src/pluginexec.rs`.
use std::ffi::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::PluginExecCancel;
use serde_json::json;

use crate::session::{login_from, BastionSessionManager};
use crate::{guarded, library, optional, required, set_ok, to_c, BastionLibrary};

/// Opaque cancel switch for one running command. Free with [`bastion_plugin_exec_cancel_free`].
pub struct BastionPluginExecCancel(Arc<PluginExecCancel>);

/// A new cancel switch.
#[no_mangle]
pub extern "C" fn bastion_plugin_exec_cancel_new() -> *mut BastionPluginExecCancel {
    Box::into_raw(Box::new(BastionPluginExecCancel(PluginExecCancel::new())))
}

/// Sets the switch: the running command ends. Returns 0, or -1 with `*err` set.
///
/// # Safety
/// `c` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_exec_cancel(c: *const BastionPluginExecCancel, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        c.as_ref().ok_or_else(|| "cancel handle is NULL".to_string())?.0.cancel();
        set_ok()
    })
}

/// # Safety
/// `c` NULL or a handle from [`bastion_plugin_exec_cancel_new`], not used again.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_exec_cancel_free(c: *mut BastionPluginExecCancel) {
    if !c.is_null() {
        drop(Box::from_raw(c));
    }
}

/// Runs `command` from an `exec-go` update on plugin entry `entry_id`, with the login as for
/// `bastion_session_connect_ssh` (`login_kind`, `password`, `key_path`; zero `password` after).
/// Blocks: call it off the UI thread. JSON `{exit, stdout, stderr, error}`, ready for the view's
/// `{"type":"exec",...}` answer (add `type` and `request`).
///
/// # Safety
/// `m`, `lib` and `cancel` live; strings NULL (where allowed) or valid NUL-terminated UTF-8; `err`
/// NULL or writable. Free the result with `bastion_string_free`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_plugin_exec_json(
    m: *const BastionSessionManager,
    lib: *const BastionLibrary,
    entry_id: *const c_char,
    username: *const c_char,
    login_kind: i32,
    password: *const c_char,
    key_path: *const c_char,
    command: *const c_char,
    timeout_ms: u64,
    cancel: *const BastionPluginExecCancel,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let manager = m.as_ref().map(|m| m.0.clone()).ok_or_else(|| "session manager handle is NULL".to_string())?;
        let cancel = cancel.as_ref().map(|c| c.0.clone()).ok_or_else(|| "cancel handle is NULL".to_string())?;
        let login = login_from(login_kind, optional(password, "password")?, optional(key_path, "key_path")?, None)?;
        let user = optional(username, "username")?.unwrap_or_default();
        let r = manager.plugin_exec(library(lib)?, required(entry_id, "entry_id")?, user, login, required(command, "command")?, timeout_ms, cancel);
        Ok(to_c(json!({ "exit": r.exit, "stdout": r.stdout, "stderr": r.stderr, "error": r.error }).to_string()))
    })
}

/// A one-connection library for an `exec-terminal` update: SSH to plugin entry `entry_id`,
/// whose terminal runs `command`. Open its one connection like Quick Connect. Free with
/// `bastion_library_free`.
///
/// # Safety
/// `lib` live; strings valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_exec_terminal_library(
    lib: *const BastionLibrary,
    entry_id: *const c_char,
    command: *const c_char,
    label: *const c_char,
    err: *mut *mut c_char,
) -> *mut BastionLibrary {
    guarded(err, null_mut(), || {
        let out = library(lib)?
            .plugin_exec_terminal_library(required(entry_id, "entry_id")?, required(command, "command")?, optional(label, "label")?.unwrap_or_default())
            .map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionLibrary(out))))
    })
}
