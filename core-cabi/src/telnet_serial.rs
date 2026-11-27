//! Telnet and serial terminals for the Windows app (B7, `docs/plans/B7-TELNET-SERIAL.md`).
//! Additive exports; the ABI number is assigned at merge
//! (`docs/tasks/ABI-LEDGER.md`).
use std::ffi::c_char;
use std::ptr::null_mut;

use bastion_ffi::telnet_serial::{list_serial_ports, serial_common_bauds, serial_port_poll_ms, telnet_allowed_for, telnet_policy_lock, telnet_warning};
use bastion_ffi::Terminal;

use crate::prefs::{settings, BastionSettings};
use crate::session::{login_from, manager, BastionSessionManager};
use crate::terminal::{term, BastionTerminal};
use crate::{guarded, optional, optional_text, required, to_c, BastionLibrary};

/// 1 when Telnet may be used now (the "Allow Telnet" switch in `s` under the managed policy),
/// 0 when not or on error.
///
/// # Safety
/// `s` NULL or a live settings handle.
#[no_mangle]
pub unsafe extern "C" fn bastion_telnet_allowed(s: *const BastionSettings) -> i32 {
    guarded(null_mut(), 0, || Ok(telnet_allowed_for(settings(s)?) as i32))
}

/// Why the "Allow Telnet" switch is locked by the administrator, or NULL when the user decides.
/// Free with `bastion_string_free`.
#[no_mangle]
pub extern "C" fn bastion_telnet_policy_lock() -> *mut c_char {
    optional_text(telnet_policy_lock())
}

/// The Telnet warning band text. Free with `bastion_string_free`.
#[no_mangle]
pub extern "C" fn bastion_telnet_warning() -> *mut c_char {
    to_c(telnet_warning())
}

/// Serial ports on this machine as JSON `[{"name","description","kind"}]` (may be `[]`).
/// Call every [`bastion_serial_port_poll_ms`] while a picker is open, off the UI thread.
///
/// # Safety
/// `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_serial_ports_json(err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let ports = list_serial_ports().map_err(|e| e.to_string())?;
        let v: Vec<_> = ports.into_iter().map(|p| serde_json::json!({ "name": p.name, "description": p.description, "kind": p.kind })).collect();
        Ok(to_c(serde_json::Value::Array(v).to_string()))
    })
}

#[no_mangle]
pub extern "C" fn bastion_serial_port_poll_ms() -> u32 {
    serial_port_poll_ms()
}

/// Common baud rates as a JSON array of numbers. Free with `bastion_string_free`.
#[no_mangle]
pub extern "C" fn bastion_serial_common_bauds_json() -> *mut c_char {
    to_c(serde_json::to_string(&serial_common_bauds()).unwrap_or_else(|_| "[]".into()))
}

/// Open the saved serial connection `connection_id`. NULL with `err` set in words ("Port not
/// found: COM3", "COM3 is in use by another program").
///
/// # Safety
/// `lib` live; `connection_id` valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_open_serial(lib: *const BastionLibrary, connection_id: *const c_char, cols: u16, rows: u16, err: *mut *mut c_char) -> *mut BastionTerminal {
    guarded(err, null_mut(), || {
        let lib = crate::library(lib)?;
        let t = Terminal::serial_connection(lib, required(connection_id, "connection_id")?, cols, rows).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionTerminal::new(t))))
    })
}

/// Open the saved Telnet connection `connection_id`. Refused (NULL, `err` set) unless Telnet is
/// allowed. `login_kind` / `secret` as for `bastion_session_connect_ssh_mfa` (password, vault,
/// Vaultwarden or provider; -1 for none). The login is used only when the connection itself has
/// "Type the saved password after the login prompt" on.
///
/// # Safety
/// Handles live; strings NULL or valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_session_connect_telnet(
    m: *const BastionSessionManager,
    lib: *const BastionLibrary,
    s: *const BastionSettings,
    connection_id: *const c_char,
    username: *const c_char,
    login_kind: i32,
    secret: *const c_char,
    cols: u16,
    rows: u16,
    err: *mut *mut c_char,
) -> *mut BastionTerminal {
    guarded(err, null_mut(), || {
        let mgr = manager(m)?;
        let lib = crate::library(lib)?;
        let login = if login_kind < 0 { None } else { Some(login_from(login_kind, optional(secret, "secret")?, None, None)?) };
        let username = optional(username, "username")?.unwrap_or_default();
        let t = mgr.connect_telnet_with(&lib, settings(s)?, &required(connection_id, "connection_id")?, username, login, cols, rows).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionTerminal::new(t))))
    })
}

/// Reconnect a Telnet terminal (nothing typed for you) or reopen a serial port. 0 on success,
/// -1 with `err` set.
///
/// # Safety
/// `t` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_reconnect(t: *const BastionTerminal, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        term(t)?.reconnect().map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// "Connection lost" / "Port disconnected" for a Telnet or serial terminal whose link dropped,
/// else NULL. Free with `bastion_string_free`.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_remote_status(t: *const BastionTerminal) -> *mut c_char {
    guarded(null_mut(), null_mut(), || Ok(optional_text(term(t)?.link_status())))
}

/// `COM3 · 115200 8N1` for a serial terminal, else NULL. Free with `bastion_string_free`.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_serial_status(t: *const BastionTerminal) -> *mut c_char {
    guarded(null_mut(), null_mut(), || Ok(optional_text(term(t)?.serial_status())))
}
