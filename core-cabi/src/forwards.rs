//! Port-forward manager over the C ABI (ABI 65): saved tunnels running on a terminal's own SSH
//! connection. "Start with connection" tunnels (`startWithConnection` in
//! `bastion_library_put_tunnel_json`) start when the terminal connects; every tunnel follows a
//! reconnect on the same ports and stops when the terminal closes.
use std::ffi::c_char;
use std::ptr::null_mut;

use serde_json::json;

use crate::terminal::BastionTerminal;
use crate::{guarded, library, required, set_ok, to_c, BastionLibrary};

fn view_json(v: &[bastion_ffi::ForwardStatusView]) -> String {
    let rows: Vec<_> = v
        .iter()
        .map(|s| {
            json!({ "id": s.id, "name": s.name, "summary": s.summary, "kind": s.kind, "port": s.port, "movedFrom": s.moved_from,
                    "running": s.running, "connections": s.connections, "bytesUp": s.bytes_up, "bytesDown": s.bytes_down, "lastError": s.last_error })
        })
        .collect();
    serde_json::Value::Array(rows).to_string()
}

unsafe fn handle<'a>(t: *const BastionTerminal) -> Result<&'a BastionTerminal, String> {
    t.as_ref().ok_or_else(|| "terminal is NULL".to_string())
}

/// Tunnels on the terminal's connection: JSON array of `{id, name, summary, kind, port,
/// movedFrom, running, connections, bytesUp, bytesDown, lastError}`. `movedFrom` is the saved
/// port when it was taken and the tunnel runs on `port` instead; bytes count closed connections.
/// A local terminal gives `[]`.
///
/// # Safety
/// `t` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_forwards_json(t: *const BastionTerminal, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(view_json(&handle(t)?.shared().forwards()))))
}

/// Start saved tunnels (`tunnel_ids_json`: JSON array of ids, each saved for this terminal's
/// connection) on its SSH connection; one already listed restarts. A tunnel that cannot start is
/// listed with `lastError`. Returns the same JSON as `bastion_terminal_forwards_json`.
///
/// # Safety
/// `t` and `lib` live; `tunnel_ids_json` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_start_forwards_json(t: *const BastionTerminal, lib: *const BastionLibrary, tunnel_ids_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let ids: Vec<String> = serde_json::from_str(&required(tunnel_ids_json, "tunnel_ids_json")?).map_err(|_| "tunnel_ids_json must be a JSON array of ids".to_string())?;
        let lib = library(lib)?;
        let st = handle(t)?.shared().start_forwards(lib, ids).map_err(|e| e.to_string())?;
        Ok(to_c(view_json(&st)))
    })
}

/// Stop one tunnel; it stays listed as stopped and is not restarted on reconnect. Returns 0, or
/// -1 with `*err` set.
///
/// # Safety
/// `t` live; `tunnel_id` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_stop_forward(t: *const BastionTerminal, tunnel_id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(t)?.shared().stop_forward(required(tunnel_id, "tunnel_id")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}
