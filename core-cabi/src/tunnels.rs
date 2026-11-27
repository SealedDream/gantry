//! Saved tunnels started on their own SSH connection, without a shell (ABI 72): the Windows
//! Tunnel Manager. Definitions are edited with `bastion_library_*_tunnel*` (webtunnel.rs);
//! tunnels on an open terminal's connection are `bastion_terminal_*forward*` (forwards.rs).
//!
//! Sign-in follows `bastion_session_connect_ssh_mfa` exactly (same `LOGIN_*` kinds, `CONNECT_*`
//! outcomes and explicit host-key trust), and listeners bind 127.0.0.1 only, as in the core.
use std::ffi::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::RunningTunnel;
use serde_json::json;

use crate::session::{connect_failure, jump_logins_from, jump_trust_from, login_from, manager, BastionSessionManager, CONNECT_FAILED, CONNECT_OK};
use crate::{guarded, library, optional, required, set_ok, to_c, BastionLibrary};

/// Opaque handle for one running tunnel. Freeing it stops the tunnel.
pub struct BastionTunnel(Arc<RunningTunnel>);

unsafe fn tunnel<'a>(t: *const BastionTunnel) -> Result<&'a RunningTunnel, String> {
    t.as_ref().map(|t| &*t.0).ok_or_else(|| "tunnel handle is NULL".to_string())
}

/// Sign in to saved tunnel `tunnel_id`'s SSH connection and start it. Parameters, `outcome`,
/// `fingerprint` and `hop` are as for `bastion_session_connect_ssh_mfa` (no terminal size).
/// Returns a handle (free with [`bastion_tunnel_free`]) and [`CONNECT_OK`], or NULL and another
/// `CONNECT_*` value with `*err` set. A local port already in use fails with `CONNECT_FAILED`.
///
/// # Safety
/// `m` and `lib` live; strings NULL (where allowed) or valid NUL-terminated UTF-8; `outcome`,
/// `fingerprint`, `hop` and `err` NULL or writable. Zero `password` and `jump_logins_json` after.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_tunnel_start(
    m: *const BastionSessionManager,
    lib: *const BastionLibrary,
    tunnel_id: *const c_char,
    username: *const c_char,
    login_kind: i32,
    password: *const c_char,
    key_path: *const c_char,
    code: *const c_char,
    trust_fingerprint: *const c_char,
    jump_trust_json: *const c_char,
    jump_logins_json: *const c_char,
    outcome: *mut i32,
    fingerprint: *mut *mut c_char,
    hop: *mut *mut c_char,
    err: *mut *mut c_char,
) -> *mut BastionTunnel {
    if !outcome.is_null() {
        *outcome = CONNECT_FAILED;
    }
    for p in [fingerprint, hop] {
        if !p.is_null() {
            *p = null_mut();
        }
    }
    guarded(err, null_mut(), || {
        let id = required(tunnel_id, "tunnel_id")?;
        let user = optional(username, "username")?.unwrap_or_default();
        let login = login_from(login_kind, optional(password, "password")?, optional(key_path, "key_path")?, optional(code, "code")?)?;
        let jump_logins = jump_logins_from(optional(jump_logins_json, "jump_logins_json")?)?;
        let trust = optional(trust_fingerprint, "trust_fingerprint")?;
        let jump_trust = jump_trust_from(optional(jump_trust_json, "jump_trust_json")?)?;
        match manager(m)?.start_tunnel(library(lib)?, id, user, login, trust, jump_trust, jump_logins) {
            Ok(t) => {
                if !outcome.is_null() {
                    *outcome = CONNECT_OK;
                }
                Ok(Box::into_raw(Box::new(BastionTunnel(t))))
            }
            Err(e) => Err(connect_failure(e, outcome, fingerprint, hop)),
        }
    })
}

/// State of a started tunnel: JSON `{summary, running, connections, lastError}`.
///
/// # Safety
/// `t` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_tunnel_status_json(t: *const BastionTunnel, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let t = tunnel(t)?;
        Ok(to_c(json!({ "summary": t.summary(), "running": t.is_running(), "connections": t.connections(), "lastError": t.last_error() }).to_string()))
    })
}

/// Stop the tunnel (closes its listener or cancels the remote forward). The handle stays valid
/// and reports `running: false`. Returns 0, or -1 with `*err` set.
///
/// # Safety
/// `t` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_tunnel_stop(t: *const BastionTunnel, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        tunnel(t)?.stop();
        set_ok()
    })
}

/// Stop and free a tunnel handle. NULL is ignored.
///
/// # Safety
/// `t` NULL or a handle from [`bastion_tunnel_start`] not yet freed.
#[no_mangle]
pub unsafe extern "C" fn bastion_tunnel_free(t: *mut BastionTunnel) {
    if !t.is_null() {
        let t = Box::from_raw(t);
        t.0.stop();
    }
}
