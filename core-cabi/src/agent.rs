//! Bastion's own SSH agent over the C ABI (v60, `bastion_core::keyagent`): serve vault keys to
//! `ssh`, `git` and other tools. `socket` is a Unix socket path (its folder mode 700) or, on
//! Windows, a named pipe `\\.\pipe\...` (owner-only, local, same-user clients only). Put it in
//! `SSH_AUTH_SOCK` for child processes. Clients cannot add or remove keys.
use std::ffi::{c_char, c_void, CString};
use std::path::Path;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_core::keyagent::{self, ConfirmFn, KeyAgent};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::supervisor::RUNTIME;
use crate::{guarded, required, to_c};

/// Asked before each signature: `(ctx, comment, sha256_fingerprint)`, return non-zero to sign.
/// Called on a background thread, and may block (e.g. while a dialog is open).
pub type BastionAgentConfirm = Option<unsafe extern "C" fn(ctx: *mut c_void, comment: *const c_char, fingerprint: *const c_char) -> i32>;

/// Opaque handle for a running agent; free it to stop serving.
pub struct BastionAgent {
    agent: KeyAgent,
    gate: Option<Arc<Gate>>,
}

/// Called once no confirm callback is running any more (`bastion_agent_stop`).
pub type BastionAgentStopped = Option<unsafe extern "C" fn(ctx: *mut c_void)>;

/// Tracks confirm callbacks in flight so stopping can wait for them (F02): after stop no new
/// callback starts, and completion is reported only when the running ones have returned.
#[derive(Default)]
struct Gate {
    state: std::sync::Mutex<GateState>,
    idle: std::sync::Condvar,
}

#[derive(Default)]
struct GateState {
    stopped: bool,
    in_flight: usize,
    on_idle: Option<Box<dyn FnOnce() + Send>>,
}

impl Gate {
    fn state(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// False once stopped: the callback must not run.
    fn enter(&self) -> bool {
        let mut s = self.state();
        if s.stopped {
            return false;
        }
        s.in_flight += 1;
        true
    }

    fn leave(&self) {
        let done = {
            let mut s = self.state();
            s.in_flight -= 1;
            if s.in_flight == 0 { s.on_idle.take() } else { None }
        };
        self.idle.notify_all();
        if let Some(f) = done {
            f();
        }
    }

    /// Stop new callbacks; `on_idle` runs once none is running (now, if none is).
    fn stop(&self, on_idle: Option<Box<dyn FnOnce() + Send>>) {
        let now = {
            let mut s = self.state();
            s.stopped = true;
            if s.in_flight == 0 {
                on_idle
            } else {
                s.on_idle = on_idle;
                None
            }
        };
        if let Some(f) = now {
            f();
        }
    }

    fn wait_idle(&self) {
        let mut s = self.state();
        while s.in_flight > 0 {
            s = self.idle.wait(s).unwrap_or_else(|e| e.into_inner());
        }
    }
}

#[derive(Deserialize)]
struct KeyIn {
    key: String,
    #[serde(default)]
    passphrase: Option<String>,
}

impl Drop for KeyIn {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        if let Some(p) = self.passphrase.as_mut() {
            p.zeroize();
        }
    }
}

/// `ctx` crosses to the runtime thread; the host promises it is thread-safe.
struct Ctx(*mut c_void);
unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}

impl Ctx {
    fn ptr(&self) -> *mut c_void {
        self.0
    }
}

fn confirm_fn(cb: BastionAgentConfirm, ctx: *mut c_void, gate: Arc<Gate>) -> Option<ConfirmFn> {
    let cb = cb?;
    let ctx = Ctx(ctx);
    Some(Arc::new(move |comment: &str, fingerprint: &str| {
        let (Ok(c), Ok(f)) = (CString::new(comment), CString::new(fingerprint)) else { return false };
        // Refuse (no callback) once the host stopped the agent.
        if !gate.enter() {
            return false;
        }
        // SAFETY: the host keeps the callback and a thread-safe `ctx` valid until stop completes.
        let ok = unsafe { cb(ctx.ptr(), c.as_ptr(), f.as_ptr()) != 0 };
        gate.leave();
        ok
    }))
}

/// Start serving keys. `keys_json`: `[{"key": "<private key text>", "passphrase": null}]`
/// (OpenSSH, PEM or `.ppk`; FIDO2 `sk-` keys are skipped). `confirm` NULL signs without asking;
/// otherwise every signature calls it with `ctx`, which must stay valid until `bastion_agent_free`
/// returns, or until `bastion_agent_stop`'s `stopped` callback has run.
/// Returns NULL with `*err` set on a bad key, a socket already in use or an unsafe folder.
///
/// # Safety
/// Strings valid NUL-terminated UTF-8; `confirm` NULL or a valid function; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_agent_start(socket: *const c_char, keys_json: *const c_char, confirm: BastionAgentConfirm, ctx: *mut c_void, err: *mut *mut c_char) -> *mut BastionAgent {
    guarded(err, null_mut(), || {
        let socket = required(socket, "socket")?;
        let keys_text = Zeroizing::new(required(keys_json, "keys_json")?);
        let input: Vec<KeyIn> = serde_json::from_str(&keys_text).map_err(|e| format!("keys_json: {e}"))?;
        let keys = input
            .iter()
            .map(|k| bastion_core::keymanager::load(&k.key, k.passphrase.as_deref()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let gate = confirm.map(|_| Arc::new(Gate::default()));
        let check = gate.clone().and_then(|g| confirm_fn(confirm, ctx, g));
        let agent = RUNTIME.block_on(keyagent::start(Path::new(&socket), &keys, check)).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionAgent { agent, gate })))
    })
}

/// The socket or pipe path to put in `SSH_AUTH_SOCK`; NULL for a NULL handle. Free with `bastion_string_free`.
///
/// # Safety
/// `a` NULL or a live handle.
#[no_mangle]
pub unsafe extern "C" fn bastion_agent_socket(a: *const BastionAgent) -> *mut c_char {
    match a.as_ref() {
        Some(a) => to_c(a.agent.socket().to_string_lossy().into_owned()),
        None => null_mut(),
    }
}

/// Stop serving and remove the socket, then wait until no confirm callback is still running:
/// on return the callback and `ctx` are no longer used. Never call it from a thread that a
/// confirm callback may be waiting on (a UI thread showing the dialog); use
/// `bastion_agent_stop` there. NULL is ignored.
///
/// # Safety
/// `a` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_agent_free(a: *mut BastionAgent) {
    if a.is_null() {
        return;
    }
    if let Some(gate) = stop_serving(Box::from_raw(a)) {
        gate.stop(None);
        gate.wait_idle();
    }
}

/// (ABI 83) Stop serving and remove the socket now, without waiting. `stopped(stopped_ctx)` is
/// called exactly once when no confirm callback is running any more: right away (before this
/// returns) when none is, else on the thread that finishes the last one. Keep the confirm
/// callback and its `ctx` valid until then. `stopped` NULL just stops. NULL `a` is ignored
/// (and `stopped` is not called).
///
/// # Safety
/// `a` NULL or a live handle, not used afterwards; `stopped` NULL or valid; `stopped_ctx` usable
/// from any thread.
#[no_mangle]
pub unsafe extern "C" fn bastion_agent_stop(a: *mut BastionAgent, stopped: BastionAgentStopped, stopped_ctx: *mut c_void) {
    if a.is_null() {
        return;
    }
    let ctx = Ctx(stopped_ctx);
    let notify: Option<Box<dyn FnOnce() + Send>> = stopped.map(|f| {
        Box::new(move || {
            // SAFETY: the host gave a valid function and a context usable from any thread.
            unsafe { f(ctx.ptr()) }
        }) as Box<dyn FnOnce() + Send>
    });
    match stop_serving(Box::from_raw(a)) {
        Some(gate) => gate.stop(notify),
        None => {
            if let Some(f) = notify {
                f();
            }
        }
    }
}

/// Drop the agent (aborts the serve task and removes the socket); the gate, if any, remains.
fn stop_serving(a: Box<BastionAgent>) -> Option<Arc<Gate>> {
    // The serve task belongs to the runtime.
    let _guard = RUNTIME.enter();
    let BastionAgent { agent, gate } = *a;
    drop(agent);
    gate
}
