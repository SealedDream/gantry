//! Supervised SSH sessions over the C ABI (ABI v8): reconnect, cancel and sleep/wake for a shell
//! opened with `bastion_session_connect_ssh`.
//!
//! The first connect stays interactive in the host (login dialog, host-key verification). Once it
//! succeeds, the host hands the terminal to [`bastion_supervisor_new`], and `core::session`'s
//! `spawn_supervised` takes over: it watches the link, reconnects with exponential back-off, drops
//! the link on [`EVENT_SLEEP`], reconnects on [`EVENT_WAKE`], and stops on [`EVENT_CANCEL`].
//!
//! Reconnect never asks for, stores or replays a secret, and never logs in again from here (F06).
//! A shell from `bastion_session_connect_ssh` already has its own supervisor in the core; this
//! handle wraps it. Reconnects then reuse the first connect's prepared credentials and broker
//! leases (an expired lease fails and needs a sign-in by hand) and happen only when the
//! connection opts in to `auto_reconnect`. The same shell reattaches in place, so
//! [`bastion_supervisor_link`] stays 1. A shell without its own supervisor (a local program)
//! gets cancel handling only and is never redialled. `login_kind` and `credential_or_key` are
//! still validated for compatibility; `max_attempts` applies to the unsupervised case only.
use std::ffi::c_char;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use bastion_core::session::{spawn_supervised, AttemptError, Link, ReconnectPolicy, SessionEvent, SessionState, Supervisor};
use bastion_ffi::Terminal;

use crate::terminal::BastionTerminal;
use crate::{guarded, library, optional, optional_text, required, set_ok, BastionLibrary, BastionSessionManager};

/// Connecting (the host's own first connect passes through this briefly).
pub const STATE_CONNECTING: i32 = 0;
pub const STATE_CONNECTED: i32 = 1;
/// The link dropped; attempt `*attempt` is under way or waiting for its back-off delay.
pub const STATE_RECONNECTING: i32 = 2;
/// The system went to sleep; the link was dropped on purpose and comes back on wake.
pub const STATE_SUSPENDED: i32 = 3;
/// Disconnected and not retrying (not allowed for this login, attempts used up, or refused).
pub const STATE_FAILED: i32 = 4;
/// Closed by cancel.
pub const STATE_CLOSED: i32 = 5;

pub const EVENT_SLEEP: i32 = 0;
pub const EVENT_WAKE: i32 = 1;
pub const EVENT_CANCEL: i32 = 2;
/// The network path changed (ABI 62): with reconnect on, replace the link now and skip any back-off.
pub const EVENT_NETWORK_CHANGED: i32 = 3;

/// Upper bound for `max_attempts`.
pub const MAX_RECONNECT_ATTEMPTS: u32 = 10;

/// The supervisor needs a reactor of its own: `bastion_ffi`'s runtime is private, and its blocking
/// connect must not run on a runtime thread anyway. One worker is plenty: the tasks only wait.
pub(crate) static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().thread_name("bastion-supervisor").build().expect("supervisor runtime")
});

/// The current terminal and how many links have connected so far.
struct Current {
    terminal: Arc<Terminal>,
    link: u64,
}

/// Opaque handle for one supervised session.
pub struct BastionSupervisor {
    supervisor: Supervisor,
    current: Arc<Mutex<Current>>,
}

impl BastionSupervisor {
    /// Cancel closes the shell, as before.
    fn close_shell(&self) {
        self.current.lock().unwrap_or_else(|p| p.into_inner()).terminal.close();
    }
}

/// A connected shell as the supervisor sees it. Dropping it (cancel, sleep) closes the shell.
struct TerminalLink(Arc<Terminal>);

impl Link for TerminalLink {
    fn closed(&mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bastion_core::session::LinkEnd> + Send + '_>> {
        Box::pin(async move {
            while self.0.is_alive() {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            bastion_core::session::LinkEnd::Lost("the connection closed".into())
        })
    }
}

impl Drop for TerminalLink {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Supervise the SSH shell `terminal`, which `bastion_session_connect_ssh` just opened for
/// `connection_id`. The supervisor keeps its own reference; the host still frees its `terminal`
/// handle as usual.
///
/// - `login_kind` and `credential_or_key` say how to log in again: the credential id for
///   [`crate::LOGIN_VAULT`], the item id for [`crate::LOGIN_VAULTWARDEN`] (the session must stay unlocked), the key file path for [`crate::LOGIN_KEY_FILE`] (a key without a
///   passphrase only). [`crate::LOGIN_PASSWORD`] disables reconnect; `credential_or_key` is then
///   ignored and must never be the password.
/// - `username`: the user name the first connect used; NULL or empty for the saved one.
/// - `max_attempts`: 1..=[`MAX_RECONNECT_ATTEMPTS`] attempts per drop (back-off 1 s, 2 s, 4 s, … up to 60 s).
///
/// Returns NULL and sets `*err` on bad arguments.
///
/// # Safety
/// `m`, `lib` and `terminal` live; strings NULL (where allowed) or valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_supervisor_new(
    m: *const BastionSessionManager,
    lib: *const BastionLibrary,
    terminal: *const BastionTerminal,
    connection_id: *const c_char,
    username: *const c_char,
    login_kind: i32,
    credential_or_key: *const c_char,
    max_attempts: u32,
    err: *mut *mut c_char,
) -> *mut BastionSupervisor {
    guarded(err, std::ptr::null_mut(), || {
        let manager = m.as_ref().map(|m| m.0.clone()).ok_or_else(|| "session manager handle is NULL".to_string())?;
        let library = library(lib)?;
        let first = terminal.as_ref().map(|t| t.shared().clone()).ok_or_else(|| "terminal handle is NULL".to_string())?;
        let id = required(connection_id, "connection_id")?;
        let user = optional(username, "username")?.unwrap_or_default();
        if max_attempts == 0 || max_attempts > MAX_RECONNECT_ATTEMPTS {
            return Err(format!("max_attempts must be 1..={MAX_RECONNECT_ATTEMPTS}"));
        }
        // The login kind is still checked so a bad call fails as before, but reconnecting never
        // logs in again from here (F06): the terminal's own supervisor redials with the first
        // connect's prepared credentials and broker leases, and only when the connection opts in
        // to `auto_reconnect`. An expired lease therefore needs a fresh sign-in by hand.
        match login_kind {
            crate::LOGIN_PASSWORD | crate::LOGIN_PROVIDER | crate::LOGIN_AGENT => {}
            crate::LOGIN_VAULT => {
                optional(credential_or_key, "credential_or_key")?.ok_or_else(|| "a credential id is required for a vault login".to_string())?;
            }
            crate::LOGIN_VAULTWARDEN => {
                optional(credential_or_key, "credential_or_key")?.ok_or_else(|| "an item id is required for a Vaultwarden login".to_string())?;
            }
            crate::LOGIN_KEY_FILE => {
                optional(credential_or_key, "credential_or_key")?.ok_or_else(|| "key_path is required for a key-file login".to_string())?;
            }
            k => return Err(format!("unknown login_kind {k}")),
        }
        let _ = (manager, library, id, user);
        let current = Arc::new(Mutex::new(Current { terminal: first.clone(), link: 1 }));
        let supervisor = match first.supervision_channels() {
            Some((events, state)) => Supervisor { events, state },
            // An unsupervised shell gets cancel and sleep handling only: it is never redialled.
            None => {
                let mut first = Some(first);
                let policy = ReconnectPolicy { enabled: false, max_attempts, ..ReconnectPolicy::default() };
                let _rt = RUNTIME.enter();
                spawn_supervised(policy, move || {
                    let first = first.take();
                    async move {
                        match first {
                            Some(t) => Ok(TerminalLink(t)),
                            None => Err(AttemptError { reason: "reconnect by hand to sign in again".into(), auth: true }),
                        }
                    }
                })
            }
        };
        Ok(Box::into_raw(Box::new(BastionSupervisor { supervisor, current })))
    })
}

/// # Safety
/// `s` NULL or a live handle.
unsafe fn sup<'a>(s: *const BastionSupervisor) -> Result<&'a BastionSupervisor, String> {
    s.as_ref().ok_or_else(|| "supervisor handle is NULL".to_string())
}

/// Current state as a `STATE_*` value, or -1 for a NULL handle. `attempt` (optional) receives the
/// attempt number for [`STATE_RECONNECTING`], else 0. `reason` (optional) receives why the link
/// failed for [`STATE_FAILED`] (never a secret), else NULL; free it with `bastion_string_free`.
///
/// # Safety
/// `s` NULL or live; `attempt` and `reason` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_supervisor_state(s: *const BastionSupervisor, attempt: *mut u32, reason: *mut *mut c_char) -> i32 {
    if !attempt.is_null() {
        *attempt = 0;
    }
    if !reason.is_null() {
        *reason = std::ptr::null_mut();
    }
    let Ok(s) = sup(s) else { return -1 };
    let state = s.supervisor.state.borrow().clone();
    match state {
        SessionState::Idle | SessionState::Connecting | SessionState::Authenticating => STATE_CONNECTING,
        SessionState::Connected => STATE_CONNECTED,
        SessionState::Reconnecting { attempt: n } => {
            if !attempt.is_null() {
                *attempt = n;
            }
            STATE_RECONNECTING
        }
        SessionState::Suspended => STATE_SUSPENDED,
        SessionState::Failed(why) => {
            if !reason.is_null() {
                *reason = optional_text(Some(why));
            }
            STATE_FAILED
        }
        SessionState::Disconnecting | SessionState::Closed => STATE_CLOSED,
    }
}

/// How many links have connected so far (1 after the host's own connect). When it moves, take the
/// new shell with [`bastion_supervisor_terminal`]. 0 for a NULL handle.
///
/// # Safety
/// `s` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_supervisor_link(s: *const BastionSupervisor) -> u64 {
    sup(s).map(|s| s.current.lock().unwrap_or_else(|p| p.into_inner()).link).unwrap_or(0)
}

/// A new handle to the current shell (free it with `bastion_terminal_free`).
///
/// # Safety
/// `s` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_supervisor_terminal(s: *const BastionSupervisor, err: *mut *mut c_char) -> *mut BastionTerminal {
    guarded(err, std::ptr::null_mut(), || {
        let t = sup(s)?.current.lock().unwrap_or_else(|p| p.into_inner()).terminal.clone();
        Ok(Box::into_raw(Box::new(BastionTerminal::new(t))))
    })
}

/// Deliver [`EVENT_SLEEP`], [`EVENT_WAKE`], [`EVENT_CANCEL`] or [`EVENT_NETWORK_CHANGED`]. 0, or -1 for a bad event, a NULL
/// handle, or a supervisor that has already stopped.
///
/// # Safety
/// `s` NULL or live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_supervisor_event(s: *const BastionSupervisor, event: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let e = match event {
            EVENT_SLEEP => SessionEvent::Sleep,
            EVENT_WAKE => SessionEvent::Wake,
            EVENT_CANCEL => SessionEvent::Cancel,
            EVENT_NETWORK_CHANGED => SessionEvent::NetworkChanged,
            e => return Err(format!("unknown event {e}")),
        };
        let s = sup(s)?;
        let cancel = matches!(e, SessionEvent::Cancel);
        s.supervisor.events.send(e).map_err(|_| "the session has already stopped".to_string())?;
        if cancel {
            s.close_shell();
        }
        set_ok()
    })
}

/// Cancel the session (closing its shell) and release the handle. NULL is ignored. Terminal
/// handles taken from it stay valid until freed.
///
/// # Safety
/// `s` NULL or a live handle not in use by another thread; not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_supervisor_free(s: *mut BastionSupervisor) {
    if !s.is_null() {
        let s = Box::from_raw(s);
        let _ = s.supervisor.events.send(SessionEvent::Cancel);
        s.close_shell();
    }
}
