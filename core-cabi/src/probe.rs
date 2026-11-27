//! Test Connection over the C ABI (v29; the library and `connection_id` since v99): the same core
//! `probe` the Mac app uses.
//!
//! `bastion_probe_start` takes what the dialog holds (unsaved) as JSON and returns at once;
//! `bastion_probe_wait_json` blocks until the result (call it off the UI thread);
//! `bastion_probe_cancel` stops it from any thread. Secrets go in only: the report never holds
//! one, and the caller should zero its JSON buffer after the start call.
//!
//! SEC-07: a password is never sent to an SSH host whose key the user has not confirmed. Such a test
//! ends with the fingerprint in the report's `needs_host_key_confirmation` and a skipped login step;
//! the host shows it, and only the user's yes puts that exact string into the next request's
//! `trusted_fingerprint`. It is used for that one test: nothing is stored.
use std::ffi::c_char;
use std::sync::Arc;

use bastion_ffi::{ProbeInput, ProbeJump, ProbeTask};
use serde_json::json;

use crate::session::{login_from, manager, BastionSessionManager};
use crate::{guarded, required, to_c, BastionLibrary};

/// Opaque handle for one running test.
pub struct BastionProbe(Arc<ProbeTask>);

#[derive(serde::Deserialize)]
struct Login {
    kind: i32,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    key_path: Option<String>,
    #[serde(default)]
    code: Option<String>,
}

#[derive(serde::Deserialize)]
struct Jump {
    host: String,
    port: u16,
    username: String,
    login: Login,
}

#[derive(serde::Deserialize)]
struct Input {
    protocol: String,
    host: String,
    port: u16,
    #[serde(default)]
    username: String,
    #[serde(default)]
    login: Option<Login>,
    #[serde(default)]
    jumps: Vec<Jump>,
    /// The saved connection the dialog edits; absent or `null` for an entry not saved yet.
    #[serde(default)]
    connection_id: Option<String>,
    /// The fingerprint the user confirmed for this one test (SEC-07). Never a value taken from the server unseen.
    #[serde(default)]
    trusted_fingerprint: Option<String>,
}

fn login(l: Login) -> Result<bastion_ffi::SshLogin, String> {
    let some = |s: Option<String>| s.filter(|s| !s.is_empty());
    login_from(l.kind, some(l.secret), some(l.key_path), some(l.code))
}

/// Start a test. `input_json`:
/// `{"protocol":"ssh","host":…,"port":22,"username":…,"login":{"kind":LOGIN_*,"secret":…,"key_path":…,"code":…}|null,
/// "jumps":[{"host":…,"port":…,"username":…,"login":{…}}],"trusted_fingerprint":"SHA256:…"|null,"connection_id":…|null}`.
/// `trusted_fingerprint` is only ever the string a previous report gave in `needs_host_key_confirmation`,
/// after the user confirmed it; absent, null or empty means nothing is confirmed. A blocked protocol fails here.
///
/// Since ABI 104 the call takes the library (`lib`, NULL allowed) and `"connection_id"`, the saved
/// connection the dialog edits. A `LOGIN_VAULT` login, for the target or a jump, is read only for a
/// saved connection that may use it without asking: its own inline secret (the credential id is the
/// connection id) or its own or inherited login, and only when the host, port and jump hosts match the
/// saved connection. Otherwise the call fails before anything is read or dialled: "that login is not
/// offered for this connection", the route-differs message, or, with `lib` NULL or no `"connection_id"`,
/// "save the connection before testing it with a saved login, or type the password".
/// Other login kinds are unaffected. Free the handle with [`bastion_probe_free`].
///
/// # Safety
/// `m` live; `lib` NULL or live; `input_json` a valid NUL-terminated string; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_probe_start(m: *const BastionSessionManager, lib: *const BastionLibrary, input_json: *const c_char, err: *mut *mut c_char) -> *mut BastionProbe {
    guarded(err, std::ptr::null_mut(), || {
        // The parse error never echoes the input: it may hold a password.
        let input: Input = serde_json::from_str(&required(input_json, "input_json")?).map_err(|_| "input_json is not a valid Test Connection request".to_string())?;
        let jumps = input
            .jumps
            .into_iter()
            .map(|j| Ok(ProbeJump { host: j.host, port: j.port, username: j.username, login: login(j.login)? }))
            .collect::<Result<Vec<_>, String>>()?;
        let trusted_fingerprint = input.trusted_fingerprint.filter(|f| !f.is_empty());
        let input = ProbeInput { protocol: input.protocol, host: input.host, port: input.port, username: input.username, login: input.login.map(login).transpose()?, jumps, pasted_key: None, pasted_key_passphrase: None, trusted_fingerprint, connection_id: input.connection_id.filter(|c| !c.is_empty()) };
        let task = manager(m)?.test_connection(lib.as_ref().map(|l| l.0.clone()), input).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionProbe(task))))
    })
}

/// Block until the test ends and return its report:
/// `{"ok":bool,"cancelled":bool,"steps":[{"kind":"dns|tcp|handshake|host_key|jump_host|login",
/// "status":"ok|warn|failed|skipped","detail":…,"fix":…|null,"millis":…}],
/// "needs_host_key_confirmation":"SHA256:…"|null}`. Read `needs_host_key_confirmation` before `ok`: when it is
/// set the test stopped before the login and is not a success, whatever `ok` says. Free with `bastion_string_free`.
///
/// # Safety
/// `p` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_probe_wait_json(p: *const BastionProbe, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let p = p.as_ref().ok_or_else(|| "probe handle is NULL".to_string())?;
        let r = p.0.wait();
        let steps: Vec<_> = r.steps.iter().map(|s| json!({"kind": s.kind, "status": s.status, "detail": s.detail, "fix": s.fix, "millis": s.millis})).collect();
        Ok(to_c(json!({"ok": r.ok, "cancelled": r.cancelled, "steps": steps, "needs_host_key_confirmation": r.needs_host_key_confirmation, "host_key_failure": r.host_key_failure}).to_string()))
    })
}

/// Stop the test now; a pending or later wait returns `"cancelled":true`. NULL is ignored.
///
/// # Safety
/// `p` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_probe_cancel(p: *const BastionProbe) {
    if let Some(p) = p.as_ref() {
        p.0.cancel();
    }
}

/// Release a probe handle (cancelling it if still running). NULL is ignored.
///
/// # Safety
/// `p` NULL or a live handle no other thread is using; not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_probe_free(p: *mut BastionProbe) {
    if !p.is_null() {
        let p = Box::from_raw(p);
        p.0.cancel();
    }
}

#[cfg(test)]
#[path = "a1_fu3_tests.rs"]
mod a1_fu3_tests;
