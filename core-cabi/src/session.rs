//! SSH sessions over the C ABI (ABI v3): open a saved connection and get a terminal handle that
//! works with every `bastion_terminal_*` function.
//!
//! This wraps `bastion_ffi::SessionManager` without adding policy of its own, so the broker,
//! strict host-key checking and the audit log behave exactly as in the core and on macOS.
//!
//! Host-key trust is an explicit step, never implicit. A first connect to an unknown server
//! fails with outcome [`CONNECT_HOST_KEY_UNKNOWN`] and hands the host the server's fingerprint
//! (and, for a jump host, which hop it belongs to). The host shows it, the user verifies it out
//! of band, and only then does the host retry with that value in `trust_fingerprint` (or in
//! `jump_trust_json`). Nothing is trusted because the server asserted it.
//!
//! Secrets: `password` is the only parameter that carries one. It is copied once into the core's
//! one-shot credential provider and is never stored, logged or returned here; no error message
//! from this module contains a secret. Hosts should zero their own buffer after the call.
use std::collections::HashMap;
use std::ffi::c_char;
use std::sync::Arc;

use bastion_ffi::{FfiError, SessionManager, SshLogin};
use serde_json::json;

use crate::terminal::BastionTerminal;
use crate::{guarded, library, optional, required, set_ok, to_c, BastionLibrary};

/// Connected; the return value is a terminal handle.
pub const CONNECT_OK: i32 = 0;
/// The server's (or a jump host's) key is not trusted yet. `fingerprint` is set, and `hop` is set
/// to `host:port` when the unknown key belongs to a jump host rather than the target.
pub const CONNECT_HOST_KEY_UNKNOWN: i32 = 1;
/// The credentials were refused.
pub const CONNECT_AUTH_FAILED: i32 = 2;
/// An imported host still has unanswered placeholders; `*err` lists them.
pub const CONNECT_NEEDS_CONFIGURATION: i32 = 3;
/// Anything else (unreachable host, bad id, no username, …); `*err` says what.
pub const CONNECT_FAILED: i32 = 4;
/// The server asked keyboard-interactive for a second factor (a one-time code). Ask the user and
/// retry with [`LOGIN_PASSWORD_AND_CODE`] and the code in `code`.
pub const CONNECT_TWO_FACTOR_REQUIRED: i32 = 5;
/// SSH negotiation found no algorithm both sides accept. `*err` names what the server offers;
/// `fingerprint` is set to JSON `{"kind","serverOffers","weakAllowable"}`. When `weakAllowable`
/// is non-empty, offer "Allow for this host" (`bastion_library_allow_weak_algorithms`).
pub const CONNECT_NO_COMMON_ALGORITHM: i32 = 6;

/// `login_kind`: the secret in `password` is an account password.
pub const LOGIN_PASSWORD: i32 = 0;
/// `login_kind`: `key_path` is a private key file and `password` its passphrase (may be empty).
pub const LOGIN_KEY_FILE: i32 = 1;
/// `login_kind`: log in with a credential from the vault given to [`bastion_session_set_credentials`].
/// `password` carries the credential id (not a secret); the secret is read inside the core. An empty
/// `username` uses the credential's own.
pub const LOGIN_VAULT: i32 = 2;
/// `login_kind`: log in with an item of the Vaultwarden session given to
/// [`crate::bastion_session_set_vaultwarden`]. `password` carries the item id (not a secret); the
/// secret is read inside the core. An empty `username` uses the item's own.
pub const LOGIN_VAULTWARDEN: i32 = 3;
/// `login_kind`: keys held by the user's SSH agent (`SSH_AUTH_SOCK`, or on Windows the OpenSSH
/// agent pipe `\\.\pipe\openssh-ssh-agent`). `password` and `key_path` are ignored; no secret is typed.
pub const LOGIN_AGENT: i32 = 4;
/// `login_kind`: `password` plus the one-time `code` of [`bastion_session_connect_ssh_mfa`], after
/// a [`CONNECT_TWO_FACTOR_REQUIRED`]. The code is used for one dial only.
pub const LOGIN_PASSWORD_AND_CODE: i32 = 5;
/// `login_kind`: a password from a registered external provider ([`crate::bastion_provider_register`]).
/// `password` carries `"<provider id>:<item>"` (not a secret), e.g. `keepass:<entry uuid>`; the
/// secret is read inside the core when the login is built and is not cached.
pub const LOGIN_PROVIDER: i32 = 6;

/// Build the login for `kind` from the strings the host passed. `secret` is the password,
/// passphrase, credential id or item id, depending on `kind`.
pub(crate) fn login_from(kind: i32, secret: Option<String>, key_path: Option<String>, code: Option<String>) -> Result<SshLogin, String> {
    Ok(match kind {
        LOGIN_PASSWORD => SshLogin::Password { password: secret.unwrap_or_default() },
        LOGIN_KEY_FILE => SshLogin::KeyFile { path: key_path.ok_or_else(|| "key_path is required for a key-file login".to_string())?, passphrase: secret },
        LOGIN_VAULT => SshLogin::Vault { credential_id: secret.ok_or_else(|| "a credential id is required for a vault login".to_string())? },
        LOGIN_VAULTWARDEN => SshLogin::Vaultwarden { item_id: secret.ok_or_else(|| "an item id is required for a Vaultwarden login".to_string())? },
        LOGIN_AGENT => SshLogin::Agent,
        LOGIN_PROVIDER => SshLogin::Password {
            password: crate::providers::resolve(&secret.ok_or_else(|| "a provider item is required for a provider login".to_string())?)?.expose().to_string(),
        },
        LOGIN_PASSWORD_AND_CODE => SshLogin::PasswordAndCode {
            password: secret.unwrap_or_default(),
            code: code.ok_or_else(|| "a one-time code is required for a two-factor login".to_string())?,
        },
        k => return Err(format!("unknown login_kind {k}")),
    })
}

/// One jump host's own login in `jump_logins_json`.
#[derive(serde::Deserialize)]
struct JumpLogin {
    kind: i32,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    key_path: Option<String>,
    #[serde(default)]
    code: Option<String>,
}

/// Parse `jump_trust_json`: NULL, or a JSON object of a jump host's `host:port` to a verified fingerprint.
pub(crate) fn jump_trust_from(json: Option<String>) -> Result<HashMap<String, String>, String> {
    match json {
        None => Ok(HashMap::new()),
        Some(j) => serde_json::from_str(&j).map_err(|_| "jump_trust_json must be a JSON object of host:port to fingerprint".to_string()),
    }
}

/// Parse `{"host:port":{"kind":…,"secret":…,"key_path":…,"code":…}}`. Empty strings count as absent.
pub(crate) fn jump_logins_from(json: Option<String>) -> Result<HashMap<String, SshLogin>, String> {
    let Some(json) = json else { return Ok(HashMap::new()) };
    let parsed: HashMap<String, JumpLogin> =
        serde_json::from_str(&json).map_err(|_| "jump_logins_json must be a JSON object of host:port to {kind, secret, key_path, code}".to_string())?;
    let some = |s: Option<String>| s.filter(|s| !s.is_empty());
    parsed
        .into_iter()
        .map(|(hop, l)| login_from(l.kind, some(l.secret), some(l.key_path), some(l.code)).map(|login| (hop, login)).map_err(|e| format!("jump host {e}")))
        .collect()
}

/// Opaque handle for one session manager (broker, audit log and known_hosts for one data dir).
pub struct BastionSessionManager(pub(crate) Arc<SessionManager>);

/// # Safety
/// `m` must be NULL or a handle from [`bastion_session_manager_new`] that has not been freed.
pub(crate) unsafe fn manager<'a>(m: *const BastionSessionManager) -> Result<&'a SessionManager, String> {
    m.as_ref().map(|m| &*m.0).ok_or_else(|| "session manager handle is NULL".to_string())
}

/// Open a session manager for `data_dir` (created when missing). `known_hosts` and `audit.jsonl`
/// live there. Returns NULL and sets `*err` on failure.
///
/// # Safety
/// `data_dir` a valid NUL-terminated UTF-8 string; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_session_manager_new(data_dir: *const c_char, err: *mut *mut c_char) -> *mut BastionSessionManager {
    guarded(err, std::ptr::null_mut(), || {
        let dir = required(data_dir, "data_dir")?;
        if dir.trim().is_empty() {
            return Err("data_dir is required".into());
        }
        let m = SessionManager::new(dir).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionSessionManager(m))))
    })
}

/// Release a session manager handle. NULL is ignored. Terminals it opened stay valid: each one
/// owns its SSH connection until it is freed.
///
/// # Safety
/// `m` must be NULL or a live handle not in use by another thread, and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_session_manager_free(m: *mut BastionSessionManager) {
    if !m.is_null() {
        drop(Box::from_raw(m));
    }
}

/// Let `LOGIN_VAULT` connects read from this credential vault. The vault stays shared with the
/// caller's handle; secrets never cross back. 0 / -1.
///
/// # Safety
/// `m` and `creds` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_session_set_credentials(m: *const BastionSessionManager, creds: *const crate::BastionCredentials, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let v = creds.as_ref().ok_or_else(|| "credentials handle is NULL".to_string())?;
        manager(m)?.set_vault(v.0.clone());
        set_ok()
    })
}

/// Forget every unlocked credential now (the "Lock credentials" action). 0 / -1.
///
/// # Safety
/// `m` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_session_lock_credentials(m: *const BastionSessionManager, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        manager(m)?.lock_credentials().map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// The resolved jump hosts of `connection_id`, in connect order, as JSON:
/// `[{"key":"host:port","username":"…"}]` — `[]` for a direct connection. No secrets are
/// involved. Free the result with `bastion_string_free`.
///
/// # Safety
/// `m` and `lib` live; `connection_id` a valid NUL-terminated string; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_session_jump_hosts_json(
    m: *const BastionSessionManager,
    lib: *const BastionLibrary,
    connection_id: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let id = required(connection_id, "connection_id")?;
        let hops = manager(m)?.jump_hosts(library(lib)?, id).map_err(|e| e.to_string())?;
        let value = hops.into_iter().map(|h| json!({ "key": h.key, "username": h.username })).collect::<Vec<_>>();
        Ok(to_c(serde_json::Value::Array(value).to_string()))
    })
}

/// Connect `connection_id` over SSH and open a shell. Same as [`bastion_session_connect_ssh_mfa`]
/// with no `code` and no `jump_logins_json`: each jump host logs in with a copy of the target's login.
///
/// Deprecated (H12): superseded by [`bastion_session_connect_ssh_mfa`]; no shipped host calls it.
/// Kept for ABI compatibility until a release removes it.
///
/// # Safety
/// As for [`bastion_session_connect_ssh_mfa`].
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_session_connect_ssh(
    m: *const BastionSessionManager,
    lib: *const BastionLibrary,
    connection_id: *const c_char,
    username: *const c_char,
    login_kind: i32,
    password: *const c_char,
    key_path: *const c_char,
    trust_fingerprint: *const c_char,
    jump_trust_json: *const c_char,
    cols: u16,
    rows: u16,
    outcome: *mut i32,
    fingerprint: *mut *mut c_char,
    hop: *mut *mut c_char,
    err: *mut *mut c_char,
) -> *mut BastionTerminal {
    bastion_session_connect_ssh_mfa(
        m, lib, connection_id, username, login_kind, password, key_path, std::ptr::null(), trust_fingerprint, jump_trust_json, std::ptr::null(), cols, rows,
        outcome, fingerprint, hop, err,
    )
}

/// Connect `connection_id` over SSH and open a shell in a terminal of `cols` x `rows`.
///
/// Returns a terminal handle (free with `bastion_terminal_free`) and writes [`CONNECT_OK`] to
/// `outcome`, or returns NULL and writes one of the other `CONNECT_*` values. `outcome` is the
/// value to branch on; `*err` carries the message for the failing outcomes.
///
/// - `username` overrides the connection's own user name; empty or NULL uses the saved one.
/// - `login_kind` is one of the `LOGIN_*` values; `key_path` is required for [`LOGIN_KEY_FILE`]
///   and `password` is then the key's passphrase (NULL or empty for an unencrypted key).
/// - `code` is the one-time code for [`LOGIN_PASSWORD_AND_CODE`], NULL otherwise.
/// - `trust_fingerprint` must be NULL on a first attempt. On [`CONNECT_HOST_KEY_UNKNOWN`] with
///   no `hop`, retry with the `fingerprint` the call returned, but only after the user verified it.
///   A host certificate signed by a `@cert-authority` in known_hosts is accepted without a prompt.
/// - `jump_trust_json` is NULL or a JSON object mapping a jump host's `host:port` to a verified
///   fingerprint, for a [`CONNECT_HOST_KEY_UNKNOWN`] that named a `hop`.
/// - `jump_logins_json` is NULL or a JSON object mapping a jump host's `host:port` to its own
///   login `{"kind":LOGIN_*,"secret":…,"key_path":…,"code":…}`; hops not named use a copy of the
///   target's login. The caller should zero this buffer after the call, as for `password`.
/// - `fingerprint` and `hop` are optional out-parameters. When non-NULL they are set to NULL
///   first, then to strings the caller frees with `bastion_string_free`.
///
/// # Safety
/// `m` and `lib` live; the string parameters NULL (where allowed above) or valid NUL-terminated
/// UTF-8; `outcome`, `fingerprint`, `hop` and `err` NULL or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_session_connect_ssh_mfa(
    m: *const BastionSessionManager,
    lib: *const BastionLibrary,
    connection_id: *const c_char,
    username: *const c_char,
    login_kind: i32,
    password: *const c_char,
    key_path: *const c_char,
    code: *const c_char,
    trust_fingerprint: *const c_char,
    jump_trust_json: *const c_char,
    jump_logins_json: *const c_char,
    cols: u16,
    rows: u16,
    outcome: *mut i32,
    fingerprint: *mut *mut c_char,
    hop: *mut *mut c_char,
    err: *mut *mut c_char,
) -> *mut BastionTerminal {
    let out = |c: i32| {
        if !outcome.is_null() {
            *outcome = c;
        }
    };
    out(CONNECT_FAILED);
    for p in [fingerprint, hop] {
        if !p.is_null() {
            *p = std::ptr::null_mut();
        }
    }
    guarded(err, std::ptr::null_mut(), || {
        if cols == 0 || rows == 0 || cols > 1000 || rows > 1000 {
            return Err(format!("terminal size {cols}x{rows} out of range"));
        }
        let id = required(connection_id, "connection_id")?;
        let user = optional(username, "username")?.unwrap_or_default();
        // The secrets are read once here and moved into the core's one-shot provider.
        let login = login_from(login_kind, optional(password, "password")?, optional(key_path, "key_path")?, optional(code, "code")?)?;
        let jump_logins = jump_logins_from(optional(jump_logins_json, "jump_logins_json")?)?;
        let trust = optional(trust_fingerprint, "trust_fingerprint")?;
        let jump_trust = jump_trust_from(optional(jump_trust_json, "jump_trust_json")?)?;

        match manager(m)?.connect_ssh(library(lib)?, id, user, login, trust, jump_trust, jump_logins, cols, rows) {
            Ok(t) => {
                out(CONNECT_OK);
                Ok(Box::into_raw(Box::new(BastionTerminal::new(t))))
            }
            Err(e) => Err(connect_failure(e, outcome, fingerprint, hop)),
        }
    })
}

/// Map a failed SSH dial to its `CONNECT_*` outcome, filling `fingerprint` / `hop` where the
/// outcome carries one, and return the message for `*err`. Shared by every C entry point that
/// dials SSH (shells, tunnels) so they branch identically.
///
/// # Safety
/// `outcome`, `fingerprint` and `hop` NULL or writable.
pub(crate) unsafe fn connect_failure(e: FfiError, outcome: *mut i32, fingerprint: *mut *mut c_char, hop: *mut *mut c_char) -> String {
    let out = |c: i32| {
        if !outcome.is_null() {
            *outcome = c;
        }
    };
    let result: Result<(), String> = match e {
            // Deliberately not an error string: the host must branch on the outcome and show the
            // fingerprint for verification, never offer "connect anyway".
            FfiError::HostKeyUnknown { fingerprint: fp } => {
                out(CONNECT_HOST_KEY_UNKNOWN);
                if !fingerprint.is_null() {
                    *fingerprint = to_c(fp.clone());
                }
                Err(format!("the server's host key is not trusted yet ({fp})"))
            }
            FfiError::JumpHostKeyUnknown { hop: h, fingerprint: fp } => {
                out(CONNECT_HOST_KEY_UNKNOWN);
                if !fingerprint.is_null() {
                    *fingerprint = to_c(fp.clone());
                }
                if !hop.is_null() {
                    *hop = to_c(h.clone());
                }
                Err(format!("the key of jump host {h} is not trusted yet ({fp})"))
            }
            FfiError::AuthFailed => {
                out(CONNECT_AUTH_FAILED);
                Err("authentication failed".into())
            }
            FfiError::TwoFactorRequired => {
                out(CONNECT_TWO_FACTOR_REQUIRED);
                Err("the server asks for a one-time code".into())
            }
            FfiError::NeedsConfiguration { missing } => {
                out(CONNECT_NEEDS_CONFIGURATION);
                Err(format!("this host needs values for {}", missing.iter().map(|m| format!("<{m}>")).collect::<Vec<_>>().join(", ")))
            }
            FfiError::NoCommonAlgorithm { message, kind, server_offers, weak_allowable } => {
                out(CONNECT_NO_COMMON_ALGORITHM);
                if !fingerprint.is_null() {
                    *fingerprint = to_c(json!({ "kind": kind, "serverOffers": server_offers, "weakAllowable": weak_allowable }).to_string());
                }
                Err(message)
            }
            e => {
                out(CONNECT_FAILED);
                Err(e.to_string())
            }
    };
    result.err().unwrap_or_default()
}
