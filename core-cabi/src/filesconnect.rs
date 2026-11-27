//! Files-only connections over the C ABI (ABI 87): an SFTP or SCP connection dialled over SSH, or
//! an FTPS sign-in, opened straight into the same [`BastionSftp`] browser a terminal's Files panel
//! uses. Outcomes follow `bastion_session_connect_ssh_mfa`: branch on `outcome`, show an unknown
//! host key or certificate for verification, retry with it only after the user confirmed it.
use std::ffi::c_char;

use crate::session::{connect_failure, jump_logins_from, jump_trust_from, login_from, manager, BastionSessionManager, CONNECT_FAILED, CONNECT_OK};
use crate::sftp::BastionSftp;
use crate::{guarded, library, optional, required, BastionLibrary};

/// # Safety
/// `outcome`, `fingerprint` and `hop` NULL or writable.
unsafe fn reset(outcome: *mut i32, fingerprint: *mut *mut c_char, hop: *mut *mut c_char) {
    if !outcome.is_null() {
        *outcome = CONNECT_FAILED;
    }
    for p in [fingerprint, hop] {
        if !p.is_null() {
            *p = std::ptr::null_mut();
        }
    }
}

/// Dial an `sftp` or `scp` connection (or an `ssh` one, browsed over SFTP) and open a files
/// browser; no shell is started. Parameters, outcomes and out-strings as for
/// `bastion_session_connect_ssh_mfa` without the terminal size. A server without the SFTP
/// subsystem fails for `sftp`; `scp` connections browse with `scp` and POSIX commands.
///
/// # Safety
/// As for `bastion_session_connect_ssh_mfa`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_session_connect_files(
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
    outcome: *mut i32,
    fingerprint: *mut *mut c_char,
    hop: *mut *mut c_char,
    err: *mut *mut c_char,
) -> *mut BastionSftp {
    reset(outcome, fingerprint, hop);
    guarded(err, std::ptr::null_mut(), || {
        let id = required(connection_id, "connection_id")?;
        let user = optional(username, "username")?.unwrap_or_default();
        let login = login_from(login_kind, optional(password, "password")?, optional(key_path, "key_path")?, optional(code, "code")?)?;
        let jump_logins = jump_logins_from(optional(jump_logins_json, "jump_logins_json")?)?;
        let trust = optional(trust_fingerprint, "trust_fingerprint")?;
        let jump_trust = jump_trust_from(optional(jump_trust_json, "jump_trust_json")?)?;
        match manager(m)?.connect_sftp(library(lib)?, id, user, login, trust, jump_trust, jump_logins) {
            Ok(b) => {
                if !outcome.is_null() {
                    *outcome = CONNECT_OK;
                }
                Ok(Box::into_raw(Box::new(BastionSftp(b))))
            }
            Err(e) => Err(connect_failure(e, outcome, fingerprint, hop)),
        }
    })
}

/// Sign in to an `ftps` connection (explicit TLS; plain FTP is refused by policy) and open a
/// files browser. An untrusted certificate gives `CONNECT_HOST_KEY_UNKNOWN` with its SHA-256
/// `fingerprint`; retry with `trusted_fingerprint` only after the user verified it. The password
/// is used for this sign-in only and never stored; the caller should zero its buffer after.
///
/// # Safety
/// `m`, `lib` live; strings NULL (`username`, `password`, `trusted_fingerprint`) or valid
/// NUL-terminated UTF-8; out-parameters NULL or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_session_connect_ftps(
    m: *const BastionSessionManager,
    lib: *const BastionLibrary,
    connection_id: *const c_char,
    username: *const c_char,
    password: *const c_char,
    trusted_fingerprint: *const c_char,
    outcome: *mut i32,
    fingerprint: *mut *mut c_char,
    err: *mut *mut c_char,
) -> *mut BastionSftp {
    reset(outcome, fingerprint, std::ptr::null_mut());
    guarded(err, std::ptr::null_mut(), || {
        let id = required(connection_id, "connection_id")?;
        let user = optional(username, "username")?.unwrap_or_default();
        let pw = optional(password, "password")?.unwrap_or_default();
        let trusted = optional(trusted_fingerprint, "trusted_fingerprint")?;
        match manager(m)?.connect_ftps(library(lib)?, id, user, pw, trusted) {
            Ok(b) => {
                if !outcome.is_null() {
                    *outcome = CONNECT_OK;
                }
                Ok(Box::into_raw(Box::new(BastionSftp(b))))
            }
            Err(e) => Err(connect_failure(e, outcome, fingerprint, std::ptr::null_mut())),
        }
    })
}
