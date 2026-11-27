//! The administrator's managed policy (`%ProgramData%\Bastion\policy.json`), read-only for the host:
//! `bastion_ffi::policy_state` for Settings, and the protocol gate for connect paths the core does not
//! orchestrate (RDP, web). SSH, SFTP, FTPS and VNC already check it inside the core. A managed file
//! that is unreadable, wrongly owned or invalid fails closed: every check returns its reason.
use std::os::raw::c_char;

use bastion_ffi::{policy_check_protocol, policy_state, remembered_login_usable, session_login_reuse_minutes};
use serde_json::json;

use crate::{guarded, required, set_ok, to_c};

/// The policy in force as JSON: `{managedPath, source, error, deniedProtocols, allowedLegacy, forbidLegacy,
/// allowCrossCustomerCredentials, bulkConfirmThreshold, inactivityLockSecs, allowSessionRecording, documentAutoLockMaxMinutes, passwordOnlyDocumentUnlock,
/// lockCredentialsOnOsLock, forbidOsc52Write, requireRdpNla, forbidWeakSshAlgorithms, sessionLoginReuseMinutes}` (`sessionLoginReuseMinutes`:
/// the managed maximum for reusing a remembered login, 0 = no limit; a field added by A1-CORE-02, no new export). `source` is null when no managed policy is
/// installed; `error` is set when one is installed but cannot be used. Free the result.
#[no_mangle]
pub extern "C" fn bastion_policy_state_json() -> *mut c_char {
    let p = policy_state();
    to_c(
        json!({
            "managedPath": p.managed_path,
            "source": p.source,
            "error": p.error,
            "deniedProtocols": p.denied_protocols,
            "allowedLegacy": p.allowed_legacy,
            "forbidLegacy": p.forbid_legacy,
            "allowCrossCustomerCredentials": p.allow_cross_customer_credentials,
            "bulkConfirmThreshold": p.bulk_confirm_threshold,
            "inactivityLockSecs": p.inactivity_lock_secs,
            "allowSessionRecording": p.allow_session_recording,
            "lockCredentialsOnOsLock": p.lock_credentials_on_os_lock,
            "forbidOsc52Write": p.forbid_osc52_write,
            "forbidWeakSshAlgorithms": p.forbid_weak_ssh_algorithms,
            "requireRdpNla": p.require_rdp_nla,
            "documentAutoLockMaxMinutes": p.document_auto_lock_max_minutes,
            "passwordOnlyDocumentUnlock": p.password_only_document_unlock,
            "sessionLoginReuseMinutes": p.session_login_reuse_minutes,
        })
        .to_string(),
    )
}

/// Minutes the app may reuse the login it remembers for a connection (0 = until Lock or quit): `user_minutes`
/// (the `security.session-login-reuse-minutes` setting) under the managed maximum; the smaller non-zero one
/// wins, and a managed policy that cannot be read gives 1. Pass the result to `bastion_remembered_login_usable`.
#[no_mangle]
pub extern "C" fn bastion_session_login_reuse_minutes(user_minutes: u32) -> u32 {
    session_login_reuse_minutes(user_minutes)
}

/// 1 when the app may still reuse a remembered login, 0 when it must forget it and resolve the connection's
/// logins again. `remembered_at`: time of the last successful sign-in with it; `now`: the current time (seconds,
/// same clock); `minutes` from `bastion_session_login_reuse_minutes`. Under a limit, a clock that went backwards
/// gives 0. Takes no secret and keeps nothing.
#[no_mangle]
pub extern "C" fn bastion_remembered_login_usable(remembered_at: u64, now: u64, minutes: u32) -> i32 {
    i32::from(remembered_login_usable(remembered_at, now, minutes))
}

/// 0 when the policy allows `protocol` (`rdp`, `web`, `vnc`, `ssh`, …); -1 with the reason in `*err` when it
/// refuses it, the managed policy is broken, or the protocol is unknown.
///
/// # Safety
/// `protocol` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_policy_check_protocol(protocol: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        policy_check_protocol(required(protocol, "protocol")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}
