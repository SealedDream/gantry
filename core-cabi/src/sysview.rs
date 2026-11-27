//! Read-only Services, Processes and Event Log over the C ABI (ABI 93, owner point 11), as the
//! Windows shell uses them. Forwards to `bastion_ffi::SystemView`, so the fixed read-only scripts,
//! the BusyBox and plain-systemctl fallbacks, the RDP "management via SSH" target and the audit
//! entries stay in the core. Opening dials SSH: an SSH connection itself, or for RDP the same host
//! over SSH (`rdp.ssh_management` on).
use std::ffi::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::{FfiError, SysEventFilter, SystemView};
use serde_json::{json, Value};

use crate::session::{login_from, BastionSessionManager, CONNECT_AUTH_FAILED, CONNECT_FAILED, CONNECT_HOST_KEY_UNKNOWN, CONNECT_OK};
use crate::{guarded, library, optional, required, to_c, BastionLibrary};

/// Opaque handle for one open view. Free with [`bastion_sysview_free`].
pub struct BastionSysView(Arc<SystemView>);

unsafe fn view<'a>(v: *const BastionSysView) -> Result<&'a SystemView, String> {
    v.as_ref().map(|v| &*v.0).ok_or_else(|| "system view handle is NULL".to_string())
}

/// Open `view` (`services`, `processes` or `eventlog`; NULL = the connection's own) on
/// `connection_id`. Writes `CONNECT_OK`, `CONNECT_HOST_KEY_UNKNOWN` (`fingerprint` set: retry with
/// it as `trust_fingerprint` once the user verified it), `CONNECT_AUTH_FAILED` or `CONNECT_FAILED`
/// to `outcome`. Login arguments as `bastion_task_run_start`.
///
/// # Safety
/// `m` and `lib` live; strings NULL (where allowed) or NUL-terminated UTF-8; `outcome`,
/// `fingerprint` and `err` NULL or writable. Free `fingerprint` with `bastion_string_free`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_sysview_open(
    m: *const BastionSessionManager,
    lib: *const BastionLibrary,
    connection_id: *const c_char,
    view_name: *const c_char,
    username: *const c_char,
    login_kind: i32,
    password: *const c_char,
    key_path: *const c_char,
    trust_fingerprint: *const c_char,
    outcome: *mut i32,
    fingerprint: *mut *mut c_char,
    err: *mut *mut c_char,
) -> *mut BastionSysView {
    let set = |c: i32| {
        if !outcome.is_null() {
            *outcome = c;
        }
    };
    set(CONNECT_FAILED);
    if !fingerprint.is_null() {
        *fingerprint = null_mut();
    }
    guarded(err, null_mut(), || {
        let manager = m.as_ref().map(|m| m.0.clone()).ok_or_else(|| "session manager handle is NULL".to_string())?;
        let login = login_from(login_kind, optional(password, "password")?, optional(key_path, "key_path")?, None)?;
        let user = optional(username, "username")?.unwrap_or_default();
        let opened = SystemView::open_view(
            manager,
            library(lib)?,
            required(connection_id, "connection_id")?,
            optional(view_name, "view")?,
            user,
            login,
            optional(trust_fingerprint, "trust_fingerprint")?,
        );
        match opened {
            Ok(v) => {
                set(CONNECT_OK);
                Ok(Box::into_raw(Box::new(BastionSysView(v))))
            }
            Err(FfiError::HostKeyUnknown { fingerprint: fp }) => {
                set(CONNECT_HOST_KEY_UNKNOWN);
                if !fingerprint.is_null() {
                    *fingerprint = to_c(fp.clone());
                }
                Err(format!("unknown host key {fp}"))
            }
            Err(FfiError::AuthFailed) => {
                set(CONNECT_AUTH_FAILED);
                Err("authentication failed".into())
            }
            Err(e) => Err(e.to_string()),
        }
    })
}

/// `{"os":"linux"|"windows","view":"services"|"processes"|"events"}`.
///
/// # Safety
/// `v` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_sysview_info_json(v: *const BastionSysView, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let v = view(v)?;
        Ok(to_c(json!({ "os": v.os(), "view": v.view() }).to_string()))
    })
}

/// Services: `[{name, description, state, sub, startType}]`.
///
/// # Safety
/// `v` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_sysview_services_json(v: *const BastionSysView, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let rows = view(v)?.services().map_err(|e| e.to_string())?;
        let out: Vec<Value> = rows.iter().map(|r| json!({ "name": r.name, "description": r.description, "state": r.state, "sub": r.sub, "startType": r.start_type })).collect();
        Ok(to_c(Value::Array(out).to_string()))
    })
}

/// Processes: `[{pid, user, cpuPercent, cpuSeconds, memBytes, name}]` (cpu fields may be null).
///
/// # Safety
/// `v` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_sysview_processes_json(v: *const BastionSysView, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let rows = view(v)?.processes().map_err(|e| e.to_string())?;
        let out: Vec<Value> = rows
            .iter()
            .map(|r| json!({ "pid": r.pid, "user": r.user, "cpuPercent": r.cpu_percent, "cpuSeconds": r.cpu_seconds, "memBytes": r.mem_bytes, "name": r.name }))
            .collect();
        Ok(to_c(Value::Array(out).to_string()))
    })
}

/// Events new since the previous call with the same filter: `[{cursor, time, level, source, message}]`.
/// `filter_json` NULL or `{unit, priority, log, level}` (all optional).
///
/// # Safety
/// `v` live; `filter_json` NULL or NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_sysview_tail_json(v: *const BastionSysView, filter_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let f: Value = match optional(filter_json, "filter_json")? {
            Some(j) => serde_json::from_str(&j).map_err(|_| "filter_json must be a JSON object".to_string())?,
            None => json!({}),
        };
        let text = |k: &str| f.get(k).and_then(Value::as_str).map(str::to_string);
        let num = |k: &str| f.get(k).and_then(Value::as_u64).and_then(|n| u8::try_from(n).ok());
        let filter = SysEventFilter { unit: text("unit"), priority: num("priority"), log: text("log"), level: num("level") };
        let rows = view(v)?.tail(filter).map_err(|e| e.to_string())?;
        let out: Vec<Value> = rows.iter().map(|r| json!({ "cursor": r.cursor, "time": r.time, "level": r.level, "source": r.source, "message": r.message })).collect();
        Ok(to_c(Value::Array(out).to_string()))
    })
}

/// Disconnect; the handle stays valid until [`bastion_sysview_free`].
///
/// # Safety
/// `v` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_sysview_close(v: *const BastionSysView) {
    if let Ok(v) = view(v) {
        v.close();
    }
}

/// Release a handle from [`bastion_sysview_open`].
///
/// # Safety
/// `v` NULL or a handle not yet freed.
#[no_mangle]
pub unsafe extern "C" fn bastion_sysview_free(v: *mut BastionSysView) {
    if !v.is_null() {
        drop(Box::from_raw(v));
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_handles_fail_cleanly() {
        unsafe {
            let mut err = null_mut();
            assert!(bastion_sysview_services_json(std::ptr::null(), &mut err).is_null());
            assert!(!err.is_null());
            crate::bastion_string_free(err);
            let mut outcome = 0;
            let mut fp = null_mut();
            let mut err = null_mut();
            let id = std::ffi::CString::new("x").unwrap();
            let v = bastion_sysview_open(std::ptr::null(), std::ptr::null(), id.as_ptr(), std::ptr::null(), std::ptr::null(), 0, std::ptr::null(), std::ptr::null(), std::ptr::null(), &mut outcome, &mut fp, &mut err);
            assert!(v.is_null());
            assert_eq!(outcome, CONNECT_FAILED);
            assert!(fp.is_null());
            crate::bastion_string_free(err);
            bastion_sysview_close(std::ptr::null());
            bastion_sysview_free(null_mut());
        }
    }
}
