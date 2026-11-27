//! Gateway Manager over the C ABI (ABI v22): shared SSH gateways in the library, and a connection's
//! route through its gateway (RDP and VNC over a loopback port forward, web over a loopback SOCKS
//! proxy). Gateway definitions hold no secrets; the gateway's login crosses the ABI the same way as
//! an SSH connect's (a caller-owned buffer the host zeroes), and its host key is checked strictly.
//! SSH and SFTP connections need nothing here: `bastion_session_connect_ssh_mfa` already uses the
//! gateway as their first jump host.
use std::ffi::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::{FfiError, GatewayInputView, GatewayRoute};
use serde_json::{json, Value};

use crate::session::{login_from, manager, BastionSessionManager, CONNECT_AUTH_FAILED, CONNECT_FAILED, CONNECT_HOST_KEY_UNKNOWN, CONNECT_OK, CONNECT_TWO_FACTOR_REQUIRED};
use crate::{guarded, handle, library, optional, required, set_ok, to_c, BastionLibrary};

/// What the host sends for a new or edited gateway: `{name, host, port, username, notes}`.
#[derive(serde::Deserialize)]
struct GatewayJson {
    name: String,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    notes: String,
}

fn parse_input(json: &str) -> Result<GatewayInputView, String> {
    let g: GatewayJson = serde_json::from_str(json).map_err(|_| "gateway must be a JSON object {name, host, port, username, notes}".to_string())?;
    Ok(GatewayInputView { name: g.name, host: g.host, port: g.port, username: g.username, notes: g.notes })
}

/// JSON array of `{id, name, host, port, username, notes, usedBy:[…]}`, by name.
///
/// # Safety
/// `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_gateways_json(lib: *const BastionLibrary, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let list: Vec<Value> = handle(lib)?
            .gateways()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|g| json!({ "id": g.id, "name": g.name, "host": g.host, "port": g.port, "username": g.username, "notes": g.notes, "usedBy": g.used_by }))
            .collect();
        Ok(to_c(Value::Array(list).to_string()))
    })
}

/// Add a gateway from `{name, host, port, username, notes}`; returns its id. Call `bastion_library_save` after.
///
/// # Safety
/// Strings valid NUL-terminated; `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_gateway_add(lib: *const BastionLibrary, gateway_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(handle(lib)?.add_gateway(parse_input(&required(gateway_json, "gateway")?)?).map_err(|e| e.to_string())?)))
}

/// Replace gateway `id`. Returns 0, or -1. Call `bastion_library_save` after.
///
/// # Safety
/// Strings valid NUL-terminated; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_gateway_update(lib: *const BastionLibrary, id: *const c_char, gateway_json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.update_gateway(required(id, "id")?, parse_input(&required(gateway_json, "gateway")?)?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Delete gateway `id`. Refused while anything uses it; `*err` names those places. Returns 0, or -1.
///
/// # Safety
/// Strings valid NUL-terminated; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_gateway_remove(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.remove_gateway(required(id, "id")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// The gateway an RDP, VNC or web connection goes through, as `{name, key, username}` (`key` is the
/// gateway's `host:port`), or `null` for a direct connection. A dangling reference or a protocol that
/// cannot use a gateway is an error (NULL and `*err`), never a direct connect.
///
/// # Safety
/// Strings valid NUL-terminated; `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_gateway_route_json(lib: *const BastionLibrary, connection_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let hop = handle(lib)?.gateway_route(required(connection_id, "connection_id")?).map_err(|e| e.to_string())?;
        let v = hop.map_or(Value::Null, |h| json!({ "name": h.name, "key": h.key, "username": h.username }));
        Ok(to_c(v.to_string()))
    })
}

/// An open route through a gateway: one SSH session to the gateway plus a loopback listener.
pub struct BastionGatewayRoute(Arc<GatewayRoute>);

unsafe fn route<'a>(r: *const BastionGatewayRoute) -> Result<&'a GatewayRoute, String> {
    r.as_ref().map(|r| &*r.0).ok_or_else(|| "route handle is NULL".to_string())
}

/// Sign in to the connection's gateway and open its route on a free loopback port. `username`,
/// `login_kind`, `password` and `key_path` are the gateway's login, as in
/// `bastion_session_connect_ssh_mfa` (an empty `username` uses the gateway's own). `*outcome` is a
/// `CONNECT_*` code: on `CONNECT_HOST_KEY_UNKNOWN` `*fingerprint` is set; retry with it in
/// `trust_fingerprint` only after the user verified it. Since ABI 104 `LOGIN_VAULT` is refused here
/// ("a gateway does not take a saved login: …", `CONNECT_FAILED`) before the gateway is looked up or
/// dialled: a gateway is not a library entry, so no login rule covers it. Free the route with
/// [`bastion_gateway_route_free`].
///
/// # Safety
/// `m` and `lib` live; strings NULL or valid NUL-terminated UTF-8 (`connection_id` required);
/// `outcome`, `fingerprint` and `err` NULL or writable. The host zeroes `password` after the call.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_gateway_route_open(
    m: *const BastionSessionManager,
    lib: *const BastionLibrary,
    connection_id: *const c_char,
    username: *const c_char,
    login_kind: i32,
    password: *const c_char,
    key_path: *const c_char,
    trust_fingerprint: *const c_char,
    outcome: *mut i32,
    fingerprint: *mut *mut c_char,
    err: *mut *mut c_char,
) -> *mut BastionGatewayRoute {
    let out = |c: i32| {
        if !outcome.is_null() {
            *outcome = c;
        }
    };
    out(CONNECT_FAILED);
    if !fingerprint.is_null() {
        *fingerprint = null_mut();
    }
    guarded(err, null_mut(), || {
        let id = required(connection_id, "connection_id")?;
        let user = optional(username, "username")?.unwrap_or_default();
        let login = login_from(login_kind, optional(password, "password")?, optional(key_path, "key_path")?, None)?;
        let trust = optional(trust_fingerprint, "trust_fingerprint")?;
        match manager(m)?.open_gateway_route(library(lib)?, id, user, login, trust) {
            Ok(r) => {
                out(CONNECT_OK);
                Ok(Box::into_raw(Box::new(BastionGatewayRoute(r))))
            }
            // The host must show the fingerprint for verification, never offer "connect anyway".
            Err(FfiError::HostKeyUnknown { fingerprint: fp }) => {
                out(CONNECT_HOST_KEY_UNKNOWN);
                if !fingerprint.is_null() {
                    *fingerprint = to_c(fp.clone());
                }
                Err(format!("the gateway's host key is not trusted yet ({fp})"))
            }
            Err(FfiError::AuthFailed) => {
                out(CONNECT_AUTH_FAILED);
                Err("the gateway refused the login".into())
            }
            Err(FfiError::TwoFactorRequired) => {
                out(CONNECT_TWO_FACTOR_REQUIRED);
                Err("the gateway asks for a one-time code, which gateway routes do not support yet".into())
            }
            Err(e) => Err(e.to_string()),
        }
    })
}

/// The loopback port to connect to (RDP, VNC) or to use as a SOCKS5 proxy (web); 0 for NULL.
///
/// # Safety
/// `r` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_gateway_route_port(r: *const BastionGatewayRoute) -> u16 {
    route(r).map(|r| r.local_port()).unwrap_or(0)
}

/// 1 for a SOCKS proxy (web), 0 for a port forward or NULL.
///
/// # Safety
/// `r` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_gateway_route_is_socks(r: *const BastionGatewayRoute) -> i32 {
    route(r).map(|r| r.is_socks() as i32).unwrap_or(0)
}

/// 1 while the listener runs, 0 once it stopped (or NULL).
///
/// # Safety
/// `r` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_gateway_route_is_running(r: *const BastionGatewayRoute) -> i32 {
    route(r).map(|r| r.is_running() as i32).unwrap_or(0)
}

/// e.g. `via Jump (10.0.0.1:22) → 10.0.0.5:3389`. Free the result.
///
/// # Safety
/// `r` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_gateway_route_summary(r: *const BastionGatewayRoute, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(route(r)?.summary())))
}

/// Close the listener and the gateway session, then free the handle. NULL is ignored.
///
/// # Safety
/// `r` NULL or a handle from [`bastion_gateway_route_open`] not yet freed.
#[no_mangle]
pub unsafe extern "C" fn bastion_gateway_route_free(r: *mut BastionGatewayRoute) {
    if !r.is_null() {
        let r = Box::from_raw(r);
        r.0.close();
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};

    use super::*;
    use crate::{bastion_library_free, bastion_library_open, bastion_string_free};

    unsafe fn take(p: *mut c_char) -> String {
        assert!(!p.is_null());
        let s = CStr::from_ptr(p).to_str().unwrap().to_string();
        bastion_string_free(p);
        s
    }

    #[test]
    fn gateways_round_trip_and_refuse_bad_input() {
        let dir = std::env::temp_dir().join(format!("bastion-cabi-gw-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = CString::new(dir.join("lib.json").to_string_lossy().into_owned()).unwrap();
        unsafe {
            let mut err = null_mut();
            let lib = bastion_library_open(path.as_ptr(), &mut err);
            assert!(!lib.is_null());
            let input = CString::new(r#"{"name":"Jump","host":"10.0.0.1","port":2222,"username":"ops","notes":""}"#).unwrap();
            let id = take(bastion_gateway_add(lib, input.as_ptr(), &mut err));
            let list: Value = serde_json::from_str(&take(bastion_gateways_json(lib, &mut err))).unwrap();
            assert_eq!(list[0]["name"], "Jump");
            assert_eq!(list[0]["port"], 2222);
            assert_eq!(list[0]["usedBy"], json!([]));

            let dup = bastion_gateway_add(lib, input.as_ptr(), &mut err);
            assert!(dup.is_null());
            assert!(take(err).contains("already exists"));
            let bad = CString::new(r#"{"name":"X","host":"-oProxyCommand=x"}"#).unwrap();
            assert!(bastion_gateway_add(lib, bad.as_ptr(), &mut err).is_null());
            bastion_string_free(err);

            let cid = CString::new(id).unwrap();
            let edit = CString::new(r#"{"name":"Edge","host":"10.0.0.2"}"#).unwrap();
            assert_eq!(bastion_gateway_update(lib, cid.as_ptr(), edit.as_ptr(), &mut err), 0);
            let list: Value = serde_json::from_str(&take(bastion_gateways_json(lib, &mut err))).unwrap();
            assert_eq!((list[0]["name"].as_str(), list[0]["port"].is_null()), (Some("Edge"), true));
            assert_eq!(bastion_gateway_remove(lib, cid.as_ptr(), &mut err), 0);
            assert_eq!(take(bastion_gateways_json(lib, &mut err)), "[]");
            bastion_library_free(lib);
        }
        std::fs::remove_dir_all(dir).ok();
    }

    /// Live (`BASTION_SSH_TEST=1`): a VNC connection to `bastion-vnc:5900`, which only bastion-jump
    /// (127.0.0.1:2223) can reach, opens its route after the gateway key is verified, and the loopback
    /// port answers with the RFB banner. A wrong gateway password is AuthFailed, never a direct connect.
    #[test]
    fn vnc_route_reaches_a_private_host_through_the_gateway() {
        use std::io::Read;
        use std::net::TcpStream;
        if std::env::var("BASTION_SSH_TEST").is_err() {
            return eprintln!("SKIPPED vnc_route_reaches_a_private_host_through_the_gateway: set BASTION_SSH_TEST=1");
        }
        let target = std::env::var("BASTION_GW_VNC_HOST").unwrap_or_else(|_| "bastion-vnc".into());
        let jump_port: u16 = std::env::var("BASTION_GW_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(2223);
        let dir = std::env::temp_dir().join(format!("bastion-cabi-gwl-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = |s: &str| CString::new(s).unwrap();
        unsafe {
            let mut err = null_mut();
            let lib = bastion_library_open(c(&dir.join("lib.json").to_string_lossy()).as_ptr(), &mut err);
            let gw = take(bastion_gateway_add(lib, c(&format!(r#"{{"name":"Jump","host":"127.0.0.1","port":{jump_port},"username":"tester"}}"#)).as_ptr(), &mut err));
            let vnc = take(crate::bastion_library_add_connection(lib, std::ptr::null(), c("desk").as_ptr(), c("vnc").as_ptr(), c(&target).as_ptr(), 5900, std::ptr::null(), &mut err));
            assert_eq!(crate::properties::bastion_library_set_property(lib, c(&vnc).as_ptr(), c("gateway_id").as_ptr(), c(&gw).as_ptr(), &mut err), 0);
            let hop: Value = serde_json::from_str(&take(bastion_gateway_route_json(lib, c(&vnc).as_ptr(), &mut err))).unwrap();
            assert_eq!(hop["key"], format!("127.0.0.1:{jump_port}"));

            let m = crate::session::bastion_session_manager_new(c(&dir.to_string_lossy()).as_ptr(), &mut err);
            let open = |pw: &str, trust: Option<&str>, outcome: &mut i32, fp: &mut *mut c_char, err: &mut *mut c_char| {
                let trust = trust.map(c);
                bastion_gateway_route_open(m, lib, c(&vnc).as_ptr(), std::ptr::null(), crate::session::LOGIN_PASSWORD, c(pw).as_ptr(), std::ptr::null(),
                    trust.as_ref().map_or(std::ptr::null(), |t| t.as_ptr()), outcome, fp, err)
            };
            let (mut outcome, mut fp) = (-1, null_mut());
            assert!(open("test-pass-123", None, &mut outcome, &mut fp, &mut err).is_null());
            assert_eq!(outcome, CONNECT_HOST_KEY_UNKNOWN, "{}", take(err));
            let fingerprint = take(fp);
            assert!(open("wrong", Some(&fingerprint), &mut outcome, &mut fp, &mut err).is_null());
            assert_eq!(outcome, CONNECT_AUTH_FAILED);
            bastion_string_free(err);
            let r = open("test-pass-123", Some(&fingerprint), &mut outcome, &mut fp, &mut err);
            assert!(!r.is_null(), "{}", take(err));
            assert_eq!((outcome, bastion_gateway_route_is_socks(r), bastion_gateway_route_is_running(r)), (CONNECT_OK, 0, 1));
            assert!(take(bastion_gateway_route_summary(r, &mut err)).contains(&format!("→ {target}:5900")));
            let mut s = TcpStream::connect(("127.0.0.1", bastion_gateway_route_port(r))).unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
            let mut banner = [0u8; 4];
            s.read_exact(&mut banner).unwrap();
            assert_eq!(&banner, b"RFB ");
            bastion_gateway_route_free(r);
            crate::session::bastion_session_manager_free(m);
            bastion_library_free(lib);
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn null_route_handles_are_harmless() {
        unsafe {
            assert_eq!(bastion_gateway_route_port(std::ptr::null()), 0);
            assert_eq!(bastion_gateway_route_is_socks(std::ptr::null()), 0);
            bastion_gateway_route_free(null_mut());
        }
    }
}
