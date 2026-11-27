//! Web tabs through a saved tunnel over the C ABI (`bastion_ffi` webtunnel): the per-tunnel proxy
//! URL (WebView2 `--proxy-server`) or forward address, and the per-tunnel WebView2 user-data folder.
use std::ffi::c_char;
use std::ptr::null_mut;

use serde_json::json;

use crate::{guarded, library, optional, required, set_ok, to_c, BastionLibrary};

/// Set the tunnel (`tunnel_id` NULL clears it) a web connection's tab goes through. Returns 0, or
/// -1 with `*err` set (not a web connection, unknown or remote tunnel). Save the library after.
///
/// # Safety
/// `lib` live; strings valid NUL-terminated (`tunnel_id` may be NULL); `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_set_web_tunnel(lib: *const BastionLibrary, connection_id: *const c_char, tunnel_id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        library(lib)?.set_web_tunnel(required(connection_id, "connection_id")?, optional(tunnel_id, "tunnel_id")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// How to open a web connection. JSON `null` = direct; else `{tunnelId, tunnelName, viaId,
/// proxyUrl, forwardAddress, dataDir}` with exactly one of `proxyUrl` / `forwardAddress` set.
/// `dataDir` is created owner-only: use it as the WebView2 user-data folder. A deleted tunnel is
/// an error, never a direct connection.
///
/// # Safety
/// `lib` live; strings valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_web_tunnel_plan_json(lib: *const BastionLibrary, connection_id: *const c_char, data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let p = library(lib)?.web_tunnel_plan(required(connection_id, "connection_id")?, required(data_dir, "data_dir")?).map_err(|e| e.to_string())?;
        let v = p.map(|p| json!({ "tunnelId": p.tunnel_id, "tunnelName": p.tunnel_name, "viaId": p.via_id, "proxyUrl": p.proxy_url, "forwardAddress": p.forward_address, "dataDir": p.data_dir }));
        Ok(to_c(v.unwrap_or(serde_json::Value::Null).to_string()))
    })
}

/// "Copy proxy settings": `{url, pac, host, port}` for a SOCKS tunnel, JSON `null` otherwise.
///
/// # Safety
/// `lib` live; `tunnel_id` valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_tunnel_proxy_settings_json(lib: *const BastionLibrary, tunnel_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let s = library(lib)?.tunnel_proxy_settings(required(tunnel_id, "tunnel_id")?).map_err(|e| e.to_string())?;
        let v = s.map(|s| json!({ "url": s.url, "pac": s.pac, "host": s.host, "port": s.port }));
        Ok(to_c(v.unwrap_or(serde_json::Value::Null).to_string()))
    })
}

/// Delete one tunnel's web data. Returns 0, or -1 with `*err` set.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_web_tunnel_clear_data(data_dir: *const c_char, tunnel_id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        bastion_ffi::clear_web_tunnel_data(required(data_dir, "data_dir")?, required(tunnel_id, "tunnel_id")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Remove data folders of deleted tunnels. Returns how many, or -1 with `*err` set.
///
/// # Safety
/// `lib` live; `data_dir` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_prune_web_tunnel_data(lib: *const BastionLibrary, data_dir: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let n = library(lib)?.prune_web_tunnel_data(required(data_dir, "data_dir")?).map_err(|e| e.to_string())?;
        Ok(i32::try_from(n).unwrap_or(i32::MAX))
    })
}

/// `port` when `127.0.0.1:port` is free, else the next free port shortly above it; -1 if none.
#[no_mangle]
pub extern "C" fn bastion_local_port_next_free(port: u16) -> i32 {
    bastion_ffi::next_free_local_port(port).map_or(-1, i32::from)
}

/// External-browser fallback: JSON array of arguments for `family` (`chromium` / `firefox`) in a
/// separate profile at `profile_dir`. Start the browser with them as an argument list, never via
/// a shell; for Firefox write `bastion_firefox_user_js` to `<profile_dir>\user.js` first.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_tunnel_browser_args_json(family: *const c_char, port: u16, profile_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let a = bastion_ffi::tunnel_browser_args(required(family, "family")?, port, required(profile_dir, "profile_dir")?).map_err(|e| e.to_string())?;
        Ok(to_c(serde_json::to_string(&a).map_err(|e| e.to_string())?))
    })
}

/// `user.js` text for a Firefox fallback profile. Free with `bastion_string_free`.
#[no_mangle]
pub extern "C" fn bastion_firefox_user_js(port: u16) -> *mut c_char {
    to_c(bastion_ffi::firefox_user_js(port))
}

fn tunnel_json(t: &bastion_ffi::TunnelDefView) -> serde_json::Value {
    json!({ "id": t.id, "name": t.name, "viaId": t.via_id, "viaName": t.via_name, "kind": t.kind,
            "localPort": t.local_port, "host": t.host, "port": t.port, "summary": t.summary, "startWithConnection": t.start_with_connection })
}

/// Saved tunnel definitions: JSON array of `{id, name, viaId, viaName, kind, localPort, host,
/// port, summary, startWithConnection}`; `kind` is `local`, `remote` or `dynamic`.
///
/// # Safety
/// `lib` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_tunnels_json(lib: *const BastionLibrary, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let v: Vec<_> = library(lib)?.tunnels().map_err(|e| e.to_string())?.iter().map(tunnel_json).collect();
        Ok(to_c(serde_json::Value::Array(v).to_string()))
    })
}

/// Add (`id` empty or missing) or replace a tunnel from JSON `{id?, name, viaId, kind, localPort,
/// host?, port?, startWithConnection?}`; binds 127.0.0.1 only. Returns the id. Save the library after.
///
/// # Safety
/// `lib` live; `tunnel_json` valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_put_tunnel_json(lib: *const BastionLibrary, tunnel_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let v: serde_json::Value = serde_json::from_str(&required(tunnel_json, "tunnel_json")?).map_err(|_| "tunnel_json must be a JSON object".to_string())?;
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
        let port = |k: &str| v.get(k).and_then(|x| x.as_u64()).map_or(Ok(0), |p| u16::try_from(p).map_err(|_| format!("{k} must be 1 to 65535")));
        let def = bastion_ffi::TunnelDefView {
            id: s("id"),
            name: s("name"),
            via_id: s("viaId"),
            via_name: String::new(),
            kind: s("kind"),
            local_port: port("localPort")?,
            host: s("host"),
            port: port("port")?,
            summary: String::new(),
            start_with_connection: v.get("startWithConnection").and_then(|x| x.as_bool()).unwrap_or(false),
        };
        Ok(to_c(library(lib)?.put_tunnel(def).map_err(|e| e.to_string())?))
    })
}

/// Remove a tunnel. Returns 0, or -1 with `*err` set.
///
/// # Safety
/// `lib` live; `tunnel_id` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_remove_tunnel(lib: *const BastionLibrary, tunnel_id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        library(lib)?.remove_tunnel(required(tunnel_id, "tunnel_id")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}
