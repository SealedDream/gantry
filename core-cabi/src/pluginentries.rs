//! PLUG-08-WIN (ABI 139): plugin entries for Native Windows, over `bastion_ffi::pluginentries`
//! (the Mac's path): the installed plugins' connection types, adding an entry of one, its
//! core-owned TLS settings, a certificate probe, and opening the owning plugin's view on the
//! entry. The login is read from the vault inside the core and never crosses into the app.
use std::os::raw::c_char;
use std::ptr::null_mut;

use bastion_ffi::{plugin_certificate_check, plugin_certificate_probe, plugin_connection_types, plugin_entry_sidebar_open, plugin_entry_test, plugin_entry_view_open_via, PluginRoute};
use serde_json::json;

use crate::credentials::BastionCredentials;
use crate::pluginview::BastionPluginView;
use crate::{coded, guarded, handle, library, optional, required, set_ok, to_c, BastionLibrary};

/// The installed plugins' connection types as JSON:
/// `[{id, pluginId, pluginName, tier, name, defaultPort}]`. Free the string.
///
/// # Safety
/// `data_dir` NUL-terminated UTF-8; `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_connection_types_json(data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let types = plugin_connection_types(required(data_dir, "data_dir")?).map_err(coded)?;
        let v: Vec<_> = types
            .into_iter()
            .map(|t| json!({ "id": t.id, "pluginId": t.plugin_id, "pluginName": t.plugin_name, "tier": t.tier, "name": t.name, "defaultPort": t.default_port, "sidebarTree": t.sidebar_tree }))
            .collect();
        Ok(to_c(serde_json::Value::Array(v).to_string()))
    })
}

/// Adds an entry of plugin type `type_id` (`<plugin id>/<type id>`) under `parent` (null = root).
/// Returns the new id (free it), or null and sets `err`.
///
/// # Safety
/// `lib` live; strings NUL-terminated UTF-8 (`parent` may be null); `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_add_plugin_connection(lib: *const BastionLibrary, data_dir: *const c_char, parent: *const c_char, name: *const c_char, host: *const c_char, type_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let id = handle(lib)?
            .add_plugin_connection(required(data_dir, "data_dir")?, optional(parent, "parent")?, required(name, "name")?, required(host, "host")?, required(type_id, "type_id")?)
            .map_err(coded)?;
        Ok(to_c(id))
    })
}

/// The plugin entry's TLS settings: `{mode: "verify-full"|"pinned", pinSha256, damaged}` (`damaged`: a saved
/// pin could not be read, so system trust applies). Free the string.
///
/// # Safety
/// `lib` live; `id` NUL-terminated UTF-8; `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_plugin_entry_tls_json(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let t = handle(lib)?.plugin_entry_tls(required(id, "id")?).map_err(coded)?;
        Ok(to_c(json!({ "mode": t.mode, "pinSha256": t.pin_sha256, "damaged": t.damaged }).to_string()))
    })
}

/// Sets the plugin entry's TLS mode: `verify-full`, or `pinned` with `pin_sha256` (64 hex).
/// Returns 0, or -1 and sets `err`.
///
/// # Safety
/// `lib` live; strings NUL-terminated UTF-8 (`pin_sha256` may be null); `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_set_plugin_entry_tls(lib: *const BastionLibrary, id: *const c_char, mode: *const c_char, pin_sha256: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.set_plugin_entry_tls(required(id, "id")?, required(mode, "mode")?, optional(pin_sha256, "pin_sha256")?).map_err(coded)?;
        set_ok()
    })
}

/// The SHA-256 pin (lowercase hex) of the certificate `host:port` presents. TLS handshake only;
/// nothing is sent. Call off the UI thread (up to 10 s). Free the string.
///
/// # Safety
/// `host` NUL-terminated UTF-8; `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_certificate_probe(host: *const c_char, port: u16, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(plugin_certificate_probe(required(host, "host")?, port).map_err(coded)?)))
}

/// PVE-TLS (ABI 142): Test Connection for a plugin entry. A full TLS handshake under the entry's
/// rule (`pin_sha256` set: exactly that certificate; null: system trust and the host name).
/// Nothing is sent after the handshake. Call off the UI thread (up to 10 s). 0 = passed; -1 and
/// `err` set (the core's reason) otherwise.
///
/// # Safety
/// `host` NUL-terminated UTF-8; `pin_sha256` null or NUL-terminated UTF-8; `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_certificate_check(host: *const c_char, port: u16, pin_sha256: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        plugin_certificate_check(required(host, "host")?, port, optional(pin_sha256, "pin_sha256")?).map_err(coded)?;
        set_ok()
    })
}

/// The id of the gateway a plugin entry goes through (own or a folder's), or null when it goes direct.
/// The app starts a forward through it first and opens with [`bastion_plugin_entry_view_open`] route 1.
/// On a failure returns null and sets `err`: check `err`.
///
/// # Safety
/// `lib` live; `id` NUL-terminated UTF-8; `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_plugin_entry_gateway(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(handle(lib)?.plugin_entry_gateway(required(id, "id")?).map_err(coded)?.map(to_c).unwrap_or(null_mut())))
}

fn route(kind: i32, port: u16, target: Option<String>) -> Result<PluginRoute, String> {
    match kind {
        0 => Ok(PluginRoute::Direct),
        1 => Ok(PluginRoute::Forward { port, target: target.ok_or("route: target is required for a forward")? }),
        2 => Ok(PluginRoute::Socks { port }),
        _ => Err("route: kind must be 0 (direct), 1 (forward) or 2 (socks)".into()),
    }
}

/// Opens the view of the plugin that owns entry `connection_id`'s type, on that entry. With `vault`
/// open (non-null), the core reads the entry's login and keeps it; it never reaches the app.
/// `route_kind`: 0 direct, 1 a loopback forward on `port` whose SSH server reaches `target`, 2 a
/// loopback SOCKS proxy on `port`. An entry with a gateway is never sent direct, whatever is asked.
/// Call off the UI thread. Returns a view handle (free with `bastion_plugin_view_free`), or null and
/// sets `err`.
///
/// # Safety
/// `lib` live; `vault` null or live; strings NUL-terminated UTF-8 (`target` may be null); `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_entry_view_open(lib: *const BastionLibrary, vault: *const BastionCredentials, connection_id: *const c_char, data_dir: *const c_char, allow_unverified: i32, safe_mode: i32, route_kind: i32, port: u16, target: *const c_char, err: *mut *mut c_char) -> *mut BastionPluginView {
    guarded(err, null_mut(), || {
        let lib = library(lib)?;
        let vault = vault.as_ref().map(|v| v.0.clone());
        let via = route(route_kind, port, optional(target, "target")?)?;
        let v = plugin_entry_view_open_via(lib, vault, required(connection_id, "connection_id")?, required(data_dir, "data_dir")?, allow_unverified != 0, safe_mode != 0, via).map_err(coded)?;
        Ok(Box::into_raw(Box::new(BastionPluginView(v))))
    })
}

/// PVE-AUTH (ABI 144): Test Connection's login step for a plugin entry. Opens the plugin's view on
/// the entry as [`bastion_plugin_entry_view_open`] does (same login, TLS and route), waits until it
/// has loaded, and closes it: `{ok, message}`, `message` the plugin's error or warning banner (empty
/// when it loaded cleanly). Blocks up to 45 s: call off the UI thread. Free the string; null and
/// `err` set when the view could not be opened.
///
/// # Safety
/// As [`bastion_plugin_entry_view_open`].
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_entry_test_json(lib: *const BastionLibrary, vault: *const BastionCredentials, connection_id: *const c_char, data_dir: *const c_char, allow_unverified: i32, route_kind: i32, port: u16, target: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let lib = library(lib)?;
        let vault = vault.as_ref().map(|v| v.0.clone());
        let via = route(route_kind, port, optional(target, "target")?)?;
        let t = plugin_entry_test(lib, vault, required(connection_id, "connection_id")?, required(data_dir, "data_dir")?, allow_unverified != 0, via).map_err(coded)?;
        Ok(to_c(json!({ "ok": t.ok, "message": t.message }).to_string()))
    })
}

/// Entry `id`'s fields of its installed plugin type: `{heading, typeId, fields: [{key, label, kind, value}]}`
/// (`kind` as the property editor's kinds: `text`, `toggle`, …; `value` null when unset). Free the string. ABI 141.
/// On a failure returns null and sets `err`.
///
/// # Safety
/// `lib` live; strings NUL-terminated UTF-8; `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_plugin_entry_fields_json(lib: *const BastionLibrary, data_dir: *const c_char, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(handle(lib)?.plugin_entry_fields_json(required(data_dir, "data_dir")?, required(id, "id")?).map_err(coded)?)))
}

/// Sets (or clears, with `value` null or empty) plugin field `key` of entry `id`, checked against its installed
/// type (a toggle takes `true` or `false`). Save the library afterwards. ABI 141. Returns 0, or -1 and sets `err`.
///
/// # Safety
/// `lib` live; strings NUL-terminated UTF-8 (`value` may be null); `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_set_plugin_field(lib: *const BastionLibrary, data_dir: *const c_char, id: *const c_char, key: *const c_char, value: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.set_plugin_field(required(data_dir, "data_dir")?, required(id, "id")?, required(key, "key")?, optional(value, "value")?).map_err(coded)?;
        set_ok()
    })
}

/// As [`bastion_plugin_entry_view_open`], for the entry's tree in the library sidebar (plugin API
/// 1.3): refused unless the entry's connection type declares `sidebar = "tree"`. ABI 141.
///
/// # Safety
/// As [`bastion_plugin_entry_view_open`].
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_entry_sidebar_open(lib: *const BastionLibrary, vault: *const BastionCredentials, connection_id: *const c_char, data_dir: *const c_char, allow_unverified: i32, safe_mode: i32, route_kind: i32, port: u16, target: *const c_char, err: *mut *mut c_char) -> *mut BastionPluginView {
    guarded(err, null_mut(), || {
        let lib = library(lib)?;
        let vault = vault.as_ref().map(|v| v.0.clone());
        let via = route(route_kind, port, optional(target, "target")?)?;
        let v = plugin_entry_sidebar_open(lib, vault, required(connection_id, "connection_id")?, required(data_dir, "data_dir")?, allow_unverified != 0, safe_mode != 0, via).map_err(coded)?;
        Ok(Box::into_raw(Box::new(BastionPluginView(v))))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn no_types_without_plugins() {
        let dir = tempfile::tempdir().unwrap();
        let d = CString::new(dir.path().to_string_lossy().as_bytes()).unwrap();
        let mut e = null_mut();
        let s = unsafe { bastion_plugin_connection_types_json(d.as_ptr(), &mut e) };
        assert!(e.is_null());
        assert_eq!(unsafe { CStr::from_ptr(s) }.to_str().unwrap(), "[]");
        unsafe { crate::bastion_string_free(s) };
    }

    #[test]
    fn entry_open_refuses_a_null_library() {
        let c = CString::new("x").unwrap();
        let mut e = null_mut();
        let v = unsafe { bastion_plugin_entry_view_open(std::ptr::null(), std::ptr::null(), c.as_ptr(), c.as_ptr(), 0, 0, 0, 0, std::ptr::null(), &mut e) };
        assert!(v.is_null() && !e.is_null());
        unsafe { crate::bastion_string_free(e) };
    }

    /// ABI 141: plugin fields read and set over the C surface (the Windows property editor).
    #[test]
    fn plugin_fields_read_and_set() {
        let dir = tempfile::tempdir().unwrap();
        let c = |s: &str| CString::new(s).unwrap();
        let take = |p: *mut c_char| -> Option<String> {
            if p.is_null() { return None }
            let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
            unsafe { crate::bastion_string_free(p) };
            Some(s)
        };
        let data = c(&dir.path().join("data").display().to_string());
        let pkg = c(concat!(env!("CARGO_MANIFEST_DIR"), "/../apps/macos/uitests/fixtures/vmware.bastionplugin"));
        let mut err: *mut c_char = std::ptr::null_mut();
        unsafe {
            assert!(take(crate::plugins::bastion_plugin_install_file(data.as_ptr(), pkg.as_ptr(), 1, &mut err)).is_some());
            let types = take(bastion_plugin_connection_types_json(data.as_ptr(), &mut err)).unwrap();
            assert!(types.contains("\"sidebarTree\":true"), "{types}");
            let lib = crate::bastion_library_open(c(&dir.path().join("library.json").display().to_string()).as_ptr(), &mut err);
            assert!(!lib.is_null());
            let id = take(bastion_library_add_plugin_connection(lib, data.as_ptr(), std::ptr::null(), c("vc").as_ptr(), c("vc.lab").as_ptr(), c("com.example.vmware/vcenter").as_ptr(), &mut err)).unwrap();
            let id = c(&id);
            let key = c("allow-changes");
            let fields = take(bastion_library_plugin_entry_fields_json(lib, data.as_ptr(), id.as_ptr(), &mut err)).unwrap();
            assert!(fields.contains("\"kind\":\"toggle\"") && fields.contains("\"value\":null"), "{fields}");
            assert_eq!(bastion_library_set_plugin_field(lib, data.as_ptr(), id.as_ptr(), key.as_ptr(), c("true").as_ptr(), &mut err), 0);
            assert!(take(bastion_library_plugin_entry_fields_json(lib, data.as_ptr(), id.as_ptr(), &mut err)).unwrap().contains("\"value\":\"true\""));
            assert_eq!(bastion_library_set_plugin_field(lib, data.as_ptr(), id.as_ptr(), key.as_ptr(), c("maybe").as_ptr(), &mut err), -1);
            assert!(take(err).is_some(), "a refused value sets err");
            let mut err2: *mut c_char = std::ptr::null_mut();
            assert_eq!(bastion_library_set_plugin_field(lib, data.as_ptr(), id.as_ptr(), key.as_ptr(), std::ptr::null(), &mut err2), 0, "null clears");
            assert!(take(bastion_library_plugin_entry_fields_json(std::ptr::null(), data.as_ptr(), id.as_ptr(), &mut err2)).is_none(), "null library");
            take(err2);
            crate::bastion_library_free(lib);
        }
    }

    #[test]
    fn route_kinds_map() {
        assert!(matches!(route(0, 0, None), Ok(PluginRoute::Direct)));
        assert!(matches!(route(1, 5000, Some("db".into())), Ok(PluginRoute::Forward { port: 5000, .. })));
        assert!(route(1, 5000, None).is_err());
        assert!(matches!(route(2, 1080, None), Ok(PluginRoute::Socks { port: 1080 })));
        assert!(route(3, 0, None).is_err());
    }
}
