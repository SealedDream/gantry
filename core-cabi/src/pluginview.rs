//! PLUG-VIEW-CABI: plugin view sessions for Native Windows, over `bastion_ffi::pluginview`
//! (the Mac's `PluginViewWindow.swift` path). Set the helper path once at app start, open a view
//! off the UI thread (a cold open compiles the plugin, at most 30 s), poll `next_update`, send
//! events, close, and free the handle. Updates and events are JSON, as in core-ffi.
use std::os::raw::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::{plugin_host_set_helper_path, plugin_view_open, PluginField, PluginView, PluginViewEntry};
use serde_json::Value;

use crate::{coded, guarded, optional, required, set_ok, to_c};

/// An open plugin view. Free with [`bastion_plugin_view_free`] (which also closes it).
pub struct BastionPluginView(pub(crate) Arc<PluginView>);

fn entry_from_json(text: &str) -> Result<PluginViewEntry, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("entry: {e}"))?;
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let need = |k: &str| s(k).ok_or_else(|| format!("entry: {k} is required"));
    let port = match v.get("port") {
        None | Some(Value::Null) => 0,
        Some(p) => p.as_u64().and_then(|p| u16::try_from(p).ok()).ok_or("entry: port must be 0..65535")?,
    };
    let fields = match v.get("fields") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(m)) => m
            .iter()
            .map(|(k, val)| val.as_str().map(|x| PluginField { key: k.clone(), value: x.to_string() }).ok_or_else(|| format!("entry: field {k} must be a string")))
            .collect::<Result<_, _>>()?,
        Some(_) => return Err("entry: fields must be an object of strings".into()),
    };
    Ok(PluginViewEntry {
        document_id: need("documentId")?,
        entry_id: need("entryId")?,
        name: s("name").unwrap_or_default(),
        host: s("host").unwrap_or_default(),
        port,
        fields,
        protected: v.get("protected").and_then(Value::as_bool).unwrap_or(false),
        environment: s("environment").unwrap_or_default(),
    })
}

unsafe fn view<'a>(v: *const BastionPluginView) -> Result<&'a PluginView, String> {
    v.as_ref().map(|h| &*h.0).ok_or_else(|| "view handle is NULL".to_string())
}

/// Where the plugin helper is: `bastion-plugin-host.exe` beside `Bastion.exe`, else refused. Set once;
/// another path later is refused. Returns 0, or -1 and sets `err`.
///
/// # Safety
/// `path` is NUL-terminated UTF-8; `err` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_host_set_helper_path(path: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        plugin_host_set_helper_path(required(path, "path")?).map_err(coded)?;
        set_ok()
    })
}

/// Opens plugin `plugin_id`'s view `view_name` on an entry, or on none when `entry_json` is null or empty.
/// `entry_json`: `{documentId, entryId, name, host, port, fields: {key: value}, protected, environment}`.
/// Non-zero `allow_unverified` / `safe_mode` = on. Call off the UI thread. Returns a handle, or null and sets
/// `err` (code `policy`, `plugin` or `invalid`).
///
/// # Safety
/// Strings are NUL-terminated UTF-8 (`entry_json` may be null); `err` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_view_open(data_dir: *const c_char, plugin_id: *const c_char, view_name: *const c_char, entry_json: *const c_char, allow_unverified: i32, safe_mode: i32, err: *mut *mut c_char) -> *mut BastionPluginView {
    guarded(err, null_mut(), || {
        let data_dir = required(data_dir, "data_dir")?;
        let plugin_id = required(plugin_id, "plugin_id")?;
        let view_name = required(view_name, "view_name")?;
        let entry = optional(entry_json, "entry_json")?.map(|t| entry_from_json(&t)).transpose()?;
        let v = plugin_view_open(data_dir, plugin_id, view_name, entry, allow_unverified != 0, safe_mode != 0).map_err(coded)?;
        Ok(Box::into_raw(Box::new(BastionPluginView(v))))
    })
}

/// The next update as JSON (free it), waiting at most `timeout_ms` (capped at 10 s). Null when none came;
/// on a bad handle also null with `err` set: check `err`. The last update has type `ended`.
///
/// # Safety
/// `v` is null or a live handle; `err` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_view_next_update(v: *const BastionPluginView, timeout_ms: u32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(view(v)?.next_update(timeout_ms).map(to_c).unwrap_or(null_mut())))
}

/// Sends what the user did, as JSON. Returns 0, or -1 and sets `err` (unknown event, bad JSON).
///
/// # Safety
/// `v` is null or a live handle; `json` NUL-terminated UTF-8; `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_view_send_event(v: *const BastionPluginView, json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let view = view(v)?;
        view.send_event(required(json, "json")?).map_err(coded)?;
        set_ok()
    })
}

/// Stops the plugin: `run` gets 2 s, then its helper is killed. The handle stays valid until freed.
///
/// # Safety
/// `v` is null or a live handle.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_view_close(v: *const BastionPluginView) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if let Ok(view) = view(v) {
            view.close();
        }
    }));
}

/// Closes the view and frees the handle. Null is ignored.
///
/// # Safety
/// `v` is null or a handle from [`bastion_plugin_view_open`] not yet freed.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_view_free(v: *mut BastionPluginView) {
    if v.is_null() {
        return;
    }
    let h = Box::from_raw(v);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h.0.close()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    unsafe fn take(e: *mut c_char) -> String {
        let s = CStr::from_ptr(e).to_string_lossy().into_owned();
        crate::bastion_string_free(e);
        s
    }

    #[test]
    fn entry_json_maps_every_field() {
        let e = entry_from_json(r#"{"documentId":"d","entryId":"e","name":"n","host":"h","port":5432,"fields":{"db":"x"},"protected":true,"environment":"prod"}"#).unwrap();
        assert_eq!((e.document_id.as_str(), e.entry_id.as_str(), e.port, e.protected), ("d", "e", 5432, true));
        assert_eq!((e.fields[0].key.as_str(), e.fields[0].value.as_str()), ("db", "x"));
        assert!(entry_from_json(r#"{"documentId":"d","entryId":"e","port":70000}"#).is_err());
        assert!(entry_from_json(r#"{"entryId":"e"}"#).is_err());
        assert!(entry_from_json(r#"{"documentId":"d","entryId":"e","fields":{"a":1}}"#).is_err());
    }

    #[test]
    fn a_helper_outside_the_app_is_refused() {
        let mut err = null_mut();
        let p = CString::new("/nonexistent/bastion-plugin-host").unwrap();
        assert_eq!(unsafe { bastion_plugin_host_set_helper_path(p.as_ptr(), &mut err) }, -1);
        assert!(!err.is_null());
        unsafe { take(err) };
    }

    #[test]
    fn open_without_helper_fails_and_null_handles_are_safe() {
        let dir = tempfile::tempdir().unwrap();
        let d = CString::new(dir.path().to_string_lossy().as_bytes()).unwrap();
        let id = CString::new("com.example.pg").unwrap();
        let name = CString::new("settings").unwrap();
        let mut err = null_mut();
        let v = unsafe { bastion_plugin_view_open(d.as_ptr(), id.as_ptr(), name.as_ptr(), std::ptr::null(), 0, 0, &mut err) };
        assert!(v.is_null() && !err.is_null());
        unsafe { take(err) };
        let bad = CString::new("{").unwrap();
        let v = unsafe { bastion_plugin_view_open(d.as_ptr(), id.as_ptr(), name.as_ptr(), bad.as_ptr(), 0, 0, &mut err) };
        assert!(v.is_null() && !err.is_null());
        unsafe { take(err) };
        assert!(unsafe { bastion_plugin_view_next_update(std::ptr::null(), 0, &mut err) }.is_null());
        assert!(!err.is_null());
        unsafe { take(err) };
        let ev = CString::new("{}").unwrap();
        assert_eq!(unsafe { bastion_plugin_view_send_event(std::ptr::null(), ev.as_ptr(), &mut err) }, -1);
        unsafe { take(err) };
        unsafe { bastion_plugin_view_close(std::ptr::null()) };
        unsafe { bastion_plugin_view_free(null_mut()) };
    }
}
