//! PLUG-04b part 2 for Native Windows: installed plugins, install from a file, remove, refreshing the
//! catalogue and the update plan, over `bastion_ffi::plugins`. Strings are NUL-terminated UTF-8; results
//! are JSON or text the caller frees. On failure the result is null and `err` is set.
use std::os::raw::c_char;
use std::ptr::null_mut;

use bastion_ffi::{plugin_install_file, plugin_remove, plugins_installed, plugins_refresh, plugins_updates, InstalledPluginView, PluginUpdateView};
use serde_json::{json, Value};

use crate::{coded, guarded, optional, required, set_ok, to_c};

fn installed_json(v: InstalledPluginView) -> Value {
    let InstalledPluginView { id, version, tier, previous_version } = v;
    json!({ "id": id, "version": version, "tier": tier, "previousVersion": previous_version })
}

fn update_json(v: PluginUpdateView) -> Value {
    let PluginUpdateView { id, from, to, tier, needs_consent } = v;
    json!({ "id": id, "from": from, "to": to, "tier": tier, "needsConsent": needs_consent })
}

/// The installed plugins as a JSON array of `{id, version, tier, previousVersion}`.
///
/// # Safety
/// `data_dir` is NUL-terminated UTF-8; `err` is null or points to writable storage.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugins_installed_json(data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let list = plugins_installed(required(data_dir, "data_dir")?).map_err(coded)?;
        Ok(to_c(Value::Array(list.into_iter().map(installed_json).collect()).to_string()))
    })
}

/// Install the `.bastionplugin` at `path`. `allow_unverified`: the setting "Allow unverified plugins"
/// (non-zero = on). Returns `installed`, `updated`, `restored` or `unchanged`.
///
/// # Safety
/// `data_dir` and `path` are NUL-terminated UTF-8; `err` is null or points to writable storage.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_install_file(data_dir: *const c_char, path: *const c_char, allow_unverified: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let kind = plugin_install_file(required(data_dir, "data_dir")?, required(path, "path")?, allow_unverified != 0).map_err(coded)?;
        Ok(to_c(kind))
    })
}

/// Remove plugin `id`; `delete_data` non-zero also deletes its data folder. Returns 0, or -1 with `err` set.
///
/// # Safety
/// `data_dir` and `id` are NUL-terminated UTF-8; `err` is null or points to writable storage.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_remove(data_dir: *const c_char, id: *const c_char, delete_data: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        plugin_remove(required(data_dir, "data_dir")?, required(id, "id")?, delete_data != 0).map_err(coded)?;
        set_ok()
    })
}

/// Fetch the catalogue index (the official one, or the mirror folder `mirror` when not null). Returns
/// `accepted`, `expired`, `clock-wrong`, `refused: …` or `unreachable: …`; nothing changes unless accepted.
///
/// # Safety
/// `data_dir` is NUL-terminated UTF-8, `mirror` null or NUL-terminated UTF-8; `err` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugins_refresh(data_dir: *const c_char, mirror: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(plugins_refresh(required(data_dir, "data_dir")?, optional(mirror, "mirror")?).map_err(coded)?)))
}

/// The updates the cached catalogue offers, as a JSON array of `{id, from, to, tier, needsConsent}`.
///
/// # Safety
/// `data_dir` is NUL-terminated UTF-8; `err` is null or points to writable storage.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugins_updates_json(data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let list = plugins_updates(required(data_dir, "data_dir")?).map_err(coded)?;
        Ok(to_c(Value::Array(list.into_iter().map(update_json).collect()).to_string()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn an_empty_data_folder_lists_no_plugins() {
        let dir = tempfile::tempdir().unwrap();
        let d = CString::new(dir.path().display().to_string()).unwrap();
        let mut err = null_mut();
        let out = unsafe { bastion_plugins_installed_json(d.as_ptr(), &mut err) };
        assert!(err.is_null());
        assert_eq!(unsafe { CStr::from_ptr(out) }.to_str().unwrap(), "[]");
        unsafe { crate::bastion_string_free(out) };
        let out = unsafe { bastion_plugins_updates_json(d.as_ptr(), &mut err) };
        assert_eq!(unsafe { CStr::from_ptr(out) }.to_str().unwrap(), "[]");
        unsafe { crate::bastion_string_free(out) };
        let id = CString::new("com.example.none").unwrap();
        assert_eq!(unsafe { bastion_plugin_remove(d.as_ptr(), id.as_ptr(), 0, &mut err) }, -1);
        assert!(!err.is_null());
        unsafe { crate::bastion_string_free(err) };
    }
}
