//! PLUG-OPEN-WIN (ABI 140): a plugin's request to open SSH, RDP or VNC (plugin API 1.2), app
//! side for Native Windows, over `bastion_ffi`'s `pluginopen` (the Mac's path). The request, the
//! user's answer and the go-ahead travel as plugin view updates and events; these are the calls
//! the app makes after an `open-go`: check every address of a name it is about to connect to,
//! and make the connection, unsaved or saved beside the plugin entry. The host is checked again
//! here, the protocol is limited to SSH, RDP and VNC, and no credential is copied.
use std::os::raw::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::plugin_open_resolve;

use crate::{coded, guarded, handle, required, to_c, BastionLibrary};

/// Resolves `host` once and checks every address against the plugin-open rules. Returns a JSON
/// array of IP strings (connect to the first that answers; keep `host` for host-key and
/// certificate checks). For an `open-go` whose `check_resolved` is true, with its `loopback_ok`.
/// Call off the UI thread. Free the string.
///
/// # Safety
/// `host` NUL-terminated UTF-8; `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_open_resolve_json(host: *const c_char, port: u16, loopback_ok: bool, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let ips = plugin_open_resolve(required(host, "host")?.to_string(), port, loopback_ok).map_err(coded)?;
        Ok(to_c(serde_json::to_string(&ips).map_err(|e| e.to_string())?))
    })
}

/// A one-connection library for an `open-go`, never saved, like Quick Connect. With
/// `via_entry_route` it holds a copy of the plugin entry's gateway. Free with `bastion_library_free`.
///
/// # Safety
/// `lib` live; strings NUL-terminated UTF-8; `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_plugin_open_library(lib: *const BastionLibrary, entry_id: *const c_char, protocol: *const c_char, host: *const c_char, port: u16, label: *const c_char, via_entry_route: bool, err: *mut *mut c_char) -> *mut BastionLibrary {
    guarded(err, null_mut(), || {
        let out = handle(lib)?
            .plugin_open_library(required(entry_id, "entry_id")?.into(), required(protocol, "protocol")?.into(), required(host, "host")?.into(), port, required(label, "label")?.into(), via_entry_route)
            .map_err(coded)?;
        Ok(Box::into_raw(Box::new(BastionLibrary(Arc::clone(&out)))))
    })
}

/// "Save as a library entry": the connection goes into the plugin entry's folder, named by the
/// label. Returns the new id (free it), or null and sets `err`.
///
/// # Safety
/// `lib` live; strings NUL-terminated UTF-8; `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_plugin_open_save(lib: *const BastionLibrary, entry_id: *const c_char, protocol: *const c_char, host: *const c_char, port: u16, label: *const c_char, via_entry_route: bool, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let id = handle(lib)?
            .plugin_open_save(required(entry_id, "entry_id")?.into(), required(protocol, "protocol")?.into(), required(host, "host")?.into(), port, required(label, "label")?.into(), via_entry_route)
            .map_err(coded)?;
        Ok(to_c(id))
    })
}

/// ABI 149, Save as Connection (plugin API 1.6): JSON array of booleans, one per row of
/// `rows_json` (`[{"name","host","protocol"}]`): a connection to the same host by the same
/// protocol is already in `folder_id` (empty or null: the top level), or an earlier row has it.
/// Free the string.
///
/// # Safety
/// `lib` live; strings NUL-terminated UTF-8 (`folder_id` may be null); `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_plugin_propose_duplicates_json(lib: *const BastionLibrary, folder_id: *const c_char, rows_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let folder = crate::optional(folder_id, "folder_id")?.unwrap_or_default();
        let d = handle(lib)?.plugin_propose_duplicates(folder, required(rows_json, "rows_json")?.into()).map_err(coded)?;
        Ok(to_c(serde_json::to_string(&d).map_err(|e| e.to_string())?))
    })
}

/// ABI 149, Save as Connection: saves the sheet's rows into `folder_id` (empty or null: the top
/// level) or a new folder `new_folder` made there, skipping duplicates, linking `credential_id`
/// (empty or null: none) by id. Returns `{"ids":[…],"duplicates":[…],"folder":id|null}`; free it.
///
/// # Safety
/// `lib` live; strings NUL-terminated UTF-8 (all but `rows_json` may be null); `err` null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_plugin_propose_save_json(lib: *const BastionLibrary, folder_id: *const c_char, new_folder: *const c_char, rows_json: *const c_char, credential_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let folder = crate::optional(folder_id, "folder_id")?.unwrap_or_default();
        let new_folder = crate::optional(new_folder, "new_folder")?.unwrap_or_default();
        let credential = crate::optional(credential_id, "credential_id")?.unwrap_or_default();
        let out = handle(lib)?.plugin_propose_save(folder, new_folder, required(rows_json, "rows_json")?.into(), credential).map_err(coded)?;
        Ok(to_c(out))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    unsafe fn take(p: *mut c_char) -> String {
        let s = CStr::from_ptr(p).to_str().unwrap().to_string();
        crate::bastion_string_free(p);
        s
    }

    #[test]
    fn a_literal_resolves_to_itself_and_refused_addresses_fail() {
        let ok = CString::new("10.0.0.5").unwrap();
        let mut e = null_mut();
        let s = unsafe { bastion_plugin_open_resolve_json(ok.as_ptr(), 22, false, &mut e) };
        assert!(e.is_null());
        assert_eq!(unsafe { take(s) }, r#"["10.0.0.5"]"#);
        for bad in ["169.254.169.254", "::ffff:127.0.0.1", "0x7f.1"] {
            let b = CString::new(bad).unwrap();
            let mut e = null_mut();
            let s = unsafe { bastion_plugin_open_resolve_json(b.as_ptr(), 22, true, &mut e) };
            assert!(s.is_null() && !e.is_null(), "{bad}");
            unsafe { crate::bastion_string_free(e) };
        }
    }

    #[test]
    fn open_library_and_save_refuse_a_null_library_or_argument() {
        let c = CString::new("x").unwrap();
        let mut e = null_mut();
        let l = unsafe { bastion_library_plugin_open_library(std::ptr::null(), c.as_ptr(), c.as_ptr(), c.as_ptr(), 22, c.as_ptr(), true, &mut e) };
        assert!(l.is_null() && !e.is_null());
        unsafe { crate::bastion_string_free(e) };
        let mut e = null_mut();
        let s = unsafe { bastion_library_plugin_open_save(std::ptr::null(), c.as_ptr(), std::ptr::null(), c.as_ptr(), 22, c.as_ptr(), false, &mut e) };
        assert!(s.is_null() && !e.is_null());
        unsafe { crate::bastion_string_free(e) };
    }
}
