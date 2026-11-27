//! Connection templates (B9) over the C ABI (ABI 117). JSON in and out; no secrets cross.
use std::collections::HashMap;
use std::ffi::c_char;
use std::ptr::null_mut;

use crate::{guarded, handle, optional, required, set_ok, to_c, BastionLibrary};

/// Every template as a JSON array of `{id, name, protocol, host, port, username, notes, tokens:[…]}`.
///
/// # Safety
/// `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_templates_json(lib: *const BastionLibrary, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(serde_json::to_string(&handle(lib)?.templates()).map_err(|e| e.to_string())?)))
}

/// "Save as Template…": the new template's id.
///
/// # Safety
/// Strings valid NUL-terminated; `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_template_save_from(lib: *const BastionLibrary, connection_id: *const c_char, name: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let id = handle(lib)?.save_as_template(required(connection_id, "connection_id")?, required(name, "name")?).map_err(|e| e.to_string())?;
        Ok(to_c(id))
    })
}

/// "New from Template…": `values_json` is `{"Token": "value", …}`; `parent` NULL for the root.
/// Returns the new connection's id. Call `bastion_library_save` after.
///
/// # Safety
/// Strings valid NUL-terminated (`parent` may be NULL); `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_template_instantiate(lib: *const BastionLibrary, template_id: *const c_char, values_json: *const c_char, parent: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let values: HashMap<String, String> = serde_json::from_str(&required(values_json, "values_json")?).map_err(|e| format!("values_json: {e}"))?;
        let id = handle(lib)?.new_from_template(required(template_id, "template_id")?, values, optional(parent, "parent")?).map_err(|e| e.to_string())?;
        Ok(to_c(id))
    })
}

/// Edit a template's token fields; `port` and `username` may be NULL. Returns 0, or -1.
///
/// # Safety
/// Strings valid NUL-terminated (`port`, `username` may be NULL); `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_template_update(lib: *const BastionLibrary, id: *const c_char, name: *const c_char, host: *const c_char, port: *const c_char, username: *const c_char, notes: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?
            .update_template(required(id, "id")?, required(name, "name")?, required(host, "host")?, optional(port, "port")?, optional(username, "username")?, required(notes, "notes")?)
            .map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Delete a template. Returns 0, or -1.
///
/// # Safety
/// `id` valid NUL-terminated; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_template_delete(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.delete_template(required(id, "id")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}
