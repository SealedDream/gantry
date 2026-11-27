//! Bulk edit over the C ABI (packet B3-BULK-EDIT, ABI 126):
//! the properties several selected connections share, and one change applied to all of them or
//! to none. Same calls as Native Mac (`core-ffi/src/bulk_edit.rs`, core `bulk_edit`).
use std::ffi::c_char;
use std::ptr::null_mut;

use bastion_ffi::Library;
use serde_json::{json, Value};

use crate::{guarded, optional, required, to_c, BastionLibrary};

/// # Safety
/// `lib` NULL or a live handle.
unsafe fn library<'a>(lib: *const BastionLibrary) -> Result<&'a Library, String> {
    lib.as_ref().map(|l| &*l.0).ok_or_else(|| "library handle is NULL".to_string())
}

fn ids_from_json(raw: String) -> Result<Vec<String>, String> {
    serde_json::from_str(&raw).map_err(|_| "ids_json: expected a JSON array of id strings".to_string())
}

/// Properties every connection in `ids_json` (a JSON string array) has, as JSON
/// `[{def:{key,label,category,kind,help,inheritable,options:[{id,label}]}, value, mixed}]`.
/// `value` is the shared own value (null when all inherit or `mixed` is true). `name` and `host`
/// are never listed. Free with `bastion_string_free`.
///
/// # Safety
/// `ids_json` valid NUL-terminated; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_properties_for_selection_json(lib: *const BastionLibrary, ids_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let ids = ids_from_json(required(ids_json, "ids_json")?)?;
        let props = library(lib)?.properties_for_selection(ids).map_err(|e| e.to_string())?;
        let out: Vec<Value> = props
            .into_iter()
            .map(|p| {
                let d = p.def;
                json!({ "def": { "key": d.key, "label": d.label, "category": d.category, "kind": d.kind, "help": d.help, "inheritable": d.inheritable,
                    "options": d.options.iter().map(|o| json!({ "id": o.id, "label": o.label })).collect::<Vec<_>>() },
                    "value": p.value, "mixed": p.mixed })
            })
            .collect();
        Ok(to_c(Value::Array(out).to_string()))
    })
}

/// Set `key` to `value` (NULL or blank: inherit) on every connection in `ids_json`, or on none
/// when one refuses it. Returns how many changed, or -1. Call `bastion_library_save` afterwards.
///
/// # Safety
/// Strings valid NUL-terminated (`value` may be NULL); `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_apply_to_selection(lib: *const BastionLibrary, ids_json: *const c_char, key: *const c_char, value: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let ids = ids_from_json(required(ids_json, "ids_json")?)?;
        let (key, value) = (required(key, "key")?, optional(value, "value")?);
        let n = library(lib)?.apply_to_selection(ids, key, value).map_err(|e| e.to_string())?;
        Ok(i32::try_from(n).unwrap_or(i32::MAX))
    })
}

/// Add the tags in `add_json` and remove those in `remove_json` (JSON string arrays) on every
/// connection in `ids_json`, or on none; other tags stay. Returns how many changed, or -1 (v131).
/// Call `bastion_library_save` afterwards.
///
/// # Safety
/// Strings valid NUL-terminated; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_edit_tags_on_selection(lib: *const BastionLibrary, ids_json: *const c_char, add_json: *const c_char, remove_json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let ids = ids_from_json(required(ids_json, "ids_json")?)?;
        let add = ids_from_json(required(add_json, "add_json")?).map_err(|_| "add_json: expected a JSON array of strings".to_string())?;
        let remove = ids_from_json(required(remove_json, "remove_json")?).map_err(|_| "remove_json: expected a JSON array of strings".to_string())?;
        let n = library(lib)?.edit_tags_on_selection(ids, add, remove).map_err(|e| e.to_string())?;
        Ok(i32::try_from(n).unwrap_or(i32::MAX))
    })
}

#[cfg(test)]
mod tests {
    use super::ids_from_json;

    #[test]
    fn ids_json_must_be_a_string_array() {
        assert_eq!(ids_from_json(r#"["a","b"]"#.into()).unwrap(), vec!["a", "b"]);
        assert!(ids_from_json("{}".into()).is_err());
        assert!(ids_from_json("[1]".into()).is_err());
    }
}
