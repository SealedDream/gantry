//! Triggers over the C ABI (ABI 69): the per-user rules in `triggers.json` (pass its path) and
//! applying them to a terminal. Trigger JSON: `{id?, name, pattern, caseInsensitive?, enabled?,
//! highlight?: {fg?, bg?, bold?}, notify?}`; colours are 0xRRGGBB numbers.
use std::ffi::c_char;
use std::ptr::null_mut;

use bastion_core::triggers::{Trigger, TriggerStore};

use crate::terminal::BastionTerminal;
use crate::{guarded, optional, required, set_ok, to_c};

fn store(path: *const c_char) -> Result<TriggerStore, String> {
    let p = unsafe { required(path, "path") }?;
    TriggerStore::open(std::path::Path::new(&p)).map_err(|e| e.to_string())
}

/// All triggers as a JSON array. Free with `bastion_string_free`.
///
/// # Safety
/// `path` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_triggers_list_json(path: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(serde_json::to_string(store(path)?.list()).map_err(|e| e.to_string())?)))
}

/// Add (`id` missing or empty) or replace a trigger. Returns its id; free with `bastion_string_free`.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_triggers_save_json(path: *const c_char, trigger_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let mut v: serde_json::Value = serde_json::from_str(&required(trigger_json, "trigger_json")?).map_err(|_| "trigger_json must be a JSON object".to_string())?;
        if v.get("id").and_then(|i| i.as_str()).is_none_or(str::is_empty) {
            v["id"] = serde_json::Value::String(uuid::Uuid::new_v4().to_string());
        }
        let t: Trigger = serde_json::from_value(v).map_err(|e| format!("trigger_json: {e}"))?;
        let id = t.id.to_string();
        store(path)?.save(t).map_err(|e| e.to_string())?;
        Ok(to_c(id))
    })
}

/// Returns 0, or -1 with `*err` set.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_triggers_remove(path: *const c_char, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let id = uuid::Uuid::parse_str(&required(id, "id")?).map_err(|_| "id is not a trigger id".to_string())?;
        store(path)?.remove(id).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// The triggers as a file another computer can import. Free with `bastion_string_free`.
///
/// # Safety
/// `path` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_triggers_export_json(path: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(store(path)?.export_json())))
}

/// Import an exported file (all or nothing; an id or name already here is replaced). Returns how
/// many triggers it held, or -1 with `*err` set.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_triggers_import_json(path: *const c_char, json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let n = store(path)?.import_json(&required(json, "json")?).map_err(|e| e.to_string())?;
        Ok(i32::try_from(n).unwrap_or(i32::MAX))
    })
}

/// Apply the enabled triggers in `path` to the terminal (call again after edits); `path` NULL
/// turns them off. Returns 0, or -1 with `*err` set.
///
/// # Safety
/// `t` live; `path` NULL or valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_set_triggers(t: *const BastionTerminal, path: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let term = t.as_ref().ok_or("terminal is NULL")?;
        let lib = match optional(path, "path")? {
            None => None,
            Some(p) => Some(bastion_ffi::TriggerLibrary::open(p).map_err(|e| e.to_string())?),
        };
        term.shared().set_triggers(lib).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Notifications raised since the last call: JSON array of `{triggerId, name, line}`.
/// Free with `bastion_string_free`.
///
/// # Safety
/// `t` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_take_trigger_events_json(t: *const BastionTerminal, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let term = t.as_ref().ok_or("terminal is NULL")?;
        let rows: Vec<_> = term.shared().take_trigger_events().into_iter().map(|e| serde_json::json!({ "triggerId": e.trigger_id, "name": e.name, "line": e.line })).collect();
        Ok(to_c(serde_json::Value::Array(rows).to_string()))
    })
}
