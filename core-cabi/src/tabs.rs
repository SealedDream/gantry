//! Tab groups over the C ABI (v32): the strip operations and folder auto-grouping from
//! `bastion_core::tabgroups`, so Windows and Tauri follow the same rules as Native Mac. The
//! strip crosses as JSON and holds tab and connection ids only.
use std::ffi::c_char;
use std::ptr::null_mut;

use crate::{guarded, library, required, to_c, BastionLibrary};

/// Apply one operation to a strip. `strip_json` =
/// `{"tabs":[{"id","connection","group","detached"}],"groups":[{"id","name","color","collapsed","folder"}]}`;
/// `op_json` = `{"op":"newGroup","tabs":[ids],"name","color"}`, `rename {group,name}`,
/// `recolor {group,color}`, `setCollapsed {group,collapsed}`, `addToGroup {tab,group}`,
/// `removeFromGroup {tab}`, `move {tab,to}`, `ungroup {group}` or `closeGroup {group}`.
/// Colours: `grey blue red yellow green pink purple cyan`. Returns `{"strip":…,"closed":[tab ids to close]}`.
/// Free with `bastion_string_free`.
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_tab_strip_apply_json(strip_json: *const c_char, op_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = bastion_ffi::tab_strip_apply(required(strip_json, "strip_json")?, required(op_json, "op_json")?).map_err(|e| e.to_string())?;
        Ok(to_c(out))
    })
}

/// Folder auto-grouping (setting `tabs.auto-group` → `enabled` 0/1): two or more tabs from one
/// folder form a group named after it and coloured by its inherited "Tab group colour"
/// (`tab_group_color`). Returns the new strip JSON.
///
/// # Safety
/// `lib` from `bastion_library_open`; strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_tab_strip_auto_group_json(lib: *const BastionLibrary, strip_json: *const c_char, enabled: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = library(lib)?.tab_strip_auto_group(required(strip_json, "strip_json")?, enabled != 0).map_err(|e| e.to_string())?;
        Ok(to_c(out))
    })
}

/// The eight group colours as `[{"id","label"}]`. Free with `bastion_string_free`.
#[no_mangle]
pub extern "C" fn bastion_tab_group_colors_json() -> *mut c_char {
    let list: Vec<_> = bastion_ffi::tab_group_colors().into_iter().map(|p| serde_json::json!({ "id": p[0], "label": p[1] })).collect();
    to_c(serde_json::Value::Array(list).to_string())
}
