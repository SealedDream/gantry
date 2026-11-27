//! Split panes and broadcast input over the C ABI (v53): pane-tree operations, the saved
//! layout conversion and the broadcast review from `bastion_core::panes` and
//! `bastion_core::broadcast`, so every app splits, focuses and broadcasts by the same rules.
use std::ffi::c_char;
use std::ptr::null_mut;

use crate::{guarded, required, to_c};

/// Apply one operation to a pane tree. `tree_json` = `{"kind":"leaf","id"}` or
/// `{"kind":"split","axis":"right|down","ratio","first","second"}`; `op_json` =
/// `{"op":"split","pane","axis","newPane"}`, `close {pane}`, `resize {pane,axis,delta}`,
/// `equalize` or `focus {pane,direction:"left|right|up|down"}`. At most 16 panes.
/// Returns `{"tree":…|null,"focus":id|null}` (null tree: the last pane closed, close the tab).
/// Free with `bastion_string_free`.
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_panes_apply_json(tree_json: *const c_char, op_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = bastion_ffi::panes_apply(required(tree_json, "tree_json")?, required(op_json, "op_json")?).map_err(|e| e.to_string())?;
        Ok(to_c(out))
    })
}

/// The layout to save in a workspace tab (`layout`) for a live pane tree.
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_panes_to_layout_json(tree_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = bastion_ffi::panes_to_layout(required(tree_json, "tree_json")?).map_err(|e| e.to_string())?;
        Ok(to_c(out))
    })
}

/// A live pane tree for a saved workspace layout, one fresh pane id per leaf in reading order.
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_panes_from_layout_json(layout_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = bastion_ffi::panes_from_layout(required(layout_json, "layout_json")?).map_err(|e| e.to_string())?;
        Ok(to_c(out))
    })
}

/// Who receives broadcast input and whether to ask first. `kind` = `keys` or `paste`;
/// `targets_json` = `[{"pane","name","connected","sensitive"}]`; `acknowledged` 1 once the user
/// confirmed this set's sensitive hosts. Returns
/// `{"sendTo":[ids],"skipped":[ids],"sensitive":[names],"needsConfirm":bool}`; refuses NUL, over
/// 64 KiB, and a paste holding the bracketed-paste end sequence.
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_broadcast_review_json(kind: *const c_char, input: *const c_char, targets_json: *const c_char, acknowledged: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = bastion_ffi::broadcast_review(required(kind, "kind")?, required(input, "input")?, required(targets_json, "targets_json")?, acknowledged != 0)
            .map_err(|e| e.to_string())?;
        Ok(to_c(out))
    })
}
