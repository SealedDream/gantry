//! Navigation tree and command registry over the C ABI (ABI 15): context menus evaluated by the core,
//! ordered moves, rename, duplicate, sort, and the shared icon and theme tokens. Same conventions as
//! the rest of this crate: JSON out, `char **err`, nothing unwinds.
use std::ffi::c_char;
use std::ptr::null_mut;

use bastion_ffi::{action_ids, all_icons, theme_accents, theme_colors, theme_metrics, SessionSnapshot, TreeState};
use serde_json::{json, Value};

use crate::{guarded, handle, optional, required, to_c, BastionLibrary};

fn strings(v: &Value, key: &str) -> Vec<String> {
    v.get(key).and_then(Value::as_array).map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

/// Context menu for a folder or connection (`id` NULL or empty = library root), as a JSON array of
/// `{id,label,glyph,section,enabled,disabledReason,destructive,confirm,primary}`.
/// `sessions_json` is `{"connected":[ids],"connecting":[ids],"failed":[ids]}` from the host's open tabs
/// (NULL = none). `handled_json` is the JSON array of action ids the host has handlers for; nothing
/// else is returned. Put a separator between entries whose `section` differs.
///
/// # Safety
/// Strings valid NUL-terminated or NULL where allowed; `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_menu_json(
    lib: *const BastionLibrary,
    id: *const c_char,
    sessions_json: *const c_char,
    handled_json: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let id = optional(id, "id")?;
        let sessions: Value = match optional(sessions_json, "sessions")? {
            Some(s) => serde_json::from_str(&s).map_err(|e| format!("sessions: {e}"))?,
            None => json!({}),
        };
        let handled: Vec<String> = serde_json::from_str(&required(handled_json, "handled")?).map_err(|e| format!("handled: {e}"))?;
        let snapshot = SessionSnapshot {
            connected: strings(&sessions, "connected"),
            connecting: strings(&sessions, "connecting"),
            failed: strings(&sessions, "failed"),
        };
        let items = handle(lib)?.menu(id, snapshot, handled).map_err(|e| e.to_string())?;
        let out: Vec<Value> = items
            .into_iter()
            .map(|m| {
                json!({"id": m.id, "label": m.label, "glyph": m.glyph, "section": m.section, "enabled": m.enabled,
                       "disabledReason": m.disabled_reason, "destructive": m.destructive, "confirm": m.confirm, "primary": m.primary})
            })
            .collect();
        Ok(to_c(Value::Array(out).to_string()))
    })
}

/// Every action id the registry knows, as a JSON array (for a host to check its handler table).
#[no_mangle]
pub extern "C" fn bastion_action_ids_json() -> *mut c_char {
    to_c(json!(action_ids()).to_string())
}

/// Every icon id with its full label and tint token: `[{id,label,tint}]`.
#[no_mangle]
pub extern "C" fn bastion_icons_json() -> *mut c_char {
    to_c(Value::Array(all_icons().into_iter().map(|i| json!({"id": i.id, "label": i.label, "tint": i.tint})).collect()).to_string())
}

/// Colour tokens for the dark (`dark` != 0) or light appearance: `{"icon.terminal":"#RRGGBB",…}`.
#[no_mangle]
pub extern "C" fn bastion_theme_colors_json(dark: i32) -> *mut c_char {
    let map: serde_json::Map<String, Value> = theme_colors(dark != 0).into_iter().map(|c| (c.name, Value::String(c.hex))).collect();
    to_c(Value::Object(map).to_string())
}

/// The accent palette as JSON `{"electric": "#2E6BFF", …}` (the `appearance.accent` ids). Free the result.
#[no_mangle]
pub extern "C" fn bastion_theme_accents_json() -> *mut c_char {
    let map: serde_json::Map<String, Value> = theme_accents().into_iter().map(|c| (c.name, Value::String(c.hex))).collect();
    to_c(Value::Object(map).to_string())
}

/// Row and icon metrics for an `appearance.density` id as JSON `{treeRow, treeIcon, treeIndent, inspectorRow}` (points;
/// an unknown id gives `comfortable`). Free the result.
///
/// # Safety
/// `density` NULL or valid NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn bastion_theme_metrics_json(density: *const c_char) -> *mut c_char {
    let d = if density.is_null() { String::new() } else { std::ffi::CStr::from_ptr(density).to_string_lossy().into_owned() };
    let m = theme_metrics(d);
    to_c(serde_json::json!({ "treeRow": m.tree_row, "treeIcon": m.tree_icon, "treeIndent": m.tree_indent, "inspectorRow": m.inspector_row }).to_string())
}

/// Drag-and-drop: move `id` into `parent` (NULL/empty = root) before sibling `before` (NULL/empty = last).
/// Refuses, changing nothing, for a folder into itself or a descendant. Returns 0, or -1 on failure.
///
/// # Safety
/// Strings valid NUL-terminated or NULL where allowed; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_move_before(lib: *const BastionLibrary, id: *const c_char, parent: *const c_char, before: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let (id, parent, before) = (required(id, "id")?, optional(parent, "parent")?, optional(before, "before")?);
        handle(lib)?.move_node_before(id, parent, before).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Rename a folder or connection. Returns 0, or -1 on failure (blank names are refused).
///
/// # Safety
/// Strings valid NUL-terminated; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_rename(lib: *const BastionLibrary, id: *const c_char, name: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.rename(required(id, "id")?, required(name, "name")?).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Duplicate a connection, or a folder with its subtree. Returns the new id.
///
/// # Safety
/// `id` valid NUL-terminated; `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_duplicate(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(handle(lib)?.duplicate_node(required(id, "id")?).map_err(|e| e.to_string())?)))
}

/// Sort a folder's children by name, folders first (`id` NULL/empty = root). Returns 0, or -1.
///
/// # Safety
/// `id` valid NUL-terminated or NULL; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_sort(lib: *const BastionLibrary, id: *const c_char, recursive: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.sort_folder(optional(id, "id")?, recursive != 0).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Text for Copy SSH Command (`ssh -p 2222 user@host`) or, with `ssh` = 0, Copy Address.
///
/// # Safety
/// `id` valid NUL-terminated; `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_copy_text(lib: *const BastionLibrary, id: *const c_char, ssh: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let (lib, id) = (handle(lib)?, required(id, "id")?);
        let text = if ssh != 0 { lib.ssh_command(id) } else { lib.address(id) };
        Ok(to_c(text.map_err(|e| e.to_string())?))
    })
}

/// Add or remove a connection from Favorites. Returns 0, or -1 on failure.
///
/// # Safety
/// `id` valid NUL-terminated; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_set_favorite(lib: *const BastionLibrary, id: *const c_char, favorite: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.set_favorite(required(id, "id")?, favorite != 0).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Opaque handle for the persisted view state (`ui-state.json` next to the library): expanded
/// folders and inspector visibility. Every change is saved at once.
pub struct BastionTreeState(TreeState);

/// # Safety
/// `state` must be NULL or a handle from [`bastion_tree_state_open`] that has not been freed.
unsafe fn tree<'a>(state: *const BastionTreeState) -> Result<&'a TreeState, String> {
    state.as_ref().map(|s| &s.0).ok_or_else(|| "tree state handle is NULL".to_string())
}

/// Open `path`; a missing or damaged file starts empty (view state is disposable). NULL on a bad path.
///
/// # Safety
/// `path` valid NUL-terminated; `err` NULL or writable. Free with [`bastion_tree_state_free`].
#[no_mangle]
pub unsafe extern "C" fn bastion_tree_state_open(path: *const c_char, err: *mut *mut c_char) -> *mut BastionTreeState {
    guarded(err, null_mut(), || Ok(Box::into_raw(Box::new(BastionTreeState(TreeState::open(required(path, "path")?))))))
}

/// # Safety
/// `state` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_tree_state_free(state: *mut BastionTreeState) {
    if !state.is_null() {
        drop(Box::from_raw(state));
    }
}

/// Expanded folder ids as a JSON array.
///
/// # Safety
/// `state` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_tree_state_expanded_json(state: *const BastionTreeState, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(json!(tree(state)?.expanded()).to_string())))
}

/// The user expanded (`expanded` != 0) or collapsed one folder. Returns 0, or -1.
///
/// # Safety
/// `id` valid NUL-terminated; `state` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_tree_state_set_expanded(state: *const BastionTreeState, id: *const c_char, expanded: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        tree(state)?.set_expanded(required(id, "id")?, expanded != 0).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Expand All / Collapse All on a folder and its descendants (`id` NULL/empty = the whole library).
///
/// # Safety
/// `id` valid NUL-terminated or NULL; `state` and `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_tree_state_set_subtree(state: *const BastionTreeState, lib: *const BastionLibrary, id: *const c_char, expanded: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        tree(state)?.set_subtree_expanded_in(handle(lib)?, optional(id, "id")?, expanded != 0).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Forget folders that no longer exist in `lib` (after deletes). Returns 0, or -1.
///
/// # Safety
/// `state` and `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_tree_state_prune(state: *const BastionTreeState, lib: *const BastionLibrary, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        tree(state)?.prune_in(handle(lib)?).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Whether the details pane is shown (1) or hidden (0).
///
/// # Safety
/// `state` live.
#[no_mangle]
pub unsafe extern "C" fn bastion_tree_state_inspector_visible(state: *const BastionTreeState) -> i32 {
    guarded(null_mut(), 1, || Ok(i32::from(tree(state)?.inspector_visible())))
}

/// Show (`visible` != 0) or hide the details pane, saved at once. Returns 0, or -1.
///
/// # Safety
/// `state` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_tree_state_set_inspector_visible(state: *const BastionTreeState, visible: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        tree(state)?.set_inspector_visible(visible != 0).map_err(|e| e.to_string())?;
        Ok(0)
    })
}
