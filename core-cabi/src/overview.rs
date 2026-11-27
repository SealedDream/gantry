//! Folder overview over the C ABI (ABI 97): the rows of the folder dashboard, the call Native
//! Mac makes (`core-ffi/src/overview.rs`, core `overview::folder_overview`). Names and states
//! only; no secret and no credential id leaves the core.
use std::ffi::c_char;
use std::ptr::null_mut;

use serde_json::{json, Value};

use crate::credentials::BastionCredentials;
use crate::{coded, guarded, handle, optional, required, to_c, BastionLibrary};

/// The rows of `folder_id` (the root folder's id for the whole library) as a JSON array of
/// `{id, kind, name, address, protocol, typeLabel, username, login, loginFrom, lastConnectedAt,
/// lastResult, tags, folderPath, favorite, hostColor, icon:{id,label,tint}}`. Without
/// `include_subfolders` (0): its connections, then its folders. With it: every connection below,
/// in tree order, with `folderPath`, and no folder rows.
///
/// `kind` is `connection` or `folder`. `protocol` is null for a folder and for an entry of a type
/// this app does not know; `typeLabel` is then the stored type name, untrusted text for display
/// only. `login` is `none`, `saved`, `inherited` (from the folder or type `loginFrom`) or
/// `offered` (saved for the connection `loginFrom` on the same host; the user confirms it before
/// use, it is never used without asking). `lastConnectedAt` is Unix seconds.
///
/// Pass `v` only while credentials are unlocked. With NULL the login state is read from the
/// library alone (`saved`, `inherited` or `none`) and the vault is not touched. `data_dir` holds
/// the connection history; NULL leaves the history fields null. NULL on error, also for an
/// unknown folder id (`not_found`).
///
/// # Safety
/// `lib` live; `v` NULL or live; strings NUL-terminated UTF-8 (`data_dir` may be NULL); `err`
/// NULL or writable. Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_folder_overview_json(lib: *const BastionLibrary, v: *const BastionCredentials, data_dir: *const c_char, folder_id: *const c_char, include_subfolders: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let lib = handle(lib)?;
        let vault = v.as_ref().map(|v| v.0.clone());
        let data_dir = optional(data_dir, "data_dir")?;
        let folder = required(folder_id, "folder id")?;
        let rows = lib.folder_overview(vault, data_dir, folder, include_subfolders != 0).map_err(coded)?;
        let out: Vec<Value> = rows
            .into_iter()
            .map(|r| {
                json!({
                    "id": r.id, "kind": r.kind, "name": r.name, "address": r.address, "protocol": r.protocol, "typeLabel": r.type_label,
                    "username": r.username, "login": r.login, "loginFrom": r.login_from,
                    "lastConnectedAt": r.last_connected_at, "lastResult": r.last_result, "tags": r.tags, "folderPath": r.folder_path,
                    "favorite": r.favorite, "hostColor": r.host_color,
                    "icon": { "id": r.icon.id, "label": r.icon.label, "tint": r.icon.tint },
                })
            })
            .collect();
        Ok(to_c(Value::Array(out).to_string()))
    })
}
