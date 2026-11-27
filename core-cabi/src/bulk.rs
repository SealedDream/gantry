//! Folder actions over the C ABI (ABI 97; `skippedBlocked` since 109): the plan for Connect All, the call Native Mac makes
//! (`core-ffi/src/bulk.rs`, core `actions::plan_connect_all`). Ids and counts only; no secret
//! leaves the core and nothing is connected here.
use std::ffi::c_char;
use std::ptr::null_mut;

use serde_json::json;

use crate::credentials::BastionCredentials;
use crate::{coded, guarded, library, optional, to_c, BastionLibrary};

/// What Connect All on `folder_id` (NULL or empty: the whole library) does with each connection
/// in it and in its subfolders, in tree order: `{ready:[id], needsLogin:[id], skippedOpen:[id],
/// skippedUnsupported:[id], skippedBlocked:[id], toConnect, needsConfirmation}`. Every connection is in exactly one list.
///
/// `skippedBlocked` (ABI 109) are types the effective managed policy forbids: never connect them;
/// show them as blocked. A broken managed policy file is an error here, as for every connect.
/// `ready` have a login of their own (or their type takes none): open them without asking.
/// `needsLogin` have none: never connect these with a login the app picked; open them one by one
/// through the normal sign-in. `toConnect` is `ready` plus `needsLogin`; ask before starting when
/// `needsConfirmation` is true. `open_ids_json` (NULL: none) is a JSON array of the connection
/// ids that have a session now. NULL on error, also for an unknown folder id (`not_found`).
///
/// # Safety
/// `v`, `lib` live; strings NUL-terminated UTF-8 (`folder_id`, `open_ids_json` may be NULL);
/// `err` NULL or writable. Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_plan_connect_all_json(v: *const BastionCredentials, lib: *const BastionLibrary, folder_id: *const c_char, open_ids_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let vault = v.as_ref().map(|v| &*v.0).ok_or_else(|| "credentials handle is NULL".to_string())?;
        let lib = library(lib)?;
        let folder = optional(folder_id, "folder id")?;
        let open = optional(open_ids_json, "open ids")?
            .map(|s| serde_json::from_str::<Vec<String>>(&s).map_err(|_| "open ids must be a JSON array of strings".to_string()))
            .transpose()?
            .unwrap_or_default();
        let p = vault.plan_connect_all(lib, folder, open).map_err(coded)?;
        Ok(to_c(
            json!({
                "ready": p.ready, "needsLogin": p.needs_login, "skippedOpen": p.skipped_open, "skippedUnsupported": p.skipped_unsupported,
                "skippedBlocked": p.skipped_blocked,
                "toConnect": p.to_connect, "needsConfirmation": p.needs_confirmation,
            })
            .to_string(),
        ))
    })
}
