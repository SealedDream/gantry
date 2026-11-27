//! Recently Deleted over the C ABI (ABI v114, B10). The host passes the time (Unix seconds) and
//! the keep time in days (setting `library.deleted-retention-days`; 0 = Off). Calls that drop
//! connections for good return their ids as a JSON array; the host then prunes inline secrets
//! against `bastion_library_live_connection_ids_json`, never against the tree alone.
use std::ffi::c_char;
use std::ptr::null_mut;

use serde_json::json;

use crate::credentials::BastionCredentials;
use crate::{guarded, handle, required, to_c, BastionLibrary};

fn ids_json(ids: Vec<String>) -> Result<*mut c_char, String> {
    Ok(to_c(serde_json::to_string(&ids).map_err(|e| e.to_string())?))
}

/// Delete a folder or connection: into Recently Deleted, or for good when `retention_days` is 0.
/// Returns the JSON array of connection ids dropped for good (empty when kept), NULL on failure.
///
/// # Safety
/// `id` a valid NUL-terminated string; `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_trash(lib: *const BastionLibrary, id: *const c_char, now: i64, retention_days: u32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let id = required(id, "id")?;
        ids_json(handle(lib)?.trash_node(id, now, retention_days).map_err(|e| e.to_string())?)
    })
}

/// Recently Deleted, oldest first: `[{id, name, kind, parentId, parentName, deletedAt, connectionCount}]`.
///
/// # Safety
/// `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_deleted_json(lib: *const BastionLibrary, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let items: Vec<_> = handle(lib)?
            .deleted_items()
            .into_iter()
            .map(|d| json!({ "id": d.id, "name": d.name, "kind": d.kind, "parentId": d.parent_id, "parentName": d.parent_name, "deletedAt": d.deleted_at, "connectionCount": d.connection_count }))
            .collect();
        Ok(to_c(json!(items).to_string()))
    })
}

/// Restore a Recently Deleted item. Returns `{landedIn, atRootBecauseParentMissing}`, NULL on failure.
///
/// # Safety
/// `id` a valid NUL-terminated string; `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_restore(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let id = required(id, "id")?;
        let r = handle(lib)?.restore_node(id).map_err(|e| e.to_string())?;
        Ok(to_c(json!({ "landedIn": r.landed_in, "atRootBecauseParentMissing": r.at_root_because_parent_missing }).to_string()))
    })
}

/// Drop one Recently Deleted item now. Returns the JSON array of its connection ids.
///
/// # Safety
/// `id` a valid NUL-terminated string; `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_delete_permanently(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let id = required(id, "id")?;
        ids_json(handle(lib)?.delete_permanently(id).map_err(|e| e.to_string())?)
    })
}

/// Empty Recently Deleted. Returns the JSON array of connection ids dropped.
///
/// # Safety
/// `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_empty_deleted(lib: *const BastionLibrary, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || ids_json(handle(lib)?.empty_deleted()))
}

/// Drop items older than the keep time (call at open and once a day). Returns dropped connection ids.
///
/// # Safety
/// `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_purge_deleted(lib: *const BastionLibrary, now: i64, retention_days: u32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || ids_json(handle(lib)?.purge_deleted(now, retention_days)))
}

/// Every connection id in the tree and in Recently Deleted: the live set for pruning inline secrets.
///
/// # Safety
/// `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_live_connection_ids_json(lib: *const BastionLibrary, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || ids_json(handle(lib)?.live_connection_ids()))
}

/// Delete the inline secrets of connections that are neither in the tree nor in Recently Deleted,
/// then save the vault when any were removed. Call after `_trash` with a keep time of 0,
/// `_delete_permanently`, `_empty_deleted` and `_purge_deleted`. Returns how many were removed, -1 on failure.
///
/// # Safety
/// `v` and `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_prune_inline(v: *const BastionCredentials, lib: *const BastionLibrary, err: *mut *mut c_char) -> i64 {
    guarded(err, -1, || {
        let live = handle(lib)?.live_connection_ids();
        let vault: &bastion_ffi::CredentialVault = v.as_ref().map(|v| &*v.0).ok_or_else(|| "credentials handle is NULL".to_string())?;
        let n = vault.prune_inline(live).map_err(|e| e.to_string())?;
        if n > 0 {
            vault.save().map_err(|e| e.to_string())?;
        }
        Ok(i64::from(n))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use bastion_ffi::{CredentialVault, Library};

    #[test]
    fn prune_keeps_a_deleted_connections_inline_secret_until_purge() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(CredentialVault::open_ephemeral(dir.path().join("c.vault").to_string_lossy().into_owned()).unwrap());
        let lib = Arc::new(Library::open(dir.path().join("lib.json").to_string_lossy().into_owned()).unwrap());
        let conn = lib.add_connection(None, "a".into(), "ssh".into(), "a.lab.invalid".into(), None, None).unwrap();
        vault.set_inline_password(conn.clone(), "tester".into(), uuid::Uuid::new_v4().to_string()).unwrap();
        let (v, l) = (BastionCredentials(vault.clone()), BastionLibrary(lib.clone()));
        let mut err = std::ptr::null_mut();
        unsafe {
            lib.trash_node(conn.clone(), 1_000, 30).unwrap();
            assert_eq!(bastion_credentials_prune_inline(&v, &l, &mut err), 0, "a deleted connection keeps its secret");
            assert!(vault.inline_for(conn.clone()).unwrap().is_some());
            lib.purge_deleted(1_000 + 30 * 86_400, 30);
            assert_eq!(bastion_credentials_prune_inline(&v, &l, &mut err), 1);
            assert!(vault.inline_for(conn).unwrap().is_none());
            assert_eq!(bastion_credentials_prune_inline(std::ptr::null(), &l, &mut err), -1);
            assert!(!err.is_null());
            crate::bastion_string_free(err);
        }
    }
}
