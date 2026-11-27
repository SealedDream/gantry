//! Credentials section of the tree over the C ABI (`bastion_ffi::CredentialVault` tree calls).
//! Every result is JSON with ids, names, usernames and kinds only; no secret crosses here.
//! Call `bastion_credentials_save` (and `bastion_library_save` where noted) to persist.
use std::ffi::c_char;
use std::ptr::null_mut;

use bastion_ffi::{CredentialUsageView, CredentialVault, Library};
use serde_json::{json, Value};

use crate::credentials::BastionCredentials;
use crate::{guarded, optional, required, to_c, BastionLibrary};

/// # Safety
/// `v` NULL or a live credentials handle.
unsafe fn vault<'a>(v: *const BastionCredentials) -> Result<&'a CredentialVault, String> {
    v.as_ref().map(|v| &*v.0).ok_or_else(|| "credentials handle is NULL".to_string())
}

/// # Safety
/// `lib` NULL or a live library handle.
unsafe fn library(lib: *const BastionLibrary) -> Result<std::sync::Arc<Library>, String> {
    lib.as_ref().map(|l| l.0.clone()).ok_or_else(|| "library handle is NULL".to_string())
}

fn users_json(users: Vec<CredentialUsageView>) -> Value {
    Value::Array(users.into_iter().map(|u| json!({ "nodeId": u.node_id, "name": u.name, "isFolder": u.is_folder, "path": u.path })).collect())
}

/// The Credentials section as flat JSON rows `[{id,name,parent,isFolder,username,kind}]`
/// (`kind` = `folder` | `password` | `ssh-key`; `parent` null at the root). Under each parent:
/// its folders (each followed by its contents), then its credentials, by name.
///
/// # Safety
/// `v` live; `err` NULL or writable. Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_tree_json(v: *const BastionCredentials, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let rows: Vec<Value> = vault(v)?
            .tree_items()
            .into_iter()
            .map(|r| json!({ "id": r.id, "name": r.name, "parent": r.parent, "isFolder": r.is_folder, "username": r.username, "kind": r.kind }))
            .collect();
        Ok(to_c(Value::Array(rows).to_string()))
    })
}

/// Add a folder under `parent` (NULL/empty: the root) and return its id.
///
/// # Safety
/// `name` valid NUL-terminated, `parent` NULL or valid; `v` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_add_folder(v: *const BastionCredentials, name: *const c_char, parent: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let name = required(name, "name")?;
        let parent = optional(parent, "parent")?;
        Ok(to_c(vault(v)?.add_folder(name, parent).map_err(|e| e.to_string())?))
    })
}

/// Rename a folder (sibling names are unique). Returns 0 on success, -1 on failure.
///
/// # Safety
/// Strings valid NUL-terminated; `v` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_rename_folder(v: *const BastionCredentials, id: *const c_char, name: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        vault(v)?.rename_folder(required(id, "id")?, required(name, "name")?).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Move a folder under `parent` (NULL/empty: the root); moving it into itself is refused.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// `id` valid, `parent` NULL or valid; `v` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_move_folder(v: *const BastionCredentials, id: *const c_char, parent: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        vault(v)?.move_folder(required(id, "id")?, optional(parent, "parent")?).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Delete an empty folder; one that still holds anything is refused. Returns 0 / -1.
///
/// # Safety
/// `id` valid NUL-terminated; `v` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_remove_folder(v: *const BastionCredentials, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        vault(v)?.remove_folder(required(id, "id")?).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Rename a credential; references by id keep working. Returns 0 / -1.
///
/// # Safety
/// Strings valid NUL-terminated; `v` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_rename(v: *const BastionCredentials, id: *const c_char, name: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        vault(v)?.rename_credential(required(id, "id")?, required(name, "name")?).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Put a credential in `folder` (NULL/empty: the root). Returns 0 / -1.
///
/// # Safety
/// `id` valid, `folder` NULL or valid; `v` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_move(v: *const BastionCredentials, id: *const c_char, folder: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        vault(v)?.move_credential(required(id, "id")?, optional(folder, "folder")?).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Hosts and folders of `lib` that point straight at the credential:
/// `[{nodeId,name,isFolder,path}]` (`path` = library folder names above the node).
///
/// # Safety
/// `id` valid NUL-terminated; `v`, `lib` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_users_json(v: *const BastionCredentials, lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let users = vault(v)?.credential_users(library(lib)?, required(id, "id")?).map_err(|e| e.to_string())?;
        Ok(to_c(users_json(users).to_string()))
    })
}

/// Delete a credential with the in-use check: `{removed, users}`. In use and `force` 0: nothing
/// changes and `users` lists who points at it, for the warning. `force` 1: those hosts and
/// folders inherit again and the credential is deleted; save the vault and the library.
///
/// # Safety
/// `id` valid NUL-terminated; `v`, `lib` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_remove_checked_json(v: *const BastionCredentials, lib: *const BastionLibrary, id: *const c_char, force: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = vault(v)?.remove_checked(library(lib)?, required(id, "id")?, force != 0).map_err(|e| e.to_string())?;
        Ok(to_c(json!({ "removed": out.removed, "users": users_json(out.users) }).to_string()))
    })
}

/// Point a host or folder at ONE saved credential, or with `credential_id` NULL/empty let it
/// inherit. Call `bastion_library_save` afterwards. Returns 0 / -1.
///
/// # Safety
/// `node_id` valid, `credential_id` NULL or valid; `v`, `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_assign(v: *const BastionCredentials, lib: *const BastionLibrary, node_id: *const c_char, credential_id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        vault(v)?.assign_credential(library(lib)?, required(node_id, "node id")?, optional(credential_id, "credential id")?).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// The credential a host connects with: `{credentialId, sourceId, inherited}` or `null` when
/// nothing up the chain sets one.
///
/// # Safety
/// `connection_id` valid NUL-terminated; `v`, `lib` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_effective_json(v: *const BastionCredentials, lib: *const BastionLibrary, connection_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let eff = vault(v)?.effective_credential(library(lib)?, required(connection_id, "connection id")?).map_err(|e| e.to_string())?;
        let out = eff.map_or(Value::Null, |e| json!({ "credentialId": e.credential_id, "sourceId": e.source_id, "inherited": e.inherited }));
        Ok(to_c(out.to_string()))
    })
}

/// The logins a connection can use, best first (owner point W23, ABI 95): a JSON array of
/// `{credentialId, name, username, kind, source, sourceId, sourceName, autoUse}`; `source` is
/// `default`, `connection`, `named`, `inherited` or `same-host`. `passwords_only` 1 for RDP. No secrets.
/// ABI 96: `autoUse` is true for the connection's own and inherited logins, which connect without
/// asking, and false for `same-host`, which is offered and needs the user's yes; `named` is new.
///
/// # Safety
/// `connection_id` valid NUL-terminated; `v`, `lib` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_logins_json(v: *const BastionCredentials, lib: *const BastionLibrary, connection_id: *const c_char, passwords_only: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let list = vault(v)?.login_candidates(library(lib)?, required(connection_id, "connection id")?, passwords_only != 0).map_err(|e| e.to_string())?;
        let out: Vec<Value> = list
            .into_iter()
            .map(|l| json!({ "credentialId": l.credential_id, "name": l.name, "username": l.username, "kind": l.kind, "source": l.source, "sourceId": l.source_id, "sourceName": l.source_name, "autoUse": l.auto_use }))
            .collect();
        Ok(to_c(Value::Array(out).to_string()))
    })
}

/// Change a connection's logins (ABI 95): `op` 0 add, 1 remove, 2 make default. Save the library afterwards. 0 / -1.
///
/// # Safety
/// `connection_id`, `credential_id` valid NUL-terminated; `v`, `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_edit_login(v: *const BastionCredentials, lib: *const BastionLibrary, connection_id: *const c_char, credential_id: *const c_char, op: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let (v, lib) = (vault(v)?, library(lib)?);
        let (conn, cred) = (required(connection_id, "connection id")?, required(credential_id, "credential id")?);
        match op {
            0 => v.add_login(lib, conn, cred),
            1 => v.remove_login(lib, conn, cred).map(|_| ()),
            2 => v.set_default_login(lib, conn, cred),
            _ => return Err(format!("unknown login operation {op}")),
        }
        .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// `{"username","password"}` of one of the connection's password logins, for the in-process RDP
/// client (ABI 95). Refuses a credential outside that connection's login list; audited. Clear the copy promptly.
///
/// # Safety
/// `connection_id`, `credential_id` valid NUL-terminated; `v`, `lib` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_release_login_json(v: *const BastionCredentials, lib: *const BastionLibrary, connection_id: *const c_char, credential_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let l = vault(v)?.release_login(library(lib)?, required(connection_id, "connection id")?, required(credential_id, "credential id")?).map_err(|e| e.to_string())?;
        let out = zeroize::Zeroizing::new(json!({ "username": l.username, "password": l.password }).to_string());
        Ok(to_c(out.to_string()))
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};
    use std::ptr::null;
    use std::sync::Arc;

    use super::*;

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    unsafe fn take(p: *mut c_char) -> String {
        assert!(!p.is_null(), "expected a string");
        let s = CStr::from_ptr(p).to_str().unwrap().to_string();
        crate::bastion_string_free(p);
        s
    }

    unsafe fn json(p: *mut c_char) -> Value {
        serde_json::from_str(&take(p)).unwrap()
    }

    /// Ephemeral vault (no OS key store, so it runs headless on every platform) and a library.
    fn setup() -> (tempfile::TempDir, BastionCredentials, BastionLibrary) {
        let dir = tempfile::tempdir().unwrap();
        let v = CredentialVault::open_ephemeral(dir.path().join("c.vault").to_string_lossy().into_owned()).unwrap();
        let lib = Library::open(dir.path().join("lib.json").to_string_lossy().into_owned()).unwrap();
        (dir, BastionCredentials(Arc::new(v)), BastionLibrary(Arc::new(lib)))
    }

    #[test]
    fn tree_assign_inherit_and_delete_in_use() {
        let (_dir, v, lib) = setup();
        let folder = lib.0.add_folder(None, "Prod".into()).unwrap();
        let host = lib.0.add_connection(Some(folder.clone()), "web1".into(), "ssh".into(), "10.0.0.1".into(), None, None).unwrap();
        let cred = v.0.save_password(None, "Admin".into(), None, "ops".into(), "s3cret-pw".into()).unwrap();
        unsafe {
            let mut err = null_mut();
            let team = take(bastion_credentials_add_folder(&v, c("Team").as_ptr(), null(), &mut err));
            assert_eq!(bastion_credentials_move(&v, c(&cred).as_ptr(), c(&team).as_ptr(), &mut err), 0);
            assert_eq!(bastion_credentials_rename(&v, c(&cred).as_ptr(), c("Root").as_ptr(), &mut err), 0);
            let rows = json(bastion_credentials_tree_json(&v, &mut err));
            assert_eq!(rows[0]["kind"], "folder");
            assert_eq!(rows[1]["parent"], team.as_str());
            assert_eq!(rows[1]["name"], "Root");
            assert!(!rows.to_string().contains("s3cret-pw"));

            assert_eq!(bastion_credentials_assign(&v, &lib, c(&folder).as_ptr(), c(&cred).as_ptr(), &mut err), 0);
            assert_eq!(bastion_credentials_assign(&v, &lib, c(&host).as_ptr(), c(&team).as_ptr(), &mut err), -1, "a folder is not a credential");
            take(err);
            err = null_mut();
            let eff = json(bastion_credentials_effective_json(&v, &lib, c(&host).as_ptr(), &mut err));
            assert_eq!((eff["credentialId"].as_str(), eff["sourceId"].as_str(), eff["inherited"].as_bool()), (Some(cred.as_str()), Some(folder.as_str()), Some(true)));

            let users = json(bastion_credentials_users_json(&v, &lib, c(&cred).as_ptr(), &mut err));
            assert_eq!(users[0]["name"], "Prod");
            assert_eq!(bastion_credentials_remove_folder(&v, c(&team).as_ptr(), &mut err), -1, "not empty");
            take(err);
            err = null_mut();
            let out = json(bastion_credentials_remove_checked_json(&v, &lib, c(&cred).as_ptr(), 0, &mut err));
            assert_eq!(out["removed"], false);
            assert_eq!(out["users"][0]["isFolder"], true);
            let out = json(bastion_credentials_remove_checked_json(&v, &lib, c(&cred).as_ptr(), 1, &mut err));
            assert_eq!(out["removed"], true);
            assert_eq!(json(bastion_credentials_effective_json(&v, &lib, c(&host).as_ptr(), &mut err)), Value::Null);
            assert_eq!(bastion_credentials_remove_folder(&v, c(&team).as_ptr(), &mut err), 0);
            assert!(err.is_null());
        }
    }

    #[test]
    fn logins_share_by_host_and_release_only_offered_passwords() {
        let (_dir, v, lib) = setup();
        let ssh = lib.0.add_connection(None, "K8s SSH".into(), "ssh".into(), "192.168.1.20".into(), None, None).unwrap();
        let rdp = lib.0.add_connection(None, "K8s RDP".into(), "rdp".into(), "192.168.1.20".into(), None, None).unwrap();
        let a = v.0.save_password(None, "A".into(), None, "appuser".into(), "pw-a".into()).unwrap();
        let b = v.0.save_password(None, "B".into(), None, "root".into(), "pw-b".into()).unwrap();
        let stranger = v.0.save_password(None, "Z".into(), None, "z".into(), "pw-z".into()).unwrap();
        unsafe {
            let mut err = null_mut();
            assert_eq!(bastion_credentials_edit_login(&v, &lib, c(&ssh).as_ptr(), c(&a).as_ptr(), 0, &mut err), 0);
            assert_eq!(bastion_credentials_edit_login(&v, &lib, c(&ssh).as_ptr(), c(&b).as_ptr(), 0, &mut err), 0);
            assert_eq!(bastion_credentials_edit_login(&v, &lib, c(&ssh).as_ptr(), c(&b).as_ptr(), 2, &mut err), 0);
            let list = json(bastion_credentials_logins_json(&v, &lib, c(&ssh).as_ptr(), 0, &mut err));
            assert_eq!((list[0]["credentialId"].as_str(), list[0]["source"].as_str(), list[0]["autoUse"].as_bool()), (Some(b.as_str()), Some("default"), Some(true)));
            assert_eq!((list[1]["source"].as_str(), list[1]["autoUse"].as_bool()), (Some("connection"), Some(true)));
            let list = json(bastion_credentials_logins_json(&v, &lib, c(&rdp).as_ptr(), 1, &mut err));
            assert_eq!((list[0]["source"].as_str(), list[0]["sourceName"].as_str(), list[0]["sourceId"].as_str()), (Some("same-host"), Some("K8s SSH"), Some(ssh.as_str())));
            assert_eq!(list[0]["autoUse"], false, "saved for another connection: offered, never used without asking");
            assert!(!list.to_string().contains("pw-"));
            let got = json(bastion_credentials_release_login_json(&v, &lib, c(&rdp).as_ptr(), c(&b).as_ptr(), &mut err));
            assert_eq!((got["username"].as_str(), got["password"].as_str()), (Some("root"), Some("pw-b")));
            assert!(bastion_credentials_release_login_json(&v, &lib, c(&rdp).as_ptr(), c(&stranger).as_ptr(), &mut err).is_null());
            take(err);
            err = null_mut();
            assert_eq!(bastion_credentials_edit_login(&v, &lib, c(&ssh).as_ptr(), c(&b).as_ptr(), 9, &mut err), -1);
            take(err);
        }
    }

    /// A1-CORE-01: what the scope rules leave out is neither listed nor released, and a folder
    /// becomes a boundary through the ordinary property call.
    #[test]
    fn logins_stop_at_folders_loopback_and_boundaries_and_are_not_released_past_them() {
        let (_dir, v, lib) = setup();
        let (acme, globex) = (lib.0.add_folder(None, "Acme".into()).unwrap(), lib.0.add_folder(None, "Globex".into()).unwrap());
        let (site, other_site) = (lib.0.add_folder(Some(acme.clone()), "Site".into()).unwrap(), lib.0.add_folder(Some(acme.clone()), "Other site".into()).unwrap());
        let add = |parent: &str, name: &str, protocol: &str, host: &str| lib.0.add_connection(Some(parent.into()), name.into(), protocol.into(), host.into(), None, None).unwrap();
        let ssh = add(&site, "db ssh", "ssh", "10.0.0.5");
        let same_site = add(&site, "db rdp", "rdp", "10.0.0.5");
        let sibling = add(&other_site, "db rdp 2", "rdp", "10.0.0.5");
        let other_customer = add(&globex, "db", "rdp", "10.0.0.5");
        let forward_a = add(&acme, "forward 2222", "ssh", "127.0.0.1");
        let forward_b = add(&acme, "forward 2223", "rdp", "127.0.0.1");
        let pw = v.0.save_password(None, "Acme db".into(), None, "dba".into(), "pw-acme".into()).unwrap();
        let local = v.0.save_password(None, "Forward".into(), None, "root".into(), "pw-local".into()).unwrap();
        unsafe {
            let mut err = null_mut();
            assert_eq!(bastion_credentials_edit_login(&v, &lib, c(&ssh).as_ptr(), c(&pw).as_ptr(), 0, &mut err), 0);
            assert_eq!(bastion_credentials_edit_login(&v, &lib, c(&forward_a).as_ptr(), c(&local).as_ptr(), 0, &mut err), 0);
            let offered = |to: &str| json(bastion_credentials_logins_json(&v, &lib, c(to).as_ptr(), 1, &mut null_mut()));
            let refused = |to: &str, cred: &str| {
                let mut err = null_mut();
                assert!(bastion_credentials_release_login_json(&v, &lib, c(to).as_ptr(), c(cred).as_ptr(), &mut err).is_null(), "released past the boundary");
                let message = take(err);
                assert!(message.contains("not offered") && !message.contains("pw-"), "{message}");
            };
            // One top-level folder: offered to the sibling folder's connection, not auto-used.
            for to in [&same_site, &sibling] {
                let list = offered(to);
                assert_eq!((list[0]["source"].as_str(), list[0]["autoUse"].as_bool(), list.as_array().map(Vec::len)), (Some("same-host"), Some(false), Some(1)));
            }
            // Another top-level folder, and loopback: nothing listed, nothing released.
            assert_eq!(offered(&other_customer), Value::Array(vec![]));
            refused(&other_customer, &pw);
            assert_eq!(offered(&forward_b), Value::Array(vec![]));
            refused(&forward_b, &local);
            // Mark the folder as a boundary: its sibling loses the offer, the folder keeps it.
            assert_eq!(crate::properties::bastion_library_set_property(&lib, c(&site).as_ptr(), c("credential_boundary").as_ptr(), c("true").as_ptr(), &mut err), 0);
            assert!(err.is_null());
            assert_eq!(offered(&sibling), Value::Array(vec![]));
            refused(&sibling, &pw);
            let got = json(bastion_credentials_release_login_json(&v, &lib, c(&same_site).as_ptr(), c(&pw).as_ptr(), &mut err));
            assert_eq!((got["username"].as_str(), got["password"].as_str()), (Some("dba"), Some("pw-acme")));
            // A connection cannot carry the setting.
            assert_eq!(crate::properties::bastion_library_set_property(&lib, c(&ssh).as_ptr(), c("credential_boundary").as_ptr(), c("true").as_ptr(), &mut err), -1);
            take(err);
        }
    }

    #[test]
    fn null_handles_fail_cleanly() {
        unsafe {
            let mut err = null_mut();
            assert!(bastion_credentials_tree_json(null(), &mut err).is_null());
            assert!(take(err).contains("NULL"));
            let (_dir, v, _lib) = setup();
            err = null_mut();
            assert!(bastion_credentials_users_json(&v, null(), c("x").as_ptr(), &mut err).is_null());
            take(err);
        }
    }
    /// PLUG-03a: no password leaves the vault for an entry of an unknown type, and that entry
    /// offers its login to no other entry on its host.
    #[test]
    fn no_login_is_released_for_an_entry_of_an_unknown_type() {
        const FIXTURE: &str = include_str!("../../core/tests/fixtures/plug03a/library-unknown.json");
        const UNKNOWN_ID: &str = "0a000000-0000-4000-8000-000000000004";
        let dir = tempfile::tempdir().unwrap();
        let v = BastionCredentials(Arc::new(CredentialVault::open_ephemeral(dir.path().join("c.vault").to_string_lossy().into_owned()).unwrap()));
        let cred = v.0.save_password(None, "App".into(), None, "app".into(), "pw-app".into()).unwrap();
        let mut fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        fixture.pointer_mut("/root/children/0/children/0/settings").unwrap()["credential_id"] = Value::String(cred.clone());
        let path = dir.path().join("lib.json");
        std::fs::write(&path, fixture.to_string()).unwrap();
        let lib = BastionLibrary(Arc::new(Library::open(path.to_string_lossy().into_owned()).unwrap()));
        let rdp = lib.0.add_connection(None, "orders-rdp".into(), "rdp".into(), "db.lab.example".into(), None, None).unwrap();
        unsafe {
            let mut err = null_mut();
            assert!(bastion_credentials_release_login_json(&v, &lib, c(UNKNOWN_ID).as_ptr(), c(&cred).as_ptr(), &mut err).is_null());
            let message = take(err);
            assert!(message.contains("Needs a newer Gantry or a plugin") && !message.contains("pw-"), "{message}");
            err = null_mut();
            assert!(bastion_credentials_logins_json(&v, &lib, c(UNKNOWN_ID).as_ptr(), 0, &mut err).is_null());
            assert!(take(err).contains("Needs a newer Gantry or a plugin"));
            err = null_mut();
            assert_eq!(json(bastion_credentials_logins_json(&v, &lib, c(&rdp).as_ptr(), 1, &mut err)), Value::Array(vec![]), "no same-host login from the unknown entry");
            assert!(bastion_credentials_release_login_json(&v, &lib, c(&rdp).as_ptr(), c(&cred).as_ptr(), &mut err).is_null());
            take(err);
        }
    }

}
