//! Personal as one encrypted `.bastion` document over the C ABI (ABI 94, NW-OF-A; owner points 7, 20).
//! The same `bastion_ffi::PersonalLibrary` Native Mac uses (#703): the tree and the credential vault live
//! inside the document, and the old `library.json` + `credentials.vault` move in once, verified, with a
//! backup kept. On Windows the device key is one DPAPI (current user) blob in `<data dir>\device-key`,
//! read once per launch; no prompt. `BASTION_DEVICE_KEY` (64 hex) overrides it for hermetic tests.
use std::ffi::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::PersonalLibrary;
use serde_json::json;
use zeroize::Zeroizing;

use crate::credentials::BastionCredentials;
use crate::{guarded, required, set_ok, to_c, BastionLibrary};

/// Opaque handle for the open Personal document.
pub struct BastionPersonal(Arc<PersonalLibrary>);

const DEVICE_KEY_ENV: &str = "BASTION_DEVICE_KEY";

unsafe fn personal<'a>(p: *const BastionPersonal) -> Result<&'a PersonalLibrary, String> {
    p.as_ref().map(|h| h.0.as_ref()).ok_or_else(|| "personal is NULL".to_string())
}

/// The device key (hex): the test override, else this account's DPAPI blob (created on first use).
fn device_key(data_dir: &str) -> Result<Zeroizing<String>, String> {
    if let Ok(k) = std::env::var(DEVICE_KEY_ENV) {
        if !k.is_empty() {
            return Ok(Zeroizing::new(k));
        }
    }
    os_device_key(data_dir)
}

#[cfg(windows)]
fn os_device_key(data_dir: &str) -> Result<Zeroizing<String>, String> {
    let provider = bastion_core::provider::DpapiProvider::new(std::path::Path::new(data_dir).join("device-key"));
    let key = bastion_core::provider::vault_key(&provider, "personal").map_err(|e| e.to_string())?;
    Ok(Zeroizing::new(key.expose().to_string()))
}

#[cfg(not(windows))]
fn os_device_key(_data_dir: &str) -> Result<Zeroizing<String>, String> {
    Err(format!("no device key store on this platform; set {DEVICE_KEY_ENV}"))
}

/// Open `path` (e.g. `Documents\Bastion\Personal.bastion`), creating it or moving the old Personal files
/// in `data_dir` into it once. NULL and `*err` on failure; the old files are then untouched.
///
/// # Safety
/// `data_dir`, `path` valid NUL-terminated; `err` NULL or writable. Free with [`bastion_personal_free`].
#[no_mangle]
pub unsafe extern "C" fn bastion_personal_open(data_dir: *const c_char, path: *const c_char, err: *mut *mut c_char) -> *mut BastionPersonal {
    guarded(err, null_mut(), || {
        let dir = required(data_dir, "data_dir")?;
        let path = required(path, "path")?;
        let key = device_key(&dir)?;
        let p = PersonalLibrary::open(dir, path, key.to_string()).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionPersonal(p))))
    })
}

/// # Safety
/// `p` NULL or a live handle, not used afterwards. Library and vault handles taken from it stay valid.
#[no_mangle]
pub unsafe extern "C" fn bastion_personal_free(p: *mut BastionPersonal) {
    if !p.is_null() {
        drop(Box::from_raw(p));
    }
}

/// The tree as a library handle that saves into the document. Free with `bastion_library_free`.
///
/// # Safety
/// `p` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_personal_library(p: *const BastionPersonal, err: *mut *mut c_char) -> *mut BastionLibrary {
    guarded(err, null_mut(), || {
        let lib = personal(p)?.library().map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionLibrary(lib))))
    })
}

/// The credential vault inside the document. Free with `bastion_credentials_free`.
///
/// # Safety
/// `p` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_personal_vault(p: *const BastionPersonal, err: *mut *mut c_char) -> *mut BastionCredentials {
    guarded(err, null_mut(), || {
        let v = personal(p)?.vault().map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionCredentials(v))))
    })
}

/// `{"id","path","name","locked","hasMasterPassword"}`. Free with `bastion_string_free`.
///
/// # Safety
/// `p` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_personal_info_json(p: *const BastionPersonal, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let i = personal(p)?.info();
        Ok(to_c(json!({ "id": i.id, "path": i.path, "name": i.name, "locked": i.locked, "hasMasterPassword": i.has_master_password }).to_string()))
    })
}

/// What this launch's one-time move did, `{"folders","connections","credentials","backup"}`, or `null`
/// when nothing moved. Free with `bastion_string_free`.
///
/// # Safety
/// `p` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_personal_migration_json(p: *const BastionPersonal, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let m = personal(p)?.migration();
        let v = m.map(|m| json!({ "folders": m.folders, "connections": m.connections, "credentials": m.credentials, "backup": m.backup }));
        Ok(to_c(v.unwrap_or(serde_json::Value::Null).to_string()))
    })
}

/// Rename Personal (owner point 33): only the name inside the document changes. Returns 0 or -1.
///
/// # Safety
/// `p` live; `name` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_personal_rename(p: *const BastionPersonal, name: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let name = required(name, "name")?;
        personal(p)?.rename(name).map_err(|e| e.to_string())?;
        set_ok()
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn opens_creates_and_hands_out_library_and_vault() {
        std::env::set_var(DEVICE_KEY_ENV, KEY);
        let t = tempfile::tempdir().unwrap();
        let dir = CString::new(t.path().display().to_string()).unwrap();
        let path = CString::new(t.path().join("Personal.bastion").display().to_string()).unwrap();
        let mut err = null_mut();
        unsafe {
            let p = bastion_personal_open(dir.as_ptr(), path.as_ptr(), &mut err);
            assert!(!p.is_null(), "open failed");
            let lib = bastion_personal_library(p, &mut err);
            let vault = bastion_personal_vault(p, &mut err);
            assert!(!lib.is_null() && !vault.is_null());
            let info = bastion_personal_info_json(p, &mut err);
            let text = std::ffi::CStr::from_ptr(info).to_string_lossy().into_owned();
            assert!(text.contains("\"locked\":false"), "{text}");
            crate::bastion_string_free(info);
            let name = CString::new("Mine").unwrap();
            assert_eq!(bastion_personal_rename(p, name.as_ptr(), &mut err), 0);
            crate::credentials::bastion_credentials_free(vault);
            crate::bastion_library_free(lib);
            bastion_personal_free(p);
        }
        assert!(t.path().join("Personal.bastion").exists());
    }
}

/// LIB-01: the user showed Personal by hand (Documents › Show Personal); the next launch opens it.
/// Never call it for a lock. Returns 0 or -1.
///
/// # Safety
/// `p` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_personal_note_shown(p: *const BastionPersonal, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        personal(p)?.note_shown();
        set_ok()
    })
}
