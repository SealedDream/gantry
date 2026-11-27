//! Royal TS-style `.bastion` documents over the C ABI: the same `bastion_ffi::BastionDocument`
//! the macOS app uses (see `core-ffi/src/documents.rs` for behaviour).
//!
//! Secrets go in only, as caller-owned byte buffers (`ptr`, `len`) the caller zeroes after the
//! call. A document's tree is reached through an ordinary `BastionLibrary` handle
//! ([`bastion_document_library`]), so every existing `bastion_library_*` call works on it and
//! saves into the document. Windows Hello: show the Hello prompt (`UserConsentVerifier`) first,
//! then call [`bastion_document_unlock_biometric`]; the key is a DPAPI blob for the current user.
use std::ffi::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::{BastionDocument, DocumentExportView, DocumentImportView, DocumentInfoView, DocumentOrigin};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{coded, guarded, library, optional, required, set_ok, to_c, BastionLibrary};

/// Opaque handle for one open document.
pub struct BastionDocumentHandle(pub(crate) Arc<BastionDocument>);

/// # Safety
/// `d` must be NULL or a live handle from `bastion_document_create` / `_open`.
pub(crate) unsafe fn doc<'a>(d: *const BastionDocumentHandle) -> Result<&'a BastionDocument, String> {
    d.as_ref().map(|d| &*d.0).ok_or_else(|| "document handle is NULL".to_string())
}

/// # Safety
/// `ptr` must be NULL (with `len` 0) or point to `len` readable bytes.
unsafe fn secret(ptr: *const u8, len: usize, what: &str) -> Result<Option<Zeroizing<String>>, String> {
    if ptr.is_null() || len == 0 {
        return Ok(None);
    }
    let bytes = std::slice::from_raw_parts(ptr, len);
    std::str::from_utf8(bytes).map(|s| Some(Zeroizing::new(s.to_string()))).map_err(|_| format!("{what} is not valid UTF-8"))
}

fn info_json(i: &DocumentInfoView) -> Value {
    json!({
        "id": i.id, "name": i.name, "path": i.path, "protected": i.protected, "locked": i.locked,
        "biometric": i.biometric, "dirty": i.dirty, "loadedVersion": i.loaded_version, "credentials": i.credentials,
    })
}

fn export_json(v: &DocumentExportView) -> Value {
    json!({ "folders": v.folders, "connections": v.connections, "credentials": v.credentials, "credentialRefs": v.credential_refs,
            "strippedFields": v.stripped_fields, "protected": v.protected })
}

fn import_json(v: &DocumentImportView) -> Value {
    json!({ "sourceName": v.source_name, "connections": v.connections, "duplicates": v.duplicates, "credentials": v.credentials,
            "credentialsDropped": v.credentials_dropped, "folder": v.folder })
}

fn ids(json_ids: Option<String>) -> Result<Option<Vec<String>>, String> {
    json_ids.map(|s| serde_json::from_str::<Vec<String>>(&s).map_err(|e| format!("ids must be a JSON array of strings: {e}"))).transpose()
}

fn boxed(d: Arc<BastionDocument>) -> *mut BastionDocumentHandle {
    Box::into_raw(Box::new(BastionDocumentHandle(d)))
}

/// A new untitled, unprotected document. `data_dir` holds the audit log and recent list.
///
/// # Safety
/// Strings valid and NUL-terminated; `err` NULL or writable. Free with `bastion_document_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_create(name: *const c_char, data_dir: *const c_char, err: *mut *mut c_char) -> *mut BastionDocumentHandle {
    guarded(err, null_mut(), || {
        let d = BastionDocument::create(required(name, "name")?, required(data_dir, "data_dir")?).map_err(coded)?;
        Ok(boxed(d))
    })
}

/// Open a `.bastion` file (or an old `library.json`); protected documents open locked.
///
/// # Safety
/// As [`bastion_document_create`].
#[no_mangle]
pub unsafe extern "C" fn bastion_document_open(path: *const c_char, data_dir: *const c_char, err: *mut *mut c_char) -> *mut BastionDocumentHandle {
    guarded(err, null_mut(), || {
        let d = BastionDocument::open(required(path, "path")?, required(data_dir, "data_dir")?).map_err(coded)?;
        Ok(boxed(d))
    })
}

/// Release a document handle (unsaved changes are not saved). NULL is ignored.
///
/// # Safety
/// `d` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_free(d: *mut BastionDocumentHandle) {
    if !d.is_null() {
        drop(Box::from_raw(d));
    }
}

/// `{id,name,path,protected,locked,biometric,dirty,loadedVersion,credentials}`.
///
/// # Safety
/// `d` live; `err` NULL or writable. Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_info_json(d: *const BastionDocumentHandle, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(info_json(&doc(d)?.info()).to_string())))
}

/// Unlock with the password buffer. Returns 0, or -1 with `*err` set (the same message for a
/// wrong password and a damaged file).
///
/// # Safety
/// `d` live; `password` points to `len` bytes; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_unlock(d: *const BastionDocumentHandle, password: *const u8, len: usize, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let pw = secret(password, len, "password")?.ok_or("a password is required")?;
        doc(d)?.unlock(pw.to_string()).map_err(coded)?;
        set_ok()
    })
}

/// Unlock with the DPAPI-kept key. Call only after Windows Hello verification succeeded.
///
/// # Safety
/// `d` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_unlock_biometric(d: *const BastionDocumentHandle, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        doc(d)?.unlock_biometric().map_err(coded)?;
        set_ok()
    })
}

/// Save pending changes and forget the key, credentials and tree. Returns 1 when it locked, 0
/// when there was nothing to lock (unprotected or already locked), -1 on error.
///
/// # Safety
/// `d` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_lock(d: *const BastionDocumentHandle, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || doc(d)?.lock().map(i32::from).map_err(coded))
}

/// The document's tree as a library handle (free with `bastion_library_free`). Fails while locked.
///
/// # Safety
/// `d` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_library(d: *const BastionDocumentHandle, err: *mut *mut c_char) -> *mut BastionLibrary {
    guarded(err, null_mut(), || {
        let lib = doc(d)?.library().map_err(coded)?;
        Ok(Box::into_raw(Box::new(BastionLibrary(lib))))
    })
}

/// Save to the document's file (`path` NULL) or Save As `path`.
///
/// # Safety
/// `d` live; `path` NULL or valid; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_save(d: *const BastionDocumentHandle, path: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let d = doc(d)?;
        match optional(path, "path")? {
            Some(p) => d.save_as(p),
            None => d.save(),
        }
        .map_err(coded)?;
        set_ok()
    })
}

/// Rename the document.
///
/// # Safety
/// `d` live; `name` valid; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_rename(d: *const BastionDocumentHandle, name: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        doc(d)?.rename(required(name, "name")?).map_err(coded)?;
        set_ok()
    })
}

/// Set or change the password (`password` non-empty) or remove it (`password` NULL / `len` 0).
///
/// # Safety
/// `d` live; `password` NULL or `len` readable bytes; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_set_password(d: *const BastionDocumentHandle, password: *const u8, len: usize, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let pw = secret(password, len, "password")?;
        doc(d)?.set_password(pw.map(|p| p.to_string())).map_err(coded)?;
        set_ok()
    })
}

/// Turn Windows Hello unlock on (`on` != 0) or off. Needs an unlocked, protected document.
///
/// # Safety
/// `d` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_set_biometric(d: *const BastionDocumentHandle, on: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        doc(d)?.set_biometric(on != 0).map_err(coded)?;
        set_ok()
    })
}

/// The document's credentials, `[{id,name,folder,username,kind}]`, no secrets.
///
/// # Safety
/// `d` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_credentials_json(d: *const BastionDocumentHandle, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let list: Vec<Value> = doc(d)?
            .credentials()
            .map_err(coded)?
            .into_iter()
            .map(|c| json!({ "id": c.id, "name": c.name, "folder": c.folder, "username": c.username, "kind": c.kind }))
            .collect();
        Ok(to_c(Value::Array(list).to_string()))
    })
}

/// Add (`id` NULL) or update a password credential in a protected document; returns its id.
/// An empty password on update keeps the stored one.
///
/// # Safety
/// `d` live; strings valid; `password` NULL or `len` readable bytes; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_save_password_credential(
    d: *const BastionDocumentHandle,
    id: *const c_char,
    name: *const c_char,
    username: *const c_char,
    password: *const u8,
    len: usize,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let pw = secret(password, len, "password")?.map(|p| p.to_string()).unwrap_or_default();
        let id = doc(d)?.save_password_credential(optional(id, "id")?, required(name, "name")?, required(username, "username")?, pw).map_err(coded)?;
        Ok(to_c(id))
    })
}

/// Remove a credential from the document.
///
/// # Safety
/// `d` live; `id` valid; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_remove_credential(d: *const BastionDocumentHandle, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        doc(d)?.remove_credential(required(id, "id")?).map_err(coded)?;
        set_ok()
    })
}

/// Export to a new `.bastion` at `path`. `ids_json` NULL = whole document, else a JSON array of
/// folder/connection ids. Secrets only with `include_secrets` != 0, which needs a password.
/// Returns `{folders,connections,credentials,credentialRefs,strippedFields,protected}`.
///
/// # Safety
/// `d` live; strings NULL or valid; `password` NULL or `len` readable bytes; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_export_json(
    d: *const BastionDocumentHandle,
    path: *const c_char,
    ids_json: *const c_char,
    name: *const c_char,
    include_secrets: i32,
    password: *const u8,
    len: usize,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let pw = secret(password, len, "password")?.map(|p| p.to_string());
        let v = doc(d)?
            .export_to(required(path, "path")?, ids(optional(ids_json, "ids")?)?, required(name, "name")?, include_secrets != 0, pw)
            .map_err(coded)?;
        Ok(to_c(export_json(&v).to_string()))
    })
}

/// Preview (`apply` 0) or perform importing the `.bastion` at `path` into this document. Returns
/// `{sourceName,connections,duplicates,credentials,credentialsDropped,folder}`.
///
/// # Safety
/// `d` live; `path` valid; `password` NULL or `len` readable bytes; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_import_json(d: *const BastionDocumentHandle, path: *const c_char, password: *const u8, len: usize, apply: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let pw = secret(password, len, "password")?.map(|p| p.to_string());
        let v = doc(d)?.import_document(required(path, "path")?, pw, apply != 0).map_err(coded)?;
        Ok(to_c(import_json(&v).to_string()))
    })
}

/// Export the Personal library (secret-free) to a `.bastion` at `path`; optional password.
///
/// # Safety
/// `lib` live library handle; strings NULL or valid; `password` NULL or `len` bytes; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_export_document_json(
    lib: *const BastionLibrary,
    path: *const c_char,
    ids_json: *const c_char,
    name: *const c_char,
    password: *const u8,
    len: usize,
    data_dir: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let pw = secret(password, len, "password")?.map(|p| p.to_string());
        let v = bastion_ffi::export_library_document(library(lib)?, required(path, "path")?, ids(optional(ids_json, "ids")?)?, required(name, "name")?, pw, required(data_dir, "data_dir")?)
            .map_err(coded)?;
        Ok(to_c(export_json(&v).to_string()))
    })
}

/// Preview (`apply` 0) or import a `.bastion` into the Personal library (no secrets come along).
///
/// # Safety
/// As [`bastion_library_export_document_json`].
#[no_mangle]
pub unsafe extern "C" fn bastion_library_import_document_json(lib: *const BastionLibrary, path: *const c_char, password: *const u8, len: usize, apply: i32, data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let pw = secret(password, len, "password")?.map(|p| p.to_string());
        let v = bastion_ffi::import_document_into_library(library(lib)?, required(path, "path")?, pw, apply != 0, required(data_dir, "data_dir")?).map_err(coded)?;
        Ok(to_c(import_json(&v).to_string()))
    })
}

/// Whether to ask "Did you make this library?" (ABI 100, A1-CORE-01-FU5). Returns 0 when this
/// device knows the library (made here, answered for before, device-keyed, or opened before
/// this rule existed), 1 when it was opened by path and never answered for, -1 on error.
/// While it is 1, every login the file names is offered, not used. Ask before the tree is
/// shown (a locked library: after it is unlocked) and send the answer with
/// [`bastion_document_answer_origin`]; closing the question sends nothing.
///
/// # Safety
/// `d` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_origin(d: *const BastionDocumentHandle, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        Ok(match doc(d)?.origin() {
            DocumentOrigin::Known => 0,
            DocumentOrigin::Unknown => 1,
        })
    })
}

/// The user's answer for an unlocked library whose origin is 1 (ABI 100). `made_by_me` 1 ("I
/// made it"): the id is recorded on this device and the contents are read again from the file
/// as they are. 0 ("Someone sent it"): the id is recorded and the logins the file names stay
/// to be confirmed one by one; that is a change, kept with the next save. Any other value is
/// refused. Returns 0, or -1 with `*err` set (locked; or 1 after the library was changed).
///
/// # Safety
/// `d` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_answer_origin(d: *const BastionDocumentHandle, made_by_me: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let made_by_me = match made_by_me {
            0 => false,
            1 => true,
            other => return Err(format!("made_by_me must be 0 or 1, not {other}")),
        };
        doc(d)?.answer_origin(made_by_me).map_err(coded)?;
        set_ok()
    })
}

/// Once at start, before any document is opened or restored (ABI 100): when this device has
/// no known-libraries record yet, write it with the Personal library (`personal_id`, may be
/// NULL), every document in Recents and every path in `restore_paths_json` (a JSON array of
/// strings, may be NULL), so nothing opened before this rule existed is asked about. Returns 1
/// when it ran, 0 when a record already exists (damaged or not; it is left alone), -1 on
/// error: then unknown libraries are asked about and the next start tries again.
///
/// # Safety
/// `data_dir` valid NUL-terminated; `personal_id`, `restore_paths_json` NULL or valid
/// NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_known_documents_migrate(data_dir: *const c_char, personal_id: *const c_char, restore_paths_json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let paths = optional(restore_paths_json, "restore_paths_json")?
            .map(|s| serde_json::from_str::<Vec<String>>(&s).map_err(|e| format!("restore_paths_json must be a JSON array of strings: {e}")))
            .transpose()?
            .unwrap_or_default();
        let ran = bastion_ffi::migrate_known_documents(required(data_dir, "data_dir")?, optional(personal_id, "personal_id")?, paths).map_err(coded)?;
        Ok(i32::from(ran))
    })
}

/// Recent documents, newest first: a JSON array of paths.
///
/// # Safety
/// `data_dir` valid; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_documents_recent_json(data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(json!(bastion_ffi::recent_documents(required(data_dir, "data_dir")?)).to_string())))
}

#[cfg(test)]
#[path = "a1_fu5_tests.rs"]
mod a1_fu5_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn document_round_trip_over_the_c_abi() {
        let dir = tempfile::tempdir().unwrap();
        let c = |s: &str| CString::new(s).unwrap();
        let data = c(dir.path().to_str().unwrap());
        let path = c(dir.path().join("Team.bastion").to_str().unwrap());
        let mut err = null_mut();
        unsafe {
            let d = bastion_document_create(c("Team").as_ptr(), data.as_ptr(), &mut err);
            assert!(!d.is_null());
            let pw = b"long password";
            assert_eq!(bastion_document_set_password(d, pw.as_ptr(), pw.len(), &mut err), 0);
            assert_eq!(bastion_document_save(d, path.as_ptr(), &mut err), 0);
            assert_eq!(bastion_document_lock(d, &mut err), 1);
            bastion_document_free(d);

            let d = bastion_document_open(path.as_ptr(), data.as_ptr(), &mut err);
            let wrong = b"nope nope";
            assert_eq!(bastion_document_unlock(d, wrong.as_ptr(), wrong.len(), &mut err), -1);
            assert!(!err.is_null());
            crate::bastion_string_free(err);
            assert_eq!(bastion_document_unlock(d, pw.as_ptr(), pw.len(), &mut err), 0);
            let info = bastion_document_info_json(d, &mut err);
            let v: Value = serde_json::from_str(CStr::from_ptr(info).to_str().unwrap()).unwrap();
            assert_eq!((v["protected"].as_bool(), v["locked"].as_bool()), (Some(true), Some(false)));
            crate::bastion_string_free(info);
            let lib = bastion_document_library(d, &mut err);
            assert!(!lib.is_null());
            crate::bastion_library_free(lib);
            bastion_document_free(d);
        }
    }
}

/// LIB-01: the user brought this document to the front by hand (Documents › Show); it becomes the
/// last document in Recents and the next launch opens it. Never call it for a lock. Returns 0 or -1.
///
/// # Safety
/// `d` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_document_note_opened(d: *const BastionDocumentHandle, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        doc(d)?.note_opened();
        set_ok()
    })
}
