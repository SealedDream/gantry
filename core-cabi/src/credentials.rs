//! Credential vault over the C ABI: the same `bastion_ffi::CredentialVault` the macOS app uses,
//! keyed on Windows by a DPAPI-wrapped random key (see `core-ffi/src/credentials.rs`).
//!
//! Secrets go in only. A password or private key is passed as a caller-owned byte buffer
//! (`ptr`, `len`) that the caller zeroes after the call; nothing here returns a secret, and the
//! listing carries names, folders, usernames and kinds only.
use std::ffi::c_char;
use std::ptr::null_mut;

use bastion_ffi::CredentialVault;
use serde_json::json;
use zeroize::Zeroizing;

use crate::{guarded, optional, required, to_c, BastionLibrary};

/// Opaque handle for one open credential vault.
pub struct BastionCredentials(pub(crate) std::sync::Arc<CredentialVault>);

/// # Safety
/// `v` must be NULL or a live handle from [`bastion_credentials_open`].
unsafe fn vault<'a>(v: *const BastionCredentials) -> Result<&'a CredentialVault, String> {
    v.as_ref().map(|v| &*v.0).ok_or_else(|| "credentials handle is NULL".to_string())
}

/// # Safety
/// `ptr` must be NULL (with `len` 0) or point to `len` readable bytes.
unsafe fn secret(ptr: *const u8, len: usize, what: &str) -> Result<String, String> {
    if ptr.is_null() || len == 0 {
        return Ok(String::new()); // empty on update keeps the stored secret
    }
    let bytes = std::slice::from_raw_parts(ptr, len);
    std::str::from_utf8(bytes).map(str::to_string).map_err(|_| format!("{what} is not valid UTF-8"))
}

/// Open (or create) the vault at `path`. The key is generated on first use and kept as a DPAPI
/// blob for the current Windows user next to the vault. Returns NULL and sets `*err` on failure.
///
/// # Safety
/// `path` a valid NUL-terminated string; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_open(path: *const c_char, err: *mut *mut c_char) -> *mut BastionCredentials {
    guarded(err, null_mut(), || {
        let path = required(path, "path")?;
        let v = CredentialVault::open(path).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionCredentials(std::sync::Arc::new(v)))))
    })
}

/// Test-only: a vault handle with a random in-memory key, so hermetic tests never create OS
/// key-store items (login Keychain / DPAPI) for throwaway paths (Codex T04). Not a C export.
#[doc(hidden)]
pub fn ephemeral_handle_for_tests(path: &str) -> Result<*mut BastionCredentials, String> {
    let v = CredentialVault::open_ephemeral(path.to_string()).map_err(|e| e.to_string())?;
    Ok(Box::into_raw(Box::new(BastionCredentials(std::sync::Arc::new(v)))))
}

/// Release a vault handle. NULL is ignored. Unsaved changes are not saved.
///
/// # Safety
/// `v` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_free(v: *mut BastionCredentials) {
    if !v.is_null() {
        drop(Box::from_raw(v));
    }
}

/// The credentials as JSON: `[{id,name,folder,username,kind}]`, `kind` = `password` | `ssh-key` | `unsupported`
/// (a kind a newer app wrote: it can be deleted, not edited or used).
/// No secret is included.
///
/// # Safety
/// `v` live; `err` NULL or writable. Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_list_json(v: *const BastionCredentials, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let list: Vec<_> = vault(v)?
            .list()
            .into_iter()
            .map(|c| json!({ "id": c.id, "name": c.name, "folder": c.folder, "username": c.username, "kind": c.kind }))
            .collect();
        Ok(to_c(serde_json::Value::Array(list).to_string()))
    })
}

/// Add (`id` NULL) or update a password credential and return its id. On update an empty
/// password (`password` NULL or `len` 0) keeps the stored one.
///
/// # Safety
/// Strings valid NUL-terminated (`id`, `folder` may be NULL); `password` NULL or `len` readable
/// bytes; `v` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_save_password(
    v: *const BastionCredentials,
    id: *const c_char,
    name: *const c_char,
    folder: *const c_char,
    username: *const c_char,
    password: *const u8,
    password_len: usize,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let (id, name, folder, user) = (optional(id, "id")?, required(name, "name")?, optional(folder, "folder")?, required(username, "username")?);
        let pw = secret(password, password_len, "password")?;
        vault(v)?.save_password(id, name, folder, user, pw).map(to_c).map_err(|e| e.to_string())
    })
}

/// Add or update an SSH private key credential (OpenSSH/PEM text) and return its id. On update an
/// empty key keeps the stored one. Passphrase-protected keys are refused.
///
/// # Safety
/// As [`bastion_credentials_save_password`].
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_save_ssh_key(
    v: *const BastionCredentials,
    id: *const c_char,
    name: *const c_char,
    folder: *const c_char,
    username: *const c_char,
    private_key: *const u8,
    private_key_len: usize,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let (id, name, folder, user) = (optional(id, "id")?, required(name, "name")?, optional(folder, "folder")?, required(username, "username")?);
        let key = secret(private_key, private_key_len, "private key")?;
        vault(v)?.save_ssh_key(id, name, folder, user, key).map(to_c).map_err(|e| e.to_string())
    })
}

/// Upper bound on a private key file, so a wrong pick (a disk image, a log) is refused before it is read.
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Import an SSH private key from the file at `path` as a vault credential (add with `id` NULL,
/// or replace the key of an existing one) and return its id. The file is read and parsed here, so
/// the key text never crosses this boundary. A passphrase-protected key is decrypted with
/// `passphrase` (`passphrase_len` bytes of UTF-8, caller-zeroed after the call) and stored without
/// it; the passphrase itself is not kept. A wrong or missing passphrase, or a file that is not a
/// private key, fails with a message and stores nothing.
///
/// # Safety
/// Strings valid NUL-terminated (`id`, `folder` may be NULL); `passphrase` NULL or `passphrase_len`
/// readable bytes; `v` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_import_key_file(
    v: *const BastionCredentials,
    id: *const c_char,
    name: *const c_char,
    folder: *const c_char,
    username: *const c_char,
    path: *const c_char,
    passphrase: *const u8,
    passphrase_len: usize,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let (id, name, folder, user) = (optional(id, "id")?, required(name, "name")?, optional(folder, "folder")?, required(username, "username")?);
        let path = required(path, "path")?;
        let pass = Zeroizing::new(secret(passphrase, passphrase_len, "passphrase")?);
        let pem = read_key_file(&path)?;
        let plain = decrypt_key(&pem, &pass)?;
        vault(v)?.save_ssh_key(id, name, folder, user, (*plain).clone()).map(to_c).map_err(|e| e.to_string())
    })
}

fn read_key_file(path: &str) -> Result<Zeroizing<String>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot read the key file: {e}"))?;
    if !meta.is_file() || meta.len() > MAX_KEY_FILE_BYTES {
        return Err("this is not a private key file".into());
    }
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|e| format!("cannot read the key file: {e}"))?);
    std::str::from_utf8(&bytes).map(|s| Zeroizing::new(s.to_string())).map_err(|_| "this is not a private key file".into())
}

/// Parse `pem` (decrypting with `pass` when it is encrypted) and return it as unencrypted OpenSSH text.
fn decrypt_key(pem: &str, pass: &str) -> Result<Zeroizing<String>, String> {
    let encrypted = pem.contains("ENCRYPTED") || russh::keys::PrivateKey::from_openssh(pem).is_ok_and(|k| k.is_encrypted());
    if encrypted && pass.is_empty() {
        return Err("this key has a passphrase; enter it to import the key".into());
    }
    let key = russh::keys::decode_secret_key(pem, (!pass.is_empty()).then_some(pass)).map_err(|e| {
        if encrypted { "the passphrase is wrong, or the key could not be decrypted".to_string() } else { format!("this is not a private key file ({e})") }
    })?;
    key.to_openssh(russh::keys::ssh_key::LineEnding::LF).map_err(|e| format!("could not store the key: {e}"))
}

/// Remove a credential. Returns 0 on success, -1 on failure.
///
/// # Safety
/// `id` valid NUL-terminated; `v` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_remove(v: *const BastionCredentials, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let id = required(id, "id")?;
        vault(v)?.remove(id).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Seal and write the vault (atomic). Returns 0 on success, -1 on failure.
///
/// # Safety
/// `v` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_save(v: *const BastionCredentials, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        vault(v)?.save().map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Assign a vault credential to a connection, or clear it with `credential_id` NULL/empty. Call
/// `bastion_library_save` afterwards. Returns 0 on success, -1 on failure.
///
/// # Safety
/// Strings valid NUL-terminated (`credential_id` may be NULL); `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_set_credential(lib: *const BastionLibrary, connection_id: *const c_char, credential_id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let conn = required(connection_id, "connection id")?;
        let cred = optional(credential_id, "credential id")?;
        let lib = lib.as_ref().map(|l| &l.0).ok_or_else(|| "library handle is NULL".to_string())?;
        lib.set_credential(conn, cred).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// The RDP login a connection uses without asking (its inline password, else the credential
/// `credential_id`), `{"username","password"}`, or `null` when none is saved (ABI 94, owner points 23, 26).
/// Since ABI 104 the call takes the library: a `credential_id` is read only when the shared login rule
/// gives it to this connection as its own or inherited login. Any other id (another folder scope, another
/// loopback connection, a login that is only offered, one not listed at all) fails with "that login is not
/// offered for this connection" before the vault is read; a login the user picks goes through
/// `bastion_credentials_release_login_json`. The release is audited. Free with `bastion_string_free` and
/// clear the copy promptly.
///
/// # Safety
/// `v` and `lib` live; `connection_id` valid NUL-terminated; `credential_id` NULL or valid; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_rdp_login_json(
    v: *const BastionCredentials,
    lib: *const BastionLibrary,
    connection_id: *const c_char,
    credential_id: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let id = required(connection_id, "connection_id")?;
        let cred = optional(credential_id, "credential_id")?;
        let lib = lib.as_ref().map(|l| l.0.clone()).ok_or_else(|| "library handle is NULL".to_string())?;
        let login = vault(v)?.rdp_login_for(lib, id, cred).map_err(|e| e.to_string())?;
        let out = login.map(|l| Zeroizing::new(json!({ "username": l.username, "password": l.password }).to_string()));
        Ok(to_c(out.map(|s| s.to_string()).unwrap_or_else(|| "null".into())))
    })
}

/// B13 "Fill sign-in" (ABI_TBD_WEBFILL): whether to show the button for this web connection
/// (policy allows it and the connection's inherited switch is on). 1, 0, or -1 with `err`.
///
/// # Safety
/// `lib` live; `connection_id` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_web_autofill_offered(lib: *const BastionLibrary, connection_id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let lib = lib.as_ref().map(|l| l.0.clone()).ok_or_else(|| "library handle is NULL".to_string())?;
        Ok(i32::from(bastion_ffi::web_autofill_offered(lib, required(connection_id, "connection_id")?).map_err(|e| e.to_string())?))
    })
}

/// B13 "Fill sign-in" (ABI_TBD_WEBFILL): the core's decision for the page the user is looking at, as JSON
/// `{"script": string|null, "code": string, "message": string}`. With `script` set, run it once in the TOP
/// frame and drop it (it holds the password as a JS string literal); otherwise show `message`. Every call
/// is audited with the page origin only. `is_main_frame`, `is_secure` are 0 or 1.
///
/// # Safety
/// `v`, `lib` live; strings valid NUL-terminated (`credential_id` may be NULL); `err` NULL or writable.
/// Free with `bastion_string_free` (the result is wiped on free).
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_web_autofill_json(
    v: *const BastionCredentials,
    lib: *const BastionLibrary,
    connection_id: *const c_char,
    credential_id: *const c_char,
    page_url: *const c_char,
    is_main_frame: i32,
    is_secure: i32,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let lib = lib.as_ref().map(|l| l.0.clone()).ok_or_else(|| "library handle is NULL".to_string())?;
        let (id, cred, page) = (required(connection_id, "connection_id")?, optional(credential_id, "credential_id")?, required(page_url, "page_url")?);
        let r = vault(v)?.web_autofill(lib, id, cred, page, is_main_frame != 0, is_secure != 0).map_err(|e| e.to_string())?;
        // Every copy that holds the password is wiped (review of #1008, item 3): the script is moved
        // into a Zeroizing buffer, serialised straight into another one, and that buffer is moved
        // into the returned C string, which `bastion_string_free` wipes.
        #[derive(serde::Serialize)]
        struct Out<'a> {
            script: Option<&'a str>,
            code: &'a str,
            message: &'a str,
        }
        let script = r.script.map(Zeroizing::new);
        let mut out = Zeroizing::new(Vec::with_capacity(script.as_ref().map_or(0, |s| s.len()) + 128));
        serde_json::to_writer(&mut *out, &Out { script: script.as_deref().map(String::as_str), code: &r.code, message: &r.message }).map_err(|e| e.to_string())?;
        let text = String::from_utf8(std::mem::take(&mut *out)).map_err(|e| e.to_string())?;
        Ok(to_c(text))
    })
}

/// B8: what importing a KeePass `.kdbx` would do, without secrets:
/// `{"rows":[{"title","username","folder","status":"new"|"duplicate"|"no-password"}]}`.
/// `password` (caller-owned bytes, zeroed by the caller) may be empty when `keyfile` is given.
///
/// # Safety
/// `path` valid NUL-terminated; `keyfile` NULL or NUL-terminated; `password` NULL or `len`
/// readable bytes; `v` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_keepass_preview_json(
    v: *const BastionCredentials,
    path: *const c_char,
    password: *const u8,
    password_len: usize,
    keyfile: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let (path, keyfile) = (required(path, "path")?, optional(keyfile, "keyfile")?);
        let pw = Zeroizing::new(secret(password, password_len, "password")?);
        let rows = vault(v)?.keepass_import_preview(path, pw.to_string(), keyfile).map_err(|e| e.to_string())?;
        let rows: Vec<_> = rows.iter().map(|r| json!({"title": r.title, "username": r.username, "folder": r.folder, "status": r.status})).collect();
        Ok(to_c(json!({ "rows": rows }).to_string()))
    })
}

/// B8: import every entry with a password into the vault and save it. `duplicates`: `skip`,
/// `replace` or `keep-both`. Returns `{"added","replaced","skippedDuplicates","skippedNoPassword","folder"}`.
///
/// # Safety
/// As [`bastion_credentials_keepass_preview_json`]; `duplicates` valid NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn bastion_credentials_keepass_import_json(
    v: *const BastionCredentials,
    path: *const c_char,
    password: *const u8,
    password_len: usize,
    keyfile: *const c_char,
    duplicates: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let (path, keyfile, dup) = (required(path, "path")?, optional(keyfile, "keyfile")?, required(duplicates, "duplicates")?);
        let pw = Zeroizing::new(secret(password, password_len, "password")?);
        let r = vault(v)?.keepass_import(path, pw.to_string(), keyfile, dup).map_err(|e| e.to_string())?;
        Ok(to_c(
            json!({"added": r.added, "replaced": r.replaced, "skippedDuplicates": r.skipped_duplicates, "skippedNoPassword": r.skipped_no_password, "folder": r.folder}).to_string(),
        ))
    })
}
