//! External credential providers over the C ABI: 1Password (`op` CLI), KeePass `.kdbx` and
//! HashiCorp Vault KV. All three are read-only and keep no decrypted cache.
//!
//! The host opens a provider (`bastion_provider_open_*`), unlocks it with a caller-owned byte
//! buffer it zeroes afterwards, and registers it (`bastion_provider_register`). Secrets never
//! come back out: an SSH connect with [`crate::LOGIN_PROVIDER`] and `password` =
//! `"<provider id>:<item>"` (for example `onepassword:op://Prod/db/password`,
//! `keepass:<entry uuid>#username`, `hcvault:secret/prod/db#password`) reads the secret inside
//! the core at dial time. [`bastion_provider_check_item`] tests a reference without revealing it.
use std::ffi::c_char;
use std::path::Path;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_core::external_providers::{ExternalProvider, ProviderCheck, ProviderRegistry};
use bastion_core::vault::Secret;
use serde_json::json;
use zeroize::Zeroizing;

use crate::{guarded, optional, required, set_ok, to_c};

/// Result of [`bastion_provider_unlock`] and [`bastion_provider_check_item`]: it worked.
pub const PROVIDER_OK: i32 = 0;
/// The password, key file or token was refused (or the provider is signed out).
pub const PROVIDER_AUTH_FAILED: i32 = 1;
/// The item does not exist (check only).
pub const PROVIDER_NOT_FOUND: i32 = 2;

/// Opaque handle for one opened provider.
pub struct BastionProvider(Arc<ExternalProvider>);

/// # Safety
/// `p` NULL or a live handle.
unsafe fn handle<'a>(p: *const BastionProvider) -> Result<&'a Arc<ExternalProvider>, String> {
    p.as_ref().map(|p| &p.0).ok_or_else(|| "provider handle is NULL".to_string())
}

/// # Safety
/// `ptr` NULL (with `len` 0) or `len` readable bytes.
unsafe fn secret(ptr: *const u8, len: usize) -> Result<Option<Secret>, String> {
    if ptr.is_null() || len == 0 {
        return Ok(None);
    }
    let bytes = Zeroizing::new(std::slice::from_raw_parts(ptr, len).to_vec());
    std::str::from_utf8(&bytes).map(|s| Some(Secret::new(s))).map_err(|_| "secret is not valid UTF-8".to_string())
}

fn boxed(kind: ExternalProvider) -> *mut BastionProvider {
    Box::into_raw(Box::new(BastionProvider(Arc::new(kind))))
}

fn code(c: ProviderCheck) -> i32 {
    match c {
        ProviderCheck::Ok => PROVIDER_OK,
        ProviderCheck::AuthFailed => PROVIDER_AUTH_FAILED,
        ProviderCheck::NotFound => PROVIDER_NOT_FOUND,
    }
}

/// Read the secret for `"<provider id>:<item>"` from a registered provider, inside the core.
pub(crate) fn resolve(reference: &str) -> Result<Secret, String> {
    ProviderRegistry::global().resolve(reference).map_err(|e| e.to_string())
}

/// Open 1Password through its CLI. `op_path` NULL looks `op` up on PATH and the usual install
/// dirs; `account` NULL uses op's default account. Desktop-app sign-in needs no unlock; a
/// service-account token can be given with [`bastion_provider_unlock`].
///
/// # Safety
/// Strings NULL or valid NUL-terminated; `err` NULL or writable. Free with [`bastion_provider_free`].
#[no_mangle]
pub unsafe extern "C" fn bastion_provider_open_onepassword(op_path: *const c_char, account: *const c_char, err: *mut *mut c_char) -> *mut BastionProvider {
    guarded(err, null_mut(), || {
        let p = ExternalProvider::onepassword(optional(op_path, "op_path")?, optional(account, "account")?).map_err(|e| e.to_string())?;
        Ok(boxed(p))
    })
}

/// Open a KeePass `.kdbx` file (read-only). It starts locked.
///
/// # Safety
/// `path` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_provider_open_keepass(path: *const c_char, err: *mut *mut c_char) -> *mut BastionProvider {
    guarded(err, null_mut(), || Ok(boxed(ExternalProvider::keepass(required(path, "path")?))))
}

/// Open a HashiCorp Vault KV mount. `kv_version` 1 or 2; `namespace` NULL for none. `base_url`
/// must be https (http only on loopback). It starts locked.
///
/// # Safety
/// Strings valid NUL-terminated (`namespace` may be NULL); `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_provider_open_hcvault(base_url: *const c_char, kv_version: i32, namespace: *const c_char, err: *mut *mut c_char) -> *mut BastionProvider {
    guarded(err, null_mut(), || {
        let p = ExternalProvider::hcvault(&required(base_url, "base_url")?, kv_version.into(), optional(namespace, "namespace")?).map_err(|e| e.to_string())?;
        Ok(boxed(p))
    })
}

/// Unlock with `secret` (`len` bytes of UTF-8, zeroed by the caller afterwards):
/// KeePass master password (may be empty when `keyfile_path` is given), the Vault token, or a
/// 1Password service-account token (empty clears it). `keyfile_path` is for KeePass only.
/// Returns [`PROVIDER_OK`], [`PROVIDER_AUTH_FAILED`], or -1 with `*err`.
///
/// # Safety
/// `p` live; `secret` NULL or `len` readable bytes; `keyfile_path` NULL or NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_provider_unlock(p: *const BastionProvider, secret_ptr: *const u8, len: usize, keyfile_path: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let kind = handle(p)?;
        let s = secret(secret_ptr, len)?;
        let keyfile = optional(keyfile_path, "keyfile_path")?.filter(|k| !k.is_empty());
        kind.unlock(s, keyfile.as_deref().map(Path::new)).map(code).map_err(|e| e.to_string())
    })
}

/// Forget the unlock (password, key file or token). NULL is ignored.
///
/// # Safety
/// `p` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_provider_lock(p: *const BastionProvider) {
    if let Some(p) = p.as_ref() {
        p.0.lock();
    }
}

/// `{"id":"keepass","status":"available"|"locked"|"unavailable","reason":…}`.
///
/// # Safety
/// `p` live; `err` NULL or writable. Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_provider_status_json(p: *const BastionProvider, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let prov = handle(p)?;
        let (status, reason) = prov.status();
        Ok(to_c(json!({ "id": prov.id(), "status": status, "reason": reason }).to_string()))
    })
}

/// Entries without secrets: KeePass gives `{"items":[{"id","title","username","group":[…]}]}`;
/// 1Password and Vault cannot list and give `{"items":[]}`.
///
/// # Safety
/// `p` live; `err` NULL or writable. Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_provider_items_json(p: *const BastionProvider, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let items: Vec<_> = handle(p)?
            .items()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|i| json!({ "id": i.id, "title": i.title, "username": i.username, "group": i.group }))
            .collect();
        Ok(to_c(json!({ "items": items }).to_string()))
    })
}

/// Check that `item` resolves, without returning the secret. [`PROVIDER_OK`],
/// [`PROVIDER_AUTH_FAILED`], [`PROVIDER_NOT_FOUND`], or -1 with `*err`.
///
/// # Safety
/// `p` live; `item` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_provider_check_item(p: *const BastionProvider, item: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let item = required(item, "item")?;
        handle(p)?.check_item(&item).map(code).map_err(|e| e.to_string())
    })
}

/// Make `LOGIN_PROVIDER` connects read from this provider, under its id (`onepassword`,
/// `keepass`, `hcvault`). 0 / -1.
///
/// # Safety
/// `p` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_provider_register(p: *const BastionProvider, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        ProviderRegistry::global().register(handle(p)?.clone());
        set_ok()
    })
}

/// Lock and drop every registered provider (the "Lock Credentials" action). Open handles stay
/// valid but locked.
#[no_mangle]
pub extern "C" fn bastion_providers_lock_all() {
    ProviderRegistry::global().lock_all();
}

/// Release a handle. It stays registered (and unlocked) until [`bastion_providers_lock_all`]
/// or another provider with the same id is registered. NULL is ignored.
///
/// # Safety
/// `p` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_provider_free(p: *mut BastionProvider) {
    if !p.is_null() {
        drop(Box::from_raw(p));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::fs::PermissionsExt;

    /// `LOGIN_PROVIDER` resolves through the registry inside the core; unknown ids are refused.
    #[test]
    fn provider_login_resolves_inside_the_core() {
        let d = tempfile::tempdir().unwrap();
        let op = d.path().join("op");
        std::fs::write(&op, "#!/bin/sh\nprintf 'pw-for-%s' \"$4\"\n").unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = CString::new(op.to_str().unwrap()).unwrap();
        let mut err = null_mut();
        unsafe {
            let p = bastion_provider_open_onepassword(path.as_ptr(), std::ptr::null(), &mut err);
            assert!(!p.is_null());
            let item = CString::new("Prod/db/pw").unwrap();
            assert_eq!(bastion_provider_check_item(p, item.as_ptr(), &mut err), PROVIDER_OK);
            assert!(crate::session::login_from(crate::LOGIN_PROVIDER, Some("onepassword:Prod/db/pw".into()), None, None).is_err(), "not registered yet");
            assert_eq!(bastion_provider_register(p, &mut err), 0);
            bastion_provider_free(p);
        }
        match crate::session::login_from(crate::LOGIN_PROVIDER, Some("onepassword:Prod/db/pw".into()), None, None).unwrap() {
            bastion_ffi::SshLogin::Password { password } => assert_eq!(password, "pw-for-op://Prod/db/pw"),
            _ => panic!("expected a password login"),
        }
        assert!(crate::session::login_from(crate::LOGIN_PROVIDER, Some("nope:x".into()), None, None).is_err());
        assert!(crate::session::login_from(crate::LOGIN_PROVIDER, None, None, None).is_err());
        bastion_providers_lock_all();
        assert!(resolve("onepassword:Prod/db/pw").is_err(), "lock_all unregisters");
    }
}
