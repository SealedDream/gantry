//! Key manager over the C ABI (v39, merged after 53): generate ed25519, inspect and convert
//! OpenSSH / PEM / PuTTY `.ppk` keys through `bastion_core::keymanager`, so every app imports
//! and converts keys by the same rules. FIDO2 `sk-` keys report `"hardware":true`.
use std::ffi::c_char;
use std::ptr::null_mut;

use crate::{guarded, optional, required, to_c};

/// A new ed25519 key. `passphrase` NULL or empty = unencrypted. Returns
/// `{"algorithm","fingerprint","comment","public_openssh","format","hardware","private_openssh"}`;
/// store `private_openssh` in the vault and never log it. Free with `bastion_string_free`.
///
/// # Safety
/// Strings NULL (where optional) or valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_keys_generate_json(comment: *const c_char, passphrase: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let comment = optional(comment, "comment")?.unwrap_or_default();
        let out = bastion_ffi::keys_generate(comment, optional(passphrase, "passphrase")?).map_err(|e| e.to_string())?;
        Ok(to_c(out))
    })
}

/// Describe a private key (OpenSSH, PEM or `.ppk`) without key material:
/// `{"algorithm","fingerprint","comment","public_openssh","format","hardware"}`.
///
/// # Safety
/// Strings NULL (where optional) or valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_keys_inspect_json(key_text: *const c_char, passphrase: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = bastion_ffi::keys_inspect(required(key_text, "key_text")?, optional(passphrase, "passphrase")?).map_err(|e| e.to_string())?;
        Ok(to_c(out))
    })
}

/// Import a key as OpenSSH under `new_passphrase` (NULL/empty = plain); `comment` NULL or
/// empty keeps the key's own. Returns the same shape as `bastion_keys_generate_json`.
///
/// # Safety
/// Strings NULL (where optional) or valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_keys_convert_json(key_text: *const c_char, passphrase: *const c_char, new_passphrase: *const c_char, comment: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out = bastion_ffi::keys_convert(
            required(key_text, "key_text")?,
            optional(passphrase, "passphrase")?,
            optional(new_passphrase, "new_passphrase")?,
            optional(comment, "comment")?.unwrap_or_default(),
        )
        .map_err(|e| e.to_string())?;
        Ok(to_c(out))
    })
}
