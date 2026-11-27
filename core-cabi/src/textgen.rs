//! The password generator and `$Name$` variable substitution for hosts on the C ABI
//! (`bastion_ffi::generate_password` / `password_strength_bits`, `Library::variables` / `substitute`).
//! Substitution only ever sees plain variables: secret ones are listed by name and refused.
use std::ffi::c_char;

use bastion_ffi::{generate_password, password_strength_bits};
use serde_json::json;

use crate::{guarded, handle, required, to_c, BastionLibrary};

/// A random password of `length` characters (12–128), or NULL with the reason in `*err`. The text is
/// handed to the host once and not kept by the core. Free the result.
///
/// # Safety
/// `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_generate_password(length: u32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || Ok(to_c(generate_password(length).map_err(|e| e.to_string())?)))
}

/// Rough strength in bits for the generator's indicator; 0 for NULL or invalid text.
///
/// # Safety
/// `password` NULL or a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn bastion_password_strength_bits(password: *const c_char) -> f64 {
    guarded(std::ptr::null_mut(), 0.0, || Ok(password_strength_bits(required(password, "password")?)))
}

/// `{plain: [{name, value}], secret: [name]}`: the variables text for connection `id` may use. Secret
/// variables come by name only. Free the result.
///
/// # Safety
/// `lib` a live handle; `id` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_variables_json(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let v = handle(lib)?.variables(required(id, "connection id")?).map_err(|e| e.to_string())?;
        Ok(to_c(
            json!({
                "plain": v.plain.iter().map(|p| json!({ "name": p.name, "value": p.value })).collect::<Vec<_>>(),
                "secret": v.secret,
            })
            .to_string(),
        ))
    })
}

/// `template` with `$Name$` replaced for connection `id` (`$$` is a literal `$`). An unknown or secret
/// variable is refused: NULL with the reason in `*err`. Free the result.
///
/// # Safety
/// `lib` a live handle; `id`, `template` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_substitute(
    lib: *const BastionLibrary,
    id: *const c_char,
    template: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let text = handle(lib)?.substitute(required(id, "connection id")?, required(template, "text")?).map_err(|e| e.to_string())?;
        Ok(to_c(text))
    })
}
