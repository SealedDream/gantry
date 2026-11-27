//! LOG-ERRCODES: support codes and log redaction for Native Windows. C ABI 146.

use crate::{optional, to_c};
use std::os::raw::c_char;

/// `GT-` code for an error `message` in `area`. NULL arguments read as empty. Free the result
/// with `bastion_string_free`.
///
/// # Safety
/// Each argument must be NULL or a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn bastion_error_code(area: *const c_char, message: *const c_char) -> *mut c_char {
    let area = optional(area, "area").ok().flatten().unwrap_or_default();
    let message = optional(message, "message").ok().flatten().unwrap_or_default();
    to_c(bastion_core::errcodes::classify(&area, &message).to_string())
}

/// `text` with secrets, user names, host names and addresses removed. Free the result with
/// `bastion_string_free`.
///
/// # Safety
/// `text` must be NULL or a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn bastion_log_redact(text: *const c_char) -> *mut c_char {
    let text = optional(text, "text").ok().flatten().unwrap_or_default();
    to_c(bastion_core::errcodes::redact(&text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn exports_classify_and_redact() {
        let a = CString::new("SSH").unwrap();
        let m = CString::new("Connection timed out").unwrap();
        let t = CString::new("password=x 10.0.0.1").unwrap();
        unsafe {
            let c = bastion_error_code(a.as_ptr(), m.as_ptr());
            assert_eq!(CStr::from_ptr(c).to_str().unwrap(), "GT-NET-003");
            crate::bastion_string_free(c);
            let r = bastion_log_redact(t.as_ptr());
            assert_eq!(CStr::from_ptr(r).to_str().unwrap(), "password=(secret) (host)");
            crate::bastion_string_free(r);
            let n = bastion_error_code(std::ptr::null(), std::ptr::null());
            assert_eq!(CStr::from_ptr(n).to_str().unwrap(), "GT-APP-000");
            crate::bastion_string_free(n);
        }
    }
}
