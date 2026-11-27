//! Updates from GitHub releases for hosts on the C ABI: check the latest release's signed manifest,
//! then download one of its files, verified (`bastion_ffi::check_for_updates` / `download_update`).
//! Both block on the network: call them off the UI thread. Installing is left to the host.
use std::os::raw::c_char;

use bastion_ffi::{check_for_updates, download_update};
use serde_json::json;

use crate::{guarded, required, to_c};

/// `{installed, latest, available, notes, url, manifestExpires, files: [{name, size}]}` for the latest
/// release, or NULL with the reason in `*err` (bad signature, expired, downgrade, wrong channel, host
/// not allowed, network). Free the result.
///
/// # Safety
/// `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_update_check_json(err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let s = check_for_updates().map_err(|e| e.to_string())?;
        Ok(to_c(
            json!({
                "installed": s.installed, "latest": s.latest, "available": s.available, "notes": s.notes,
                "url": s.url, "manifestExpires": s.manifest_expires,
                "files": s.files.iter().map(|f| json!({ "name": f.name, "size": f.size })).collect::<Vec<_>>(),
            })
            .to_string(),
        ))
    })
}

/// Download `file_name` from the latest release into the existing directory `dest_dir`, checked
/// against the signed size and SHA-256, and return its path (free it); NULL with the reason in `*err`.
///
/// # Safety
/// `file_name` and `dest_dir` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_update_download(file_name: *const c_char, dest_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let path = download_update(required(file_name, "file name")?, required(dest_dir, "destination")?).map_err(|e| e.to_string())?;
        Ok(to_c(path))
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};

    use super::*;

    #[test]
    fn download_refuses_missing_arguments() {
        let mut err = std::ptr::null_mut();
        let dir = CString::new("/nonexistent").unwrap();
        assert!(unsafe { bastion_update_download(std::ptr::null(), dir.as_ptr(), &mut err) }.is_null());
        assert!(unsafe { CStr::from_ptr(err) }.to_str().unwrap().contains("file name"));
        unsafe { crate::bastion_string_free(err) };
    }
}
