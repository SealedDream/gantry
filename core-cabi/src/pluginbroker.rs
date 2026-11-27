//! PLUG-02c: the plugin broker's app-facing decisions for Native Windows, over
//! `bastion_ffi::pluginbroker`. The policy keys in force, whether a plugin may load, and the
//! warning before a plugin field value that matches the entry's saved password is stored.
use std::os::raw::c_char;

use bastion_ffi::{plugin_field_save_warning, plugin_may_load, plugin_policy_state, PluginPolicyView};
use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::{guarded, optional, optional_text, required, to_c};

fn policy_json(v: PluginPolicyView) -> Value {
    // Destructured without `..` (H09): a field added to the record fails to compile here.
    let PluginPolicyView {
        error,
        plugins_disabled,
        official_only,
        allowed_ids,
        forbid_unverified,
        stop_helpers_on_credentials_lock,
        forbid_unencrypted,
        forbid_tls_off,
    } = v;
    json!({
        "error": error,
        "pluginsDisabled": plugins_disabled,
        "officialOnly": official_only,
        "allowedIds": allowed_ids,
        "forbidUnverified": forbid_unverified,
        "stopHelpersOnCredentialsLock": stop_helpers_on_credentials_lock,
        "forbidUnencrypted": forbid_unencrypted,
        "forbidTlsOff": forbid_tls_off,
    })
}

/// The plugin keys of the policy in force as JSON: `{error, pluginsDisabled, officialOnly, allowedIds,
/// forbidUnverified, stopHelpersOnCredentialsLock, forbidUnencrypted, forbidTlsOff}`. `allowedIds` is null
/// when the policy has no list. `error` is set when the managed policy cannot be used; then `pluginsDisabled`
/// is true. Free the result.
#[no_mangle]
pub extern "C" fn bastion_plugin_policy_state_json() -> *mut c_char {
    to_c(policy_json(plugin_policy_state()).to_string())
}

/// Whether plugin `id` may load. `tier`: `official`, `external` or `unverified`. `allow_unverified`: the user's
/// "Allow unverified plugins" setting (non-zero = on); `safe_mode`: the app's Safe mode (non-zero = on).
/// Returns null when it may load, else the reason in the core's words (free it). On a bad argument, returns
/// null and sets `err`: check `err` first.
///
/// # Safety
/// `id` and `tier` are NUL-terminated UTF-8; `err` is null or points to writable storage.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_may_load(id: *const c_char, tier: *const c_char, allow_unverified: i32, safe_mode: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let id = required(id, "id")?;
        let tier = required(tier, "tier")?;
        Ok(optional_text(plugin_may_load(id, tier, allow_unverified != 0, safe_mode != 0)))
    })
}

/// Call before storing a plugin field value. `entry_password`: the entry's saved password while credentials
/// are unlocked, else null; an empty string counts as null (nothing is compared). Returns the warning to show (the user may cancel or confirm; free it), or null to
/// save. On a bad argument, returns null and sets `err`: check `err` first. The core keeps no copy of the
/// password or the value; the host wipes its own buffer.
///
/// # Safety
/// `value` and `entry_password` (if not null) are NUL-terminated UTF-8; `err` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_plugin_field_save_warning(value: *const c_char, entry_password: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let mut pw = optional(entry_password, "entry_password");
        let value = match required(value, "value") {
            Ok(v) => v,
            Err(e) => {
                if let Ok(Some(p)) = pw.as_mut() {
                    p.zeroize();
                }
                return Err(e);
            }
        };
        Ok(optional_text(plugin_field_save_warning(value, pw?)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bastion_string_free;
    use std::ffi::{CStr, CString};
    use std::ptr::null_mut;

    unsafe fn take(p: *mut c_char) -> Option<String> {
        if p.is_null() {
            return None;
        }
        let s = CStr::from_ptr(p).to_string_lossy().into_owned();
        bastion_string_free(p);
        Some(s)
    }

    #[test]
    fn policy_state_has_every_plugin_key() {
        let v: Value = serde_json::from_str(&unsafe { take(bastion_plugin_policy_state_json()) }.unwrap()).unwrap();
        for k in ["error", "pluginsDisabled", "officialOnly", "allowedIds", "forbidUnverified", "stopHelpersOnCredentialsLock", "forbidUnencrypted", "forbidTlsOff"] {
            assert!(v.get(k).is_some(), "{k}");
        }
    }

    #[test]
    fn may_load_official_and_refuses_external_and_bad_arguments() {
        let id = CString::new("pg").unwrap();
        let mut err = null_mut();
        unsafe {
            let off = CString::new("official").unwrap();
            assert_eq!(take(bastion_plugin_may_load(id.as_ptr(), off.as_ptr(), 0, 0, &mut err)), None);
            assert!(err.is_null());
            let ext = CString::new("external").unwrap();
            assert_eq!(take(bastion_plugin_may_load(id.as_ptr(), ext.as_ptr(), 0, 0, &mut err)).as_deref(), Some("External plugins are not available yet"));
            assert!(take(bastion_plugin_may_load(id.as_ptr(), off.as_ptr(), 0, 1, &mut err)).unwrap().contains("Safe mode"));
            assert_eq!(take(bastion_plugin_may_load(std::ptr::null(), off.as_ptr(), 0, 0, &mut err)), None);
            assert!(take(err).is_some());
        }
    }

    #[test]
    fn field_warning_only_for_the_password() {
        let pw = CString::new("hunter22").unwrap();
        let mut err = null_mut();
        unsafe {
            let same = CString::new("hunter22").unwrap();
            assert!(take(bastion_plugin_field_save_warning(same.as_ptr(), pw.as_ptr(), &mut err)).is_some());
            let other = CString::new("postgres").unwrap();
            assert_eq!(take(bastion_plugin_field_save_warning(other.as_ptr(), pw.as_ptr(), &mut err)), None);
            assert_eq!(take(bastion_plugin_field_save_warning(same.as_ptr(), std::ptr::null(), &mut err)), None);
            assert!(err.is_null());
            assert_eq!(take(bastion_plugin_field_save_warning(std::ptr::null(), pw.as_ptr(), &mut err)), None);
            assert!(take(err).is_some());
        }
    }
}
