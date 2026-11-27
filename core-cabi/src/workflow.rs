//! Inspector data over the C ABI: a connection's notes, and for hosts imported from an OpenSSH
//! config their effective values and the user's personal overrides (`ssh-workflow.json` in the
//! data directory, the same store the macOS app and `SessionManager` connects read). No secrets:
//! overrides hold host names, ports, paths and placeholder answers only.
use std::collections::HashMap;
use std::ffi::c_char;
use std::ptr::null_mut;

use bastion_ffi::{HostOverrideView, SshWorkflow};
use serde_json::{json, Value};

use crate::{guarded, handle, library, required, set_ok, to_c, BastionLibrary};

/// The connection's notes ("" when none).
///
/// # Safety
/// `id` valid NUL-terminated; `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_notes(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(handle(lib)?.notes(required(id, "id")?).map_err(|e| e.to_string())?)))
}

/// Replace the connection's notes. Returns 0, or -1. Call `bastion_library_save` after.
///
/// # Safety
/// Strings valid NUL-terminated; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_set_notes(lib: *const BastionLibrary, id: *const c_char, notes: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.set_notes(required(id, "id")?, required(notes, "notes")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Effective values of an imported connection as JSON `{identity, hostname, user, port,
/// identityFile, proxyJump, credentialRef, unresolved:[…], sourcePlaceholders:[…]}`, or `null`
/// for a connection created in Bastion. Nothing is written.
///
/// # Safety
/// Strings valid NUL-terminated; `lib` live; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_ssh_effective_json(data_dir: *const c_char, lib: *const BastionLibrary, connection_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let wf = SshWorkflow::open(required(data_dir, "data_dir")?).map_err(|e| e.to_string())?;
        let e = wf.effective_for(library(lib)?, required(connection_id, "connection_id")?).map_err(|e| e.to_string())?;
        let v = e.map_or(Value::Null, |e| {
            json!({
                "identity": e.identity, "hostname": e.hostname, "user": e.user, "port": e.port,
                "identityFile": e.identity_file, "proxyJump": e.proxy_jump, "credentialRef": e.credential_ref,
                "unresolved": e.unresolved, "sourcePlaceholders": e.source_placeholders,
            })
        });
        Ok(to_c(v.to_string()))
    })
}

/// The personal overrides of the imported host `identity` as JSON `{user, hostname, port,
/// identityFile, proxyJump, credentialRef, placeholders:{name: value}}` (all null/empty when none).
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_ssh_override_json(data_dir: *const c_char, identity: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let wf = SshWorkflow::open(required(data_dir, "data_dir")?).map_err(|e| e.to_string())?;
        let o = wf.get_override(required(identity, "identity")?);
        Ok(to_c(
            json!({
                "user": o.user, "hostname": o.hostname, "port": o.port, "identityFile": o.identity_file,
                "proxyJump": o.proxy_jump, "credentialRef": o.credential_ref, "placeholders": o.placeholders,
            })
            .to_string(),
        ))
    })
}

/// Replace the overrides of `identity` from JSON in the shape [`bastion_ssh_override_json`]
/// returns; blank strings mean "use the source value". Saved at once. Returns 0, or -1.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_ssh_set_override(data_dir: *const c_char, identity: *const c_char, override_json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let v: Value = serde_json::from_str(&required(override_json, "override")?).map_err(|e| format!("override must be a JSON object: {e}"))?;
        let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let port = match v.get("port") {
            None | Some(Value::Null) => None,
            Some(p) => Some(p.as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0).ok_or_else(|| "port must be 1 to 65535".to_string())?),
        };
        let placeholders: HashMap<String, String> = match v.get("placeholders") {
            None | Some(Value::Null) => HashMap::new(),
            Some(p) => serde_json::from_value(p.clone()).map_err(|_| "placeholders must map names to strings".to_string())?,
        };
        let o = HostOverrideView {
            user: text("user"),
            hostname: text("hostname"),
            port,
            identity_file: text("identityFile"),
            proxy_jump: text("proxyJump"),
            credential_ref: text("credentialRef"),
            placeholders,
        };
        let wf = SshWorkflow::open(required(data_dir, "data_dir")?).map_err(|e| e.to_string())?;
        wf.set_override(required(identity, "identity")?, o).map_err(|e| e.to_string())?;
        set_ok()
    })
}
