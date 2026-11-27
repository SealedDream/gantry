//! The shared-config workflow over the C ABI (ABI 89), the same calls the macOS app makes through
//! core-ffi's `SshWorkflow`: settings, placeholder answers, importing hosts with a change
//! baseline, previewing what changed in `~/.ssh/config` (+ `config.d`) since then, and applying
//! that refresh. Everything lives in `<data dir>/ssh-workflow.json`; config files are only read.
use std::ffi::c_char;
use std::ptr::null_mut;

use bastion_ffi::{SshWorkflow, WorkflowSettingsView};
use serde_json::{json, Value};

use crate::{guarded, library, required, set_ok, to_c, BastionLibrary};

unsafe fn workflow(data_dir: *const c_char) -> Result<std::sync::Arc<SshWorkflow>, String> {
    SshWorkflow::open(required(data_dir, "data_dir")?).map_err(|e| e.to_string())
}

/// Settings as JSON `{scanConfigD, placeholders, overrides, changeDetection, sshDir}` (`sshDir`
/// null = `~/.ssh`). Free the result.
///
/// # Safety
/// `data_dir` NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_ssh_workflow_settings_json(data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let s = workflow(data_dir)?.settings();
        Ok(to_c(
            json!({ "scanConfigD": s.scan_config_d, "placeholders": s.placeholders, "overrides": s.overrides,
                    "changeDetection": s.change_detection, "sshDir": s.ssh_dir })
            .to_string(),
        ))
    })
}

/// Replace the settings from JSON in the shape above (every key required). Turning change
/// detection off drops the baseline. 0 / -1.
///
/// # Safety
/// Strings NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_ssh_workflow_set_settings(data_dir: *const c_char, settings_json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let v: Value = serde_json::from_str(&required(settings_json, "settings")?).map_err(|e| format!("settings must be a JSON object: {e}"))?;
        let flag = |k: &str| v.get(k).and_then(Value::as_bool).ok_or_else(|| format!("settings need `{k}` (true/false)"));
        let ssh_dir = match v.get("sshDir") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err("`sshDir` must be a string or null".into()),
        };
        let view = WorkflowSettingsView {
            scan_config_d: flag("scanConfigD")?,
            placeholders: flag("placeholders")?,
            overrides: flag("overrides")?,
            change_detection: flag("changeDetection")?,
            ssh_dir,
        };
        workflow(data_dir)?.set_settings(view).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Placeholders as JSON `{values:{name: answer}, used:{name: hosts using it}}`. Free the result.
///
/// # Safety
/// `data_dir` NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_ssh_workflow_placeholders_json(data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let wf = workflow(data_dir)?;
        Ok(to_c(json!({ "values": wf.placeholder_values(), "used": wf.source_placeholders() }).to_string()))
    })
}

/// Answer placeholder `name` for every host (an empty `value` clears it). Bad names or values
/// that could inject config are refused. 0 / -1.
///
/// # Safety
/// Strings NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_ssh_workflow_set_placeholder(data_dir: *const c_char, name: *const c_char, value: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        workflow(data_dir)?.set_placeholder(required(name, "name")?, required(value, "value")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Import the hosts in `identities_json` (string array) from the configured sources and take the
/// sources as the change baseline. Saves the library. Returns the number added, or -1.
///
/// # Safety
/// Strings NUL-terminated UTF-8; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_ssh_workflow_import_hosts(data_dir: *const c_char, lib: *const BastionLibrary, identities_json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let ids: Vec<String> = serde_json::from_str(&required(identities_json, "identities")?).map_err(|_| "identities must be a JSON array of strings".to_string())?;
        let n = workflow(data_dir)?.import_hosts(library(lib)?, ids).map_err(|e| e.to_string())?;
        Ok(i32::try_from(n).unwrap_or(i32::MAX))
    })
}

/// What changed in the sources since the baseline, as JSON `{root, hasBaseline, files:[…],
/// hosts:[{identity, alias, group, sourceFile, kind: added|changed|removed, fields:[{field, old,
/// new}]}]}`. Nothing is written. Free the result.
///
/// # Safety
/// `data_dir` NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_ssh_workflow_changes_json(data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let p = workflow(data_dir)?.changes().map_err(|e| e.to_string())?;
        let hosts: Vec<Value> = p
            .hosts
            .iter()
            .map(|h| {
                json!({ "identity": h.identity, "alias": h.alias, "group": h.group, "sourceFile": h.source_file, "kind": h.kind,
                        "fields": h.fields.iter().map(|f| json!({ "field": f.field, "old": f.old, "new": f.new })).collect::<Vec<_>>() })
            })
            .collect();
        Ok(to_c(json!({ "root": p.root, "hasBaseline": p.has_baseline, "lastSyncedSecs": p.last_synced_secs, "files": p.files, "hosts": hosts }).to_string()))
    })
}

/// Apply the previewed changes to the library: changed hosts are updated, removed ones marked
/// (never deleted), added ones imported when `import_added` is non-zero. Saves the library and
/// takes the sources as the new baseline. Returns JSON `{added, updated, markedRemoved}`.
///
/// # Safety
/// `data_dir` NUL-terminated UTF-8; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_ssh_workflow_apply_refresh_json(data_dir: *const c_char, lib: *const BastionLibrary, import_added: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let r = workflow(data_dir)?.apply_refresh(library(lib)?, import_added != 0).map_err(|e| e.to_string())?;
        Ok(to_c(json!({ "added": r.added, "updated": r.updated, "markedRemoved": r.marked_removed }).to_string()))
    })
}
