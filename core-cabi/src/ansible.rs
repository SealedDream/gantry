//! Ansible over the C ABI (ABI 90), the calls Native Mac and Tauri make: export the library's SSH
//! connections as an inventory, and build the validated argv for an ad-hoc or playbook run. The
//! host spawns `argv[0]` with the rest (for example with `bastion_terminal_spawn`), never a shell.
use std::ffi::c_char;
use std::ptr::null_mut;

use bastion_ffi::{ansible_remote_plan, ansible_run_plan, ansible_task, AnsibleRunInput};
use serde_json::{json, Value};

use crate::{guarded, optional, required, to_c, BastionLibrary};

/// Write the SSH connections in `ids_json` (NULL = all; a JSON array of connection or folder ids)
/// to `path` as an Ansible inventory, YAML when `yaml` is non-zero else INI (owner-only, atomic,
/// no secrets). Returns `{exported, skipped:["name: reason", …]}`; NULL on error. Free the result.
///
/// # Safety
/// `lib` live; strings NUL-terminated UTF-8 (`ids_json` may be NULL); `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_export_ansible_inventory_json(lib: *const BastionLibrary, path: *const c_char, ids_json: *const c_char, yaml: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let ids = optional(ids_json, "ids")?
            .map(|s| serde_json::from_str::<Vec<String>>(&s).map_err(|_| "ids must be a JSON array of strings".to_string()))
            .transpose()?;
        let lib = lib.as_ref().map(|l| &l.0).ok_or_else(|| "library handle is NULL".to_string())?;
        let v = lib.export_ansible_inventory(required(path, "path")?, ids, yaml != 0).map_err(|e| e.to_string())?;
        Ok(to_c(json!({ "exported": v.exported, "skipped": v.skipped }).to_string()))
    })
}

/// Check a run sheet and return `{argv:[…], warnings:[…]}` (argv[0] is `ansible` or
/// `ansible-playbook`), or NULL with the first problem in `err`. Input JSON: `{kind: "adhoc" |
/// "playbook", inventory, pattern, module, moduleArgs, playbook, limit, check, diff, become, forks,
/// verbosity, tags, extraVars, remote}`; unused fields may be omitted. With `remote: {home, runId,
/// uploadFolder}` (a control-host run) the result also has `remote: {dir, dirs, uploads:[{local,
/// remote}], argv, command}`. With `task: {mode: "local" | "wsl" | "host", hostName}` (Save as
/// Task) the result also has `task: {name, program, args, runOn}`. Free the result.
///
/// # Safety
/// `input_json` NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_ansible_run_plan_json(input_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let v: Value = serde_json::from_str(&required(input_json, "input")?).map_err(|e| format!("run input must be a JSON object: {e}"))?;
        let text = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let flag = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
        let forks = match v.get("forks") {
            None | Some(Value::Null) => None,
            Some(f) => Some(f.as_u64().and_then(|f| u32::try_from(f).ok()).ok_or("forks must be a whole number")?),
        };
        let verbosity = v.get("verbosity").and_then(Value::as_u64).map_or(Ok(0), |n| u8::try_from(n).map_err(|_| "verbosity is 0 to 4"))?;
        let input = AnsibleRunInput {
            kind: text("kind"),
            inventory: text("inventory"),
            pattern: text("pattern"),
            module: text("module"),
            module_args: text("moduleArgs"),
            playbook: text("playbook"),
            limit: v.get("limit").and_then(Value::as_str).map(str::to_string),
            check: flag("check"),
            diff: flag("diff"),
            become_root: flag("become"),
            forks,
            verbosity,
            tags: v.get("tags").and_then(Value::as_str).map(str::to_string),
            extra_vars: v.get("extraVars").and_then(Value::as_str).map(str::to_string),
        };
        let remote = match v.get("remote") {
            Some(r) if r.is_object() => {
                let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
                let p = ansible_remote_plan(input.clone(), s("home"), s("runId"), r.get("uploadFolder").and_then(Value::as_bool).unwrap_or(false)).map_err(|e| e.to_string())?;
                let uploads: Vec<Value> = p.uploads.iter().map(|u| json!({ "local": u.local, "remote": u.remote })).collect();
                Some(json!({ "dir": p.dir, "dirs": p.dirs, "uploads": uploads, "argv": p.argv, "command": p.command }))
            }
            _ => None,
        };
        let task = match v.get("task") {
            Some(t) if t.is_object() => {
                let mode = t.get("mode").and_then(Value::as_str).unwrap_or_default().to_string();
                let host = t.get("hostName").and_then(Value::as_str).map(str::to_string);
                let t = ansible_task(input.clone(), mode, host).map_err(|e| e.to_string())?;
                Some(json!({ "name": t.name, "program": t.program, "args": t.args, "runOn": t.run_on }))
            }
            _ => None,
        };
        let plan = ansible_run_plan(input).map_err(|e| e.to_string())?;
        Ok(to_c(json!({ "argv": plan.argv, "warnings": plan.warnings, "remote": remote, "task": task }).to_string()))
    })
}
