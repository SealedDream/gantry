//! Saved tasks over the C ABI (ABI 92), as the Windows Tasks section uses them. Forwards to
//! `bastion_ffi`'s task calls, so validation, policy, the confirmation rule for custom tasks on
//! sensitive connections and the `task` audit entries stay in the core.
//!
//! Task JSON: `{id, name, favorite, builtin, kind, program, args, runOn, timeoutSecs}`; `kind` is
//! `ping`, `trace_route`, `dns_lookup`, `tcp_check` or `custom`, `runOn` `local` or `ssh`.
use std::collections::HashMap;
use std::ffi::c_char;
use std::ptr::null_mut;
use std::sync::Arc;

use bastion_ffi::{TaskHookView, TaskRun, TaskRunView, TaskView};
use serde_json::{json, Value};

use crate::session::{login_from, BastionSessionManager};
use crate::{guarded, handle, library, optional, required, set_ok, to_c, BastionLibrary};

/// Opaque handle for one task run. Free with [`bastion_task_run_free`].
pub struct BastionTaskRun(Arc<TaskRun>);

unsafe fn run<'a>(r: *const BastionTaskRun) -> Result<&'a TaskRun, String> {
    r.as_ref().map(|r| &*r.0).ok_or_else(|| "task run handle is NULL".to_string())
}

fn task_json(t: &TaskView) -> Value {
    json!({ "id": t.id, "name": t.name, "favorite": t.favorite, "builtin": t.builtin, "kind": t.kind,
            "program": t.program, "args": t.args, "runOn": t.run_on, "timeoutSecs": t.timeout_secs })
}

fn task_from(v: &Value) -> Result<TaskView, String> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let args = match v.get("args") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(str::to_string).ok_or_else(|| "args must be strings".to_string())).collect::<Result<_, _>>()?,
        Some(_) => return Err("args must be a JSON array".into()),
    };
    let timeout = v.get("timeoutSecs").and_then(Value::as_u64).unwrap_or(u64::from(bastion_core::tasks::DEFAULT_TIMEOUT_SECS));
    Ok(TaskView {
        id: s("id"),
        name: s("name"),
        favorite: v.get("favorite").and_then(Value::as_bool).unwrap_or(false),
        builtin: false,
        kind: if s("kind").is_empty() { "custom".into() } else { s("kind") },
        program: s("program"),
        args,
        run_on: if s("runOn").is_empty() { "local".into() } else { s("runOn") },
        timeout_secs: u32::try_from(timeout).map_err(|_| "timeoutSecs is too large".to_string())?,
    })
}

fn run_json(o: &TaskRunView) -> Value {
    json!({ "state": o.state, "exit": o.exit, "stdout": o.stdout, "stderr": o.stderr, "error": o.error, "millis": o.millis })
}

/// Built-in tasks first, then the library's own, as a JSON array of task objects.
///
/// # Safety
/// `lib` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_tasks_json(lib: *const BastionLibrary, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(Value::Array(handle(lib)?.tasks().iter().map(task_json).collect()).to_string())))
}

/// Add (`id` missing or empty) or replace a custom task. Returns its id; NULL with `*err` when the
/// core refuses it (built-in, empty name or program, too many or too long args, bad timeout).
///
/// # Safety
/// `lib` live; `task_json` valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_tasks_save_json(lib: *const BastionLibrary, task_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let v: Value = serde_json::from_str(&required(task_json, "task_json")?).map_err(|_| "task_json must be a JSON object".to_string())?;
        if !v.is_object() {
            return Err("task_json must be a JSON object".into());
        }
        Ok(to_c(handle(lib)?.save_task(task_from(&v)?).map_err(|e| e.to_string())?))
    })
}

/// Remove a custom task and every hook that used it. Returns 0, or -1 with `*err` set.
///
/// # Safety
/// `lib` live; `id` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_tasks_remove(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.remove_task(required(id, "id")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Mark a task (built-in or custom) as a favourite or not. Returns 0, or -1 with `*err` set.
///
/// # Safety
/// `lib` live; `id` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_tasks_set_favorite(lib: *const BastionLibrary, id: *const c_char, favorite: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.set_task_favorite(required(id, "id")?, favorite != 0).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Hooks on a connection or folder: `[{taskId, when, target, snippetId}]` (B5).
///
/// # Safety
/// `lib` live; `connection_id` valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_task_hooks_json(lib: *const BastionLibrary, connection_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let hooks = handle(lib)?.task_hooks(required(connection_id, "connection_id")?).map_err(|e| e.to_string())?;
        Ok(to_c(Value::Array(hooks.iter().map(|h| json!({ "taskId": h.task_id, "when": h.when, "target": h.target, "snippetId": h.snippet_id })).collect()).to_string()))
    })
}

/// Replace the tasks attached to a connection with `hooks_json` (`[{taskId, when}]`). Returns 0, or -1.
///
/// # Safety
/// `lib` live; strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_task_set_hooks_json(lib: *const BastionLibrary, connection_id: *const c_char, hooks_json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let v: Vec<Value> = serde_json::from_str(&required(hooks_json, "hooks_json")?).map_err(|_| "hooks_json must be a JSON array".to_string())?;
        let hooks = v
            .iter()
            .map(|h| {
                let s = |k: &str| h.get(k).and_then(Value::as_str).map(str::to_string).ok_or_else(|| format!("each hook needs `{k}`"));
                Ok(TaskHookView { task_id: h.get("taskId").and_then(Value::as_str).unwrap_or_default().to_string(), when: s("when")?, target: h.get("target").and_then(Value::as_str).unwrap_or("task").to_string(), snippet_id: h.get("snippetId").and_then(Value::as_str).map(str::to_string) })
            })
            .collect::<Result<Vec<_>, String>>()?;
        handle(lib)?.set_task_hooks(required(connection_id, "connection_id")?, hooks).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// B5: the hooks to run for a connection at `when` (`before_connect`, `after_connect`, `after_disconnect`), in order
/// (outer folder first, then the connection; no duplicates), each marked by the shared trust rule (T01):
/// `[{hook:{taskId, when, target, snippetId}, ownerId, runnable, untrusted}]`. `data_dir` holds
/// `trusted-local-tasks.json`. As UniFFI `resolved_task_hooks`.
///
/// # Safety
/// `lib` live; strings valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_task_resolved_hooks_json(
    lib: *const BastionLibrary,
    connection_id: *const c_char,
    when: *const c_char,
    data_dir: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let rows = handle(lib)?
            .resolved_task_hooks(required(connection_id, "connection_id")?, required(when, "when")?, required(data_dir, "data_dir")?)
            .map_err(|e| e.to_string())?;
        Ok(to_c(
            Value::Array(
                rows.iter()
                    .map(|r| {
                        let h = &r.hook;
                        json!({ "hook": { "taskId": h.task_id, "when": h.when, "target": h.target, "snippetId": h.snippet_id },
                                "ownerId": r.owner_id, "runnable": r.runnable, "untrusted": r.untrusted })
                    })
                    .collect(),
            )
            .to_string(),
        ))
    })
}

/// B5: record a custom task as saved by the user on this computer (T01), so it may run as a hook. Call only from the
/// user's own Save in the task editor. As UniFFI `trust_task`. Returns 0, or -1.
///
/// # Safety
/// `lib` live; strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_task_trust(lib: *const BastionLibrary, task_id: *const c_char, data_dir: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.trust_task(required(task_id, "task_id")?, required(data_dir, "data_dir")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// What running a task on a connection would execute: `{display, needsConfirmation}`.
///
/// # Safety
/// `lib` live; strings valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_task_review_json(lib: *const BastionLibrary, task_id: *const c_char, connection_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    bastion_task_review_with_json(lib, task_id, connection_id, std::ptr::null(), err)
}

/// The `$Ask:Label$` labels a run of this task must ask for, once per run, first use first:
/// a JSON array of strings (empty when none). Additive in ABI 135.
///
/// # Safety
/// `lib` live; `task_id` valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_task_ask_labels_json(lib: *const BastionLibrary, task_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let labels = bastion_ffi::task_ask_labels(library(lib)?, required(task_id, "task_id")?).map_err(|e| e.to_string())?;
        Ok(to_c(json!(labels).to_string()))
    })
}

/// Prompt answers from JSON `{"Label": "answer", ...}`; NULL means none.
unsafe fn answers_from(answers_json: *const c_char) -> Result<HashMap<String, String>, String> {
    match optional(answers_json, "answers_json")? {
        None => Ok(HashMap::new()),
        Some(j) => serde_json::from_str(&j).map_err(|e| format!("answers_json: {e}")),
    }
}

/// As [`bastion_task_review_json`] with `$Ask:Label$` answers (`{"Label": "answer"}` or NULL). A label
/// without an answer, or an answer with control characters, is refused. Additive in ABI 135.
///
/// # Safety
/// `lib` live; strings NULL (answers) or valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_task_review_with_json(
    lib: *const BastionLibrary,
    task_id: *const c_char,
    connection_id: *const c_char,
    answers_json: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let answers = answers_from(answers_json)?;
        let r = bastion_ffi::review_task(library(lib)?, required(task_id, "task_id")?, required(connection_id, "connection_id")?, answers).map_err(|e| e.to_string())?;
        Ok(to_c(json!({ "display": r.display, "needsConfirmation": r.needs_confirmation }).to_string()))
    })
}

/// Start a task on a connection in the background. `login_kind`, `password` and `key_path` are as
/// for `bastion_session_connect_ssh` and only used by SSH tasks; zero `password` after. Refused
/// (NULL, `*err`) when the review asks for confirmation and `confirmed` is 0.
///
/// # Safety
/// `m` and `lib` live; strings NULL (where allowed) or valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_task_run_start(
    m: *const BastionSessionManager,
    lib: *const BastionLibrary,
    task_id: *const c_char,
    connection_id: *const c_char,
    username: *const c_char,
    login_kind: i32,
    password: *const c_char,
    key_path: *const c_char,
    confirmed: i32,
    err: *mut *mut c_char,
) -> *mut BastionTaskRun {
    bastion_task_run_start_with(m, lib, task_id, connection_id, username, login_kind, password, key_path, confirmed, std::ptr::null(), err)
}

/// As [`bastion_task_run_start`] with `$Ask:Label$` answers (`{"Label": "answer"}` or NULL). Answers
/// are not stored. Additive in ABI 135.
///
/// # Safety
/// As [`bastion_task_run_start`]; `answers_json` NULL or valid NUL-terminated.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_task_run_start_with(
    m: *const BastionSessionManager,
    lib: *const BastionLibrary,
    task_id: *const c_char,
    connection_id: *const c_char,
    username: *const c_char,
    login_kind: i32,
    password: *const c_char,
    key_path: *const c_char,
    confirmed: i32,
    answers_json: *const c_char,
    err: *mut *mut c_char,
) -> *mut BastionTaskRun {
    guarded(err, null_mut(), || {
        let manager = m.as_ref().map(|m| m.0.clone()).ok_or_else(|| "session manager handle is NULL".to_string())?;
        let login = login_from(login_kind, optional(password, "password")?, optional(key_path, "key_path")?, None)?;
        let user = optional(username, "username")?.unwrap_or_default();
        let answers = answers_from(answers_json)?;
        let r = TaskRun::start(manager, library(lib)?, required(task_id, "task_id")?, required(connection_id, "connection_id")?, user, login, confirmed != 0, answers)
            .map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionTaskRun(r))))
    })
}

/// Progress: `{display, finished, state, exit, stdout, stderr, error, millis}`; `state` is
/// `running`, `done`, `failed`, `timed_out` or `cancelled`.
///
/// # Safety
/// `r` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_task_run_output_json(r: *const BastionTaskRun, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let r = run(r)?;
        let mut v = run_json(&r.output());
        v["display"] = Value::String(r.display());
        v["finished"] = Value::Bool(r.is_finished());
        Ok(to_c(v.to_string()))
    })
}

/// Kill the local program, or stop waiting for the remote one. Returns 0, or -1.
///
/// # Safety
/// `r` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_task_run_cancel(r: *const BastionTaskRun, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        run(r)?.cancel();
        set_ok()
    })
}

/// Release a run handle (a run still going finishes in the background and is audited).
///
/// # Safety
/// `r` NULL or a handle from [`bastion_task_run_start`] not yet freed.
#[no_mangle]
pub unsafe extern "C" fn bastion_task_run_free(r: *mut BastionTaskRun) {
    if !r.is_null() {
        drop(Box::from_raw(r));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_json_round_trips_custom_fields() {
        let v = json!({ "name": "uptime", "program": "uptime", "args": ["-p"], "runOn": "ssh", "timeoutSecs": 30 });
        let t = task_from(&v).unwrap();
        assert_eq!((t.kind.as_str(), t.run_on.as_str(), t.timeout_secs, t.args.len()), ("custom", "ssh", 30, 1));
        assert!(!t.builtin);
        assert_eq!(task_json(&t)["runOn"], "ssh");
    }

    #[test]
    fn task_from_rejects_non_string_args() {
        assert!(task_from(&json!({ "name": "x", "program": "y", "args": [1] })).is_err());
        assert!(task_from(&json!({ "name": "x", "program": "y", "args": "z" })).is_err());
    }
}
