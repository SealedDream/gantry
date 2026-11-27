//! Dynamic folders (B15): a folder whose children come from a saved local task that prints
//! Royal JSON (`{"Objects": [...]}`). Security review: `docs/reviews/B15-SECURITY-REVIEW.md`.
//!
//! Order of checks on every run (conditions C1–C12 of the review):
//! 1. policy: off by default, managed `forbid_dynamic_folders` wins (C2);
//! 2. the folder names a saved `Custom` task that runs locally, with no `$...$` token (C3);
//! 3. the program is an absolute path to an existing file (C4);
//! 4. the task is trusted for this document on this computer, with its present content (C1).
//!
//! Then the program runs with no shell, at most 300 s, output capped at 1 MiB, tree-killed on
//! timeout or Cancel (C5). The output is parsed and cleaned (C6, C7). The generated items are
//! returned to the caller and never written into the document (C8) unless the user makes them
//! permanent. Runs happen only when the user asks (C11); the caller runs this off the UI thread
//! (C12) and writes the audit record from [`audit_details`] (C10), which holds no output.
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::import::Found;
use crate::model::{Document, Folder, Node};
use crate::policy::Policy;
use crate::tasks::{self, RunOn, TaskDef, TaskKind};
use crate::tasktrust::{self, TrustRecord};

/// Longest a refresh may run, whatever the task's own timeout (F2).
pub const MAX_REFRESH_SECS: u32 = 300;
pub const MAX_ITEMS: usize = 5000;
pub const MAX_NAME_CHARS: usize = 256;
pub const MAX_HOST_CHARS: usize = 253;
pub const MAX_NOTES_BYTES: usize = 8 * 1024;
pub const MAX_USERNAME_CHARS: usize = 256;
pub const MAX_TAGS: usize = 32;
/// stderr shown to the user, at most.
pub const MAX_STDERR_SHOWN: usize = 4 * 1024;

/// Whether the feature is on: the user's switch, and no managed ban.
pub fn enabled(policy: &Policy) -> bool {
    policy.dynamic_folders_enabled && !policy.forbid_dynamic_folders
}

fn check_enabled(policy: &Policy) -> Result<()> {
    if policy.forbid_dynamic_folders {
        return Err(CoreError::PolicyDenied("dynamic folders are turned off by your organisation".into()));
    }
    if !policy.dynamic_folders_enabled {
        return Err(CoreError::PolicyDenied("dynamic folders are off; turn them on in Settings".into()));
    }
    Ok(())
}

fn has_token(s: &str) -> bool {
    s.find('$').is_some_and(|i| s[i + 1..].contains('$'))
}

/// The program and arguments a task would run as a dynamic folder source, or why it cannot be
/// one (C3, C4). Checked when the folder is set and again before every run.
pub fn eligible(task: &TaskDef) -> Result<(String, Vec<String>)> {
    let TaskKind::Custom { program, args, run_on } = &task.kind else {
        return Err(CoreError::Invalid("a dynamic folder needs a custom task; built-in tasks print no Royal JSON".into()));
    };
    if *run_on != RunOn::Local {
        return Err(CoreError::Invalid("a dynamic folder needs a task that runs on this computer".into()));
    }
    tasks::validate(task)?;
    if has_token(program) || args.iter().any(|a| has_token(a)) {
        return Err(CoreError::Invalid("a dynamic folder task cannot use $...$ variables".into()));
    }
    // A network path runs whatever the share serves at run time (review of #1166, M3).
    if program.starts_with("\\\\") || program.starts_with("//") {
        return Err(CoreError::Invalid(format!("`{program}` is a network path; a dynamic folder task must run a local program")));
    }
    let path = Path::new(program);
    if !path.is_absolute() {
        return Err(CoreError::Invalid(format!("`{program}` is not a full path; a dynamic folder task needs one")));
    }
    if !path.is_file() {
        return Err(CoreError::Invalid(format!("`{program}` does not exist")));
    }
    Ok((program.clone(), args.clone()))
}

fn folder_task(doc: &Document, folder_id: Uuid) -> Result<TaskDef> {
    let folder = doc.folder(folder_id).ok_or_else(|| CoreError::NotFound(folder_id.to_string()))?;
    let task_id = folder.dynamic_task_id.ok_or_else(|| CoreError::Invalid("this folder is not a dynamic folder".into()))?;
    doc.tasks.iter().find(|t| t.id == task_id).cloned().ok_or_else(|| CoreError::NotFound(format!("task {task_id}")))
}

/// What the consent sheet shows before the first run of a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    pub task_id: Uuid,
    pub task_name: String,
    pub program: String,
    pub args: Vec<String>,
    pub timeout_secs: u32,
    pub trusted: bool,
    /// What "Trust and run" must send back: the task as reviewed (see `tasktrust::trust_reviewed`).
    pub sha256: String,
    /// Risks the sheet shows, one line each (for example a folder others can write to).
    pub warnings: Vec<String>,
}

/// Unix: a program, or its folder, that other users can write to can be swapped after trust.
#[cfg(unix)]
fn path_warnings(program: &str) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;
    let p = Path::new(program);
    [Some(p), p.parent()]
        .into_iter()
        .flatten()
        .filter(|x| std::fs::metadata(x).is_ok_and(|m| m.permissions().mode() & 0o002 != 0))
        .map(|x| format!("{} can be changed by other users", x.display()))
        .collect()
}

#[cfg(not(unix))]
fn path_warnings(_: &str) -> Vec<String> {
    Vec::new()
}

/// The task behind `folder_id`, as the consent sheet shows it, and whether it is trusted here.
pub fn review(doc: &Document, folder_id: Uuid, trusted: &[TrustRecord]) -> Result<Review> {
    let task = folder_task(doc, folder_id)?;
    let (program, args) = eligible(&task)?;
    Ok(Review {
        task_id: task.id,
        task_name: task.name.clone(),
        args,
        timeout_secs: task.timeout_secs.clamp(1, MAX_REFRESH_SECS),
        trusted: tasktrust::is_trusted(trusted, doc.id, &task),
        sha256: tasktrust::task_hash(&task).unwrap_or_default(),
        warnings: path_warnings(&program),
        program,
    })
}

/// Trust the folder's task for this library on this computer, only when the feature is on, the
/// task is still eligible and it still hashes to `reviewed_sha256` (what the user saw). Returns
/// the task trusted, for the audit record.
pub fn trust(doc: &Document, folder_id: Uuid, policy: &Policy, trust_dir: &Path, reviewed_sha256: &str) -> Result<TaskDef> {
    check_enabled(policy)?;
    let task = folder_task(doc, folder_id)?;
    eligible(&task)?;
    tasktrust::trust_reviewed(trust_dir, doc.id, &task, reviewed_sha256)?;
    Ok(task)
}

/// Make `folder_id` a dynamic folder fed by `task_id`, or a plain folder with `None`. Only a
/// task that is eligible now is accepted. Refused when the feature is off.
pub fn set_task(doc: &mut Document, folder_id: Uuid, task_id: Option<Uuid>, policy: &Policy) -> Result<()> {
    if task_id.is_some() {
        check_enabled(policy)?;
    }
    if folder_id == doc.root.id {
        return Err(CoreError::Invalid("the library root cannot be a dynamic folder".into()));
    }
    if let Some(id) = task_id {
        let task = doc.tasks.iter().find(|t| t.id == id).ok_or_else(|| CoreError::NotFound(format!("task {id}")))?;
        eligible(task)?;
    }
    let folder = folder_mut(&mut doc.root, folder_id).ok_or_else(|| CoreError::NotFound(folder_id.to_string()))?;
    folder.dynamic_task_id = task_id;
    Ok(())
}

fn folder_mut(f: &mut Folder, id: Uuid) -> Option<&mut Folder> {
    if f.id == id {
        return Some(f);
    }
    f.children.iter_mut().find_map(|n| match n {
        Node::Folder(sub) => folder_mut(sub, id),
        Node::Connection(_) => None,
    })
}

/// A run that passed every check and may start.
#[derive(Debug, Clone)]
pub struct Plan {
    pub task: TaskDef,
    pub program: String,
    pub args: Vec<String>,
    pub timeout: Duration,
}

/// Every check before a run, in the order of the review (C2, C3, C4, C1).
pub fn plan(doc: &Document, folder_id: Uuid, policy: &Policy, trusted: &[TrustRecord]) -> Result<Plan> {
    check_enabled(policy)?;
    let task = folder_task(doc, folder_id)?;
    let (program, args) = eligible(&task)?;
    if !tasktrust::is_trusted(trusted, doc.id, &task) {
        return Err(CoreError::PolicyDenied(format!("the task `{}` is not trusted on this computer; review it first", task.name)));
    }
    let timeout = Duration::from_secs(u64::from(task.timeout_secs.clamp(1, MAX_REFRESH_SECS)));
    Ok(Plan { task, program, args, timeout })
}

/// The result of one refresh. `items` are generated, in memory only.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DynResult {
    pub items: Vec<Found>,
    /// What was left out and why (secrets, unsupported types, caps). Names only, never values.
    pub skipped: Vec<String>,
    /// One line for the folder when the run or the parse failed.
    pub error: Option<String>,
    pub exit: Option<i32>,
    pub millis: u64,
    pub stdout_bytes: usize,
    pub timed_out: bool,
    pub cancelled: bool,
}

/// Run a checked plan and parse its output. Blocks; call it off the UI thread.
pub fn run(plan: &Plan, cancel: &AtomicBool) -> DynResult {
    let t0 = Instant::now();
    let out = tasks::run_local(&plan.program, &plan.args, plan.timeout, cancel);
    let mut result = DynResult { millis: t0.elapsed().as_millis() as u64, ..Default::default() };
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            result.error = Some(e.to_string());
            return result;
        }
    };
    result.exit = out.exit;
    result.timed_out = out.timed_out;
    result.cancelled = out.cancelled;
    result.stdout_bytes = out.stdout.len();
    if out.cancelled {
        result.error = Some("cancelled".into());
        return result;
    }
    if out.timed_out {
        result.error = Some(format!("stopped after {} s", plan.timeout.as_secs()));
        return result;
    }
    if out.exit != Some(0) {
        let code = out.exit.map_or_else(|| "a signal".to_string(), |c| format!("code {c}"));
        let detail = clean(out.stderr.trim(), MAX_STDERR_SHOWN);
        // stderr is the program's own text: shown as quoted, untrusted output.
        result.error = Some(if detail.is_empty() { format!("the task ended with {code}") } else { format!("the task ended with {code}; task output (untrusted): {detail}") });
        return result;
    }
    match parse(&out.stdout) {
        Ok((items, skipped)) => {
            result.items = items;
            result.skipped = skipped;
        }
        Err(e) => result.error = Some(e.to_string()),
    }
    result
}

/// All checks, then the run: what the apps call on Refresh.
pub fn refresh(doc: &Document, folder_id: Uuid, policy: &Policy, trust_dir: &Path, cancel: &AtomicBool) -> Result<DynResult> {
    let plan = plan(doc, folder_id, policy, &tasktrust::load(trust_dir))?;
    Ok(run(&plan, cancel))
}

/// Keys whose values are never kept from generated output (C6).
fn secret_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    crate::audit::is_sensitive_key(&k) || (k.contains("key") && k != "keyboardlayout")
}

/// Note every secret-shaped field in the output, by object name and field name only.
fn note_secrets(v: &serde_json::Value, skipped: &mut Vec<String>, depth: usize) {
    if depth > crate::import::MAX_TREE_DEPTH + 1 {
        return;
    }
    if let Some(objects) = v.get("Objects").and_then(|o| o.as_array()) {
        for o in objects {
            let name = o.get("Name").and_then(|n| n.as_str()).unwrap_or("Unnamed");
            if let Some(map) = o.as_object() {
                for k in map.keys().filter(|k| secret_key(k) && k.as_str() != "Password") {
                    skipped.push(format!("{}: {} dropped", clean(name, MAX_NAME_CHARS), clean(k, MAX_NAME_CHARS)));
                }
            }
            note_secrets(o, skipped, depth + 1);
        }
    }
}

/// Strip control characters and cap at `max` characters.
fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Notes keep line breaks and tabs; other control characters go. Capped in bytes.
fn clean_notes(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().filter(|c| !c.is_control() || matches!(c, '\n' | '\t')) {
        if out.len() + c.len_utf8() > MAX_NOTES_BYTES {
            break;
        }
        out.push(c);
    }
    out
}

/// Parse Royal JSON output into generated items (C6, C7).
pub fn parse(stdout: &str) -> Result<(Vec<Found>, Vec<String>)> {
    if stdout.len() >= tasks::MAX_OUTPUT {
        return Err(CoreError::Invalid("the task printed more than 1 MiB; output was cut off".into()));
    }
    let value: serde_json::Value = serde_json::from_str(stdout).map_err(|e| CoreError::Invalid(format!("not Royal JSON: {e}")))?;
    let mut skipped = Vec::new();
    note_secrets(&value, &mut skipped, 0);
    let imported = crate::import::royal_json(stdout)?;
    skipped.extend(imported.skipped.into_iter().map(|s| clean(&s, MAX_NAME_CHARS * 2)));
    let total = imported.found.len();
    let items: Vec<Found> = imported.found.into_iter().take(MAX_ITEMS).filter_map(|f| generated(f, &mut skipped)).collect();
    if total > MAX_ITEMS {
        skipped.push(format!("{} items over the limit of {MAX_ITEMS} left out", total - MAX_ITEMS));
    }
    Ok((items, skipped))
}

/// Whether free text looks like it carries a secret (`password=`, `token:` and the like).
fn looks_secret(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    ["password", "passwd", "passphrase", "secret", "token", "private_key", "privatekey", "api_key", "apikey"].iter().any(|k| l.contains(k))
}

/// A clean, plain connection from one parsed item (C7): fresh id, capped strings, no metadata,
/// a host that passes the normal host rules, no credential (the script cannot pick a vault
/// entry for a host it also picks: review of #1166, M2), and free text without secret-looking
/// lines. `None`, with a line in `skipped`, when the item is refused.
fn generated(f: Found, skipped: &mut Vec<String>) -> Option<Found> {
    let src = f.connection;
    let name = clean(&src.name, MAX_NAME_CHARS);
    let mut c = crate::model::Connection::new(&name, src.protocol, clean(&src.host, MAX_HOST_CHARS + 1));
    // A cut host would be another host: one over the limit is refused, not shortened.
    if c.host.chars().count() > MAX_HOST_CHARS || crate::properties::check_host(&c.host).and_then(|_| crate::properties::check_url_scheme(&c)).is_err() {
        skipped.push(format!("{name}: computer name refused"));
        return None;
    }
    if src.settings.credential_name.is_some() {
        skipped.push(format!("{name}: credential name ignored (choose one after Make permanent)"));
    }
    c.settings.port = src.settings.port;
    c.settings.username = src.settings.username.as_deref().map(|u| clean(u, MAX_USERNAME_CHARS)).filter(|u| !u.is_empty() && !looks_secret(u));
    let notes = clean_notes(&src.notes);
    let kept: Vec<&str> = notes.lines().filter(|l| !looks_secret(l)).collect();
    if kept.len() != notes.lines().count() {
        skipped.push(format!("{name}: notes lines that look like secrets dropped"));
    }
    c.notes = kept.join("\n");
    c.tags = src.tags.iter().take(MAX_TAGS).map(|t| clean(t, MAX_NAME_CHARS)).filter(|t| !t.is_empty() && !looks_secret(t)).collect();
    let path = f.path.iter().take(crate::import::MAX_TREE_DEPTH).map(|p| clean(p, MAX_NAME_CHARS)).filter(|p| !p.is_empty()).collect();
    Some(Found { path, connection: c })
}

/// Copy generated items into `folder_id` as ordinary connections (in their sub-folders), so they
/// are saved like any other entry. Each gets a fresh id. Returns how many were added.
pub fn make_permanent(doc: &mut Document, folder_id: Uuid, items: &[Found]) -> Result<usize> {
    if items.len() > MAX_ITEMS {
        return Err(CoreError::Invalid(format!("at most {MAX_ITEMS} items")));
    }
    let mut ignored = Vec::new();
    let cleaned: Vec<Found> = items.iter().cloned().filter_map(|f| generated(f, &mut ignored)).collect();
    let added = cleaned.len();
    let tmp = crate::import::into_folder("generated", cleaned);
    let folder = folder_mut(&mut doc.root, folder_id).ok_or_else(|| CoreError::NotFound(folder_id.to_string()))?;
    folder.children.extend(tmp.children);
    Ok(added)
}

/// Audit details for a run (C10): task identity, program path, exit, time and counts. Never
/// arguments or output.
pub fn audit_details(plan: &Plan, result: &DynResult) -> BTreeMap<String, String> {
    let mut d = BTreeMap::from([
        ("task_id".to_string(), plan.task.id.to_string()),
        ("task".to_string(), plan.task.name.clone()),
        ("program".to_string(), plan.program.clone()),
        ("millis".to_string(), result.millis.to_string()),
        ("bytes".to_string(), result.stdout_bytes.to_string()),
        ("items".to_string(), result.items.len().to_string()),
        ("skipped".to_string(), result.skipped.len().to_string()),
    ]);
    if let Some(code) = result.exit {
        d.insert("exit".into(), code.to_string());
    }
    if result.timed_out {
        d.insert("state".into(), "timed_out".into());
    } else if result.cancelled {
        d.insert("state".into(), "cancelled".into());
    }
    d
}

/// Audit details for a trust grant or revoke (C10).
pub fn trust_audit_details(doc_id: Uuid, task: &TaskDef) -> BTreeMap<String, String> {
    let program = match &task.kind {
        TaskKind::Custom { program, .. } => program.clone(),
        TaskKind::Builtin { .. } => String::new(),
    };
    BTreeMap::from([
        ("doc_id".to_string(), doc_id.to_string()),
        ("task_id".to_string(), task.id.to_string()),
        ("task".to_string(), task.name.clone()),
        ("program".to_string(), program),
    ])
}

/// Drop every dynamic folder binding in `f` (exports and imports, C8 and C9).
pub fn strip(f: &mut Folder) {
    f.dynamic_task_id = None;
    for n in &mut f.children {
        if let Node::Folder(sub) = n {
            strip(sub);
        }
    }
}

#[cfg(test)]
#[path = "dynfolder_tests.rs"]
mod tests;
