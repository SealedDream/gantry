//! Dynamic folders (B15) for the native apps: bind a folder to a saved local task, review and
//! trust the task, Refresh in the background with Cancel, and Make permanent. Every check is in
//! `bastion_core::dynfolder`; this bridge adds the managed policy, the audit records and the
//! background thread.
//!
//! `user_enabled` is the user's own switch, which the app keeps in its settings; a managed
//! `forbid_dynamic_folders` always wins. The trust file lives in the session manager's data
//! directory, never in a path the caller names.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bastion_core::audit::{Category, Outcome};
use bastion_core::dynfolder::{self, DynResult};
use bastion_core::error::CoreError;
use bastion_core::import::Found;
use bastion_core::model::Document;
use bastion_core::policy::Policy;
use bastion_core::tasks::TaskDef;
use bastion_core::tasktrust;
use uuid::Uuid;

use crate::terminal::SessionManager;
use crate::{parse_id, FfiError, FfiResult, Library};

fn policy(user_enabled: bool) -> FfiResult<Policy> {
    let managed = crate::policy::effective()?;
    Ok(Policy { dynamic_folders_enabled: user_enabled, ..managed })
}

/// Whether the apps may show dynamic folders at all: false under a managed ban or while the
/// managed policy cannot be read.
#[uniffi::export]
pub fn dynamic_folders_allowed() -> bool {
    crate::policy::effective().is_ok_and(|p| !p.forbid_dynamic_folders)
}

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct DynamicReviewView {
    pub task_id: String,
    pub task_name: String,
    /// Absolute program path, shown as is on the consent sheet.
    pub program: String,
    pub args: Vec<String>,
    pub timeout_secs: u32,
    pub trusted: bool,
    /// Pass back to `dynamic_folder_trust` unchanged: trust is refused if the task changed since.
    pub sha256: String,
    /// One line per risk to show on the sheet.
    pub warnings: Vec<String>,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct GeneratedItemView {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    /// A credential by name; resolved through the vault at connect time.
    pub credential_name: Option<String>,
    pub notes: String,
    /// Sub-folders below the dynamic folder.
    pub path: Vec<String>,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct DynamicRunView {
    /// `running`, `done`, `failed`, `timed_out` or `cancelled`.
    pub state: String,
    pub items: Vec<GeneratedItemView>,
    pub skipped: Vec<String>,
    pub error: Option<String>,
    pub exit: Option<i32>,
    pub millis: u64,
}

pub(crate) fn item_view(f: &Found) -> GeneratedItemView {
    let c = &f.connection;
    GeneratedItemView {
        id: c.id.to_string(),
        name: c.name.clone(),
        protocol: c.protocol_name().to_string(),
        host: c.host.clone(),
        port: c.settings.port,
        username: c.settings.username.clone(),
        credential_name: c.settings.credential_name.clone(),
        notes: c.notes.clone(),
        path: f.path.clone(),
    }
}

fn run_view(r: &DynResult) -> DynamicRunView {
    let state = if r.cancelled {
        "cancelled"
    } else if r.timed_out {
        "timed_out"
    } else if r.error.is_some() {
        "failed"
    } else {
        "done"
    };
    DynamicRunView { state: state.into(), items: r.items.iter().map(item_view).collect(), skipped: r.skipped.clone(), error: r.error.clone(), exit: r.exit, millis: r.millis }
}

/// The library id and the task bound to `folder_id`.
fn bound_task(d: &Document, folder_id: Uuid) -> bastion_core::Result<(Uuid, TaskDef)> {
    let tid = d.folder(folder_id).and_then(|f| f.dynamic_task_id).ok_or_else(|| CoreError::Invalid("this folder is not a dynamic folder".into()))?;
    let task = d.tasks.iter().find(|t| t.id == tid).cloned().ok_or_else(|| CoreError::NotFound(format!("task {tid}")))?;
    Ok((d.id, task))
}

#[uniffi::export]
impl Library {
    /// The task id bound to a folder, if it is a dynamic folder.
    pub fn dynamic_folder_task(&self, folder_id: String) -> FfiResult<Option<String>> {
        let id = parse_id(&folder_id)?;
        self.with_doc(|d| Ok(d.folder(id).and_then(|f| f.dynamic_task_id).map(|t| t.to_string())))
    }

    /// Bind a folder to a saved local task (`task_id`), or make it a plain folder (`None`).
    pub fn set_dynamic_folder_task(&self, folder_id: String, task_id: Option<String>, user_enabled: bool) -> FfiResult<()> {
        let fid = parse_id(&folder_id)?;
        let tid = task_id.filter(|t| !t.is_empty()).map(|t| parse_id(&t)).transpose()?;
        let p = policy(user_enabled)?;
        self.with_doc(|d| dynfolder::set_task(d, fid, tid, &p))
    }

    /// Custom local tasks that may feed a dynamic folder, as `[id, name]` pairs for the picker.
    pub fn dynamic_folder_task_choices(&self) -> Vec<Vec<String>> {
        self.with_doc(|d| Ok(d.tasks.iter().filter(|t| dynfolder::eligible(t).is_ok()).map(|t| vec![t.id.to_string(), t.name.clone()]).collect())).unwrap_or_default()
    }

    /// Copy the items of a finished run into the folder as ordinary connections.
    pub fn dynamic_folder_make_permanent(&self, folder_id: String, run: Arc<DynamicFolderRun>) -> FfiResult<u32> {
        let fid = parse_id(&folder_id)?;
        if run.folder_id != fid {
            return Err(FfiError::failed("this run belongs to another folder".into()));
        }
        let items = run.result.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|r| r.items.clone()).unwrap_or_default();
        Ok(self.with_doc(|d| dynfolder::make_permanent(d, fid, &items))? as u32)
    }
}

/// What the consent sheet shows: the exact program, arguments and timeout, and whether this
/// task is trusted here already.
#[uniffi::export]
pub fn dynamic_folder_review(manager: Arc<SessionManager>, library: Arc<Library>, folder_id: String) -> FfiResult<DynamicReviewView> {
    let fid = parse_id(&folder_id)?;
    // A damaged trust file is shown to the user, not read as "nothing trusted" in silence.
    let trusted = tasktrust::load_checked(manager.data_dir())?;
    let r = library.with_doc(|d| dynfolder::review(d, fid, &trusted))?;
    Ok(DynamicReviewView { task_id: r.task_id.to_string(), task_name: r.task_name, program: r.program, args: r.args, timeout_secs: r.timeout_secs, trusted: r.trusted, sha256: r.sha256, warnings: r.warnings })
}

/// Trust the folder's task for this library on this computer. `reviewed_sha256` is the review's
/// `sha256`: refused when the task changed since the user saw it, or when the feature is off.
/// Call only from the user's "Trust and run" on the consent sheet. Audited.
#[uniffi::export]
pub fn dynamic_folder_trust(manager: Arc<SessionManager>, library: Arc<Library>, folder_id: String, reviewed_sha256: String, user_enabled: bool) -> FfiResult<()> {
    let fid = parse_id(&folder_id)?;
    let p = policy(user_enabled)?;
    let (doc_id, task) = library.with_doc(|d| Ok((d.id, dynfolder::trust(d, fid, &p, manager.data_dir(), &reviewed_sha256)?)))?;
    manager.record_audit(Category::Task, "dynamic_folder.trust", Some(&task.name), Outcome::Success, dynfolder::trust_audit_details(doc_id, &task));
    Ok(())
}

/// Remove the trust of the folder's task on this computer. Audited when one was removed.
#[uniffi::export]
pub fn dynamic_folder_revoke(manager: Arc<SessionManager>, library: Arc<Library>, folder_id: String) -> FfiResult<bool> {
    let fid = parse_id(&folder_id)?;
    let (doc_id, task) = library.with_doc(|d| bound_task(d, fid))?;
    let removed = tasktrust::revoke(manager.data_dir(), doc_id, task.id)?;
    if removed {
        manager.record_audit(Category::Task, "dynamic_folder.revoke", Some(&task.name), Outcome::Success, dynfolder::trust_audit_details(doc_id, &task));
    }
    Ok(removed)
}

/// Folders with a Refresh running: one at a time per folder (review of #1166, L5).
static RUNNING: Mutex<Vec<Uuid>> = Mutex::new(Vec::new());

fn running() -> std::sync::MutexGuard<'static, Vec<Uuid>> {
    RUNNING.lock().unwrap_or_else(|e| e.into_inner())
}

/// One Refresh of a dynamic folder, on a background thread. Dropping the handle cancels it.
#[derive(uniffi::Object)]
pub struct DynamicFolderRun {
    folder_id: Uuid,
    cancel: Arc<AtomicBool>,
    result: Arc<Mutex<Option<DynResult>>>,
}

#[uniffi::export]
impl DynamicFolderRun {
    /// Check everything (policy, task, path, trust) and start the run. A refused run is audited
    /// as denied and returns the reason; nothing has started then.
    #[uniffi::constructor]
    pub fn start(manager: Arc<SessionManager>, library: Arc<Library>, folder_id: String, user_enabled: bool) -> FfiResult<Arc<Self>> {
        let fid = parse_id(&folder_id)?;
        let trusted = tasktrust::load(manager.data_dir());
        let planned = policy(user_enabled).and_then(|p| library.with_doc(|d| dynfolder::plan(d, fid, &p, &trusted)));
        let plan = match planned {
            Ok(p) => p,
            Err(e) => {
                let details = [("folder_id".to_string(), fid.to_string()), ("error".to_string(), e.to_string())].into_iter().collect();
                manager.record_audit(Category::Task, "dynamic_folder.refresh", None, Outcome::Denied, details);
                return Err(e);
            }
        };
        {
            let mut busy = running();
            if busy.contains(&fid) {
                return Err(FfiError::failed("this folder is already refreshing".into()));
            }
            busy.push(fid);
        }
        let run = Arc::new(DynamicFolderRun { folder_id: fid, cancel: Arc::new(AtomicBool::new(false)), result: Arc::new(Mutex::new(None)) });
        let (cancel, result) = (run.cancel.clone(), run.result.clone());
        std::thread::spawn(move || {
            let r = dynfolder::run(&plan, &cancel);
            let outcome = if r.error.is_none() { Outcome::Success } else { Outcome::Failure };
            let details = dynfolder::audit_details(&plan, &r);
            manager.record_audit(Category::Task, "dynamic_folder.refresh", Some(&plan.task.name), outcome, details);
            *result.lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
            running().retain(|f| *f != fid);
        });
        Ok(run)
    }

    /// Stop the program and everything it started.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    pub fn is_finished(&self) -> bool {
        self.result.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    pub fn output(&self) -> DynamicRunView {
        match &*self.result.lock().unwrap_or_else(|e| e.into_inner()) {
            Some(r) => run_view(r),
            None => DynamicRunView { state: "running".into(), items: vec![], skipped: vec![], error: None, exit: None, millis: 0 },
        }
    }
}

impl Drop for DynamicFolderRun {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_view_states() {
        assert_eq!(run_view(&DynResult::default()).state, "done");
        assert_eq!(run_view(&DynResult { cancelled: true, error: Some("cancelled".into()), ..Default::default() }).state, "cancelled");
        assert_eq!(run_view(&DynResult { timed_out: true, error: Some("x".into()), ..Default::default() }).state, "timed_out");
        assert_eq!(run_view(&DynResult { error: Some("x".into()), ..Default::default() }).state, "failed");
    }
}
