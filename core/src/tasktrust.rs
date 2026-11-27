//! Local trust for tasks that fill dynamic folders (B15, condition C1).
//!
//! A dynamic folder runs a program, and the folder and its task travel inside the document, so
//! the author can be someone other than the person who opens it. Nothing runs until the local
//! user has trusted that exact task for that document on this computer. Trust is kept per OS
//! user in the app's data directory (owner-only file), never in a document, an export, an
//! import, IPC or a plugin.
//!
//! Key: document id + task id. Value: SHA-256 of the canonical task (program, args, run_on,
//! timeout). Any change to the task in the document changes the hash and drops the trust.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::tasks::{TaskDef, TaskKind};

pub const FILE: &str = "trusted-dynamic-folder-tasks.json";
/// Most records kept; the oldest go first. Bounds the file whatever is trusted over time.
pub const MAX_RECORDS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRecord {
    pub doc_id: Uuid,
    pub task_id: Uuid,
    /// Hex SHA-256 of the canonical task.
    pub sha256: String,
}

/// The fields that decide what runs. The name and favourite flag do not.
#[derive(Serialize)]
struct Canonical<'a> {
    program: &'a str,
    args: &'a [String],
    run_on: &'a crate::tasks::RunOn,
    timeout_secs: u32,
}

/// Hex SHA-256 of the task's program, args, run location and timeout. `None` for a built-in.
pub fn task_hash(task: &TaskDef) -> Option<String> {
    let TaskKind::Custom { program, args, run_on } = &task.kind else { return None };
    let json = serde_json::to_vec(&Canonical { program, args, run_on, timeout_secs: task.timeout_secs }).ok()?;
    Some(hex::encode(Sha256::digest(&json)))
}

/// One writer at a time in this process; `store::write_atomic` makes each write all-or-nothing.
static WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const DAMAGED: &str = "the dynamic folder trust file is damaged; nothing is trusted until it is removed";

/// The trust records in `dir`, or an error when the file exists but cannot be read or parsed.
pub fn load_checked(dir: &std::path::Path) -> Result<Vec<TrustRecord>> {
    match std::fs::read(dir.join(FILE)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(CoreError::Invalid(DAMAGED.into())),
        Ok(b) => serde_json::from_slice(&b).map_err(|_| CoreError::Invalid(DAMAGED.into())),
    }
}

/// The trust records in `dir`. A missing or damaged file means nothing is trusted (fail closed);
/// [`load_checked`] tells the two apart for the UI.
pub fn load(dir: &std::path::Path) -> Vec<TrustRecord> {
    load_checked(dir).unwrap_or_default()
}

/// Whether `task` in document `doc_id` is trusted, with its present content.
pub fn is_trusted(records: &[TrustRecord], doc_id: Uuid, task: &TaskDef) -> bool {
    let Some(hash) = task_hash(task) else { return false };
    records.iter().any(|r| r.doc_id == doc_id && r.task_id == task.id && r.sha256 == hash)
}

fn save(dir: &std::path::Path, records: &[TrustRecord]) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let json = serde_json::to_vec(records).map_err(|e| CoreError::Invalid(e.to_string()))?;
    crate::store::write_atomic(&dir.join(FILE), &json)
}

/// Trust `task` for document `doc_id` as it is now; an older trust of the same task is replaced.
/// Call only from the user's own confirmation on the consent sheet.
pub fn trust(dir: &std::path::Path, doc_id: Uuid, task: &TaskDef) -> Result<()> {
    let hash = task_hash(task).ok_or_else(|| CoreError::Invalid("only custom tasks can be trusted".into()))?;
    trust_hash(dir, doc_id, task.id, hash)
}

/// [`trust`], only when the task still hashes to `reviewed_sha256`, the value the consent sheet
/// showed the user. A task changed between review and confirmation is refused.
pub fn trust_reviewed(dir: &std::path::Path, doc_id: Uuid, task: &TaskDef, reviewed_sha256: &str) -> Result<()> {
    let hash = task_hash(task).ok_or_else(|| CoreError::Invalid("only custom tasks can be trusted".into()))?;
    if !hash.eq_ignore_ascii_case(reviewed_sha256.trim()) {
        return Err(CoreError::Invalid("the task changed after it was reviewed; review it again".into()));
    }
    trust_hash(dir, doc_id, task.id, hash)
}

fn trust_hash(dir: &std::path::Path, doc_id: Uuid, task_id: Uuid, hash: String) -> Result<()> {
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut records: Vec<TrustRecord> = load_checked(dir)?.into_iter().filter(|r| !(r.doc_id == doc_id && r.task_id == task_id)).collect();
    records.push(TrustRecord { doc_id, task_id, sha256: hash });
    let over = records.len().saturating_sub(MAX_RECORDS);
    records.drain(..over);
    save(dir, &records)
}

/// Remove the trust of `task_id` in document `doc_id`. True when one was removed.
pub fn revoke(dir: &std::path::Path, doc_id: Uuid, task_id: Uuid) -> Result<bool> {
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let before = load_checked(dir)?;
    let after: Vec<TrustRecord> = before.iter().filter(|r| !(r.doc_id == doc_id && r.task_id == task_id)).cloned().collect();
    if after.len() == before.len() {
        return Ok(false);
    }
    save(dir, &after)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::RunOn;

    fn task(args: &[&str]) -> TaskDef {
        TaskDef {
            id: Uuid::from_u128(7),
            name: "List".into(),
            favorite: false,
            kind: TaskKind::Custom { program: "/bin/echo".into(), args: args.iter().map(|s| s.to_string()).collect(), run_on: RunOn::Local },
            timeout_secs: 30,
        }
    }

    #[test]
    fn trust_is_per_document_and_per_content() {
        let dir = tempfile::tempdir().unwrap();
        let doc = Uuid::from_u128(1);
        let t = task(&["a"]);
        assert!(!is_trusted(&load(dir.path()), doc, &t));
        trust(dir.path(), doc, &t).unwrap();
        assert!(is_trusted(&load(dir.path()), doc, &t));
        assert!(!is_trusted(&load(dir.path()), Uuid::from_u128(2), &t), "another document is not trusted");
        assert!(!is_trusted(&load(dir.path()), doc, &task(&["b"])), "a changed argument drops trust");
        let mut longer = t.clone();
        longer.timeout_secs = 31;
        assert!(!is_trusted(&load(dir.path()), doc, &longer), "a changed timeout drops trust");
        let mut renamed = t.clone();
        renamed.name = "Other".into();
        assert!(is_trusted(&load(dir.path()), doc, &renamed), "the name does not decide what runs");
    }

    #[test]
    fn revoke_and_replace() {
        let dir = tempfile::tempdir().unwrap();
        let doc = Uuid::from_u128(1);
        trust(dir.path(), doc, &task(&["a"])).unwrap();
        trust(dir.path(), doc, &task(&["b"])).unwrap();
        assert_eq!(load(dir.path()).len(), 1, "a new trust replaces the older one");
        assert!(revoke(dir.path(), doc, Uuid::from_u128(7)).unwrap());
        assert!(!revoke(dir.path(), doc, Uuid::from_u128(7)).unwrap());
        assert!(load(dir.path()).is_empty());
    }

    #[test]
    fn builtins_and_garbage_are_never_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let b = crate::tasks::builtins().remove(0);
        assert!(trust(dir.path(), Uuid::nil(), &b).is_err());
        std::fs::write(dir.path().join(FILE), b"not json").unwrap();
        assert!(load(dir.path()).is_empty());
    }

    #[test]
    fn trust_needs_the_reviewed_hash_and_damage_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let t = task(&["a"]);
        let reviewed = task_hash(&t).unwrap();
        assert!(trust_reviewed(dir.path(), Uuid::nil(), &task(&["b"]), &reviewed).is_err(), "changed after review");
        trust_reviewed(dir.path(), Uuid::nil(), &t, &reviewed).unwrap();
        assert!(is_trusted(&load(dir.path()), Uuid::nil(), &t));
        std::fs::write(dir.path().join(FILE), b"{broken").unwrap();
        assert!(load_checked(dir.path()).is_err());
        assert!(load(dir.path()).is_empty(), "fail closed");
        assert!(trust(dir.path(), Uuid::nil(), &t).is_err(), "a damaged file is not overwritten silently");
    }

    #[cfg(unix)]
    #[test]
    fn file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        trust(dir.path(), Uuid::nil(), &task(&[])).unwrap();
        let mode = std::fs::metadata(dir.path().join(FILE)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
