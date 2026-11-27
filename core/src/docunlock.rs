//! Document-first launch around [`crate::docfile`]: wrong-password back-off, the auto-lock
//! decision, each document's own state folder (open-session set, connection history) and the
//! details the Unlock and Welcome screens show for recent documents.
//!
//! Nothing here holds a secret. The back-off file keeps a failure count and a time per document
//! id. No password hints are stored.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::store::write_atomic;

/// Back-off file in the app data directory.
pub const BACKOFF_FILE: &str = "document-unlock.json";
/// Last-opened times of documents, in the app data directory.
pub const OPENED_FILE: &str = "document-opened.json";
/// Connection count per recent document, written while the document is unlocked (save, lock),
/// so the start window can show it without decrypting anything.
pub const COUNTS_FILE: &str = "document-counts.json";
/// Folder in the app data directory that holds one folder per document id.
pub const STATE_DIR: &str = "documents";
/// Wrong passwords allowed before the first wait.
pub const FREE_ATTEMPTS: u32 = 5;
/// First wait, doubled for every further wrong password.
pub const FIRST_WAIT_SECS: u64 = 30;
/// Longest wait.
pub const MAX_WAIT_SECS: u64 = 3600;
/// Settings this module reads (see `settings`).
pub const AUTO_LOCK_SETTING: &str = "document.auto-lock-minutes";
pub const CLOSE_ON_LOCK_SETTING: &str = "document.close-sessions-on-lock";
pub const REMEMBER_UNLOCK_SETTING: &str = "document.remember-unlock";

// ---------------------------------------------------------------------------------------------
// Wrong-password back-off

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Attempts {
    /// Wrong passwords since the last successful unlock.
    pub failures: u32,
    /// Unix seconds before which no password is tried.
    pub retry_at: u64,
}

impl Attempts {
    /// Seconds still to wait at `now` (0 = may try).
    pub fn wait_secs(&self, now: u64) -> u64 {
        self.retry_at.saturating_sub(now)
    }
}

/// The wait after `failures` wrong passwords: none for the first four, 30 s at the fifth, then
/// doubling.
pub fn wait_after(failures: u32) -> u64 {
    if failures < FREE_ATTEMPTS {
        return 0;
    }
    let doublings = (failures - FREE_ATTEMPTS).min(16);
    (FIRST_WAIT_SECS << doublings).min(MAX_WAIT_SECS)
}

/// Kept on disk so quitting and relaunching does not reset the wait.
pub struct UnlockBackoff {
    path: PathBuf,
}

impl UnlockBackoff {
    pub fn in_dir(data_dir: impl AsRef<Path>) -> Self {
        UnlockBackoff { path: data_dir.as_ref().join(BACKOFF_FILE) }
    }

    fn load(&self) -> BTreeMap<Uuid, Attempts> {
        std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&self, map: &BTreeMap<Uuid, Attempts>) -> Result<()> {
        write_atomic(&self.path, &serde_json::to_vec(map).map_err(|e| CoreError::Invalid(e.to_string()))?)
    }

    pub fn get(&self, doc: Uuid) -> Attempts {
        self.load().get(&doc).copied().unwrap_or_default()
    }

    /// `Err` with the wait when a password may not be tried yet.
    pub fn check(&self, doc: Uuid, now: u64) -> Result<()> {
        match self.get(doc).wait_secs(now) {
            0 => Ok(()),
            s => Err(CoreError::Invalid(format!("too many wrong passwords; try again in {s} s"))),
        }
    }

    /// Count a wrong password; returns the new state.
    pub fn record_failure(&self, doc: Uuid, now: u64) -> Result<Attempts> {
        let mut map = self.load();
        let failures = map.get(&doc).map_or(0, |a| a.failures).saturating_add(1);
        let wait = wait_after(failures);
        let a = Attempts { failures, retry_at: if wait == 0 { 0 } else { now + wait } };
        map.insert(doc, a);
        self.save(&map)?;
        Ok(a)
    }

    /// A successful unlock clears the count.
    pub fn record_success(&self, doc: Uuid) -> Result<()> {
        let mut map = self.load();
        if map.remove(&doc).is_some() {
            self.save(&map)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Auto-lock

/// Why the document should lock now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LockReason {
    Idle,
    ScreenLocked,
    Sleep,
}

/// The idle minutes in force: the user's value (0 = never) capped by a managed policy maximum.
pub fn effective_auto_lock_minutes(user_minutes: u32, policy_max: Option<u32>) -> u32 {
    match policy_max.filter(|m| *m > 0) {
        Some(max) if user_minutes == 0 || user_minutes > max => max,
        _ => user_minutes,
    }
}

/// [`effective_auto_lock_minutes`] with the cap from the policy in force.
pub fn policy_auto_lock_minutes(user_minutes: u32, policy: &crate::policy::Policy) -> u32 {
    effective_auto_lock_minutes(user_minutes, policy.document_auto_lock_max_minutes)
}

/// `Err` when the policy in force allows only the document password.
pub fn check_biometric_allowed(policy: &crate::policy::Policy) -> Result<()> {
    if policy.password_only_document_unlock {
        return Err(CoreError::PolicyDenied("your organisation requires the document password; biometric unlock is off".into()));
    }
    Ok(())
}

/// Whether to lock now. `idle_secs` is the time since the last keyboard or mouse input in the
/// app; `screen_locked` / `asleep` come from the OS. A "Remember unlock until I quit" choice
/// only skips the idle timer, never the screen lock or sleep.
pub fn auto_lock_due(minutes: u32, idle_secs: u64, screen_locked: bool, asleep: bool, remember_until_quit: bool) -> Option<LockReason> {
    if asleep {
        return Some(LockReason::Sleep);
    }
    if screen_locked {
        return Some(LockReason::ScreenLocked);
    }
    (!remember_until_quit && minutes > 0 && idle_secs >= u64::from(minutes) * 60).then_some(LockReason::Idle)
}

/// The complete document lock decision, keeping the managed cap's provenance (audit TM-02).
/// `user_minutes` is the user's own idle setting (0 = never) and `policy_max` the managed
/// maximum (`None` or 0 = no cap). "Remember unlock until I quit" suppresses only the user's
/// optional timeout: an enforced maximum still locks the document, and so do the screen lock
/// and sleep.
pub fn document_lock_due(user_minutes: u32, policy_max: Option<u32>, idle_secs: u64, screen_locked: bool, asleep: bool, remember_until_quit: bool) -> Option<LockReason> {
    let cap = policy_max.filter(|m| *m > 0);
    let minutes = if remember_until_quit { cap.unwrap_or(0) } else { effective_auto_lock_minutes(user_minutes, cap) };
    auto_lock_due(minutes, idle_secs, screen_locked, asleep, false)
}

// ---------------------------------------------------------------------------------------------
// Per-document state and recent document details

/// The folder for one document's own state (pass it as `data_dir` to `open_sessions` and
/// `connection_history`). Created owner-only on first use.
pub fn document_state_dir(data_dir: impl AsRef<Path>, doc: Uuid) -> Result<PathBuf> {
    let dir = data_dir.as_ref().join(STATE_DIR).join(doc.to_string());
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

fn opened_path(data_dir: &Path) -> PathBuf {
    data_dir.join(OPENED_FILE)
}

fn load_opened(data_dir: &Path) -> BTreeMap<PathBuf, u64> {
    std::fs::read(opened_path(data_dir)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// Remember when `doc` was last opened (kept only for paths still in the recent list).
pub fn record_opened(data_dir: &Path, doc: &Path, recent: &[PathBuf], at: u64) -> Result<()> {
    let mut map = load_opened(data_dir);
    map.insert(doc.to_path_buf(), at);
    map.retain(|p, _| recent.contains(p));
    write_atomic(&opened_path(data_dir), &serde_json::to_vec(&map).map_err(|e| CoreError::Invalid(e.to_string()))?)
}

fn load_counts(data_dir: &Path) -> BTreeMap<PathBuf, u32> {
    std::fs::read(data_dir.join(COUNTS_FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// Remember how many connections `doc` held when last saved or locked (only for paths still in
/// the recent list). A count is plain metadata: no name, host or secret.
pub fn record_connection_count(data_dir: &Path, doc: &Path, recent: &[PathBuf], count: u32) -> Result<()> {
    let mut map = load_counts(data_dir);
    if map.get(doc) == Some(&count) && map.keys().all(|p| recent.contains(p)) {
        return Ok(());
    }
    map.insert(doc.to_path_buf(), count);
    map.retain(|p, _| recent.contains(p));
    write_atomic(&data_dir.join(COUNTS_FILE), &serde_json::to_vec(&map).map_err(|e| CoreError::Invalid(e.to_string()))?)
}

/// One row of the Welcome screen's recent documents (and the Unlock screen's header).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentDocument {
    pub path: PathBuf,
    /// From the file header (readable while locked); `None` when the file is missing or unreadable.
    pub name: Option<String>,
    pub id: Option<Uuid>,
    /// False: greyed out with "Locate…".
    pub present: bool,
    pub protected: bool,
    pub biometric: bool,
    pub last_opened_at: Option<u64>,
    /// Connections at the last save or lock on this device; `None` when never recorded.
    pub connection_count: Option<u32>,
}

/// Details for `recent` (newest first). The first present one is the launch's "last document".
pub fn recent_details(data_dir: &Path, recent: &[PathBuf]) -> Vec<RecentDocument> {
    let opened = load_opened(data_dir);
    let counts = load_counts(data_dir);
    recent
        .iter()
        .map(|p| {
            let file = p.is_file().then(|| crate::docfile::DocumentFile::open(p).ok()).flatten();
            RecentDocument {
                path: p.clone(),
                name: file.as_ref().map(|f| f.name().to_string()),
                id: file.as_ref().map(|f| f.id()),
                present: file.is_some(),
                protected: file.as_ref().is_some_and(|f| f.is_protected()),
                biometric: file.as_ref().is_some_and(|f| f.biometric()),
                last_opened_at: opened.get(p).copied(),
                connection_count: if file.is_some() { counts.get(p).copied() } else { None },
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "docunlock_tests.rs"]
mod tests;
