//! Session restore and recents (`bastion_core::open_sessions`). The open-session set and the
//! launch plan cross as JSON, the same shapes the C ABI takes, so every app shares one set of rules.
//!
//! Lifecycle: at launch call `Library::open_sessions_begin` once, open the plan's tabs (they
//! reconnect with `restore_reconnect_policy`); call `open_sessions_save` after every tab change;
//! call `open_sessions_mark_clean_quit` on a normal quit. No secrets are stored.
use bastion_core::open_sessions::{self, OpenSessionSet, OpenSessionStore};

use crate::{FfiError, FfiResult, Library};

fn to_json<T: serde::Serialize>(v: &T) -> FfiResult<String> {
    serde_json::to_string(v).map_err(|e| FfiError::failed(e.to_string()))
}

/// Save the open-session set after any change. `set_json`:
/// `{"tabs":[{"connection","mode":"terminal|files","layout"?,"group"?,"cwd"?}],"selected":0,"groups":[…]}`.
#[uniffi::export]
pub fn open_sessions_save(data_dir: String, set_json: String) -> FfiResult<()> {
    let set: OpenSessionSet = serde_json::from_str(&set_json).map_err(|e| FfiError::failed(format!("invalid open-session set: {e}")))?;
    Ok(OpenSessionStore::in_dir(data_dir).save(set)?)
}

/// Mark a clean quit (call after the last save). The set is kept for "Restore sessions on launch".
#[uniffi::export]
pub fn open_sessions_mark_clean_quit(data_dir: String) -> FfiResult<()> {
    Ok(OpenSessionStore::in_dir(data_dir).mark_clean_quit()?)
}

/// The id of the "Restore sessions on launch" setting (toggle, default on).
#[uniffi::export]
pub fn open_sessions_restore_setting_id() -> String {
    open_sessions::RESTORE_SETTING.into()
}

#[uniffi::export]
impl Library {
    /// Call once at launch. Returns the plan JSON
    /// `{"lastExit":"none|clean|crash","restore","tabs":[…],"selected"?,"groups","missing","autoReconnect"}`.
    /// After a crash tabs always come back; after a clean quit only when `restore_on_launch`.
    pub fn open_sessions_begin(&self, data_dir: String, restore_on_launch: bool) -> FfiResult<String> {
        let ids: std::collections::HashSet<_> = self.lock().connections().into_iter().map(|r| r.connection.id).collect();
        let plan = OpenSessionStore::in_dir(data_dir).begin(restore_on_launch, |id| ids.contains(id))?;
        to_json(&plan)
    }

    /// Start page "Recent sessions", most recent first, at most `limit` (capped at 200):
    /// `[{"connection","name","host","port","user","protocol","lastConnectedAt","lastError"}]`.
    /// Remove one with `forget_connection_history`.
    pub fn recent_sessions_json(&self, data_dir: String, limit: u32) -> FfiResult<String> {
        let history = bastion_core::connection_history::ConnectionHistory::in_dir(data_dir);
        to_json(&open_sessions::recents(&history, &self.lock(), limit as usize))
    }
}
