//! Which helpers stop when a document or the credentials lock (spec section 5, `credentials`
//! row; owner decision 8; T18.27).
//!
//! Helpers keep running on lock, as live sessions do, and nothing new is released while
//! credentials are locked ([`super::grants::HelperGrants::begin_release`]). Two cases stop
//! helpers, both as ordinary stops (abort bytes are sent, editor text is kept).

use crate::policy::Policy;

use super::StopReason;

/// What the lock logic needs to know about one running helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningHelper {
    pub helper_id: u64,
    /// The document holding the helper's entry, if it has one.
    pub document_id: Option<String>,
    pub holds_release: bool,
}

/// A document locked. Its plugin helpers stop with its sessions when its "Close sessions on
/// lock" setting is on.
pub fn on_document_lock(document_id: &str, close_sessions_on_lock: bool, helpers: &[RunningHelper]) -> Vec<(u64, StopReason)> {
    if !close_sessions_on_lock {
        return Vec::new();
    }
    helpers.iter().filter(|h| h.document_id.as_deref() == Some(document_id)).map(|h| (h.helper_id, StopReason::DocumentLocked)).collect()
}

/// Credentials locked (manually, on screen lock or sleep, or by auto-lock). Helpers that hold a
/// released password stop only when managed policy says so.
pub fn on_credentials_lock(policy: &Policy, helpers: &[RunningHelper]) -> Vec<(u64, StopReason)> {
    if !policy.stop_plugin_helpers_on_credentials_lock {
        return Vec::new();
    }
    helpers.iter().filter(|h| h.holds_release).map(|h| (h.helper_id, StopReason::CredentialsLockedByPolicy)).collect()
}
