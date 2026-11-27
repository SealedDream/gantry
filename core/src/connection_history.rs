//! Connection history for the inspector footer, which shows exactly two lines:
//! "Last connected: <time> as <user>" and "Last result: OK / <short error>".
//!
//! Kept per connection id in its own owner-only file beside the library (so recording a connect
//! never bumps the library revision). It holds no secrets: a username, two timestamps and a short
//! one-line error. Error text is cut to one bounded line and anything that looks like a secret
//! assignment is dropped before it is written.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::store::write_atomic;

/// File name inside the app data directory.
pub const FILE_NAME: &str = "connection-history.json";
/// Connections remembered; the least recently used are dropped beyond this.
pub const MAX_CONNECTIONS: usize = 5000;
/// Longest short error kept, in characters.
pub const MAX_ERROR_CHARS: usize = 80;
/// Words that mark text as possibly holding a secret; such errors are stored generically.
const SECRET_WORDS: &[&str] = &["password", "passphrase", "secret", "token", "apikey", "api_key", "private key"];

/// What the footer shows for one connection. Times are Unix seconds; the app formats them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct History {
    /// Last successful connect.
    pub last_connected_at: Option<u64>,
    /// The user that connect logged in as.
    pub last_user: Option<String>,
    /// Time of the last attempt, successful or not.
    pub last_attempt_at: Option<u64>,
    /// `None` when the last attempt succeeded (or there was none); else its short error.
    pub last_error: Option<String>,
}

impl History {
    /// "OK", the short error, or `None` before the first attempt.
    pub fn last_result(&self) -> Option<&str> {
        self.last_attempt_at.map(|_| self.last_error.as_deref().unwrap_or("OK"))
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct HistoryFile {
    connections: BTreeMap<Uuid, History>,
}

/// A short, single-line, secret-free version of an error message.
pub fn short_error(message: &str) -> String {
    let line = message.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("Failed");
    let clean: String = line.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let clean = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    let lower = clean.to_ascii_lowercase();
    if SECRET_WORDS.iter().any(|w| lower.contains(w)) && clean.contains(['=', ':']) {
        return "Failed (details hidden)".into();
    }
    if clean.chars().count() <= MAX_ERROR_CHARS {
        return clean;
    }
    let cut: String = clean.chars().take(MAX_ERROR_CHARS - 1).collect();
    format!("{}…", cut.trim_end())
}

/// The footer's short error for a core error.
pub fn short_core_error(e: &CoreError) -> String {
    match e {
        CoreError::AuthFailed => "Authentication failed".into(),
        CoreError::TwoFactorRequired => "Two-factor code needed".into(),
        CoreError::Timeout => "Timed out".into(),
        CoreError::HostKeyUnknown { .. } | CoreError::JumpHostKeyUnknown { .. } => "Host key not trusted yet".into(),
        CoreError::HostKeyChanged { .. } => "Host key changed".into(),
        CoreError::NoCommonAlgorithm { .. } => "No common algorithm".into(),
        CoreError::Offline(_) => "Offline".into(),
        CoreError::PolicyDenied(_) => "Blocked by policy".into(),
        CoreError::VaultAuth => "Vault locked".into(),
        // Never echo what the leak guard caught.
        CoreError::SecretLeak(_) => "Failed (details hidden)".into(),
        other => short_error(&other.to_string()),
    }
}

pub struct ConnectionHistory {
    path: PathBuf,
}

impl ConnectionHistory {
    pub fn in_dir(data_dir: impl AsRef<Path>) -> Self {
        ConnectionHistory { path: data_dir.as_ref().join(FILE_NAME) }
    }

    /// Unreadable or missing file = no history (it is informational, never worth an error).
    fn load(&self) -> HistoryFile {
        std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&self, f: &HistoryFile) -> Result<()> {
        let json = serde_json::to_vec(f).map_err(|e| CoreError::Invalid(e.to_string()))?;
        write_atomic(&self.path, &json)
    }

    pub fn get(&self, id: Uuid) -> History {
        self.load().connections.remove(&id).unwrap_or_default()
    }

    /// Every remembered connection, for a list view.
    pub fn all(&self) -> BTreeMap<Uuid, History> {
        self.load().connections
    }

    /// A successful connect as `user` (`None` when the protocol has no user, e.g. VNC).
    pub fn record_success(&self, id: Uuid, user: Option<&str>, at: u64) -> Result<()> {
        let user = user.map(crate::recent_users::validate_username).transpose()?.map(String::from);
        self.update(id, |_h| History { last_connected_at: Some(at), last_user: user, last_attempt_at: Some(at), last_error: None })
    }

    /// A failed attempt; `error` is shortened with [`short_error`]. "Last connected" is kept.
    pub fn record_failure(&self, id: Uuid, error: &str, at: u64) -> Result<()> {
        let error = short_error(error);
        self.update(id, |h| History { last_attempt_at: Some(at), last_error: Some(error), ..h })
    }

    fn update(&self, id: Uuid, f: impl FnOnce(History) -> History) -> Result<()> {
        let mut file = self.load();
        let old = file.connections.remove(&id).unwrap_or_default();
        file.connections.insert(id, f(old));
        if file.connections.len() > MAX_CONNECTIONS {
            let mut by_age: Vec<(u64, Uuid)> = file.connections.iter().filter(|(k, _)| **k != id).map(|(k, h)| (h.last_attempt_at.unwrap_or(0), *k)).collect();
            by_age.sort();
            let excess = file.connections.len() - MAX_CONNECTIONS;
            for (_, k) in by_age.into_iter().take(excess) {
                file.connections.remove(&k);
            }
        }
        self.save(&file)
    }

    /// Forget one connection (e.g. when it is deleted).
    pub fn forget(&self, id: Uuid) -> Result<()> {
        let mut file = self.load();
        if file.connections.remove(&id).is_some() {
            self.save(&file)?;
        }
        Ok(())
    }

    /// Drop history for connections not in `live`; returns how many were dropped.
    pub fn prune(&self, live: &[Uuid]) -> Result<usize> {
        let mut file = self.load();
        let before = file.connections.len();
        file.connections.retain(|k, _| live.contains(k));
        let dropped = before - file.connections.len();
        if dropped > 0 {
            self.save(&file)?;
        }
        Ok(dropped)
    }
}
