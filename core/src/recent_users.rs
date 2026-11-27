//! Recent usernames per host for "Connect as…" / "Reconnect as…": the names a user typed for a
//! host, newest first, offered as suggestions next time. Only usernames are kept (never a password,
//! key path or passphrase), in their own file beside the library so recording one never bumps the
//! library revision.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{CoreError, Result};
use crate::store::write_atomic;

/// File name inside the app data directory.
pub const FILE_NAME: &str = "recent-users.json";
/// Suggestions kept per host.
pub const MAX_PER_HOST: usize = 8;
/// Hosts remembered; the least recently used host is dropped beyond this.
pub const MAX_HOSTS: usize = 500;
/// Longest username accepted.
pub const MAX_USERNAME_LEN: usize = 256;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct RecentFile {
    /// Host key (lowercase host, `:port` when given) → usernames, newest first.
    hosts: BTreeMap<String, Vec<String>>,
    /// Host keys, most recently used last (for the `MAX_HOSTS` cap).
    order: Vec<String>,
}

/// The key a host's suggestions are filed under: case-insensitive host, port only when given.
pub fn host_key(host: &str, port: Option<u16>) -> Result<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || host.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(CoreError::Invalid("host must be a non-empty host name or address".into()));
    }
    Ok(match port {
        Some(p) => format!("{host}:{p}"),
        None => host,
    })
}

/// A username the store accepts: non-empty, no whitespace or control characters, bounded.
pub fn validate_username(user: &str) -> Result<&str> {
    let user = user.trim();
    if user.is_empty() {
        return Err(CoreError::Invalid("username is empty".into()));
    }
    if user.len() > MAX_USERNAME_LEN || user.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(CoreError::Invalid("username has spaces or control characters, or is too long".into()));
    }
    Ok(user)
}

pub struct RecentUsers {
    path: PathBuf,
}

impl RecentUsers {
    pub fn in_dir(data_dir: impl AsRef<Path>) -> Self {
        RecentUsers { path: data_dir.as_ref().join(FILE_NAME) }
    }

    /// Unreadable or missing file = no suggestions (they are a convenience, never worth an error).
    fn load(&self) -> RecentFile {
        std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&self, f: &RecentFile) -> Result<()> {
        let json = serde_json::to_vec_pretty(f).map_err(|e| CoreError::Invalid(e.to_string()))?;
        write_atomic(&self.path, &json)
    }

    /// Suggestions for a host, newest first.
    pub fn list(&self, host: &str, port: Option<u16>) -> Result<Vec<String>> {
        let key = host_key(host, port)?;
        Ok(self.load().hosts.get(&key).cloned().unwrap_or_default())
    }

    /// Put `user` first for this host (moving it if already there), keeping `MAX_PER_HOST`.
    pub fn record(&self, host: &str, port: Option<u16>, user: &str) -> Result<()> {
        let key = host_key(host, port)?;
        let user = validate_username(user)?.to_string();
        let old = self.load();
        let users: Vec<String> = std::iter::once(user.clone())
            .chain(old.hosts.get(&key).into_iter().flatten().filter(|u| **u != user).cloned())
            .take(MAX_PER_HOST)
            .collect();
        let mut order: Vec<String> = old.order.iter().filter(|k| **k != key && old.hosts.contains_key(*k)).cloned().collect();
        order.push(key.clone());
        let kept = order.split_off(order.len().saturating_sub(MAX_HOSTS));
        let mut hosts: BTreeMap<String, Vec<String>> = old.hosts.into_iter().filter(|(k, _)| kept.contains(k)).collect();
        hosts.insert(key, users);
        self.save(&RecentFile { hosts, order: kept })
    }

    /// Forget one username for a host, or all of them when `user` is None.
    pub fn forget(&self, host: &str, port: Option<u16>, user: Option<&str>) -> Result<()> {
        let key = host_key(host, port)?;
        let old = self.load();
        let hosts: BTreeMap<String, Vec<String>> = old
            .hosts
            .into_iter()
            .filter_map(|(k, v)| {
                if k != key {
                    return Some((k, v));
                }
                let rest: Vec<String> = user.map(|u| v.into_iter().filter(|x| x != u).collect()).unwrap_or_default();
                (!rest.is_empty()).then_some((k, rest))
            })
            .collect();
        let order = old.order.into_iter().filter(|k| hosts.contains_key(k)).collect();
        self.save(&RecentFile { hosts, order })
    }
}
