//! Multi-host exec: one approved command on several SSH connections at once, with a bounded
//! number running together, a result per host, cancel, retry of the failed ones and export.
//! This module holds the rules; the bridge runs the sessions.
use serde::Serialize;

use crate::error::{CoreError, Result};
use crate::model::Connection;

pub const MAX_HOSTS: usize = 500;
pub const MAX_CONCURRENCY: u32 = 16;
const MAX_COMMAND: usize = 4096;
/// Output kept per host and stream; the rest is dropped with a marker.
pub const MAX_OUTPUT: usize = 256 * 1024;

/// What the user approved: the exact command and the exact hosts.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub command: String,
    pub hosts: Vec<Connection>,
    pub concurrency: u32,
}

/// Why a plan needs a stronger confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Review {
    /// Hosts classified production / customer-sensitive / privileged.
    pub sensitive: Vec<String>,
    /// The confirmation must name these hosts and require an extra acknowledgement.
    pub needs_production_ack: bool,
}

/// Check a plan before anything runs. One line only (a newline would run a second command
/// without review), no NUL or other control characters, SSH hosts only, no duplicates.
pub fn review(plan: &Plan) -> Result<Review> {
    let cmd = plan.command.trim();
    if cmd.is_empty() || cmd.len() > MAX_COMMAND {
        return Err(CoreError::Invalid(format!("The command must be 1 to {MAX_COMMAND} characters.")));
    }
    if cmd.chars().any(|c| c.is_control() && c != '\t') {
        return Err(CoreError::Invalid("The command must be a single line without control characters.".into()));
    }
    if plan.hosts.is_empty() || plan.hosts.len() > MAX_HOSTS {
        return Err(CoreError::Invalid(format!("Choose 1 to {MAX_HOSTS} hosts.")));
    }
    if !(1..=MAX_CONCURRENCY).contains(&plan.concurrency) {
        return Err(CoreError::Invalid(format!("Run 1 to {MAX_CONCURRENCY} hosts at a time.")));
    }
    let mut seen = std::collections::HashSet::new();
    for h in &plan.hosts {
        if !matches!(h.protocol, crate::model::Protocol::Ssh) {
            return Err(CoreError::Invalid(format!("{} is not an SSH connection.", h.name)));
        }
        if !seen.insert(h.id) {
            return Err(CoreError::Invalid(format!("{} is listed twice.", h.name)));
        }
    }
    let sensitive: Vec<String> = plan.hosts.iter().filter(|h| h.classification.is_sensitive()).map(|h| h.name.clone()).collect();
    Ok(Review { needs_production_ack: !sensitive.is_empty(), sensitive })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostState {
    Waiting,
    Running,
    /// Ran; `exit` holds the remote status (0 = success).
    Done,
    /// Could not connect or run (see `error`).
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostResult {
    pub host: String,
    pub state: HostState,
    pub exit: Option<u32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
    pub millis: u64,
}

impl HostResult {
    pub fn waiting(host: &str) -> HostResult {
        HostResult { host: host.into(), state: HostState::Waiting, exit: None, stdout: String::new(), stderr: String::new(), error: None, millis: 0 }
    }

    pub fn succeeded(&self) -> bool {
        self.state == HostState::Done && self.exit == Some(0)
    }
}

/// Bytes to text, capped at `MAX_OUTPUT`.
pub fn capture(bytes: &[u8]) -> String {
    let mut s = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_OUTPUT)]).into_owned();
    if bytes.len() > MAX_OUTPUT {
        s.push_str("\n[output truncated by Gantry]");
    }
    s
}

/// Indexes to run again: everything that did not succeed (failed, cancelled, non-zero exit).
pub fn retry_set(results: &[HostResult]) -> Vec<usize> {
    results.iter().enumerate().filter(|(_, r)| !r.succeeded() && r.state != HostState::Running).map(|(i, _)| i).collect()
}

/// Export as `json` (full results) or `csv` (host, state, exit, duration, first error line).
pub fn export(command: &str, results: &[HostResult], format: &str) -> Result<String> {
    match format {
        "json" => serde_json::to_string_pretty(&serde_json::json!({ "command": command, "results": results })).map_err(|e| CoreError::Corrupt(e.to_string())),
        "csv" => {
            let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
            let mut out = String::from("host,state,exit,millis,error\n");
            for r in results {
                let state = serde_json::to_value(r.state).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
                // A leading = + - @ would be read as a formula by spreadsheets.
                let cell = |s: &str| if s.starts_with(['=', '+', '-', '@']) { q(&format!("'{s}")) } else { q(s) };
                out.push_str(&format!(
                    "{},{},{},{},{}\n",
                    cell(&r.host),
                    state,
                    r.exit.map(|e| e.to_string()).unwrap_or_default(),
                    r.millis,
                    cell(r.error.as_deref().unwrap_or("").lines().next().unwrap_or(""))
                ));
            }
            Ok(out)
        }
        other => Err(CoreError::Invalid(format!("unknown export format {other}"))),
    }
}
