//! Read-only views of the audit log for the apps' Audit Log page (LOG-NATIVE-01 item 5): a page
//! of records, newest first, and the state of the hash chain. Nothing here writes, deletes or
//! repairs; the log stays append-only. Details were redacted when they were written.
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::Serialize;

use crate::audit::{hash, AuditEvent, GENESIS};
use crate::error::Result;

/// The most records one page returns.
pub const MAX_PAGE: usize = 500;

/// One page, newest first, and how many records the log holds. A line that does not parse is
/// left out here; [`check`] names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditPage {
    pub total: usize,
    pub records: Vec<AuditEvent>,
}

/// The hash chain: intact, or the first record (1-based) that does not follow from the one
/// before it (edited, deleted, reordered, or not a record at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditCheck {
    pub intact: bool,
    pub records: usize,
    pub changed_at: Option<usize>,
}

fn lines(path: &Path) -> Result<Vec<String>> {
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    f.lock_shared()?; // a writer's half-appended record is never read
    Ok(BufReader::new(f).lines().collect::<std::io::Result<Vec<_>>>()?)
}

/// Records `offset..offset + limit` counted from the newest. A missing log is empty.
pub fn page(path: &Path, offset: usize, limit: usize) -> Result<AuditPage> {
    let all = lines(path)?;
    let total = all.len();
    let records = all
        .iter()
        .rev()
        .skip(offset)
        .take(limit.min(MAX_PAGE))
        .filter_map(|l| serde_json::from_str::<AuditEvent>(l).ok())
        .collect();
    Ok(AuditPage { total, records })
}

/// Walk the chain from the first record. A missing log is intact with no records.
pub fn check(path: &Path) -> Result<AuditCheck> {
    let all = lines(path)?;
    let mut expected = GENESIS.to_string();
    for (n, line) in all.iter().enumerate() {
        let follows = serde_json::from_str::<AuditEvent>(line).is_ok_and(|e| e.prev_hash == expected);
        if !follows {
            return Ok(AuditCheck { intact: false, records: all.len(), changed_at: Some(n + 1) });
        }
        expected = hash(line);
    }
    Ok(AuditCheck { intact: true, records: all.len(), changed_at: None })
}

#[cfg(test)]
#[path = "audit_view_tests.rs"]
mod tests;
