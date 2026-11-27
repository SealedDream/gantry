//! The Audit Log page (LOG-NATIVE-01 item 5): read-only. A page of audit records, newest
//! first, and the state of the hash chain. The log is `audit.jsonl` in `data_dir`.
use std::path::Path;

use bastion_core::audit_view;

use crate::{FfiError, FfiResult};

fn to_json<T: serde::Serialize>(v: &T) -> FfiResult<String> {
    serde_json::to_string(v).map_err(|e| FfiError::failed(e.to_string()))
}

/// `{"total":n,"records":[{"id","ts_unix_ms","category","action","actor","target","outcome",
/// "correlation_id","details":{…},"prev_hash"}]}`, newest first. `limit` is capped at 500. A
/// missing log is empty; a line that is not a record is left out (`audit_verify_json` names it).
#[uniffi::export]
pub fn audit_read_json(data_dir: String, offset: u32, limit: u32) -> FfiResult<String> {
    to_json(&audit_view::page(&Path::new(&data_dir).join("audit.jsonl"), offset as usize, limit as usize)?)
}

/// `{"intact":bool,"records":n,"changedAt":n|null}`: `changedAt` is the first record (1-based)
/// that does not follow from the one before it. A missing log is intact with 0 records.
#[uniffi::export]
pub fn audit_verify_json(data_dir: String) -> FfiResult<String> {
    to_json(&audit_view::check(&Path::new(&data_dir).join("audit.jsonl"))?)
}
