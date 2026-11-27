//! Connection history for the inspector footer (`bastion_core::connection_history`): exactly two
//! lines, "Last connected: <time> as <user>" and "Last result: OK / <short error>". Owner-only
//! file in the data directory, no secrets.
use std::path::PathBuf;

use bastion_core::connection_history::ConnectionHistory;

use crate::{parse_id, FfiResult};

#[derive(uniffi::Record)]
pub struct ConnectionHistoryView {
    /// Unix seconds of the last successful connect; format it locally.
    pub last_connected_at: Option<u64>,
    pub last_user: Option<String>,
    /// "OK", a short one-line error, or `None` before the first attempt.
    pub last_result: Option<String>,
}

fn store(data_dir: &str) -> ConnectionHistory {
    ConnectionHistory::in_dir(PathBuf::from(data_dir))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[uniffi::export]
pub fn connection_history(data_dir: String, connection_id: String) -> FfiResult<ConnectionHistoryView> {
    let h = store(&data_dir).get(parse_id(&connection_id)?);
    Ok(ConnectionHistoryView { last_result: h.last_result().map(String::from), last_connected_at: h.last_connected_at, last_user: h.last_user })
}

/// Record a successful connect now, as `user` (`None` when the protocol has no user).
#[uniffi::export]
pub fn record_connection_success(data_dir: String, connection_id: String, user: Option<String>) -> FfiResult<()> {
    Ok(store(&data_dir).record_success(parse_id(&connection_id)?, user.as_deref(), now())?)
}

/// Record a failed attempt now; `error` is cut to one short secret-free line.
#[uniffi::export]
pub fn record_connection_failure(data_dir: String, connection_id: String, error: String) -> FfiResult<()> {
    Ok(store(&data_dir).record_failure(parse_id(&connection_id)?, &error, now())?)
}

/// Forget a connection's history (call when it is deleted).
#[uniffi::export]
pub fn forget_connection_history(data_dir: String, connection_id: String) -> FfiResult<()> {
    Ok(store(&data_dir).forget(parse_id(&connection_id)?)?)
}
