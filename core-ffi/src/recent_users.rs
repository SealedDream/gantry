//! Recent usernames per host for "Connect as…" / "Reconnect as…" (`core::recent_users`). Usernames
//! only: the dialog's password or key never reaches this module.
use bastion_core::recent_users::RecentUsers;

use crate::FfiResult;

/// Suggestions for a host, newest first.
#[uniffi::export]
pub fn recent_usernames(data_dir: String, host: String, port: Option<u16>) -> FfiResult<Vec<String>> {
    Ok(RecentUsers::in_dir(data_dir).list(&host, port)?)
}

/// Remember `username` for a host after a successful Connect as…, newest first.
#[uniffi::export]
pub fn record_recent_username(data_dir: String, host: String, port: Option<u16>, username: String) -> FfiResult<()> {
    Ok(RecentUsers::in_dir(data_dir).record(&host, port, &username)?)
}

/// Forget one suggestion, or every one for the host when `username` is None.
#[uniffi::export]
pub fn forget_recent_username(data_dir: String, host: String, port: Option<u16>, username: Option<String>) -> FfiResult<()> {
    Ok(RecentUsers::in_dir(data_dir).forget(&host, port, username.as_deref())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_through_the_bridge() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().to_str().unwrap().to_string();
        record_recent_username(dir.clone(), "h".into(), Some(22), "alice".into()).unwrap();
        record_recent_username(dir.clone(), "h".into(), Some(22), "bob".into()).unwrap();
        assert_eq!(recent_usernames(dir.clone(), "H".into(), Some(22)).unwrap(), ["bob", "alice"]);
        assert!(record_recent_username(dir.clone(), "h".into(), None, "a b".into()).is_err());
        forget_recent_username(dir.clone(), "h".into(), Some(22), None).unwrap();
        assert!(recent_usernames(dir, "h".into(), Some(22)).unwrap().is_empty());
    }
}
