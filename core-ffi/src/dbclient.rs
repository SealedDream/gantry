//! DEPRECATED (PLUG-11, owner 2026-11-23): Native Mac and Native Windows no longer use this; the PostgreSQL
//! plugin replaces it. Kept only for the paused Tauri app. Fixes only; remove with the Tauri page and `tokio-postgres`.
//! Database client bridge (`bastion_core::dbclient`, step 1: PostgreSQL). Stateless: each call
//! connects, runs the SQL and disconnects. Direct routes are loopback only; anything else goes
//! through a running `-L` or `-D` tunnel. Blocking: call off the main thread.
use bastion_core::dbclient::{run_query, DbQuery, DbRoute};

use crate::terminal::RUNTIME;
use crate::{FfiError, FfiResult};

/// How the query reaches the server.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbRouteView {
    /// `host:port` on this Mac (loopback only).
    Direct,
    /// A running `-L` tunnel's local port.
    Forward { port: u16 },
    /// A running `-D` tunnel's local port; the SSH server connects on to `host:port`.
    Socks { port: u16 },
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct DbQueryRequest {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub database: Option<String>,
    pub sql: String,
    pub via: DbRouteView,
    pub max_rows: Option<u32>,
    pub read_only: bool,
    pub timeout_secs: Option<u32>,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct DbStatementView {
    pub columns: Vec<String>,
    /// Text form of each value; `None` is SQL NULL.
    pub rows: Vec<Vec<Option<String>>>,
    pub truncated: bool,
    pub row_count: u64,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct DbResultView {
    pub statements: Vec<DbStatementView>,
    pub elapsed_ms: u64,
}

fn route(v: DbRouteView) -> DbRoute {
    match v {
        DbRouteView::Direct => DbRoute::Direct,
        DbRouteView::Forward { port } => DbRoute::Forward { port },
        DbRouteView::Socks { port } => DbRoute::Socks { port },
    }
}

fn query(r: DbQueryRequest) -> DbQuery {
    DbQuery {
        host: r.host.trim().to_string(),
        port: r.port,
        user: r.user.trim().to_string(),
        password: r.password.filter(|p| !p.is_empty()),
        database: r.database.map(|d| d.trim().to_string()).filter(|d| !d.is_empty()),
        sql: r.sql,
        via: route(r.via),
        max_rows: r.max_rows.map(|n| n as usize),
        read_only: r.read_only,
        timeout_secs: r.timeout_secs.map(u64::from),
    }
}

/// Run one query. Errors name what failed (bad request, tunnel not running, login, SQL, time
/// limit) and never echo the password.
#[uniffi::export]
pub fn db_query(request: DbQueryRequest) -> FfiResult<DbResultView> {
    let q = query(request);
    let r = RUNTIME.block_on(run_query(&q)).map_err(|e| FfiError::failed(e.to_string()))?;
    Ok(DbResultView {
        statements: r
            .statements
            .into_iter()
            .map(|s| DbStatementView { columns: s.columns, rows: s.rows, truncated: s.truncated, row_count: s.row_count })
            .collect(),
        elapsed_ms: r.elapsed_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(via: DbRouteView) -> DbQueryRequest {
        DbQueryRequest {
            host: " db.internal ".into(),
            port: 5432,
            user: " app ".into(),
            password: Some(String::new()),
            database: Some("  ".into()),
            sql: "select 1".into(),
            via,
            max_rows: Some(10),
            read_only: true,
            timeout_secs: Some(5),
        }
    }

    #[test]
    fn request_maps_and_trims() {
        let q = query(req(DbRouteView::Socks { port: 1080 }));
        assert_eq!(q.host, "db.internal");
        assert_eq!(q.user, "app");
        assert_eq!(q.password, None);
        assert_eq!(q.database, None);
        assert_eq!(q.via, DbRoute::Socks { port: 1080 });
        assert_eq!(q.max_rows, Some(10));
        assert_eq!(q.timeout_secs, Some(5));
    }

    #[test]
    fn direct_to_remote_host_is_refused_by_core() {
        let e = db_query(req(DbRouteView::Direct)).unwrap_err();
        assert!(e.to_string().to_lowercase().contains("loopback") || e.to_string().contains("tunnel"), "{e}");
    }

    #[test]
    fn forward_to_closed_port_fails_cleanly() {
        let mut r = req(DbRouteView::Forward { port: 1 });
        r.password = Some("hunter2".into());
        let e = db_query(r).unwrap_err().to_string();
        assert!(!e.contains("hunter2"), "{e}");
    }
}
