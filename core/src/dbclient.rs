//! DEPRECATED (PLUG-11, owner 2026-11-23): Native Mac and Native Windows no longer use this; the PostgreSQL
//! plugin replaces it. Kept only for the paused Tauri app. Fixes only; remove with the Tauri page and `tokio-postgres`.
//! Database client, step 1: a PostgreSQL query tool that reaches the server through a Bastion
//! tunnel.
//!
//! The request names the database server as the *remote* side sees it (`host`, `port`) and how
//! to get there (`via`): through a running local (`-L`) tunnel's listening port, through a
//! running SOCKS (`-D`) tunnel (the SSH server resolves `host`), or direct. Step 1 speaks plain
//! PostgreSQL wire protocol without TLS, so a direct connection is only allowed to a loopback
//! address; anything else must go through a tunnel, where SSH encrypts the hop.
//!
//! Results come back as text (PostgreSQL's simple query protocol), capped at `max_rows` per
//! statement. `read_only` (the default) starts the session with
//! `default_transaction_read_only=on`: a guard against mistakes, not a permission boundary — use
//! a read-only database role for that. The password is only used for the login and never
//! returned or logged.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use futures::{pin_mut, TryStreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_postgres::{Config, NoTls, SimpleQueryMessage};

use crate::error::{CoreError, Result};

/// Rows returned per statement unless the request asks for fewer.
pub const DEFAULT_MAX_ROWS: usize = 1000;
/// Hard ceiling on `max_rows`, so one query can't exhaust memory.
pub const MAX_ROWS_LIMIT: usize = 100_000;
/// Whole-query time limit unless the request sets one.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Hard ceiling on `timeout_secs`.
pub const MAX_TIMEOUT_SECS: u64 = 3600;
/// Longest SQL text accepted.
pub const MAX_SQL_BYTES: usize = 1 << 20;

/// How the client reaches the database server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DbRoute {
    /// Straight to `host:port`. Loopback only (no TLS in step 1).
    #[default]
    Direct,
    /// A running `-L` tunnel listening on `127.0.0.1:port` whose far end is the database server;
    /// `host`/`port` in the request are informational.
    Forward { port: u16 },
    /// A running `-D` tunnel on `127.0.0.1:port`; the SSH server connects on to `host:port`.
    Socks { port: u16 },
}

/// One query run.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DbQuery {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub database: Option<String>,
    pub sql: String,
    #[serde(default)]
    pub via: DbRoute,
    #[serde(default)]
    pub max_rows: Option<usize>,
    #[serde(default = "yes")]
    pub read_only: bool,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

fn default_port() -> u16 {
    5432
}

fn yes() -> bool {
    true
}

/// One statement's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DbStatement {
    pub columns: Vec<String>,
    /// Each value as PostgreSQL's text form; `None` is SQL NULL.
    pub rows: Vec<Vec<Option<String>>>,
    /// More rows existed than `max_rows`.
    pub truncated: bool,
    /// Rows the server reported (selected or affected), counting any past the cap.
    pub row_count: u64,
}

/// Everything a query returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DbResult {
    pub statements: Vec<DbStatement>,
    pub elapsed_ms: u64,
}

impl DbQuery {
    fn validate(&self) -> Result<(usize, Duration)> {
        if self.host.trim().is_empty() {
            return Err(CoreError::Invalid("Enter the database host.".into()));
        }
        if self.user.trim().is_empty() {
            return Err(CoreError::Invalid("Enter the database user.".into()));
        }
        if self.sql.trim().is_empty() {
            return Err(CoreError::Invalid("Enter a query to run.".into()));
        }
        if self.sql.len() > MAX_SQL_BYTES {
            return Err(CoreError::Invalid("The query is longer than 1 MB.".into()));
        }
        if self.port == 0 || matches!(self.via, DbRoute::Forward { port: 0 } | DbRoute::Socks { port: 0 }) {
            return Err(CoreError::Invalid("Port 0 is not a valid port.".into()));
        }
        if self.via == DbRoute::Direct && !is_loopback(&self.host) {
            return Err(CoreError::Invalid(
                "Without TLS the database client only connects directly to this computer; choose a tunnel to reach another host.".into(),
            ));
        }
        let rows = self.max_rows.unwrap_or(DEFAULT_MAX_ROWS);
        if rows == 0 || rows > MAX_ROWS_LIMIT {
            return Err(CoreError::Invalid(format!("Row limit must be 1 to {MAX_ROWS_LIMIT}.")));
        }
        let secs = self.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if secs == 0 || secs > MAX_TIMEOUT_SECS {
            return Err(CoreError::Invalid(format!("Time limit must be 1 to {MAX_TIMEOUT_SECS} seconds.")));
        }
        Ok((rows, Duration::from_secs(secs)))
    }

    fn config(&self) -> Config {
        let mut c = Config::new();
        c.user(&self.user).dbname(self.database.as_deref().unwrap_or(&self.user)).application_name("Gantry");
        if let Some(p) = &self.password {
            c.password(p);
        }
        if self.read_only {
            c.options("-c default_transaction_read_only=on");
        }
        c
    }
}

/// `localhost` or a loopback IP literal.
pub fn is_loopback(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    h.eq_ignore_ascii_case("localhost") || h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Run `q` and collect its results. Errors name what went wrong without echoing the password.
pub async fn run_query(q: &DbQuery) -> Result<DbResult> {
    let (max_rows, limit) = q.validate()?;
    let started = Instant::now();
    let statements = connect_and_run(q, max_rows, limit).await?;
    Ok(DbResult { statements, elapsed_ms: started.elapsed().as_millis() as u64 })
}

/// How long a timed-out query's server-side cancel request may take before it is given up.
const CANCEL_GRACE: Duration = Duration::from_secs(3);

/// Aborts the connection driver task when dropped, so it never outlives the query — whether the
/// query completes, fails, times out or the caller's future is dropped (audit CC-01). A bare
/// `JoinHandle` detaches its task on drop, which left drivers running on persistent runtimes.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn timed_out(limit: Duration) -> CoreError {
    CoreError::Invalid(format!("The query took longer than {} seconds and was stopped.", limit.as_secs()))
}

async fn connect_and_run(q: &DbQuery, max_rows: usize, limit: Duration) -> Result<Vec<DbStatement>> {
    let deadline = tokio::time::Instant::now() + limit;
    let connect = async {
        let stream = open_stream(q).await?;
        q.config().connect_raw(stream, NoTls).await.map_err(pg_err)
    };
    let (client, conn) = tokio::time::timeout_at(deadline, connect).await.map_err(|_| timed_out(limit))??;
    let _driver = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));
    match tokio::time::timeout_at(deadline, collect(&client, &q.sql, max_rows)).await {
        Ok(out) => out,
        Err(_) => {
            // Ask the server to stop the statement too (best effort, bounded): dropping the
            // socket alone does not stop SQL that is already running.
            let token = client.cancel_token();
            let cancel = async {
                let stream = open_stream(q).await?;
                token.cancel_query_raw(stream, NoTls).await.map_err(pg_err)
            };
            let _ = tokio::time::timeout(CANCEL_GRACE, cancel).await;
            Err(timed_out(limit))
        }
    }
}

async fn collect(client: &tokio_postgres::Client, sql: &str, max_rows: usize) -> Result<Vec<DbStatement>> {
    let stream = client.simple_query_raw(sql).await.map_err(pg_err)?;
    pin_mut!(stream);
    let mut out = Vec::new();
    let mut cur: Option<DbStatement> = None;
    while let Some(msg) = stream.try_next().await.map_err(pg_err)? {
        match msg {
            SimpleQueryMessage::RowDescription(cols) => {
                cur = Some(DbStatement { columns: cols.iter().map(|c| c.name().to_string()).collect(), ..empty() });
            }
            SimpleQueryMessage::Row(row) => {
                let st = cur.get_or_insert_with(empty);
                if st.rows.len() < max_rows {
                    st.rows.push((0..row.len()).map(|i| row.get(i).map(str::to_string)).collect());
                } else {
                    st.truncated = true;
                }
            }
            SimpleQueryMessage::CommandComplete(n) => {
                let mut st = cur.take().unwrap_or_else(empty);
                st.row_count = n;
                out.push(st);
            }
            _ => {}
        }
    }
    Ok(out)
}

fn empty() -> DbStatement {
    DbStatement { columns: Vec::new(), rows: Vec::new(), truncated: false, row_count: 0 }
}

fn pg_err(e: tokio_postgres::Error) -> CoreError {
    match e.as_db_error() {
        Some(db) => CoreError::Invalid(format!("PostgreSQL: {} ({})", db.message(), db.code().code())),
        None => CoreError::Invalid(format!("PostgreSQL connection failed: {e}")),
    }
}

async fn open_stream(q: &DbQuery) -> Result<TcpStream> {
    let lo = |port| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    match q.via {
        DbRoute::Direct => TcpStream::connect((q.host.trim(), q.port)).await.map_err(|e| unreachable(&q.host, e)),
        DbRoute::Forward { port } => TcpStream::connect(lo(port)).await.map_err(|e| tunnel_down(port, e)),
        DbRoute::Socks { port } => {
            let mut s = TcpStream::connect(lo(port)).await.map_err(|e| tunnel_down(port, e))?;
            socks5_connect(&mut s, q.host.trim(), q.port).await?;
            Ok(s)
        }
    }
}

fn unreachable(host: &str, e: std::io::Error) -> CoreError {
    CoreError::Invalid(format!("Couldn't reach the database at {host}: {e}"))
}

fn tunnel_down(port: u16, e: std::io::Error) -> CoreError {
    CoreError::Invalid(format!("The tunnel on port {port} isn't running ({e}); start it first."))
}

/// SOCKS5 CONNECT with no authentication (Bastion's own `-D` listener), the host sent as a name
/// so the SSH server resolves it.
pub(crate) async fn socks5_connect(s: &mut TcpStream, host: &str, port: u16) -> Result<()> {
    if host.is_empty() || host.len() > 255 {
        return Err(CoreError::Invalid("The database host name is too long for a SOCKS tunnel.".into()));
    }
    let fail = |what: &str| CoreError::Invalid(format!("The SOCKS tunnel {what}."));
    s.write_all(&[5, 1, 0]).await?;
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello).await?;
    if hello != [5, 0] {
        return Err(fail("wants a login Gantry doesn't use"));
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 5 || head[1] != 0 {
        return Err(fail(&format!("couldn't reach {host}:{port} (code {})", head[1])));
    }
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => s.read_u8().await? as usize,
        _ => return Err(fail("sent a reply Gantry doesn't understand")),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await?;
    Ok(())
}

#[cfg(test)]
#[path = "dbclient_tests.rs"]
mod tests;
