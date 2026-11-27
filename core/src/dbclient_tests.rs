use super::*;
use tokio::net::TcpListener;

fn query(host: &str, via: DbRoute) -> DbQuery {
    serde_json::from_value(serde_json::json!({ "host": host, "user": "app", "sql": "select 1", "via": via })).unwrap()
}

fn invalid(q: &DbQuery) -> String {
    q.validate().unwrap_err().to_string()
}

#[test]
fn request_defaults_are_safe() {
    let q = query("127.0.0.1", DbRoute::Direct);
    assert_eq!((q.port, q.read_only, q.via.clone()), (5432, true, DbRoute::Direct));
    assert_eq!(q.validate().unwrap(), (DEFAULT_MAX_ROWS, Duration::from_secs(DEFAULT_TIMEOUT_SECS)));
    let bad: std::result::Result<DbQuery, _> = serde_json::from_str(r#"{"host":"h","user":"u","sql":"x","sslmode":"disable"}"#);
    assert!(bad.is_err(), "unknown fields are refused, not ignored");
}

#[test]
fn direct_connections_are_loopback_only() {
    assert!(invalid(&query("db.example.com", DbRoute::Direct)).contains("tunnel"));
    assert!(invalid(&query("10.0.0.5", DbRoute::Direct)).contains("tunnel"));
    for h in ["localhost", "127.0.0.1", "::1", "[::1]", " LOCALHOST "] {
        assert!(query(h, DbRoute::Direct).validate().is_ok(), "{h}");
    }
    assert!(query("db.internal", DbRoute::Forward { port: 15432 }).validate().is_ok());
    assert!(query("db.internal", DbRoute::Socks { port: 1080 }).validate().is_ok());
}

#[test]
fn limits_and_required_fields_are_checked() {
    let base = query("localhost", DbRoute::Direct);
    let with = |f: &dyn Fn(&mut DbQuery)| {
        let mut q = base.clone();
        f(&mut q);
        invalid(&q)
    };
    assert!(with(&|q| q.host = " ".into()).contains("host"));
    assert!(with(&|q| q.user = String::new()).contains("user"));
    assert!(with(&|q| q.sql = "  ".into()).contains("query"));
    assert!(with(&|q| q.sql = "x".repeat(MAX_SQL_BYTES + 1)).contains("1 MB"));
    assert!(with(&|q| q.port = 0).contains("Port 0"));
    assert!(with(&|q| q.via = DbRoute::Forward { port: 0 }).contains("Port 0"));
    assert!(with(&|q| q.max_rows = Some(0)).contains("Row limit"));
    assert!(with(&|q| q.max_rows = Some(MAX_ROWS_LIMIT + 1)).contains("Row limit"));
    assert!(with(&|q| q.timeout_secs = Some(0)).contains("Time limit"));
    assert!(with(&|q| q.timeout_secs = Some(MAX_TIMEOUT_SECS + 1)).contains("Time limit"));
}

#[test]
fn config_sets_read_only_and_defaults_database_to_user() {
    let mut q = query("localhost", DbRoute::Direct);
    q.password = Some("s3cret".into());
    let c = q.config();
    assert_eq!((c.get_user(), c.get_dbname()), (Some("app"), Some("app")));
    assert_eq!(c.get_options(), Some("-c default_transaction_read_only=on"));
    q.read_only = false;
    assert_eq!(q.config().get_options(), None);
}

#[tokio::test]
async fn a_stopped_tunnel_is_named_in_the_error() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let e = run_query(&query("db", DbRoute::Forward { port })).await.unwrap_err().to_string();
    assert!(e.contains(&format!("port {port}")) && e.contains("start it"), "{e}");
}

/// A fake SOCKS5 server: checks the CONNECT request, replies with `code` and a domain-name bound
/// address, and returns what it was asked for.
async fn fake_socks(code: u8) -> (u16, tokio::task::JoinHandle<(String, u16)>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut hello = [0u8; 3];
        s.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello, [5, 1, 0]);
        s.write_all(&[5, 0]).await.unwrap();
        let mut head = [0u8; 5];
        s.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..4], &[5, 1, 0, 3], "CONNECT by name");
        let mut name = vec![0u8; head[4] as usize + 2];
        s.read_exact(&mut name).await.unwrap();
        let p = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
        name.truncate(name.len() - 2);
        s.write_all(&[5, code, 0, 3, 2, b'o', b'k', 0, 1]).await.unwrap();
        (String::from_utf8(name).unwrap(), p)
    });
    (port, task)
}

#[tokio::test]
async fn socks_connect_sends_the_name_for_remote_resolution() {
    let (port, server) = fake_socks(0).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socks5_connect(&mut s, "pgdb.internal", 5433).await.unwrap();
    assert_eq!(server.await.unwrap(), ("pgdb.internal".to_string(), 5433));
}

#[tokio::test]
async fn socks_refusal_is_reported() {
    let (port, _server) = fake_socks(5).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let e = socks5_connect(&mut s, "pgdb", 5432).await.unwrap_err().to_string();
    assert!(e.contains("couldn't reach pgdb:5432") && e.contains("code 5"), "{e}");
}

/// What a fake PostgreSQL server saw: whether the client's socket closed after the timeout, and
/// whether a cancel request arrived on a second connection.
struct StallReport {
    socket_closed: bool,
    cancel_requested: bool,
}

/// A fake server that completes startup, accepts one query and never answers it (CC-01).
async fn stalling_postgres(respond: bool) -> (u16, tokio::task::JoinHandle<StallReport>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let len = s.read_u32().await.unwrap() as usize;
        let mut startup = vec![0; len - 4];
        s.read_exact(&mut startup).await.unwrap();
        let mut hello = vec![b'R', 0, 0, 0, 8, 0, 0, 0, 0];
        hello.extend_from_slice(&[b'K', 0, 0, 0, 12, 0, 0, 0, 7, 0, 0, 0, 9]);
        hello.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
        s.write_all(&hello).await.unwrap();
        let mut buf = [0u8; 512];
        let _ = s.read(&mut buf).await.unwrap(); // the query
        if respond {
            let mut done = vec![b'C', 0, 0, 0, 13];
            done.extend_from_slice(b"SELECT 0\0");
            done.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
            s.write_all(&done).await.unwrap();
        }
        let wait = Duration::from_secs(10);
        let (closed, cancel) = tokio::join!(
            async {
                loop {
                    match tokio::time::timeout(wait, s.read(&mut buf)).await {
                        Ok(Ok(0)) | Ok(Err(_)) => break true,
                        Ok(Ok(_)) => continue, // e.g. Terminate
                        Err(_) => break false,
                    }
                }
            },
            async {
                let Ok(Ok((mut c, _))) = tokio::time::timeout(Duration::from_secs(4), l.accept()).await else { return false };
                let mut req = [0u8; 16];
                c.read_exact(&mut req).await.is_ok() && req[4..8] == 80_877_102u32.to_be_bytes() && req[8..12] == 7u32.to_be_bytes()
            }
        );
        StallReport { socket_closed: closed, cancel_requested: cancel }
    });
    (port, task)
}

fn local_query(port: u16, timeout_secs: u64) -> DbQuery {
    serde_json::from_value(serde_json::json!({ "host": "127.0.0.1", "port": port, "user": "app", "sql": "select pg_sleep(3600)", "timeoutSecs": timeout_secs, "via": DbRoute::Direct })).unwrap()
}

/// CC-01: on a shared (persistent) runtime a timed-out query returns, its connection is
/// closed — the driver did not outlive it — and the server is asked to cancel the statement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timed_out_query_closes_its_connection_and_requests_cancel() {
    let (port, server) = stalling_postgres(false).await;
    let started = Instant::now();
    let e = run_query(&local_query(port, 1)).await.unwrap_err().to_string();
    assert!(e.contains("longer than 1 seconds"), "{e}");
    assert!(started.elapsed() < Duration::from_secs(1) + CANCEL_GRACE + Duration::from_secs(1));
    let r = server.await.unwrap();
    assert!(r.socket_closed, "the driver kept the connection open after the timeout");
    assert!(r.cancel_requested, "no server-side cancel was requested");
}

/// Dropping the caller's future (e.g. the UI closing) also closes the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_a_running_query_closes_its_connection() {
    let (port, server) = stalling_postgres(false).await;
    let q = local_query(port, 60);
    let _ = tokio::time::timeout(Duration::from_millis(500), run_query(&q)).await;
    assert!(server.await.unwrap().socket_closed);
}

/// A query that completes still returns its result and closes the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_query_returns_and_closes() {
    let (port, server) = stalling_postgres(true).await;
    let r = run_query(&local_query(port, 5)).await.unwrap();
    assert_eq!(r.statements.len(), 1);
    let report = server.await.unwrap();
    assert!(report.socket_closed);
    assert!(!report.cancel_requested);
}
