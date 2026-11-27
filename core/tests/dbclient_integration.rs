//! Database client through real Bastion tunnels. Topology (docs/TESTING.md): this machine →
//! 127.0.0.1:2223 (bastion-jump) → pgdb:5432 (throwaway postgres on bastion-net, not published).
//! Requires `BASTION_PG_TEST=1`; otherwise every test prints SKIPPED.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bastion_core::dbclient::{run_query, DbQuery, DbRoute};
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::tunnel::{dynamic_socks, local_forward};
use bastion_core::vault::Secret;
use serde_json::json;

const PG_PASSWORD: &str = "pg-test-pass";

fn enabled(name: &str) -> bool {
    let on = std::env::var("BASTION_PG_TEST").is_ok();
    if !on {
        eprintln!("SKIPPED {name}: set BASTION_PG_TEST=1 with bastion-jump and the pgdb container running");
    }
    on
}

async fn jump(dir: &tempfile::TempDir) -> Arc<SshSession> {
    let p = SshParams {
        host: "127.0.0.1".into(),
        port: 2223,
        username: "tester".into(),
        auth: SshAuth::Password(Secret::new("test-pass-123")),
        known_hosts: dir.path().join("known_hosts"),
        policy: HostKeyPolicy::AcceptNew,
        connect_timeout: Duration::from_secs(10),
        keepalive: None,
        prompter: None,
        algorithms: Default::default(),
    };
    Arc::new(SshSession::connect(p).await.unwrap())
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn q(via: DbRoute, sql: &str, extra: serde_json::Value) -> DbQuery {
    let mut v = json!({ "host": "pgdb", "user": "bastion", "password": PG_PASSWORD, "database": "lab", "sql": sql, "via": via });
    v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    serde_json::from_value(v).unwrap()
}

#[ignore = "live: needs BASTION_PG_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn query_through_a_local_forward() {
    assert!(std::env::var_os("BASTION_PG_TEST").is_some(), "live test run without BASTION_PG_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("local_forward") { return; }
    let dir = tempfile::tempdir().unwrap();
    let t = local_forward(jump(&dir).await, loopback(), "pgdb", 5432).await.unwrap();
    let via = DbRoute::Forward { port: t.local_addr.port() };

    let r = run_query(&q(via.clone(), "select 1 as one, null::text as nothing, 'hé'::text as s; select current_user", json!({}))).await.unwrap();
    assert_eq!(r.statements.len(), 2);
    assert_eq!(r.statements[0].columns, ["one", "nothing", "s"]);
    assert_eq!(r.statements[0].rows, vec![vec![Some("1".into()), None, Some("hé".into())]]);
    assert_eq!(r.statements[1].rows[0][0].as_deref(), Some("bastion"));

    // Row cap: the rest are counted but not returned.
    let r = run_query(&q(via.clone(), "select g from generate_series(1, 50) g", json!({ "maxRows": 10 }))).await.unwrap();
    let st = &r.statements[0];
    assert_eq!((st.rows.len(), st.truncated, st.row_count), (10, true, 50));

    // Read-only by default; writes need readOnly:false.
    let e = run_query(&q(via.clone(), "create table t(x int)", json!({}))).await.unwrap_err().to_string();
    assert!(e.contains("read-only") && e.contains("25006"), "{e}");
    let r = run_query(&q(via.clone(), "create temp table t(x int); insert into t values (1),(2)", json!({ "readOnly": false }))).await.unwrap();
    assert_eq!(r.statements[1].row_count, 2);

    // SQL errors and a wrong password come back readable, without the password.
    let e = run_query(&q(via.clone(), "select * from nope", json!({}))).await.unwrap_err().to_string();
    assert!(e.contains("nope") && e.contains("42P01"), "{e}");
    let e = run_query(&q(via.clone(), "select 1", json!({ "password": "wrong-pass" }))).await.unwrap_err().to_string();
    assert!(e.contains("28P01") && !e.contains("wrong-pass"), "{e}");

    // Time limit stops a long query.
    let e = run_query(&q(via, "select pg_sleep(10)", json!({ "timeoutSecs": 1 }))).await.unwrap_err().to_string();
    assert!(e.contains("longer than 1 seconds"), "{e}");
    t.shutdown().await;
}

#[ignore = "live: needs BASTION_PG_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn query_through_a_socks_tunnel_resolves_on_the_far_side() {
    assert!(std::env::var_os("BASTION_PG_TEST").is_some(), "live test run without BASTION_PG_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("socks") { return; }
    let dir = tempfile::tempdir().unwrap();
    let t = dynamic_socks(jump(&dir).await, loopback()).await.unwrap();
    let r = run_query(&q(DbRoute::Socks { port: t.local_addr.port() }, "select inet_server_port()", json!({}))).await.unwrap();
    assert_eq!(r.statements[0].rows[0][0].as_deref(), Some("5432"));
    t.shutdown().await;
}
