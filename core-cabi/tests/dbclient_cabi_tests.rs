//! Database client through the C ABI: request validation, and (with `BASTION_PG_TEST=1`) a real
//! query over a Bastion `-L` tunnel to the throwaway pgdb container (docs/TESTING.md).
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;
use std::sync::Arc;
use std::time::Duration;

use bastion_cabi::dbclient::bastion_db_query_json;
use bastion_cabi::bastion_string_free;
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::tunnel::local_forward;
use bastion_core::vault::Secret;
use serde_json::{json, Value};

unsafe fn take(p: *mut c_char) -> String {
    assert!(!p.is_null(), "expected a string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    s
}

fn call(req: &Value) -> Result<Value, String> {
    let c = CString::new(req.to_string()).unwrap();
    let mut err = null_mut();
    unsafe {
        let out = bastion_db_query_json(c.as_ptr(), &mut err);
        if out.is_null() { Err(take(err)) } else { Ok(serde_json::from_str(&take(out)).unwrap()) }
    }
}

#[test]
fn bad_requests_are_refused_before_connecting() {
    assert!(call(&json!({ "host": "h" })).unwrap_err().contains("not valid"));
    assert!(call(&json!({ "host": "h", "user": "u", "sql": "x", "tls": true })).unwrap_err().contains("unknown field"));
    let e = call(&json!({ "host": "db.example.com", "user": "u", "sql": "select 1" })).unwrap_err();
    assert!(e.contains("choose a tunnel"), "{e}");
    let mut err = null_mut();
    unsafe {
        assert!(bastion_db_query_json(std::ptr::null(), &mut err).is_null());
        assert!(take(err).contains("request_json"));
    }
}

#[ignore = "live: needs BASTION_PG_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn query_over_a_tunnel_returns_rows_as_json() {
    assert!(std::env::var_os("BASTION_PG_TEST").is_some(), "live test run without BASTION_PG_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_PG_TEST").is_err() {
        eprintln!("SKIPPED query_over_a_tunnel: set BASTION_PG_TEST=1 with bastion-jump and pgdb running");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let t = rt.block_on(async {
        let p = SshParams {
            host: "127.0.0.1".into(), port: 2223, username: "tester".into(),
            auth: SshAuth::Password(Secret::new("test-pass-123")), known_hosts: dir.path().join("kh"),
            policy: HostKeyPolicy::AcceptNew, connect_timeout: Duration::from_secs(10), keepalive: None,
            prompter: None, algorithms: Default::default(),
        };
        let s = Arc::new(SshSession::connect(p).await.unwrap());
        local_forward(s, "127.0.0.1:0".parse().unwrap(), "pgdb", 5432).await.unwrap()
    });
    let r = call(&json!({ "host": "pgdb", "user": "bastion", "password": "pg-test-pass", "database": "lab",
                          "sql": "select 7 as n, null as z", "via": { "kind": "forward", "port": t.local_addr.port() } })).unwrap();
    let st = &r["statements"][0];
    assert_eq!(st["columns"], json!(["n", "z"]));
    assert_eq!(st["rows"], json!([["7", null]]));
    assert_eq!((st["truncated"].as_bool(), st["rowCount"].as_u64()), (Some(false), Some(1)));
    assert!(r["elapsedMs"].is_u64() && !r.to_string().contains("pg-test-pass"));
    rt.block_on(t.shutdown());
}
