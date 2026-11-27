//! Port-forward manager on a real server: this machine → 127.0.0.1:2223 (bastion-jump), with
//! tunnels to `target:2222` (bastion-target, reachable only from the jump host; docs/TESTING.md).
//! Requires `BASTION_SSH_TEST=1`; otherwise each test prints SKIPPED.
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bastion_core::forwards::ForwardSet;
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::tunneldefs::{TunnelDef, TunnelSpec};
use bastion_core::vault::Secret;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

fn enabled(name: &str) -> bool {
    let on = std::env::var("BASTION_SSH_TEST").is_ok();
    if !on {
        eprintln!("SKIPPED {name}: set BASTION_SSH_TEST=1 with the test servers running");
    }
    on
}

async fn jump(kh: &Path) -> Arc<SshSession> {
    let p = SshParams {
        host: "127.0.0.1".into(),
        port: 2223,
        username: "tester".into(),
        auth: SshAuth::Password(Secret::new("test-pass-123")),
        known_hosts: kh.to_path_buf(),
        policy: HostKeyPolicy::AcceptNew,
        connect_timeout: Duration::from_secs(10),
        keepalive: None,
        prompter: None,
        algorithms: Default::default(),
    };
    Arc::new(SshSession::connect(p).await.unwrap())
}

fn def(name: &str, spec: TunnelSpec) -> TunnelDef {
    TunnelDef { id: Uuid::new_v4(), name: name.into(), via: Uuid::new_v4(), spec, start_with_connection: true }
}

async fn banner(port: u16) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// A free port with the next one free too, held by a listener so the forward has to move.
async fn taken_port() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    (l, p)
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn taken_port_moves_counts_bytes_and_survives_a_reconnect() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("forwards_move_and_restart") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    let (_hold, taken) = taken_port().await;
    let set = ForwardSet::new();
    let d = def("target ssh", TunnelSpec::Local { local_port: taken, dest_host: "target".into(), dest_port: 2222 });
    let st = set.start(&jump(&kh).await, vec![d.clone()]).await.unwrap();
    let port = st[0].port.expect("started");
    assert_ne!(port, taken);
    assert_eq!(st[0].moved_from, Some(taken));
    assert!(banner(port).await.starts_with("SSH-2.0-"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let s = &set.status()[0];
    assert!(s.running && s.connections == 1 && s.bytes_down > 0, "{s:?}");

    // Reconnect: same port on the new session.
    let st = set.restart(&jump(&kh).await).await;
    assert_eq!(st[0].port, Some(port), "{st:?}");
    assert!(banner(port).await.starts_with("SSH-2.0-"));

    // A stopped tunnel stays stopped across a reconnect.
    set.stop(d.id).await.unwrap();
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    let st = set.restart(&jump(&kh).await).await;
    assert!(!st[0].running);
    set.stop_all().await;
    assert!(set.is_empty());
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn one_failing_tunnel_does_not_stop_the_others() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("forwards_partial_failure") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    let session = jump(&kh).await;
    let (_hold, free) = taken_port().await;
    drop(_hold);
    // The jump host's sshd already listens on 2222, so the server refuses this forward.
    let bad = def("taken on server", TunnelSpec::Remote { remote_port: 2222, local_host: "127.0.0.1".into(), local_port: 9 });
    let good = def("socks", TunnelSpec::Dynamic { local_port: free });
    let st = ForwardSet::new().start(&session, vec![bad, good]).await.unwrap();
    assert!(!st[0].running && st[0].last_error.is_some(), "{st:?}");
    assert!(st[1].running && st[1].port.is_some(), "{st:?}");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn a_set_for_one_connection_refuses_another_connections_tunnel() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("forwards_wrong_connection") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let set = ForwardSet::for_connection(Uuid::new_v4());
    let other = def("elsewhere", TunnelSpec::Dynamic { local_port: 1080 });
    assert!(set.start(&jump(&dir.path().join("kh")).await, vec![other]).await.is_err());
    assert!(set.is_empty());
}
