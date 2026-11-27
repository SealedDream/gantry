//! Real-endpoint jump-host and tunnel tests. Topology (docs/TESTING.md):
//! this machine → 127.0.0.1:2223 (bastion-jump) → target:2222 (bastion-target, not published).
//! Requires `BASTION_SSH_TEST=1`; otherwise every test prints SKIPPED.
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::tunnel::{dynamic_socks, local_forward};
use bastion_core::vault::Secret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn enabled(name: &str) -> bool {
    let on = std::env::var("BASTION_SSH_TEST").is_ok();
    if !on {
        eprintln!("SKIPPED {name}: set BASTION_SSH_TEST=1 with the test servers running");
    }
    on
}

fn hop(host: &str, port: u16, password: &str, kh: &PathBuf) -> SshParams {
    SshParams {
        host: host.into(),
        port,
        username: "tester".into(),
        auth: SshAuth::Password(Secret::new(password)),
        known_hosts: kh.clone(),
        policy: HostKeyPolicy::AcceptNew,
        connect_timeout: Duration::from_secs(10),
        keepalive: None,
        prompter: None,
        algorithms: Default::default(),
    }
}

fn jump(kh: &PathBuf) -> SshParams {
    hop("127.0.0.1", 2223, "test-pass-123", kh)
}

fn target(kh: &PathBuf) -> SshParams {
    hop("target", 2222, "target-pass-456", kh)
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

async fn read_banner(mut s: TcpStream) -> String {
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn proxyjump_reaches_private_host_and_verifies_each_hop() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("proxyjump") { return; }
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    let s = SshSession::connect_via(vec![jump(&kh)], target(&kh)).await.unwrap();
    let out = s.exec("cat /etc/hostname; echo via-jump").await.unwrap();
    assert_eq!(out.exit_status, Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).ends_with("via-jump\n"));
    let recorded = std::fs::read_to_string(&kh).unwrap();
    assert!(recorded.contains("[127.0.0.1]:2223") && recorded.contains("[target]:2222"), "{recorded}");

    // Both hop keys are now known, so strict verification succeeds on every hop.
    let strict = |mut p: SshParams| { p.policy = HostKeyPolicy::Strict; p };
    let s2 = SshSession::connect_via(vec![strict(jump(&kh))], strict(target(&kh))).await.unwrap();
    assert_eq!(s2.exec("true").await.unwrap().exit_status, Some(0));
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn target_is_not_reachable_directly() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("no_direct") { return; }
    let dir = tempfile::tempdir().unwrap();
    let mut p = target(&dir.path().join("kh"));
    p.connect_timeout = Duration::from_secs(3);
    assert!(SshSession::connect(p).await.is_err(), "target must only be reachable through the jump host");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn local_forward_carries_traffic_and_stops_cleanly() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("local_forward") { return; }
    let dir = tempfile::tempdir().unwrap();
    let s = Arc::new(SshSession::connect(jump(&dir.path().join("kh"))).await.unwrap());
    let t = local_forward(s, loopback(), "target", 2222).await.unwrap();
    assert!(read_banner(TcpStream::connect(t.local_addr).await.unwrap()).await.starts_with("SSH-2.0-"));
    assert_eq!(t.stats().connections, 1);
    let addr = t.local_addr;
    t.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!t.is_running());
    assert!(TcpStream::connect(addr).await.is_err(), "listener must be closed after stop");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn port_conflict_is_reported() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("port_conflict") { return; }
    let dir = tempfile::tempdir().unwrap();
    let s = Arc::new(SshSession::connect(jump(&dir.path().join("kh"))).await.unwrap());
    let first = local_forward(s.clone(), loopback(), "target", 2222).await.unwrap();
    let err = local_forward(s, first.local_addr, "target", 2222).await.err().unwrap();
    assert!(err.to_string().contains("already in use"), "{err}");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn socks5_proxy_connects_by_hostname_and_reports_failures() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("socks5") { return; }
    let dir = tempfile::tempdir().unwrap();
    let s = Arc::new(SshSession::connect(jump(&dir.path().join("kh"))).await.unwrap());
    let t = dynamic_socks(s, loopback()).await.unwrap();

    let connect = |host: &'static str, port: u16| async move {
        let mut c = TcpStream::connect(t.local_addr).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut m = [0u8; 2];
        c.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [5, 0]);
        let mut req = vec![5, 1, 0, 3, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        (rep[1], c)
    };
    let (code, stream) = connect("target", 2222).await;
    assert_eq!(code, 0);
    assert!(read_banner(stream).await.starts_with("SSH-2.0-"));
    let (code, _) = connect("no-such-host.invalid", 22).await;
    assert_ne!(code, 0, "unreachable destination must not report success");
    assert!(dynamic_socks(Arc::new(SshSession::connect(jump(&dir.path().join("kh"))).await.unwrap()), "0.0.0.0:0".parse().unwrap())
        .await
        .is_err(), "SOCKS must refuse non-loopback binds");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn remote_forward_exposes_local_service_on_server() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("remote_forward") { return; }
    let echo = TcpListener::bind(loopback()).await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&[b"echo:", &buf[..n]].concat()).await;
                }
            });
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let s = SshSession::connect(jump(&dir.path().join("kh"))).await.unwrap();
    let remote_port = 40_000 + (echo_port % 10_000);
    let bound = s.remote_forward("127.0.0.1", remote_port, "127.0.0.1", echo_port).await.unwrap();
    let cmd = format!("exec 3<>/dev/tcp/127.0.0.1/{bound}; echo ping >&3; head -c 10 <&3");
    let out = s.exec(&format!("bash -c '{cmd}'")).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "echo:ping\n", "stderr: {}", String::from_utf8_lossy(&out.stderr));
    s.cancel_remote_forward("127.0.0.1", bound).await.unwrap();
}

// Security findings F4 / F5: tunnels must not silently expose services to other networks.
#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn f4_f5_tunnels_refuse_non_loopback_binds() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("tunnel_bind_scope") { return; }
    let dir = tempfile::tempdir().unwrap();
    let s = Arc::new(SshSession::connect(jump(&dir.path().join("kh"))).await.unwrap());
    let err = local_forward(s.clone(), "0.0.0.0:0".parse().unwrap(), "target", 2222).await.err().unwrap();
    assert!(err.to_string().contains("loopback"), "{err}");
    let err = s.remote_forward("0.0.0.0", 45000, "127.0.0.1", 1).await.err().unwrap();
    assert!(err.to_string().contains("loopback"), "{err}");
}
