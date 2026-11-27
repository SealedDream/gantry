//! Test Connection against the real test servers (docs/TESTING.md): bastion-sshd on
//! 127.0.0.1:2222, bastion-jump on :2223 → target:2222, xrdp on :33890, VNC on :59000.
//! Offline cases (no host, DNS failure, refused port, cancel) always run.
use std::path::PathBuf;
use std::time::Duration;

use bastion_core::model::Protocol;
use bastion_core::probe::{run, ProbeHop, ProbeReport, ProbeRequest, ProbeStep, StepKind, StepStatus};
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::vault::Secret;

fn live() -> bool {
    let on = std::env::var("BASTION_SSH_TEST").is_ok();
    if !on {
        eprintln!("SKIPPED: set BASTION_SSH_TEST=1 with the test servers running");
    }
    on
}

fn req(protocol: Protocol, host: &str, port: u16, password: Option<&str>, kh: PathBuf) -> ProbeRequest {
    ProbeRequest {
        protocol,
        host: host.into(),
        port,
        username: "tester".into(),
        auth: password.map(|p| SshAuth::Password(Secret::new(p))),
        jumps: Vec::new(),
        known_hosts: kh,
        timeout: Duration::from_secs(3),
        trusted_fingerprint: None,
    }
}

fn step(r: &ProbeReport, kind: StepKind) -> &ProbeStep {
    r.steps.iter().find(|s| s.kind == kind && s.status != StepStatus::Skipped).unwrap_or_else(|| panic!("no {kind:?} step in {r:#?}"))
}

fn kh(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("known_hosts")
}

/// Trust `fingerprint` for host:port the way the app does after the user verified it.
async fn trust(kh: PathBuf, port: u16, fingerprint: &str) {
    let p = SshParams {
        host: "127.0.0.1".into(),
        port,
        username: "tester".into(),
        auth: SshAuth::Password(Secret::new("test-pass-123")),
        known_hosts: kh,
        policy: HostKeyPolicy::TrustFingerprint(fingerprint.into()),
        connect_timeout: Duration::from_secs(5),
        keepalive: None,
        prompter: None,
        algorithms: Default::default(),
    };
    SshSession::connect(p).await.unwrap().disconnect().await.unwrap();
}

fn jump(password: &str) -> Vec<ProbeHop> {
    vec![ProbeHop { host: "127.0.0.1".into(), port: 2223, username: "tester".into(), auth: SshAuth::Password(Secret::new(password)) }]
}

#[tokio::test]
async fn empty_host_and_unknown_name_fail_at_dns_with_a_fix() {
    let dir = tempfile::tempdir().unwrap();
    let r = run(req(Protocol::Ssh, " ", 22, None, kh(&dir))).await;
    assert!(!r.ok && step(&r, StepKind::Dns).detail.contains("No host name"));
    let r = run(req(Protocol::Ssh, "no-such-host.invalid", 22, None, kh(&dir))).await;
    let s = step(&r, StepKind::Dns);
    assert_eq!((s.status, s.detail.as_str()), (StepStatus::Failed, "Host 'no-such-host.invalid' not found"));
    assert!(s.fix.is_some());
    assert_eq!(r.steps.len(), 1, "stops at the failing step");
}

#[tokio::test]
async fn closed_port_is_reported_as_refused() {
    let dir = tempfile::tempdir().unwrap();
    // Bind and drop to find a port nothing listens on.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let r = run(req(Protocol::Ssh, "127.0.0.1", port, None, kh(&dir))).await;
    assert_eq!(step(&r, StepKind::Tcp).detail, format!("Port {port} refused on 127.0.0.1 (nothing listening)"));
}

#[tokio::test]
async fn dropping_the_future_cancels_promptly() {
    let dir = tempfile::tempdir().unwrap();
    // 10.255.255.1 is unroutable: the connect would hang for the whole timeout.
    let mut r = req(Protocol::Ssh, "10.255.255.1", 22, None, kh(&dir));
    r.timeout = Duration::from_secs(30);
    let task = tokio::spawn(run(r));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let t = std::time::Instant::now();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(t.elapsed() < Duration::from_millis(500));
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn new_host_key_waits_for_the_user_then_logs_in_and_writes_nothing() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !live() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // SEC-07: a password is not sent to a key nobody confirmed; the report asks first.
    let r = run(req(Protocol::Ssh, "127.0.0.1", 2222, Some("test-pass-123"), kh(&dir))).await;
    let fp = r.needs_host_key_confirmation.clone().expect("the test must stop for the host key");
    assert!(r.steps.iter().any(|s| s.kind == StepKind::Login && s.status == StepStatus::Skipped && s.detail == "Not tested: confirm the host key first"), "{r:#?}");
    let mut confirmed = req(Protocol::Ssh, "127.0.0.1", 2222, Some("test-pass-123"), kh(&dir));
    confirmed.trusted_fingerprint = Some(fp);
    let r = run(confirmed).await;
    assert!(r.ok, "{r:#?}");
    assert!(step(&r, StepKind::Tcp).detail.contains("ms (best of 3)"));
    assert!(step(&r, StepKind::Handshake).detail.starts_with("SSH-2.0-"));
    let key = step(&r, StepKind::HostKey);
    assert_eq!(key.status, StepStatus::Warn);
    assert!(key.detail.starts_with("NEW host key SHA256:"));
    assert_eq!(step(&r, StepKind::Login).detail, "Logged in as 'tester'");
    assert!(!kh(&dir).exists(), "a test must never trust a key");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn bad_password_names_the_user_and_the_secret_never_appears() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !live() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let r = run(req(Protocol::Ssh, "127.0.0.1", 2222, Some("wrong-secret-xyz"), kh(&dir))).await;
    assert!(!r.ok);
    assert_eq!(step(&r, StepKind::Login).detail, "Password or key rejected for user 'tester'");
    assert!(!serde_json::to_string(&r).unwrap().contains("wrong-secret-xyz"));
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn known_key_is_ok_and_a_changed_key_stops_before_login() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !live() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let r = run(req(Protocol::Ssh, "127.0.0.1", 2222, None, kh(&dir))).await;
    let fp = step(&r, StepKind::HostKey).detail.trim_start_matches("NEW host key ").to_string();
    trust(kh(&dir), 2222, &fp).await;
    let r = run(req(Protocol::Ssh, "127.0.0.1", 2222, Some("test-pass-123"), kh(&dir))).await;
    assert!(r.ok, "{r:#?}");
    assert_eq!(step(&r, StepKind::HostKey).status, StepStatus::Ok);

    // Replace the recorded key with a different one of the same type: the key "changed".
    let text = std::fs::read_to_string(kh(&dir)).unwrap();
    let forged: Vec<String> = text
        .lines()
        .map(|l| {
            let parts: Vec<&str> = l.split(' ').collect();
            format!("{} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", parts[0])
        })
        .collect();
    std::fs::write(kh(&dir), forged.join("\n") + "\n").unwrap();
    let r = run(req(Protocol::Ssh, "127.0.0.1", 2222, Some("test-pass-123"), kh(&dir))).await;
    assert!(!r.ok);
    assert!(step(&r, StepKind::HostKey).detail.starts_with("Host key CHANGED"), "{r:#?}");
    assert!(r.steps.iter().all(|s| s.kind != StepKind::Login || s.status == StepStatus::Skipped));
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn wrong_port_with_another_service_fails_the_handshake() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !live() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // The xrdp port speaks RDP and stays silent until spoken to.
    let r = run(req(Protocol::Ssh, "127.0.0.1", 33890, Some("x"), kh(&dir))).await;
    let s = step(&r, StepKind::Handshake);
    assert_eq!(s.status, StepStatus::Failed);
    assert!(s.detail.contains("SSH"), "{s:?}");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn jump_host_then_target_each_with_its_own_login() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !live() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut r = req(Protocol::Ssh, "target", 2222, Some("target-pass-456"), kh(&dir));
    r.jumps = jump("test-pass-123");
    // The jump host's key is not known yet: the test names the hop to trust.
    let rep = run(r).await;
    let j = step(&rep, StepKind::JumpHost);
    assert!(j.detail.starts_with("Jump host 127.0.0.1:2223: NEW host key"), "{rep:#?}");
    trust(kh(&dir), 2223, j.detail.rsplit(' ').next().unwrap()).await;

    // The target's key is new as well: the password waits for the user's yes (SEC-07).
    let mut r = req(Protocol::Ssh, "target", 2222, Some("target-pass-456"), kh(&dir));
    r.jumps = jump("test-pass-123");
    let rep = run(r).await;
    let target_fp = rep.needs_host_key_confirmation.clone().expect("the test must stop for the target's key");
    let mut r = req(Protocol::Ssh, "target", 2222, Some("target-pass-456"), kh(&dir));
    r.jumps = jump("test-pass-123");
    r.trusted_fingerprint = Some(target_fp);
    let rep = run(r).await;
    assert!(rep.ok, "{rep:#?}");
    assert_eq!(step(&rep, StepKind::JumpHost).status, StepStatus::Ok);
    assert_eq!(step(&rep, StepKind::Login).detail, "Logged in as 'tester'");

    // A wrong jump password is reported on the jump host, not the target.
    let mut r = req(Protocol::Ssh, "target", 2222, Some("target-pass-456"), kh(&dir));
    r.jumps = jump("nope");
    let rep = run(r).await;
    assert_eq!(step(&rep, StepKind::JumpHost).detail, "Jump host 127.0.0.1:2223: Password or key rejected for user 'tester'");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn rdp_and_vnc_handshakes() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !live() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let r = run(req(Protocol::Rdp, "127.0.0.1", 33890, None, kh(&dir))).await;
    assert!(r.ok, "{r:#?}");
    assert!(step(&r, StepKind::Handshake).detail.starts_with("RDP server, selected"));
    let r = run(req(Protocol::Vnc, "127.0.0.1", 59000, None, kh(&dir))).await;
    assert!(r.ok, "{r:#?}");
    assert!(step(&r, StepKind::Handshake).detail.starts_with("RFB "));
}
