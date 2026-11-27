//! Connect orchestrator against the real test server (docs/TESTING.md, container
//! `bastion-sshd` on 127.0.0.1:2222). Policy/denial tests run without the server.
use std::sync::Arc;

use bastion_core::audit::{self, AuditLog};
use bastion_core::broker::{Broker, LeaseLimits, SystemClock};
use bastion_core::connect::{CredentialRef, Orchestrator, SecretUse};
use bastion_core::model::{Connection, Protocol};
use bastion_core::policy::Policy;
use bastion_core::provider::LocalVaultProvider;
use bastion_core::vault::{Credential, CredentialKind, Secret, Vault};
use bastion_core::CoreError;
use uuid::Uuid;

fn setup(dir: &tempfile::TempDir, password: &str) -> (Orchestrator, CredentialRef) {
    let mut v = Vault::default();
    let id = v.add(Credential {
        id: Uuid::new_v4(),
        name: "tester".into(),
        folder: None,
        scope: Some("acme".into()),
        owner: None,
        kind: CredentialKind::Password { username: "tester".into(), password: Secret::new(password) },
    });
    let broker = Arc::new(Broker::new(LeaseLimits::default(), Policy::default(), Arc::new(SystemClock)));
    let o = Orchestrator::new(
        Policy::default(),
        broker,
        vec![Arc::new(LocalVaultProvider::new(Some(v)))],
        AuditLog::open(dir.path().join("audit.jsonl")).unwrap(),
        dir.path().join("known_hosts"),
    );
    let cred = CredentialRef { provider: "vault".into(), item: id.to_string(), scope: Some("acme".into()), username: "tester".into(), usage: SecretUse::Password };
    (o, cred)
}

fn conn(customer: &str, protocol: Protocol) -> Connection {
    let mut c = Connection::new("acme-test", protocol, "127.0.0.1");
    c.settings.port = Some(2222);
    c.classification.customer = Some(customer.into());
    c
}

fn audit_text(dir: &tempfile::TempDir) -> String {
    audit::verify(&dir.path().join("audit.jsonl")).unwrap();
    std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap()
}

#[tokio::test]
async fn cross_customer_and_legacy_protocols_are_denied_and_audited() {
    let dir = tempfile::tempdir().unwrap();
    let (o, cred) = setup(&dir, "unused");
    assert!(matches!(o.connect_ssh(&conn("globex", Protocol::Ssh), &cred).await, Err(CoreError::PolicyDenied(_))));
    assert!(matches!(o.connect_ssh(&conn("acme", Protocol::Telnet), &cred).await, Err(CoreError::PolicyDenied(_))));
    let log = audit_text(&dir);
    assert_eq!(log.matches("\"denied\"").count(), 2);
    assert!(o.broker().status().unwrap().is_empty(), "no secret was unlocked for a denied connection");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn unknown_host_requires_explicit_fingerprint_trust() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_SSH_TEST").is_err() {
        return eprintln!("SKIPPED: set BASTION_SSH_TEST=1 with the test server running");
    }
    let dir = tempfile::tempdir().unwrap();
    let (o, cred) = setup(&dir, "test-pass-123");
    let c = conn("acme", Protocol::Ssh);

    // Valid credentials, unknown host: refused, nothing written to known_hosts.
    let Err(CoreError::HostKeyUnknown { fingerprint }) = o.connect_ssh(&c, &cred).await else { panic!("expected HostKeyUnknown") };
    assert!(fingerprint.starts_with("SHA256:"));
    assert!(!dir.path().join("known_hosts").exists(), "successful auth must not trust the host");

    // A different fingerprint than the one presented is not accepted.
    let wrong = o.connect_ssh_trusting(&c, &cred, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").await;
    assert!(matches!(wrong, Err(CoreError::HostKeyUnknown { .. })));
    assert!(!dir.path().join("known_hosts").exists());

    // Explicit trust of the exact fingerprint records it; later connects are strict and work.
    let s = o.connect_ssh_trusting(&c, &cred, &fingerprint).await.unwrap();
    s.disconnect().await.unwrap();
    let s = o.connect_ssh(&c, &cred).await.unwrap();

    // Locking credentials does not tear down the live session.
    assert_eq!(o.broker().status().unwrap().len(), 1);
    o.broker().lock_all().unwrap();
    let out = s.exec("echo still-alive").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "still-alive");
    s.disconnect().await.unwrap();

    let log = audit_text(&dir);
    assert!(!log.contains("test-pass-123"));
    assert!(log.contains("hostkey.trust") && log.contains("credential.unlock") && log.contains("security_warning"));
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn auth_failure_drops_the_cached_secret() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_SSH_TEST").is_err() {
        return eprintln!("SKIPPED: set BASTION_SSH_TEST=1 with the test server running");
    }
    let dir = tempfile::tempdir().unwrap();
    let (o, cred) = setup(&dir, "wrong-password");
    let c = conn("acme", Protocol::Ssh);
    let Err(CoreError::HostKeyUnknown { fingerprint }) = o.connect_ssh(&c, &cred).await else { panic!() };
    assert!(matches!(o.connect_ssh_trusting(&c, &cred, &fingerprint).await, Err(CoreError::AuthFailed)));
    assert!(o.broker().status().unwrap().is_empty());
}

/// ProxyJump through the orchestrator: bastion-jump (127.0.0.1:2223) → target:2222, which is
/// only reachable through the jump host. Each hop has its own credential and its own trust.
#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn jump_chain_with_per_hop_credentials_and_trust() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_SSH_TEST").is_err() {
        return eprintln!("SKIPPED: set BASTION_SSH_TEST=1 with the jump/target containers running");
    }
    use bastion_core::connect::JumpHop;
    let dir = tempfile::tempdir().unwrap();
    let mut v = Vault::default();
    let mut add = |name: &str, pw: &str| {
        v.add(Credential {
            id: Uuid::new_v4(),
            name: name.into(),
            folder: None,
            scope: Some("acme".into()),
            owner: None,
            kind: CredentialKind::Password { username: "tester".into(), password: Secret::new(pw) },
        })
    };
    let (jump_id, target_id) = (add("jump", "test-pass-123"), add("target", "target-pass-456"));
    let broker = Arc::new(Broker::new(LeaseLimits::default(), Policy::default(), Arc::new(SystemClock)));
    let o = Orchestrator::new(
        Policy::default(),
        broker,
        vec![Arc::new(LocalVaultProvider::new(Some(v)))],
        AuditLog::open(dir.path().join("audit.jsonl")).unwrap(),
        dir.path().join("known_hosts"),
    );
    let cred = |id: Uuid| CredentialRef { provider: "vault".into(), item: id.to_string(), scope: Some("acme".into()), username: "tester".into(), usage: SecretUse::Password };
    let mut jump_conn = Connection::new("acme-jump", Protocol::Ssh, "127.0.0.1");
    jump_conn.settings.port = Some(2223);
    jump_conn.classification.customer = Some("acme".into());
    let mut target = Connection::new("acme-target", Protocol::Ssh, "target");
    target.settings.port = Some(2222);
    target.classification.customer = Some("acme".into());
    let mut hop = JumpHop { conn: jump_conn, cred: cred(jump_id), trust: None };

    // The jump host's key is checked first, and the error says which hop it is.
    let jump_fp = match o.connect_ssh_via(&[hop.clone()], &target, &cred(target_id), None).await {
        Err(CoreError::JumpHostKeyUnknown { hop, fingerprint }) => {
            assert_eq!(hop, "127.0.0.1:2223");
            fingerprint
        }
        other => panic!("expected JumpHostKeyUnknown, got {:?}", other.err()),
    };
    hop.trust = Some(jump_fp);
    // Then the target's own key, independently.
    let Err(CoreError::HostKeyUnknown { fingerprint }) = o.connect_ssh_via(&[hop.clone()], &target, &cred(target_id), None).await else {
        panic!("target key must still need explicit trust")
    };
    let s = o.connect_ssh_via(&[hop.clone()], &target, &cred(target_id), Some(&fingerprint)).await.unwrap();
    let out = s.exec("cat /etc/hostname; echo via-jump").await.unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("via-jump"));
    s.disconnect().await.unwrap();

    // Both keys are now known: a strict connect needs no trust at all.
    hop.trust = None;
    let s = o.connect_ssh_via(&[hop], &target, &cred(target_id), None).await.unwrap();
    s.disconnect().await.unwrap();
    let log = audit_text(&dir);
    assert!(log.contains("127.0.0.1:2223") && log.contains("\"via\""));
    assert!(!log.contains("test-pass-123") && !log.contains("target-pass-456"));
}

#[tokio::test]
async fn jump_hop_policy_is_enforced() {
    use bastion_core::connect::JumpHop;
    let dir = tempfile::tempdir().unwrap();
    let (o, cred) = setup(&dir, "unused");
    // A jump host belonging to another customer cannot use this customer's credential.
    let hop = JumpHop { conn: conn("globex", Protocol::Ssh), cred: cred.clone(), trust: None };
    assert!(matches!(o.connect_ssh_via(&[hop], &conn("acme", Protocol::Ssh), &cred, None).await, Err(CoreError::PolicyDenied(_))));
    assert!(o.broker().status().unwrap().is_empty(), "nothing unlocked for a denied chain");
}
