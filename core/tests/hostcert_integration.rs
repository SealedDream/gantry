//! Live: a throwaway OpenSSH server whose host key is signed by the test CA
//! (tests/fixtures/hostcert/ca.pub; docs/TESTING.md), on `BASTION_HOSTCERT_TEST=<port>`, user
//! tester, password in `BASTION_HOSTCERT_PASSWORD`. Strict host-key checking with only a
//! @cert-authority line connects; without it, or with the wrong CA, the server is unknown.
use std::time::Duration;

use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::vault::Secret;
use bastion_core::CoreError;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/fixtures/hostcert/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

async fn connect(port: u16, known_hosts: &str) -> Result<SshSession, CoreError> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    std::fs::write(&path, known_hosts).unwrap();
    let r = SshSession::connect(SshParams {
        host: "127.0.0.1".into(),
        port,
        username: "tester".into(),
        auth: SshAuth::Password(Secret::new(std::env::var("BASTION_HOSTCERT_PASSWORD").unwrap())),
        known_hosts: path.clone(),
        policy: HostKeyPolicy::Strict,
        connect_timeout: Duration::from_secs(10),
        keepalive: None,
        prompter: None,
        algorithms: Default::default(),
    })
    .await;
    // Trusting a CA never writes the server's key into known_hosts.
    assert_eq!(std::fs::read_to_string(&path).unwrap(), known_hosts);
    r
}

#[ignore = "live: needs BASTION_HOSTCERT_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn a_trusted_ca_replaces_trust_on_first_use() {
    assert!(std::env::var_os("BASTION_HOSTCERT_TEST").is_some(), "live test run without BASTION_HOSTCERT_TEST: start the fixture (docs/TESTING.md)");
    let Some(port) = std::env::var("BASTION_HOSTCERT_TEST").ok().and_then(|p| p.parse::<u16>().ok()) else {
        return eprintln!("SKIPPED hostcert_integration: set BASTION_HOSTCERT_TEST=<port>");
    };
    let trusted = format!("@cert-authority [127.0.0.1]:{port} {}", fixture("ca.pub"));
    let s = connect(port, &trusted).await.expect("connects through the CA");
    let out = s.exec("echo cert-ok").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "cert-ok");

    match connect(port, "").await {
        Err(CoreError::HostKeyUnknown { .. }) => {}
        other => panic!("without a CA the plain key is unknown, got {:?}", other.err()),
    }
    let wrong = format!("@cert-authority [127.0.0.1]:{port} {}", fixture("otherca.pub"));
    let err = connect(port, &wrong).await.err().expect("a different CA is refused").to_string();
    assert!(err.contains("not signed by a trusted CA"), "{err}");
    let revoked = format!("{trusted}\n@revoked * {}", fixture("ca.pub"));
    let err = connect(port, &revoked).await.err().expect("a revoked CA is refused").to_string();
    assert!(err.contains("@revoked"), "{err}");
}
