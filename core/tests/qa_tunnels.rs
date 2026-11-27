//! Journey 9: accepted clients must lose access when the user stops a tunnel.
//! Explicit live reproduction against only the documented localhost jump/target lab.
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::tunnel::dynamic_socks;
use bastion_core::vault::Secret;
use bastion_core::CoreError;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
#[ignore = "live: requires the localhost SSH jump lab (BASTION_SSH_TEST=1); regression test for Q11"]
async fn stopping_socks_revokes_previously_accepted_clients() {
    assert_eq!(
        std::env::var("BASTION_SSH_TEST").expect("enable the documented disposable SSH lab"),
        "1"
    );
    let dir = tempfile::tempdir().unwrap();
    let params = |policy| SshParams {
        host: "127.0.0.1".into(),
        port: 2223,
        username: "tester".into(),
        auth: SshAuth::Password(Secret::new("test-pass-123")),
        known_hosts: dir.path().join("known_hosts"),
        policy,
        connect_timeout: Duration::from_secs(5),
        keepalive: None,
        prompter: None,
        algorithms: Default::default(),
    };
    let fingerprint = match SshSession::connect(params(HostKeyPolicy::Strict)).await {
        Err(CoreError::HostKeyUnknown { fingerprint }) => fingerprint,
        _ => panic!("a fresh lab key must require explicit trust"),
    };
    let session = Arc::new(
        SshSession::connect(params(HostKeyPolicy::TrustFingerprint(fingerprint)))
            .await
            .unwrap(),
    );
    let tunnel = dynamic_socks(session, "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let mut client = TcpStream::connect(tunnel.local_addr).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut method))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        method,
        [5, 0],
        "the server accepted this client before stop"
    );
    tunnel.stop();
    tokio::time::timeout(Duration::from_secs(2), async {
        while tunnel.is_running() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    // The new destination request is sent only after the listener task has stopped.
    let mut request = vec![5, 1, 0, 3, 6];
    request.extend_from_slice(b"target");
    request.extend_from_slice(&2222u16.to_be_bytes());
    if client.write_all(&request).await.is_err() {
        return;
    }
    let mut reply = [0u8; 10];
    match tokio::time::timeout(Duration::from_secs(2), client.read(&mut reply)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!(
            "Q11: stopped tunnel still answers a new destination request: {:?}",
            &reply[..n]
        ),
        Err(_) => panic!("Q11: stopped tunnel did not close its accepted client"),
    }
}
