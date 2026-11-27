//! SCP against the Docker SSH server (`bastion-sshd`, `BASTION_SSH_TEST=1`) and FTPS against a
//! throwaway vsftpd that requires TLS (`BASTION_FTPS_TEST=host:port`, user ftptest, password in
//! `BASTION_FTPS_PASSWORD`; docs/TESTING.md). Without them every test prints SKIPPED.
use std::time::Duration;

use bastion_core::ftps::Ftps;
use bastion_core::scp::Scp;
use bastion_core::sftp::EntryKind;
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::vault::Secret;
use bastion_core::CoreError;
use rand::RngCore;

async fn ssh(dir: &tempfile::TempDir) -> SshSession {
    SshSession::connect(SshParams {
        host: "127.0.0.1".into(),
        port: 2222,
        username: "tester".into(),
        auth: SshAuth::Password(Secret::new("test-pass-123")),
        known_hosts: dir.path().join("known_hosts"),
        policy: HostKeyPolicy::AcceptNew,
        connect_timeout: Duration::from_secs(10),
        keepalive: None,
        prompter: None,
        algorithms: Default::default(),
    })
    .await
    .unwrap()
}

fn random(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn scp_round_trip_and_refusals() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_SSH_TEST").is_err() {
        return eprintln!("SKIPPED scp_round_trip_and_refusals: set BASTION_SSH_TEST=1");
    }
    let dir = tempfile::tempdir().unwrap();
    let session = ssh(&dir).await;
    let scp = Scp::new(&session);
    let home = scp.home().await.unwrap();
    let base = format!("{home}/bastion scp '{}'", uuid::Uuid::new_v4().simple());
    scp.mkdir(&base).await.unwrap();

    let data = random(2 * 1024 * 1024 + 77);
    let local = dir.path().join("up.bin");
    std::fs::write(&local, &data).unwrap();
    let remote = format!("{base}/it's here.bin");
    assert_eq!(scp.upload(&local, &remote, false).await.unwrap(), data.len() as u64);
    assert!(scp.upload(&local, &remote, false).await.is_err(), "no silent overwrite");

    let listed = scp.list(&base).await.unwrap();
    let f = listed.iter().find(|e| e.name == "it's here.bin").expect("listed");
    assert_eq!((f.kind.clone(), f.size), (EntryKind::File, data.len() as u64));
    assert!(!listed.iter().any(|e| e.name.ends_with(".bastion-part")), "no part file left");

    let moved = format!("{base}/moved.bin");
    scp.rename(&remote, &moved).await.unwrap();
    let down = dir.path().join("down.bin");
    assert_eq!(scp.download(&moved, &down, false).await.unwrap(), data.len() as u64);
    assert_eq!(std::fs::read(&down).unwrap(), data);
    assert!(scp.download(&moved, &down, false).await.is_err(), "local file not overwritten");
    let missing = scp.download(&format!("{base}/nope"), &dir.path().join("x"), false).await.unwrap_err().to_string();
    assert!(missing.contains("No such file"), "{missing}");

    session.exec(&format!("rm -rf -- {}", bastion_core::scp::shell_quote(&base))).await.unwrap();
}

#[ignore = "live: needs BASTION_FTPS_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn ftps_pins_the_certificate_and_transfers_over_tls() {
    assert!(std::env::var_os("BASTION_FTPS_TEST").is_some(), "live test run without BASTION_FTPS_TEST: start the fixture (docs/TESTING.md)");
    let Ok(addr) = std::env::var("BASTION_FTPS_TEST") else {
        return eprintln!("SKIPPED ftps: set BASTION_FTPS_TEST=127.0.0.1:2121 and BASTION_FTPS_PASSWORD");
    };
    let (host, port) = addr.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let pw = Secret::new(std::env::var("BASTION_FTPS_PASSWORD").unwrap());
    let fp = match Ftps::connect(host, port, "ftptest", &pw, None).await {
        Err(CoreError::HostKeyUnknown { fingerprint }) => fingerprint,
        Err(e) => panic!("expected an unknown certificate first, got {e}"),
        Ok(_) => panic!("an unpinned certificate was accepted"),
    };
    assert_eq!(fp.len(), 64);
    let wrong = "00".repeat(32);
    assert!(matches!(Ftps::connect(host, port, "ftptest", &pw, Some(&wrong)).await, Err(CoreError::HostKeyUnknown { .. })), "a different pin is refused");
    match Ftps::connect(host, port, "ftptest", &Secret::new("wrong"), Some(&fp)).await {
        Err(CoreError::AuthFailed) => {}
        Err(e) => panic!("expected AuthFailed, got {e:?}"),
        Ok(_) => panic!("wrong password accepted"),
    }

    let mut ftp = Ftps::connect(host, port, "ftptest", &pw, Some(&fp)).await.unwrap();
    let home = ftp.home().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let base = format!("{}/bastion-ftps-{}", home.trim_end_matches('/'), uuid::Uuid::new_v4().simple());
    ftp.mkdir(&base).await.unwrap();
    let data = random(1024 * 1024 + 5);
    let local = dir.path().join("up.bin");
    std::fs::write(&local, &data).unwrap();
    let remote = format!("{base}/up.bin");
    assert_eq!(ftp.upload(&local, &remote, false).await.unwrap(), data.len() as u64);
    assert!(ftp.upload(&local, &remote, false).await.is_err(), "no silent overwrite");
    let listed = ftp.list(&base).await.unwrap();
    assert_eq!(listed.iter().map(|e| (e.name.as_str(), e.size)).collect::<Vec<_>>(), [("up.bin", data.len() as u64)]);
    ftp.rename(&remote, &format!("{base}/moved.bin")).await.unwrap();
    let down = dir.path().join("down.bin");
    assert_eq!(ftp.download(&format!("{base}/moved.bin"), &down, false).await.unwrap(), data.len() as u64);
    assert_eq!(std::fs::read(&down).unwrap(), data);
    ftp.remove_file(&format!("{base}/moved.bin")).await.unwrap();
    ftp.quit().await.unwrap();
}
