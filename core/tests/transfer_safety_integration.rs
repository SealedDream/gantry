//! Codex review C04/C05/C06/C10 against the Docker SSH server (`bastion-sshd`,
//! `BASTION_SSH_TEST=1`; docs/TESTING.md). Without it every test prints SKIPPED.
//!
//! A dangling symlink is how these tests make a destination "appear during the transfer": the
//! up-front existence check (`test -e`, `Path::exists`) does not see it, so only an atomic
//! no-replace commit can refuse it.
#![cfg(unix)]
use std::time::Duration;

use bastion_core::scp::{shell_quote, Scp, PART_SUFFIX};
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::vault::Secret;

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

fn enabled(test: &str) -> bool {
    let on = std::env::var("BASTION_SSH_TEST").is_ok();
    if !on {
        eprintln!("SKIPPED {test}: set BASTION_SSH_TEST=1");
    }
    on
}

async fn remote_base(scp: &Scp<'_>) -> String {
    let home = scp.home().await.unwrap();
    let base = format!("{home}/bastion-safety-{}", uuid::Uuid::new_v4().simple());
    scp.mkdir(&base).await.unwrap();
    base
}

/// C05: a planted `<name>.bastion-part` symlink must not redirect an SCP download.
#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn scp_download_does_not_follow_a_planted_part_symlink() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("scp_download_does_not_follow_a_planted_part_symlink") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let session = ssh(&dir).await;
    let scp = Scp::new(&session);
    let base = remote_base(&scp).await;
    let src = dir.path().join("src.txt");
    std::fs::write(&src, b"remote payload").unwrap();
    scp.upload(&src, &format!("{base}/download.txt"), false).await.unwrap();

    let dest = tempfile::tempdir().unwrap();
    let victim = dest.path().join("victim.txt");
    std::fs::write(&victim, b"victim data").unwrap();
    std::os::unix::fs::symlink(&victim, dest.path().join(format!("download.txt{PART_SUFFIX}"))).unwrap();
    let local = dest.path().join("download.txt");
    scp.download(&format!("{base}/download.txt"), &local, false).await.unwrap();

    assert_eq!(std::fs::read(&victim).unwrap(), b"victim data", "the planted symlink's target is untouched");
    assert_eq!(std::fs::read(&local).unwrap(), b"remote payload");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&local).unwrap().permissions().mode() & 0o777, 0o600, "owner-only");
    session.exec(&format!("rm -rf -- {}", shell_quote(&base))).await.unwrap();
}

/// C10 (SCP upload): without overwrite, the remote commit must not replace a destination.
#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn scp_upload_without_overwrite_never_replaces_at_commit() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("scp_upload_without_overwrite_never_replaces_at_commit") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let session = ssh(&dir).await;
    let scp = Scp::new(&session);
    let base = remote_base(&scp).await;
    let remote = format!("{base}/target.txt");
    session.exec(&format!("ln -s -- {} {}", shell_quote(&format!("{base}/nowhere")), shell_quote(&remote))).await.unwrap();
    let src = dir.path().join("src.txt");
    std::fs::write(&src, b"new").unwrap();

    assert!(scp.upload(&src, &remote, false).await.is_err(), "the destination appeared; it must not be replaced");
    let still_link = session.exec(&format!("test -L {}", shell_quote(&remote))).await.unwrap();
    assert_eq!(still_link.exit_status, Some(0), "the existing entry survives");
    let listed = scp.list(&base).await.unwrap();
    assert!(!listed.iter().any(|e| e.name.ends_with(PART_SUFFIX)), "no part file left: {listed:?}");

    scp.upload(&src, &format!("{base}/fresh.txt"), false).await.unwrap();
    scp.upload(&src, &remote, true).await.unwrap();
    session.exec(&format!("rm -rf -- {}", shell_quote(&base))).await.unwrap();
}

/// C10 (downloads): a local destination that appears during the transfer is not replaced.
#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn downloads_without_overwrite_never_replace_at_commit() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("downloads_without_overwrite_never_replace_at_commit") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let session = ssh(&dir).await;
    let scp = Scp::new(&session);
    let sftp = session.open_sftp().await.unwrap();
    let base = remote_base(&scp).await;
    let src = dir.path().join("src.txt");
    std::fs::write(&src, b"payload").unwrap();
    let remote = format!("{base}/file.txt");
    scp.upload(&src, &remote, false).await.unwrap();

    let dest = tempfile::tempdir().unwrap();
    let local = dest.path().join("file.txt");
    std::os::unix::fs::symlink(dest.path().join("nowhere"), &local).unwrap();
    assert!(!local.exists(), "the up-front check cannot see it");
    assert!(sftp.download(&remote, &local, false).await.is_err(), "SFTP must refuse to replace it");
    assert!(scp.download(&remote, &local, false).await.is_err(), "SCP must refuse to replace it");
    assert!(std::fs::symlink_metadata(&local).unwrap().file_type().is_symlink(), "the existing entry survives");
    assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 1, "no temporary file left");

    sftp.download(&remote, &local, true).await.unwrap();
    assert_eq!(std::fs::read(&local).unwrap(), b"payload");
    session.exec(&format!("rm -rf -- {}", shell_quote(&base))).await.unwrap();
}

/// C04: a download target whose name would escape the folder on Windows is refused, and SFTP
/// listings never offer such a name there.
#[tokio::test]
async fn hostile_names_never_become_download_targets() {
    let downloads = std::path::Path::new("/Users/me/Downloads");
    assert!(bastion_core::localfile::download_target(downloads, "../evil").is_err());
    for name in ["..\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.cmd", "C:\\Users\\me\\evil.cmd", "x:stream"] {
        assert!(!bastion_core::localfile::safe_file_name_for(name, true), "{name}");
    }
    if !enabled("hostile_names_never_become_download_targets (listing part)") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let session = ssh(&dir).await;
    let scp = Scp::new(&session);
    let sftp = session.open_sftp().await.unwrap();
    let base = remote_base(&scp).await;
    let hostile = "..\\AppData\\evil.cmd";
    session.exec(&format!("touch -- {}", shell_quote(&format!("{base}/{hostile}")))).await.unwrap();
    let listed = sftp.list(&base).await.unwrap();
    assert_eq!(listed.iter().any(|e| e.name == hostile), !cfg!(windows), "listed on Unix (a legal name), hidden on Windows");
    session.exec(&format!("rm -rf -- {}", shell_quote(&base))).await.unwrap();
}

/// C06: an overwrite upload replaces the file, leaves no recovery or part file behind, and
/// refuses to replace a directory.
#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn sftp_overwrite_upload_replaces_in_place() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("sftp_overwrite_upload_replaces_in_place") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let session = ssh(&dir).await;
    let scp = Scp::new(&session);
    let sftp = session.open_sftp().await.unwrap();
    let base = remote_base(&scp).await;
    let remote = format!("{base}/config.yml");
    let (old, new) = (dir.path().join("old"), dir.path().join("new"));
    std::fs::write(&old, b"original").unwrap();
    std::fs::write(&new, b"replacement").unwrap();
    sftp.upload(&old, &remote, false).await.unwrap();
    assert!(sftp.upload(&new, &remote, false).await.is_err());
    sftp.upload(&new, &remote, true).await.unwrap();
    assert_eq!(sftp.read_capped(&remote, 1024).await.unwrap(), b"replacement");
    let names: Vec<_> = sftp.list(&base).await.unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, ["config.yml"], "no recovery or part file left");

    let folder = format!("{base}/folder");
    sftp.mkdir(&folder).await.unwrap();
    assert!(sftp.upload(&new, &folder, true).await.unwrap_err().to_string().contains("not a file"));
    assert!(sftp.stat_path(&folder).await.unwrap().is_some_and(|s| !s.is_file), "the folder survives");
    session.exec(&format!("rm -rf -- {}", shell_quote(&base))).await.unwrap();
}

/// C05/C06/C10 over FTPS, against the throwaway vsftpd (`BASTION_FTPS_TEST=127.0.0.1:2121`,
/// user ftptest, password in `BASTION_FTPS_PASSWORD`; docs/TESTING.md).
#[ignore = "live: needs BASTION_FTPS_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn ftps_downloads_and_overwrite_uploads_are_safe() {
    assert!(std::env::var_os("BASTION_FTPS_TEST").is_some(), "live test run without BASTION_FTPS_TEST: start the fixture (docs/TESTING.md)");
    use bastion_core::ftps::Ftps;
    let (Ok(addr), Ok(pw)) = (std::env::var("BASTION_FTPS_TEST"), std::env::var("BASTION_FTPS_PASSWORD")) else {
        return eprintln!("SKIPPED ftps_downloads_and_overwrite_uploads_are_safe: set BASTION_FTPS_TEST and BASTION_FTPS_PASSWORD");
    };
    let (host, port) = addr.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let pw = Secret::new(pw);
    let pin = match Ftps::connect(host, port, "ftptest", &pw, None).await {
        Err(bastion_core::CoreError::HostKeyUnknown { fingerprint }) => fingerprint,
        other => panic!("expected an untrusted certificate first, got {:?}", other.map(|_| ())),
    };
    let mut ftp = Ftps::connect(host, port, "ftptest", &pw, Some(&pin)).await.unwrap();
    let home = ftp.home().await.unwrap();
    let base = format!("{}/safety-{}", home.trim_end_matches('/'), uuid::Uuid::new_v4().simple());
    ftp.mkdir(&base).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = (dir.path().join("old"), dir.path().join("new"));
    std::fs::write(&old, b"original").unwrap();
    std::fs::write(&new, b"replacement").unwrap();
    let remote = format!("{base}/config.yml");

    // C06: overwrite replaces, and neither a recovery copy nor a part file is left behind.
    ftp.upload(&old, &remote, false).await.unwrap();
    assert!(ftp.upload(&new, &remote, false).await.is_err());
    ftp.upload(&new, &remote, true).await.unwrap();
    let names: Vec<_> = ftp.list(&base).await.unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, ["config.yml"], "no recovery or part file left");

    // C05: a planted part-file symlink is not followed; the download is owner-only.
    let dest = tempfile::tempdir().unwrap();
    let victim = dest.path().join("victim.txt");
    std::fs::write(&victim, b"victim data").unwrap();
    std::os::unix::fs::symlink(&victim, dest.path().join(format!("config.yml{PART_SUFFIX}"))).unwrap();
    let local = dest.path().join("config.yml");
    ftp.download(&remote, &local, false).await.unwrap();
    assert_eq!(std::fs::read(&local).unwrap(), b"replacement");
    assert_eq!(std::fs::read(&victim).unwrap(), b"victim data");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&local).unwrap().permissions().mode() & 0o777, 0o600);

    // C10: a destination that appears during the transfer (a dangling symlink) is not replaced.
    let raced = dest.path().join("raced.yml");
    std::os::unix::fs::symlink(dest.path().join("nowhere"), &raced).unwrap();
    assert!(ftp.download(&remote, &raced, false).await.is_err());
    assert!(std::fs::symlink_metadata(&raced).unwrap().file_type().is_symlink());

    ftp.remove_file(&remote).await.unwrap();
    let _ = ftp.quit().await;
}
