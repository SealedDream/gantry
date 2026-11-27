//! SFTP against the Docker server (docs/TESTING.md, `bastion-sshd` on 127.0.0.1:2222).
//! Without `BASTION_SSH_TEST` every test prints SKIPPED and returns.
use std::time::Duration;

use bastion_core::sftp::EntryKind;
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::vault::Secret;
use rand::RngCore;

fn enabled(name: &str) -> bool {
    let on = std::env::var("BASTION_SSH_TEST").is_ok();
    if !on {
        eprintln!("SKIPPED {name}: set BASTION_SSH_TEST=1 with the test server running");
    }
    on
}

async fn connect(dir: &tempfile::TempDir) -> SshSession {
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

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn upload_list_rename_download_round_trip() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("sftp_round_trip") { return; }
    let dir = tempfile::tempdir().unwrap();
    let ssh = connect(&dir).await;
    let sftp = ssh.open_sftp().await.unwrap();
    let home = sftp.canonicalize(".").await.unwrap();
    let base = format!("{home}/bastion-sftp-{}", uuid::Uuid::new_v4().simple());
    sftp.mkdir(&base).await.unwrap();

    // 3 MiB + change exercises many chunks and a partial last one.
    let mut data = vec![0u8; 3 * 1024 * 1024 + 123];
    rand::thread_rng().fill_bytes(&mut data);
    let local = dir.path().join("payload.bin");
    std::fs::write(&local, &data).unwrap();

    let remote = format!("{base}/payload.bin");
    assert_eq!(sftp.upload(&local, &remote, false).await.unwrap(), data.len() as u64);
    assert!(sftp.upload(&local, &remote, false).await.is_err(), "existing file must not be overwritten silently");

    let listing = sftp.list(&base).await.unwrap();
    assert_eq!(listing.len(), 1, "no temp files left behind: {listing:?}");
    assert_eq!(listing[0].name, "payload.bin");
    assert_eq!(listing[0].kind, EntryKind::File);
    assert_eq!(listing[0].size, data.len() as u64);

    let renamed = format!("{base}/renamed.bin");
    sftp.rename(&remote, &renamed).await.unwrap();
    assert!(!sftp.exists(&remote).await.unwrap());

    let back = dir.path().join("back.bin");
    assert_eq!(sftp.download(&renamed, &back, false).await.unwrap(), data.len() as u64);
    assert_eq!(std::fs::read(&back).unwrap(), data);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&back).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert!(sftp.download(&renamed, &back, false).await.is_err(), "local file must not be overwritten silently");

    // Overwrite when asked, and rename refuses to clobber.
    std::fs::write(&local, b"small").unwrap();
    sftp.upload(&local, &renamed, true).await.unwrap();
    sftp.download(&renamed, &back, true).await.unwrap();
    assert_eq!(std::fs::read(&back).unwrap(), b"small");
    sftp.upload(&local, &remote, false).await.unwrap();
    assert!(sftp.rename(&remote, &renamed).await.is_err());

    let sub = format!("{base}/sub");
    sftp.mkdir(&sub).await.unwrap();
    let listing = sftp.list(&base).await.unwrap();
    assert_eq!(listing[0].kind, EntryKind::Dir, "directories sort first: {listing:?}");

    sftp.remove_dir(&sub).await.unwrap();
    sftp.remove_file(&remote).await.unwrap();
    sftp.remove_file(&renamed).await.unwrap();
    sftp.remove_dir(&base).await.unwrap();
    assert!(!sftp.exists(&base).await.unwrap());
    sftp.close().await.unwrap();
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn missing_paths_are_errors_not_empty_results() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("sftp_missing") { return; }
    let dir = tempfile::tempdir().unwrap();
    let ssh = connect(&dir).await;
    let sftp = ssh.open_sftp().await.unwrap();
    assert!(sftp.list("/definitely/not/here").await.is_err());
    assert!(sftp.download("/definitely/not/here", &dir.path().join("x"), false).await.is_err());
    assert!(!dir.path().join("x").exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "only known_hosts; no partial download left");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn remote_editor_saves_and_detects_conflicts() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    use bastion_core::remoteedit::{open, save, SaveOutcome};
    if !enabled("remote_editor") { return; }
    let dir = tempfile::tempdir().unwrap();
    let ssh = connect(&dir).await;
    let sftp = ssh.open_sftp().await.unwrap();
    let home = sftp.canonicalize(".").await.unwrap();
    let base = format!("{home}/bastion-edit-{}", uuid::Uuid::new_v4().simple());
    sftp.mkdir(&base).await.unwrap();
    let path = format!("{base}/app.conf");

    // Save As a new file, then reopen it.
    assert!(matches!(save(&sftp, &path, None, b"a=1\n", false).await.unwrap(), SaveOutcome::Saved(_)));
    assert!(matches!(save(&sftp, &path, None, b"x\n", false).await.unwrap(), SaveOutcome::Conflict(Some(_))), "Save As never overwrites");
    let opened = open(&sftp, &path).await.unwrap();
    assert_eq!(opened.bytes, b"a=1\n");

    // Normal save keeps permissions and leaves no side files.
    let before = sftp.stat_path(&path).await.unwrap().unwrap().permissions;
    let SaveOutcome::Saved(fp) = save(&sftp, &path, Some(&opened.fingerprint), b"a=2\n", false).await.unwrap() else { panic!("expected save") };
    assert_eq!(sftp.stat_path(&path).await.unwrap().unwrap().permissions, before);
    assert_eq!(sftp.list(&base).await.unwrap().len(), 1, "no temp or backup files left");

    // Someone else edits (same size): our stale save is refused, force wins.
    let other = dir.path().join("other");
    std::fs::write(&other, b"a=9\n").unwrap();
    sftp.upload(&other, &path, true).await.unwrap();
    assert!(matches!(save(&sftp, &path, Some(&fp), b"a=3\n", false).await.unwrap(), SaveOutcome::Conflict(Some(_))));
    assert_eq!(open(&sftp, &path).await.unwrap().bytes, b"a=9\n");
    assert!(matches!(save(&sftp, &path, Some(&fp), b"a=3\n", true).await.unwrap(), SaveOutcome::Saved(_)));
    assert_eq!(open(&sftp, &path).await.unwrap().bytes, b"a=3\n");

    assert!(open(&sftp, &base).await.is_err(), "folders are refused");
    sftp.remove_file(&path).await.unwrap();
    sftp.remove_dir(&base).await.unwrap();
}
