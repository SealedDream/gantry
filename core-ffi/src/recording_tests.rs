//! LOG-CORE-01-WIRING: sessions opened through the bridge reach the activity store, and file
//! sessions write their connect and disconnect audit events. The offline tests dial a port
//! nobody listens on; the live ones use bastion-sshd (`BASTION_SSH_TEST=1`, docs/TESTING.md).
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bastion_core::activity::{ActivityLog, App, EndReason, Filter, LoginSource, Page, SessionStart, SessionSummary};
use bastion_core::logins::LoginSource as Candidate;
use bastion_core::settings::SettingsStore;
use serde_json::Value;
use uuid::Uuid;

use crate::activity::{activity_close_orphans, activity_query_json};
use crate::reconnect_tests::{pw, setup, trust, wait_text};
use crate::{recording, Library, SessionManager, SshLogin};

/// A password that must never be found in anything the app writes.
const TYPED: &str = "wiring-typed-secret-91";
/// A port nobody listens on.
const CLOSED_PORT: u16 = 1;
const PAGE: Page = Page { offset: 0, limit: 50 };

fn sessions(data_dir: &str) -> Vec<Value> {
    serde_json::from_str(&activity_query_json(data_dir.into(), "{}".into(), 0, 50).unwrap()).unwrap()
}

fn audit(data_dir: &str, action: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(Path::new(data_dir).join("audit.jsonl")).unwrap_or_default();
    text.lines().map(|l| serde_json::from_str::<Value>(l).unwrap()).filter(|e| e["action"] == action).collect()
}

/// Everything under the data directory, as text.
fn everything_written(dir: &Path) -> String {
    let mut out = String::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out += &everything_written(&path);
        } else {
            match std::fs::read(&path) {
                Ok(bytes) => out += &String::from_utf8_lossy(&bytes),
                // Windows: a file the app holds a byte-range lock on cannot be read while it is open
                // (ERROR_LOCK_VIOLATION). Those are the activity run and gate locks, which the app
                // never writes to, so the scan still covers them: a locked file must be empty.
                #[cfg(windows)]
                Err(e) if e.raw_os_error() == Some(33) => {
                    let len = std::fs::metadata(&path).unwrap().len();
                    assert_eq!(len, 0, "{}: a locked file holds {len} bytes the scan cannot read", path.display());
                }
                Err(e) => panic!("{}: {e}", path.display()),
            }
        }
    }
    out
}

/// CORE-SEC-LOWS: the scan above runs over files the app holds locked while a session is live.
/// On Windows such a file cannot be read; the scan must still refuse one that holds data.
#[cfg(windows)]
#[test]
fn the_secret_scan_covers_a_locked_live_file_on_windows() {
    let dir = tempfile::tempdir().unwrap();
    let empty = std::fs::OpenOptions::new().create(true).truncate(true).write(true).open(dir.path().join("run.lock")).unwrap();
    empty.lock().unwrap();
    // A locked empty file, as the activity run lock is, passes, and is really unreadable.
    assert_eq!(std::fs::read(dir.path().join("run.lock")).map(|_| ()).unwrap_err().raw_os_error(), Some(33));
    assert!(!everything_written(dir.path()).contains(TYPED));

    // A locked file that holds bytes the scan cannot read fails the scan.
    let full_path = dir.path().join("live.rec");
    std::fs::write(&full_path, TYPED).unwrap();
    let full = std::fs::OpenOptions::new().write(true).open(&full_path).unwrap();
    full.lock().unwrap();
    let scan = std::panic::catch_unwind(|| everything_written(dir.path()));
    assert!(scan.is_err(), "a locked file with data was skipped by the secret scan");
    drop((empty, full));
}

fn set(data_dir: &str, id: &str, value: &str) {
    let store = SettingsStore::new(Path::new(data_dir).join("settings.json"));
    let mut settings = store.load().unwrap();
    settings.set(id, value).unwrap();
    store.save(&settings).unwrap();
}

/// A library with `Customers / Acme / <connection>` on a closed port.
fn offline(protocol: &str) -> (tempfile::TempDir, String, Arc<Library>, Arc<SessionManager>, String) {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().display().to_string();
    let lib = Arc::new(Library::open(dir.path().join("lib.json").display().to_string()).unwrap());
    let customers = lib.add_folder(None, "Customers".into()).unwrap();
    let acme = lib.add_folder(Some(customers), "Acme".into()).unwrap();
    let id = lib.add_connection(Some(acme), "web-01".into(), protocol.into(), "127.0.0.1".into(), Some(CLOSED_PORT), Some("tester".into())).unwrap();
    let mgr = SessionManager::new(data_dir.clone()).unwrap();
    (dir, data_dir, lib, mgr, id)
}

fn typed() -> SshLogin {
    SshLogin::Password { password: TYPED.into() }
}

#[test]
fn a_connect_that_fails_is_recorded_with_its_folders_its_login_source_and_no_secret() {
    let (dir, data_dir, lib, mgr, id) = offline("ssh");
    assert!(mgr.connect_ssh(lib, id.clone(), "tester".into(), typed(), None, HashMap::new(), HashMap::new(), 80, 24).is_err());

    let all = sessions(&data_dir);
    assert_eq!(all.len(), 1, "{all:?}");
    let s = &all[0];
    assert_eq!((s["connectionId"].as_str(), s["connectionName"].as_str(), s["protocol"].as_str()), (Some(id.as_str()), Some("web-01"), Some("ssh")));
    assert_eq!((s["host"].as_str(), s["port"].as_u64(), s["username"].as_str()), (Some("127.0.0.1"), Some(CLOSED_PORT.into()), Some("tester")));
    assert_eq!(s["folderPath"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect::<Vec<_>>(), ["Customers", "Acme"], "root first");
    assert_eq!(s["loginSource"], "typed");
    assert_eq!(s["app"], if cfg!(windows) { "native-windows" } else { "native-mac" });
    assert_eq!(s["appVersion"].as_str(), Some(crate::app_version().as_str()));
    assert!(!s["deviceName"].as_str().unwrap().is_empty());
    assert_eq!(s["open"], false, "a failed connect is ended at once");
    assert!(!EndReason::is_ok(serde_json::from_value(s["endReason"].clone()).unwrap()), "{}", s["endReason"]);
    assert!(s["connectedAt"].is_null(), "it never connected");

    // The audit record of the attempt carries the session id.
    let connects = audit(&data_dir, "ssh.connect");
    assert_eq!(connects.len(), 1);
    assert_eq!((connects[0]["outcome"].as_str(), &connects[0]["correlation_id"]), (Some("failure"), &s["sessionId"]));
    assert!(audit(&data_dir, "ssh.disconnect").is_empty(), "nothing connected, so nothing disconnected");
    assert!(!everything_written(dir.path()).contains(TYPED), "the typed password was written to disk");
}

#[test]
fn nothing_is_recorded_while_the_setting_is_off() {
    let (dir, data_dir, lib, mgr, id) = offline("ssh");
    set(&data_dir, "logging.activity-enabled", "false");
    assert!(mgr.connect_ssh(lib.clone(), id.clone(), "tester".into(), typed(), None, HashMap::new(), HashMap::new(), 80, 24).is_err());
    assert!(mgr.connect_sftp(lib.clone(), id, "tester".into(), typed(), None, HashMap::new(), HashMap::new()).is_err());
    assert!(!dir.path().join("activity").exists(), "the store was created while history is off");
    assert!(sessions(&data_dir).is_empty());
    // The audit log is not the activity store: it is written as before, without a session id.
    let connects = audit(&data_dir, "ssh.connect");
    assert_eq!(connects.len(), 2);
    assert!(connects.iter().all(|e| e["correlation_id"].is_null()));
}

#[test]
fn a_files_connect_that_fails_is_recorded_once_and_writes_no_sftp_event() {
    let (dir, data_dir, lib, mgr, id) = offline("sftp");
    assert!(mgr.connect_sftp(lib, id, "tester".into(), typed(), None, HashMap::new(), HashMap::new()).is_err());
    let all = sessions(&data_dir);
    assert_eq!(all.len(), 1);
    assert_eq!((all[0]["protocol"].as_str(), all[0]["open"].as_bool()), (Some("sftp"), Some(false)));
    assert!(audit(&data_dir, "sftp.connect").is_empty() && audit(&data_dir, "sftp.disconnect").is_empty(), "no file session was opened");
    assert!(!everything_written(dir.path()).contains(TYPED));
}

#[test]
fn an_ftps_sign_in_that_fails_is_recorded_and_its_audit_record_carries_the_session_id() {
    let (dir, data_dir, lib, mgr, id) = offline("ftps");
    assert!(mgr.connect_ftps(lib, id, String::new(), TYPED.into(), None).is_err());
    let all = sessions(&data_dir);
    assert_eq!(all.len(), 1, "{all:?}");
    let s = &all[0];
    assert_eq!((s["protocol"].as_str(), s["open"].as_bool(), s["loginSource"].as_str(), s["username"].as_str()), (Some("ftps"), Some(false), Some("typed"), Some("tester")));
    assert_eq!(s["folderPath"].as_array().unwrap().len(), 2);
    assert!(!EndReason::is_ok(serde_json::from_value(s["endReason"].clone()).unwrap()));
    let connects = audit(&data_dir, "ftps.connect");
    assert_eq!(connects.len(), 1);
    assert_eq!((connects[0]["outcome"].as_str(), &connects[0]["correlation_id"]), (Some("failure"), &s["sessionId"]));
    assert!(audit(&data_dir, "ftps.disconnect").is_empty(), "nothing connected, so nothing disconnected");
    assert!(!everything_written(dir.path()).contains(TYPED), "the password was written to disk");

    let (_dir2, data_dir2, lib2, mgr2, id2) = offline("ftps");
    set(&data_dir2, "logging.activity-enabled", "false");
    assert!(mgr2.connect_ftps(lib2, id2, String::new(), TYPED.into(), None).is_err());
    assert!(sessions(&data_dir2).is_empty(), "recorded while history is off");
    assert!(audit(&data_dir2, "ftps.connect")[0]["correlation_id"].is_null());
}

#[test]
fn the_login_source_follows_what_the_user_chose() {
    assert_eq!(recording::typed_login_source(&typed()), Some(LoginSource::Typed));
    assert_eq!(recording::typed_login_source(&SshLogin::PasswordAndCode { password: TYPED.into(), code: "123456".into() }), Some(LoginSource::Typed));
    assert_eq!(recording::typed_login_source(&SshLogin::KeyFile { path: "/keys/id".into(), passphrase: None }), Some(LoginSource::Key));
    assert_eq!(recording::typed_login_source(&SshLogin::Agent), Some(LoginSource::Agent));
    assert_eq!(recording::typed_login_source(&SshLogin::Vault { credential_id: Uuid::new_v4().to_string() }), None, "a saved login is looked up");
    let other = Uuid::new_v4();
    assert_eq!(recording::saved_login_source(Some(&Candidate::Default)), LoginSource::Own);
    assert_eq!(recording::saved_login_source(Some(&Candidate::Connection)), LoginSource::Own);
    assert_eq!(recording::saved_login_source(Some(&Candidate::Named)), LoginSource::Own);
    assert_eq!(recording::saved_login_source(Some(&Candidate::Inherited { folder: Some(other), name: "Acme".into() })), LoginSource::Inherited);
    assert_eq!(recording::saved_login_source(Some(&Candidate::SameHost { connection: other, name: "db".into() })), LoginSource::SameHost);
    assert_eq!(recording::saved_login_source(None), LoginSource::Own, "a saved login the resolver does not list");
}

fn start(connection: Uuid) -> SessionStart {
    SessionStart {
        connection_id: connection,
        connection_name: "web-01".into(),
        folder_path: vec![],
        protocol: "ssh".into(),
        host: "web-01.example.test".into(),
        port: Some(22),
        username: Some("deploy".into()),
        route: vec![],
        login_source: LoginSource::Own,
        started_at: bastion_core::activity::now_ms(),
        app: App::NativeMac,
        app_version: "1.0.0".into(),
        device_name: "test-mac".into(),
    }
}

#[test]
fn a_session_left_open_by_a_run_that_quit_is_closed_as_crashed_at_the_next_start() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().display().to_string();
    // An earlier run: it began a session and went away without ending it.
    let earlier = ActivityLog::in_dir(dir.path());
    let id = earlier.begin(start(Uuid::new_v4())).unwrap();
    drop(earlier);

    assert_eq!(activity_close_orphans(data_dir.clone()).unwrap(), 1);
    let all = sessions(&data_dir);
    assert_eq!((all[0]["sessionId"].as_str(), all[0]["open"].as_bool(), all[0]["endReason"].as_str()), (Some(id.to_string().as_str()), Some(false), Some("app_crashed")));
    assert_eq!(activity_close_orphans(data_dir).unwrap(), 0, "closed once");
}

#[test]
fn a_start_up_sweep_that_cannot_get_the_gate_closes_nothing_and_is_not_a_failure() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().display().to_string();
    let earlier = ActivityLog::in_dir(dir.path());
    earlier.begin(start(Uuid::new_v4())).unwrap();
    drop(earlier);
    // Another instance stopped while holding the gate.
    let gate = std::fs::OpenOptions::new().write(true).open(dir.path().join("activity").join("runs.lock")).unwrap();
    gate.lock().unwrap();

    let began = Instant::now();
    assert_eq!(activity_close_orphans(data_dir.clone()).unwrap(), 0, "a stuck gate is 'try at the next start', not an error");
    assert!(began.elapsed() < Duration::from_secs(8), "the sweep waited {:?}", began.elapsed());
    assert_eq!(sessions(&data_dir)[0]["open"], true, "nothing was closed without the gate");
    drop(gate);
    assert_eq!(activity_close_orphans(data_dir).unwrap(), 1, "the next start closes it");
}

// ---- live: bastion-sshd behind the reconnect tests' proxy ----

fn wait_for(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The sessions of `connection` that connected, as another instance of the app reads them.
fn connected(dir: &Path, connection: &str) -> Vec<SessionSummary> {
    let other = ActivityLog::in_dir(dir);
    let filter = Filter { connection: Some(connection.parse().unwrap()), ..Filter::default() };
    other.query(&filter, PAGE).unwrap().into_iter().filter(|s| s.connected_at.is_some() || s.open).collect()
}

fn live(auto_reconnect: bool) -> (std::path::PathBuf, String, Arc<Library>, Arc<SessionManager>, String, crate::reconnect_tests::Proxy, String) {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    let (dir, lib, mgr, id, proxy) = setup(auto_reconnect).unwrap();
    let fp = trust(&mgr, &lib, &id);
    let data_dir = dir.display().to_string();
    (dir, data_dir, lib, mgr, id, proxy, fp)
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn a_terminal_closed_by_the_user_is_one_session_from_connect_to_disconnect() {
    let (dir, data_dir, lib, mgr, id, _proxy, fp) = live(false);
    let t = mgr.connect_ssh(lib, id.clone(), "tester".into(), pw(), Some(fp), HashMap::new(), HashMap::new(), 80, 24).unwrap();
    wait_text(&t, "$", 10);

    // While it is open, a second instance of the app sees it open and does not take it for dead.
    let open = connected(&dir, &id);
    assert_eq!(open.len(), 1, "{open:?}");
    assert!(open[0].open && open[0].login_source == LoginSource::Typed && open[0].username.as_deref() == Some("tester"));
    assert_eq!(ActivityLog::in_dir(&dir).close_orphans(bastion_core::activity::now_ms()).unwrap(), 0, "another instance closed a live session");

    t.close();
    wait_for("the session to end", 10, || connected(&dir, &id).iter().all(|s| !s.open));
    let done = connected(&dir, &id);
    assert_eq!(done.len(), 1, "one terminal is one session: {done:?}");
    let s = &done[0];
    assert_eq!((s.end_reason, s.reconnects), (Some(EndReason::ClosedByUser), Some(0)));
    assert!(s.connected_at.is_some() && s.duration_ms.is_some());

    // The audit log ties the connect and the disconnect to the session; the host-key refusal
    // before it was a session of its own.
    let session = s.session_id.to_string();
    let with_id = |action: &str| audit(&data_dir, action).into_iter().filter(|e| e["correlation_id"] == session.as_str()).collect::<Vec<_>>();
    assert_eq!(with_id("ssh.connect").len(), 1);
    let disconnects = with_id("ssh.disconnect");
    assert_eq!(disconnects.len(), 1, "exactly one disconnect");
    assert_eq!(disconnects[0]["details"]["reason"], "closed_by_user");
    assert_eq!(audit(&data_dir, "ssh.disconnect").len(), 1);
    assert!(!everything_written(&dir).contains("test-pass-123"), "the password was written to disk");
    std::fs::remove_dir_all(dir).ok();
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn a_shell_that_exits_ends_the_session_as_closed_by_the_remote_side() {
    let (dir, _data_dir, lib, mgr, id, _proxy, fp) = live(false);
    let t = mgr.connect_ssh(lib, id.clone(), "tester".into(), pw(), Some(fp), HashMap::new(), HashMap::new(), 80, 24).unwrap();
    wait_text(&t, "$", 10);
    t.write(b"exit\r".to_vec()).unwrap();
    wait_for("the session to end", 10, || connected(&dir, &id).iter().all(|s| !s.open));
    let done = connected(&dir, &id);
    assert_eq!(done.iter().map(|s| s.end_reason).collect::<Vec<_>>(), [Some(EndReason::RemoteClosed)]);
    // Closing the tab afterwards does not end it a second time.
    t.close();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(connected(&dir, &id).len(), 1);
    std::fs::remove_dir_all(dir).ok();
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn a_dropped_link_that_is_given_up_ends_the_session_as_network_lost() {
    let (dir, data_dir, lib, mgr, id, proxy, fp) = live(false);
    let t = mgr.connect_ssh(lib, id.clone(), "tester".into(), pw(), Some(fp), HashMap::new(), HashMap::new(), 80, 24).unwrap();
    wait_text(&t, "$", 10);
    proxy.cut();
    wait_for("the session to end", 20, || connected(&dir, &id).iter().all(|s| !s.open));
    let done = connected(&dir, &id);
    assert_eq!(done.iter().map(|s| s.end_reason).collect::<Vec<_>>(), [Some(EndReason::NetworkLost)]);
    assert_eq!(audit(&data_dir, "ssh.disconnect")[0]["details"]["reason"], "network_lost");
    t.close();
    std::fs::remove_dir_all(dir).ok();
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn a_terminal_that_reconnects_stays_one_session_and_counts_the_reconnect() {
    let (dir, data_dir, lib, mgr, id, proxy, fp) = live(true);
    let t = mgr.connect_ssh(lib, id.clone(), "tester".into(), pw(), Some(fp), HashMap::new(), HashMap::new(), 80, 24).unwrap();
    wait_text(&t, "$", 10);
    proxy.cut();
    wait_text(&t, "reconnected", 30);
    assert_eq!(connected(&dir, &id).iter().filter(|s| s.open).count(), 1, "the reconnect did not start a second session");
    t.close();
    wait_for("the session to end", 10, || connected(&dir, &id).iter().all(|s| !s.open));
    let done = connected(&dir, &id);
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!((done[0].end_reason, done[0].reconnects), (Some(EndReason::ClosedByUser), Some(1)));
    assert_eq!(audit(&data_dir, "ssh.disconnect").len(), 1);
    std::fs::remove_dir_all(dir).ok();
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn a_files_session_is_recorded_and_writes_its_connect_and_disconnect_events() {
    let (dir, data_dir, lib, mgr, id, _proxy, fp) = live(false);
    let b = mgr.connect_sftp(lib, id.clone(), "tester".into(), pw(), Some(fp), HashMap::new(), HashMap::new()).unwrap();
    assert!(!b.home().unwrap().is_empty());
    let open = connected(&dir, &id);
    assert_eq!(open.len(), 1);
    let session = open[0].session_id.to_string();
    let connects = audit(&data_dir, "sftp.connect");
    assert_eq!(connects.len(), 1);
    assert_eq!((connects[0]["correlation_id"].as_str(), connects[0]["details"]["protocol"].as_str(), connects[0]["outcome"].as_str()), (Some(session.as_str()), Some("sftp"), Some("success")));
    assert!(audit(&data_dir, "sftp.disconnect").is_empty());

    drop(b);
    wait_for("the session to end", 10, || connected(&dir, &id).iter().all(|s| !s.open));
    assert_eq!(connected(&dir, &id)[0].end_reason, Some(EndReason::ClosedByUser));
    let disconnects = audit(&data_dir, "sftp.disconnect");
    assert_eq!(disconnects.len(), 1);
    assert_eq!((disconnects[0]["correlation_id"].as_str(), disconnects[0]["details"]["reason"].as_str()), (Some(session.as_str()), Some("closed_by_user")));
    // The SSH connection under it ended too, with the same id.
    let ssh = audit(&data_dir, "ssh.disconnect");
    assert_eq!((ssh.len(), ssh[0]["correlation_id"].as_str()), (1, Some(session.as_str())));
    std::fs::remove_dir_all(dir).ok();
}
