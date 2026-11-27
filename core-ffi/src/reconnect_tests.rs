//! Live: split panes and SFTP browsers follow an opt-in reconnect. bastion-sshd sits behind a
//! local proxy that the test cuts, like a network drop (`BASTION_SSH_TEST=1`).
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bastion_core::model::{Connection, Node, Protocol};
use tokio::sync::watch;
use uuid::Uuid;

use crate::terminal::RUNTIME;
use crate::{FfiError, Library, SessionManager, SshLogin, Terminal};

/// Forwards 127.0.0.1:<port> to bastion-sshd. Bumping the generation drops every open
/// connection; the listener stays, so a reconnect gets through.
pub(crate) struct Proxy {
    port: u16,
    cut: watch::Sender<u64>,
}

impl Proxy {
    fn start() -> Proxy {
        let listener = RUNTIME.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (cut, rx) = watch::channel(0u64);
        RUNTIME.spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let mut rx = rx.clone();
                rx.borrow_and_update();
                tokio::spawn(async move {
                    let Ok(mut server) = tokio::net::TcpStream::connect("127.0.0.1:2222").await else { return };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
                        _ = rx.changed() => {}
                    }
                });
            }
        });
        Proxy { port, cut }
    }

    pub(crate) fn cut(&self) {
        self.cut.send_modify(|g| *g += 1);
    }
}

fn text(t: &Terminal) -> String {
    let s = t.screen();
    s.cells.chunks(s.cols as usize).map(|r| r.iter().map(|c| c.text.as_str()).collect::<String>() + "\n").collect()
}

pub(crate) fn wait_text(t: &Terminal, needle: &str, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !text(t).contains(needle) {
        assert!(Instant::now() < deadline, "timed out waiting for {needle}:\n{}", text(t));
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub(crate) fn setup(auto_reconnect: bool) -> Option<(std::path::PathBuf, Arc<Library>, Arc<SessionManager>, String, Proxy)> {
    if std::env::var("BASTION_SSH_TEST").is_err() {
        eprintln!("SKIPPED: set BASTION_SSH_TEST=1");
        return None;
    }
    let proxy = Proxy::start();
    let dir = std::env::temp_dir().join(format!("bastion-ffi-rc-{}", Uuid::new_v4()));
    let lib = Arc::new(Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap());
    let mut c = Connection::new("proxied", Protocol::Ssh, "127.0.0.1");
    c.settings.port = Some(proxy.port);
    c.settings.username = Some("tester".into());
    c.settings.auto_reconnect = Some(auto_reconnect);
    let id = c.id.to_string();
    lib.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();
    let mgr = SessionManager::new(dir.to_string_lossy().into_owned()).unwrap();
    Some((dir, lib, mgr, id, proxy))
}

pub(crate) fn pw() -> SshLogin {
    SshLogin::Password { password: "test-pass-123".into() }
}

/// Trust the proxied server's key the way the sheet does after the prompt.
pub(crate) fn trust(mgr: &SessionManager, lib: &Arc<Library>, id: &str) -> String {
    match mgr.connect_ssh(lib.clone(), id.into(), "tester".into(), pw(), None, HashMap::new(), HashMap::new(), 80, 24) {
        Err(FfiError::HostKeyUnknown { fingerprint }) => fingerprint,
        Err(e) => panic!("expected a host-key prompt, got {e}"),
        Ok(_) => panic!("unknown key"),
    }
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn split_panes_continue_after_a_reconnect() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    let Some((dir, lib, mgr, id, proxy)) = setup(true) else { return };
    let fp = trust(&mgr, &lib, &id);
    let main = mgr.connect_ssh(lib.clone(), id.clone(), "tester".into(), pw(), Some(fp), HashMap::new(), HashMap::new(), 80, 24).unwrap();
    wait_text(&main, "$", 10);
    let pane = main.open_sibling(80, 24).unwrap();
    pane.write(b"echo pane-$((1+1))\r".to_vec()).unwrap();
    wait_text(&pane, "pane-2", 10);

    proxy.cut();
    wait_text(&main, "reconnected", 30);
    wait_text(&pane, "reconnected", 5);
    pane.write(b"echo pane-after-$((2+2))\r".to_vec()).unwrap();
    wait_text(&pane, "pane-after-4", 10);
    main.write(b"echo main-after-$((3+3))\r".to_vec()).unwrap();
    wait_text(&main, "main-after-6", 10);

    // A pane whose shell exits stays closed; closing the main terminal ends the rest.
    pane.write(b"exit\r".to_vec()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while pane.is_alive() {
        assert!(Instant::now() < deadline, "exited pane still alive");
        std::thread::sleep(Duration::from_millis(50));
    }
    main.close();
    std::fs::remove_dir_all(dir).ok();
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn split_panes_end_with_a_terminal_that_does_not_reconnect() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    let Some((dir, lib, mgr, id, proxy)) = setup(false) else { return };
    let fp = trust(&mgr, &lib, &id);
    let main = mgr.connect_ssh(lib.clone(), id.clone(), "tester".into(), pw(), Some(fp), HashMap::new(), HashMap::new(), 80, 24).unwrap();
    wait_text(&main, "$", 10);
    let pane = main.open_sibling(80, 24).unwrap();
    wait_text(&pane, "$", 10);
    proxy.cut();
    let deadline = Instant::now() + Duration::from_secs(15);
    while pane.is_alive() || main.is_alive() {
        assert!(Instant::now() < deadline, "panes still alive after the link dropped");
        std::thread::sleep(Duration::from_millis(50));
    }
    std::fs::remove_dir_all(dir).ok();
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn sftp_reconnects_on_the_next_call() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    let Some((dir, lib, mgr, id, proxy)) = setup(true) else { return };
    let fp = trust(&mgr, &lib, &id);
    let b = mgr.connect_sftp(lib.clone(), id.clone(), "tester".into(), pw(), Some(fp), HashMap::new(), HashMap::new()).unwrap();
    let home = b.home().unwrap();
    assert!(!b.list(home.clone()).unwrap().is_empty() || b.list(home.clone()).is_ok());

    proxy.cut();
    let deadline = Instant::now() + Duration::from_secs(10);
    while b.is_connected() {
        assert!(Instant::now() < deadline, "drop not noticed");
        std::thread::sleep(Duration::from_millis(50));
    }
    b.list(home.clone()).expect("list reconnects first");
    assert_eq!(b.reconnects(), 1);
    assert!(b.is_connected());

    // A write is not repeated after a drop mid-call; outside one it just reconnects and runs.
    proxy.cut();
    while b.is_connected() {
        std::thread::sleep(Duration::from_millis(50));
    }
    let folder = format!("{home}/rc-{}", Uuid::new_v4().simple());
    b.mkdir(folder.clone()).unwrap();
    assert_eq!(b.reconnects(), 2);
    b.with_sftp_for_tests(|s| RUNTIME.block_on(s.remove_dir(&folder))).unwrap();
    std::fs::remove_dir_all(dir).ok();
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn sftp_without_auto_reconnect_reports_the_drop() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    let Some((dir, lib, mgr, id, proxy)) = setup(false) else { return };
    let fp = trust(&mgr, &lib, &id);
    let b = mgr.connect_sftp(lib.clone(), id.clone(), "tester".into(), pw(), Some(fp), HashMap::new(), HashMap::new()).unwrap();
    let home = b.home().unwrap();
    proxy.cut();
    std::thread::sleep(Duration::from_secs(1));
    assert!(b.list(home).is_err());
    assert_eq!(b.reconnects(), 0);
    std::fs::remove_dir_all(dir).ok();
}

/// PR-1289 HIGH: Disconnect closes the terminal and keeps it for its scrollback. The SSH transport must end with it,
/// so an SFTP browser opened on the terminal's connection can no longer reach the server.
#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn closing_a_terminal_ends_its_transport_and_files_browser() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    let Some((dir, lib, mgr, id, _proxy)) = setup(true) else { return };
    let fp = trust(&mgr, &lib, &id);
    let main = mgr.connect_ssh(lib.clone(), id.clone(), "tester".into(), pw(), Some(fp), HashMap::new(), HashMap::new(), 80, 24).unwrap();
    wait_text(&main, "$", 10);
    let files = main.open_sftp().unwrap();
    let home = files.home().unwrap();
    files.list(home.clone()).unwrap();

    main.close();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !main.transport_closed() {
        assert!(Instant::now() < deadline, "SSH transport still open after close");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(files.list(home).is_err(), "Files browser still lists after Disconnect");
    std::fs::remove_dir_all(dir).ok();
}
