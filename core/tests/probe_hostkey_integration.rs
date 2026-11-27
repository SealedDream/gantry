//! SEC-07: Test Connection never sends a login to a host whose key nobody confirmed.
//!
//! In-process russh servers record every authentication request they receive, so "the server
//! saw no authentication attempt" is checked on the server side. Nothing here needs the network
//! or the Docker fixture: these cases always run, also offline.
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bastion_core::model::Protocol;
use bastion_core::probe::{run, HostKeyFailure, ProbeHop, ProbeReport, ProbeRequest, ProbeStep, StepKind, StepStatus};
use bastion_core::ssh::{fingerprint, SshAuth};
use bastion_core::vault::Secret;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::LineEnding;
use russh::keys::PrivateKey;
use russh::server::{self, Auth};
use russh::Channel;

const USER: &str = "tester";
const PASSWORD: &str = "lab-only-not-a-real-password";
const NOT_TESTED: &str = "Not tested: confirm the host key first";
/// A valid ed25519 public key that no server here uses: a "changed" known_hosts entry.
const OTHER_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

/// Every authentication request a server received, by method name.
type Seen = Arc<Mutex<Vec<&'static str>>>;

struct Lab(Seen);

impl Lab {
    fn saw(&self, method: &'static str) {
        self.0.lock().unwrap().push(method);
    }
}

impl server::Handler for Lab {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        self.saw("none");
        Ok(Auth::reject())
    }
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.saw("password");
        Ok(if user == USER && password == PASSWORD { Auth::Accept } else { Auth::reject() })
    }
    async fn auth_publickey_offered(&mut self, _user: &str, _offer: server::PublicKeyOffer<'_>) -> Result<Auth, Self::Error> {
        self.saw("publickey-offered");
        Ok(Auth::Accept)
    }
    async fn auth_publickey(&mut self, _user: &str, _key: server::VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        self.saw("publickey");
        Ok(Auth::Accept)
    }
    async fn auth_keyboard_interactive<'a>(&'a mut self, _user: &str, _submethods: &str, _response: Option<server::Response<'a>>) -> Result<Auth, Self::Error> {
        self.saw("keyboard-interactive");
        Ok(Auth::reject())
    }
    /// Acts as a jump host: pipe the channel to the asked address.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<server::Msg>,
        host: &str,
        port: u32,
        _originator: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let Ok(mut out) = tokio::net::TcpStream::connect((host, port as u16)).await else { return Ok(()) };
        reply.accept().await;
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut out, &mut stream).await;
        });
        Ok(())
    }
}

struct Server {
    port: u16,
    /// `ssh-ed25519 AAAA…`, as a known_hosts line holds it.
    public: String,
    fingerprint: String,
    seen: Seen,
}

impl Server {
    fn attempts(&self) -> Vec<&'static str> {
        self.seen.lock().unwrap().clone()
    }
    fn known_hosts_line(&self) -> String {
        format!("[127.0.0.1]:{} {}\n", self.port, self.public)
    }
}

/// An SSH server on a free loopback port whose host key comes from `seed`.
async fn server(seed: u8) -> Server {
    let key = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&[seed; 32])), "").unwrap();
    let public = key.public_key().to_openssh().unwrap();
    let print = fingerprint(key.public_key());
    let config = Arc::new(server::Config { keys: vec![key], auth_rejection_time: Duration::ZERO, ..Default::default() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let record = seen.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let (config, seen) = (config.clone(), record.clone());
            tokio::spawn(async move {
                if let Ok(s) = server::run_stream(config, sock, Lab(seen)).await {
                    let _ = s.await;
                }
            });
        }
    });
    Server { port, public, fingerprint: print, seen }
}

fn password() -> Option<SshAuth> {
    Some(SshAuth::Password(Secret::new(PASSWORD)))
}

fn req(port: u16, auth: Option<SshAuth>, kh: &Path) -> ProbeRequest {
    ProbeRequest {
        protocol: Protocol::Ssh,
        host: "127.0.0.1".into(),
        port,
        username: USER.into(),
        auth,
        jumps: Vec::new(),
        known_hosts: kh.to_path_buf(),
        timeout: Duration::from_secs(5),
        trusted_fingerprint: None,
    }
}

fn hop(s: &Server) -> ProbeHop {
    ProbeHop { host: "127.0.0.1".into(), port: s.port, username: USER.into(), auth: SshAuth::Password(Secret::new(PASSWORD)) }
}

fn find(r: &ProbeReport, kind: StepKind) -> &ProbeStep {
    r.steps.iter().rev().find(|s| s.kind == kind).unwrap_or_else(|| panic!("no {kind:?} step in {r:#?}"))
}

fn kh(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("known_hosts")
}

/// The report of a test that stopped for the user's decision on `s`'s key.
fn assert_waits_for_confirmation(r: &ProbeReport, s: &Server) {
    assert_eq!(r.needs_host_key_confirmation.as_deref(), Some(s.fingerprint.as_str()), "{r:#?}");
    let key = find(r, StepKind::HostKey);
    assert_eq!((key.status, key.detail.as_str()), (StepStatus::Warn, format!("NEW host key {}", s.fingerprint).as_str()));
    let login = find(r, StepKind::Login);
    assert_eq!((login.status, login.detail.as_str()), (StepStatus::Skipped, NOT_TESTED));
    assert_eq!(s.attempts(), Vec::<&str>::new(), "a login reached a host whose key nobody confirmed");
}

#[tokio::test]
async fn unknown_key_with_a_password_stops_before_any_login() {
    let s = server(1).await;
    let dir = tempfile::tempdir().unwrap();
    let r = run(req(s.port, password(), &kh(&dir))).await;
    assert_waits_for_confirmation(&r, &s);
    assert!(!kh(&dir).exists(), "a test must never create known_hosts");
    assert!(!serde_json::to_string(&r).unwrap().contains(PASSWORD));
}

#[tokio::test]
async fn unknown_key_with_password_and_code_stops_before_any_login() {
    let s = server(1).await;
    let dir = tempfile::tempdir().unwrap();
    let auth = SshAuth::PasswordAndCode { password: Secret::new(PASSWORD), code: Secret::new("000000") };
    let r = run(req(s.port, Some(auth), &kh(&dir))).await;
    assert_waits_for_confirmation(&r, &s);
}

#[tokio::test]
async fn the_confirmed_fingerprint_lets_the_login_be_tested_and_stores_nothing() {
    let s = server(1).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(kh(&dir), "# the user's file\n").unwrap();
    let mut q = req(s.port, password(), &kh(&dir));
    q.trusted_fingerprint = Some(s.fingerprint.clone());
    let r = run(q).await;
    assert!(r.ok, "{r:#?}");
    assert_eq!(r.needs_host_key_confirmation, None);
    assert_eq!(find(&r, StepKind::HostKey).status, StepStatus::Warn, "the key is still reported as new");
    assert_eq!(find(&r, StepKind::Login).detail, "Logged in as 'tester'");
    assert_eq!(s.attempts(), vec!["password"]);
    assert_eq!(std::fs::read_to_string(kh(&dir)).unwrap(), "# the user's file\n", "the real known_hosts was written");
}

/// Declining, or confirming a key other than the one the server shows now (it changed between
/// the two tests, or the caller made one up): the login is still not sent.
#[tokio::test]
async fn a_different_trusted_fingerprint_does_not_release_the_login() {
    let s = server(1).await;
    let other = server(2).await;
    let dir = tempfile::tempdir().unwrap();
    for wrong in [other.fingerprint.clone(), String::new(), "SHA256:".into()] {
        let mut q = req(s.port, password(), &kh(&dir));
        q.trusted_fingerprint = Some(wrong);
        let r = run(q).await;
        assert_waits_for_confirmation(&r, &s);
    }
    assert!(!kh(&dir).exists());
}

#[tokio::test]
async fn unknown_key_with_a_private_key_still_tests_the_login() {
    let s = server(1).await;
    let dir = tempfile::tempdir().unwrap();
    let client = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&[7; 32])), "").unwrap();
    let pem = client.to_openssh(LineEnding::LF).unwrap().to_string();
    let r = run(req(s.port, Some(SshAuth::KeyPem { pem: Secret::new(pem), passphrase: None }), &kh(&dir))).await;
    assert!(r.ok, "{r:#?}");
    assert_eq!(r.needs_host_key_confirmation, None);
    assert_eq!(find(&r, StepKind::HostKey).status, StepStatus::Warn);
    assert_eq!(find(&r, StepKind::Login).detail, "Logged in as 'tester'");
    assert!(s.attempts().contains(&"publickey"), "{:?}", s.attempts());
    assert!(!s.attempts().contains(&"password"));
    assert!(!kh(&dir).exists());
}

#[tokio::test]
async fn known_key_tests_the_login_at_once() {
    let s = server(1).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(kh(&dir), s.known_hosts_line()).unwrap();
    let r = run(req(s.port, password(), &kh(&dir))).await;
    assert!(r.ok, "{r:#?}");
    assert_eq!(r.needs_host_key_confirmation, None);
    let key = find(&r, StepKind::HostKey);
    assert_eq!((key.status, key.detail.as_str()), (StepStatus::Ok, "Host key matches known_hosts"));
    assert_eq!(find(&r, StepKind::Login).detail, "Logged in as 'tester'");
    assert_eq!(s.attempts(), vec!["password"]);
    assert_eq!(std::fs::read_to_string(kh(&dir)).unwrap(), s.known_hosts_line());
}

#[tokio::test]
async fn changed_key_stops_before_any_login_even_when_trusted() {
    let s = server(1).await;
    let dir = tempfile::tempdir().unwrap();
    let recorded = format!("[127.0.0.1]:{} {OTHER_KEY}\n", s.port);
    std::fs::write(kh(&dir), &recorded).unwrap();
    for trusted in [None, Some(s.fingerprint.clone())] {
        let mut q = req(s.port, password(), &kh(&dir));
        q.trusted_fingerprint = trusted;
        let r = run(q).await;
        assert!(!r.ok);
        assert!(find(&r, StepKind::HostKey).detail.starts_with("Host key CHANGED"), "{r:#?}");
        assert_eq!(find(&r, StepKind::Login).status, StepStatus::Skipped);
        assert_eq!(r.needs_host_key_confirmation, None, "a changed key is never offered for trust");
        assert_eq!(r.host_key_failure, Some(HostKeyFailure::Changed));
    }
    assert_eq!(s.attempts(), Vec::<&str>::new());
    assert_eq!(std::fs::read_to_string(kh(&dir)).unwrap(), recorded);
}

/// SEC-07-FU1: an unreadable known_hosts is its own failure, not a changed key, and no login is sent.
#[tokio::test]
async fn unreadable_known_hosts_is_told_apart_from_a_changed_key() {
    let s = server(1).await;
    let dir = tempfile::tempdir().unwrap();
    let not_a_file = dir.path().join("known_hosts_dir");
    std::fs::create_dir(&not_a_file).unwrap();
    let r = run(req(s.port, password(), &not_a_file)).await;
    assert!(!r.ok);
    let step = find(&r, StepKind::HostKey);
    assert_eq!(step.status, StepStatus::Failed, "{r:#?}");
    assert!(step.detail.starts_with("Cannot read known_hosts"), "{r:#?}");
    assert_eq!(r.host_key_failure, Some(HostKeyFailure::KnownHostsUnreadable));
    assert_eq!(s.attempts(), Vec::<&str>::new());
}

/// Review note: with nothing to log in with, the test used to send an empty password (as
/// `bastion-test` when no user was entered), leaving failed logins on the server.
#[tokio::test]
async fn nothing_to_log_in_with_checks_the_key_and_sends_no_login() {
    let s = server(1).await;
    let dir = tempfile::tempdir().unwrap();

    let r = run(req(s.port, None, &kh(&dir))).await;
    assert!(r.ok, "{r:#?}");
    assert_eq!(find(&r, StepKind::HostKey).detail, format!("NEW host key {}", s.fingerprint));
    assert_eq!(find(&r, StepKind::Login).detail, "No credential entered");
    assert_eq!(r.needs_host_key_confirmation, None, "nothing to confirm a key for");

    let mut q = req(s.port, password(), &kh(&dir));
    q.username = "  ".into();
    let r = run(q).await;
    assert_eq!(find(&r, StepKind::HostKey).status, StepStatus::Warn);
    let login = find(&r, StepKind::Login);
    assert_eq!((login.status, login.detail.as_str()), (StepStatus::Failed, "No user name entered"));

    std::fs::write(kh(&dir), s.known_hosts_line()).unwrap();
    let r = run(req(s.port, None, &kh(&dir))).await;
    assert_eq!(find(&r, StepKind::HostKey).detail, "Host key matches known_hosts");
    let mut q = req(s.port, password(), &kh(&dir));
    q.username = String::new();
    let r = run(q).await;
    assert_eq!(find(&r, StepKind::HostKey).detail, "Host key matches known_hosts");
    assert_eq!(find(&r, StepKind::Login).detail, "No user name entered");

    assert_eq!(s.attempts(), Vec::<&str>::new(), "a login was sent with nothing entered");
}

#[tokio::test]
async fn jump_host_with_an_unknown_key_gets_no_login() {
    let jump = server(3).await;
    let target = server(1).await;
    let dir = tempfile::tempdir().unwrap();
    // Trusting a fingerprint is for the target only: it never unlocks a jump host.
    for trusted in [None, Some(jump.fingerprint.clone())] {
        let mut q = req(target.port, password(), &kh(&dir));
        q.jumps = vec![hop(&jump)];
        q.trusted_fingerprint = trusted;
        let r = run(q).await;
        assert!(!r.ok);
        let j = find(&r, StepKind::JumpHost);
        assert_eq!(j.status, StepStatus::Failed);
        assert_eq!(j.detail, format!("Jump host 127.0.0.1:{}: NEW host key {}", jump.port, jump.fingerprint));
        assert_eq!(r.needs_host_key_confirmation, None);
    }
    assert_eq!(jump.attempts(), Vec::<&str>::new(), "a login reached a jump host with an unknown key");
    assert_eq!(target.attempts(), Vec::<&str>::new());
    assert!(!kh(&dir).exists());
}

#[tokio::test]
async fn target_behind_a_known_jump_host_follows_the_same_rule() {
    let jump = server(3).await;
    let target = server(1).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(kh(&dir), jump.known_hosts_line()).unwrap();

    let mut q = req(target.port, password(), &kh(&dir));
    q.jumps = vec![hop(&jump)];
    let r = run(q).await;
    assert_eq!(find(&r, StepKind::JumpHost).status, StepStatus::Ok, "{r:#?}");
    assert_waits_for_confirmation(&r, &target);

    let mut q = req(target.port, password(), &kh(&dir));
    q.jumps = vec![hop(&jump)];
    q.trusted_fingerprint = Some(target.fingerprint.clone());
    let r = run(q).await;
    assert!(r.ok, "{r:#?}");
    assert_eq!(find(&r, StepKind::Login).detail, "Logged in as 'tester'");
    assert_eq!(target.attempts(), vec!["password"]);
    assert_eq!(std::fs::read_to_string(kh(&dir)).unwrap(), jump.known_hosts_line(), "the real known_hosts was written");
}
