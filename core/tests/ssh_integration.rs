//! Real-endpoint SSH tests. Run against the disposable server described in docs/TESTING.md:
//! `BASTION_SSH_TEST=1 BASTION_SSH_KEY=<path to private key> cargo test --test ssh_integration`
//! Without `BASTION_SSH_TEST` every test prints SKIPPED and returns — it does not count as verified.
use std::path::PathBuf;
use std::time::Duration;

use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::vault::Secret;
use bastion_core::CoreError;
use russh::ChannelMsg;

const HOST: &str = "127.0.0.1";
const PORT: u16 = 2222;
const USER: &str = "tester";
const PASSWORD: &str = "test-pass-123";

fn enabled(name: &str) -> bool {
    let on = std::env::var("BASTION_SSH_TEST").is_ok();
    if !on {
        eprintln!("SKIPPED {name}: set BASTION_SSH_TEST=1 with the test server running");
    }
    on
}

fn params(known_hosts: PathBuf, auth: SshAuth, policy: HostKeyPolicy) -> SshParams {
    SshParams {
        host: HOST.into(),
        port: PORT,
        username: USER.into(),
        auth,
        known_hosts,
        policy,
        connect_timeout: Duration::from_secs(10),
        keepalive: Some(Duration::from_secs(30)),
        prompter: None,
        algorithms: Default::default(),
    }
}

fn password(pw: &str) -> SshAuth {
    SshAuth::Password(Secret::new(pw))
}

async fn trusted_known_hosts(dir: &tempfile::TempDir) -> PathBuf {
    let kh = dir.path().join("known_hosts");
    let s = SshSession::connect(params(kh.clone(), password(PASSWORD), HostKeyPolicy::AcceptNew)).await.unwrap();
    s.disconnect().await.unwrap();
    kh
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn strict_policy_refuses_unknown_host_and_reports_fingerprint() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("strict_unknown") { return; }
    let dir = tempfile::tempdir().unwrap();
    let err = SshSession::connect(params(dir.path().join("kh"), password(PASSWORD), HostKeyPolicy::Strict))
        .await
        .err()
        .expect("must refuse");
    match err {
        CoreError::HostKeyUnknown { fingerprint } => assert!(fingerprint.starts_with("SHA256:")),
        other => panic!("unexpected {other:?}"),
    }
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn password_login_exec_and_learned_key_is_trusted_strictly() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("password_exec") { return; }
    let dir = tempfile::tempdir().unwrap();
    let kh = trusted_known_hosts(&dir).await;
    let s = SshSession::connect(params(kh, password(PASSWORD), HostKeyPolicy::Strict)).await.unwrap();
    let out = s.exec("echo hello-$((40+2)); echo oops >&2; exit 3").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello-42\n");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "oops\n");
    assert_eq!(out.exit_status, Some(3));
    s.disconnect().await.unwrap();
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn wrong_password_is_auth_failure() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("wrong_password") { return; }
    let dir = tempfile::tempdir().unwrap();
    let kh = trusted_known_hosts(&dir).await;
    let err = SshSession::connect(params(kh, password("nope"), HostKeyPolicy::Strict)).await.err().unwrap();
    assert!(matches!(err, CoreError::AuthFailed), "{err:?}");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn private_key_login_from_file_and_from_memory() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("key_login") { return; }
    let key_path = PathBuf::from(std::env::var("BASTION_SSH_KEY").expect("BASTION_SSH_KEY"));
    let dir = tempfile::tempdir().unwrap();
    let kh = trusted_known_hosts(&dir).await;
    let file_auth = SshAuth::KeyFile { path: key_path.clone(), passphrase: None };
    let s = SshSession::connect(params(kh.clone(), file_auth, HostKeyPolicy::Strict)).await.unwrap();
    assert_eq!(s.exec("whoami").await.unwrap().stdout, b"tester\n");
    let pem = Secret::new(std::fs::read_to_string(&key_path).unwrap());
    let s2 = SshSession::connect(params(kh, SshAuth::KeyPem { pem, passphrase: None }, HostKeyPolicy::Strict))
        .await
        .unwrap();
    assert_eq!(s2.exec("whoami").await.unwrap().exit_status, Some(0));
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn changed_host_key_is_refused_even_with_accept_new() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("key_changed") { return; }
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    // A syntactically valid but different ed25519 key recorded for the same host:port.
    std::fs::write(
        &kh,
        format!("[{HOST}]:{PORT} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"),
    )
    .unwrap();
    let err = SshSession::connect(params(kh.clone(), password(PASSWORD), HostKeyPolicy::AcceptNew)).await.err().unwrap();
    assert!(matches!(err, CoreError::HostKeyChanged { line: 1 }), "{err:?}");
    assert_eq!(std::fs::read_to_string(&kh).unwrap().lines().count(), 1, "known_hosts must not be modified");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn unroutable_host_times_out() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("timeout") { return; }
    let mut p = params(PathBuf::from("/nonexistent"), password(PASSWORD), HostKeyPolicy::Strict);
    p.host = "10.255.255.1".into();
    p.connect_timeout = Duration::from_secs(1);
    let err = SshSession::connect(p).await.err().unwrap();
    assert!(matches!(err, CoreError::Timeout | CoreError::Ssh(_)), "{err:?}");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn interactive_pty_shell_round_trip_and_resize() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("pty_shell") { return; }
    let dir = tempfile::tempdir().unwrap();
    let kh = trusted_known_hosts(&dir).await;
    let s = SshSession::connect(params(kh, password(PASSWORD), HostKeyPolicy::Strict)).await.unwrap();
    let mut ch = s.open_shell("xterm-256color", 80, 24).await.unwrap();
    ch.window_change(132, 40, 0, 0).await.unwrap();
    ch.data(&b"stty size; echo marker-$((6*7)); exit\n"[..]).await.unwrap();
    let mut screen = String::new();
    let collect = async {
        while let Some(msg) = ch.wait().await {
            if let ChannelMsg::Data { data } = msg {
                screen.push_str(&String::from_utf8_lossy(&data));
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), collect).await.expect("shell did not exit");
    assert!(screen.contains("marker-42"), "{screen}");
    assert!(screen.contains("40 132"), "resize not applied: {screen}");
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn many_simultaneous_sessions() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("concurrency") { return; }
    let dir = tempfile::tempdir().unwrap();
    let kh = trusted_known_hosts(&dir).await;
    let tasks: Vec<_> = (0..8)
        .map(|i| {
            let kh = kh.clone();
            tokio::spawn(async move {
                let s = SshSession::connect(params(kh, password(PASSWORD), HostKeyPolicy::Strict)).await.unwrap();
                s.exec(&format!("echo {i}")).await.unwrap().stdout
            })
        })
        .collect();
    for (i, t) in tasks.into_iter().enumerate() {
        assert_eq!(t.await.unwrap(), format!("{i}\n").into_bytes());
    }
}

/// Needs an agent holding the test key: `eval $(ssh-agent) && ssh-add $BASTION_SSH_KEY`, then
/// `BASTION_SSH_AGENT_TEST=1`.
#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn agent_identity_logs_in() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("agent") || std::env::var("BASTION_SSH_AGENT_TEST").is_err() { return; }
    let dir = tempfile::tempdir().unwrap();
    let kh = trusted_known_hosts(&dir).await;
    let s = SshSession::connect(params(kh, SshAuth::Agent { socket: None }, HostKeyPolicy::Strict)).await.expect("agent login");
    let out = s.exec("echo agent-ok").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "agent-ok");
    s.disconnect().await.unwrap();
}

/// A key with `<key>-cert.pub` next to it logs in with the certificate. Needs a server that
/// trusts the signing CA (`BASTION_SSH_CERT_KEY=<key path>`; see docs/TESTING.md).
#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn key_with_certificate_logs_in() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("certificate") { return; }
    let Ok(key) = std::env::var("BASTION_SSH_CERT_KEY") else { return };
    let dir = tempfile::tempdir().unwrap();
    let kh = trusted_known_hosts(&dir).await;
    let auth = SshAuth::KeyFile { path: PathBuf::from(key), passphrase: None };
    let s = SshSession::connect(params(kh, auth, HostKeyPolicy::Strict)).await.expect("certificate login");
    s.disconnect().await.unwrap();
}

/// Keyboard-interactive tests run against a server that offers no `password` method (PAM through
/// keyboard-interactive only); `BASTION_SSH_KBD_PORT=<port>`, see docs/TESTING.md.
fn kbd_port() -> Option<u16> {
    std::env::var("BASTION_SSH_KBD_PORT").ok()?.parse().ok()
}

struct Answers(Vec<&'static str>, std::sync::Mutex<Vec<bastion_core::ssh_auth::KbdChallenge>>);

impl bastion_core::ssh_auth::KbdPrompter for Answers {
    fn answer<'a>(&'a self, c: &'a bastion_core::ssh_auth::KbdChallenge) -> bastion_core::ssh_auth::PromptFuture<'a> {
        self.1.lock().unwrap().push(c.clone());
        Box::pin(async move { Some(self.0.iter().map(|a| Secret::new(*a)).collect()) })
    }
}

async fn kbd_params(port: u16, auth: SshAuth, prompter: Option<std::sync::Arc<dyn bastion_core::ssh_auth::KbdPrompter>>) -> SshParams {
    let dir = tempfile::tempdir().unwrap().keep();
    SshParams { port, prompter, ..params(dir.join("kh"), auth, HostKeyPolicy::AcceptNew) }
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn password_falls_back_to_keyboard_interactive() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("kbd_password") { return; }
    let Some(port) = kbd_port() else { return };
    let s = SshSession::connect(kbd_params(port, password(PASSWORD), None).await).await.expect("PAM login with the saved password");
    s.disconnect().await.unwrap();
}

/// The server requires a key and then keyboard-interactive (`AuthenticationMethods
/// publickey,keyboard-interactive`): the second factor is asked of the prompter.
#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn second_factor_is_asked_of_the_person() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("kbd_mfa") || std::env::var("BASTION_SSH_KBD_MFA").is_err() { return; }
    let (Some(port), Ok(key)) = (kbd_port(), std::env::var("BASTION_SSH_KEY")) else { return };
    let answers = std::sync::Arc::new(Answers(vec![PASSWORD], Default::default()));
    let auth = SshAuth::KeyFile { path: PathBuf::from(key), passphrase: None };
    let s = SshSession::connect(kbd_params(port, auth, Some(answers.clone())).await).await.expect("key + second factor");
    s.disconnect().await.unwrap();
    let asked = answers.1.lock().unwrap();
    assert_eq!(asked.len(), 1);
    assert!(!asked[0].prompts[0].echo);
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn second_factor_without_a_prompter_fails() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("kbd_mfa_none") || std::env::var("BASTION_SSH_KBD_MFA").is_err() { return; }
    let (Some(port), Ok(key)) = (kbd_port(), std::env::var("BASTION_SSH_KEY")) else { return };
    let auth = SshAuth::KeyFile { path: PathBuf::from(key), passphrase: None };
    let err = SshSession::connect(kbd_params(port, auth, None).await).await.err().expect("must fail");
    assert!(matches!(err, CoreError::AuthFailed), "{err:?}");
}
