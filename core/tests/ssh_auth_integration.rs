//! Keyboard-interactive, TOTP second factor and SSH agent logins against a throwaway PAM server
//! (docs/TESTING.md, "SSH keyboard-interactive / MFA / agent"):
//! `BASTION_KBD_TEST=1 BASTION_AGENT_SOCK=<agent socket holding the test key> cargo test --test ssh_auth_integration`
//! On Windows `BASTION_AGENT_KEY=<agentkey>` instead serves the key from an agent on a named pipe
//! inside the test (the OpenSSH agent is a service, and `ssh-agent -d` serves one connection).
use std::path::PathBuf;
use std::time::Duration;

use bastion_core::ssh::{classify_prompt, HostKeyPolicy, PromptKind, SshAuth, SshParams, SshSession};
use bastion_core::vault::Secret;
use bastion_core::CoreError;

const PORT: u16 = 2231;
/// RFC 6238 test secret ("12345678901234567890"), as configured in the server's users.oath.
const TOTP_HEX: &str = "3132333435363738393031323334353637383930";

fn enabled(name: &str) -> bool {
    let on = std::env::var("BASTION_KBD_TEST").is_ok();
    if !on {
        eprintln!("SKIPPED {name}: set BASTION_KBD_TEST=1 with bastion-p1-kbd running");
    }
    on
}

fn params(kh: PathBuf, user: &str, auth: SshAuth) -> SshParams {
    SshParams {
        host: "127.0.0.1".into(),
        port: PORT,
        username: user.into(),
        auth,
        known_hosts: kh,
        policy: HostKeyPolicy::AcceptNew,
        connect_timeout: Duration::from_secs(10),
        keepalive: None,
        prompter: None,
        algorithms: Default::default(),
    }
}

/// The current TOTP, computed by the server image's own oathtool.
fn totp() -> String {
    let out = std::process::Command::new("docker").args(["exec", "bastion-p1-kbd", "oathtool", "--totp", TOTP_HEX]).output().unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// Windows: an agent holding `BASTION_AGENT_KEY` on the named pipe `name`, for as long as the
/// test runs. Returns `None` without the key, or when the pipe is taken (a running agent service).
#[cfg(windows)]
async fn pipe_agent(name: &str) -> Option<PathBuf> {
    use russh::keys::agent::{client::AgentClient, server};
    use tokio::net::windows::named_pipe::ServerOptions;
    let key = russh::keys::load_secret_key(std::env::var("BASTION_AGENT_KEY").ok()?, None).unwrap();
    let first = ServerOptions::new().first_pipe_instance(true).create(name).ok()?;
    let listener = futures::stream::unfold((first, name.to_string()), |(pipe, name)| async move {
        let accepted = pipe.connect().await.map(|_| pipe);
        let next = ServerOptions::new().create(&name).ok()?;
        Some((accepted, (next, name)))
    });
    tokio::spawn(server::serve(Box::pin(listener), ()));
    let mut client = AgentClient::connect_named_pipe(name).await.unwrap();
    client.add_identity(&key, &[]).await.unwrap();
    Some(PathBuf::from(name))
}

async fn agent_sock() -> PathBuf {
    #[cfg(windows)]
    if let Some(p) = pipe_agent(&format!(r"\\.\pipe\bastion-test-agent-{}", std::process::id())).await {
        return p;
    }
    PathBuf::from(std::env::var("BASTION_AGENT_SOCK").expect("BASTION_AGENT_SOCK"))
}

async fn run(s: &SshSession) -> String {
    String::from_utf8(s.exec("echo ok-$(whoami)").await.unwrap().stdout).unwrap()
}

#[test]
fn prompts_are_classified() {
    assert_eq!(classify_prompt("Password: ", false), PromptKind::Password);
    assert_eq!(classify_prompt("kbd@host's password: ", false), PromptKind::Password);
    assert_eq!(classify_prompt("One-time password (OATH) for `mfa': ", false), PromptKind::Code);
    assert_eq!(classify_prompt("Verification code: ", false), PromptKind::Code);
    assert_eq!(classify_prompt("Enter PIN for token: ", false), PromptKind::Code);
    assert_eq!(classify_prompt("Duo two-factor login: ", true), PromptKind::Code, "visible prompts are never the password");
}

#[ignore = "live: needs BASTION_KBD_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn password_falls_back_to_keyboard_interactive() {
    assert!(std::env::var_os("BASTION_KBD_TEST").is_some(), "live test run without BASTION_KBD_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("password_falls_back_to_keyboard_interactive") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    let s = SshSession::connect(params(kh.clone(), "kbd", SshAuth::Password(Secret::new("kbd-pass-321")))).await.unwrap();
    assert_eq!(run(&s).await.trim(), "ok-kbd");
    let bad = SshSession::connect(params(kh, "kbd", SshAuth::Password(Secret::new("wrong")))).await;
    assert!(matches!(bad, Err(CoreError::AuthFailed)), "{:?}", bad.err());
}

#[ignore = "live: needs BASTION_KBD_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn second_factor_is_asked_for_then_accepted() {
    assert!(std::env::var_os("BASTION_KBD_TEST").is_some(), "live test run without BASTION_KBD_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("second_factor_is_asked_for_then_accepted") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    let pw = || Secret::new("mfa-pass-789");
    let first = SshSession::connect(params(kh.clone(), "mfa", SshAuth::Password(pw()))).await;
    assert!(matches!(first, Err(CoreError::TwoFactorRequired)), "{:?}", first.err());
    let wrong = SshSession::connect(params(kh.clone(), "mfa", SshAuth::PasswordAndCode { password: pw(), code: Secret::new("000000") })).await;
    assert!(matches!(wrong, Err(CoreError::TwoFactorRequired | CoreError::AuthFailed)), "{:?}", wrong.err());
    let s = SshSession::connect(params(kh, "mfa", SshAuth::PasswordAndCode { password: pw(), code: Secret::new(totp()) })).await.unwrap();
    assert_eq!(run(&s).await.trim(), "ok-mfa");
}

#[ignore = "live: needs BASTION_KBD_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn agent_keys_log_in_without_the_key_entering_bastion() {
    assert!(std::env::var_os("BASTION_KBD_TEST").is_some(), "live test run without BASTION_KBD_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("agent_keys_log_in_without_the_key_entering_bastion") {
        return;
    }
    let sock = agent_sock().await;
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    let s = SshSession::connect(params(kh.clone(), "agent", SshAuth::Agent { socket: Some(sock.clone()) })).await.unwrap();
    assert_eq!(run(&s).await.trim(), "ok-agent");
    // An agent the server does not accept any key from is an auth failure, not a crash.
    let other = SshSession::connect(params(kh.clone(), "kbd", SshAuth::Agent { socket: Some(sock) })).await;
    assert!(matches!(other, Err(CoreError::AuthFailed)), "{:?}", other.err());
    let missing = SshSession::connect(params(kh, "agent", SshAuth::Agent { socket: Some(dir.path().join("no-such.sock")) })).await;
    assert!(matches!(missing, Err(CoreError::Invalid(ref m)) if m.contains("agent")), "{:?}", missing.err());
}

/// Windows: with no agent named, Bastion finds the OpenSSH agent's own pipe.
#[cfg(windows)]
#[ignore = "live: needs BASTION_KBD_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn default_windows_agent_pipe_is_found() {
    assert!(std::env::var_os("BASTION_KBD_TEST").is_some(), "live test run without BASTION_KBD_TEST: start the fixture (docs/TESTING.md)");
    if !enabled("default_windows_agent_pipe_is_found") {
        return;
    }
    if pipe_agent(r"\\.\pipe\openssh-ssh-agent").await.is_none() {
        return eprintln!("SKIPPED default_windows_agent_pipe_is_found: no BASTION_AGENT_KEY, or the agent service holds the pipe");
    }
    let dir = tempfile::tempdir().unwrap();
    let s = SshSession::connect(params(dir.path().join("known_hosts"), "agent", SshAuth::Agent { socket: None })).await.unwrap();
    assert_eq!(run(&s).await.trim(), "ok-agent");
}

/// Windows: with no agent named and no OpenSSH agent pipe, Bastion falls back to PuTTY's Pageant.
/// `BASTION_PAGEANT_TEST=<host>:<port>:<user>` names a server that accepts the key Pageant holds.
#[cfg(windows)]
#[ignore = "live: needs BASTION_PAGEANT_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn pageant_is_used_when_no_openssh_agent_runs() {
    assert!(std::env::var_os("BASTION_PAGEANT_TEST").is_some(), "live test run without BASTION_PAGEANT_TEST: start the fixture (docs/TESTING.md)");
    let Ok(target) = std::env::var("BASTION_PAGEANT_TEST") else {
        return eprintln!("SKIPPED pageant_is_used_when_no_openssh_agent_runs: set BASTION_PAGEANT_TEST=<host>:<port>:<user>");
    };
    let parts: Vec<&str> = target.split(':').collect();
    let [host, port, user] = parts[..] else { panic!("BASTION_PAGEANT_TEST must be <host>:<port>:<user>") };
    assert!(
        tokio::net::windows::named_pipe::ClientOptions::new().open(r"\\.\pipe\openssh-ssh-agent").is_err(),
        "stop the OpenSSH agent service first, or it is used instead of Pageant"
    );
    let dir = tempfile::tempdir().unwrap();
    let p = SshParams {
        host: host.into(),
        port: port.parse().unwrap(),
        username: user.into(),
        ..params(dir.path().join("known_hosts"), user, SshAuth::Agent { socket: None })
    };
    let s = SshSession::connect(p).await.unwrap();
    assert_eq!(run(&s).await.trim(), format!("ok-{user}"));
}
