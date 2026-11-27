//! Test Connection: check everything a connection dialog holds, end to end, without saving
//! anything. Steps run in order (DNS, TCP, handshake, host key, jump hosts, login) and stop at
//! the first failure, which carries the exact problem and how to fix it.
//!
//! Nothing is trusted or written, and no secret goes to a host nobody confirmed (SEC-07):
//! - a CHANGED key stops the test;
//! - with a NEW key, a password login is not sent. The report carries the fingerprint in
//!   `needs_host_key_confirmation`, and only a second test with that exact fingerprint in
//!   `ProbeRequest::trusted_fingerprint` (the user's yes) tries the login. A key or agent login
//!   is still tried: it sends a signature, not a secret;
//! - a NEW key is learned into a throwaway copy of known_hosts only, never the real file;
//! - with nothing to log in with, the host key is checked by key exchange alone;
//! - a jump host with a NEW or CHANGED key fails before its login.
//!
//! Secrets arrive in `SshAuth` (held in memory only, zeroized on drop) and never appear in a
//! step's text.
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::audit::Outcome;
use crate::error::CoreError;
use crate::model::Protocol;
use crate::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use crate::vault::Secret;

/// How many TCP connects the latency figure is the best of.
const TCP_TRIES: usize = 3;
/// Longest banner line read during the handshake.
const BANNER_MAX: usize = 255;
const NEW_KEY_FIX: &str = "Compare it with the server administrator's copy; you will be asked to trust it on first connect.";
const NEEDS_CONFIRMATION: &str = "Not tested: confirm the host key first";
const CHANGED_KEY_FIX: &str = "Do not connect. Ask the administrator whether the server was reinstalled; if so, remove the old key and verify the new one.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    Dns,
    Tcp,
    Handshake,
    HostKey,
    JumpHost,
    Login,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Ok,
    /// Passed, with something the user should know (a NEW host key).
    Warn,
    Failed,
    /// Not run: it does not apply, or nothing was entered for it.
    Skipped,
}

/// Why the target's `host_key` step failed. The apps show a different message for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyFailure {
    /// A known host showed another key: do not connect.
    Changed,
    /// known_hosts could not be read: a local file problem, nothing learnt about the server.
    KnownHostsUnreadable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeStep {
    pub kind: StepKind,
    pub status: StepStatus,
    /// What happened, in plain words ("Port 22 refused on 10.0.0.5 (nothing listening)").
    pub detail: String,
    /// What to do about it; set on failures and warnings.
    pub fix: Option<String>,
    pub millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeReport {
    pub ok: bool,
    pub steps: Vec<ProbeStep>,
    /// Set when the test stopped before the login because the target's host key is not in
    /// known_hosts and the login would send a password: the SHA-256 fingerprint the server
    /// presented. The app shows it; only the user's yes (a second test carrying it in
    /// `ProbeRequest::trusted_fingerprint`) lets the login be tried.
    pub needs_host_key_confirmation: Option<String>,
    /// Set when the target's `host_key` step failed, saying which of the two cases it was.
    pub host_key_failure: Option<HostKeyFailure>,
}

impl ProbeReport {
    /// The audit outcome: a test that stopped to wait for the host key proved nothing.
    pub fn audit_outcome(&self) -> Outcome {
        if self.ok && self.needs_host_key_confirmation.is_none() { Outcome::Success } else { Outcome::Failure }
    }

    /// The result for the audit log: never a secret (step texts hold none).
    pub fn summary(&self) -> String {
        match self.steps.iter().find(|s| s.status == StepStatus::Failed) {
            None if self.needs_host_key_confirmation.is_some() => "stopped before login: host key not confirmed".into(),
            None => "ok".into(),
            Some(s) => format!("{:?} failed: {}", s.kind, s.detail),
        }
    }
}

/// A jump host the target is reached through, with its own login.
pub struct ProbeHop {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
}

pub struct ProbeRequest {
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// The login to try; `None` skips the login step (no credential entered).
    pub auth: Option<SshAuth>,
    pub jumps: Vec<ProbeHop>,
    pub known_hosts: PathBuf,
    pub timeout: Duration,
    /// The fingerprint the user confirmed for this test (from an earlier report's
    /// `needs_host_key_confirmation`). Used for this test only: nothing is stored.
    pub trusted_fingerprint: Option<String>,
}

/// The steps so far, the fingerprint waiting for the user's yes, and why the target's host-key
/// step failed (see `ProbeReport`).
#[derive(Default)]
struct Steps(Vec<ProbeStep>, Option<String>, Option<HostKeyFailure>);

impl Steps {
    fn push(&mut self, kind: StepKind, status: StepStatus, detail: impl Into<String>, fix: Option<&str>, started: Instant) {
        let millis = started.elapsed().as_millis() as u64;
        self.0.push(ProbeStep { kind, status, detail: detail.into(), fix: fix.map(str::to_string), millis });
    }
    fn fail(&mut self, kind: StepKind, detail: impl Into<String>, fix: &str, started: Instant) {
        self.push(kind, StepStatus::Failed, detail, Some(fix), started);
    }
    fn skip(&mut self, kind: StepKind, detail: &str) {
        self.0.push(ProbeStep { kind, status: StepStatus::Skipped, detail: detail.into(), fix: None, millis: 0 });
    }
    fn new_key(&mut self, fingerprint: &str, started: Instant) {
        self.push(StepKind::HostKey, StepStatus::Warn, format!("NEW host key {fingerprint}"), Some(NEW_KEY_FIX), started);
    }
    fn changed_key(&mut self, line: usize, started: Instant) {
        self.fail(StepKind::HostKey, format!("Host key CHANGED since last connect (known_hosts line {line})"), CHANGED_KEY_FIX, started);
        self.2 = Some(HostKeyFailure::Changed);
    }
    fn known_hosts_unreadable(&mut self, e: &std::io::Error, started: Instant) {
        self.fail(StepKind::HostKey, format!("Cannot read known_hosts: {e}"), "Check the file's permissions.", started);
        self.2 = Some(HostKeyFailure::KnownHostsUnreadable);
    }
}

/// Run the whole test. Cancel by dropping the future (the FFI and C ABI abort its task).
pub async fn run(req: ProbeRequest) -> ProbeReport {
    let mut steps = Steps::default();
    if req.host.trim().is_empty() {
        steps.fail(StepKind::Dns, "No host name entered", "Type the server's name or IP address in Host.", Instant::now());
    } else if !req.jumps.is_empty() {
        if is_ssh(req.protocol) {
            run_via_jumps(&req, &mut steps).await;
        } else {
            steps.fail(StepKind::JumpHost, "Jump hosts only carry SSH, SFTP and SCP", "Remove the jump host, or route through an SSH gateway.", Instant::now());
        }
    } else {
        run_direct(&req, &mut steps).await;
    }
    let ok = !steps.0.iter().any(|s| s.status == StepStatus::Failed);
    ProbeReport { ok, steps: steps.0, needs_host_key_confirmation: steps.1, host_key_failure: steps.2 }
}

fn is_ssh(p: Protocol) -> bool {
    matches!(p, Protocol::Ssh | Protocol::Sftp | Protocol::Scp)
}

async fn run_direct(req: &ProbeRequest, steps: &mut Steps) {
    let Some(addr) = dns(&req.host, req.port, steps).await else { return };
    if !tcp(addr, &req.host, req.port, req.timeout, steps).await {
        return;
    }
    match req.protocol {
        p if is_ssh(p) => {
            if banner(addr, req.timeout, "SSH-", steps).await {
                ssh_target(req, steps).await;
            }
        }
        Protocol::Vnc => {
            banner(addr, req.timeout, "RFB ", steps).await;
            steps.skip(StepKind::Login, "Login is checked when the viewer opens");
        }
        Protocol::Rdp => {
            rdp_handshake(addr, req.timeout, steps).await;
            steps.skip(StepKind::Login, "Login is checked when the session opens");
        }
        _ => {
            steps.skip(StepKind::Handshake, "Not checked for this protocol yet");
            steps.skip(StepKind::Login, "Not checked for this protocol yet");
        }
    }
}

async fn dns(host: &str, port: u16, steps: &mut Steps) -> Option<SocketAddr> {
    let started = Instant::now();
    if let Ok(ip) = host.parse::<IpAddr>() {
        steps.push(StepKind::Dns, StepStatus::Ok, format!("{ip} (IP address, no lookup needed)"), None, started);
        return Some(SocketAddr::new(ip, port));
    }
    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((host, port)).await {
        Ok(a) => a.collect(),
        Err(_) => Vec::new(),
    };
    let Some(first) = addrs.first().copied() else {
        steps.fail(StepKind::Dns, format!("Host '{host}' not found"), "Check the spelling, your DNS or VPN, or use the IP address instead.", started);
        return None;
    };
    let list = addrs.iter().map(|a| a.ip().to_string()).collect::<Vec<_>>().join(", ");
    steps.push(StepKind::Dns, StepStatus::Ok, format!("{host} → {list}"), None, started);
    Some(first)
}

async fn tcp(addr: SocketAddr, host: &str, port: u16, timeout: Duration, steps: &mut Steps) -> bool {
    let started = Instant::now();
    let mut best: Option<Duration> = None;
    for _ in 0..TCP_TRIES {
        let t = Instant::now();
        let failure = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                best = Some(best.map_or(t.elapsed(), |b| b.min(t.elapsed())));
                continue;
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => (
                format!("Port {port} refused on {} (nothing listening)", addr.ip()),
                "Check the port number and that the service is running on the server.",
            ),
            Ok(Err(e)) => (format!("Cannot reach {host}:{port}: {e}"), "Check the network route, VPN or firewall."),
            Err(_) => (
                format!("Timed out after {} s connecting to {}:{port}", timeout.as_secs(), addr.ip()),
                "A firewall is dropping the connection, or the IP is wrong.",
            ),
        };
        steps.fail(StepKind::Tcp, failure.0, failure.1, started);
        return false;
    }
    let ms = best.map_or(0.0, |b| b.as_secs_f64() * 1000.0);
    steps.push(StepKind::Tcp, StepStatus::Ok, format!("Port {port} open, {ms:.1} ms (best of {TCP_TRIES})"), None, started);
    true
}

/// Read the server's first line and check it starts with `expect` ("SSH-", "RFB ").
async fn banner(addr: SocketAddr, timeout: Duration, expect: &str, steps: &mut Steps) -> bool {
    let started = Instant::now();
    let read = async {
        let mut s = TcpStream::connect(addr).await?;
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while buf.len() < BANNER_MAX && s.read(&mut byte).await? == 1 && byte[0] != b'\n' {
            buf.push(byte[0]);
        }
        Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf).trim_end().to_string())
    };
    let what = expect.trim();
    let (detail, fix) = match tokio::time::timeout(timeout, read).await {
        Ok(Ok(line)) if line.starts_with(expect) => {
            steps.push(StepKind::Handshake, StepStatus::Ok, line, None, started);
            return true;
        }
        Ok(Ok(line)) if line.is_empty() => {
            (format!("The server closed the connection without a {what} greeting"), "Another service owns this port, or the server refused this client.")
        }
        Ok(Ok(line)) => {
            let shown: String = line.chars().take(60).collect();
            (format!("Not a {what} server: it answered '{shown}'"), "Check the port: another service is listening there.")
        }
        Ok(Err(e)) => (format!("Handshake failed: {e}"), "Try again; if it repeats, check the server's logs."),
        Err(_) => (format!("No {what} greeting within {} s", timeout.as_secs()), "Check the port: the service there does not speak first, or is hung."),
    };
    steps.fail(StepKind::Handshake, detail, fix, started);
    false
}

/// X.224 Connection Request asking for TLS and NLA; the confirm says which the server picked.
async fn rdp_handshake(addr: SocketAddr, timeout: Duration, steps: &mut Steps) {
    const REQUEST: [u8; 19] = [3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0];
    let started = Instant::now();
    let exchange = async {
        let mut s = TcpStream::connect(addr).await?;
        s.write_all(&REQUEST).await?;
        let mut buf = [0u8; 19];
        s.read_exact(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(Ok(b)) if b[0] == 3 && b[5] == 0xd0 && b[11] == 2 => {
            let what = match b[15] {
                0 => "standard RDP security (no TLS)",
                1 => "TLS",
                2 | 8 => "NLA (CredSSP)",
                _ => "an extended security mode",
            };
            steps.push(StepKind::Handshake, StepStatus::Ok, format!("RDP server, selected {what}"), None, started);
        }
        Ok(Ok(b)) if b[0] == 3 && b[5] == 0xd0 && b[11] == 3 => {
            steps.fail(StepKind::Handshake, "The RDP server refused TLS and NLA", "Check the server's RDP security layer setting.", started)
        }
        Ok(_) => steps.fail(StepKind::Handshake, "Not an RDP server on this port", "Check the port (RDP is usually 3389).", started),
        Err(_) => steps.fail(StepKind::Handshake, "No RDP answer in time", "Check the port: the service there does not speak RDP.", started),
    }
}

/// A private temp directory removed on drop, holding a copy of known_hosts so a NEW key can be
/// learned for this test only.
struct Scratch(PathBuf);

impl Scratch {
    fn copy_of(real: &Path) -> std::io::Result<Scratch> {
        let dir = std::env::temp_dir().join(format!("bastion-probe-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir)?;
        let scratch = Scratch(dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&scratch.0, std::fs::Permissions::from_mode(0o700))?;
        }
        match std::fs::copy(real, scratch.known_hosts()) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::write(scratch.known_hosts(), b"")?,
            Err(e) => return Err(e),
        }
        Ok(scratch)
    }
    fn known_hosts(&self) -> PathBuf {
        self.0.join("known_hosts")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn params(host: &str, port: u16, username: &str, auth: SshAuth, known_hosts: PathBuf, policy: HostKeyPolicy, timeout: Duration) -> SshParams {
    SshParams { host: host.into(), port, username: username.into(), auth, known_hosts, policy, connect_timeout: timeout, keepalive: None, prompter: None, algorithms: Default::default() }
}

/// Whether trying this login puts a secret on the wire. A key or agent login sends a signature
/// bound to the session; a passphrase only unlocks the key file locally.
fn sends_password(auth: &SshAuth) -> bool {
    matches!(auth, SshAuth::Password(_) | SshAuth::PasswordAndCode { .. })
}

/// Host key and login of the target, through the request's jump hosts (already tested).
async fn ssh_target(req: &ProbeRequest, steps: &mut Steps) {
    let started = Instant::now();
    let scratch = match Scratch::copy_of(&req.known_hosts) {
        Ok(s) => s,
        Err(e) => return steps.known_hosts_unreadable(&e, started),
    };
    let user = req.username.trim();
    let Some(auth) = req.auth.as_ref().filter(|_| !user.is_empty()) else {
        return target_key_only(req, &scratch, steps, started).await;
    };
    // Strict: an unknown or changed key ends this dial during key exchange, before any login.
    let target = params(&req.host, req.port, user, dup_auth(auth), scratch.known_hosts(), HostKeyPolicy::Strict, req.timeout);
    let mut result = SshSession::connect_via(jump_params(req, &scratch), target).await;
    let mut login_started = started;
    match &result {
        Err(CoreError::HostKeyUnknown { fingerprint }) => {
            steps.new_key(fingerprint, started);
            if sends_password(auth) && req.trusted_fingerprint.as_deref() != Some(fingerprint.as_str()) {
                steps.skip(StepKind::Login, NEEDS_CONFIRMATION);
                steps.1 = Some(fingerprint.clone());
                return;
            }
            // Learn the key into the scratch copy only, then try the login. A server that shows
            // another key on this dial is refused: only this fingerprint is trusted.
            login_started = Instant::now();
            let policy = HostKeyPolicy::TrustFingerprint(fingerprint.clone());
            let target = params(&req.host, req.port, user, dup_auth(auth), scratch.known_hosts(), policy, req.timeout);
            result = SshSession::connect_via(jump_params(req, &scratch), target).await;
        }
        Err(CoreError::HostKeyChanged { line }) => {
            steps.changed_key(*line, started);
            return steps.skip(StepKind::Login, "Stopped: the host key changed");
        }
        Err(CoreError::Timeout) | Err(CoreError::Ssh(_)) => {}
        _ => steps.push(StepKind::HostKey, StepStatus::Ok, "Host key matches known_hosts", None, started),
    }
    login_outcome(result, user, steps, login_started);
}

/// Nothing to log in with (no credential, or no user name): check the host key by key exchange
/// alone. No authentication request reaches the server, so the test leaves no failed login
/// there and cannot trip a lockout.
async fn target_key_only(req: &ProbeRequest, scratch: &Scratch, steps: &mut Steps, started: Instant) {
    let target = params(&req.host, req.port, "", SshAuth::Agent { socket: None }, scratch.known_hosts(), HostKeyPolicy::Strict, req.timeout);
    match SshSession::check_host_key_via(jump_params(req, scratch), target).await {
        Ok(()) => steps.push(StepKind::HostKey, StepStatus::Ok, "Host key matches known_hosts", None, started),
        Err(CoreError::HostKeyUnknown { fingerprint }) => steps.new_key(&fingerprint, started),
        Err(CoreError::HostKeyChanged { line }) => {
            steps.changed_key(line, started);
            return steps.skip(StepKind::Login, "Stopped: the host key changed");
        }
        // As before: with no login to try, a key exchange that did not finish adds no step.
        Err(_) => {}
    }
    no_login(req, steps);
}

fn no_login(req: &ProbeRequest, steps: &mut Steps) {
    if req.auth.is_none() {
        steps.skip(StepKind::Login, "No credential entered");
    } else {
        steps.fail(StepKind::Login, "No user name entered", "Fill in User, or pick a credential that has one.", Instant::now());
    }
}

fn disconnect(session: SshSession) {
    tokio::spawn(async move {
        let _ = session.disconnect().await;
    });
}

fn login_outcome(result: crate::error::Result<SshSession>, user: &str, steps: &mut Steps, started: Instant) {
    match result {
        Ok(session) => {
            steps.push(StepKind::Login, StepStatus::Ok, format!("Logged in as '{user}'"), None, started);
            disconnect(session);
        }
        Err(e) => {
            let (detail, fix) = explain_login(&e, user);
            steps.fail(StepKind::Login, detail, fix, started);
        }
    }
}

fn explain_login(e: &CoreError, user: &str) -> (String, &'static str) {
    match e {
        CoreError::AuthFailed => (format!("Password or key rejected for user '{user}'"), "Check the user name and the password or key."),
        CoreError::TwoFactorRequired => ("The server asks for a one-time code".into(), "Connect normally; Gantry asks for the code then."),
        CoreError::Timeout => ("Timed out during key exchange or login".into(), "The server is slow or overloaded; try again."),
        CoreError::Invalid(m) | CoreError::Ssh(m) if m.to_lowercase().contains("passphrase") || m.to_lowercase().contains("encrypted") => {
            ("The key file needs a passphrase, or the passphrase is wrong".into(), "Enter the key's passphrase in the password field.")
        }
        CoreError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => ("The key file does not exist".into(), "Pick the private key file again."),
        other => (format!("Login failed: {other}"), "Check the credential and the server's authentication settings."),
    }
}

/// Test each jump host in turn (its key and its own login), then the target through them.
async fn run_via_jumps(req: &ProbeRequest, steps: &mut Steps) {
    let first = &req.jumps[0];
    let Some(addr) = dns(&first.host, first.port, steps).await else { return };
    if !tcp(addr, &first.host, first.port, req.timeout, steps).await {
        return;
    }
    let scratch = match Scratch::copy_of(&req.known_hosts) {
        Ok(s) => s,
        Err(e) => return steps.fail(StepKind::JumpHost, format!("Cannot read known_hosts: {e}"), "Check the file's permissions.", Instant::now()),
    };
    // Bring the chain up one hop longer each time, so a failure names its hop.
    for n in 1..=req.jumps.len() {
        let started = Instant::now();
        let hop = &req.jumps[n - 1];
        let name = format!("{}:{}", hop.host, hop.port);
        let mut chain = jump_params(req, &scratch);
        chain.truncate(n);
        let Some(last) = chain.pop() else { return };
        match SshSession::connect_via(chain, last).await {
            Ok(s) => {
                steps.push(StepKind::JumpHost, StepStatus::Ok, format!("Jump host {name}: key known, logged in as '{}'", hop.username), None, started);
                disconnect(s);
            }
            Err(CoreError::HostKeyUnknown { fingerprint }) | Err(CoreError::JumpHostKeyUnknown { fingerprint, .. }) => {
                return steps.fail(
                    StepKind::JumpHost,
                    format!("Jump host {name}: NEW host key {fingerprint}"),
                    "Connect to the jump host once on its own and trust its key after verifying it.",
                    started,
                );
            }
            Err(CoreError::HostKeyChanged { line }) => {
                return steps.fail(StepKind::JumpHost, format!("Jump host {name}: host key CHANGED (known_hosts line {line})"), CHANGED_KEY_FIX, started);
            }
            Err(e) => {
                let (detail, fix) = explain_login(&e, &hop.username);
                return steps.fail(StepKind::JumpHost, format!("Jump host {name}: {detail}"), fix, started);
            }
        }
    }
    steps.skip(StepKind::Tcp, &format!("{}:{} is reached through the jump host", req.host, req.port));
    ssh_target(req, steps).await;
}

/// Fresh `SshParams` for every jump host: a dial consumes its auth.
fn jump_params(req: &ProbeRequest, scratch: &Scratch) -> Vec<SshParams> {
    req.jumps.iter().map(|h| params(&h.host, h.port, &h.username, dup_auth(&h.auth), scratch.known_hosts(), HostKeyPolicy::Strict, req.timeout)).collect()
}

/// `SshAuth` is not `Clone` (it owns secrets); copy it in memory for one more dial.
fn dup_auth(a: &SshAuth) -> SshAuth {
    let dup = |s: &Secret| Secret::new(s.expose());
    match a {
        SshAuth::Password(p) => SshAuth::Password(dup(p)),
        SshAuth::PasswordAndCode { password, code } => SshAuth::PasswordAndCode { password: dup(password), code: dup(code) },
        SshAuth::KeyFile { path, passphrase } => SshAuth::KeyFile { path: path.clone(), passphrase: passphrase.as_ref().map(dup) },
        SshAuth::KeyPem { pem, passphrase } => SshAuth::KeyPem { pem: dup(pem), passphrase: passphrase.as_ref().map(dup) },
        SshAuth::Agent { socket } => SshAuth::Agent { socket: socket.clone() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_password_logins_wait_for_the_host_key() {
        let secret = || Secret::new("x".to_string());
        assert!(sends_password(&SshAuth::Password(secret())));
        assert!(sends_password(&SshAuth::PasswordAndCode { password: secret(), code: secret() }));
        assert!(!sends_password(&SshAuth::Agent { socket: None }));
        assert!(!sends_password(&SshAuth::KeyFile { path: PathBuf::from("id"), passphrase: Some(secret()) }));
        assert!(!sends_password(&SshAuth::KeyPem { pem: secret(), passphrase: None }));
    }

    #[test]
    fn the_audit_summary_says_the_login_was_not_tested() {
        let waiting = ProbeReport { ok: true, steps: Vec::new(), needs_host_key_confirmation: Some("SHA256:abc".into()), host_key_failure: None };
        assert_eq!(waiting.summary(), "stopped before login: host key not confirmed");
        let done = ProbeReport { ok: true, steps: Vec::new(), needs_host_key_confirmation: None, host_key_failure: None };
        assert_eq!(done.summary(), "ok");
    }

    fn report(ok: bool, waiting: bool) -> ProbeReport {
        ProbeReport { ok, steps: Vec::new(), needs_host_key_confirmation: waiting.then(|| "SHA256:abc".into()), host_key_failure: None }
    }

    #[test]
    fn a_test_waiting_for_the_host_key_is_not_a_success_in_the_audit_log() {
        assert_eq!(report(true, true).audit_outcome(), Outcome::Failure);
        assert_eq!(report(true, false).audit_outcome(), Outcome::Success);
        assert_eq!(report(false, false).audit_outcome(), Outcome::Failure);
    }

    #[test]
    fn a_changed_key_and_an_unreadable_known_hosts_are_told_apart() {
        let mut changed = Steps::default();
        changed.changed_key(7, Instant::now());
        assert_eq!(changed.2, Some(HostKeyFailure::Changed));
        let mut unreadable = Steps::default();
        unreadable.known_hosts_unreadable(&std::io::Error::other("denied"), Instant::now());
        assert_eq!(unreadable.2, Some(HostKeyFailure::KnownHostsUnreadable));
        assert_eq!((unreadable.0[0].kind, unreadable.0[0].status), (StepKind::HostKey, StepStatus::Failed));
        let mut fine = Steps::default();
        fine.new_key("SHA256:abc", Instant::now());
        assert_eq!(fine.2, None);
    }

    #[test]
    fn the_kind_is_named_in_snake_case() {
        assert_eq!(serde_json::to_value(HostKeyFailure::KnownHostsUnreadable).unwrap(), "known_hosts_unreadable");
        assert_eq!(serde_json::to_value(HostKeyFailure::Changed).unwrap(), "changed");
    }
}
