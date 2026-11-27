//! SSH client built on `russh`: strict host-key verification, password / private-key auth,
//! remote command execution and interactive PTY shells.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::{self, HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, Disconnect};

use crate::error::{CoreError, Result};
use crate::vault::Secret;

/// What to do with a server key that is not yet in known_hosts.
/// A key that *differs* from the recorded one is always rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Refuse unknown hosts; the UI shows the fingerprint and asks the user to trust it.
    Strict,
    /// Record any unknown key on first use. Test fixtures only (SEC-07): the variant exists
    /// only under the `test-accept-new` feature, which no app build enables, so the product
    /// cannot trust a key the user did not confirm.
    #[cfg(feature = "test-accept-new")]
    AcceptNew,
    /// Record an unknown key only if its SHA-256 fingerprint equals the one the user confirmed
    /// out of band; any other unknown key is refused like `Strict`.
    TrustFingerprint(String),
}

pub enum SshAuth {
    /// Password authentication, falling back to keyboard-interactive when the server only offers
    /// that (hidden prompts get the password). A prompt for anything else fails with
    /// `TwoFactorRequired` so the caller can ask for a code and retry with `PasswordAndCode`.
    Password(Secret),
    /// Keyboard-interactive with a second factor: password prompts get `password`, code prompts
    /// (verification code, OTP, token, PIN) get `code`.
    PasswordAndCode { password: Secret, code: Secret },
    KeyFile { path: PathBuf, passphrase: Option<Secret> },
    KeyPem { pem: Secret, passphrase: Option<Secret> },
    /// Keys held by an SSH agent: `socket`, else `SSH_AUTH_SOCK`. Private keys never enter
    /// Bastion; each identity the agent lists is offered in turn.
    Agent { socket: Option<PathBuf> },
}

pub struct SshParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    pub known_hosts: PathBuf,
    pub policy: HostKeyPolicy,
    pub connect_timeout: Duration,
    pub keepalive: Option<Duration>,
    /// Answers keyboard-interactive questions (one-time codes, PAM prompts) as they come; `None`
    /// keeps the `TwoFactorRequired` / `PasswordAndCode` round trip.
    pub prompter: Option<Arc<dyn crate::ssh_auth::KbdPrompter>>,
    /// Algorithm lists to offer (`ResolvedAlgorithms::default()` is russh's safe set).
    pub algorithms: crate::algorithms::ResolvedAlgorithms,
}

/// Most bytes [`SshSession::exec`] keeps of each of stdout and stderr; the rest is read and
/// discarded so a flooding command (or server) cannot exhaust memory.
pub const EXEC_OUTPUT_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<u32>,
    /// Output beyond [`EXEC_OUTPUT_LIMIT`] was dropped from stdout or stderr.
    pub truncated: bool,
}

/// Append at most up to `EXEC_OUTPUT_LIMIT`; returns whether anything was dropped.
fn append_capped(buf: &mut Vec<u8>, data: &[u8]) -> bool {
    let room = EXEC_OUTPUT_LIMIT.saturating_sub(buf.len());
    buf.extend_from_slice(&data[..data.len().min(room)]);
    data.len() > room
}

#[derive(Debug, Clone)]
enum HostKeyIssue {
    Unknown(String),
    Changed(usize),
    Unsupported(String),
}

pub(crate) struct Verifier {
    host: String,
    port: u16,
    known_hosts: PathBuf,
    policy: HostKeyPolicy,
    issue: Arc<Mutex<Option<HostKeyIssue>>>,
    /// Remote-forward table: server-side bound port → local (host, port) to connect to.
    forwards: RemoteForwards,
}

type RemoteForwards = Arc<Mutex<HashMap<u32, (String, u16)>>>;

impl Verifier {
    fn record(&self, issue: HostKeyIssue) -> bool {
        if let Ok(mut slot) = self.issue.lock() {
            *slot = Some(issue);
        }
        false
    }

    fn unknown(&self, key: &PublicKey) -> std::result::Result<bool, russh::Error> {
        match &self.policy {
            #[cfg(feature = "test-accept-new")]
            HostKeyPolicy::AcceptNew => {
                keys::known_hosts::learn_known_hosts_path(&self.host, self.port, key, &self.known_hosts)?;
                Ok(true)
            }
            HostKeyPolicy::TrustFingerprint(fp) if *fp == fingerprint(key) => {
                keys::known_hosts::learn_known_hosts_path(&self.host, self.port, key, &self.known_hosts)?;
                Ok(true)
            }
            HostKeyPolicy::Strict | HostKeyPolicy::TrustFingerprint(_) => Ok(self.record(HostKeyIssue::Unknown(fingerprint(key)))),
        }
    }

    fn verify(&self, key: &PublicKey) -> std::result::Result<bool, russh::Error> {
        // `@revoked` overrides an ordinary known_hosts entry, trust-on-first-use and a
        // fingerprint the user trusted; russh's own lookup does not read those lines.
        if crate::hostcert::authorities_in(&self.known_hosts, &self.host, self.port).revokes(key.key_data()) {
            return Ok(self.record(HostKeyIssue::Unsupported("the host key is marked @revoked in known_hosts".into())));
        }
        match keys::check_known_hosts_path(&self.host, self.port, key, &self.known_hosts) {
            Ok(true) => Ok(true),
            Ok(false) => self.unknown(key),
            Err(keys::Error::KeyChanged { line }) => Ok(self.record(HostKeyIssue::Changed(line))),
            // A missing known_hosts file just means nothing is known yet.
            Err(keys::Error::IO(e)) if e.kind() == std::io::ErrorKind::NotFound => self.unknown(key),
            Err(e) => Err(e.into()),
        }
    }
}

impl client::Handler for Verifier {
    type Error = russh::Error;

    async fn check_server_key(&mut self, server_key: &PublicKeyOrCertificate) -> std::result::Result<bool, Self::Error> {
        match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => self.verify(key),
            // Certificates are only offered for hosts a @cert-authority line covers (see `connect`).
            PublicKeyOrCertificate::Certificate(cert) => {
                let auth = crate::hostcert::authorities_in(&self.known_hosts, &self.host, self.port);
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                match crate::hostcert::check(cert, &auth, &self.host, now) {
                    Ok(()) => Ok(true),
                    Err(why) => Ok(self.record(HostKeyIssue::Unsupported(format!("host certificate refused: {why}")))),
                }
            }
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        // Only ports this session explicitly requested are honoured; anything else is rejected
        // by dropping `reply`.
        let target = self.forwards.lock().ok().and_then(|m| m.get(&connected_port).cloned());
        let Some((host, port)) = target else { return Ok(()) };
        reply.accept().await;
        tokio::spawn(async move {
            if let Ok(mut local) = tokio::net::TcpStream::connect((host.as_str(), port)).await {
                let mut remote = channel.into_stream();
                let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
            }
        });
        Ok(())
    }
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

pub struct SshSession {
    handle: Handle<Verifier>,
    forwards: RemoteForwards,
    /// Jump-host sessions this session is tunnelled through; kept alive for its lifetime.
    _jumps: Vec<SshSession>,
    /// `user@host:port`, the key under which SFTP remembers upload temp files across reconnects.
    pub(crate) peer: String,
}

/// How long authentication may take when a prompter can wait on a person (an MFA code, a
/// keyboard-interactive answer). Server-only authentication uses the connect timeout.
pub const INTERACTIVE_AUTH_TIMEOUT: Duration = Duration::from_secs(5 * 60);

impl SshSession {
    pub async fn connect(p: SshParams) -> Result<SshSession> {
        Self::connect_via(Vec::new(), p).await
    }

    /// Connect through a chain of jump hosts (ProxyJump semantics: first entry is dialled
    /// directly, each later hop is reached through a direct-tcpip channel of the previous one).
    /// Every hop does its own host-key verification and authentication.
    pub async fn connect_via(jumps: Vec<SshParams>, target: SshParams) -> Result<SshSession> {
        let mut chain: Vec<SshSession> = Vec::new();
        let hops = jumps.len();
        for (i, hop) in jumps.into_iter().chain(std::iter::once(target)).enumerate() {
            let name = format!("{}:{}", hop.host, hop.port);
            let connected = match chain.last() {
                None => Self::connect_hop(hop, None).await,
                Some(prev) => {
                    // The jump host's channel-open reply is a server-controlled wait too: bounded
                    // by this hop's connect budget, before its own handshake timer starts (PR-01).
                    let ch = tokio::time::timeout(hop.connect_timeout, prev.open_direct_tcpip(&hop.host, hop.port)).await.map_err(|_| CoreError::Timeout)??;
                    Self::connect_hop(hop, Some(ch)).await
                }
            };
            // Say which jump host needs trusting; the final target keeps the plain error.
            let session = match connected {
                Err(CoreError::HostKeyUnknown { fingerprint }) if i < hops => return Err(CoreError::JumpHostKeyUnknown { hop: name, fingerprint }),
                other => other?,
            };
            chain.push(session);
        }
        let mut last = chain.pop().ok_or_else(|| CoreError::Invalid("empty hop chain".into()))?;
        last._jumps = chain;
        Ok(last)
    }

    /// Reach `target` through `jumps` (which log in as usual) and stop after the target's key
    /// exchange: its host key is checked against `target.policy` and no authentication request
    /// is sent to it (`target.username` and `target.auth` are not used). Test Connection uses
    /// this when there is nothing to log in with.
    pub async fn check_host_key_via(mut jumps: Vec<SshParams>, target: SshParams) -> Result<()> {
        let via = match jumps.pop() {
            None => None,
            Some(last) => {
                let hop = format!("{}:{}", last.host, last.port);
                match Self::connect_via(jumps, last).await {
                    Err(CoreError::HostKeyUnknown { fingerprint }) => return Err(CoreError::JumpHostKeyUnknown { hop, fingerprint }),
                    other => Some(other?),
                }
            }
        };
        let channel = match &via {
            None => None,
            Some(prev) => Some(tokio::time::timeout(target.connect_timeout, prev.open_direct_tcpip(&target.host, target.port)).await.map_err(|_| CoreError::Timeout)??),
        };
        let (handle, _) = Self::handshake(&target, channel).await?;
        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
        Ok(())
    }

    async fn connect_hop(p: SshParams, via: Option<Channel<client::Msg>>) -> Result<SshSession> {
        let (mut handle, forwards) = Self::handshake(&p, via).await?;
        // An interactive prompter, key certificates and the cross-platform agent (OpenSSH agent,
        // Pageant) go through `ssh_auth`; the two-step code flow and agent sockets stay here.
        let sha1 = p.algorithms.allows_rsa_sha1();
        // Authentication waits on the server, so it has a deadline of its own (PR-01): the
        // connect budget when nothing asks the user, or the explicit, longer interactive budget
        // when a prompter may wait on a person (MFA code, keyboard-interactive). On timeout the
        // handle is dropped, which closes the connection.
        let peer = format!("{}@{}:{}", p.username, p.host, p.port);
        let budget = if p.prompter.is_some() { INTERACTIVE_AUTH_TIMEOUT } else { p.connect_timeout };
        let auth = async {
            match (&p.auth, &p.prompter) {
                (SshAuth::PasswordAndCode { .. }, _) | (SshAuth::Agent { socket: Some(_) }, _) | (SshAuth::Password(_), None) => {
                    authenticate(&mut handle, &p.username, p.auth, sha1).await
                }
                _ => crate::ssh_auth::authenticate(&mut handle, &p.username, p.auth, p.prompter, sha1).await,
            }
        };
        tokio::time::timeout(budget, auth).await.map_err(|_| CoreError::Timeout)??;
        Ok(SshSession { handle, forwards, _jumps: Vec::new(), peer })
    }

    /// Key exchange with one hop: the server's host key is checked against `p.policy`. Nothing
    /// is sent to log in.
    async fn handshake(p: &SshParams, via: Option<Channel<client::Msg>>) -> Result<(Handle<Verifier>, RemoteForwards)> {
        let issue = Arc::new(Mutex::new(None));
        let forwards: RemoteForwards = Arc::default();
        let verifier = Verifier {
            host: p.host.clone(),
            port: p.port,
            known_hosts: p.known_hosts.clone(),
            policy: p.policy.clone(),
            issue: issue.clone(),
            forwards: forwards.clone(),
        };
        let mut config = client::Config { keepalive_interval: p.keepalive, keepalive_max: crate::session::KEEPALIVE_MAX_MISSED, preferred: p.algorithms.preferred(), ..Default::default() };
        // Ask for a host certificate only where a trusted CA could vouch for it; elsewhere the
        // server proves itself with its plain key against known_hosts as before.
        if !crate::hostcert::authorities_in(&p.known_hosts, &p.host, p.port).cas.is_empty() {
            config.preferred.host_key_certificates = config.preferred.key.clone();
        }
        let config = Arc::new(config);
        if via.is_none() {
            crate::offline::check_host(&p.host, p.port)?;
        }
        let connected = match via {
            None => tokio::time::timeout(p.connect_timeout, client::connect(config, (p.host.as_str(), p.port), verifier)).await,
            Some(ch) => tokio::time::timeout(p.connect_timeout, client::connect_stream(config, ch.into_stream(), verifier)).await,
        };
        match connected {
            Err(_) => Err(CoreError::Timeout),
            Ok(Ok(handle)) => Ok((handle, forwards)),
            Ok(Err(russh::Error::NoCommonAlgo { kind, theirs, .. })) => Err(crate::algorithms::explain_no_common(kind, theirs)),
            Ok(Err(e)) => Err(host_key_error(&issue).unwrap_or_else(|| ssh_err(e))),
        }
    }

    /// Open a direct-tcpip channel to `host:port` as seen from the SSH server.
    pub async fn open_direct_tcpip(&self, host: &str, port: u16) -> Result<Channel<client::Msg>> {
        self.handle
            .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
            .await
            .map_err(|e| CoreError::Ssh(format!("cannot open channel to {host}:{port}: {e}")))
    }

    /// Ask the server to listen on `bind_addr:remote_port` and forward connections to
    /// `local_host:local_port` on this machine. Returns the port the server actually bound.
    pub async fn remote_forward(&self, bind_addr: &str, remote_port: u16, local_host: &str, local_port: u16) -> Result<u16> {
        // Binding a wildcard address on the server would publish a local service to its network.
        if !matches!(bind_addr, "127.0.0.1" | "::1" | "localhost") {
            return Err(CoreError::Invalid("remote forward must bind a loopback address on the server".into()));
        }
        let bound = self.handle.tcpip_forward(bind_addr, remote_port as u32).await.map_err(ssh_err)?;
        let bound = if bound == 0 { remote_port as u32 } else { bound };
        if let Ok(mut m) = self.forwards.lock() {
            m.insert(bound, (local_host.to_string(), local_port));
        }
        Ok(bound as u16)
    }

    pub async fn cancel_remote_forward(&self, bind_addr: &str, port: u16) -> Result<()> {
        if let Ok(mut m) = self.forwards.lock() {
            m.remove(&(port as u32));
        }
        self.handle.cancel_tcpip_forward(bind_addr, port as u32).await.map_err(ssh_err)
    }

    /// A fresh session channel (for subsystems such as SFTP).
    pub(crate) async fn channel_session(&self) -> Result<Channel<client::Msg>> {
        self.handle.channel_open_session().await.map_err(ssh_err)
    }

    /// Run one command and collect its output and exit status.
    pub async fn exec(&self, command: &str) -> Result<ExecOutput> {
        let mut channel = self.handle.channel_open_session().await.map_err(ssh_err)?;
        channel.exec(true, command).await.map_err(ssh_err)?;
        let mut out = ExecOutput::default();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.truncated |= append_capped(&mut out.stdout, &data),
                ChannelMsg::ExtendedData { data, .. } => out.truncated |= append_capped(&mut out.stderr, &data),
                ChannelMsg::ExitStatus { exit_status } => out.exit_status = Some(exit_status),
                _ => {}
            }
        }
        Ok(out)
    }

    /// A channel running `command` with its stdin and stdout open (SCP, which talks over them).
    pub async fn open_exec(&self, command: &str) -> Result<Channel<client::Msg>> {
        let channel = self.handle.channel_open_session().await.map_err(ssh_err)?;
        channel.exec(true, command).await.map_err(ssh_err)?;
        Ok(channel)
    }

    /// Open an interactive shell with a PTY. The caller drives the returned channel:
    /// `data()` to send keystrokes, `wait()` for output, `window_change()` on resize.
    pub async fn open_shell(&self, term: &str, cols: u32, rows: u32) -> Result<Channel<client::Msg>> {
        let channel = self.handle.channel_open_session().await.map_err(ssh_err)?;
        channel.request_pty(true, term, cols, rows, 0, 0, &[]).await.map_err(ssh_err)?;
        channel.request_shell(true).await.map_err(ssh_err)?;
        Ok(channel)
    }

    /// Like [`Self::open_shell`], but run `command` (tmux attach, `remoteshell::tmux_command`) in
    /// the PTY instead of the login shell when one is given.
    pub async fn open_terminal(&self, term: &str, cols: u32, rows: u32, command: Option<&str>) -> Result<Channel<client::Msg>> {
        let Some(command) = command else { return self.open_shell(term, cols, rows).await };
        let channel = self.handle.channel_open_session().await.map_err(ssh_err)?;
        channel.request_pty(true, term, cols, rows, 0, 0, &[]).await.map_err(ssh_err)?;
        channel.exec(true, command).await.map_err(ssh_err)?;
        Ok(channel)
    }

    /// True once the connection is gone (network drop, server restart, disconnect).
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.handle.disconnect(Disconnect::ByApplication, "", "en").await.map_err(ssh_err)
    }
}

async fn authenticate(handle: &mut Handle<Verifier>, user: &str, auth: SshAuth, sha1: bool) -> Result<()> {
    let result = match auth {
        SshAuth::Password(pw) => {
            let r = handle.authenticate_password(user, pw.expose()).await.map_err(ssh_err)?;
            if r.success() {
                return Ok(());
            }
            // Servers with PAM-only logins accept the password through keyboard-interactive.
            return keyboard_interactive(handle, user, &pw, None).await;
        }
        SshAuth::PasswordAndCode { password, code } => return keyboard_interactive(handle, user, &password, Some(&code)).await,
        SshAuth::Agent { socket } => return agent(handle, user, socket, sha1).await,
        SshAuth::KeyFile { path, passphrase } => {
            let key = keys::load_secret_key(&path, passphrase.as_ref().map(Secret::expose))
                .map_err(|e| CoreError::Invalid(format!("cannot load key {}: {e}", path.display())))?;
            publickey(handle, user, key, sha1).await
        }
        SshAuth::KeyPem { pem, passphrase } => {
            let key = keys::decode_secret_key(pem.expose(), passphrase.as_ref().map(Secret::expose))
                .map_err(|e| CoreError::Invalid(format!("cannot decode key: {e}")))?;
            publickey(handle, user, key, sha1).await
        }
    };
    if result.map_err(ssh_err)?.success() {
        Ok(())
    } else {
        Err(CoreError::AuthFailed)
    }
}

async fn publickey(
    handle: &mut Handle<Verifier>,
    user: &str,
    key: keys::PrivateKey,
    sha1: bool,
) -> std::result::Result<client::AuthResult, russh::Error> {
    let hash = crate::ssh_auth::rsa_hash(handle, sha1).await?;
    handle.authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash)).await
}

/// What a keyboard-interactive prompt asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    Password,
    /// A one-time or second-factor value.
    Code,
}

/// Classify a server prompt. Visible (echo) prompts and prompts naming a code, token, OTP, PIN or
/// verification are second-factor prompts; other hidden prompts are the password.
pub fn classify_prompt(prompt: &str, echo: bool) -> PromptKind {
    let p = prompt.to_ascii_lowercase();
    let code_words = ["code", "token", "otp", "one-time", "one time", "verification", "pin", "authenticator", "passcode", "2fa", "mfa"];
    if p.contains("password") && !p.contains("one-time") && !p.contains("one time") {
        return PromptKind::Password;
    }
    if echo || code_words.iter().any(|w| p.contains(w)) {
        PromptKind::Code
    } else {
        PromptKind::Password
    }
}

/// Bound on info-request rounds, so a hostile server cannot keep us answering forever.
const MAX_KBD_ROUNDS: usize = 8;

async fn keyboard_interactive(handle: &mut Handle<Verifier>, user: &str, password: &Secret, code: Option<&Secret>) -> Result<()> {
    use client::KeyboardInteractiveAuthResponse as R;
    let mut reply = handle.authenticate_keyboard_interactive_start(user, None).await.map_err(ssh_err)?;
    // A code is sent at most once: a server asking again means it was wrong.
    let mut code_used = false;
    for _ in 0..MAX_KBD_ROUNDS {
        match reply {
            R::Success => return Ok(()),
            R::Failure { .. } => return Err(if code_used { CoreError::TwoFactorRequired } else { CoreError::AuthFailed }),
            R::InfoRequest { prompts, .. } => {
                let mut answers = Vec::with_capacity(prompts.len());
                for p in &prompts {
                    match classify_prompt(&p.prompt, p.echo) {
                        PromptKind::Password => answers.push(password.expose().to_string()),
                        PromptKind::Code => match code {
                            Some(c) if !code_used => answers.push(c.expose().to_string()),
                            _ => return Err(CoreError::TwoFactorRequired),
                        },
                    }
                }
                if prompts.iter().any(|p| classify_prompt(&p.prompt, p.echo) == PromptKind::Code) {
                    code_used = true;
                }
                reply = handle.authenticate_keyboard_interactive_respond(answers).await.map_err(ssh_err)?;
            }
        }
    }
    Err(CoreError::AuthFailed)
}

async fn agent(handle: &mut Handle<Verifier>, user: &str, socket: Option<PathBuf>, sha1: bool) -> Result<()> {
    let unavailable = |e: keys::Error| CoreError::Invalid(format!("SSH agent is not available: {e}"));
    // An explicit agent (IdentityAgent) is a Unix socket, or on Windows a named pipe path; the
    // default is SSH_AUTH_SOCK, or on Windows the OpenSSH agent pipe and then Pageant.
    let mut client = match socket {
        #[cfg(unix)]
        Some(path) => keys::agent::client::AgentClient::connect_uds(&path).await.map_err(unavailable)?.dynamic(),
        #[cfg(windows)]
        Some(path) => keys::agent::client::AgentClient::connect_named_pipe(&path).await.map_err(unavailable)?.dynamic(),
        None => crate::ssh_auth::agent_client().await?,
    };
    let identities = client.request_identities().await.map_err(unavailable)?;
    if identities.is_empty() {
        return Err(CoreError::Invalid("the SSH agent holds no keys; add one with ssh-add".into()));
    }
    let hash = crate::ssh_auth::rsa_hash(handle, sha1).await.map_err(ssh_err)?;
    for id in identities {
        let key = id.public_key().into_owned();
        match handle.authenticate_publickey_with(user, key, hash, &mut client).await {
            Ok(r) if r.success() => return Ok(()),
            Ok(_) => continue,
            Err(e) => return Err(CoreError::Ssh(format!("SSH agent signing failed: {e}"))),
        }
    }
    Err(CoreError::AuthFailed)
}

fn host_key_error(issue: &Mutex<Option<HostKeyIssue>>) -> Option<CoreError> {
    let issue = issue.lock().ok()?.clone()?;
    Some(match issue {
        HostKeyIssue::Unknown(fp) => CoreError::HostKeyUnknown { fingerprint: fp },
        HostKeyIssue::Changed(line) => CoreError::HostKeyChanged { line },
        HostKeyIssue::Unsupported(msg) => CoreError::Ssh(msg),
    })
}

fn ssh_err(e: russh::Error) -> CoreError {
    CoreError::Ssh(e.to_string())
}

#[cfg(test)]
#[path = "ssh_tests.rs"]
mod tests;
