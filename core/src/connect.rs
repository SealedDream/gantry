//! SSH connect orchestrator: the one path the UI uses to open a session. It ties together
//! policy (protocol and customer isolation), the credential broker and providers, strict
//! host-key verification and the audit log.
//!
//! Host-key trust is always explicit: connections run with `HostKeyPolicy::Strict`, an unknown
//! key comes back as `CoreError::HostKeyUnknown { fingerprint }`, and only a follow-up call to
//! [`Orchestrator::connect_ssh_trusting`] with that exact fingerprint records it. Successful
//! authentication never causes a key to be trusted.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::activity::{self, ActivityLog, App, EndReason, FolderRef, LoginSource, SessionEnd, SessionId, SessionStart};
use crate::audit::{AuditLog, Category, Outcome};
use crate::broker::{Broker, LeaseKey};
use crate::error::{CoreError, Result};
use crate::model::Connection;
use crate::policy::Policy;
use crate::provider::CredentialProvider;
use crate::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use crate::vault::Secret;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretUse {
    Password,
    KeyPem,
    /// Private key on disk; the brokered secret is its passphrase.
    KeyFilePassphrase(PathBuf),
    /// Keys in an SSH agent (this socket, else `SSH_AUTH_SOCK`): no secret is brokered.
    Agent(Option<PathBuf>),
}

/// Where the secret for a connection lives. Never contains the secret itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRef {
    pub provider: String,
    pub item: String,
    /// Customer the credential belongs to.
    pub scope: Option<String>,
    pub username: String,
    pub usage: SecretUse,
}

impl CredentialRef {
    fn lease_key(&self) -> LeaseKey {
        LeaseKey { credential: format!("{}:{}", self.provider, self.item), scope: self.scope.clone() }
    }
}

/// Where the orchestrator records sessions (`activity`), with what it cannot know by itself.
/// It holds no secret.
#[derive(Clone)]
pub struct ActivitySink {
    pub log: Arc<ActivityLog>,
    /// The connection's folders, root first, as they are now.
    pub folder_path: Vec<FolderRef>,
    pub login_source: LoginSource,
    pub app: App,
    pub app_version: String,
    pub device_name: String,
}

/// The session a successful connect opened, until [`Orchestrator::session_ended`].
struct LiveSession {
    /// `None` when no activity sink is set (or its write failed).
    id: Option<SessionId>,
    target: String,
    connected_at: u64,
}

/// One connect attempt. Dropped before it finished (the caller gave up on the future), it
/// still ends the session it began, so no attempt stays open in the history.
struct Attempt<'a> {
    orchestrator: &'a Orchestrator,
    session: Option<SessionId>,
    finished: bool,
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        self.orchestrator.set_attempt(None);
        if !self.finished {
            self.orchestrator.activity_end(self.session, None, EndReason::Failed, None, None, None);
        }
    }
}

/// The end reason a failed connect is recorded with.
fn end_reason_for(e: &CoreError) -> EndReason {
    match e {
        CoreError::AuthFailed | CoreError::TwoFactorRequired => EndReason::AuthFailed,
        CoreError::HostKeyUnknown { .. } | CoreError::JumpHostKeyUnknown { .. } | CoreError::HostKeyChanged { .. } => EndReason::HostKey,
        CoreError::Timeout => EndReason::Timeout,
        CoreError::Offline(_) => EndReason::NetworkLost,
        CoreError::Cancelled => EndReason::ClosedByUser,
        _ => EndReason::Failed,
    }
}

pub struct Orchestrator {
    policy: Policy,
    broker: Arc<Broker>,
    providers: Vec<Arc<dyn CredentialProvider>>,
    audit: Mutex<AuditLog>,
    pub known_hosts: PathBuf,
    pub connect_timeout: Duration,
    /// A one-time second-factor code for the target's keyboard-interactive login. Used once,
    /// never brokered or stored.
    pub verification_code: Option<Secret>,
    /// Answers keyboard-interactive questions as the server asks them (instead of the
    /// `TwoFactorRequired` round trip with `verification_code`).
    pub prompter: Option<Arc<dyn crate::ssh_auth::KbdPrompter>>,
    /// When set, every connect attempt is recorded in the activity store, and the audit
    /// records of the attempt carry its session id as correlation id.
    pub activity: Option<ActivitySink>,
    /// The session id of the connect attempt in progress. An orchestrator makes one connect at
    /// a time and owns one session (the bridges build one per connect): do not share it across
    /// concurrent connects, or the second overwrites `attempt` and `live` and the first
    /// session never gets its end.
    attempt: Mutex<Option<SessionId>>,
    live: Mutex<Option<LiveSession>>,
}

impl Orchestrator {
    pub fn new(policy: Policy, broker: Arc<Broker>, providers: Vec<Arc<dyn CredentialProvider>>, audit: AuditLog, known_hosts: PathBuf) -> Self {
        Orchestrator {
            policy,
            broker,
            providers,
            audit: Mutex::new(audit),
            known_hosts,
            connect_timeout: Duration::from_secs(15),
            verification_code: None,
            prompter: None,
            activity: None,
            attempt: Mutex::new(None),
            live: Mutex::new(None),
        }
    }

    pub fn broker(&self) -> &Broker {
        &self.broker
    }

    fn record(&self, category: Category, action: &str, conn: &Connection, outcome: Outcome, details: &[(&str, String)]) {
        let correlation = self.attempt.lock().ok().and_then(|a| *a);
        self.audit(category, action, &conn.name, outcome, details, correlation);
    }

    fn audit(&self, category: Category, action: &str, target: &str, outcome: Outcome, details: &[(&str, String)], correlation: Option<SessionId>) {
        let details: BTreeMap<String, String> = details.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        // Audit failures must not be silent, but they must not block an operator either: they
        // surface on stderr until the UI has a security-warning channel.
        if let Ok(mut log) = self.audit.lock() {
            if let Err(e) = log.record_correlated(category, action, Some(target), outcome, details, correlation) {
                eprintln!("bastion: audit log write failed: {e}");
            }
        }
    }

    /// Wait, off the async runtime's workers, for the full audit-log check the log's open let run behind it.
    async fn audit_checked(&self) -> Result<()> {
        let Some(path) = self.audit.lock().ok().and_then(|l| l.pending_check()) else { return Ok(()) };
        tokio::task::spawn_blocking(move || crate::audit::await_check(&path))
            .await
            .map_err(|e| CoreError::Corrupt(format!("audit log check did not finish: {e}")))??;
        Ok(())
    }

    fn set_attempt(&self, session: Option<SessionId>) {
        if let Ok(mut attempt) = self.attempt.lock() {
            *attempt = session;
        }
    }

    /// Write the start of a session for this attempt. Like the audit log, a failed write is
    /// reported on stderr and never blocks the connect.
    fn activity_begin(&self, jumps: &[JumpHop], conn: &Connection, cred: &CredentialRef) -> Option<SessionId> {
        let sink = self.activity.as_ref()?;
        let start = SessionStart {
            connection_id: conn.id,
            connection_name: conn.name.clone(),
            folder_path: sink.folder_path.clone(),
            protocol: conn.protocol.as_str().into(),
            host: conn.host.clone(),
            port: Some(conn.settings.port.unwrap_or(22)),
            username: Some(cred.username.clone()),
            route: jumps.iter().map(|j| j.conn.name.clone()).collect(),
            login_source: sink.login_source,
            started_at: activity::now_ms(),
            app: sink.app,
            app_version: sink.app_version.clone(),
            device_name: sink.device_name.clone(),
        };
        sink.log.begin(start).map_err(|e| eprintln!("bastion: activity log write failed: {e}")).ok()
    }

    fn activity_end(&self, session: Option<SessionId>, connected_at: Option<u64>, reason: EndReason, reconnects: Option<u32>, transcript_path: Option<String>, transcript_sha256: Option<String>) {
        let (Some(sink), Some(session)) = (&self.activity, session) else { return };
        let end = SessionEnd { connected_at, ended_at: activity::now_ms(), end_reason: reason, reconnects, transcript_path, transcript_sha256 };
        if let Err(e) = sink.log.end(session, end) {
            eprintln!("bastion: activity log write failed: {e}");
        }
    }

    /// The activity session id of the session the last successful connect opened, until
    /// [`Orchestrator::session_ended`]. `None` without an activity sink.
    pub fn activity_session(&self) -> Option<SessionId> {
        self.live.lock().ok().and_then(|live| live.as_ref().and_then(|l| l.id))
    }

    /// Tell the orchestrator that the session it connected has ended. The orchestrator hands
    /// the `SshSession` to its caller and does not see it close, so the owner of the session
    /// calls this once: it writes the activity `session_end` and the audit event
    /// `ssh.disconnect`, tied to the connect by the session id. Does nothing when no session is
    /// open. `transcript_*`: the session log, when one was written.
    pub fn session_ended(&self, reason: EndReason, reconnects: Option<u32>, transcript_path: Option<String>, transcript_sha256: Option<String>) {
        let Some(live) = self.live.lock().ok().and_then(|mut live| live.take()) else { return };
        self.activity_end(live.id, Some(live.connected_at), reason, reconnects, transcript_path, transcript_sha256);
        let reason = serde_json::to_value(reason).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        self.audit(Category::Connection, "ssh.disconnect", &live.target, Outcome::Success, &[("reason", reason)], live.id);
    }

    fn secret(&self, cred: &CredentialRef, conn: &Connection) -> Result<Secret> {
        let key = cred.lease_key();
        if let Some(s) = self.broker.get(&key, conn)? {
            return Ok(s);
        }
        let provider = self
            .providers
            .iter()
            .find(|p| p.id() == cred.provider)
            .ok_or_else(|| CoreError::NotFound(format!("credential provider `{}`", cred.provider)))?;
        let s = provider.fetch(&cred.item)?;
        self.broker.unlock(key, s.clone())?;
        self.record(Category::CredentialAccess, "credential.unlock", conn, Outcome::Success, &[("provider", cred.provider.clone())]);
        Ok(s)
    }

    pub async fn connect_ssh(&self, conn: &Connection, cred: &CredentialRef) -> Result<SshSession> {
        self.connect_ssh_via(&[], conn, cred, None).await
    }

    /// Retry after the user independently verified `fingerprint` (from `HostKeyUnknown`).
    pub async fn connect_ssh_trusting(&self, conn: &Connection, cred: &CredentialRef, fingerprint: &str) -> Result<SshSession> {
        self.connect_ssh_via(&[], conn, cred, Some(fingerprint)).await
    }

    /// Connect through a ProxyJump chain. Every hop goes through the same checks as a direct
    /// connection: protocol and customer policy, its own credential via the broker, strict host
    /// keys (an unknown jump key fails with `JumpHostKeyUnknown { hop }`), and its own audit
    /// record. `trust` / `JumpHop::trust` record a fingerprint the user verified for that host.
    pub async fn connect_ssh_via(&self, jumps: &[JumpHop], conn: &Connection, cred: &CredentialRef, trust: Option<&str>) -> Result<SshSession> {
        let mut attempt = Attempt { orchestrator: self, session: self.activity_begin(jumps, conn, cred), finished: false };
        self.set_attempt(attempt.session);
        let result = self.connect_ssh_attempt(jumps, conn, cred, trust).await;
        attempt.finished = true;
        match &result {
            Ok(_) => {
                if let Ok(mut live) = self.live.lock() {
                    *live = Some(LiveSession { id: attempt.session, target: conn.name.clone(), connected_at: activity::now_ms() });
                }
            }
            Err(e) => self.activity_end(attempt.session, None, end_reason_for(e), None, None, None),
        }
        result
    }

    async fn connect_ssh_attempt(&self, jumps: &[JumpHop], conn: &Connection, cred: &CredentialRef, trust: Option<&str>) -> Result<SshSession> {
        // SEC-3: the audit log's full check (started when the log was opened) must pass before
        // any secret is fetched, any host is authenticated to, or any record is appended.
        if let Err(e) = self.audit_checked().await {
            eprintln!("bastion: connect refused, {e}");
            return Err(e);
        }
        let mut hops = Vec::with_capacity(jumps.len());
        for j in jumps {
            hops.push(self.params(&j.conn, &j.cred, j.trust.as_deref()).await?);
        }
        let mut target = self.params(conn, cred, trust).await?;
        if let (Some(code), SshAuth::Password(_)) = (&self.verification_code, &target.auth) {
            let SshAuth::Password(password) = std::mem::replace(&mut target.auth, SshAuth::Agent { socket: None }) else { unreachable!() };
            target.auth = SshAuth::PasswordAndCode { password, code: code.clone() };
        }
        let via: Vec<String> = jumps.iter().map(|j| format!("{}:{}", j.conn.host, j.conn.settings.port.unwrap_or(22))).collect();
        let details: Vec<(&str, String)> = if via.is_empty() { vec![] } else { vec![("via", via.join(","))] };
        match SshSession::connect_via(hops, target).await {
            Ok(s) => {
                // The audit log's full check passed at the start of this attempt.
                self.record(Category::Connection, "ssh.connect", conn, Outcome::Success, &details);
                Ok(s)
            }
            Err(e) => {
                let category = match &e {
                    CoreError::HostKeyUnknown { .. } | CoreError::JumpHostKeyUnknown { .. } | CoreError::HostKeyChanged { .. } => Category::SecurityWarning,
                    CoreError::AuthFailed => {
                        // A cached secret that no longer works must not be retried silently.
                        // The failing hop is not reported by the transport, so every lease in the chain is dropped.
                        let _ = self.broker.lock(&cred.lease_key());
                        for j in jumps {
                            let _ = self.broker.lock(&j.cred.lease_key());
                        }
                        Category::Authentication
                    }
                    _ => Category::Connection,
                };
                let mut d = details.clone();
                d.push(("reason", e.to_string()));
                self.record(category, "ssh.connect", conn, Outcome::Failure, &d);
                Err(e)
            }
        }
    }

    /// Policy check, secret and SSH parameters for one hop (jump or target).
    async fn params(&self, conn: &Connection, cred: &CredentialRef, trust: Option<&str>) -> Result<SshParams> {
        let pre = self
            .policy
            .check_protocol(conn.protocol)
            .and_then(|_| self.policy.check_credential_scope(cred.scope.as_deref(), conn));
        if let Err(e) = pre {
            self.record(Category::Connection, "ssh.connect", conn, Outcome::Denied, &[("reason", e.to_string())]);
            return Err(e);
        }
        if let SecretUse::Agent(socket) = &cred.usage {
            return self.ssh_params(conn, cred, SshAuth::Agent { socket: socket.clone() }, trust);
        }
        let secret = match self.secret(cred, conn) {
            Ok(s) => s,
            Err(e) => {
                self.record(Category::CredentialAccess, "credential.unlock", conn, Outcome::Failure, &[("reason", e.to_string())]);
                return Err(e);
            }
        };
        let auth = match &cred.usage {
            SecretUse::Password => SshAuth::Password(secret),
            SecretUse::KeyPem => SshAuth::KeyPem { pem: secret, passphrase: None },
            // An empty brokered passphrase means the key file is not encrypted.
            SecretUse::KeyFilePassphrase(path) => SshAuth::KeyFile { path: path.clone(), passphrase: (!secret.expose().is_empty()).then_some(secret) },
            SecretUse::Agent(_) => unreachable!("agent logins return above"),
        };
        self.ssh_params(conn, cred, auth, trust)
    }

    fn ssh_params(&self, conn: &Connection, cred: &CredentialRef, auth: SshAuth, trust: Option<&str>) -> Result<SshParams> {
        let algorithms = conn.settings.ssh_algorithms.clone().unwrap_or_default().resolve(self.policy.forbid_weak_ssh_algorithms)?;
        if !algorithms.weak_enabled.is_empty() {
            self.record(Category::SecurityWarning, "ssh.weak_algorithms", conn, Outcome::Success, &[("algorithms", algorithms.weak_enabled.join(","))]);
        }
        let policy = match trust {
            Some(fp) => {
                self.record(Category::SecurityWarning, "hostkey.trust", conn, Outcome::Success, &[("fingerprint", fp.into())]);
                HostKeyPolicy::TrustFingerprint(fp.into())
            }
            None => HostKeyPolicy::Strict,
        };
        Ok(SshParams {
            host: conn.host.clone(),
            port: conn.settings.port.unwrap_or(22),
            username: cred.username.clone(),
            auth,
            known_hosts: self.known_hosts.clone(),
            policy,
            connect_timeout: self.connect_timeout,
            keepalive: crate::session::ReconnectPolicy::keepalive_for(&conn.settings),
            prompter: self.prompter.clone(),
            algorithms,
        })
    }
}

/// One jump host in a ProxyJump chain, with its own credential reference and optional trust.
#[derive(Debug, Clone)]
pub struct JumpHop {
    pub conn: Connection,
    pub cred: CredentialRef,
    pub trust: Option<String>,
}

#[cfg(test)]
#[path = "connect_audit_gate_tests.rs"]
mod audit_gate_tests;
