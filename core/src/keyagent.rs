//! Bastion's own SSH agent: serves keys from the vault to `ssh`, `git` and other tools on an
//! owner-only Unix socket, so private keys never need to sit on disk unencrypted. Keys are
//! loaded only by Bastion itself; requests from clients to add or remove keys are refused.
//! With a confirm callback, every signature asks the frontend first (OpenSSH's `ssh-add -c`).
//! The agent stops, and the socket file is removed, when [`KeyAgent`] is dropped; clients
//! already connected are refused and disconnected at the same moment.
//! On Windows the "socket" is a named pipe (`\\.\pipe\...`) with an owner-only DACL, local
//! clients only, and clients running as another user are dropped (as the IPC pipe does).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use russh::keys::agent::server::{Agent, MessageType};
use russh::keys::{Algorithm, PrivateKey};

use crate::error::{CoreError, Result};

/// Asked before each signature when set; gets the key's comment and SHA-256 fingerprint and
/// returns whether to sign.
pub type ConfirmFn = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

#[derive(Clone)]
struct Policy {
    /// True only while Bastion loads its own keys.
    loading: Arc<AtomicBool>,
    /// Set when the agent stops: every request is refused from then on.
    stopped: Arc<AtomicBool>,
    confirm: Option<ConfirmFn>,
}

impl Policy {
    fn new(confirm: Option<ConfirmFn>) -> Self {
        Policy { loading: Arc::new(AtomicBool::new(true)), stopped: Arc::new(AtomicBool::new(false)), confirm }
    }
}

impl Agent for Policy {
    fn confirm(self, pk: Arc<PrivateKey>) -> Box<dyn std::future::Future<Output = (Self, bool)> + Unpin + Send> {
        let ok = !self.stopped.load(Ordering::SeqCst) && match &self.confirm {
            Some(ask) => ask(&pk.comment().to_string(), &pk.fingerprint(russh::keys::HashAlg::Sha256).to_string()),
            None => true,
        };
        Box::new(std::future::ready((self, ok)))
    }

    fn confirm_request(&self, msg: MessageType) -> impl std::future::Future<Output = bool> + Send {
        if self.stopped.load(Ordering::SeqCst) {
            return std::future::ready(false);
        }
        let allowed = match msg {
            MessageType::AddKeys | MessageType::RemoveKeys | MessageType::RemoveAllKeys => {
                self.loading.load(Ordering::SeqCst)
            }
            _ => true,
        };
        std::future::ready(allowed)
    }
}

/// A running agent; dropping it stops serving and removes the socket.
pub struct KeyAgent {
    socket: PathBuf,
    task: tokio::task::JoinHandle<()>,
    stopped: Arc<AtomicBool>,
    stop: tokio::sync::watch::Sender<bool>,
}

/// A client connection that ends (reads EOF, writes fail) as soon as the agent stops, so
/// russh's per-client task exits and drops its references to the key store.
struct Revocable<S> {
    inner: S,
    stopped: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>,
    done: bool,
}

impl<S> Revocable<S> {
    fn new(inner: S, mut rx: tokio::sync::watch::Receiver<bool>) -> Self {
        let stopped = Box::pin(async move {
            let _ = rx.wait_for(|s| *s).await;
        });
        Revocable { inner, stopped, done: false }
    }

    fn poll_stopped(&mut self, cx: &mut std::task::Context<'_>) -> bool {
        if !self.done && self.stopped.as_mut().poll(cx).is_ready() {
            self.done = true;
        }
        self.done
    }
}

fn revoked() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "agent stopped")
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Revocable<S> {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        if self.poll_stopped(cx) {
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Revocable<S> {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        if self.poll_stopped(cx) {
            return std::task::Poll::Ready(Err(revoked()));
        }
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl KeyAgent {
    /// Path to put in `SSH_AUTH_SOCK`.
    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

impl Drop for KeyAgent {
    fn drop(&mut self) {
        // Refuse signing first, then end every connected client and the listener.
        self.stopped.store(true, Ordering::SeqCst);
        let _ = self.stop.send(true);
        self.task.abort();
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn is_hardware(key: &PrivateKey) -> bool {
    matches!(key.algorithm(), Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256)
}

/// Start serving `keys` at `socket` (its folder must exist and be private to the user).
/// FIDO2 `sk-` keys are skipped: they sign on the authenticator through the system agent.
#[cfg(unix)]
pub async fn start(socket: &Path, keys: &[PrivateKey], confirm: Option<ConfirmFn>) -> Result<KeyAgent> {
    use russh::keys::agent::Constraint;
    use russh::keys::agent::client::AgentClient;
    use std::os::unix::fs::PermissionsExt;

    let dir = socket.parent().ok_or_else(|| CoreError::Invalid("Agent socket needs a folder".into()))?;
    if std::fs::metadata(dir)?.permissions().mode() & 0o077 != 0 {
        return Err(CoreError::Invalid("Agent socket folder must be private to you (mode 700)".into()));
    }
    if socket.exists() {
        return Err(CoreError::Invalid("Agent socket already exists".into()));
    }
    let listener = tokio::net::UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    let constraints = if confirm.is_some() { vec![Constraint::Confirm] } else { Vec::new() };
    let policy = Policy::new(confirm);
    let loading = policy.loading.clone();
    let stopped = policy.stopped.clone();
    let (stop, rx) = tokio::sync::watch::channel(false);
    let incoming = futures::stream::unfold((listener, rx), |(l, rx)| async move {
        let next = l.accept().await.map(|(s, _)| Revocable::new(s, rx.clone()));
        Some((next, (l, rx)))
    });
    let task = tokio::spawn(async move {
        let _ = russh::keys::agent::server::serve(Box::pin(incoming), policy).await;
    });
    let agent = KeyAgent { socket: socket.to_path_buf(), task, stopped, stop };

    let mut client = AgentClient::connect_uds(socket).await.map_err(|e| CoreError::Invalid(e.to_string()))?;
    for key in keys.iter().filter(|k| !is_hardware(k)) {
        client.add_identity(key, &constraints).await.map_err(|e| CoreError::Invalid(e.to_string()))?;
    }
    loading.store(false, Ordering::SeqCst);
    Ok(agent)
}

#[cfg(windows)]
pub async fn start(socket: &Path, keys: &[PrivateKey], confirm: Option<ConfirmFn>) -> Result<KeyAgent> {
    use russh::keys::agent::Constraint;
    use russh::keys::agent::client::AgentClient;
    use std::os::windows::io::AsRawHandle;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    /// ERROR_ACCESS_DENIED: with `first_pipe_instance`, the name is already taken.
    const ACCESS_DENIED: i32 = 5;

    fn create(name: &Path, first: bool) -> std::io::Result<NamedPipeServer> {
        crate::winacl::with_owner_only_attributes(|sa| {
            // SAFETY: `sa` is a valid SECURITY_ATTRIBUTES that outlives the call.
            unsafe { ServerOptions::new().first_pipe_instance(first).reject_remote_clients(true).create_with_security_attributes_raw(name, sa) }
        })?
    }

    if !socket.to_string_lossy().starts_with(r"\\.\pipe\") {
        return Err(CoreError::Invalid(r"Agent pipe must be named \\.\pipe\...".into()));
    }
    let first = create(socket, true).map_err(|e| match e.raw_os_error() {
        Some(ACCESS_DENIED) => CoreError::Invalid("Agent pipe name is already in use".into()),
        _ => e.into(),
    })?;
    let constraints = if confirm.is_some() { vec![Constraint::Confirm] } else { Vec::new() };
    let policy = Policy::new(confirm);
    let loading = policy.loading.clone();
    let stopped = policy.stopped.clone();
    let (stop, rx) = tokio::sync::watch::channel(false);
    let name = socket.to_path_buf();
    let incoming = futures::stream::unfold(first, move |mut server| {
        let name = name.clone();
        let rx = rx.clone();
        async move {
            loop {
                if let Err(e) = server.connect().await {
                    return Some((Err(e), server));
                }
                // The next instance exists before this client is served, so callers are not refused.
                let next = match create(&name, false) {
                    Ok(n) => n,
                    Err(e) => return Some((Err(e), server)),
                };
                let connected = std::mem::replace(&mut server, next);
                if crate::winacl::pipe_peer_is_current_user(connected.as_raw_handle() as _, true).unwrap_or(false) {
                    return Some((Ok(Revocable::new(connected, rx)), server));
                }
                let _ = connected.disconnect();
            }
        }
    });
    let task = tokio::spawn(async move {
        let _ = russh::keys::agent::server::serve(Box::pin(incoming), policy).await;
    });
    let agent = KeyAgent { socket: socket.to_path_buf(), task, stopped, stop };

    let mut client = AgentClient::connect_named_pipe(socket).await.map_err(|e| CoreError::Invalid(e.to_string()))?;
    for key in keys.iter().filter(|k| !is_hardware(k)) {
        client.add_identity(key, &constraints).await.map_err(|e| CoreError::Invalid(e.to_string()))?;
    }
    loading.store(false, Ordering::SeqCst);
    Ok(agent)
}

#[cfg(all(test, unix))]
#[path = "keyagent_tests.rs"]
mod tests;
