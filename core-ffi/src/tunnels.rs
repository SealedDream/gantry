//! Bridge for the Tunnel Manager: saved definitions (`bastion_core::tunneldefs`) and running
//! tunnels over a session from `SessionManager` (policy, broker, strict host keys, audit apply).
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bastion_core::ssh::SshSession;
use bastion_core::tunnel::{self, Tunnel};
use bastion_core::tunneldefs::{self, TunnelDef, TunnelSpec};
use uuid::Uuid;

use crate::terminal::{SessionManager, RUNTIME};
use crate::{parse_id, FfiError, FfiResult, Library, SshLogin};

#[derive(uniffi::Record, Clone)]
pub struct TunnelDefView {
    /// Empty for a new definition.
    pub id: String,
    pub name: String,
    pub via_id: String,
    /// Display name of the SSH connection (filled in by `tunnels`).
    pub via_name: String,
    /// `local`, `remote` or `dynamic`.
    pub kind: String,
    /// Local listener (local, dynamic) or the local target (remote).
    pub local_port: u16,
    /// Destination host as seen from the server (local) or from this Mac (remote).
    pub host: String,
    /// Destination port (local) or the server-side listener port (remote).
    pub port: u16,
    pub summary: String,
    /// Start when a terminal on the SSH connection connects (and follow its reconnects).
    #[uniffi(default = false)]
    pub start_with_connection: bool,
}

fn view(doc: &bastion_core::model::Document, t: &TunnelDef) -> TunnelDefView {
    let via_name = doc.resolve(t.via).map(|r| r.connection.name).unwrap_or_else(|_| "missing connection".into());
    let (kind, local_port, host, port) = match &t.spec {
        TunnelSpec::Local { local_port, dest_host, dest_port } => ("local", *local_port, dest_host.clone(), *dest_port),
        TunnelSpec::Remote { remote_port, local_host, local_port } => ("remote", *local_port, local_host.clone(), *remote_port),
        TunnelSpec::Dynamic { local_port } => ("dynamic", *local_port, String::new(), 0),
    };
    TunnelDefView { id: t.id.to_string(), name: t.name.clone(), via_id: t.via.to_string(), via_name, kind: kind.into(), local_port, host, port, summary: t.summary(), start_with_connection: t.start_with_connection }
}

fn spec(v: &TunnelDefView) -> FfiResult<TunnelSpec> {
    Ok(match v.kind.as_str() {
        "local" => TunnelSpec::Local { local_port: v.local_port, dest_host: v.host.trim().into(), dest_port: v.port },
        "remote" => TunnelSpec::Remote { remote_port: v.port, local_host: v.host.trim().into(), local_port: v.local_port },
        "dynamic" => TunnelSpec::Dynamic { local_port: v.local_port },
        other => return Err(FfiError::failed(format!("unknown tunnel kind {other}"))),
    })
}

#[uniffi::export]
impl Library {
    pub fn tunnels(&self) -> FfiResult<Vec<TunnelDefView>> {
        self.with_doc(|d| {
            let mut v: Vec<_> = d.tunnels.iter().map(|t| view(d, t)).collect();
            v.sort_by_key(|t| t.name.to_lowercase());
            Ok(v)
        })
    }

    /// Add (empty id) or replace a definition; returns its id.
    pub fn put_tunnel(&self, tunnel: TunnelDefView) -> FfiResult<String> {
        let id = if tunnel.id.is_empty() { Uuid::new_v4() } else { parse_id(&tunnel.id)? };
        let def = TunnelDef { id, name: tunnel.name.clone(), via: parse_id(&tunnel.via_id)?, spec: spec(&tunnel)?, start_with_connection: tunnel.start_with_connection };
        self.with_doc(|d| tunneldefs::put(d, def).map(|id| id.to_string()))
    }

    pub fn remove_tunnel(&self, id: String) -> FfiResult<()> {
        let id = parse_id(&id)?;
        self.with_doc(|d| tunneldefs::remove(d, id).map(|_| ()))
    }

    /// A definition by name or id (CLI `tun <name>`).
    pub fn find_tunnel(&self, key: String) -> FfiResult<Option<TunnelDefView>> {
        self.with_doc(|d| Ok(tunneldefs::find(d, &key).map(|t| view(d, t))))
    }
}

/// How long [`RunningTunnel::stop`] waits for an aborted listener task to finish.
const STOP_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// A started tunnel. Stopping it (or dropping it) closes its listener; the SSH connection ends
/// with the last reference.
#[derive(uniffi::Object)]
pub struct RunningTunnel {
    session: Arc<SshSession>,
    local: Option<Tunnel>,
    remote: Mutex<Option<u16>>,
    summary: String,
}

#[uniffi::export]
impl RunningTunnel {
    pub fn summary(&self) -> String {
        self.summary.clone()
    }

    pub fn is_running(&self) -> bool {
        match &self.local {
            Some(t) => t.is_running(),
            None => self.remote.lock().map(|r| r.is_some()).unwrap_or(false),
        }
    }

    /// Connections accepted so far (local and SOCKS listeners).
    pub fn connections(&self) -> u64 {
        self.local.as_ref().map(|t| t.stats().connections).unwrap_or(0)
    }

    pub fn last_error(&self) -> Option<String> {
        self.local.as_ref().and_then(|t| t.stats().last_error)
    }

    /// Stop the tunnel. Returns once the listener is closed (bounded by [`STOP_WAIT`]), so the port is free and
    /// `is_running` is false when this returns.
    pub fn stop(&self) {
        if let Some(t) = &self.local {
            t.stop();
            let deadline = std::time::Instant::now() + STOP_WAIT;
            while t.is_running() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        if let Some(port) = self.remote.lock().ok().and_then(|mut r| r.take()) {
            let _ = RUNTIME.block_on(self.session.cancel_remote_forward("127.0.0.1", port));
        }
    }
}

#[uniffi::export]
impl SessionManager {
    /// Sign in to the tunnel's SSH connection (same rules and errors as `connect_ssh`) and start it.
    #[allow(clippy::too_many_arguments)]
    pub fn start_tunnel(
        &self,
        library: Arc<Library>,
        tunnel_id: String,
        username: String,
        login: SshLogin,
        trust_fingerprint: Option<String>,
        jump_trust: HashMap<String, String>,
        jump_logins: HashMap<String, SshLogin>,
    ) -> FfiResult<Arc<RunningTunnel>> {
        let id = parse_id(&tunnel_id)?;
        let def = library.with_doc(|d| tunneldefs::find(d, &id.to_string()).cloned().ok_or_else(|| bastion_core::CoreError::NotFound(format!("tunnel {id}"))))?;
        let session = Arc::new(self.dial_ssh(&library, &def.via.to_string(), username, login, trust_fingerprint, jump_trust, jump_logins)?);
        let loopback = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        let (local, remote) = match &def.spec {
            TunnelSpec::Local { local_port, dest_host, dest_port } => {
                (Some(RUNTIME.block_on(tunnel::local_forward(session.clone(), loopback(*local_port), dest_host, *dest_port))?), None)
            }
            TunnelSpec::Dynamic { local_port } => (Some(RUNTIME.block_on(tunnel::dynamic_socks(session.clone(), loopback(*local_port)))?), None),
            TunnelSpec::Remote { remote_port, local_host, local_port } => {
                (None, Some(RUNTIME.block_on(session.remote_forward("127.0.0.1", *remote_port, local_host, *local_port))?))
            }
        };
        Ok(Arc::new(RunningTunnel { session, local, remote: Mutex::new(remote), summary: def.summary() }))
    }
}
