//! Port-forward manager runtime: saved tunnels (`tunneldefs`) running on one SSH session.
//!
//! - A local or SOCKS port that is taken moves to the next free port above it (reported as
//!   `moved_from`), so a stale listener never blocks a start.
//! - [`ForwardSet::restart`] moves every tunnel onto a new session after a reconnect, keeping
//!   the ports already bound so clients pointed at them keep working.
//! - Listeners bind loopback only (`tunnel` refuses anything else); remote forwards bind loopback
//!   on the server. One tunnel failing never stops the others.
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::ssh::SshSession;
use crate::tunnel::{self, Tunnel};
use crate::tunneldefs::{TunnelDef, TunnelSpec};
use crate::webtunnel::next_free_port;

/// At most this many tunnels run on one session.
pub const MAX_FORWARDS: usize = 64;

enum Run {
    Listener(Tunnel),
    Remote { session: Arc<SshSession>, port: u16 },
    Failed(String),
    Stopped,
}

struct Entry {
    def: TunnelDef,
    /// The port in use: local listener for local/SOCKS, server listener for remote.
    port: Option<u16>,
    run: Run,
}

/// One running, failed or stopped tunnel, for the Tunnel Manager's table.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardStatus {
    pub id: Uuid,
    pub name: String,
    pub summary: String,
    /// `local`, `remote` or `dynamic`.
    pub kind: &'static str,
    pub port: Option<u16>,
    /// The saved local port, when it was taken and the tunnel runs on `port` instead.
    pub moved_from: Option<u16>,
    pub running: bool,
    pub connections: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub last_error: Option<String>,
}

/// The tunnels running on one SSH connection.
#[derive(Default)]
pub struct ForwardSet {
    /// The connection whose session carries these tunnels; `None` accepts any definition.
    via: Option<Uuid>,
    entries: Mutex<Vec<Entry>>,
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn pick_port(wanted: u16) -> Result<u16> {
    next_free_port(wanted).ok_or_else(|| CoreError::Invalid(format!("no free local port at or above {wanted}")))
}

/// Start `def` on `session`. `keep` is the port bound before a reconnect, tried first.
async fn launch(session: &Arc<SshSession>, def: TunnelDef, keep: Option<u16>) -> Entry {
    let outcome: Result<(Run, u16)> = async {
        match &def.spec {
            TunnelSpec::Local { local_port, dest_host, dest_port } => {
                let port = pick_port(keep.unwrap_or(*local_port))?;
                Ok((Run::Listener(tunnel::local_forward(session.clone(), loopback(port), dest_host, *dest_port).await?), port))
            }
            TunnelSpec::Dynamic { local_port } => {
                let port = pick_port(keep.unwrap_or(*local_port))?;
                Ok((Run::Listener(tunnel::dynamic_socks(session.clone(), loopback(port)).await?), port))
            }
            TunnelSpec::Remote { remote_port, local_host, local_port } => {
                let port = session.remote_forward("127.0.0.1", keep.unwrap_or(*remote_port), local_host, *local_port).await?;
                Ok((Run::Remote { session: session.clone(), port }, port))
            }
        }
    }
    .await;
    match outcome {
        Ok((run, port)) => Entry { port: Some(port), run, def },
        Err(e) => Entry { def, port: None, run: Run::Failed(e.to_string()) },
    }
}

async fn halt(run: Run) {
    match run {
        Run::Listener(t) => t.shutdown().await,
        Run::Remote { session, port } => {
            let _ = session.cancel_remote_forward("127.0.0.1", port).await;
        }
        Run::Failed(_) | Run::Stopped => {}
    }
}

fn status(e: &Entry) -> ForwardStatus {
    let kind = match e.def.spec {
        TunnelSpec::Local { .. } => "local",
        TunnelSpec::Remote { .. } => "remote",
        TunnelSpec::Dynamic { .. } => "dynamic",
    };
    let saved = e.def.local_port();
    let mut s = ForwardStatus {
        id: e.def.id,
        name: e.def.name.clone(),
        summary: e.def.summary(),
        kind,
        port: e.port,
        moved_from: e.port.and(saved).filter(|p| Some(*p) != e.port),
        running: false,
        connections: 0,
        bytes_up: 0,
        bytes_down: 0,
        last_error: None,
    };
    match &e.run {
        Run::Listener(t) => {
            let st = t.stats();
            (s.running, s.connections, s.bytes_up, s.bytes_down, s.last_error) = (t.is_running(), st.connections, st.bytes_up, st.bytes_down, st.last_error);
        }
        Run::Remote { .. } => s.running = true,
        Run::Failed(err) => s.last_error = Some(err.clone()),
        Run::Stopped => {}
    }
    s
}

impl ForwardSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// A set that only runs tunnels saved for connection `via`.
    pub fn for_connection(via: Uuid) -> Self {
        ForwardSet { via: Some(via), entries: Mutex::default() }
    }

    /// Start `defs` on `session` (a tunnel already in the set is restarted). A tunnel that
    /// cannot start is listed as failed with its error; the call fails only past [`MAX_FORWARDS`].
    pub async fn start(&self, session: &Arc<SshSession>, defs: Vec<TunnelDef>) -> Result<Vec<ForwardStatus>> {
        if let (Some(via), Some(other)) = (self.via, defs.iter().find(|d| Some(d.via) != self.via)) {
            return Err(CoreError::Invalid(format!("tunnel {} runs over another connection, not {via}", other.name)));
        }
        let incoming: Vec<Uuid> = defs.iter().map(|d| d.id).collect();
        let replaced: Vec<Entry> = {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let kept = entries.iter().filter(|e| !incoming.contains(&e.def.id)).count();
            if kept + defs.len() > MAX_FORWARDS {
                return Err(CoreError::Invalid(format!("at most {MAX_FORWARDS} tunnels per connection")));
            }
            let (replaced, kept): (Vec<Entry>, Vec<Entry>) = entries.drain(..).partition(|e| incoming.contains(&e.def.id));
            *entries = kept;
            replaced
        };
        for e in replaced {
            halt(e.run).await;
        }
        let mut started = Vec::with_capacity(defs.len());
        for def in defs {
            started.push(launch(session, def, None).await);
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.extend(started);
        Ok(entries.iter().map(status).collect())
    }

    /// Move every tunnel that was not stopped onto `session` (after a reconnect), on the ports
    /// it had where they are still free. Failed ones are tried again.
    pub async fn restart(&self, session: &Arc<SshSession>) -> Vec<ForwardStatus> {
        let old: Vec<Entry> = std::mem::take(&mut *self.entries.lock().unwrap_or_else(|e| e.into_inner()));
        let mut next = Vec::with_capacity(old.len());
        for e in old {
            if matches!(e.run, Run::Stopped) {
                next.push(e);
                continue;
            }
            let keep = e.port;
            // Free the old listener first so the same port can be bound again.
            halt(e.run).await;
            next.push(launch(session, e.def, keep).await);
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let added: Vec<Entry> = entries.drain(..).collect();
        entries.extend(next);
        entries.extend(added);
        entries.iter().map(status).collect()
    }

    pub fn status(&self) -> Vec<ForwardStatus> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).iter().map(status).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
    }

    /// Stop one tunnel; it stays listed as stopped and is not restarted on reconnect.
    pub async fn stop(&self, id: Uuid) -> Result<()> {
        let run = {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let e = entries.iter_mut().find(|e| e.def.id == id).ok_or_else(|| CoreError::NotFound(format!("tunnel {id}")))?;
            std::mem::replace(&mut e.run, Run::Stopped)
        };
        halt(run).await;
        Ok(())
    }

    /// Stop and forget every tunnel (the connection is closing).
    pub async fn stop_all(&self) {
        let all: Vec<Entry> = std::mem::take(&mut *self.entries.lock().unwrap_or_else(|e| e.into_inner()));
        for e in all {
            halt(e.run).await;
        }
    }
}
