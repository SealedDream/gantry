//! Bridge for the port-forward manager (`bastion_core::forwards`): saved tunnels running on a
//! terminal's own SSH connection. Tunnels marked "start with connection" start when the terminal
//! connects, all of them follow a reconnect on the same ports, and they stop when it closes.
use std::sync::Arc;

use bastion_core::forwards::{ForwardSet, ForwardStatus};
use bastion_core::ssh::SshSession;
use bastion_core::tunneldefs::{self, TunnelDef};

use crate::terminal::RUNTIME;
use crate::{parse_id, FfiError, FfiResult, Library, Terminal};

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct ForwardStatusView {
    pub id: String,
    pub name: String,
    pub summary: String,
    /// `local`, `remote` or `dynamic`.
    pub kind: String,
    /// The port in use (local listener, or the server's for remote); `None` when not running.
    pub port: Option<u16>,
    /// The saved port, when it was taken and the tunnel moved to `port`.
    pub moved_from: Option<u16>,
    pub running: bool,
    pub connections: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub last_error: Option<String>,
}

impl From<ForwardStatus> for ForwardStatusView {
    fn from(s: ForwardStatus) -> Self {
        ForwardStatusView {
            id: s.id.to_string(),
            name: s.name,
            summary: s.summary,
            kind: s.kind.into(),
            port: s.port,
            moved_from: s.moved_from,
            running: s.running,
            connections: s.connections,
            bytes_up: s.bytes_up,
            bytes_down: s.bytes_down,
            last_error: s.last_error,
        }
    }
}

/// Start the connection's "start with connection" tunnels. Never fails the connect: a tunnel that
/// cannot start shows as failed in `forwards()`, and a library error starts none.
pub(crate) fn start_with_connection(library: &Library, connection_id: &str, session: &Arc<SshSession>, forwards: &ForwardSet) {
    let Ok(via) = parse_id(connection_id) else { return };
    let defs: Vec<TunnelDef> = library.with_doc(|d| Ok(tunneldefs::starting_with(d, via).into_iter().cloned().collect())).unwrap_or_default();
    if !defs.is_empty() {
        let _ = RUNTIME.block_on(forwards.start(session, defs));
    }
}

fn need(t: &Terminal) -> FfiResult<&Arc<ForwardSet>> {
    t.forwards.as_ref().ok_or_else(|| FfiError::failed("tunnels need an SSH session".into()))
}

#[uniffi::export]
impl Terminal {
    /// Tunnels on this connection: running, failed and stopped.
    pub fn forwards(&self) -> Vec<ForwardStatusView> {
        self.forwards.as_ref().map(|f| f.status().into_iter().map(Into::into).collect()).unwrap_or_default()
    }

    /// Start saved tunnels (by id) on this terminal's connection; one already listed restarts.
    /// Each must be saved for this terminal's connection.
    pub fn start_forwards(&self, library: Arc<Library>, tunnel_ids: Vec<String>) -> FfiResult<Vec<ForwardStatusView>> {
        let forwards = need(self)?;
        let ids = tunnel_ids.iter().map(|i| parse_id(i)).collect::<FfiResult<Vec<_>>>()?;
        let defs = library.with_doc(|d| {
            ids.iter()
                .map(|id| d.tunnels.iter().find(|t| t.id == *id).cloned().ok_or_else(|| bastion_core::CoreError::NotFound(format!("tunnel {id}"))))
                .collect::<bastion_core::Result<Vec<_>>>()
        })?;
        let session = self.ssh_session().ok_or_else(|| FfiError::failed("tunnels need an SSH session".into()))?;
        let st = RUNTIME.block_on(forwards.start(&session, defs))?;
        Ok(st.into_iter().map(Into::into).collect())
    }

    /// Stop one tunnel; it is not restarted on reconnect.
    pub fn stop_forward(&self, tunnel_id: String) -> FfiResult<()> {
        let id = parse_id(&tunnel_id)?;
        Ok(RUNTIME.block_on(need(self)?.stop(id))?)
    }
}
