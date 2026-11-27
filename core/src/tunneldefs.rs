//! Saved tunnel definitions for the Tunnel Manager: which SSH connection carries the tunnel and
//! what it forwards. Stored in the library document (no secrets; the SSH login is asked for when
//! a tunnel starts). Local listeners always bind loopback; remote forwards bind loopback on the
//! server (the transport refuses anything else).
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::{Document, Protocol};

pub const MAX_TUNNELS: usize = 500;
const MAX_NAME: usize = 120;
const MAX_HOST: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TunnelSpec {
    /// `127.0.0.1:local_port` on this Mac → `dest_host:dest_port` as seen from the SSH server.
    Local { local_port: u16, dest_host: String, dest_port: u16 },
    /// `127.0.0.1:remote_port` on the server → `local_host:local_port` as seen from this Mac.
    Remote { remote_port: u16, local_host: String, local_port: u16 },
    /// SOCKS5 proxy on `127.0.0.1:local_port` through the SSH server.
    Dynamic { local_port: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelDef {
    pub id: Uuid,
    pub name: String,
    /// The SSH connection (by id) the tunnel runs over.
    pub via: Uuid,
    pub spec: TunnelSpec,
    /// Start automatically when a terminal on the `via` connection connects (and restart with it
    /// after a reconnect). Off: started on demand from the Tunnel Manager.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub start_with_connection: bool,
}

impl TunnelDef {
    /// One-line description, e.g. `L 127.0.0.1:15432 → db:5432`.
    pub fn summary(&self) -> String {
        match &self.spec {
            TunnelSpec::Local { local_port, dest_host, dest_port } => format!("L 127.0.0.1:{local_port} → {dest_host}:{dest_port}"),
            TunnelSpec::Remote { remote_port, local_host, local_port } => format!("R server 127.0.0.1:{remote_port} → {local_host}:{local_port}"),
            TunnelSpec::Dynamic { local_port } => format!("D SOCKS5 127.0.0.1:{local_port}"),
        }
    }

    pub fn local_port(&self) -> Option<u16> {
        match self.spec {
            TunnelSpec::Local { local_port, .. } | TunnelSpec::Dynamic { local_port } => Some(local_port),
            TunnelSpec::Remote { .. } => None,
        }
    }
}

fn check_host(label: &str, h: &str) -> Result<()> {
    if h.is_empty() || h.len() > MAX_HOST || h.starts_with('-') || h.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(CoreError::Invalid(format!("{label} must be a single host name or address.")));
    }
    Ok(())
}

fn validate(doc: &Document, def: &TunnelDef) -> Result<TunnelDef> {
    let name = def.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME {
        return Err(CoreError::Invalid(format!("Tunnel name must be 1 to {MAX_NAME} characters.")));
    }
    if doc.tunnels.iter().any(|t| t.id != def.id && t.name.eq_ignore_ascii_case(name)) {
        return Err(CoreError::Invalid(format!("A tunnel named {name} already exists.")));
    }
    let via = doc.resolve(def.via).map_err(|_| CoreError::Invalid("Choose the SSH connection the tunnel runs over.".into()))?;
    if !matches!(via.connection.protocol, Protocol::Ssh | Protocol::Sftp) {
        return Err(CoreError::Invalid(format!("{} is not an SSH connection.", via.connection.name)));
    }
    let port = |p: u16, label: &str| if p == 0 { Err(CoreError::Invalid(format!("{label} must be 1 to 65535."))) } else { Ok(()) };
    match &def.spec {
        TunnelSpec::Local { local_port, dest_host, dest_port } => {
            port(*local_port, "Local port")?;
            port(*dest_port, "Destination port")?;
            check_host("Destination", dest_host)?;
        }
        TunnelSpec::Remote { remote_port, local_host, local_port } => {
            port(*remote_port, "Server port")?;
            port(*local_port, "Local port")?;
            check_host("Local host", local_host)?;
        }
        TunnelSpec::Dynamic { local_port } => port(*local_port, "Local port")?,
    }
    // Two saved tunnels on one local port could never run together.
    if let Some(p) = def.local_port() {
        if let Some(other) = doc.tunnels.iter().find(|t| t.id != def.id && t.local_port() == Some(p)) {
            return Err(CoreError::Invalid(format!("Local port {p} is already used by the tunnel {}.", other.name)));
        }
    }
    Ok(TunnelDef { name: name.into(), ..def.clone() })
}

/// Add (a new id) or replace (an existing id) a definition.
pub fn put(doc: &mut Document, def: TunnelDef) -> Result<Uuid> {
    let def = validate(doc, &def)?;
    match doc.tunnels.iter_mut().find(|t| t.id == def.id) {
        Some(slot) => *slot = def.clone(),
        None => {
            if doc.tunnels.len() >= MAX_TUNNELS {
                return Err(CoreError::Invalid(format!("A library holds at most {MAX_TUNNELS} tunnels.")));
            }
            doc.tunnels.push(def.clone())
        }
    }
    Ok(def.id)
}

pub fn remove(doc: &mut Document, id: Uuid) -> Result<TunnelDef> {
    let i = doc.tunnels.iter().position(|t| t.id == id).ok_or_else(|| CoreError::NotFound(format!("tunnel {id}")))?;
    Ok(doc.tunnels.remove(i))
}

/// By name, or by id.
pub fn find<'a>(doc: &'a Document, key: &str) -> Option<&'a TunnelDef> {
    doc.tunnels.iter().find(|t| t.id.to_string() == key || t.name.eq_ignore_ascii_case(key))
}

/// Tunnels that start with a connection to `via`, by name.
pub fn starting_with(doc: &Document, via: Uuid) -> Vec<&TunnelDef> {
    let mut v: Vec<_> = doc.tunnels.iter().filter(|t| t.via == via && t.start_with_connection).collect();
    v.sort_by_key(|t| t.name.to_lowercase());
    v
}
