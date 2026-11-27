//! Gateway manager: shared SSH gateway (bastion host) definitions stored in the library and
//! referenced from connections, folders or a type's Default Settings by `Settings::gateway_id`.
//! A connection with a gateway is reached through it, like a first ProxyJump hop: the gateway
//! gets its own host-key check, credential and audit record. Definitions hold no secrets.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::{Document, Folder, Node, Protocol};

const MAX_NAME_LEN: usize = 256;
const MAX_HOST_LEN: usize = 253;
const MAX_USER_LEN: usize = 256;
const MAX_NOTES_LEN: usize = 16 * 1024;
/// Plenty for any real estate; keeps a hostile import from bloating the library.
pub const MAX_GATEWAYS: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gateway {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    /// Empty means "the target connection's user name".
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub notes: String,
}

/// What the user typed for a new or edited gateway.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayInput {
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub notes: String,
}

/// Where a gateway is referenced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayUse {
    /// A connection that reaches its host through the gateway (own or inherited setting).
    Connection { id: Uuid, name: String, inherited: bool },
    /// A folder whose Default Settings set it.
    Folder { id: Uuid, name: String },
    /// A connection type's Default Settings set it (protocol name).
    TypeDefault(String),
}

fn check(doc: &Document, input: &GatewayInput, editing: Option<Uuid>) -> Result<GatewayInput> {
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return Err(CoreError::Invalid(format!("Gateway name must be 1 to {MAX_NAME_LEN} characters.")));
    }
    if doc.gateways.iter().any(|g| Some(g.id) != editing && g.name.eq_ignore_ascii_case(name)) {
        return Err(CoreError::Invalid(format!("A gateway named {name} already exists.")));
    }
    let host = input.host.trim();
    if host.is_empty() || host.len() > MAX_HOST_LEN || host.starts_with('-') || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(CoreError::Invalid("Gateway host must be a single host name or address without spaces.".into()));
    }
    if input.port == Some(0) {
        return Err(CoreError::Invalid("Port must be a number from 1 to 65535.".into()));
    }
    let username = input.username.as_deref().map(str::trim).filter(|u| !u.is_empty());
    if let Some(u) = username {
        if u.len() > MAX_USER_LEN || u.starts_with('-') || u.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(CoreError::Invalid("Gateway user name must be one word without spaces.".into()));
        }
    }
    if input.notes.len() > MAX_NOTES_LEN {
        return Err(CoreError::Invalid(format!("Notes are longer than {MAX_NOTES_LEN} characters.")));
    }
    Ok(GatewayInput { name: name.into(), host: host.into(), port: input.port, username: username.map(str::to_string), notes: input.notes.clone() })
}

pub fn add(doc: &mut Document, input: &GatewayInput) -> Result<Uuid> {
    if doc.gateways.len() >= MAX_GATEWAYS {
        return Err(CoreError::Invalid(format!("A library holds at most {MAX_GATEWAYS} gateways.")));
    }
    let v = check(doc, input, None)?;
    let id = Uuid::new_v4();
    doc.gateways.push(Gateway { id, name: v.name, host: v.host, port: v.port, username: v.username, notes: v.notes });
    Ok(id)
}

pub fn update(doc: &mut Document, id: Uuid, input: &GatewayInput) -> Result<()> {
    let v = check(doc, input, Some(id))?;
    let g = doc.gateways.iter_mut().find(|g| g.id == id).ok_or_else(|| CoreError::NotFound(format!("gateway {id}")))?;
    *g = Gateway { id, name: v.name, host: v.host, port: v.port, username: v.username, notes: v.notes };
    Ok(())
}

/// Delete a gateway nothing uses. A gateway in use is refused with the places that use it, so
/// no connection silently loses its route.
pub fn remove(doc: &mut Document, id: Uuid) -> Result<Gateway> {
    let uses = uses(doc, id);
    if !uses.is_empty() {
        let names: Vec<String> = uses
            .iter()
            .take(5)
            .map(|u| match u {
                GatewayUse::Connection { name, .. } | GatewayUse::Folder { name, .. } => name.clone(),
                GatewayUse::TypeDefault(p) => format!("{} Default Settings", p.to_uppercase()),
            })
            .collect();
        let more = if uses.len() > names.len() { format!(" and {} more", uses.len() - names.len()) } else { String::new() };
        return Err(CoreError::Invalid(format!("The gateway is still used by {}{more}. Change those first.", names.join(", "))));
    }
    let pos = doc.gateways.iter().position(|g| g.id == id).ok_or_else(|| CoreError::NotFound(format!("gateway {id}")))?;
    Ok(doc.gateways.remove(pos))
}

pub fn get(doc: &Document, id: Uuid) -> Option<&Gateway> {
    doc.gateways.iter().find(|g| g.id == id)
}

/// Everything that references gateway `id`, connections first (in tree order).
pub fn uses(doc: &Document, id: Uuid) -> Vec<GatewayUse> {
    let mut out: Vec<GatewayUse> = doc
        .connections()
        .into_iter()
        .filter(|r| r.effective.gateway_id == Some(id))
        .map(|r| GatewayUse::Connection { inherited: r.connection.settings.gateway_id != Some(id), id: r.connection.id, name: r.connection.name })
        .collect();
    fn folders(f: &Folder, id: Uuid, out: &mut Vec<GatewayUse>) {
        if f.defaults.gateway_id == Some(id) {
            out.push(GatewayUse::Folder { id: f.id, name: f.name.clone() });
        }
        for n in &f.children {
            if let Node::Folder(sub) = n {
                folders(sub, id, out);
            }
        }
    }
    folders(&doc.root, id, &mut out);
    for (p, s) in doc.type_defaults.iter() {
        if s.gateway_id == Some(id) {
            out.push(GatewayUse::TypeDefault(crate::properties::protocol_name(*p)));
        }
    }
    out
}

/// The gateway a resolved connection goes through, if any. A reference to a gateway that no
/// longer exists (an edited file, a partial import) is an error, never a silent direct connect.
pub fn for_connection(doc: &Document, connection: Uuid) -> Result<Option<Gateway>> {
    // A plugin entry never resolves (PLUG-03a); its own and inherited settings come from the
    // plugin-entry walk instead (PLUG-08).
    let (name, gateway_id) = match crate::pluginentry::plugin_entry_settings(doc, connection) {
        Some((c, settings)) => (c.name.clone(), settings.gateway_id),
        None => {
            let r = doc.resolve(connection)?;
            (r.connection.name.clone(), r.effective.gateway_id)
        }
    };
    match gateway_id {
        None => Ok(None),
        Some(id) => get(doc, id)
            .cloned()
            .map(Some)
            .ok_or_else(|| CoreError::Invalid(format!("{name} uses a gateway that no longer exists; choose another in its properties."))),
    }
}

/// The classification of a connection or a plugin entry (for the gateway hop's policy checks).
pub fn classification_of(doc: &Document, connection: Uuid) -> Result<crate::policy::Classification> {
    match crate::pluginentry::plugin_entry_settings(doc, connection) {
        Some((c, _)) => Ok(c.classification.clone()),
        None => Ok(doc.resolve(connection)?.connection.classification),
    }
}

/// How a non-SSH connection reaches its host through a gateway: RDP and VNC over a loopback
/// port forwarded by the gateway (`ssh -L`), web pages over a loopback SOCKS proxy (`ssh -D`)
/// so the browser keeps the real URL, its TLS name and every link on the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteKind {
    Forward { dest_host: String, dest_port: u16 },
    Socks,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub gateway: Gateway,
    pub kind: RouteKind,
}

/// The gateway route for an RDP, VNC or web connection, or a plugin entry (a forward to its host
/// and port, PLUG-08); `None` when it has no gateway. SSH and
/// SFTP use the gateway as a jump host instead (see the FFI workflow); other protocols cannot
/// be opened through one yet and are refused rather than silently connected directly.
pub fn route_for(doc: &Document, connection: Uuid) -> Result<Option<Route>> {
    let Some(gateway) = for_connection(doc, connection)? else { return Ok(None) };
    // A plugin entry (PLUG-08): a loopback forward to its own host and port. The core relay
    // then streams to that forward (`EntryRoute::Forward`), with TLS and the login gate as ever.
    if let Some((c, settings)) = crate::pluginentry::plugin_entry_settings(doc, connection) {
        let dest_host = c.host.trim().to_string();
        let dest_port = settings.port.unwrap_or(0);
        if dest_host.is_empty() || dest_port == 0 {
            return Err(CoreError::Invalid(format!("{} needs a host and a port to go through its gateway.", c.name)));
        }
        return Ok(Some(Route { gateway, kind: RouteKind::Forward { dest_host, dest_port } }));
    }
    let r = doc.resolve(connection)?;
    let kind = match r.connection.protocol {
        Protocol::Rdp | Protocol::Vnc => {
            let dest_port = r.effective.port.or(r.connection.protocol.default_port()).unwrap_or(0);
            RouteKind::Forward { dest_host: r.connection.host.trim().to_string(), dest_port }
        }
        Protocol::Web => RouteKind::Socks,
        Protocol::Ssh | Protocol::Sftp => return Err(CoreError::Invalid("SSH connections use their gateway as the first jump host.".into())),
        p => return Err(CoreError::Invalid(format!("{} connections cannot go through a gateway yet.", crate::properties::protocol_name(p).to_uppercase()))),
    };
    Ok(Some(Route { gateway, kind }))
}
