//! `open.connection` (plugin API 1.2; `docs/specs/plugins-amendment-3.md`), app side.
//!
//! The sheet's request and the user's answer go through the plugin view's updates and events
//! (`open-request`, `open-go`, `open-refused`; `{"type":"open",...}`), see
//! `core/src/plugin/host/view_open.rs`. This adds the one call the app makes before it connects
//! on a direct route: resolve the name once and check every address (section 5, step 3).

use std::sync::{Arc, Mutex};

use bastion_core::model::{Connection, Document, Node, Protocol};
use bastion_core::plugin::broker::open::{parse_host, Protocol as OpenProtocol};
use bastion_core::plugin::broker::open::resolve_checked;
use bastion_core::plugin::library_save;
use bastion_core::pluginentry::plugin_entry_settings;

use crate::pluginview::failure;
use crate::{parse_id, FfiError, FfiResult, Library};

/// The connection an `open-go` update describes. The host is checked again here (the app passes
/// back what the core sent). `via_entry_route` gives it the plugin entry's gateway.
fn open_connection(doc: &Document, entry_id: &str, protocol: &str, host: &str, port: u16, label: &str, via_entry_route: bool) -> FfiResult<(Connection, Option<uuid::Uuid>)> {
    let entry = parse_id(entry_id)?;
    let (_, settings) = plugin_entry_settings(doc, entry).ok_or_else(|| FfiError::failed("not a plugin entry".to_string()))?;
    let protocol = match OpenProtocol::parse(protocol) {
        Some(OpenProtocol::Ssh) => Protocol::Ssh,
        Some(OpenProtocol::Rdp) => Protocol::Rdp,
        Some(OpenProtocol::Vnc) => Protocol::Vnc,
        None => return Err(FfiError::failed(format!("`{protocol}` cannot be opened by a plugin"))),
    };
    let host = parse_host(host).map_err(failure)?.canonical();
    let mut c = Connection::new(label, protocol, host);
    c.settings.port = Some(port);
    let gateway = if via_entry_route { settings.gateway_id } else { None };
    c.settings.gateway_id = gateway;
    Ok((c, gateway))
}

#[uniffi::export]
impl Library {
    /// A one-connection library for an `open-go` update, never saved, like Quick Connect. With
    /// `via_entry_route` it holds a copy of the plugin entry's gateway and uses it.
    pub fn plugin_open_library(&self, entry_id: String, protocol: String, host: String, port: u16, label: String, via_entry_route: bool) -> FfiResult<Arc<Library>> {
        let doc = self.lock();
        let (c, gateway) = open_connection(&doc, &entry_id, &protocol, &host, port, &label, via_entry_route)?;
        let mut out = Document::new("Plugin connection");
        out.gateways = doc.gateways.iter().filter(|g| Some(g.id) == gateway).cloned().collect();
        out.insert(None, Node::Connection(c))?;
        Ok(Arc::new(Library { store: None, doc: Mutex::new(out), document: None, counts_dir: None, revoked: Default::default() }))
    }

    /// "Save as a library entry": the connection goes into the plugin entry's folder, named by
    /// the label, with the route shown in the sheet. No credential is copied. Returns its id.
    pub fn plugin_open_save(&self, entry_id: String, protocol: String, host: String, port: u16, label: String, via_entry_route: bool) -> FfiResult<String> {
        let mut doc = self.lock();
        let (c, _) = open_connection(&doc, &entry_id, &protocol, &host, port, &label, via_entry_route)?;
        let parent = doc.parent_of(parse_id(&entry_id)?);
        let id = c.id.to_string();
        doc.insert(parent, Node::Connection(c))?;
        Ok(id)
    }

    /// Save as Connection (plugin API 1.6, `library-propose`): for each sheet row in
    /// `rows_json` (`[{"name","host","protocol"}]`), whether `folder_id` (empty: the top level)
    /// already holds a connection to the same host by the same protocol, or an earlier row does.
    pub fn plugin_propose_duplicates(&self, folder_id: String, rows_json: String) -> FfiResult<Vec<bool>> {
        let rows: Vec<library_save::Row> = serde_json::from_str(&rows_json).map_err(|e| FfiError::failed(e.to_string()))?;
        let folder = opt_id(&folder_id)?;
        Ok(library_save::duplicates(&self.lock(), folder, &rows))
    }

    /// Save as Connection: saves the sheet's rows into `folder_id` (empty: the top level), or
    /// into a new folder `new_folder` made there, skipping duplicates. `credential_id` (empty:
    /// none) is linked by id. Returns `{"ids":[…],"duplicates":[row indexes],"folder":id|null}`.
    pub fn plugin_propose_save(&self, folder_id: String, new_folder: String, rows_json: String, credential_id: String) -> FfiResult<String> {
        let rows: Vec<library_save::Row> = serde_json::from_str(&rows_json).map_err(|e| FfiError::failed(e.to_string()))?;
        let target = library_save::Target { folder: opt_id(&folder_id)?, new_folder: Some(new_folder).filter(|n| !n.trim().is_empty()) };
        let credential = opt_id(&credential_id)?;
        let mut doc = self.lock();
        let saved = library_save::save(&mut doc, &target, &rows, credential).map_err(FfiError::failed)?;
        serde_json::to_string(&saved).map_err(|e| FfiError::failed(e.to_string()))
    }
}

fn opt_id(s: &str) -> FfiResult<Option<uuid::Uuid>> {
    if s.trim().is_empty() { Ok(None) } else { parse_id(s).map(Some) }
}

/// Resolves `host` once and checks every address it returns against the plugin-open address
/// rules. Returns the addresses as IP strings: the app connects to the first that answers and
/// keeps `host` for host-key and certificate checks. Call it for an `open-go` update whose
/// `check_resolved` is true, with its `loopback_ok`, off the main thread.
#[uniffi::export]
pub fn plugin_open_resolve(host: String, port: u16, loopback_ok: bool) -> FfiResult<Vec<String>> {
    resolve_checked(&host, port, loopback_ok).map(|a| a.into_iter().map(|s| s.ip().to_string()).collect()).map_err(failure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_literal_comes_back_and_a_refused_one_fails() {
        assert_eq!(plugin_open_resolve("10.0.0.5".into(), 22, false).unwrap(), vec!["10.0.0.5".to_string()]);
        assert!(plugin_open_resolve("169.254.169.254".into(), 22, false).is_err());
        assert!(plugin_open_resolve("::ffff:127.0.0.1".into(), 22, true).is_err());
    }

    fn lab() -> (Library, String, uuid::Uuid) {
        let mut doc = Document::new("t");
        let gw = bastion_core::gateway::Gateway { id: uuid::Uuid::new_v4(), name: "jump".into(), host: "jump.lab".into(), port: Some(22), username: None, notes: String::new() };
        let gid = gw.id;
        doc.gateways.push(gw);
        let mut folder: bastion_core::model::Folder = serde_json::from_value(serde_json::json!({ "id": uuid::Uuid::new_v4(), "name": "Lab" })).unwrap();
        let mut e = Connection::new("pve", Protocol::Unsupported, "pve.lab");
        e.unknown_protocol = Some("dev.bastion.proxmox/pve".into());
        e.settings.gateway_id = Some(gid);
        let eid = e.id.to_string();
        folder.children.push(Node::Connection(e));
        doc.insert(None, Node::Folder(folder)).unwrap();
        (Library { store: None, doc: Mutex::new(doc), document: None, counts_dir: None, revoked: Default::default() }, eid, gid)
    }

    #[test]
    fn the_open_library_carries_the_entrys_gateway_only_when_asked() {
        let (lib, eid, gid) = lab();
        let via = lib.plugin_open_library(eid.clone(), "ssh".into(), "10.0.0.5".into(), 22, "web".into(), true).unwrap();
        let d = via.lock();
        assert_eq!(d.gateways.iter().map(|g| g.id).collect::<Vec<_>>(), vec![gid]);
        let Node::Connection(c) = &d.root.children[0] else { panic!() };
        assert_eq!((c.host.as_str(), c.settings.port, c.settings.gateway_id), ("10.0.0.5", Some(22), Some(gid)));
        drop(d);
        assert!(via.save().is_err(), "never written");
        let direct = lib.plugin_open_library(eid.clone(), "rdp".into(), "10.0.0.6".into(), 3389, "win".into(), false).unwrap();
        assert!(direct.lock().gateways.is_empty());
        assert!(lib.plugin_open_library(eid.clone(), "telnet".into(), "10.0.0.6".into(), 23, "x".into(), false).is_err());
        assert!(lib.plugin_open_library(eid, "ssh".into(), "0x7f.1".into(), 22, "x".into(), false).is_err());
    }

    #[test]
    fn save_as_entry_lands_beside_the_plugin_entry_without_credentials() {
        let (lib, eid, gid) = lab();
        let id = lib.plugin_open_save(eid.clone(), "ssh".into(), "10.0.0.5".into(), 22, "web".into(), true).unwrap();
        let d = lib.lock();
        let Node::Folder(f) = &d.root.children[0] else { panic!() };
        let saved = f.children.iter().find_map(|n| match n { Node::Connection(c) if c.id.to_string() == id => Some(c), _ => None }).expect("in the entry's folder");
        assert_eq!((saved.name.as_str(), saved.settings.gateway_id), ("web", Some(gid)));
        assert!(saved.settings.credential_id.is_none() && saved.settings.credential_name.is_none());
    }
}
