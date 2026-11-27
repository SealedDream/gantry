//! `library.propose` (plugin API 1.6), app side: what the Save as Connection sheet saves.
//!
//! The core checked the plugin's proposals (`host/view_library.rs`); the user edited them in the
//! sheet. This checks the user's rows again (host syntax and class, name, protocol), skips rows
//! that would duplicate a connection already in the folder (same host and protocol), and saves
//! the rest as normal connections. A saved credential is linked by id only: nothing secret moves.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{Connection, Document, Folder, Node, Protocol};
use crate::plugin::broker::open::{check_class, check_label, parse_host, LoopbackRule, Protocol as ProposeProtocol, RouteChoice};

/// Rows one save takes at most (the core's cap on proposals).
pub const MAX_ROWS: usize = 100;

/// One row of the sheet, as the user left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    pub name: String,
    pub host: String,
    /// `ssh`, `rdp` or `vnc`.
    pub protocol: String,
}

/// Where the rows go: an existing folder (`None` is the library's top level), or a new folder
/// made under `folder`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Target {
    pub folder: Option<Uuid>,
    #[serde(default)]
    pub new_folder: Option<String>,
}

/// What a save did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    /// Ids of the new connections, in row order.
    pub ids: Vec<Uuid>,
    /// Row indexes left out as duplicates.
    pub duplicates: Vec<usize>,
    /// The new folder's id, when one was made.
    pub folder: Option<Uuid>,
}

/// An empty folder named `name`.
pub(crate) fn empty_folder(name: String) -> Folder {
    Folder { id: Uuid::new_v4(), name, color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() }
}

fn protocol_of(p: &str) -> Result<(Protocol, u16), String> {
    match ProposeProtocol::parse(p) {
        Some(ProposeProtocol::Ssh) => Ok((Protocol::Ssh, ProposeProtocol::Ssh.default_port())),
        Some(ProposeProtocol::Rdp) => Ok((Protocol::Rdp, ProposeProtocol::Rdp.default_port())),
        Some(ProposeProtocol::Vnc) => Ok((Protocol::Vnc, ProposeProtocol::Vnc.default_port())),
        None => Err(format!("`{p}` is not SSH, RDP or VNC")),
    }
}

/// A row's host in canonical form, after the same checks a plugin's host gets.
pub fn checked_host(host: &str) -> Result<String, String> {
    let h = parse_host(host.trim()).map_err(|f| f.to_string())?;
    let rule = LoopbackRule { entry_target_loopback: false, entry_direct: false };
    check_class(&h, RouteChoice::Entry, false, &rule).map_err(|f| f.to_string())?;
    Ok(h.canonical())
}

fn children<'a>(doc: &'a Document, folder: Option<Uuid>) -> Option<&'a [Node]> {
    match folder {
        None => Some(&doc.root.children),
        Some(id) => doc.folder(id).map(|f| f.children.as_slice()),
    }
}

/// For each row: whether a connection with the same host and protocol is already directly in
/// `folder`, or earlier in `rows`. Rows whose host does not pass the checks are `false`.
pub fn duplicates(doc: &Document, folder: Option<Uuid>, rows: &[Row]) -> Vec<bool> {
    let existing: Vec<(String, Protocol)> = children(doc, folder)
        .unwrap_or_default()
        .iter()
        .filter_map(|n| match n {
            Node::Connection(c) => Some((c.host.to_ascii_lowercase(), c.protocol)),
            _ => None,
        })
        .collect();
    let mut seen = existing;
    rows.iter()
        .map(|r| {
            let (Ok(h), Ok((p, _))) = (checked_host(&r.host), protocol_of(&r.protocol)) else { return false };
            let dup = seen.iter().any(|(eh, ep)| *eh == h && *ep == p);
            seen.push((h, p));
            dup
        })
        .collect()
}

/// Saves `rows` into `target`, skipping duplicates. Every row is checked before anything is
/// written: one bad row saves nothing. `credential` is linked to every new connection.
pub fn save(doc: &mut Document, target: &Target, rows: &[Row], credential: Option<Uuid>) -> Result<Saved, String> {
    if rows.is_empty() || rows.len() > MAX_ROWS {
        return Err("nothing to save".into());
    }
    if let Some(id) = target.folder {
        if doc.folder(id).is_none() {
            return Err("the folder no longer exists".into());
        }
    }
    let mut checked = Vec::with_capacity(rows.len());
    for (i, r) in rows.iter().enumerate() {
        let n = i + 1;
        let name = r.name.trim();
        check_label(name).map_err(|_| format!("row {n}: the name is empty, too long or holds a character that is not allowed"))?;
        let host = checked_host(&r.host).map_err(|e| format!("row {n}: {e}"))?;
        let (protocol, port) = protocol_of(&r.protocol).map_err(|e| format!("row {n}: {e}"))?;
        checked.push((name.to_string(), host, protocol, port));
    }
    let new_folder = match target.new_folder.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(name) => {
            check_label(name).map_err(|_| "the new folder's name is empty, too long or holds a character that is not allowed".to_string())?;
            Some(name.to_string())
        }
    };
    let dups = match &new_folder {
        Some(_) => duplicates(&Document::new("empty"), None, rows),
        None => duplicates(doc, target.folder, rows),
    };
    let folder = match new_folder {
        Some(name) => {
            let f = empty_folder(name);
            let id = f.id;
            doc.insert(target.folder, Node::Folder(f)).map_err(|e| e.to_string())?;
            Some(id)
        }
        None => target.folder,
    };
    let mut saved = Saved { ids: Vec::new(), duplicates: Vec::new(), folder: if target.new_folder.is_some() { folder } else { None } };
    for (i, (name, host, protocol, port)) in checked.into_iter().enumerate() {
        if dups[i] {
            saved.duplicates.push(i);
            continue;
        }
        let mut c = Connection::new(name, protocol, host);
        c.settings.port = Some(port);
        c.settings.credential_id = credential;
        saved.ids.push(c.id);
        doc.insert(folder, Node::Connection(c)).map_err(|e| e.to_string())?;
    }
    Ok(saved)
}

#[cfg(test)]
#[path = "library_save_tests.rs"]
mod tests;
