//! Portable, versioned export of connections and folders. **Never contains secrets**: documents
//! only reference credentials by id, and any metadata field whose name looks secret is dropped
//! (and reported) before writing. Secret portability is a separate encrypted backup.
//!
//! Exporting is `policy::Action::ExportConfiguration`, which requires user confirmation; callers
//! show [`preview`] first.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::audit::is_sensitive_key;
use crate::error::{CoreError, Result};
use crate::model::{Connection, Document, Folder, Node, Settings};

pub const FORMAT: &str = "bastion-export";
pub const VERSION: u32 = 1;
pub const MAX_IMPORT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportFile {
    pub format: String,
    pub version: u32,
    pub exported_at_unix: u64,
    pub document: Document,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    All,
    /// Selected nodes; a selected folder brings its whole subtree. Ancestors are kept as empty
    /// containers so folder defaults still apply.
    Nodes(BTreeSet<Uuid>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preview {
    pub folders: usize,
    pub connections: usize,
    pub credential_refs: BTreeSet<Uuid>,
    /// Credential names the exported connections use (`Settings::credential_name`), looked up
    /// in the vault when connecting.
    pub credential_names: BTreeSet<String>,
    /// `connection name: metadata key` pairs that will be dropped as possibly secret.
    pub stripped_fields: Vec<String>,
    /// Document-level definitions the export carries because the exported connections need
    /// them (audit DS-01): gateways they connect through, tunnels that run over them, saved
    /// tasks attached to them, and the connection types whose Default Settings they inherit.
    pub gateways: usize,
    pub tunnels: usize,
    pub tasks: usize,
    pub type_defaults: usize,
}

fn select(folder: &Folder, sel: &BTreeSet<Uuid>) -> Option<Folder> {
    if sel.contains(&folder.id) {
        return Some(folder.clone());
    }
    let children: Vec<Node> = folder
        .children
        .iter()
        .filter_map(|n| match n {
            Node::Connection(c) if sel.contains(&c.id) => Some(Node::Connection(c.clone())),
            Node::Connection(_) => None,
            Node::Folder(f) => select(f, sel).map(Node::Folder),
        })
        .collect();
    (!children.is_empty()).then(|| Folder { children, ..folder.clone() })
}

/// Secret-bearing structured settings (audit SP-01). The Wake-on-LAN SecureOn password travels
/// in cleartext on the LAN by design, but it is still a password, so a secret-free export drops
/// it at every inheritance level and reports it like any other stripped field.
fn scrub_settings(s: &mut Settings, owner: &str, p: &mut Preview) {
    if s.wol_secureon.take().is_some() {
        p.stripped_fields.push(format!("{owner}: wol_secureon"));
    }
}

/// What scrubbing removes: secret-free exports drop structured secrets too; an export that
/// carries secrets (protected, see `docfile::export`) keeps them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Scrub {
    structured_secrets: bool,
}

fn scrub(folder: &mut Folder, p: &mut Preview, how: Scrub) {
    p.folders += 1;
    p.credential_refs.extend(folder.defaults.credential_id);
    if how.structured_secrets {
        scrub_settings(&mut folder.defaults, &folder.name, p);
    }
    for n in &mut folder.children {
        match n {
            Node::Folder(f) => scrub(f, p, how),
            Node::Connection(c) => scrub_connection(c, p, how),
        }
    }
}

fn scrub_connection(c: &mut Connection, p: &mut Preview, how: Scrub) {
    p.connections += 1;
    p.credential_refs.extend(c.settings.credential_id);
    if how.structured_secrets {
        scrub_settings(&mut c.settings, &c.name, p);
    }
    // Inline secrets stay in this computer's vault; the marker would point at nothing.
    c.metadata.remove(crate::model::INLINE_CREDENTIAL_KEY);
    let secret_keys: Vec<String> = c.metadata.keys().filter(|k| is_sensitive_key(k)).cloned().collect();
    for k in secret_keys {
        c.metadata.remove(&k);
        p.stripped_fields.push(format!("{}: {k}", c.name));
    }
}

/// Build the exported document and its preview without writing anything. Secret-free: every
/// secret-bearing field is stripped and listed in `Preview::stripped_fields`.
pub fn prepare(doc: &Document, selection: &Selection) -> (Document, Preview) {
    prepare_with(doc, selection, false)
}

/// [`prepare`], except that `keep_structured_secrets` keeps structured secrets such as the
/// SecureOn password. Only `docfile::export` passes `true`, and only for a password-protected
/// export that includes secrets (the same gate credentials go through).
pub(crate) fn prepare_with(doc: &Document, selection: &Selection, keep_structured_secrets: bool) -> (Document, Preview) {
    let how = Scrub { structured_secrets: !keep_structured_secrets };
    let mut root = match selection {
        Selection::All => doc.root.clone(),
        Selection::Nodes(ids) => select(&doc.root, ids).unwrap_or_else(|| Folder { children: vec![], ..doc.root.clone() }),
    };
    // Entries of a type this app does not know, and unknown fields, never leave the library:
    // they cannot be checked for secrets (PLUG-03a).
    crate::unknown::strip_folder(&mut root);
    // A dynamic folder's binding is local to this library and never travels (B15, C8).
    crate::dynfolder::strip(&mut root);
    let mut p = Preview::default();
    scrub(&mut root, &mut p, how);
    p.folders -= 1; // the root is not a user folder
    let mut exported = match selection {
        Selection::All => Document { root, revision: 0, ..doc.clone() },
        Selection::Nodes(_) => with_dependencies(doc, root),
    };
    // Recently Deleted never leaves the library (B10).
    exported.deleted.clear();
    crate::unknown::strip_document(&mut exported);
    if how.structured_secrets {
        for (protocol, s) in exported.type_defaults.iter_mut() {
            scrub_settings(s, &format!("{protocol:?} defaults"), &mut p);
        }
    }
    // What each exported connection actually connects with, through every inheritance level
    // including the type's Default Settings (which the tree walk above does not see).
    for r in exported.connections() {
        match crate::properties::effective_credential(&exported, r.connection.id) {
            Ok(Some((crate::properties::CredentialRef::Id(id), _, _))) => {
                p.credential_refs.insert(id);
            }
            Ok(Some((crate::properties::CredentialRef::Name(name), _, _))) => {
                p.credential_names.insert(name);
            }
            _ => {}
        }
    }
    p.gateways = exported.gateways.len();
    p.tunnels = exported.tunnels.len();
    p.tasks = exported.tasks.len();
    p.type_defaults = exported.type_defaults.len();
    (exported, p)
}

/// A selected-node export: the selected tree plus only the document-level definitions it needs
/// (audit DS-01). Unrelated tasks, hooks, gateways, tunnels, type defaults and the user's
/// built-in task favourites stay behind, so exporting one customer's connection never carries
/// another customer's configuration.
fn with_dependencies(doc: &Document, root: Folder) -> Document {
    let mut exported = Document { root, revision: 0, type_defaults: Default::default(), gateways: vec![], tunnels: vec![], tasks: vec![], favorite_builtin_tasks: vec![], task_hooks: vec![], templates: vec![], ..doc.clone() };
    // Resolve against the source document so type defaults still count as inherited.
    let resolved: Vec<_> = exported.connections().iter().filter_map(|r| doc.resolve(r.connection.id).ok()).collect();
    let ids: BTreeSet<Uuid> = resolved.iter().map(|r| r.connection.id).collect();
    let protocols: BTreeSet<_> = resolved.iter().map(|r| r.connection.protocol).collect();
    let gateway_ids: BTreeSet<Uuid> = resolved.iter().filter_map(|r| r.effective.gateway_id).collect();
    exported.type_defaults = doc.type_defaults.iter().filter(|(p, _)| protocols.contains(p)).map(|(p, s)| (*p, s.clone())).collect();
    exported.gateways = doc.gateways.iter().filter(|g| gateway_ids.contains(&g.id)).cloned().collect();
    exported.tunnels = doc.tunnels.iter().filter(|t| ids.contains(&t.via)).cloned().collect();
    exported.task_hooks = doc.task_hooks.iter().filter(|h| ids.contains(&h.connection_id)).cloned().collect();
    let task_ids: BTreeSet<Uuid> = exported.task_hooks.iter().map(|h| h.task_id).collect();
    exported.tasks = doc.tasks.iter().filter(|t| task_ids.contains(&t.id)).cloned().collect();
    exported
}

pub fn preview(doc: &Document, selection: &Selection) -> Preview {
    prepare(doc, selection).1
}

pub fn export(doc: &Document, selection: &Selection) -> Result<Vec<u8>> {
    let (document, _) = prepare(doc, selection);
    let exported_at_unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let file = ExportFile { format: FORMAT.into(), version: VERSION, exported_at_unix, document };
    serde_json::to_vec_pretty(&file).map_err(|e| CoreError::Invalid(e.to_string()))
}

/// Upgrade an older export to the current version. Version 1 is the first released format, so
/// there are no steps yet; each future version adds one `n → n+1` step here.
/// The two top-level fields that say what a file is. Everything else is skipped, not built.
#[derive(Deserialize)]
struct Head {
    #[serde(default)]
    format: Option<serde_json::Value>,
    #[serde(default)]
    version: Option<serde_json::Value>,
}

/// Parse an export (untrusted input). Imported documents get fresh secret-free metadata checks.
pub fn import(bytes: &[u8]) -> Result<Document> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(CoreError::Invalid(format!("export is larger than {MAX_IMPORT_BYTES} bytes")));
    }
    let head: Head = serde_json::from_slice(bytes).map_err(|e| CoreError::Invalid(format!("not a Gantry export: {e}")))?;
    if head.format.as_ref().and_then(|f| f.as_str()) != Some(FORMAT) {
        return Err(CoreError::Invalid("not a Gantry export (missing format marker)".into()));
    }
    let version = head.version.as_ref().and_then(|v| v.as_u64()).ok_or_else(|| CoreError::Invalid("export has no version".into()))?;
    let version = u32::try_from(version).map_err(|_| CoreError::Invalid("bad export version".into()))?;
    match version {
        VERSION => {}
        v if v > VERSION => return Err(CoreError::Invalid(format!("export version {v} is newer than this app supports ({VERSION})"))),
        v => return Err(CoreError::Invalid(format!("unknown export version {v}"))),
    }
    // Read like a library (`unknown::reading`): straight from the bytes, on a thread with a
    // known stack and under the limit for a whole library. This is the most untrusted file the
    // core reads. No JSON tree of the file is built (it would also sort the keys, which puts
    // every node on the slower road of `model::Node`).
    let file: ExportFile = crate::unknown::reading(|| serde_json::from_slice(bytes)).map_err(|e| e.or_else(|e| CoreError::Invalid(format!("invalid export: {e}"))))?;
    let (mut doc, _) = prepare(&file.document, &Selection::All);
    // Every credential reference in the file is the sender's choice, not yet the user's.
    crate::logins::mark_received(&mut doc.root);
    doc.type_defaults.values_mut().for_each(crate::logins::mark_settings);
    Ok(doc)
}
