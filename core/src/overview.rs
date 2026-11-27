//! Folder overview (DASH-01): one row per object in a folder, for the folder dashboard every
//! app shows when a folder is selected. A row says what the object is, where it points, who it
//! logs in as and whether a login is available for it. It never holds a secret, a credential id
//! or anything from an inline secret.
//!
//! "Connected" is not here: each app knows its live sessions and adds that column.
//!
//! The library is walked once. User, port and host colour are inherited on the way down. The
//! login state comes from [`logins::login_candidates`], so the rules stay in one place; it is
//! asked per connection on a copy of the library cut down to the connections on the same host
//! ([`host_copy`]), because asking it on the whole library walks every connection for every row.
use std::collections::{BTreeMap, HashMap};

use uuid::Uuid;

use crate::connection_history::History;
use crate::icons::{self, Icon};
use crate::logins::{self, LoginPurpose, LoginSource};
use crate::model::{Connection, Document, Folder, Node, Protocol, Settings, INLINE_CREDENTIAL_KEY};
use crate::properties::{effective_credential_with_ancestors, ValueSource};
use crate::vault::Vault;
use crate::{CoreError, Result};

/// What the root folder is called where a login is inherited from it, as in
/// `properties::effective_credential`.
const ROOT_NAME: &str = "Library";
const FOLDER_LABEL: &str = "Folder";
const FOLDER_ICON: &str = "folder";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowKind {
    Connection,
    Folder,
}

/// Whether a login is available for a connection, and where it comes from. Names only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginState {
    None,
    /// The connection's own: its default or another saved login, the credential it names, or
    /// its inline secret.
    Saved,
    /// From the folder `from` ("Library" for the root, "rdp default" for the type's defaults).
    Inherited { from: String },
    /// Saved for the connection `from` on the same host. Only offered: the user confirms it.
    Offered { from: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct OverviewRow {
    pub id: Uuid,
    pub kind: RowKind,
    pub name: String,
    /// Host, `host:port` when the port is not the type's default, or the URL. Empty for a folder.
    pub address: String,
    /// `None` for a folder and for an entry of a type this app does not know.
    pub protocol: Option<Protocol>,
    /// "SSH Terminal", "Folder", or the stored type name of an unknown type (untrusted text).
    pub type_label: String,
    /// The user it connects as: its own, else inherited. Never a secret.
    pub username: Option<String>,
    pub login: LoginState,
    /// Unix seconds of the last successful connect.
    pub last_connected_at: Option<u64>,
    /// "OK", a short one-line error, or `None` before the first attempt.
    pub last_result: Option<String>,
    pub tags: Vec<String>,
    /// Folder names from the folder shown down to the row's parent; empty for a direct child.
    pub folder_path: Vec<String>,
    pub favorite: bool,
    /// The effective host accent, `#rrggbb`.
    pub host_color: Option<String>,
    pub icon: Icon,
}

/// The rows of `folder` (the root's id for the whole library).
///
/// Without `include_subfolders`: its direct connections, then its direct folders. With it:
/// every connection below, in tree order, each with its `folder_path`, and no folder rows.
///
/// `vault` is `None` while credentials are locked. The login state is then read from the
/// document alone (`Saved`, `Inherited` or `None`) and nothing is offered from another
/// connection, since only the vault knows which credentials still exist.
pub fn folder_overview(doc: &Document, vault: Option<&Vault>, history: &BTreeMap<Uuid, History>, folder: Uuid, include_subfolders: bool) -> Result<Vec<OverviewRow>> {
    let mut walk = Walk::new(doc, history, folder, include_subfolders, vault.is_some());
    walk.folder(&doc.root, None, Inherited::default(), None);
    if !walk.found {
        return Err(CoreError::NotFound(folder.to_string()));
    }
    let Walk { mut rows, folder_rows, pending, folders, by_host, .. } = walk;
    if let Some(vault) = vault {
        let mut copies: HashMap<&str, Document> = HashMap::new();
        for p in &pending {
            let alone;
            let copy = match p.host.as_deref() {
                Some(host) => &*copies.entry(host).or_insert_with(|| host_copy(doc, &folders, by_host.get(host).map_or(&[][..], Vec::as_slice))),
                None => {
                    alone = host_copy(doc, &folders, &[p.entry]);
                    &alone
                }
            };
            rows[p.row].login = login_from_vault(doc, copy, vault, p.entry.connection)?;
        }
    }
    rows.extend(folder_rows);
    Ok(rows)
}

/// The three settings a row shows that a connection can inherit.
#[derive(Clone, Copy, Default)]
struct Inherited<'a> {
    port: Option<u16>,
    username: Option<&'a str>,
    host_color: Option<&'a str>,
}

impl<'a> Inherited<'a> {
    fn of(s: &'a Settings) -> Inherited<'a> {
        Inherited { port: s.port, username: s.username.as_deref(), host_color: s.host_color.as_deref() }
    }

    /// These values, each falling back to `further` when unset, as `Settings::inherit_from`.
    fn or(self, further: Inherited<'a>) -> Inherited<'a> {
        Inherited { port: self.port.or(further.port), username: self.username.or(further.username), host_color: self.host_color.or(further.host_color) }
    }
}

/// A connection and the folder it is in (an index into `Walk::folders`).
#[derive(Clone, Copy)]
struct Entry<'a> {
    connection: &'a Connection,
    folder: usize,
}

/// A row whose login the vault is still to be asked about.
struct Pending<'a> {
    row: usize,
    entry: Entry<'a>,
    /// The host as compared for sharing; `None` when the connection has none and so shares
    /// with nobody.
    host: Option<String>,
}

struct Walk<'a> {
    doc: &'a Document,
    history: &'a BTreeMap<Uuid, History>,
    target: Uuid,
    deep: bool,
    unlocked: bool,
    found: bool,
    /// The folders from the root down to the one being visited.
    chain: Vec<&'a Folder>,
    /// Every folder visited, with the index of its parent.
    folders: Vec<(&'a Folder, Option<usize>)>,
    /// Every connection of the library by host, in tree order. Filled only when unlocked.
    by_host: HashMap<String, Vec<Entry<'a>>>,
    rows: Vec<OverviewRow>,
    folder_rows: Vec<OverviewRow>,
    pending: Vec<Pending<'a>>,
}

impl<'a> Walk<'a> {
    fn new(doc: &'a Document, history: &'a BTreeMap<Uuid, History>, target: Uuid, deep: bool, unlocked: bool) -> Walk<'a> {
        Walk {
            doc,
            history,
            target,
            deep,
            unlocked,
            found: false,
            chain: Vec::new(),
            folders: Vec::new(),
            by_host: HashMap::new(),
            rows: Vec::new(),
            folder_rows: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// Visit `f`. `shown_at` is the length of `chain` at the folder shown, once inside it.
    fn folder(&mut self, f: &'a Folder, parent: Option<usize>, above: Inherited<'a>, shown_at: Option<usize>) {
        let index = self.folders.len();
        self.folders.push((f, parent));
        self.chain.push(f);
        let shown_at = shown_at.or_else(|| (f.id == self.target).then_some(self.chain.len()));
        self.found |= shown_at.is_some();
        let is_shown = shown_at == Some(self.chain.len());
        let here = Inherited::of(&f.defaults).or(above);
        for child in &f.children {
            match child {
                Node::Folder(sub) => {
                    if is_shown && !self.deep {
                        self.folder_rows.push(folder_row(sub));
                    }
                    self.folder(sub, Some(index), here, shown_at);
                }
                Node::Connection(c) => self.connection(c, index, here, shown_at.filter(|_| self.deep || is_shown)),
            }
        }
        self.chain.pop();
    }

    /// Index `c` by host and, when it is in the folder shown (`shown_at`), add its row.
    fn connection(&mut self, c: &'a Connection, folder: usize, above: Inherited<'a>, shown_at: Option<usize>) {
        let entry = Entry { connection: c, folder };
        let host = self.unlocked.then(|| logins::normalize_host(&c.host)).filter(|h| !h.is_empty());
        if let Some(h) = &host {
            self.by_host.entry(h.clone()).or_default().push(entry);
        }
        let Some(shown_at) = shown_at else { return };
        let login = if c.protocol == Protocol::Unsupported {
            // Nothing connects to an entry of an unknown type, so no login is shown for it.
            LoginState::None
        } else if c.metadata.contains_key(INLINE_CREDENTIAL_KEY) {
            // Its own secret, which is never listed as a login: the marker is all there is to read.
            LoginState::Saved
        } else if self.unlocked {
            self.pending.push(Pending { row: self.rows.len(), entry, host });
            LoginState::None
        } else {
            login_from_document(self.doc, &self.chain, c)
        };
        let path = self.chain[shown_at..].iter().map(|f| f.name.clone()).collect();
        self.rows.push(connection_row(self.doc, self.history.get(&c.id), c, above, login, path));
    }
}

fn folder_row(f: &Folder) -> OverviewRow {
    OverviewRow {
        id: f.id,
        kind: RowKind::Folder,
        name: f.name.clone(),
        address: String::new(),
        protocol: None,
        type_label: FOLDER_LABEL.into(),
        username: None,
        login: LoginState::None,
        last_connected_at: None,
        last_result: None,
        tags: Vec::new(),
        folder_path: Vec::new(),
        favorite: false,
        host_color: None,
        icon: icons::by_id(FOLDER_ICON).unwrap_or(Icon { id: FOLDER_ICON, label: FOLDER_LABEL, tint: icons::Tint::Folder }),
    }
}

/// Precedence as in `Document::resolve`: connection, nearest folder … root, type defaults.
fn connection_row(doc: &Document, history: Option<&History>, c: &Connection, above: Inherited, login: LoginState, folder_path: Vec<String>) -> OverviewRow {
    let known = c.protocol != Protocol::Unsupported;
    let type_defaults = doc.type_defaults.get(&c.protocol).map(Inherited::of).unwrap_or_default();
    let effective = Inherited::of(&c.settings).or(above).or(type_defaults);
    let icon = icons::for_protocol(c.protocol);
    OverviewRow {
        id: c.id,
        kind: RowKind::Connection,
        name: c.name.clone(),
        address: crate::actions::address(&c.host, effective.port, c.protocol.default_port()),
        protocol: known.then_some(c.protocol),
        type_label: if known { icon.label.to_string() } else { c.protocol_name().to_string() },
        username: effective.username.filter(|u| !u.is_empty()).map(str::to_string),
        login,
        last_connected_at: history.and_then(|h| h.last_connected_at),
        last_result: history.and_then(|h| h.last_result()).map(str::to_string),
        tags: c.tags.clone(),
        folder_path,
        favorite: c.favorite,
        host_color: effective.host_color.and_then(|v| crate::hostcolors::derive(v).ok()).map(|h| h.accent),
        icon,
    }
}

/// The login state while credentials are locked: what the ids and names in the document say,
/// without knowing whether those credentials still exist. `chain` is the connection's folders,
/// root first.
fn login_from_document(doc: &Document, chain: &[&Folder], c: &Connection) -> LoginState {
    match effective_credential_with_ancestors(doc, chain, c) {
        Some((_, ValueSource::Own, _)) => LoginState::Saved,
        _ if !c.settings.logins.is_empty() => LoginState::Saved,
        Some((_, ValueSource::TypeDefault, _)) => LoginState::Inherited { from: format!("{} default", c.protocol.as_str()) },
        Some((_, _, from)) => LoginState::Inherited { from: from.unwrap_or_default() },
        None => LoginState::None,
    }
}

/// The login state from the first login `login_candidates` gives `c` in `copy`, its
/// [`host_copy`]. RDP takes a password itself, so an SSH key is no login for it.
fn login_from_vault(doc: &Document, copy: &Document, vault: &Vault, c: &Connection) -> Result<LoginState> {
    let purpose = if c.protocol == Protocol::Rdp { LoginPurpose::Password } else { LoginPurpose::Any };
    let first = logins::login_candidates(copy, vault, c.id, purpose)?.into_iter().next();
    Ok(match first.map(|candidate| candidate.source) {
        None => LoginState::None,
        Some(LoginSource::Default | LoginSource::Connection | LoginSource::Named) => LoginState::Saved,
        Some(LoginSource::Inherited { folder, name }) => LoginState::Inherited { from: if folder == Some(doc.root.id) { ROOT_NAME.into() } else { name } },
        Some(LoginSource::SameHost { name, .. }) => LoginState::Offered { from: name },
    })
}

/// A copy of the library holding only `group` (connections in tree order) and the folders
/// above them, with every folder's own settings and the type defaults.
///
/// `login_candidates` gives a connection the same answer here as on the whole library when
/// `group` is every connection with its host: what it reads is the connection, its folders,
/// the type defaults, and the other connections on that host. The test
/// `login_state_is_what_login_candidates_says_first_on_the_whole_library` holds it to that.
fn host_copy(doc: &Document, folders: &[(&Folder, Option<usize>)], group: &[Entry]) -> Document {
    let mut root = bare_folder(&doc.root);
    let mut below_root = Vec::new();
    for entry in group {
        below_root.clear();
        let mut at = entry.folder;
        while let Some(&(folder, Some(parent))) = folders.get(at) {
            below_root.push(folder);
            at = parent;
        }
        below_root.reverse();
        folder_in_copy(&mut root, &below_root).children.push(Node::Connection(entry.connection.clone()));
    }
    Document {
        schema: doc.schema,
        id: doc.id,
        name: String::new(),
        revision: doc.revision,
        root,
        type_defaults: doc.type_defaults.clone(),
        gateways: Vec::new(),
        tunnels: Vec::new(),
        tasks: Vec::new(),
        favorite_builtin_tasks: Vec::new(),
        task_hooks: Vec::new(),
        templates: Vec::new(),
        deleted: Vec::new(),
        extra: Default::default(),
    }
}

/// `f` without its children.
fn bare_folder(f: &Folder) -> Folder {
    Folder { id: f.id, name: f.name.clone(), color: None, defaults: f.defaults.clone(), children: Vec::new(), dynamic_task_id: None, extra: Default::default() }
}

/// The copy of the folder at the end of `path` (folders below `here`, outermost first), added
/// with any folder on the way that the copy does not have yet. Connections arrive in tree
/// order, so a folder met again is still the last child of its parent.
fn folder_in_copy<'t>(here: &'t mut Folder, path: &[&Folder]) -> &'t mut Folder {
    let Some((first, rest)) = path.split_first() else { return here };
    if !matches!(here.children.last(), Some(Node::Folder(last)) if last.id == first.id) {
        here.children.push(Node::Folder(bare_folder(first)));
    }
    match here.children.last_mut() {
        Some(Node::Folder(next)) => folder_in_copy(next, rest),
        _ => unreachable!("the last child is the folder just checked or added"),
    }
}

#[cfg(test)]
#[path = "overview_tests.rs"]
mod tests;
