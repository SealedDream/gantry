//! Central command registry: which actions exist for each object type, in which order and
//! section, and whether each is available for a given object state, backend capability and
//! security policy. Frontends render the result as native menus (context menu, inspector
//! overflow, menu bar) and never hard-code their own lists.
//!
//! An action is listed only when (a) the core implements it, (b) it applies to
//! the object's type and state, and (c) the frontend says it has a handler for it. Anything else
//! is hidden; `catalogue` reports why, so documentation never claims a missing feature works.
//! Keyboard shortcuts are not part of the registry: each platform maps action ids to its own
//! native key equivalents.
use serde::{Deserialize, Serialize};

use uuid::Uuid;

use crate::logins::{self, LoginPurpose};
use crate::model::{Connection, Document, Folder, Node, Protocol};
use crate::policy::Policy;
use crate::vault::{CredentialKind, Vault};
use crate::{CoreError, Result};

/// Kind of object a menu is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectKind {
    Folder,
    Connection,
}

/// Live session state of a connection, as the frontend's open tabs report it. Never guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionState {
    #[default]
    Closed,
    Connecting,
    Connected,
    /// The last session ended (error or remote close) and its tab is still open.
    Failed,
}

/// Stable action ids. Frontends switch on these to find their handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionId {
    // Session
    Connect,
    ConnectNewTab,
    ConnectNewWindow,
    ConnectWithOptions,
    FullScreen,
    Disconnect,
    Reconnect,
    OpenSftp,
    ConnectAs,
    ReconnectAs,
    OpenViaGateway,
    RunTask,
    // Clipboard
    CopySshCommand,
    CopyHostname,
    CopyUsername,
    CopyAddress,
    // Folder content
    NewConnection,
    NewSubfolder,
    ConnectAll,
    DisconnectAll,
    ReconnectAll,
    ExpandAll,
    CollapseAll,
    Sort,
    Import,
    Export,
    // Organisation
    Rename,
    Duplicate,
    SaveAsTemplate,
    Move,
    Copy,
    ToggleFavorite,
    CustomizeAppearance,
    AddToWorkspace,
    Properties,
    Delete,
}

impl ActionId {
    /// Wire name (`copy-ssh-command`).
    pub fn as_str(self) -> String {
        serde_json::to_string(&self).unwrap_or_default().trim_matches('"').to_string()
    }

    pub fn parse(s: &str) -> Option<ActionId> {
        serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
    }
}

/// Everything the registry needs to know about one object.
#[derive(Debug, Clone, Default)]
pub struct ActionContext {
    pub kind: Option<ObjectKind>,
    /// Connections: their type.
    pub protocol: Option<Protocol>,
    pub session: SessionState,
    pub favorite: bool,
    pub has_username: bool,
    /// Connections: classified sensitive (production, customer, privileged); deletes say so.
    pub sensitive: bool,
    /// Folders: the library root (cannot be renamed, moved, duplicated or deleted).
    pub is_root: bool,
    /// Folders: number of connections anywhere below.
    pub descendant_connections: u32,
    /// Folders: number of folders anywhere below.
    pub descendant_folders: u32,
    /// Folders: open sessions of connections anywhere below.
    pub open_sessions: u32,
}

/// One rendered menu entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MenuItem {
    pub id: ActionId,
    pub label: String,
    /// Generic action glyph name (`copy`, `trash`, …) or an `icons` id; the frontend maps it.
    pub glyph: &'static str,
    /// Items with different sections are separated by a divider.
    pub section: u8,
    pub enabled: bool,
    /// Short reason shown as a tooltip when disabled.
    pub disabled_reason: Option<String>,
    pub destructive: bool,
    /// Confirmation text the frontend must show (and get a yes for) before running it.
    pub confirm: Option<String>,
    /// The object's default action (double-click, inspector primary button).
    pub primary: bool,
}

/// Where an action's implementation stands: for documentation and the feature matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    /// Implemented in the core (or entirely by the frontend, e.g. clipboard copies).
    Implemented,
    /// Not implemented anywhere yet; the text says what is missing. Never shown in menus.
    Missing(&'static str),
}

struct Def {
    id: ActionId,
    kinds: &'static [ObjectKind],
    section: u8,
    glyph: &'static str,
    backend: Backend,
}

use ActionId::*;
use ObjectKind::*;

const F: &[ObjectKind] = &[Folder];
const C: &[ObjectKind] = &[Connection];
const FC: &[ObjectKind] = &[Folder, Connection];

const fn d(id: ActionId, kinds: &'static [ObjectKind], section: u8, glyph: &'static str, backend: Backend) -> Def {
    Def { id, kinds, section, glyph, backend }
}

const IMPL: Backend = Backend::Implemented;

/// Display order of every action. Sections: 0 session, 1 open-as, 2 clipboard, 3 create,
/// 4 bulk session, 5 view, 6 organise, 7 properties, 10 destructive.
const REGISTRY: &[Def] = &[
    d(Connect, C, 0, "connect", IMPL),
    d(ConnectNewTab, C, 0, "tab", IMPL),
    d(ConnectNewWindow, C, 0, "window", Backend::Missing("sessions live in one window")),
    d(ConnectWithOptions, C, 0, "options", Backend::Missing("per-connect option overrides")),
    d(FullScreen, C, 0, "fullscreen", IMPL),
    d(Reconnect, C, 0, "reconnect", IMPL),
    d(Disconnect, C, 0, "disconnect", IMPL),
    d(OpenSftp, C, 1, "sftp", IMPL),
    d(ConnectAs, C, 1, "credential", IMPL),
    d(ReconnectAs, C, 1, "reconnect", IMPL),
    d(OpenViaGateway, C, 1, "gateway", Backend::Missing("gateways")),
    d(RunTask, C, 1, "task", Backend::Missing("task engine")),
    d(CopySshCommand, C, 2, "copy", IMPL),
    d(CopyHostname, C, 2, "copy", IMPL),
    d(CopyUsername, C, 2, "copy", IMPL),
    d(CopyAddress, C, 2, "copy", IMPL),
    d(NewConnection, F, 3, "add", IMPL),
    d(NewSubfolder, F, 3, "folder-add", IMPL),
    d(ConnectAll, F, 4, "connect", IMPL),
    d(DisconnectAll, F, 4, "disconnect", IMPL),
    d(ReconnectAll, F, 4, "reconnect", IMPL),
    d(ExpandAll, F, 5, "expand", IMPL),
    d(CollapseAll, F, 5, "collapse", IMPL),
    d(Sort, F, 5, "sort", IMPL),
    d(Import, F, 5, "import", Backend::Missing("import into a chosen folder")),
    d(Export, F, 5, "export", Backend::Missing("export of a single folder")),
    d(Rename, FC, 6, "rename", IMPL),
    d(Duplicate, FC, 6, "duplicate", IMPL),
    d(SaveAsTemplate, C, 6, "template", IMPL),
    d(Move, FC, 6, "move", IMPL),
    d(Copy, FC, 6, "copy", Backend::Missing("tree clipboard (copy and paste)")),
    d(ToggleFavorite, C, 6, "favorite", IMPL),
    d(CustomizeAppearance, FC, 6, "appearance", Backend::Missing("custom icon and colour editor")),
    d(AddToWorkspace, C, 6, "workspace", IMPL),
    d(Properties, FC, 7, "properties", IMPL),
    d(Delete, FC, 10, "trash", IMPL),
];

/// Connection types that open a session in the apps today.
pub fn connects(p: Protocol) -> bool {
    matches!(p, Protocol::Ssh | Protocol::Rdp | Protocol::Vnc | Protocol::Web | Protocol::Sftp | Protocol::Scp | Protocol::Ftps | Protocol::Local | Protocol::Services | Protocol::Processes | Protocol::EventLog)
}

/// Types with Connect, Reconnect and a primary action: `connects`, plus Telnet and Serial (B7), which
/// the apps open in their own terminal tab. Connect All still leaves Telnet and Serial out (no
/// sign-in sheet or saved-login path for them there; a serial port is one device, not a fleet).
pub fn opens_session(p: Protocol) -> bool {
    connects(p) || matches!(p, Protocol::Telnet | Protocol::Serial)
}

/// Whether the action applies to this object's type and state (hidden otherwise).
fn applies(id: ActionId, cx: &ActionContext) -> bool {
    let p = cx.protocol;
    match id {
        Connect | ConnectNewTab | Reconnect | Disconnect => p.map_or(false, opens_session),
        FullScreen => matches!(p, Some(Protocol::Rdp | Protocol::Vnc)),
        // Workspaces restore terminal and files tabs, which only SSH connections open.
        OpenSftp | CopySshCommand | AddToWorkspace | ConnectAs | ReconnectAs => p == Some(Protocol::Ssh),
        // An entry of a type this app does not know (PLUG-03a) can be renamed, moved and
        // deleted; nothing reads its address or copies it.
        CopyHostname | CopyAddress => p.is_some_and(|p| p != Protocol::Unsupported),
        CopyUsername => p.map_or(false, |p| p != Protocol::Web && p != Protocol::Unsupported),
        Duplicate => !cx.is_root && p != Some(Protocol::Unsupported),
        SaveAsTemplate => p.is_some_and(|p| p != Protocol::Unsupported),
        Rename | Move | Delete => !cx.is_root,
        ExpandAll | CollapseAll => cx.descendant_folders > 0,
        _ => true,
    }
}

/// Enabled state and the reason when disabled, for an applicable action.
fn availability(id: ActionId, cx: &ActionContext, policy: &Policy) -> (bool, Option<String>) {
    // Telnet: only the administrator's policy disables the item. The user's own Allow Telnet switch is
    // checked when connecting (`policy::with_user_telnet`), which says how to turn it on.
    let blocked = cx.protocol.and_then(|p| match p {
        Protocol::Telnet => policy.check_protocol(Protocol::Telnet).err().filter(|_| !crate::policy::telnet_allowed(true, &Ok(policy.clone()))),
        p => policy.check_protocol(p).err(),
    }).map(|e| e.to_string());
    let open = matches!(cx.session, SessionState::Connected | SessionState::Connecting);
    match id {
        Connect | ConnectNewTab | Reconnect | FullScreen | OpenSftp | ConnectAs | ReconnectAs if blocked.is_some() => (false, blocked),
        Disconnect if !open => (false, Some("Not connected".into())),
        Reconnect | ReconnectAs if !matches!(cx.session, SessionState::Connected | SessionState::Failed) => (false, Some("No session to reconnect".into())),
        FullScreen if !open => (false, Some("Connect first".into())),
        CopyUsername if !cx.has_username => (false, Some("No username set".into())),
        ConnectAll if cx.descendant_connections == 0 => (false, Some("No connections in this folder".into())),
        DisconnectAll | ReconnectAll if cx.open_sessions == 0 => (false, Some("No open sessions in this folder".into())),
        Sort if cx.descendant_connections + cx.descendant_folders < 2 => (false, Some("Nothing to sort".into())),
        _ => (true, None),
    }
}

fn label(id: ActionId, cx: &ActionContext) -> &'static str {
    match id {
        Connect if cx.session == SessionState::Connected => "Show Session",
        Connect => "Connect",
        ConnectNewTab => "Connect in New Tab",
        ConnectNewWindow => "Connect in New Window",
        ConnectWithOptions => "Connect with Options…",
        FullScreen => "Full Screen",
        Disconnect => "Disconnect",
        Reconnect => "Reconnect",
        OpenSftp => "Open SFTP",
        ConnectAs => "Connect as…",
        ReconnectAs => "Reconnect as…",
        OpenViaGateway => "Open via Gateway…",
        RunTask => "Run Task…",
        CopySshCommand => "Copy SSH Command",
        CopyHostname => "Copy Hostname",
        CopyUsername => "Copy Username",
        CopyAddress => "Copy Address",
        NewConnection => "New Connection…",
        NewSubfolder => "New Subfolder…",
        ConnectAll => "Connect All",
        DisconnectAll => "Disconnect All",
        ReconnectAll => "Reconnect All",
        ExpandAll => "Expand All",
        CollapseAll => "Collapse All",
        Sort => "Sort by Name",
        Import => "Import…",
        Export => "Export…",
        Rename => "Rename",
        Duplicate => "Duplicate",
        SaveAsTemplate => "Save as Template…",
        Move => "Move to…",
        Copy => "Copy",
        ToggleFavorite if cx.favorite => "Remove from Favorites",
        ToggleFavorite => "Add to Favorites",
        CustomizeAppearance => "Customize Appearance…",
        AddToWorkspace => "Add to Workspace",
        Properties => "Properties…",
        Delete => "Delete…",
    }
}

fn confirmation(id: ActionId, cx: &ActionContext) -> Option<String> {
    match id {
        Delete if cx.kind == Some(Folder) => Some(match cx.descendant_connections {
            0 => "Delete this folder?".into(),
            1 => "Delete this folder and the connection in it?".into(),
            n => format!("Delete this folder and the {n} connections in it?"),
        }),
        Delete if cx.sensitive => Some("Delete this connection? It is classified as sensitive.".into()),
        Delete => Some("Delete this connection?".into()),
        DisconnectAll if cx.open_sessions > 1 => Some(format!("Close {} sessions?", cx.open_sessions)),
        _ => None,
    }
}

/// The default action for double-click and the inspector's primary button.
pub fn default_action(cx: &ActionContext) -> Option<ActionId> {
    match cx.kind? {
        Connection if cx.protocol.map_or(false, opens_session) => Some(Connect),
        Connection => Some(Properties),
        _ => None,
    }
}

fn backend_ok(def: &Def) -> bool {
    matches!(def.backend, Backend::Implemented)
}

/// Menu entries for one object, in display order. `handled` lists the actions the calling
/// frontend has handlers for; everything else is left out.
pub fn menu(cx: &ActionContext, policy: &Policy, handled: &[ActionId]) -> Vec<MenuItem> {
    let Some(kind) = cx.kind else { return vec![] };
    let primary = default_action(cx);
    REGISTRY
        .iter()
        .filter(|def| def.kinds.contains(&kind) && backend_ok(def) && handled.contains(&def.id) && applies(def.id, cx))
        .map(|def| {
            let (enabled, disabled_reason) = availability(def.id, cx, policy);
            MenuItem {
                id: def.id,
                label: label(def.id, cx).to_string(),
                glyph: def.glyph,
                section: def.section,
                enabled,
                disabled_reason,
                destructive: def.id == Delete,
                confirm: confirmation(def.id, cx),
                primary: primary == Some(def.id),
            }
        })
        .collect()
}

/// One registry row for documentation: an action an object kind can have, and whether it is
/// implemented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Availability {
    pub id: ActionId,
    pub label: &'static str,
    pub backend: Backend,
}

pub fn catalogue(kind: ObjectKind) -> Vec<Availability> {
    let cx = ActionContext { kind: Some(kind), ..Default::default() };
    REGISTRY
        .iter()
        .filter(|def| def.kinds.contains(&kind))
        .map(|def| Availability { id: def.id, label: label(def.id, &cx), backend: def.backend })
        .collect()
}

/// Every action id, in registry order.
pub fn all_ids() -> Vec<ActionId> {
    REGISTRY.iter().map(|d| d.id).collect()
}

/// Connect All asks before it opens more connections than this.
pub const CONNECT_ALL_CONFIRM_ABOVE: usize = 25;

/// What Connect All on a folder does with each connection in it and in its subfolders, in tree
/// order. Every connection is in exactly one list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BulkConnectPlan {
    /// Connect without asking: the connection has a login of its own (its saved logins, the one
    /// it inherits, or its inline secret), or its type takes none.
    pub ready: Vec<Uuid>,
    /// No login of its own. A login saved for another connection is at most offered
    /// (`LoginCandidate::auto_use` is false), so the user opens these one by one.
    pub needs_login: Vec<Uuid>,
    /// Already has a session.
    pub skipped_open: Vec<Uuid>,
    /// A type the apps open no session for.
    pub skipped_unsupported: Vec<Uuid>,
    /// A type the effective (managed) policy forbids. Never connected; listed so the app can say why.
    pub skipped_blocked: Vec<Uuid>,
}

impl BulkConnectPlan {
    /// How many connections the action is about to open, for "Connect 40 connections?".
    pub fn to_connect(&self) -> usize {
        self.ready.len() + self.needs_login.len()
    }

    /// Whether the app must ask before it starts.
    pub fn needs_confirmation(&self) -> bool {
        self.to_connect() > CONNECT_ALL_CONFIRM_ABOVE
    }
}

/// Types that sign in to nothing: a shell on this computer and a web page.
fn takes_login(p: Protocol) -> bool {
    !matches!(p, Protocol::Local | Protocol::Web)
}

/// Whether the connection can be opened without asking which login to use. The shared resolver
/// decides: only its first candidate counts, and only when it is the connection's own
/// (`auto_use`). The inline secret is stored for this connection alone and the resolver never
/// lists it, so it is read here.
fn has_own_login(doc: &Document, vault: &Vault, c: &Connection) -> Result<bool> {
    if !takes_login(c.protocol) {
        return Ok(true);
    }
    let purpose = if c.protocol == Protocol::Rdp { LoginPurpose::Password } else { LoginPurpose::Any };
    let inline = vault.inline(c.id).is_some_and(|i| purpose == LoginPurpose::Any || matches!(i.kind, CredentialKind::Password { .. }));
    Ok(inline || logins::login_candidates(doc, vault, c.id, purpose)?.first().is_some_and(|first| first.auto_use))
}

fn connections_below<'a>(f: &'a Folder, out: &mut Vec<&'a Connection>) {
    for n in &f.children {
        match n {
            Node::Connection(c) => out.push(c),
            Node::Folder(sub) => connections_below(sub, out),
        }
    }
}

/// The plan for Connect All on `folder` (the root included). `open` lists the connections that
/// have a session now. `policy` is the effective policy (managed file applied): a connection whose
/// type it forbids goes to `skipped_blocked`. Reads the document and the vault only; nothing is
/// connected or released.
pub fn plan_connect_all(doc: &Document, vault: &Vault, policy: &Policy, folder: Uuid, open: &[Uuid]) -> Result<BulkConnectPlan> {
    let folder = doc.folder(folder).ok_or_else(|| CoreError::NotFound(format!("folder {folder}")))?;
    let mut all = Vec::new();
    connections_below(folder, &mut all);
    let mut plan = BulkConnectPlan::default();
    for c in all {
        let list = if !connects(c.protocol) {
            &mut plan.skipped_unsupported
        } else if policy.check_protocol(c.protocol).is_err() {
            &mut plan.skipped_blocked
        } else if open.contains(&c.id) {
            &mut plan.skipped_open
        } else if has_own_login(doc, vault, c)? {
            &mut plan.ready
        } else {
            &mut plan.needs_login
        };
        list.push(c.id);
    }
    Ok(plan)
}

/// `ssh [-p port] [user@]host` for Copy SSH Command. The target is shell-quoted when needed;
/// secrets are never part of it.
pub fn ssh_command(host: &str, port: Option<u16>, username: Option<&str>) -> String {
    fn quote(s: &str) -> String {
        if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "@%+=:,./-_[]".contains(c)) {
            s.to_string()
        } else {
            format!("'{}'", s.replace('\'', r"'\''"))
        }
    }
    let mut cmd = String::from("ssh");
    if let Some(p) = port.filter(|p| *p != 22) {
        cmd.push_str(&format!(" -p {p}"));
    }
    let target = match username.filter(|u| !u.is_empty()) {
        Some(u) => format!("{u}@{host}"),
        None => host.to_string(),
    };
    cmd.push(' ');
    cmd.push_str(&quote(&target));
    cmd
}

/// `host` or `host:port` (IPv6 literals bracketed) for Copy Address; URLs stay as they are.
pub fn address(host: &str, port: Option<u16>, default_port: Option<u16>) -> String {
    if host.contains("://") {
        return host.to_string();
    }
    let h = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host.to_string() };
    match port {
        Some(p) if Some(p) != default_port => format!("{h}:{p}"),
        _ => h,
    }
}
