//! UniFFI bridge between `bastion-core` and the native frontends. The surface is deliberately
//! small and secret-free: frontends get views of documents and scans, never secret values.
use std::path::PathBuf;
use std::sync::Mutex;

use bastion_core::model::{Connection, Document, Folder, Node, Protocol};
use bastion_core::sshconfig::{Limits, SshConfig};
use bastion_core::store::Store;
use bastion_core::CoreError;
use uuid::Uuid;

mod activity;
mod audit_view;
pub mod telnet_serial;
mod agent;
mod ansible;
mod bulk;
mod credentials;
mod editlocal;
mod open_sessions;
mod overview;
mod forwards;
mod credtree;
mod dbclient;
mod documents;
mod personal;
mod docunlock;
mod gateway;
mod history;
mod hostcas;
mod hoststatus;
mod ipc;
mod keys;
mod kdbximport;
mod libio;
mod mosh_wsl;
mod multiexec;
mod palette;
mod highlight;
mod pluginbroker;
mod pluginentries;
mod pluginopen;
mod pluginexec;
pub use pluginexec::{PluginExecCancel, PluginExecResult};
pub use pluginopen::plugin_open_resolve;
mod pluginview;
mod plugins;
mod policy;
mod probe;
pub use probe::*;
pub use audit_view::{audit_read_json, audit_verify_json};
pub use activity::{activity_begin, activity_close_orphans, activity_end, activity_event, activity_events_json, activity_purge, activity_query_json};
mod properties;
mod bulk_edit;
pub use bulk_edit::SelectionPropertyView;
mod providers;
mod recent_users;
mod recording;
mod restore;
pub use restore::{DeletedItemView, RestoreView};
mod settings;
mod shortcuts;
mod sftp;
mod sysview;
pub use sysview::{SysEventFilter, SysEventView, SysProcessView, SysServiceView, SystemView};
mod tasks;
mod dynfolder;
mod templates;
pub use templates::TemplateView;
mod terminal;
mod termfonts;
mod themes;
mod tools;
mod triggers;
mod transfers;
mod tunnels;
mod ui;
mod update;
mod vaultwarden;
mod vnc;
mod webautofill;
mod webtunnel;
mod workflow;
mod workspace;
mod wol;
mod tabs;
mod panes;
pub use tabs::{tab_group_colors, tab_strip_apply};
pub use keys::{keys_convert, keys_generate, keys_inspect};
pub use panes::{broadcast_review, panes_apply, panes_from_layout, panes_to_layout};
#[cfg(test)]
mod reconnect_tests;
#[cfg(test)]
mod recording_tests;
#[cfg(test)]
mod scope_tests;
#[cfg(test)]
mod a1_fu1_tests;
#[cfg(test)]
mod plug03a_tests;

pub use credentials::{CredentialVault, CredentialView, InlineCredentialView, RdpSavedLogin};
pub use kdbximport::{KeePassImportResult, KeePassImportRow};
pub use personal::{personal_new_device_key, PersonalLibrary};
pub use docunlock::{document_auto_lock_due, document_auto_lock_minutes, document_biometric_unlock_allowed, effective_auto_lock_minutes, recent_document_details, UnlockStatusView};
pub use documents::{document_extension, export_library_document, forget_recent_document, import_document_into_library, migrate_known_documents, recent_documents, BastionDocument, DocumentExportView, DocumentImportView, DocumentInfoView, DocumentOrigin};
pub use gateway::{GatewayHopView, GatewayInputView, GatewayRoute, GatewayView};
pub use hostcas::HostCaView;
pub use open_sessions::{open_sessions_mark_clean_quit, open_sessions_restore_setting_id, open_sessions_save};
pub use history::{connection_history, forget_connection_history, record_connection_failure, record_connection_success, ConnectionHistoryView};
pub use credtree::{CredentialRemoveView, CredentialTreeItemView, CredentialUsageView, EffectiveCredentialView};
pub use webautofill::{web_autofill_offered, WebAutofill};
pub use webtunnel::{clear_web_tunnel_data, firefox_user_js, local_port_free, next_free_local_port, tunnel_browser_args, ProxySettingsView, WebTunnelPlanView};
pub use ipc::{IpcHandler, IpcServer};
pub use ansible::{ansible_remote_plan, ansible_run_plan, ansible_task, AnsibleRemotePlan, AnsibleTaskSpec, AnsibleRunInput, AnsibleRunPlan, AnsibleUpload};
pub use libio::{generate_password, password_strength_bits, ExportPreviewView, ImportResultView, VariableView, VariablesView};
pub use plugins::{plugin_install_file, plugin_remove, plugins_installed, plugins_refresh, plugins_updates, InstalledPluginView, PluginUpdateView};
pub use pluginentries::{plugin_certificate_check, plugin_certificate_probe, plugin_connection_types, plugin_entry_sidebar_open, plugin_entry_test, plugin_entry_view_open, plugin_entry_view_open_via, PluginEntryTestView, PluginEntryTlsView, PluginFieldValueView, PluginRoute, PluginTypeView};
pub use pluginview::{plugin_host_set_helper_path, plugin_view_open, PluginField, PluginView, PluginViewEntry};
pub use highlight::{completion_context, completions_rank, highlight_line, highlight_text, CompletionContextView, CompletionItem, HighlightSpans, HighlightToken};
pub use pluginbroker::{plugin_field_save_warning, plugin_may_load, plugin_policy_state, PluginPolicyView};
pub use policy::{policy_check_protocol, policy_state, remembered_login_usable, session_login_reuse_minutes, PolicyView};
pub use multiexec::{review_exec, ExecReviewView, HostResultView, MultiExec};
pub use tasks::{review_task, task_ask_labels, TaskHookView, TaskReviewView, TaskRun, TaskRunView, TaskView};
pub use dynfolder::{dynamic_folder_review, dynamic_folder_revoke, dynamic_folder_trust, dynamic_folders_allowed, DynamicFolderRun, DynamicRunView, GeneratedItemView};
pub use recent_users::{forget_recent_username, record_recent_username, recent_usernames};
pub use wol::{WakeCancel, WakeResult, WolPlanView};
pub use properties::{property_schema, HostColorEntry, HostColorView, PropertyDefView, PropertyOptionView, PropertyValueView, TypeDescriptorView};
pub use sftp::{FilesBrowser, RemoteFile};
pub use workflow::{ChangePreview, EffectiveView, FieldChangeView, HostChangeView, HostOverrideView, RefreshResult, SshForwardRow, SshWorkflow, WorkflowSettingsView};
pub use vaultwarden::{VaultwardenConfigView, VaultwardenItemView, VaultwardenSession};
pub use update::{app_version, check_for_updates, download_update, update_channel_configured, UpdateFileView, UpdateStatusView};
pub use vnc::{vnc_connect, VncButton, VncFrame, VncViewer};
pub use ui::{action_ids, all_icons, icon_for, theme_accents, theme_colors, theme_metrics, ColorTokenView, IconView, MenuItemView, MetricsView, SessionSnapshot, TreeState};
pub use terminal::{MouseActionView, MouseButtonView, SessionManager, SshLogin, TermCell, TermScreen, Terminal};
pub use themes::{TerminalThemeView, ThemeLibrary};
pub use forwards::ForwardStatusView;
pub use hoststatus::{HostStatusDashboard, HostStatusView};
pub use triggers::{TriggerEventView, TriggerLibrary, TriggerView};
pub use tunnels::{RunningTunnel, TunnelDefView};
pub use tools::{purge_session_logs, BroadcastGroup, ClipboardRequestView, LogStateView, PurgeReportView, RdpOptionsView, SessionLogPlanView, SnippetLibrary, SnippetView};
pub use workspace::{WorkspaceStore, WorkspaceTabView, WorkspaceView};
// Used by the Windows C ABI (`core-cabi`).
pub use palette::{PaletteConnectionView, PaletteEntryInput, PaletteIndex};
pub use settings::{auto_lock_due, search_settings, setting_categories, setting_definitions, SettingsFile};
pub use shortcuts::{search_shortcuts, ShortcutsFile};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// Any other failure. `code` is a stable class (`io`, `corrupt`, `conflict`, `not_found`,
    /// `invalid`, `vault_locked`, `policy`, `ssh`, `host_key_changed`, `timeout`, `offline`, …,
    /// see `CoreError::code`; `other` when the bridge itself failed). Decide on `code`, show
    /// `message`.
    #[error("{message}")]
    Failed { message: String, code: String },
    /// The server's key is not in known_hosts. Show the fingerprint and ask the user to verify
    /// it out of band before retrying with it.
    #[error("unknown host key {fingerprint}")]
    HostKeyUnknown { fingerprint: String },
    /// A jump host's key is unknown. Retry with `jump_trust[hop] = fingerprint` once verified.
    #[error("unknown host key {fingerprint} on jump host {hop}")]
    JumpHostKeyUnknown { hop: String, fingerprint: String },
    #[error("authentication failed")]
    AuthFailed,
    /// Vaultwarden two-step login: ask for the authenticator code and retry the unlock with it.
    #[error("an authenticator code is required")]
    TwoFactorRequired,
    /// An imported host still has unanswered placeholders (for example `<user>`).
    #[error("needs configuration: {missing:?}")]
    NeedsConfiguration { missing: Vec<String> },
    /// SSH negotiation failed. `kind` is `kex`, `cipher`, `mac`, `host_key` or `compression`;
    /// when `weak_allowable` is non-empty, offer "Allow for this host" (policy may still refuse).
    #[error("{message}")]
    NoCommonAlgorithm { message: String, kind: String, server_offers: Vec<String>, weak_allowable: Vec<String> },
}

impl From<CoreError> for FfiError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::HostKeyUnknown { fingerprint } => FfiError::HostKeyUnknown { fingerprint },
            CoreError::JumpHostKeyUnknown { hop, fingerprint } => FfiError::JumpHostKeyUnknown { hop, fingerprint },
            CoreError::AuthFailed => FfiError::AuthFailed,
            CoreError::TwoFactorRequired => FfiError::TwoFactorRequired,
            CoreError::NeedsConfiguration { missing } => FfiError::NeedsConfiguration { missing },
            e @ CoreError::NoCommonAlgorithm { .. } => {
                let message = e.to_string();
                let CoreError::NoCommonAlgorithm { kind, server_offers, weak_allowable } = e else { unreachable!() };
                let kind = serde_json::to_value(kind).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
                FfiError::NoCommonAlgorithm { message, kind, server_offers, weak_allowable }
            }
            e => FfiError::Failed { code: e.code().to_string(), message: e.to_string() },
        }
    }
}

impl FfiError {
    /// A bridge-level failure with no core class (code `other`).
    pub fn failed(message: String) -> Self {
        FfiError::Failed { message, code: "other".into() }
    }

    /// The stable class of this error (see [`FfiError::Failed`]); the variant name for the others.
    pub fn code(&self) -> &str {
        match self {
            FfiError::Failed { code, .. } => code,
            FfiError::HostKeyUnknown { .. } | FfiError::JumpHostKeyUnknown { .. } => "host_key_unknown",
            FfiError::AuthFailed => "auth_failed",
            FfiError::TwoFactorRequired => "two_factor_required",
            FfiError::NeedsConfiguration { .. } => "needs_configuration",
            FfiError::NoCommonAlgorithm { .. } => "ssh",
        }
    }
}

type FfiResult<T> = Result<T, FfiError>;

/// Connection metadata key holding an assigned Vaultwarden item id.
const VAULTWARDEN_ITEM_KEY: &str = "VaultwardenItem";

#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct ConnectionView {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub group: Option<String>,
    /// Set for imported hosts: `removed-from-source` when the host left the SSH config.
    pub source_status: Option<String>,
    pub imported: bool,
    pub favorite: bool,
    /// Vault credential assigned directly to this connection (not inherited).
    pub credential_id: Option<String>,
    /// Vaultwarden item assigned to this connection (metadata `VaultwardenItem`).
    pub vaultwarden_item: Option<String>,
    /// The vault credential it connects with: its own or inherited from a folder or the type's
    /// Default Settings (`properties::effective_credential`). An inline secret
    /// (`CredentialVault::inline_for`) takes precedence over this.
    pub effective_credential_id: Option<String>,
    /// Set instead of `effective_credential_id` when the nearest level names its credential;
    /// look it up with `CredentialVault::find_by_name`.
    pub effective_credential_name: Option<String>,
    /// `own`, `inherited` or `typedefault`; `None` when no credential applies.
    pub credential_source: Option<String>,
    /// Folder (or type) the credential is inherited from.
    pub credential_from: Option<String>,
    /// The username it connects with: own, else inherited.
    pub effective_username: Option<String>,
    /// `password` or `ssh-key` when it has an inline secret in the vault (marker only).
    pub inline_credential: Option<String>,
    /// Services, Processes and Event Log hang under it: SSH, or RDP with management via SSH on.
    pub has_tools: bool,
    /// Set when this app does not know the connection's type (PLUG-03a): the core's one fixed
    /// text, "Needs a newer Bastion or a plugin". Show it on the row; the entry cannot be
    /// connected to or edited, only renamed, moved and deleted. `protocol` is then the stored
    /// type name, which is untrusted text for display only.
    pub unavailable: Option<String>,
    /// The connection's own icon (core `model::ICONS`), drawn instead of the type icon; `None`
    /// when it uses the type icon. A stored name the core does not know reads as `None`.
    pub own_icon: Option<String>,
    /// Tags, lower case.
    pub tags: Vec<String>,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct FolderView {
    pub id: String,
    pub name: String,
    pub folders: Vec<FolderView>,
    pub connections: Vec<ConnectionView>,
}

/// One node of the tree and where it sits, for patching the tree after an edit instead of reading
/// all of it (`Library::node_view`). Exactly one of `folder` and `connection` is set.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct NodeView {
    /// The folder that holds it (the library root's id at the top level).
    pub parent_id: String,
    /// Its place among the parent's folders (a folder) or connections (a connection).
    pub index: u32,
    pub folder: Option<FolderView>,
    pub connection: Option<ConnectionView>,
}

/// Wire name of a serde enum (`Protocol::Ssh` → `ssh`).
fn serde_json_name<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default().trim_matches('"').to_string()
}

/// What the tree needs resolved once per build: effective usernames by connection id.
/// Resolving per row rebuilt the whole resolved library each time (Q09: quadratic).
struct TreeContext<'a> {
    doc: &'a Document,
    usernames: std::collections::HashMap<Uuid, Option<String>>,
}

impl<'a> TreeContext<'a> {
    fn new(doc: &'a Document) -> Self {
        let usernames = doc.connections().into_iter().map(|r| (r.connection.id, r.effective.username)).collect();
        Self { doc, usernames }
    }

    /// Only the connections `ids` names are resolved (a subtree view, `Library::node_view`).
    fn for_ids(doc: &'a Document, ids: &std::collections::HashSet<Uuid>) -> Self {
        let usernames = doc.resolve_where(|c, _| ids.contains(&c.id)).into_iter().map(|r| (r.connection.id, r.effective.username)).collect();
        Self { doc, usernames }
    }
}

/// The node `id` with its ancestors (root first) and its place among same-kind siblings.
fn find_node<'a>(f: &'a Folder, id: Uuid, chain: &mut Vec<&'a Folder>) -> Option<(&'a Node, u32)> {
    chain.push(f);
    let (mut folders, mut connections) = (0u32, 0u32);
    for n in &f.children {
        let (nid, idx) = match n {
            Node::Folder(sub) => { folders += 1; (sub.id, folders - 1) }
            Node::Connection(c) => { connections += 1; (c.id, connections - 1) }
        };
        if nid == id { return Some((n, idx)); }
    }
    for n in &f.children {
        if let Node::Folder(sub) = n {
            if let Some(found) = find_node(sub, id, chain) { return Some(found); }
        }
    }
    chain.pop();
    None
}

fn subtree_ids(n: &Node, out: &mut std::collections::HashSet<Uuid>) {
    match n {
        Node::Connection(c) => { out.insert(c.id); }
        Node::Folder(f) => f.children.iter().for_each(|c| subtree_ids(c, out)),
    }
}

fn connection_view(ctx: &TreeContext, chain: &[&Folder], c: &Connection) -> ConnectionView {
    use bastion_core::properties::{effective_credential_with_ancestors, CredentialRef};
    let doc = ctx.doc;
    let cred = effective_credential_with_ancestors(doc, chain, c);
    let (id, name) = match cred.as_ref().map(|r| &r.0) {
        Some(CredentialRef::Id(u)) => (Some(u.to_string()), None),
        Some(CredentialRef::Name(n)) => (None, Some(n.clone())),
        None => (None, None),
    };
    ConnectionView {
        effective_credential_id: id,
        effective_credential_name: name,
        credential_source: cred.as_ref().map(|r| serde_json_name(&r.1)),
        credential_from: cred.and_then(|r| r.2),
        effective_username: ctx.usernames.get(&c.id).cloned().flatten(),
        inline_credential: c.metadata.get(bastion_core::model::INLINE_CREDENTIAL_KEY).cloned(),
        id: c.id.to_string(),
        name: c.name.clone(),
        protocol: c.protocol_name().to_string(),
        host: c.host.clone(),
        port: c.settings.port,
        username: c.settings.username.clone(),
        group: c.metadata.get("Group").cloned(),
        source_status: c.metadata.get(bastion_core::sshworkflow::STATUS_KEY).cloned(),
        imported: c.metadata.contains_key("SshConfigIdentity"),
        favorite: c.favorite,
        credential_id: c.settings.credential_id.map(|u| u.to_string()),
        vaultwarden_item: c.metadata.get(VAULTWARDEN_ITEM_KEY).cloned(),
        has_tools: c.unavailable().is_none() && (c.protocol == bastion_core::model::Protocol::Ssh || bastion_core::sysview::ssh_management(c).is_some()),
        unavailable: c.unavailable().map(str::to_string),
        own_icon: c.icon.as_deref().filter(|i| bastion_core::model::ICONS.contains(i)).map(str::to_string),
        tags: c.tags.clone(),
    }
}

fn folder_view<'a>(ctx: &TreeContext<'a>, chain: &mut Vec<&'a Folder>, f: &'a Folder) -> FolderView {
    chain.push(f);
    let mut v = FolderView { id: f.id.to_string(), name: f.name.clone(), folders: vec![], connections: vec![] };
    for n in &f.children {
        match n {
            Node::Folder(sub) => v.folders.push(folder_view(ctx, chain, sub)),
            Node::Connection(c) => v.connections.push(connection_view(ctx, chain, c)),
        }
    }
    chain.pop();
    v
}

pub(crate) fn parse_id(s: &str) -> FfiResult<Uuid> {
    Uuid::parse_str(s).map_err(|_| FfiError::failed(format!("invalid id `{s}`")))
}

/// A connection library backed by one document file.
#[derive(uniffi::Object)]
pub struct Library {
    /// `None` for a Quick Connect library, which lives only in memory.
    store: Option<Store>,
    doc: Mutex<Document>,
    /// Set for a `.bastion` document's library: saves go into the document (`documents`).
    document: Option<std::sync::Arc<Mutex<bastion_core::docfile::DocumentFile>>>,
    /// A document's library: the app data dir, where each save records its connection count
    /// for the start window's Recents (`docunlock::record_connection_count`).
    counts_dir: Option<std::path::PathBuf>,
    /// Set when the document this library came from was locked: the handle is dead for good,
    /// so a stale view can never save its copy over the unlocked document (F04).
    revoked: std::sync::atomic::AtomicBool,
}

#[uniffi::export]
impl Library {
    /// Open `path`, creating an empty library when the file does not exist yet.
    #[uniffi::constructor]
    pub fn open(path: String) -> FfiResult<Self> {
        let store = Store::new(PathBuf::from(&path));
        let doc = if std::path::Path::new(&path).exists() { store.load()? } else { Document::new("Library") };
        Ok(Library { store: Some(store), doc: Mutex::new(doc), document: None, counts_dir: None, revoked: Default::default() })
    }

    /// An unsaved, in-memory library holding one connection for a Quick Connect `target`
    /// (`user@host:port`, `rdp://host`, `https://…`); `save` refuses it. Connect with it like
    /// any library, so the credential prompt and host key checks still apply.
    #[uniffi::constructor]
    pub fn quick_connect(target: String) -> FfiResult<Self> {
        let t = bastion_core::quickconnect::parse(&target)?;
        let mut c = Connection::new(t.label(), t.protocol, t.host);
        c.settings.port = t.port;
        c.settings.username = t.user;
        let mut doc = Document::new("Quick Connect");
        doc.insert(None, Node::Connection(c))?;
        Ok(Library { store: None, doc: Mutex::new(doc), document: None, counts_dir: None, revoked: Default::default() })
    }

    pub fn tree(&self) -> FolderView {
        let doc = self.lock();
        let ctx = TreeContext::new(&doc);
        folder_view(&ctx, &mut Vec::new(), &doc.root)
    }

    /// The node `id` as `tree()` shows it (with its subtree), its parent and its place there; `None`
    /// when it is not in the library (deleted). Reads only that subtree: the app patches its tree
    /// with it after an edit instead of reading the whole tree (~50 ms at 5,000 connections).
    pub fn node_view(&self, id: String) -> FfiResult<Option<NodeView>> {
        let id = parse_id(&id)?;
        let doc = self.lock();
        let mut chain = Vec::new();
        let Some((node, index)) = find_node(&doc.root, id, &mut chain) else { return Ok(None) };
        let mut ids = std::collections::HashSet::new();
        subtree_ids(node, &mut ids);
        let ctx = TreeContext::for_ids(&doc, &ids);
        let parent_id = chain.last().map(|f| f.id.to_string()).unwrap_or_default();
        let (folder, connection) = match node {
            Node::Folder(f) => (Some(folder_view(&ctx, &mut chain.clone(), f)), None),
            Node::Connection(c) => (None, Some(connection_view(&ctx, &chain, c))),
        };
        Ok(Some(NodeView { parent_id, index, folder, connection }))
    }

    pub fn add_folder(&self, parent: Option<String>, name: String) -> FfiResult<String> {
        let parent = parent.as_deref().map(parse_id).transpose()?;
        let f = Folder { id: Uuid::new_v4(), name, color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() };
        let id = f.id.to_string();
        self.lock().insert(parent, Node::Folder(f))?;
        Ok(id)
    }

    pub fn add_connection(&self, parent: Option<String>, name: String, protocol: String, host: String, port: Option<u16>, username: Option<String>) -> FfiResult<String> {
        let parent = parent.as_deref().map(parse_id).transpose()?;
        let protocol: Protocol = serde_json::from_value(serde_json::Value::String(protocol.to_lowercase()))
            .map_err(|_| FfiError::failed(format!("unknown protocol `{protocol}`")))?;
        let mut c = Connection::new(name, protocol, host);
        c.settings.port = port;
        c.settings.username = username;
        let id = c.id.to_string();
        self.lock().insert(parent, Node::Connection(c))?;
        Ok(id)
    }

    pub fn remove(&self, id: String) -> FfiResult<()> {
        self.lock().remove(parse_id(&id)?)?;
        Ok(())
    }

    /// Import discovered SSH hosts into one folder per customer group. Hosts whose stable
    /// identity is already in the library are skipped (deterministic dedupe). Returns the count.
    pub fn import_ssh_hosts(&self, root: String, identities: Vec<String>) -> FfiResult<u32> {
        let cfg = SshConfig::discover(std::path::Path::new(&root), &Limits::default());
        let chosen: Vec<_> = cfg.hosts().into_iter().filter(|h| identities.contains(&h.identity)).collect();
        self.with_doc(|doc| bastion_core::sshworkflow::import_hosts(doc, &chosen))
    }

    /// Like `import_ssh_hosts`, plus extra config files outside `root` (Windows reads
    /// `C:\ProgramData\ssh\ssh_config` this way); each file's directory may be `Include`d from it.
    pub fn import_ssh_hosts_with(&self, root: String, extra_files: Vec<String>, identities: Vec<String>) -> FfiResult<u32> {
        let cfg = scan_config(&root, &extra_files);
        let chosen: Vec<_> = cfg.hosts().into_iter().filter(|h| identities.contains(&h.identity)).collect();
        self.with_doc(|doc| bastion_core::sshworkflow::import_hosts(doc, &chosen))
    }

    /// Import-preview rows for the forward lines of the hosts in `root` (+ `extra_files`);
    /// `chosen` are ticked keys in tick order. Nothing is created.
    pub fn ssh_forward_preview_with(&self, root: String, extra_files: Vec<String>, chosen: Vec<String>) -> Vec<SshForwardRow> {
        let hosts = scan_config(&root, &extra_files).hosts();
        bastion_core::sshforwards::preview(&self.lock(), &hosts, &chosen).into_iter().map(Into::into).collect()
    }

    /// Create auto-starting tunnels for the ticked forward rows; import the hosts first.
    pub fn import_ssh_forwards_with(&self, root: String, extra_files: Vec<String>, keys: Vec<String>) -> FfiResult<u32> {
        let hosts = scan_config(&root, &extra_files).hosts();
        self.with_doc(|doc| bastion_core::sshforwards::import(doc, &hosts, &keys))
    }

    /// Assign a vault credential to a connection; `None` clears it. Connects with
    /// `SshLogin::Vault` read it from the vault inside the core.
    pub fn set_credential(&self, connection_id: String, credential_id: Option<String>) -> FfiResult<()> {
        let cred = credential_id.as_deref().map(parse_id).transpose()?;
        let id = parse_id(&connection_id)?;
        self.with_doc(|d| d.set_credential(id, cred))
    }

    /// Mark (`password` / `ssh-key`) or unmark a connection as having an inline secret. Call it
    /// after `CredentialVault::set_inline_*` / `remove_inline`; the secret stays in the vault.
    pub fn set_inline_marker(&self, connection_id: String, kind: Option<String>) -> FfiResult<()> {
        let id = parse_id(&connection_id)?;
        if kind.as_deref().is_some_and(|k| k != "password" && k != "ssh-key") {
            return Err(FfiError::failed("inline credential kind must be password or ssh-key".into()));
        }
        self.with_doc(|d| d.set_metadata(id, bastion_core::model::INLINE_CREDENTIAL_KEY, kind))
    }

    /// Assign a Vaultwarden item to a connection; `None` clears it. Kept in connection metadata
    /// because `credential_id` refers to the local vault only; the id is not a secret.
    pub fn set_vaultwarden_item(&self, connection_id: String, item_id: Option<String>) -> FfiResult<()> {
        let id = parse_id(&connection_id)?;
        let item = item_id.filter(|s| !s.trim().is_empty());
        self.with_doc(|d| d.set_metadata(id, VAULTWARDEN_ITEM_KEY, item))
    }

    pub fn save(&self) -> FfiResult<()> {
        if let Some(file) = &self.document {
            return self.save_into_document(file);
        }
        let store = self.store.as_ref().ok_or_else(|| FfiError::failed("Quick Connect sessions are not saved".into()))?;
        let mut doc = self.lock();
        *doc = store.save(&doc)?;
        Ok(())
    }
}

impl Library {
    /// What a saved local terminal connection starts.
    pub(crate) fn local_shell_spec(&self, connection_id: &str) -> FfiResult<bastion_core::localshell::LocalShellSpec> {
        let c = self.resolve(parse_id(connection_id)?)?;
        if c.protocol != Protocol::Local {
            return Err(FfiError::failed("not a local terminal connection".into()));
        }
        Ok(bastion_core::localshell::resolve(&c)?)
    }

    /// How Mosh opens a saved SSH connection (`remoteshell::mosh_launch`).
    pub(crate) fn mosh_spec(&self, connection_id: &str) -> FfiResult<bastion_core::localshell::LocalShellSpec> {
        let c = self.resolve(parse_id(connection_id)?)?;
        let mosh = bastion_core::remoteshell::find_mosh(|p| p.is_file(), std::env::var("PATH").ok().as_deref());
        // Windows without a native mosh.exe: the WSL distro's mosh (mosh_wsl), after core's checks.
        #[cfg(windows)]
        if mosh.is_none() {
            let spec = bastion_core::remoteshell::mosh_launch(&c, &c.settings, Some("mosh".into()))?;
            let distro = mosh_wsl::distro().map_err(|e| bastion_core::CoreError::Invalid(e))?;
            return Ok(mosh_wsl::wrap(&distro, spec));
        }
        Ok(bastion_core::remoteshell::mosh_launch(&c, &c.settings, mosh)?)
    }

    /// The connection with folder-inherited settings applied.
    pub(crate) fn resolve(&self, id: Uuid) -> FfiResult<Connection> {
        let r = self.lock().resolve(id)?;
        let mut c = r.connection;
        c.settings = r.effective;
        Ok(c)
    }

    /// Several connections in one pass over the library (H04), in the order given.
    pub(crate) fn resolve_many(&self, ids: &[Uuid]) -> FfiResult<Vec<Connection>> {
        let rs = self.lock().resolve_many(ids)?;
        Ok(rs
            .into_iter()
            .map(|r| {
                let mut c = r.connection;
                c.settings = r.effective;
                c
            })
            .collect())
    }

    /// Run a mutation on the document; errors leave it as the mutation left it, like `mutate` in the UI.
    pub(crate) fn with_doc<T>(&self, f: impl FnOnce(&mut Document) -> bastion_core::Result<T>) -> FfiResult<T> {
        Ok(f(&mut self.lock())?)
    }

    /// A `.bastion` document's library: plugin storage for its entries lasts only as long as
    /// the view.
    pub(crate) fn is_document(&self) -> bool {
        self.document.is_some()
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Document> {
        // A poisoned lock only means another call panicked mid-edit; the document is still
        // structurally valid, so recover it rather than wedging the UI.
        self.doc.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[derive(uniffi::Record)]
pub struct SshHostView {
    pub alias: String,
    pub hostname: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub group: String,
    pub source_file: String,
    pub identity: String,
    pub proxy_jump: Option<String>,
    pub flags: Vec<String>,
    /// `<name>` placeholders in the source values (need personal answers before connecting).
    pub placeholders: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct SshScan {
    pub hosts: Vec<SshHostView>,
    pub files: Vec<String>,
    pub warnings: Vec<String>,
}

/// True only when this library was compiled with the `test-hooks` feature (`BASTION_TEST_HOOKS=1
/// build-core.sh`, driver suites only). Release bundles never set it, so this is a build-time fact
/// the app cannot be talked out of at run time (MAC-TEST-VAULT-SCREEN-LOCK).
#[uniffi::export]
pub fn test_hooks_build() -> bool {
    cfg!(feature = "test-hooks")
}

#[cfg(test)]
mod test_hooks_build_tests {
    // `cargo test` without features is the release feature set; `--features test-hooks` the
    // driver build. Each build checks its own fixed answer (bundle.sh refuses the second).
    #[cfg(not(feature = "test-hooks"))]
    #[test]
    fn release_build_reports_no_test_hooks() {
        assert!(!super::test_hooks_build());
    }

    #[cfg(feature = "test-hooks")]
    #[test]
    fn test_hooks_build_reports_test_hooks() {
        assert!(super::test_hooks_build());
    }
}

/// Scan an OpenSSH config tree (read-only; nothing is executed) for the import preview.
#[uniffi::export]
pub fn scan_ssh_config(root: String) -> SshScan {
    scan_view(&SshConfig::discover(std::path::Path::new(&root), &Limits::default()))
}

/// [`scan_ssh_config`] plus extra config files outside `root` (see `import_ssh_hosts_with`).
#[uniffi::export]
pub fn scan_ssh_config_with(root: String, extra_files: Vec<String>) -> SshScan {
    scan_view(&scan_config(&root, &extra_files))
}

fn scan_config(root: &str, extra_files: &[String]) -> SshConfig {
    let files: Vec<PathBuf> = extra_files.iter().map(PathBuf::from).filter(|p| p.is_file()).collect();
    let roots: Vec<PathBuf> = files.iter().filter_map(|p| p.parent().map(PathBuf::from)).collect();
    SshConfig::discover_with(std::path::Path::new(root), &files, &roots, &Limits::default())
}

pub(crate) fn scan_view(cfg: &SshConfig) -> SshScan {
    SshScan {
        hosts: cfg
            .hosts()
            .into_iter()
            .map(|h| SshHostView {
                placeholders: bastion_core::sshworkflow::host_placeholders(&h).into_iter().collect(),
                flags: h.flags.iter().map(serde_json_name).collect(),
                alias: h.alias,
                hostname: h.hostname,
                user: h.user,
                port: h.port,
                group: h.group,
                source_file: h.source_file,
                identity: h.identity,
                proxy_jump: h.proxy_jump,
            })
            .collect(),
        files: cfg.files.clone(),
        warnings: cfg.warnings.iter().map(|w| format!("{}:{}: {}", w.file, w.line, w.message)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::RUNTIME;

    #[test]
    fn library_round_trip_and_ssh_import_dedupes() {
        let dir = std::env::temp_dir().join(format!("bastion-ffi-{}", Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("ssh/config.d")).unwrap();
        std::fs::write(dir.join("ssh/config.d/acme"), "Host acme-web\n  HostName web.acme\n  User ops\n").unwrap();
        let path = dir.join("lib.json").to_string_lossy().into_owned();
        let root = dir.join("ssh").to_string_lossy().into_owned();

        let lib = Library::open(path.clone()).unwrap();
        lib.add_connection(None, "home".into(), "ssh".into(), "pc.home".into(), Some(22), None).unwrap();
        let scan = scan_ssh_config(root.clone());
        assert_eq!(scan.hosts.len(), 1);
        let ids: Vec<String> = scan.hosts.iter().map(|h| h.identity.clone()).collect();
        assert_eq!(lib.import_ssh_hosts(root.clone(), ids.clone()).unwrap(), 1);
        assert_eq!(lib.import_ssh_hosts(root, ids).unwrap(), 0, "same identity is not imported twice");
        lib.save().unwrap();

        let tree = Library::open(path).unwrap().tree();
        assert_eq!(tree.connections[0].name, "home");
        assert_eq!(tree.folders[0].name, "acme");
        assert_eq!(tree.folders[0].connections[0].username.as_deref(), Some("ops"));
        assert!(lib.add_connection(None, "x".into(), "gopher".into(), "h".into(), None, None).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn ssh_forwards_preview_then_import_ticked_only() {
        let dir = std::env::temp_dir().join(format!("bastion-ffi-fwd-{}", Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("ssh")).unwrap();
        std::fs::write(dir.join("ssh/config"), "Host db\n  HostName db.acme\n  LocalForward 5432 db:5432\n  DynamicForward 1080\n").unwrap();
        let root = dir.join("ssh").to_string_lossy().into_owned();
        let lib = Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap();
        let ids: Vec<String> = scan_ssh_config(root.clone()).hosts.iter().map(|h| h.identity.clone()).collect();
        lib.import_ssh_hosts(root.clone(), ids).unwrap();
        let rows = lib.ssh_forward_preview_with(root.clone(), vec![], vec![]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].kind, "local");
        assert_eq!(lib.import_ssh_forwards_with(root.clone(), vec![], vec![rows[1].key.clone()]).unwrap(), 1);
        assert!(lib.ssh_forward_preview_with(root, vec![], vec![])[1].blocked.starts_with("Already"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn quick_connect_library_holds_one_unsaved_connection() {
        let lib = Library::quick_connect("ops@10.0.0.5:2222".into()).unwrap();
        let c = &lib.tree().connections[0];
        assert_eq!((c.name.as_str(), c.protocol.as_str(), c.host.as_str()), ("ops@10.0.0.5:2222", "ssh", "10.0.0.5"));
        assert_eq!((c.port, c.username.as_deref()), (Some(2222), Some("ops")));
        assert!(lib.save().is_err(), "a Quick Connect library is never written");
        assert_eq!(quick_connect_target("sftp://h".into()).unwrap().mode, "files");
        assert_eq!(quick_connect_target("rdp://w".into()).unwrap().protocol, "rdp");
        assert!(Library::quick_connect("telnet://h".into()).is_err());
    }

    fn wait_text(t: &Terminal, needle: &str) -> String {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let s = t.screen();
            let text: String = s.cells.chunks(s.cols as usize).map(|r| r.iter().map(|c| c.text.as_str()).collect::<String>() + "\n").collect();
            if text.contains(needle) {
                return text;
            }
            assert!(std::time::Instant::now() < deadline, "timed out waiting for {needle}:\n{text}");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[cfg(unix)]
    #[test]
    fn packed_screen_matches_record_screen() {
        let t = Terminal::local_shell(40, 10).unwrap();
        t.write("echo pk-日本\r".as_bytes().to_vec()).unwrap();
        wait_text(&t, "pk-日本");
        let (a, p) = (t.screen(), t.screen_packed());
        assert_eq!((a.cols, a.rows, a.cursor_row, a.cursor_col), (p.cols, p.rows, p.cursor_row, p.cursor_col));
        let mut i = 0;
        for c in &a.cells {
            let b = &p.cells[i..];
            assert_eq!(u32::from_le_bytes(b[0..4].try_into().unwrap()), c.fg);
            assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), c.bg);
            assert_eq!(b[8] & 1 != 0, c.bold);
            let n = b[9] as usize;
            assert_eq!(std::str::from_utf8(&b[10..10 + n]).unwrap(), c.text);
            i += crate::terminal::PACKED_CELL_HEADER + n;
        }
        assert_eq!(i, p.cells.len());
        t.close();
    }

    #[cfg(unix)]
    #[test]
    fn local_shell_terminal_round_trip() {
        let t = Terminal::local_shell(80, 24).unwrap();
        t.write(b"echo ffi-$((40+2))\r".to_vec()).unwrap();
        wait_text(&t, "ffi-42");
        assert_eq!(t.screen().cells.len(), 80 * 24);
        t.close();
    }

    /// The default local shell on Windows is `cmd.exe` (via ConPTY). Input sent before it is
    /// reading is not reliably executed, so wait for the prompt first. `%OS%` is expanded by
    /// the shell, so the typed text (`ffi-%OS%`) differs from the output (`ffi-Windows_NT`).
    #[cfg(windows)]
    #[test]
    fn local_shell_terminal_round_trip() {
        let t = Terminal::local_shell(80, 24).unwrap();
        wait_text(&t, ">");
        t.write(b"echo ffi-%OS%\r".to_vec()).unwrap();
        wait_text(&t, "ffi-Windows_NT");
        assert_eq!(t.screen().cells.len(), 80 * 24);
        t.close();
    }

    #[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
    #[test]
    fn ssh_terminal_requires_explicit_host_key_trust() {
        assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
        if std::env::var("BASTION_SSH_TEST").is_err() {
            eprintln!("SKIPPED ssh_terminal_requires_explicit_host_key_trust: set BASTION_SSH_TEST=1");
            return;
        }
        let dir = std::env::temp_dir().join(format!("bastion-ffi-ssh-{}", Uuid::new_v4()));
        let lib = std::sync::Arc::new(Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap());
        let id = lib.add_connection(None, "test".into(), "ssh".into(), "127.0.0.1".into(), Some(2222), Some("tester".into())).unwrap();
        let mgr = SessionManager::new(dir.to_string_lossy().into_owned()).unwrap();
        let pw = || SshLogin::Password { password: "test-pass-123".into() };
        let fp = match mgr.connect_ssh(lib.clone(), id.clone(), "tester".into(), pw(), None, std::collections::HashMap::new(), std::collections::HashMap::new(), 80, 24) {
            Err(FfiError::HostKeyUnknown { fingerprint }) => fingerprint,
            Err(e) => panic!("expected unknown host key, got {e}"),
            Ok(_) => panic!("unknown host must not connect"),
        };
        assert!(matches!(
            mgr.connect_ssh(lib.clone(), id.clone(), "tester".into(), SshLogin::Password { password: "wrong".into() }, Some(fp.clone()), std::collections::HashMap::new(), std::collections::HashMap::new(), 80, 24),
            Err(FfiError::AuthFailed)
        ));
        let t = mgr.connect_ssh(lib.clone(), id.clone(), "tester".into(), pw(), Some(fp), std::collections::HashMap::new(), std::collections::HashMap::new(), 80, 24).unwrap();
        t.write(b"echo over-ssh-$((40+2))\r".to_vec()).unwrap();
        wait_text(&t, "over-ssh-42");
        // A split pane shares the authenticated connection: a second shell, no second login.
        let sibling = t.open_sibling(80, 24).unwrap();
        sibling.write(b"echo sibling-$((40+3))\r".to_vec()).unwrap();
        wait_text(&sibling, "sibling-43");
        sibling.close();
        t.write(b"echo still-$((40+4))\r".to_vec()).unwrap();
        wait_text(&t, "still-44");
        // Trusted now: a plain connect works without a fingerprint.
        let t2 = mgr.connect_ssh(lib.clone(), id.clone(), "tester".into(), pw(), None, std::collections::HashMap::new(), std::collections::HashMap::new(), 80, 24).unwrap();
        t2.close();
        // A vault credential: no username typed, the secret never leaves Rust.
        let vault = std::sync::Arc::new(
            CredentialVault::open_with_key(dir.join("credentials.vault").to_string_lossy().into_owned(), bastion_core::vault::Secret::new("k".repeat(64))).unwrap(),
        );
        let cred = vault.save_password(None, "tester".into(), None, "tester".into(), "test-pass-123".into()).unwrap();
        lib.set_credential(id.clone(), Some(cred.clone())).unwrap();
        assert!(matches!(mgr.connect_ssh(lib.clone(), id.clone(), String::new(), SshLogin::Vault { credential_id: cred.clone() }, None, Default::default(), Default::default(), 80, 24), Err(FfiError::Failed { .. })));
        mgr.set_vault(vault);
        let t3 = mgr.connect_ssh(lib.clone(), id.clone(), String::new(), SshLogin::Vault { credential_id: cred }, None, Default::default(), Default::default(), 80, 24).unwrap();
        t3.write(b"echo vault-$((40+5))\r".to_vec()).unwrap();
        wait_text(&t3, "vault-45");
        t3.close();
        // A Vaultwarden item (needs the local container: BASTION_VAULTWARDEN_TEST=url,email,password,
        // with a personal login item named "lab sshd" for tester).
        if let Ok(spec) = std::env::var("BASTION_VAULTWARDEN_TEST") {
            let mut it = spec.splitn(3, ',');
            let (url, email, pw) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
            let vw = std::sync::Arc::new(VaultwardenSession::new(dir.to_string_lossy().into_owned()));
            let item = vw.unlock(url.into(), email.into(), pw.into(), None).unwrap().into_iter().find(|i| i.name == "lab sshd").expect("lab sshd item").id;
            lib.set_vaultwarden_item(id.clone(), Some(item.clone())).unwrap();
            assert_eq!(lib.tree().connections.iter().find(|c| c.id == id).and_then(|c| c.vaultwarden_item.clone()), Some(item.clone()));
            mgr.set_vaultwarden(vw.clone());
            let t4 = mgr.connect_ssh(lib.clone(), id.clone(), String::new(), SshLogin::Vaultwarden { item_id: item.clone() }, None, Default::default(), Default::default(), 80, 24).unwrap();
            t4.write(b"echo vaultwarden-$((40+6)) $(whoami)\r".to_vec()).unwrap();
            wait_text(&t4, "vaultwarden-46 tester");
            t4.close();
            // Lock Credentials locks Vaultwarden too: the same login now fails without a network call.
            assert!(vw.resync().unwrap().iter().any(|i| i.id == item), "re-sync without the master password");
            mgr.lock_credentials().unwrap();
            assert!(!vw.is_unlocked());
            assert!(vw.resync().is_err(), "lock drops the refresh token");
            assert!(mgr.connect_ssh(lib.clone(), id.clone(), String::new(), SshLogin::Vaultwarden { item_id: item }, None, Default::default(), Default::default(), 80, 24).is_err());
            let saved = std::fs::read_to_string(dir.join("vaultwarden.json")).unwrap();
            assert!(saved.contains(email) && !saved.contains(pw), "URL and e-mail remembered, never the password");
        } else {
            eprintln!("SKIPPED Vaultwarden part: set BASTION_VAULTWARDEN_TEST=url,email,password");
        }
        t.close();
        let audit = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(audit.contains("hostkey.trust") && !audit.contains("test-pass-123"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
    #[test]
    fn sftp_browser_over_orchestrated_connect() {
        assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
        if std::env::var("BASTION_SSH_TEST").is_err() {
            eprintln!("SKIPPED sftp_browser_over_orchestrated_connect: set BASTION_SSH_TEST=1");
            return;
        }
        let dir = std::env::temp_dir().join(format!("bastion-ffi-sftp-{}", Uuid::new_v4()));
        let lib = std::sync::Arc::new(Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap());
        let id = lib.add_connection(None, "test".into(), "ssh".into(), "127.0.0.1".into(), Some(2222), None).unwrap();
        let mgr = SessionManager::new(dir.to_string_lossy().into_owned()).unwrap();
        let pw = || SshLogin::Password { password: "test-pass-123".into() };
        let fp = match mgr.connect_sftp(lib.clone(), id.clone(), "tester".into(), pw(), None, std::collections::HashMap::new(), std::collections::HashMap::new()) {
            Err(FfiError::HostKeyUnknown { fingerprint }) => fingerprint,
            _ => panic!("unknown host must be refused first"),
        };
        let b = mgr.connect_sftp(lib, id, "tester".into(), pw(), Some(fp), std::collections::HashMap::new(), std::collections::HashMap::new()).unwrap();
        let home = b.home().unwrap();
        let local = dir.join("up.txt");
        std::fs::write(&local, "via ffi").unwrap();
        let remote = format!("{home}/ffi-{}.txt", Uuid::new_v4().simple());
        b.upload(local.to_string_lossy().into_owned(), remote.clone(), false).unwrap();
        let moved = format!("{remote}.moved");
        b.rename(remote, moved.clone()).unwrap();
        let name = moved.rsplit('/').next().unwrap().to_string();
        assert!(b.list(home).unwrap().iter().any(|f| f.name == name && f.kind == "file" && f.size == 7));
        let down = dir.join("down.txt");
        b.download(moved.clone(), down.to_string_lossy().into_owned(), false).unwrap();
        assert_eq!(std::fs::read_to_string(down).unwrap(), "via ffi");
        b.with_sftp_for_tests(|s| RUNTIME.block_on(s.remove_file(&moved))).unwrap();
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn workflow_placeholders_gate_connect_and_changes_are_previewed() {
        let dir = std::env::temp_dir().join(format!("bastion-ffi-wf-{}", Uuid::new_v4()));
        let ssh = dir.join("ssh");
        std::fs::create_dir_all(ssh.join("config.d")).unwrap();
        std::fs::write(ssh.join("config"), "Host personal\n  HostName pc.home\n").unwrap();
        let lab = "Host lab\n  HostName 127.0.0.1\n  Port 2222\n  User <user>\n\nHost lab-inner\n  HostName 10.0.0.9\n  User ops\n  ProxyJump lab\n";
        std::fs::write(ssh.join("config.d/lab"), lab).unwrap();
        let data = dir.join("data");
        let lib = std::sync::Arc::new(Library::open(data.join("lib.json").to_string_lossy().into_owned()).unwrap());
        let wf = SshWorkflow::open(data.to_string_lossy().into_owned()).unwrap();
        let mut st = wf.settings();
        st.ssh_dir = Some(ssh.to_string_lossy().into_owned());
        wf.set_settings(st).unwrap();

        let scan = wf.scan();
        let h = scan.hosts.iter().find(|h| h.alias == "lab").unwrap();
        assert_eq!(h.placeholders, vec!["user"]);
        let ids: Vec<String> = scan.hosts.iter().map(|h| h.identity.clone()).collect();
        assert_eq!(wf.import_hosts(lib.clone(), ids).unwrap(), 3);
        let conn_id = |name: &str| {
            fn find(f: &FolderView, n: &str) -> Option<String> {
                f.connections.iter().find(|c| c.name == n).map(|c| c.id.clone()).or_else(|| f.folders.iter().find_map(|s| find(s, n)))
            }
            find(&lib.tree(), name).unwrap()
        };
        let eff = wf.effective_for(lib.clone(), conn_id("lab")).unwrap().unwrap();
        assert_eq!(eff.unresolved, vec!["user"]);

        let mgr = SessionManager::new(data.to_string_lossy().into_owned()).unwrap();
        let pw = || SshLogin::Password { password: "test-pass-123".into() };
        match mgr.connect_ssh(lib.clone(), conn_id("lab"), String::new(), pw(), None, std::collections::HashMap::new(), std::collections::HashMap::new(), 80, 24) {
            Err(FfiError::NeedsConfiguration { missing }) => assert_eq!(missing, vec!["user"]),
            _ => panic!("a placeholder must block the connect"),
        }
        assert!(matches!(mgr.connect_ssh(lib.clone(), conn_id("lab-inner"), String::new(), pw(), None, std::collections::HashMap::new(), std::collections::HashMap::new(), 80, 24), Err(FfiError::NeedsConfiguration { .. })),
            "a jump host with an unanswered placeholder blocks the chain");

        wf.set_placeholder("user".into(), "tester".into()).unwrap();
        assert_eq!(wf.effective_for(lib.clone(), conn_id("lab")).unwrap().unwrap().user.as_deref(), Some("tester"));
        if std::env::var("BASTION_SSH_TEST").is_ok() {
            let fp = match mgr.connect_ssh(lib.clone(), conn_id("lab"), String::new(), pw(), None, std::collections::HashMap::new(), std::collections::HashMap::new(), 80, 24) {
                Err(FfiError::HostKeyUnknown { fingerprint }) => fingerprint,
                Err(e) => panic!("expected host-key prompt after answering the placeholder, got {e}"),
                Ok(_) => panic!("unknown host"),
            };
            let t = mgr.connect_ssh(lib.clone(), conn_id("lab"), String::new(), pw(), Some(fp), std::collections::HashMap::new(), std::collections::HashMap::new(), 80, 24).unwrap();
            t.write(b"echo wf-$((40+2))\r".to_vec()).unwrap();
            wait_text(&t, "wf-42");
            t.close();
        } else {
            eprintln!("SKIPPED real connect part of workflow test: set BASTION_SSH_TEST=1");
        }

        // A manual pull changes the source; the preview reports it and apply keeps the override.
        let mut o = wf.get_override(eff.identity.clone());
        o.port = Some(2222);
        wf.set_override(eff.identity.clone(), o).unwrap();
        std::fs::write(ssh.join("config.d/lab"), lab.replace("Port 2222", "Port 2200")).unwrap();
        let p = wf.changes().unwrap();
        assert!(p.has_baseline);
        let c = p.hosts.iter().find(|c| c.alias == "lab").unwrap();
        assert_eq!(c.kind, "changed");
        assert_eq!((c.fields[0].old.as_deref(), c.fields[0].new.as_deref()), (Some("2222"), Some("2200")));
        let r = wf.apply_refresh(lib.clone(), false).unwrap();
        assert_eq!(r.updated, 1);
        assert_eq!(wf.effective_for(lib.clone(), conn_id("lab")).unwrap().unwrap().port, Some(2222), "override still wins");
        assert!(wf.changes().unwrap().hosts.is_empty());
        assert_eq!(std::fs::read_to_string(ssh.join("config.d/lab")).unwrap(), lab.replace("Port 2222", "Port 2200"), "sources untouched");
        std::fs::remove_dir_all(dir).ok();
    }

    /// Imported config: `inner` uses `ProxyJump gw`, where `gw` is bastion-jump and `inner` is
    /// the private `target` container. Each hop has its own password and its own trust.
    #[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
    #[test]
    fn imported_proxyjump_chain_connects_through_the_jump_host() {
        assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
        if std::env::var("BASTION_SSH_TEST").is_err() {
            return eprintln!("SKIPPED imported_proxyjump_chain_connects_through_the_jump_host: set BASTION_SSH_TEST=1");
        }
        use std::collections::HashMap;
        let dir = std::env::temp_dir().join(format!("bastion-ffi-jump-{}", Uuid::new_v4()));
        let ssh = dir.join("ssh");
        std::fs::create_dir_all(ssh.join("config.d")).unwrap();
        std::fs::write(ssh.join("config.d/lab"), "Host gw\n  HostName 127.0.0.1\n  Port 2223\n  User <user>\n\nHost inner\n  HostName target\n  Port 2222\n  User tester\n  ProxyJump gw\n").unwrap();
        let data = dir.join("data");
        let lib = std::sync::Arc::new(Library::open(data.join("lib.json").to_string_lossy().into_owned()).unwrap());
        let wf = SshWorkflow::open(data.to_string_lossy().into_owned()).unwrap();
        let mut st = wf.settings();
        st.ssh_dir = Some(ssh.to_string_lossy().into_owned());
        wf.set_settings(st).unwrap();
        let ids = wf.scan().hosts.iter().map(|h| h.identity.clone()).collect();
        wf.import_hosts(lib.clone(), ids).unwrap();
        wf.set_placeholder("user".into(), "tester".into()).unwrap();
        let inner = lib.tree().folders[0].connections.iter().find(|c| c.name == "inner").unwrap().id.clone();
        let mgr = SessionManager::new(data.to_string_lossy().into_owned()).unwrap();
        let hops = mgr.jump_hosts(lib.clone(), inner.clone()).unwrap();
        assert_eq!(hops.iter().map(|h| (h.key.as_str(), h.username.as_str())).collect::<Vec<_>>(), [("127.0.0.1:2223", "tester")]);
        let target_pw = || SshLogin::Password { password: "target-pass-456".into() };
        let jump_login = || HashMap::from([("127.0.0.1:2223".to_string(), SshLogin::Password { password: "test-pass-123".into() })]);
        let connect = |trust: Option<String>, jt: HashMap<String, String>| mgr.connect_ssh(lib.clone(), inner.clone(), String::new(), target_pw(), trust, jt, jump_login(), 80, 24);

        let (hop, jump_fp) = match connect(None, HashMap::new()) {
            Err(FfiError::JumpHostKeyUnknown { hop, fingerprint }) => (hop, fingerprint),
            Err(e) => panic!("expected the jump host's key first, got {e}"),
            Ok(_) => panic!("unknown keys"),
        };
        assert_eq!(hop, "127.0.0.1:2223");
        let jt = HashMap::from([(hop, jump_fp)]);
        let fp = match connect(None, jt.clone()) {
            Err(FfiError::HostKeyUnknown { fingerprint }) => fingerprint,
            Err(e) => panic!("expected the target's key next, got {e}"),
            Ok(_) => panic!("unknown target key"),
        };
        let t = connect(Some(fp), jt).unwrap();
        t.write(b"echo inner-$((40+2))\r".to_vec()).unwrap();
        wait_text(&t, "inner-42");
        t.close();
        std::fs::remove_dir_all(dir).ok();
    }

    /// A shared gateway (bastion-jump) from the Gateway Manager is the first hop to the private
    /// `target` container: own login, own host-key trust, then the target.
    #[test]
    fn gateway_from_the_manager_is_the_first_hop() {
        use std::collections::HashMap;
        let dir = std::env::temp_dir().join(format!("bastion-ffi-gw-{}", Uuid::new_v4()));
        let lib = std::sync::Arc::new(Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap());
        let mut target = Connection::new("target", Protocol::Ssh, "target");
        target.settings.port = Some(2222);
        let tid = target.id.to_string();
        lib.with_doc(|d| d.insert(None, Node::Connection(target))).unwrap();
        let gw = lib
            .add_gateway(GatewayInputView { name: "Jump".into(), host: "127.0.0.1".into(), port: Some(2223), username: Some("tester".into()), notes: String::new() })
            .unwrap();
        assert!(lib.remove_gateway(gw.clone()).is_ok(), "unused gateways can be deleted");
        let gw = lib
            .add_gateway(GatewayInputView { name: "Jump".into(), host: "127.0.0.1".into(), port: Some(2223), username: Some("tester".into()), notes: String::new() })
            .unwrap();
        lib.set_property(tid.clone(), "gateway_id".into(), Some(gw.clone())).unwrap();
        assert_eq!(lib.gateways().unwrap()[0].used_by, ["target"]);
        assert!(lib.remove_gateway(gw).is_err(), "in use");
        let mgr = SessionManager::new(dir.to_string_lossy().into_owned()).unwrap();
        let hops = mgr.jump_hosts(lib.clone(), tid.clone()).unwrap();
        assert_eq!(hops.iter().map(|h| (h.key.as_str(), h.username.as_str())).collect::<Vec<_>>(), [("127.0.0.1:2223", "tester")]);
        if std::env::var("BASTION_SSH_TEST").is_err() {
            std::fs::remove_dir_all(dir).ok();
            return eprintln!("SKIPPED live part of gateway_from_the_manager_is_the_first_hop: set BASTION_SSH_TEST=1");
        }
        let jump_login = || HashMap::from([("127.0.0.1:2223".to_string(), SshLogin::Password { password: "test-pass-123".into() })]);
        let pw = || SshLogin::Password { password: "target-pass-456".into() };
        let connect = |trust: Option<String>, jt: HashMap<String, String>| mgr.connect_ssh(lib.clone(), tid.clone(), "tester".into(), pw(), trust, jt, jump_login(), 80, 24);
        let jt = match connect(None, HashMap::new()) {
            Err(FfiError::JumpHostKeyUnknown { hop, fingerprint }) => HashMap::from([(hop, fingerprint)]),
            Err(e) => panic!("expected the gateway's key first, got {e}"),
            Ok(_) => panic!("unknown keys"),
        };
        let fp = match connect(None, jt.clone()) {
            Err(FfiError::HostKeyUnknown { fingerprint }) => fingerprint,
            Err(e) => panic!("expected the target's key next, got {e}"),
            Ok(_) => panic!("unknown target key"),
        };
        let t = connect(Some(fp), jt).unwrap();
        t.write(b"echo via-gw-$((40+3))\r".to_vec()).unwrap();
        wait_text(&t, "via-gw-43");
        t.close();
        std::fs::remove_dir_all(dir).ok();
    }
}

#[derive(uniffi::Record)]
pub struct QuickConnectTarget {
    pub protocol: String,
    /// What the tab is called; also what to type to get here again.
    pub label: String,
    /// `terminal` or `files` (`sftp://`).
    pub mode: String,
}

/// Validate a Quick Connect entry as the user types; the error is the reason to show.
#[uniffi::export]
pub fn quick_connect_target(target: String) -> FfiResult<QuickConnectTarget> {
    let t = bastion_core::quickconnect::parse(&target)?;
    let protocol = t.protocol.as_str().to_string();
    Ok(QuickConnectTarget { protocol, label: t.label(), mode: if t.files { "files" } else { "terminal" }.into() })
}

/// Stable `GT-` support code for an error message in `area` (SSH, RDP, VNC, VAULT, NET, PLUG,
/// UPD, FILE, APP). Unknown errors get the area's `000` code (LOG-ERRCODES).
#[uniffi::export]
pub fn error_code(area: String, message: String) -> String {
    bastion_core::errcodes::classify(&area, &message).to_string()
}

/// A log line with secrets, user names, host names and addresses removed (LOG-ERRCODES).
#[uniffi::export]
pub fn log_redact(text: String) -> String {
    bastion_core::errcodes::redact(&text)
}

/// True when Detailed logging, on since `since_unix`, should turn itself off (LOG-ERRCODES).
#[uniffi::export]
pub fn detailed_log_expired(since_unix: u64, now_unix: u64) -> bool {
    bastion_core::settings::detailed_log_expired(since_unix, now_unix)
}
