//! Plugin entries in the library (PLUG-03b app side, PLUG-PVE-01): the installed plugins'
//! connection types, adding an entry of one, its core-owned TLS settings, a certificate probe,
//! and opening the plugin's view on the entry with the entry's login.
//!
//! The login never reaches the app: [`CredentialVault::plugin_entry_view_open`] reads it from
//! the vault here and hands it to the core's view session, which uses it only to build the
//! manifest's `[http] auth` header (the plugin never sees it, and every request and answer is
//! checked for it). It is released only to the plugin that owns the entry's type, and each
//! release is written to the audit log without the user name or secret.
use std::path::PathBuf;
use std::sync::Arc;

use bastion_core::model::{Document, Node};
use bastion_core::plugin::host::relay::{check_entry_certificate, probe_certificate_pin, EntryRoute};
use bastion_core::plugin::host::view::{self, EntryBinding, EntryLogin, ViewSpec};
use bastion_core::plugin::{list_installed, load_installed, PluginFolders};
use bastion_core::pluginentry::{binding_tls, entry_tls, entry_tls_damaged, plugin_entry_settings, set_entry_tls};
use bastion_core::plugintypes::{self, Registry};
use bastion_core::plugin::broker::stream::TlsMode;

use crate::credentials::CredentialVault;
use crate::pluginview::{failure, pool, PluginView};
use crate::policy::effective;
use crate::{parse_id, FfiError, FfiResult, Library};

/// One connection type of an installed plugin, for the New Connection menu.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PluginTypeView {
    /// `<plugin id>/<type id>`: what the library stores, and `ConnectionView.protocol`.
    pub id: String,
    pub plugin_id: String,
    pub plugin_name: String,
    /// `Official`, `External` or `Unverified`.
    pub tier: String,
    pub name: String,
    pub default_port: Option<u16>,
    /// The type's own fields (key and label), for the New Connection form.
    pub fields: Vec<PluginTypeFieldView>,
    /// The entry shows the plugin's tree in the library sidebar (plugin API 1.3).
    pub sidebar_tree: bool,
}

/// One field of a plugin connection type (PLUG-08 Mac: PostgreSQL's Database).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PluginTypeFieldView {
    pub key: String,
    pub label: String,
}

/// A plugin field of an entry with its saved value, for the property sheet (PVE-TLS).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PluginFieldValueView {
    pub key: String,
    pub label: String,
    /// `text`, `number` or `toggle`.
    pub kind: String,
    /// The saved value as text; `None` when unset.
    pub value: Option<String>,
}

/// The entry's TLS settings for the property sheet. No secret.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PluginEntryTlsView {
    /// `verify-full` or `pinned`.
    pub mode: String,
    pub pin_sha256: Option<String>,
    /// A pin was chosen but the stored one is unusable: system trust applies until it is
    /// trusted again.
    pub damaged: bool,
}

fn registry(data_dir: &str) -> FfiResult<Registry> {
    let folders = PluginFolders::new(PathBuf::from(data_dir));
    let mut reg = Registry::new();
    let installed = list_installed(&folders).map_err(|e| FfiError::failed(e.to_string()))?;
    for p in installed {
        // A plugin that no longer loads offers no types; its entries stay as they are.
        if let Ok((package, tier)) = load_installed(&folders, &p.id) {
            reg.add(&package.manifest, tier);
        }
    }
    Ok(reg)
}

/// The connection types of the installed plugins, by library name.
#[uniffi::export]
pub fn plugin_connection_types(data_dir: String) -> FfiResult<Vec<PluginTypeView>> {
    let reg = registry(&data_dir)?;
    Ok(reg
        .types()
        .map(|t| PluginTypeView {
            id: t.id.clone(),
            plugin_id: t.plugin_id.clone(),
            plugin_name: t.plugin_name.clone(),
            tier: plugintypes::tier_label(t.tier).into(),
            name: t.name.clone(),
            default_port: t.default_port,
            fields: t.fields.iter().map(|f| PluginTypeFieldView { key: f.key.clone(), label: f.label.clone() }).collect(),
            sidebar_tree: t.sidebar_tree,
        })
        .collect())
}

/// The pin of the certificate `host:port` presents (lowercase hex SHA-256 of its DER), for the
/// user to compare before trusting it. Only the TLS handshake runs: nothing is sent. Call it off
/// the main thread (up to 10 s).
#[uniffi::export]
pub fn plugin_certificate_probe(host: String, port: u16) -> FfiResult<String> {
    let policy = effective().map_err(|e| FfiError::Failed { message: e.to_string(), code: "policy".into() })?;
    probe_certificate_pin(&host, port, &policy).map_err(failure)
}

/// Test Connection for a plugin entry: a full TLS handshake under its rule (`pin_sha256` set:
/// exactly that certificate; else system trust and the host name). Nothing is sent after the
/// handshake. Call it off the main thread (up to 10 s).
#[uniffi::export]
pub fn plugin_certificate_check(host: String, port: u16, pin_sha256: Option<String>) -> FfiResult<()> {
    let policy = effective().map_err(|e| FfiError::Failed { message: e.to_string(), code: "policy".into() })?;
    check_entry_certificate(&host, port, pin_sha256.as_deref(), &policy).map_err(failure)
}

fn tls_view(mode: TlsMode, pin: Option<String>, damaged: bool) -> PluginEntryTlsView {
    let mode = if mode == TlsMode::Pinned { "pinned" } else { "verify-full" };
    PluginEntryTlsView { mode: mode.into(), pin_sha256: pin, damaged }
}

fn plugin_connection_mut<'a>(doc: &'a mut Document, id: uuid::Uuid) -> Option<&'a mut bastion_core::model::Connection> {
    fn find(f: &mut bastion_core::model::Folder, id: uuid::Uuid) -> Option<&mut bastion_core::model::Connection> {
        f.children.iter_mut().find_map(|n| match n {
            Node::Connection(c) if c.id == id && bastion_core::properties::is_plugin_entry(c) => Some(c),
            Node::Connection(_) => None,
            Node::Folder(sub) => find(sub, id),
        })
    }
    find(&mut doc.root, id)
}

#[uniffi::export]
impl Library {
    /// Add an entry of an installed plugin's connection type, with the type's default port.
    /// Returns its id.
    pub fn add_plugin_connection(&self, data_dir: String, parent: Option<String>, name: String, host: String, type_id: String) -> FfiResult<String> {
        let parent = parent.as_deref().map(parse_id).transpose()?;
        let reg = registry(&data_dir)?;
        let ty = reg.get(&type_id).ok_or_else(|| FfiError::failed(format!("No installed plugin offers the type `{type_id}`.")))?;
        let c = plugintypes::new_entry(name, host, ty);
        let id = c.id.to_string();
        self.lock().insert(parent, Node::Connection(c))?;
        Ok(id)
    }

    /// The gateway the plugin entry uses (its own or inherited), for the app to start a tunnel
    /// through it before opening the view; `None` when it connects direct.
    pub fn plugin_entry_gateway(&self, id: String) -> FfiResult<Option<String>> {
        let id = parse_id(&id)?;
        let doc = self.lock();
        let (_, settings) = plugin_entry_settings(&doc, id).ok_or_else(|| FfiError::failed("not a plugin entry".to_string()))?;
        Ok(settings.gateway_id.map(|g| g.to_string()))
    }

    /// Set (or clear, with `None` or empty) plugin field `key` of entry `id`, checked against its
    /// installed type. A value that holds the entry's saved password is not checked here: the
    /// form calls this before any password is saved.
    /// Entry `id`'s fields of its installed plugin type, for the property editor, as JSON:
    /// `{heading, typeId, fields: [{key, label, kind, value}]}` (`kind`: `text`, `port`, `toggle`, …;
    /// `value` null when unset). Stored values the manifest no longer declares are not listed.
    pub fn plugin_entry_fields_json(&self, data_dir: String, id: String) -> FfiResult<String> {
        let id = parse_id(&id)?;
        let reg = registry(&data_dir)?;
        let doc = self.lock();
        let (c, ty) = plugintypes::plugin_entry(&doc, id, &reg)?;
        let g = plugintypes::field_group(c, ty)?;
        Ok(serde_json::json!({ "heading": g.heading, "typeId": g.type_id, "fields": g.fields.iter().map(|f| serde_json::json!({ "key": f.key, "label": f.label, "kind": f.kind, "value": f.value })).collect::<Vec<_>>() }).to_string())
    }

    pub fn set_plugin_field(&self, data_dir: String, id: String, key: String, value: Option<String>) -> FfiResult<()> {
        let id = parse_id(&id)?;
        let reg = registry(&data_dir)?;
        self.with_doc(|doc| {
            let c = plugin_connection_mut(doc, id).ok_or_else(|| bastion_core::CoreError::NotFound(id.to_string()))?;
            let ty = reg.get(c.unknown_protocol.as_deref().unwrap_or("")).ok_or_else(|| bastion_core::CoreError::Invalid("No installed plugin offers this entry's type.".into()))?;
            plugintypes::set_field(c, ty, &key, value.as_deref(), None, false).map(|_| ())
        })
    }

    /// The entry's fields of its installed plugin type, in the manifest's order, with their
    /// saved values. Fails when no installed plugin offers the entry's type.
    pub fn plugin_entry_fields(&self, data_dir: String, id: String) -> FfiResult<Vec<PluginFieldValueView>> {
        let id = parse_id(&id)?;
        let reg = registry(&data_dir)?;
        let doc = self.lock();
        let (c, ty) = plugintypes::plugin_entry(&doc, id, &reg).map_err(|e| FfiError::failed(e.to_string()))?;
        let group = plugintypes::field_group(c, ty).map_err(|e| FfiError::failed(e.to_string()))?;
        Ok(group
            .fields
            .into_iter()
            .map(|f| {
                let kind = match f.kind {
                    bastion_core::properties::PropKind::Number => "number",
                    bastion_core::properties::PropKind::Toggle => "toggle",
                    _ => "text",
                };
                PluginFieldValueView { key: f.key, label: f.label, kind: kind.into(), value: f.value }
            })
            .collect())
    }

    /// The plugin entry's TLS settings.
    pub fn plugin_entry_tls(&self, id: String) -> FfiResult<PluginEntryTlsView> {
        let id = parse_id(&id)?;
        let doc = self.lock();
        let (c, _) = plugin_entry_settings(&doc, id).ok_or_else(|| FfiError::failed("not a plugin entry".to_string()))?;
        let (mode, pin) = entry_tls(c);
        Ok(tls_view(mode, pin, entry_tls_damaged(c)))
    }

    /// Set the plugin entry's TLS mode: `verify-full`, or `pinned` with the certificate's pin.
    pub fn set_plugin_entry_tls(&self, id: String, mode: String, pin_sha256: Option<String>) -> FfiResult<()> {
        let id = parse_id(&id)?;
        self.with_doc(|doc| {
            let c = plugin_connection_mut(doc, id).ok_or_else(|| bastion_core::CoreError::NotFound(id.to_string()))?;
            set_entry_tls(c, &mode, pin_sha256.as_deref())
        })
    }
}

/// Open the view of the plugin that owns entry `connection_id`'s type, on that entry. With the
/// vault open, the entry's password login (its own, or the one the shared login rule uses without
/// asking) is kept by the core for the manifest's `[http] auth`; it is never returned or logged.
/// Without it the view opens with no login, and requests that need one are refused. Call it off
/// the main thread: a cold open compiles the plugin first.
#[uniffi::export]
pub fn plugin_entry_view_open(library: Arc<Library>, vault: Option<Arc<CredentialVault>>, connection_id: String, data_dir: String, allow_unverified: bool, safe_mode: bool) -> FfiResult<Arc<PluginView>> {
    open_view_named(library, vault.as_deref(), connection_id, data_dir, allow_unverified, safe_mode, None, false)
}

/// How the app reaches a plugin entry's server (PLUG-08): a tunnel it runs to the entry.
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum PluginRoute {
    /// Straight to the host (refused for an entry that has a gateway).
    Direct,
    /// An SSH local forward the app runs, listening on loopback `port`; `target` is the host
    /// the SSH server is asked to reach (the entry's host, or a loopback literal behind a gateway).
    Forward { port: u16, target: String },
    /// An SSH SOCKS proxy (`-D`) the app runs on loopback `port`.
    Socks { port: u16 },
}

/// As [`plugin_entry_view_open`], with the route the app chose: a saved tunnel running now, or
/// one it started through the entry's gateway ([`Library::plugin_entry_gateway`]). An entry with
/// a gateway is never sent direct.
#[uniffi::export]
pub fn plugin_entry_view_open_via(library: Arc<Library>, vault: Option<Arc<CredentialVault>>, connection_id: String, data_dir: String, allow_unverified: bool, safe_mode: bool, via: PluginRoute) -> FfiResult<Arc<PluginView>> {
    open_view_named(library, vault.as_deref(), connection_id, data_dir, allow_unverified, safe_mode, Some(via), false)
}

/// As [`plugin_entry_view_open_via`], for the entry's tree in the library sidebar (plugin API 1.3,
/// `docs/plans/PLUG-API-13.md`): a second view session named `sidebar`, refused unless the entry's
/// connection type declares `sidebar = "tree"`. The app opens it when the entry is expanded and
/// drops it when it is collapsed.
#[uniffi::export]
pub fn plugin_entry_sidebar_open(library: Arc<Library>, vault: Option<Arc<CredentialVault>>, connection_id: String, data_dir: String, allow_unverified: bool, safe_mode: bool, via: PluginRoute) -> FfiResult<Arc<PluginView>> {
    open_view_named(library, vault.as_deref(), connection_id, data_dir, allow_unverified, safe_mode, Some(via), true)
}

/// What Test Connection found on a plugin entry ([`plugin_entry_test`]).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PluginEntryTestView {
    /// The plugin loaded its view with no error.
    pub ok: bool,
    /// The plugin's own words: its error or warning banner; empty when it loaded cleanly.
    pub message: String,
}

/// How long Test Connection waits for the plugin's first loaded view.
const ENTRY_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

/// Test Connection on a plugin entry: opens the plugin's view as [`plugin_entry_view_open_via`]
/// does (same login, TLS and route), so the plugin makes the very calls its list needs, then
/// reads the view until it has loaded (no busy progress node left). An error banner fails the test with
/// its text; a warning banner passes with its text. The view is closed before returning. Blocks
/// up to 45 s: call it off the main thread.
#[uniffi::export]
pub fn plugin_entry_test(library: Arc<Library>, vault: Option<Arc<CredentialVault>>, connection_id: String, data_dir: String, allow_unverified: bool, via: PluginRoute) -> FfiResult<PluginEntryTestView> {
    let view = open_view_named(library, vault.as_deref(), connection_id, data_dir, allow_unverified, false, Some(via), false)?;
    let deadline = std::time::Instant::now() + ENTRY_TEST_TIMEOUT;
    let mut nodes = std::collections::BTreeMap::<i64, serde_json::Value>::new();
    let result = loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            break PluginEntryTestView { ok: false, message: "The plugin did not finish loading in 45 s.".into() };
        }
        let Some(update) = view.next_update(left.as_millis().min(u128::from(u32::MAX)) as u32) else { continue };
        let Ok(update) = serde_json::from_str::<serde_json::Value>(&update) else { continue };
        if let Some(found) = entry_test_step(&mut nodes, &update) {
            break found;
        }
    };
    view.close();
    Ok(result)
}

/// Applies one view update to `nodes`; returns the verdict once the view has loaded.
fn entry_test_step(nodes: &mut std::collections::BTreeMap<i64, serde_json::Value>, update: &serde_json::Value) -> Option<PluginEntryTestView> {
    let put = |nodes: &mut std::collections::BTreeMap<i64, serde_json::Value>, list: Option<&serde_json::Value>| {
        for n in list.and_then(|l| l.as_array()).into_iter().flatten() {
            if let Some(id) = n.get("id").and_then(|i| i.as_i64()) {
                nodes.insert(id, n.get("component").cloned().unwrap_or_default());
            }
        }
    };
    match update.get("type").and_then(|t| t.as_str()) {
        Some("ended") => return Some(PluginEntryTestView { ok: false, message: "The plugin stopped before it loaded.".into() }),
        Some("set-view") if update.get("view").and_then(|v| v.as_i64()).unwrap_or(1) == 1 => {
            nodes.clear();
            put(nodes, update.get("nodes"));
        }
        Some("patch-view") if update.get("view").and_then(|v| v.as_i64()).unwrap_or(1) == 1 => {
            for id in update.get("remove").and_then(|r| r.as_array()).into_iter().flatten().filter_map(|i| i.as_i64()) {
                nodes.remove(&id);
            }
            put(nodes, update.get("upsert"));
        }
        _ => return None,
    }
    let kind = |c: &serde_json::Value| c.get("kind").and_then(|k| k.as_str()).unwrap_or("").to_string();
    // Only a busy mark (progress with no value) means loading: a value is a bar (a node's CPU or memory).
    let busy = |c: &serde_json::Value| kind(c) == "progress" && c.get("value").is_none_or(serde_json::Value::is_null);
    if nodes.is_empty() || nodes.values().any(busy) {
        return None;
    }
    let banner = |level: &str| nodes.values().filter(|c| kind(c) == "banner").filter_map(|c| c.get("value")).find(|v| v.get("level").and_then(|l| l.as_str()) == Some(level)).and_then(|v| v.get("text")).and_then(|t| t.as_str()).map(str::to_string);
    Some(match (banner("error"), banner("warning")) {
        (Some(e), _) => PluginEntryTestView { ok: false, message: e },
        (None, Some(w)) => PluginEntryTestView { ok: true, message: w },
        (None, None) => PluginEntryTestView { ok: true, message: String::new() },
    })
}

/// The route the relay uses: the app's tunnel, except that a gateway entry never goes direct.
fn chosen_route(default: EntryRoute, via: Option<PluginRoute>) -> EntryRoute {
    match via {
        None => default,
        Some(PluginRoute::Direct) => default,
        Some(PluginRoute::Forward { port, target }) => EntryRoute::Forward { port, target },
        Some(PluginRoute::Socks { port }) => EntryRoute::Socks { port },
    }
}

#[allow(clippy::too_many_arguments)]
fn open_view_named(library: Arc<Library>, vault: Option<&CredentialVault>, connection_id: String, data_dir: String, allow_unverified: bool, safe_mode: bool, via: Option<PluginRoute>, sidebar: bool) -> FfiResult<Arc<PluginView>> {
    let id = parse_id(&connection_id)?;
    let reg = registry(&data_dir)?;
    let (entry, credential, plugin_id, view_name) = {
        let doc = library.lock();
        let (c, ty) = plugintypes::plugin_entry(&doc, id, &reg)?;
        let (_, settings) = plugin_entry_settings(&doc, id).ok_or_else(|| FfiError::failed("not a plugin entry".to_string()))?;
        let fields = c
            .extra
            .get(plugintypes::FIELDS_KEY)
            .and_then(|v| v.as_object())
            .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect())
            .unwrap_or_default();
        let environment = serde_json::to_value(c.classification.environment).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        let entry = EntryBinding {
            document_id: doc.id.to_string(),
            entry_id: c.id.to_string(),
            name: c.name.clone(),
            host: c.host.clone(),
            port: settings.port.or(ty.default_port).unwrap_or(0),
            fields,
            protected: library.is_document(),
            environment,
            tls: {
                let mut tls = binding_tls(c, &settings);
                tls.route = chosen_route(tls.route, via);
                tls
            },
            connection_type: ty.id.split_once('/').map(|(_, t)| t.to_string()).unwrap_or_default(),
        };
        if sidebar && !ty.sidebar_tree {
            return Err(FfiError::failed("this connection type has no sidebar tree".to_string()));
        }
        let local = ty.id.split_once('/').map(|(_, t)| t.to_string()).unwrap_or_default();
        let view_name = if sidebar { bastion_core::plugin::SIDEBAR_VIEW.to_string() } else { local };
        (entry, settings.credential_id.map(|c| c.to_string()), ty.plugin_id.clone(), view_name)
    };
    // Read (and audit) the login only when the plugin can use it: its manifest has `[http] auth`
    // (the core keeps it), or `credentials = "entry"` (released on `entry-login`, PLUG-08).
    let folders = PluginFolders::new(PathBuf::from(&data_dir));
    let wants_login = load_installed(&folders, &plugin_id).ok().is_some_and(|(p, _)| p.manifest.permissions.credentials_entry || p.manifest.http.as_ref().is_some_and(|h| h.auth.is_some() || h.session.is_some()));
    let login = match vault.filter(|_| wants_login) {
        Some(v) => v.password_login_for(&library, id, credential)?.map(|(user, secret)| EntryLogin { user, secret: zeroize::Zeroizing::new(secret.as_bytes().to_vec()) }),
        None => None,
    };
    if let (Some(v), Some(_)) = (vault, &login) {
        v.audit("plugin-login-release", &connection_id, &plugin_id)?;
    }
    let policy = effective().map_err(|e| FfiError::Failed { message: e.to_string(), code: "policy".into() })?;
    let spec = ViewSpec { data_dir: PathBuf::from(data_dir), plugin_id, view_name, entry: Some(entry), policy, allow_unverified, safe_mode, login };
    let session = view::open(pool()?, spec).map_err(failure)?;
    Ok(PluginView::from_session(session))
}

#[cfg(test)]
#[path = "pluginentries_tests.rs"]
mod tests;
