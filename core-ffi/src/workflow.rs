//! Bridge for the optional shared-config workflow (`bastion_core::sshworkflow`). Personal data
//! goes to `<data dir>/ssh-workflow.json`; SSH config files are only read.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bastion_core::model::Connection;
use bastion_core::sshworkflow::{self, ChangeKind, EffectiveHost, HostOverride, WorkflowStore};

use crate::{parse_id, FfiError, FfiResult, Library, SshScan};

pub(crate) const STORE_FILE: &str = "ssh-workflow.json";

#[derive(uniffi::Record)]
pub struct WorkflowSettingsView {
    pub scan_config_d: bool,
    pub placeholders: bool,
    pub overrides: bool,
    pub change_detection: bool,
    /// Directory scanned instead of `~/.ssh`.
    pub ssh_dir: Option<String>,
}

#[derive(uniffi::Record, Default)]
pub struct HostOverrideView {
    pub user: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
    pub credential_ref: Option<String>,
    pub placeholders: HashMap<String, String>,
}

#[derive(uniffi::Record)]
pub struct EffectiveView {
    pub identity: String,
    pub hostname: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
    pub credential_ref: Option<String>,
    /// Placeholder names still unanswered ("needs configuration").
    pub unresolved: Vec<String>,
    /// Placeholder names the source values use (answered or not).
    pub source_placeholders: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct FieldChangeView {
    pub field: String,
    pub old: Option<String>,
    pub new: Option<String>,
}

#[derive(uniffi::Record)]
pub struct HostChangeView {
    pub identity: String,
    pub alias: String,
    pub group: String,
    pub source_file: String,
    /// `added`, `changed` or `removed`.
    pub kind: String,
    pub fields: Vec<FieldChangeView>,
}

#[derive(uniffi::Record)]
pub struct ChangePreview {
    pub root: String,
    pub hosts: Vec<HostChangeView>,
    pub files: Vec<String>,
    /// False when change detection is off or there is no baseline yet.
    pub has_baseline: bool,
    /// Unix seconds of the last import or sync, if any.
    pub last_synced_secs: Option<u64>,
}

#[derive(uniffi::Record)]
pub struct RefreshResult {
    pub added: u32,
    pub updated: u32,
    pub marked_removed: u32,
}

#[derive(uniffi::Object)]
pub struct SshWorkflow {
    store: Mutex<WorkflowStore>,
}

#[uniffi::export]
impl SshWorkflow {
    #[uniffi::constructor]
    pub fn open(data_dir: String) -> FfiResult<Arc<Self>> {
        std::fs::create_dir_all(&data_dir).map_err(bastion_core::CoreError::from)?;
        Ok(Arc::new(SshWorkflow { store: Mutex::new(WorkflowStore::open(Path::new(&data_dir).join(STORE_FILE))?) }))
    }

    pub fn settings(&self) -> WorkflowSettingsView {
        let s = &self.lock().data.settings;
        WorkflowSettingsView {
            scan_config_d: s.scan_config_d,
            placeholders: s.placeholders,
            overrides: s.overrides,
            change_detection: s.change_detection,
            ssh_dir: s.ssh_dir.as_ref().map(|p| p.display().to_string()),
        }
    }

    pub fn set_settings(&self, v: WorkflowSettingsView) -> FfiResult<()> {
        let mut st = self.lock();
        let s = &mut st.data.settings;
        s.scan_config_d = v.scan_config_d;
        s.placeholders = v.placeholders;
        s.overrides = v.overrides;
        s.change_detection = v.change_detection;
        s.ssh_dir = v.ssh_dir.filter(|d| !d.trim().is_empty()).map(PathBuf::from);
        if !s.change_detection {
            st.data.snapshot = None;
        }
        Ok(st.save()?)
    }

    /// The directory that will be scanned.
    pub fn ssh_dir(&self) -> Option<String> {
        self.lock().ssh_dir().map(|p| p.display().to_string())
    }

    /// Read-only scan for the import preview, honouring the discovery switches.
    pub fn scan(&self) -> SshScan {
        let st = self.lock();
        match st.ssh_dir() {
            Some(root) => crate::scan_view(&st.scan(&root)),
            None => SshScan { hosts: vec![], files: vec![], warnings: vec!["no home directory".into()] },
        }
    }

    /// Import the chosen hosts and take the current sources as the change baseline.
    pub fn import_hosts(&self, library: Arc<Library>, identities: Vec<String>) -> FfiResult<u32> {
        let mut st = self.lock();
        let root = root_of(&st)?;
        let cfg = st.scan(&root);
        let chosen: Vec<_> = cfg.hosts().into_iter().filter(|h| identities.contains(&h.identity)).collect();
        let added = library.with_doc(|doc| sshworkflow::import_hosts(doc, &chosen))?;
        library.save()?;
        st.record_snapshot(&root, &cfg);
        st.save()?;
        Ok(added)
    }

    /// Import-preview rows for every forward line of the scanned hosts. `chosen` are the keys
    /// ticked so far, in tick order (a ticked row claims its local port). Nothing is created.
    pub fn forward_preview(&self, library: Arc<Library>, chosen: Vec<String>) -> Vec<SshForwardRow> {
        let st = self.lock();
        let Ok(root) = root_of(&st) else { return vec![] };
        let hosts = st.scan(&root).hosts();
        bastion_core::sshforwards::preview(&library.lock(), &hosts, &chosen).into_iter().map(SshForwardRow::from).collect()
    }

    /// Create auto-starting tunnels for the ticked rows (`keys`). Import the hosts first. Rows
    /// that became blocked since the preview are skipped. Returns the number created.
    pub fn import_forwards(&self, library: Arc<Library>, keys: Vec<String>) -> FfiResult<u32> {
        let st = self.lock();
        let root = root_of(&st)?;
        let hosts = st.scan(&root).hosts();
        let n = library.with_doc(|doc| bastion_core::sshforwards::import(doc, &hosts, &keys))?;
        library.save()?;
        Ok(n)
    }

    pub fn placeholder_values(&self) -> HashMap<String, String> {
        self.lock().data.placeholder_values.clone().into_iter().collect()
    }

    /// Set (or, with an empty value, clear) a global placeholder answer.
    pub fn set_placeholder(&self, name: String, value: String) -> FfiResult<()> {
        let mut st = self.lock();
        if value.trim().is_empty() {
            st.clear_placeholder(&name);
        } else {
            st.set_placeholder(&name, value.trim())?;
        }
        Ok(st.save()?)
    }

    /// Placeholder names used anywhere in the current sources, with how many hosts use each.
    pub fn source_placeholders(&self) -> HashMap<String, u32> {
        let st = self.lock();
        let mut out = HashMap::new();
        if let Some(root) = st.ssh_dir() {
            for h in st.scan(&root).hosts() {
                for p in sshworkflow::host_placeholders(&h) {
                    *out.entry(p).or_insert(0) += 1;
                }
            }
        }
        out
    }

    pub fn get_override(&self, identity: String) -> HostOverrideView {
        let o = self.lock().data.hosts.get(&identity).cloned().unwrap_or_default();
        HostOverrideView {
            user: o.user,
            hostname: o.hostname,
            port: o.port,
            identity_file: o.identity_file,
            proxy_jump: o.proxy_jump,
            credential_ref: o.credential_ref,
            placeholders: o.placeholders.into_iter().collect(),
        }
    }

    /// Replace a host's personal overrides; blank strings mean "use the source value".
    pub fn set_override(&self, identity: String, v: HostOverrideView) -> FfiResult<()> {
        let blank = |s: Option<String>| s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let o = HostOverride {
            user: blank(v.user),
            hostname: blank(v.hostname),
            port: v.port,
            identity_file: blank(v.identity_file),
            proxy_jump: blank(v.proxy_jump),
            credential_ref: blank(v.credential_ref),
            placeholders: v.placeholders.into_iter().filter(|(_, val)| !val.trim().is_empty()).collect(),
        };
        let mut st = self.lock();
        st.set_override(&identity, o)?;
        Ok(st.save()?)
    }

    /// Effective values for an imported connection; `None` for manual connections.
    pub fn effective_for(&self, library: Arc<Library>, connection_id: String) -> FfiResult<Option<EffectiveView>> {
        let conn = library.resolve(parse_id(&connection_id)?)?;
        Ok(self.lock().effective_for_connection(&conn).map(|e| effective_view(e, &conn)))
    }

    /// Compare the sources with the baseline. Nothing is changed.
    pub fn changes(&self) -> FfiResult<ChangePreview> {
        let st = self.lock();
        let root = root_of(&st)?;
        let cfg = st.scan(&root);
        let ch = st.changes(&root, &cfg);
        Ok(ChangePreview {
            root: root.display().to_string(),
            has_baseline: st.data.settings.change_detection && st.data.snapshot.is_some(),
            last_synced_secs: st.data.last_synced_secs,
            files: ch.files,
            hosts: ch
                .hosts
                .into_iter()
                .map(|c| HostChangeView {
                    kind: match c.kind {
                        ChangeKind::Added => "added",
                        ChangeKind::Changed => "changed",
                        ChangeKind::Removed => "removed",
                    }
                    .into(),
                    identity: c.identity,
                    alias: c.alias,
                    group: c.group,
                    source_file: c.source_file,
                    fields: c.fields.into_iter().map(|f| FieldChangeView { field: f.field, old: f.old, new: f.new }).collect(),
                })
                .collect(),
        })
    }

    /// Apply the current changes to the library (after the user reviewed `changes()`), then
    /// take the sources as the new baseline.
    pub fn apply_refresh(&self, library: Arc<Library>, import_added: bool) -> FfiResult<RefreshResult> {
        let mut st = self.lock();
        let root = root_of(&st)?;
        let cfg = st.scan(&root);
        let ch = st.changes(&root, &cfg);
        let s = library.with_doc(|doc| sshworkflow::apply_refresh(doc, &cfg, &ch, import_added))?;
        library.save()?;
        st.record_snapshot(&root, &cfg);
        st.save()?;
        Ok(RefreshResult { added: s.added, updated: s.updated, marked_removed: s.marked_removed })
    }
}

impl SshWorkflow {
    fn lock(&self) -> std::sync::MutexGuard<'_, WorkflowStore> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn root_of(st: &WorkflowStore) -> FfiResult<PathBuf> {
    st.ssh_dir().ok_or_else(|| FfiError::failed("no home directory to find ~/.ssh in".into()))
}

fn effective_view(e: EffectiveHost, conn: &Connection) -> EffectiveView {
    let mut source_placeholders: Vec<String> = [Some(&conn.host), conn.settings.username.as_ref(), conn.metadata.get("IdentityFile"), conn.metadata.get("ProxyJump")]
        .into_iter()
        .flatten()
        .flat_map(|v| sshworkflow::find_placeholders(v))
        .collect();
    source_placeholders.sort();
    source_placeholders.dedup();
    EffectiveView {
        identity: e.identity,
        hostname: e.hostname,
        user: e.user,
        port: e.port,
        identity_file: e.identity_file,
        proxy_jump: e.proxy_jump,
        credential_ref: e.credential_ref,
        unresolved: e.unresolved,
        source_placeholders,
    }
}

/// Most hops a ProxyJump chain may expand to (nested ProxyJumps included).
const MAX_JUMP_HOPS: usize = 8;

/// One resolved jump host: where to connect and as whom.
pub(crate) struct JumpTarget {
    pub conn: Connection,
    pub username: String,
}

/// Apply the workflow to an imported connection right before connecting: placeholders and
/// overrides are resolved in memory only, and a ProxyJump is expanded into a chain of jump
/// hosts (aliases resolve to imported library hosts with their own placeholders, overrides and
/// nested ProxyJumps; anything else is parsed as `[user@]host[:port]`). Refuses when anything
/// is unanswered, when the chain loops, or when it is longer than `MAX_JUMP_HOPS`.
pub(crate) fn prepare_connection(data_dir: &Path, library: &Library, conn: &mut Connection, username: &mut String) -> FfiResult<Vec<JumpTarget>> {
    let store = WorkflowStore::open(data_dir.join(STORE_FILE))?;
    let imported = imported_by_alias(library)?;
    let mut jumps = Vec::new();
    if let Some(e) = store.effective_for_connection(conn) {
        if !e.ready() {
            return Err(FfiError::NeedsConfiguration { missing: e.unresolved });
        }
        if let Some(spec) = &e.proxy_jump {
            let mut seen = vec![conn.name.to_ascii_lowercase()];
            // A literal hop without a user logs in as the target's user, resolved as for the target below: the
            // connection's own user name, unless it is empty or still a `<placeholder>`, else the config's user.
            let mut target = conn.clone();
            let own_unusable = conn.settings.username.as_deref().map_or(true, |u| u.trim().is_empty() || !sshworkflow::find_placeholders(u).is_empty());
            if own_unusable {
                target.settings.username = e.user.clone();
            }
            jumps = expand_jumps(spec, &store, &imported, &mut seen, &target)?;
        }
        conn.host = e.hostname;
        conn.settings.port = e.port;
        if username.trim().is_empty() || !sshworkflow::find_placeholders(username).is_empty() {
            *username = e.user.unwrap_or_default();
        }
    }
    let left = sshworkflow::find_placeholders(username);
    if !left.is_empty() {
        return Err(FfiError::NeedsConfiguration { missing: left });
    }
    // A shared gateway is the first hop, ahead of any ProxyJump chain from the SSH config.
    if let Some(gw) = library.with_doc(|d| bastion_core::gateway::for_connection(d, conn.id))? {
        let mut hop = Connection::new(gw.name.clone(), bastion_core::model::Protocol::Ssh, gw.host.clone());
        hop.settings.port = gw.port;
        hop.classification = conn.classification.clone();
        let user = gw.username.clone().unwrap_or_else(|| username.clone());
        jumps.insert(0, JumpTarget { conn: hop, username: user });
        if jumps.len() > MAX_JUMP_HOPS {
            return Err(FfiError::failed(format!("gateway plus ProxyJump chain is longer than {MAX_JUMP_HOPS} hops")));
        }
    }
    Ok(jumps)
}

fn imported_by_alias(library: &Library) -> FfiResult<HashMap<String, Connection>> {
    library.with_doc(|doc| {
        Ok(doc
            .connections()
            .into_iter()
            .filter(|r| r.connection.metadata.contains_key("SshConfigIdentity"))
            .map(|r| {
                let mut c = r.connection;
                c.settings = r.effective;
                (c.name.to_ascii_lowercase(), c)
            })
            .collect())
    })
}

fn expand_jumps(spec: &str, store: &WorkflowStore, imported: &HashMap<String, Connection>, seen: &mut Vec<String>, target: &Connection) -> FfiResult<Vec<JumpTarget>> {
    let mut out = Vec::new();
    if spec.trim().eq_ignore_ascii_case("none") {
        return Ok(out);
    }
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (user, host, port) = parse_jump(part)?;
        match imported.get(&host.to_ascii_lowercase()).filter(|_| port.is_none()) {
            Some(alias) => {
                let key = alias.name.to_ascii_lowercase();
                if seen.contains(&key) {
                    return Err(FfiError::failed(format!("ProxyJump loop through `{}`", alias.name)));
                }
                seen.push(key);
                let e = store.effective_for_connection(alias).ok_or_else(|| FfiError::failed(format!("jump host `{host}` is not an imported host")))?;
                if !e.ready() {
                    return Err(FfiError::NeedsConfiguration { missing: e.unresolved });
                }
                if let Some(nested) = &e.proxy_jump {
                    out.extend(expand_jumps(nested, store, imported, seen, target)?);
                }
                let mut c = alias.clone();
                c.host = e.hostname;
                c.settings.port = e.port;
                let username = user.or(e.user).unwrap_or_default();
                out.push(JumpTarget { conn: c, username });
            }
            None => {
                let mut c = Connection::new(part, bastion_core::model::Protocol::Ssh, host);
                c.settings.port = port;
                c.classification = target.classification.clone();
                // A literal jump host without a user connects as the target's user, like OpenSSH would use the local user.
                let username = user.or_else(|| target.settings.username.clone()).unwrap_or_default();
                out.push(JumpTarget { conn: c, username });
            }
        }
        if out.len() > MAX_JUMP_HOPS {
            return Err(FfiError::failed(format!("ProxyJump chain is longer than {MAX_JUMP_HOPS} hops")));
        }
    }
    Ok(out)
}

/// `[ssh://][user@]host[:port]`, with `[v6]:port` for IPv6 literals.
fn parse_jump(s: &str) -> FfiResult<(Option<String>, String, Option<u16>)> {
    let bad = || FfiError::failed(format!("cannot read ProxyJump entry `{s}`"));
    let rest = s.strip_prefix("ssh://").unwrap_or(s);
    let (user, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_string()), h),
        None => (None, rest),
    };
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let (h, tail) = v6.split_once(']').ok_or_else(bad)?;
        (h.to_string(), tail.strip_prefix(':').map(|p| p.parse::<u16>().map_err(|_| bad())).transpose()?)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p.parse::<u16>().map_err(|_| bad())?)),
            None => (hostport.to_string(), None),
        }
    };
    let ok = |v: &str| sshworkflow::validate_value(v).is_ok();
    if host.is_empty() || !ok(&host) || user.as_deref().is_some_and(|u| !ok(u)) || port == Some(0) {
        return Err(bad());
    }
    Ok((user, host, port))
}

#[cfg(test)]
mod tests {
    use super::parse_jump;

    #[test]
    fn jump_specs_parse() {
        assert_eq!(parse_jump("bastion").unwrap(), (None, "bastion".into(), None));
        assert_eq!(parse_jump("ops@10.0.0.1:2200").unwrap(), (Some("ops".into()), "10.0.0.1".into(), Some(2200)));
        assert_eq!(parse_jump("ssh://a@[::1]:22").unwrap(), (Some("a".into()), "::1".into(), Some(22)));
        for bad in ["", "h:0", "h:x", "-oProxyCommand=x", "[::1", "a b"] {
            assert!(parse_jump(bad).is_err(), "{bad}");
        }
    }
}

/// One forward line in the OpenSSH import preview.
#[derive(uniffi::Record, Debug, Clone)]
pub struct SshForwardRow {
    pub key: String,
    pub host_identity: String,
    pub host_alias: String,
    /// `local`, `remote` or `dynamic`.
    pub kind: String,
    pub line: String,
    pub description: String,
    /// One plain sentence on what it does and that it starts on connect.
    pub explain: String,
    pub warning: String,
    pub blocked: String,
}

impl From<bastion_core::sshforwards::ForwardRow> for SshForwardRow {
    fn from(r: bastion_core::sshforwards::ForwardRow) -> Self {
        use bastion_core::sshforwards::ForwardKind::*;
        let kind = match r.kind { Local => "local", Remote => "remote", Dynamic => "dynamic" }.to_owned();
        SshForwardRow { key: r.key, host_identity: r.host_identity, host_alias: r.host_alias, kind, line: r.line, description: r.description, explain: r.explain, warning: r.warning, blocked: r.blocked }
    }
}
