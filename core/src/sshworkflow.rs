//! Optional local workflow for team-shared OpenSSH configs (owner clarification, 2026-11-01).
//!
//! Teams keep `~/.ssh/config` and `~/.ssh/config.d/*` in a Git host and pull them by hand.
//! Bastion only ever **reads** those files. Everything personal lives in a separate
//! `ssh-workflow.json` next to the library, keyed by the stable host identity:
//! - placeholder answers (`User <user>` → `User alice`), global or per host;
//! - personal overrides (user, hostname, port, key, ProxyJump, credential reference);
//! - a snapshot of the sources, so a later scan can say what was added, changed or removed.
//!
//! Every part is independently switchable in [`WorkflowSettings`], and nothing here is needed
//! for manual connections. There is no Git, GitLab or network code in this module by design.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::{Connection, Document, Folder, Node};
use crate::sshconfig::{Discovery, Limits, ResolvedHost, SshConfig};

const FORMAT_VERSION: u32 = 1;
const MAX_VALUE_LEN: usize = 255;
const MAX_STORE_BYTES: u64 = 4 * 1024 * 1024;
/// Library metadata key set on hosts that disappeared from the sources.
pub const STATUS_KEY: &str = "SshConfigStatus";
pub const STATUS_REMOVED: &str = "removed-from-source";

/// Each switch is independent. Defaults: everything available, nothing automatic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkflowSettings {
    /// Read `config.d/*` files that `config` does not include (each file = customer group).
    pub scan_config_d: bool,
    /// Detect `<name>` placeholders and substitute personal values.
    pub placeholders: bool,
    /// Apply personal per-host overrides.
    pub overrides: bool,
    /// Keep a snapshot of the sources and report changes on rescan.
    pub change_detection: bool,
    /// Directory to scan instead of `~/.ssh`.
    pub ssh_dir: Option<PathBuf>,
}

impl Default for WorkflowSettings {
    fn default() -> Self {
        WorkflowSettings { scan_config_d: true, placeholders: true, overrides: true, change_detection: true, ssh_dir: None }
    }
}

/// Personal values for one host. `None` keeps the source value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostOverride {
    pub user: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
    /// Reference to a credential (`provider:item`); never the secret itself.
    pub credential_ref: Option<String>,
    /// Placeholder answers for this host only; they win over the global ones.
    pub placeholders: BTreeMap<String, String>,
}

impl HostOverride {
    fn is_empty(&self) -> bool {
        *self == HostOverride::default()
    }
}

/// Source state at the last refresh.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshot {
    pub files: BTreeMap<String, FileState>,
    pub hosts: BTreeMap<String, HostRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileState {
    pub sha256: String,
    pub len: u64,
    pub mtime_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRecord {
    pub alias: String,
    pub group: String,
    pub source_file: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkflowData {
    pub version: u32,
    pub settings: WorkflowSettings,
    /// Global placeholder answers (`user` → `alice`).
    pub placeholder_values: BTreeMap<String, String>,
    pub hosts: BTreeMap<String, HostOverride>,
    pub snapshot: Option<SourceSnapshot>,
    /// Unix seconds of the last import or sync (shown as "Last synced"); `None` before the first.
    pub last_synced_secs: Option<u64>,
}

/// `ssh-workflow.json`: personal data kept apart from the (read-only) source files.
pub struct WorkflowStore {
    path: PathBuf,
    pub data: WorkflowData,
}

impl WorkflowStore {
    /// Load, or start empty when the file does not exist yet.
    pub fn open(path: impl Into<PathBuf>) -> Result<WorkflowStore> {
        let path = path.into();
        let data = match std::fs::metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => WorkflowData { version: FORMAT_VERSION, ..Default::default() },
            Err(e) => return Err(e.into()),
            Ok(m) if m.len() > MAX_STORE_BYTES => return Err(CoreError::Invalid(format!("{} is too large", path.display()))),
            Ok(_) => {
                let d: WorkflowData = serde_json::from_slice(&std::fs::read(&path)?).map_err(|e| CoreError::Corrupt(format!("{}: {e}", path.display())))?;
                if d.version > FORMAT_VERSION {
                    return Err(CoreError::Invalid(format!("{} was written by a newer Gantry (format {})", path.display(), d.version)));
                }
                d
            }
        };
        Ok(WorkflowStore { path, data })
    }

    pub fn save(&self) -> Result<()> {
        crate::store::write_atomic(&self.path, &serde_json::to_vec_pretty(&self.data).map_err(|e| CoreError::Invalid(e.to_string()))?)
    }

    /// The directory to scan: the configured one, else `~/.ssh`.
    pub fn ssh_dir(&self) -> Option<PathBuf> {
        self.data.settings.ssh_dir.clone().or_else(|| crate::sshconfig::home_dir().map(|h| h.join(".ssh")))
    }

    /// Scan the sources read-only with the current discovery switches.
    pub fn scan(&self, root: &Path) -> SshConfig {
        let opts = Discovery { scan_config_d: self.data.settings.scan_config_d, ..Default::default() };
        SshConfig::discover_opts(root, &opts, &Limits::default())
    }

    pub fn set_placeholder(&mut self, name: &str, value: &str) -> Result<()> {
        validate_placeholder_name(name)?;
        validate_value(value)?;
        self.data.placeholder_values.insert(name.to_string(), value.to_string());
        Ok(())
    }

    pub fn clear_placeholder(&mut self, name: &str) {
        self.data.placeholder_values.remove(name);
    }

    /// Replace one host's overrides (an empty override removes the entry).
    pub fn set_override(&mut self, identity: &str, o: HostOverride) -> Result<()> {
        for v in [&o.user, &o.hostname, &o.identity_file, &o.proxy_jump, &o.credential_ref].into_iter().flatten() {
            validate_value(v)?;
        }
        for (k, v) in &o.placeholders {
            validate_placeholder_name(k)?;
            validate_value(v)?;
        }
        if o.port == Some(0) {
            return Err(CoreError::Invalid("port 0 is not valid".into()));
        }
        if o.is_empty() {
            self.data.hosts.remove(identity);
        } else {
            self.data.hosts.insert(identity.to_string(), o);
        }
        Ok(())
    }

    /// What Bastion would use to connect to `h`: source values, then placeholder answers,
    /// then personal overrides, each only when its switch is on.
    pub fn effective(&self, h: &ResolvedHost) -> EffectiveHost {
        self.effective_values(SourceValues {
            identity: h.identity.clone(),
            alias: h.alias.clone(),
            hostname: h.hostname.clone(),
            user: h.user.clone(),
            port: h.port,
            identity_file: h.identity_files.first().cloned(),
            proxy_jump: h.proxy_jump.clone(),
        })
    }

    /// Same as [`effective`](Self::effective) for an imported library connection, using the
    /// source values recorded on it at import/refresh time. `None` for manual connections.
    pub fn effective_for_connection(&self, c: &Connection) -> Option<EffectiveHost> {
        let identity = c.metadata.get("SshConfigIdentity")?.clone();
        Some(self.effective_values(SourceValues {
            identity,
            alias: c.name.clone(),
            hostname: c.host.clone(),
            user: c.settings.username.clone(),
            port: c.settings.port,
            identity_file: c.metadata.get("IdentityFile").cloned(),
            proxy_jump: c.metadata.get("ProxyJump").cloned(),
        }))
    }

    fn effective_values(&self, h: SourceValues) -> EffectiveHost {
        let s = &self.data.settings;
        let o = if s.overrides { self.data.hosts.get(&h.identity).cloned().unwrap_or_default() } else { HostOverride::default() };
        let answers: BTreeMap<String, String> = if s.placeholders {
            let mut a = self.data.placeholder_values.clone();
            a.extend(o.placeholders.clone());
            a
        } else {
            BTreeMap::new()
        };
        let fill = |v: Option<String>| v.map(|v| substitute(&v, &answers));
        let mut e = EffectiveHost {
            identity: h.identity.clone(),
            alias: h.alias.clone(),
            hostname: substitute(&h.hostname, &answers),
            user: fill(h.user),
            port: h.port,
            identity_file: fill(h.identity_file),
            proxy_jump: fill(h.proxy_jump),
            credential_ref: None,
            unresolved: vec![],
        };
        if s.overrides {
            e.hostname = o.hostname.clone().unwrap_or(e.hostname);
            e.user = o.user.clone().or(e.user);
            e.port = o.port.or(e.port);
            e.identity_file = o.identity_file.clone().or(e.identity_file);
            e.proxy_jump = o.proxy_jump.clone().or(e.proxy_jump);
            e.credential_ref = o.credential_ref.clone();
        }
        let mut left = BTreeSet::new();
        for v in [Some(&e.hostname), e.user.as_ref(), e.identity_file.as_ref(), e.proxy_jump.as_ref()].into_iter().flatten() {
            left.extend(find_placeholders(v));
        }
        e.unresolved = left.into_iter().collect();
        e
    }

    /// Compare the current sources with the stored snapshot. With change detection off, or on
    /// the first run, there is no baseline and every host is reported as added.
    pub fn changes(&self, root: &Path, cfg: &SshConfig) -> ChangeSet {
        let new = snapshot(root, cfg);
        let empty = SourceSnapshot::default();
        let old = if self.data.settings.change_detection { self.data.snapshot.as_ref().unwrap_or(&empty) } else { &empty };
        diff(old, &new)
    }

    /// Record the current sources as the new baseline (call after the user applied a refresh).
    pub fn record_snapshot(&mut self, root: &Path, cfg: &SshConfig) {
        self.data.last_synced_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs());
        if self.data.settings.change_detection {
            self.data.snapshot = Some(snapshot(root, cfg));
        }
    }

    /// Cheap check for "did anything change on disk since the baseline?" (size/mtime first,
    /// hash only when those differ). Files that appeared in `config.d` count as changes too.
    pub fn sources_changed(&self, root: &Path, cfg: &SshConfig) -> bool {
        let Some(old) = &self.data.snapshot else { return true };
        let current: BTreeSet<&String> = cfg.files.iter().collect();
        if current != old.files.keys().collect() {
            return true;
        }
        old.files.iter().any(|(rel, st)| match file_state(&root.join(rel)) {
            Some(now) => now.len != st.len || (now.mtime_secs != st.mtime_secs && now.sha256 != st.sha256),
            None => true,
        })
    }
}

/// Source-file values for one host, before placeholders and overrides.
struct SourceValues {
    identity: String,
    alias: String,
    hostname: String,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
    proxy_jump: Option<String>,
}

/// The values a connect would use, plus anything still unanswered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveHost {
    pub identity: String,
    pub alias: String,
    pub hostname: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
    pub credential_ref: Option<String>,
    /// Placeholder names still present; a host with any is "needs configuration".
    pub unresolved: Vec<String>,
}

impl EffectiveHost {
    pub fn ready(&self) -> bool {
        self.unresolved.is_empty()
    }
}

/// `<name>` tokens in a value, e.g. `User <user>` → `["user"]`. OpenSSH's own `%h`/`${VAR}`
/// syntax is not treated as a placeholder.
pub fn find_placeholders(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = v;
    while let Some(start) = rest.find('<') {
        let after = &rest[start + 1..];
        match after.find('>') {
            Some(end) if is_placeholder_name(&after[..end]) => {
                out.push(after[..end].to_string());
                rest = &after[end + 1..];
            }
            _ => rest = after,
        }
    }
    out
}

/// Placeholders used anywhere in a host's source values.
pub fn host_placeholders(h: &ResolvedHost) -> BTreeSet<String> {
    let mut vals: Vec<&String> = vec![&h.hostname];
    vals.extend(h.user.iter());
    vals.extend(h.identity_files.iter());
    vals.extend(h.certificate_files.iter());
    vals.extend(h.proxy_jump.iter());
    vals.extend(h.identity_agent.iter());
    vals.into_iter().flat_map(|v| find_placeholders(v)).collect()
}

fn is_placeholder_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn validate_placeholder_name(name: &str) -> Result<()> {
    if is_placeholder_name(name) { Ok(()) } else { Err(CoreError::Invalid(format!("`{name}` is not a valid placeholder name"))) }
}

/// Personal values end up in hostnames, usernames and paths: no control characters, no
/// whitespace, no leading `-` (could read as an option), no nested placeholders, bounded length.
pub fn validate_value(v: &str) -> Result<()> {
    let bad = v.is_empty()
        || v.len() > MAX_VALUE_LEN
        || v.starts_with('-')
        || v.chars().any(|c| c.is_control() || c.is_whitespace())
        || !find_placeholders(v).is_empty();
    if bad { Err(CoreError::Invalid(format!("`{}` is not an acceptable value", v.escape_debug()))) } else { Ok(()) }
}

fn substitute(v: &str, answers: &BTreeMap<String, String>) -> String {
    let mut out = v.to_string();
    for name in find_placeholders(v) {
        if let Some(val) = answers.get(&name) {
            out = out.replace(&format!("<{name}>"), val);
        }
    }
    out
}

fn file_state(path: &Path) -> Option<FileState> {
    let meta = std::fs::metadata(path).ok()?;
    let bytes = std::fs::read(path).ok()?;
    Some(FileState {
        sha256: hex::encode(Sha256::digest(&bytes)),
        len: meta.len(),
        mtime_secs: meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0),
    })
}

fn host_fields(h: &ResolvedHost) -> BTreeMap<String, String> {
    let mut f = BTreeMap::new();
    f.insert("HostName".into(), h.hostname.clone());
    let opt = [
        ("User", h.user.clone()),
        ("Port", h.port.map(|p| p.to_string())),
        ("ProxyJump", h.proxy_jump.clone()),
        ("ProxyCommand", h.proxy_command.clone()),
        ("IdentityAgent", h.identity_agent.clone()),
        ("HostKeyAlias", h.host_key_alias.clone()),
        ("StrictHostKeyChecking", h.strict_host_key_checking.clone()),
        ("ServerAliveInterval", h.server_alive_interval.map(|v| v.to_string())),
        ("ConnectTimeout", h.connect_timeout.map(|v| v.to_string())),
    ];
    for (k, v) in opt {
        if let Some(v) = v {
            f.insert(k.into(), v);
        }
    }
    if !h.identity_files.is_empty() {
        f.insert("IdentityFile".into(), h.identity_files.join(", "));
    }
    f
}

/// Current source state (file hashes plus every resolved host's fields).
pub fn snapshot(root: &Path, cfg: &SshConfig) -> SourceSnapshot {
    SourceSnapshot {
        files: cfg.files.iter().filter_map(|rel| file_state(&root.join(rel)).map(|s| (rel.clone(), s))).collect(),
        hosts: cfg
            .hosts()
            .into_iter()
            .map(|h| (h.identity.clone(), HostRecord { alias: h.alias.clone(), group: h.group.clone(), source_file: h.source_file.clone(), fields: host_fields(&h) }))
            .collect(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Changed,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldChange {
    pub field: String,
    pub old: Option<String>,
    pub new: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostChange {
    pub identity: String,
    pub alias: String,
    pub group: String,
    pub source_file: String,
    pub kind: ChangeKind,
    pub fields: Vec<FieldChange>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeSet {
    pub hosts: Vec<HostChange>,
    /// Source files whose content changed, appeared or disappeared.
    pub files: Vec<String>,
}

impl ChangeSet {
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.files.is_empty()
    }
}

pub fn diff(old: &SourceSnapshot, new: &SourceSnapshot) -> ChangeSet {
    let mut out = ChangeSet::default();
    let names: BTreeSet<&String> = old.files.keys().chain(new.files.keys()).collect();
    out.files = names.into_iter().filter(|n| old.files.get(*n).map(|s| &s.sha256) != new.files.get(*n).map(|s| &s.sha256)).cloned().collect();
    let change = |id: &String, r: &HostRecord, kind, fields| HostChange {
        identity: id.clone(),
        alias: r.alias.clone(),
        group: r.group.clone(),
        source_file: r.source_file.clone(),
        kind,
        fields,
    };
    for (id, r) in &new.hosts {
        match old.hosts.get(id) {
            None => out.hosts.push(change(id, r, ChangeKind::Added, vec![])),
            Some(prev) if prev.fields != r.fields => {
                let keys: BTreeSet<&String> = prev.fields.keys().chain(r.fields.keys()).collect();
                let fields = keys
                    .into_iter()
                    .filter(|k| prev.fields.get(*k) != r.fields.get(*k))
                    .map(|k| FieldChange { field: k.clone(), old: prev.fields.get(k).cloned(), new: r.fields.get(k).cloned() })
                    .collect();
                out.hosts.push(change(id, r, ChangeKind::Changed, fields));
            }
            Some(_) => {}
        }
    }
    for (id, r) in &old.hosts {
        if !new.hosts.contains_key(id) {
            out.hosts.push(change(id, r, ChangeKind::Removed, vec![]));
        }
    }
    out
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RefreshSummary {
    pub added: u32,
    pub updated: u32,
    pub marked_removed: u32,
}

/// Import `hosts` into one top-level folder per customer group. Hosts whose identity is
/// already in the library are skipped (deterministic dedupe).
pub fn import_hosts(doc: &mut Document, hosts: &[ResolvedHost]) -> Result<u32> {
    let mut existing = BTreeSet::new();
    collect_identities(&doc.root, &mut existing);
    // Top-level group folders by name (first wins), built once rather than per host (H03).
    let mut groups: HashMap<String, usize> = HashMap::new();
    for (i, n) in doc.root.children.iter().enumerate() {
        if let Node::Folder(f) = n {
            groups.entry(f.name.clone()).or_insert(i);
        }
    }
    let mut added = 0;
    for h in hosts.iter().filter(|h| !existing.contains(&h.identity)) {
        let idx = *groups.entry(h.group.clone()).or_insert_with(|| {
            doc.root.children.push(Node::Folder(Folder { id: Uuid::new_v4(), name: h.group.clone(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() }));
            doc.root.children.len() - 1
        });
        if let Node::Folder(f) = &mut doc.root.children[idx] {
            f.children.push(Node::Connection(h.to_connection()));
        }
        added += 1;
    }
    Ok(added)
}

fn collect_identities(folder: &Folder, out: &mut BTreeSet<String>) {
    for n in &folder.children {
        match n {
            Node::Folder(f) => collect_identities(f, out),
            Node::Connection(c) => out.extend(c.metadata.get("SshConfigIdentity").cloned()),
        }
    }
}

/// Apply a reviewed change set to the library. Changed hosts get their source-derived fields
/// (host, port, user, keepalive, provenance metadata) refreshed while id, name, tags, notes,
/// favourite, classification and any other metadata are kept. Removed hosts are only marked,
/// never deleted, so the user decides. Added hosts are imported only when `import_added`.
pub fn apply_refresh(doc: &mut Document, cfg: &SshConfig, changes: &ChangeSet, import_added: bool) -> Result<RefreshSummary> {
    let current: BTreeMap<String, ResolvedHost> = cfg.hosts().into_iter().map(|h| (h.identity.clone(), h)).collect();
    let mut summary = RefreshSummary::default();
    let mut to_add = Vec::new();
    let mut changed: HashMap<&str, &ResolvedHost> = HashMap::new();
    let mut removed: BTreeSet<&str> = BTreeSet::new();
    let mut present = BTreeSet::new();
    collect_identities(&doc.root, &mut present);
    for c in &changes.hosts {
        match c.kind {
            // A host that vanished and came back is "added" again but is still in the library
            // (marked removed): refresh it in place, which also clears the mark.
            ChangeKind::Added if present.contains(&c.identity) => {
                if let Some(h) = current.get(&c.identity) {
                    changed.insert(h.identity.as_str(), h);
                }
            }
            ChangeKind::Added => {
                if import_added {
                    to_add.extend(current.get(&c.identity).cloned());
                }
            }
            ChangeKind::Changed => {
                if let Some(h) = current.get(&c.identity) {
                    changed.insert(h.identity.as_str(), h);
                }
            }
            ChangeKind::Removed => {
                removed.insert(c.identity.as_str());
            }
        }
    }
    // One traversal for every update and removal (H03); counts are per change, as before.
    let mut hit_changed = BTreeSet::new();
    let mut hit_removed = BTreeSet::new();
    apply_changes(&mut doc.root, &changed, &removed, &mut hit_changed, &mut hit_removed);
    summary.updated += hit_changed.len() as u32;
    summary.marked_removed += hit_removed.len() as u32;
    summary.added = import_hosts(doc, &to_add)?;
    Ok(summary)
}

const SOURCE_KEYS: &[&str] = &[
    "SourceFile",
    "Group",
    "ProxyJump",
    "ProxyCommand",
    "IdentityAgent",
    "HostKeyAlias",
    "UserKnownHostsFile",
    "StrictHostKeyChecking",
    "IdentityFile",
    "PubkeyAcceptedAlgorithms",
    "RequestTTY",
    "RemoteCommand",
    "AddKeysToAgent",
    "ExitOnForwardFailure",
    "SendEnv",
    "SetEnv",
];

/// Re-import `hosts` (for example after scanning `config.d` again) without duplicating any:
/// a host already in the library is refreshed in place, including one imported earlier from
/// another checkout of the same tree (same customer folder and alias, different identity),
/// which takes the new identity. Only hosts not found either way are added.
pub fn reimport_hosts(doc: &mut Document, hosts: &[ResolvedHost]) -> Result<RefreshSummary> {
    let mut summary = RefreshSummary::default();
    let mut fresh = Vec::new();
    let by_identity: HashMap<&str, &ResolvedHost> = hosts.iter().map(|h| (h.identity.as_str(), h)).collect();
    let mut hit = BTreeSet::new();
    apply_changes(&mut doc.root, &by_identity, &BTreeSet::new(), &mut hit, &mut BTreeSet::new());
    for h in hosts {
        if hit.contains(h.identity.as_str()) || adopt_moved(&mut doc.root, h) {
            summary.updated += 1;
        } else {
            fresh.push(h.clone());
        }
    }
    summary.added = import_hosts(doc, &fresh)?;
    Ok(summary)
}

/// Find an imported connection named `h.alias` in `h.group`'s top-level folder whose identity
/// is not in the current scan, re-key it to `h.identity` and refresh it.
fn adopt_moved(root: &mut Folder, h: &ResolvedHost) -> bool {
    let Some(Node::Folder(group)) = root.children.iter_mut().find(|n| matches!(n, Node::Folder(f) if f.name == h.group)) else {
        return false;
    };
    let found = group.children.iter_mut().find_map(|n| match n {
        Node::Connection(c) if c.name.eq_ignore_ascii_case(&h.alias) && c.metadata.get("SshConfigIdentity").is_some_and(|id| *id != h.identity) => Some(c),
        _ => None,
    });
    let Some(c) = found else { return false };
    c.metadata.insert("SshConfigIdentity".into(), h.identity.clone());
    update_connection(group, h)
}

fn update_connection(folder: &mut Folder, h: &ResolvedHost) -> bool {
    let mut hit = BTreeSet::new();
    apply_changes(folder, &HashMap::from([(h.identity.as_str(), h)]), &BTreeSet::new(), &mut hit, &mut BTreeSet::new());
    !hit.is_empty()
}

/// Refresh every connection whose identity is in `changed` and mark those in `removed`, in a
/// single walk. The identities that matched are collected so callers can count them.
fn apply_changes<'a>(folder: &mut Folder, changed: &HashMap<&'a str, &ResolvedHost>, removed: &BTreeSet<&'a str>, hit_changed: &mut BTreeSet<&'a str>, hit_removed: &mut BTreeSet<&'a str>) {
    for n in &mut folder.children {
        match n {
            Node::Folder(f) => apply_changes(f, changed, removed, hit_changed, hit_removed),
            Node::Connection(c) => {
                let Some(id) = c.metadata.get("SshConfigIdentity") else { continue };
                if let Some((key, h)) = changed.get_key_value(id.as_str()) {
                    hit_changed.insert(*key);
                    refresh_connection(c, h);
                } else if let Some(key) = removed.get(id.as_str()) {
                    hit_removed.insert(*key);
                    c.metadata.insert(STATUS_KEY.into(), STATUS_REMOVED.into());
                }
            }
        }
    }
}

fn refresh_connection(c: &mut Connection, h: &ResolvedHost) {
    let fresh = h.to_connection();
    c.host = fresh.host;
    c.settings.port = fresh.settings.port;
    c.settings.username = fresh.settings.username;
    c.settings.keepalive_secs = fresh.settings.keepalive_secs;
    // The user's "Allow for this host" survives a refresh; the lists follow the file.
    let allow_weak = c.settings.ssh_algorithms.as_ref().is_some_and(|a| a.allow_weak);
    c.settings.ssh_algorithms = fresh.settings.ssh_algorithms.map(|a| crate::algorithms::AlgorithmSettings { allow_weak, ..a });
    for k in SOURCE_KEYS {
        match fresh.metadata.get(*k) {
            Some(v) => c.metadata.insert(k.to_string(), v.clone()),
            None => c.metadata.remove(*k),
        };
    }
    c.metadata.remove(STATUS_KEY);
}

/// Most hops a ProxyJump chain may expand to (nested ProxyJumps included).
pub const MAX_JUMP_HOPS: usize = 8;

/// One resolved jump host: where to connect and as whom.
pub struct JumpTarget {
    pub conn: Connection,
    pub username: String,
}

/// Apply the workflow to an imported connection right before connecting: placeholders and
/// overrides are resolved in memory only, and a ProxyJump is expanded into a chain of jump
/// hosts (aliases resolve to imported library hosts with their own placeholders, overrides and
/// nested ProxyJumps; anything else is parsed as `[user@]host[:port]`). Refuses when anything
/// is unanswered, when the chain loops, or when it is longer than `MAX_JUMP_HOPS`.
pub fn prepare_connection(store: &WorkflowStore, imported: &HashMap<String, Connection>, conn: &mut Connection, username: &mut String) -> Result<Vec<JumpTarget>> {
    let mut jumps = Vec::new();
    if let Some(e) = store.effective_for_connection(conn) {
        if !e.ready() {
            return Err(CoreError::NeedsConfiguration { missing: e.unresolved });
        }
        if let Some(spec) = &e.proxy_jump {
            let mut seen = vec![conn.name.to_ascii_lowercase()];
            jumps = expand_jumps(spec, store, imported, &mut seen, conn)?;
        }
        conn.host = e.hostname;
        conn.settings.port = e.port;
        if username.trim().is_empty() || !find_placeholders(username).is_empty() {
            *username = e.user.unwrap_or_default();
        }
    }
    let left = find_placeholders(username);
    if !left.is_empty() {
        return Err(CoreError::NeedsConfiguration { missing: left });
    }
    check_proxy_command(conn, &jumps)?;
    Ok(jumps)
}

/// Longest ProxyCommand quoted back in an error.
const MAX_SHOWN_PROXY_COMMAND: usize = 300;

/// THREAT_MODEL T16: Bastion never runs a ProxyCommand (there is no code that could). A host that
/// relies on one is refused rather than reached directly, which would bypass the proxy the
/// config asked for, unless a ProxyJump (from the config or a personal override) replaces it.
pub fn check_proxy_command(conn: &Connection, jumps: &[JumpTarget]) -> Result<()> {
    let Some(cmd) = conn.metadata.get("ProxyCommand").filter(|c| !c.trim().is_empty()) else { return Ok(()) };
    if !jumps.is_empty() {
        return Ok(());
    }
    let shown: String = cmd.chars().take(MAX_SHOWN_PROXY_COMMAND).collect();
    Err(CoreError::PolicyDenied(format!(
        "{} uses ProxyCommand `{shown}`, which Gantry does not run. Set a ProxyJump in My overrides to reach it through a jump host instead.",
        conn.name
    )))
}

/// Imported library hosts by lower-case alias, with inherited settings resolved (jump targets).
pub fn imported_by_alias(doc: &Document) -> HashMap<String, Connection> {
    doc
        .connections()
        .into_iter()
        .filter(|r| r.connection.metadata.contains_key("SshConfigIdentity"))
        .map(|r| {
            let mut c = r.connection;
            c.settings = r.effective;
            (c.name.to_ascii_lowercase(), c)
        })
        .collect()
}

fn expand_jumps(spec: &str, store: &WorkflowStore, imported: &HashMap<String, Connection>, seen: &mut Vec<String>, target: &Connection) -> Result<Vec<JumpTarget>> {
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
                    return Err(CoreError::Invalid(format!("ProxyJump loop through `{}`", alias.name)));
                }
                seen.push(key);
                let e = store.effective_for_connection(alias).ok_or_else(|| CoreError::Invalid(format!("jump host `{host}` is not an imported host")))?;
                if !e.ready() {
                    return Err(CoreError::NeedsConfiguration { missing: e.unresolved });
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
                let mut c = Connection::new(part, crate::model::Protocol::Ssh, host);
                c.settings.port = port;
                c.classification = target.classification.clone();
                // A literal jump host without a user connects as the target's user, like OpenSSH would use the local user.
                let username = user.or_else(|| target.settings.username.clone()).unwrap_or_default();
                out.push(JumpTarget { conn: c, username });
            }
        }
        if out.len() > MAX_JUMP_HOPS {
            return Err(CoreError::Invalid(format!("ProxyJump chain is longer than {MAX_JUMP_HOPS} hops")));
        }
    }
    Ok(out)
}

/// `[ssh://][user@]host[:port]`, with `[v6]:port` for IPv6 literals.
pub fn parse_jump(s: &str) -> Result<(Option<String>, String, Option<u16>)> {
    let bad = || CoreError::Invalid(format!("cannot read ProxyJump entry `{s}`"));
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
    let ok = |v: &str| validate_value(v).is_ok();
    if host.is_empty() || !ok(&host) || user.as_deref().is_some_and(|u| !ok(u)) || port == Some(0) {
        return Err(bad());
    }
    Ok((user, host, port))
}
