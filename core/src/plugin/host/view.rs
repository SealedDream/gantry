//! One open plugin view: its helper, its compiled code and the calls the plugin makes
//! (PLUG-02b part 2; spec sections 4 and 5).
//!
//! [`open`] runs, in order: the installed package (hash checked by `load_installed`), the load
//! gate and the pool (`Pool::start_view`), the compiled code from the [`CodeStore`] (compiled by a
//! compile helper when missing; a mismatch is audited and compiled again), `Load`, then `Run`.
//! A thread then answers every import the plugin makes:
//!
//! - `host`, `log`, `ui` and `events` need no permission. View lists are checked with the
//!   broker's `check_view` before the app sees them, and held back past 30 updates a second.
//! - `storage` is checked against the grants on every call and writes through the secret check.
//! - `net` goes through the [`Relay`]: direct streams to the entry's host with the core's TLS
//!   (see `relay.rs`). Streams through gateways and tunnels are refused until the route relay.
//! - `credentials.entry-login` (PLUG-08): with permission `credentials = "entry"`, the login the
//!   app's vault released for this entry ([`ViewSpec::login`]: its own or inherited login, after
//!   the scope check, never a same-host one) goes to the helper once, only while every open
//!   stream passes its TLS login gate, and is audited as `credential.release.plugin`. From then
//!   on it is in the released-secret check. Without a login, or with no stream, it is refused.
//! - `clipboard.write-text` and `files.save` go to the app right after a user action (`view_files.rs`);
//!   `files.open` is refused until the apps draw its dialog.
//! - `ui.confirm` goes to the app; the answer is audited (`plugin.confirm`).
//!
//! The app reads updates as JSON with [`ViewSession::next_update`] and sends what the user did
//! with [`ViewSession::send_event`]. [`ViewSession::close`] (and drop) sends `stop`, waits 2 s for
//! `run` to return, then kills the helper.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};

use super::proto::{ToCore, ToHelper, Value, CHUNK};
use super::relay::{EntryTls, HttpJob, Outcome, Relay, SessionState};
use crate::plugin::broker::http_session::{self, LoginMethod};
use super::storage::{EntryStorage, PluginLog, MAX_STORAGE_VALUE_BYTES};
use super::store::{CodeStore, Stored};
use super::{write_audit, Event, Launch, Pool, Slot, Stopped};
use crate::plugin::broker::audit::{self as plugin_audit, ConfirmKind, MAX_PROMPT_TEXT_BYTES};
use crate::plugin::broker::cache::{max_compiled_bytes, CacheKey, COMPILE_TIME_LIMIT_MS};
use crate::plugin::broker::gate::Rollout;
use crate::plugin::broker::grants::{Binding, Call, HelperGrants};
use crate::plugin::broker::http::{self as http, HttpSpec, PluginRequest};
use crate::plugin::broker::secret::SecretCheck;
use crate::plugin::broker::view::{check_view, patched_view, NodeRef, UpdateRate, MAX_UPDATES_PER_SECOND};
use crate::plugin::broker::{Failure, StopReason};
use crate::plugin::SIDEBAR_VIEW;
use crate::plugin::{load_installed, PluginFolders};
use crate::policy::Policy;

/// The plugin's own memory limit (spec section 5, "Caps").
pub const PLUGIN_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
/// Compute time per call between two `events.next` (spec section 5, "Hangs").
pub const COMPUTE_MS: u32 = 2_000;
/// `run` must return this soon after `stop`.
pub const STOP_GRACE: Duration = Duration::from_secs(2);
/// How long the helper may take to load checked code.
const LOAD_LIMIT: Duration = Duration::from_secs(10);
/// Updates the app has not read yet; past it the oldest go.
const MAX_PENDING_UPDATES: usize = 256;
/// Events the user made that the plugin has not taken yet.
const MAX_PENDING_EVENTS: usize = 1_024;
/// One answer to an ask (rows, children, completions, marks) is at most this large as JSON.
const MAX_ANSWER_BYTES: usize = 16 * 1024 * 1024;
/// The view the app opens first.
pub const FIRST_VIEW: u32 = 1;
/// How often the dispatch thread looks at the app's events while the plugin waits.
const POLL: Duration = Duration::from_millis(10);

const API: &str = "bastion:plugin/";
/// API 1.0, 1.1 and 1.2 (1.1 adds `http`, `docs/specs/plugins-amendment-2.md`; 1.2 adds `open`,
/// `docs/specs/plugins-amendment-3.md`). Older plugins' imports keep their names; the calls
/// are the same.
/// 1.3 changes no types (`docs/plans/PLUG-API-13.md`); 1.4 changes only the manifest, so it has
/// no imports of its own; 1.5 adds `exec` (`docs/specs/plugins.md`, section 19); 1.6 adds UI
/// types (`docs/plans/PLUG-API-16.md`).
const VERSIONS: [&str; 6] = ["@1.0.0", "@1.1.0", "@1.2.0", "@1.3.0", "@1.5.0", "@1.6.0"];
/// Denied-request audits per helper: at most one a second (note section 7).
const HTTP_DENIED_AUDIT_EVERY: Duration = Duration::from_secs(1);

/// The library entry a view is opened on, as the app passes it.
#[derive(Debug, Clone)]
pub struct EntryBinding {
    pub document_id: String,
    pub entry_id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub fields: Vec<(String, String)>,
    /// The entry's document is protected: storage lasts only as long as the view.
    pub protected: bool,
    /// The environment named by policy, for confirmations ("Production").
    pub environment: String,
    /// The entry's TLS mode, pin, "Allow unencrypted" and route (core-owned, never plugin fields).
    pub tls: EntryTls,
    /// The entry's connection type, local to the plugin (`esxi`), as the library has it. Picks
    /// the type's login method from the signed manifest (design D). Empty: the view name, when
    /// it is a type, decides.
    pub connection_type: String,
}

/// What to open.
#[derive(Debug, Clone)]
pub struct ViewSpec {
    pub data_dir: PathBuf,
    pub plugin_id: String,
    /// The connection type's view, a command's view, or `settings`.
    pub view_name: String,
    pub entry: Option<EntryBinding>,
    pub policy: Policy,
    pub allow_unverified: bool,
    pub safe_mode: bool,
    /// The entry's login, released by the vault for this entry. For `[http] auth` the core keeps
    /// it and never sends it; with `credentials = "entry"` it goes to the helper once, on
    /// `entry-login`. Used only when the view is opened on an entry and the manifest asks for
    /// one of the two; otherwise dropped at once.
    pub login: Option<EntryLogin>,
}

/// A password login the vault released for one entry's plugin view.
pub struct EntryLogin {
    pub user: String,
    pub secret: zeroize::Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for EntryLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EntryLogin(<withheld>)")
    }
}

impl Clone for EntryLogin {
    fn clone(&self) -> Self {
        EntryLogin { user: self.user.clone(), secret: self.secret.clone() }
    }
}

fn invalid(e: impl std::fmt::Display) -> Failure {
    Failure::Invalid(e.to_string())
}

fn not_prepared() -> Failure {
    Failure::Invalid("Plugin could not be prepared".into())
}

fn audit_now(data_dir: &std::path::Path, a: &plugin_audit::PluginAudit) {
    if let Err(e) = write_audit(&data_dir.join("audit.jsonl"), a) {
        eprintln!("bastion: plugin audit write failed: {e}");
    }
}

/// The cache key: the component, and the helper's engine key (Wasmtime version and the hash of
/// the settings that change generated code) plus the OS and CPU.
pub fn cache_key(component: &[u8], engine_key: &str) -> CacheKey {
    CacheKey {
        component_sha256: hex::encode(Sha256::digest(component)),
        wasmtime_version: engine_key.to_string(),
        os: std::env::consts::OS.to_string(),
        target: std::env::consts::ARCH.to_string(),
        settings_hash: engine_key.to_string(),
    }
}

fn send_bytes(slot: &Slot, bytes: &[u8]) -> Result<(), Failure> {
    for piece in bytes.chunks(CHUNK) {
        slot.helper.send(&ToHelper::Chunk(piece.to_vec())).map_err(invalid)?;
    }
    slot.helper.send(&ToHelper::End).map_err(invalid)
}

/// Runs a compile helper for `component`, within the time and output limits, and stores what
/// it returns with its SHA-256.
pub(super) fn compile(pool: &Pool, launch: &Launch<'_>, store: &CodeStore, key: &CacheKey, component: &[u8]) -> Result<Vec<u8>, Failure> {
    let slot = pool.start_compile(launch, &key.component_sha256)?;
    if slot.helper.engine_key != key.wasmtime_version {
        return Err(not_prepared());
    }
    let cap = max_compiled_bytes(component.len() as u64);
    slot.helper.send(&ToHelper::Compile { total: component.len() as u64, max_output: cap }).map_err(invalid)?;
    send_bytes(&slot, component)?;
    let deadline = Instant::now() + Duration::from_millis(COMPILE_TIME_LIMIT_MS);
    let mut code = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match slot.helper.next_event(left) {
            Some(Event::Message(ToCore::Compiled(piece))) => {
                if (code.len() + piece.len()) as u64 > cap {
                    return Err(not_prepared());
                }
                code.extend_from_slice(&piece);
            }
            Some(Event::Message(ToCore::CompileDone { error: None })) => break,
            // A limit, an error, a crash or the clock: dropping the slot kills the helper.
            _ => return Err(not_prepared()),
        }
    }
    store.save(key, component.len() as u64, &code)?;
    Ok(code)
}

/// Opens a view: see the module docs. Returns once the plugin runs.
pub fn open(pool: &Pool, spec: ViewSpec) -> Result<ViewSession, Failure> {
    let folders = PluginFolders::new(&spec.data_dir);
    let (package, tier) = load_installed(&folders, &spec.plugin_id).map_err(|e| Failure::Denied(e.to_string()))?;
    let version = package.manifest.version.to_string();
    // API 1.3: the library-sidebar tree opens only on an entry whose plugin declares one.
    let sidebar = spec.view_name == SIDEBAR_VIEW;
    if sidebar && (spec.entry.is_none() || !package.manifest.connection_types.iter().any(|t| t.sidebar_tree)) {
        return Err(Failure::Denied("this connection type has no sidebar tree".into()));
    }
    let launch = Launch { policy: &spec.policy, rollout: Rollout::current(), plugin_id: &spec.plugin_id, tier, allow_unverified: spec.allow_unverified, safe_mode: spec.safe_mode };

    let slot = pool.start_view(&launch, PLUGIN_MEMORY_BYTES)?;
    let store = CodeStore::new(&spec.data_dir);
    let key = cache_key(&package.wasm, &slot.helper.engine_key);
    let code = match store.load(&key)? {
        Stored::Valid(code) => code,
        found => {
            if found == Stored::Mismatch {
                audit_now(&spec.data_dir, &plugin_audit::cache_mismatch(&spec.plugin_id, &version, &key.component_sha256));
            }
            compile(pool, &launch, &store, &key, &package.wasm)?
        }
    };

    slot.helper.send(&ToHelper::Load { memory_limit: PLUGIN_MEMORY_BYTES, compute_ms: COMPUTE_MS, total: code.len() as u64 }).map_err(invalid)?;
    send_bytes(&slot, &code)?;
    drop(code);
    match slot.helper.next_event(LOAD_LIMIT) {
        Some(Event::Message(ToCore::Loaded { error: None })) => {}
        Some(Event::Message(ToCore::Loaded { error: Some(e) })) => return Err(Failure::Invalid(format!("Plugin could not be loaded: {e}"))),
        _ => return Err(Failure::Invalid("Plugin could not be loaded".into())),
    }
    slot.helper.send(&ToHelper::Run).map_err(invalid)?;

    let binding = match &spec.entry {
        Some(e) => Binding::Entry { entry_id: e.entry_id.clone(), temporary: false },
        None => Binding::NoEntry,
    };
    let grants = HelperGrants::new(&spec.plugin_id, &version, package.manifest.permissions.clone(), binding);
    let plugin_data = folders.data_dir_of(&spec.plugin_id).map_err(|e| Failure::Denied(e.to_string()))?;
    let storage = spec.entry.as_ref().map(|e| EntryStorage::open(&plugin_data, &e.document_id, &e.entry_id, e.protected));
    let listed_ports: Vec<u16> = package.manifest.connection_types.iter().filter_map(|t| t.default_port).collect();
    let mut relay = spec.entry.as_ref().map(|e| Relay::new(&e.host, e.port, listed_ports.clone(), e.tls.clone(), spec.policy.clone()));
    if let (Some(r), Some(h)) = (relay.as_mut(), &package.manifest.http) {
        r.set_http_ports(h.ports.clone());
    }
    let login = http_login(&spec, package.manifest.http.as_ref(), login_method(&package.manifest, &spec));
    if let (Some(r), Some(s)) = (relay.as_mut(), login.as_ref().and_then(|l| l.session.clone())) {
        r.set_session(s);
    }

    let shared = Arc::new(SessionShared { updates: Mutex::new(VecDeque::new()), updated: Condvar::new(), closing: AtomicBool::new(false) });
    let (events_tx, events_rx) = mpsc::sync_channel(MAX_PENDING_EVENTS);
    // The first thing the plugin hears: open the view it was started for.
    let first = variant("open-view", record(vec![("view", Value::U32(FIRST_VIEW)), ("name", Value::String(spec.view_name.clone()))]));
    let _ = events_tx.try_send(AppEvent::Plugin(first));
    let dispatch = Dispatch {
        slot,
        grants,
        storage,
        relay,
        log: PluginLog::open(&plugin_data),
        released: SecretCheck::new(),
        rate: UpdateRate::new(),
        started: Instant::now(),
        next_request: 1,
        replies: VecDeque::new(),
        confirms: Vec::new(),
        pending_save: None,
        waiting_next: None,
        stop_at: None,
        shared: shared.clone(),
        events: events_rx,
        data_dir: spec.data_dir.clone(),
        entry: spec.entry.clone(),
        http: package.manifest.http.clone(),
        http_pending: std::collections::BTreeMap::new(),
        http_denied_at: None,
        login,
        entry_login: entry_login(&spec, package.manifest.permissions.credentials_entry),
        trees: std::collections::HashMap::new(),
        policy: spec.policy.clone(),
        open: view_open::OpenState::new(package.manifest.open.clone()),
        exec: view_exec::ExecState::new(package.manifest.exec.clone()),
        library: view_library::LibraryState::default(),
        sidebar,
    };
    let thread = std::thread::Builder::new().name("bastion-plugin-view".into()).spawn(move || dispatch.run()).map_err(invalid)?;
    Ok(ViewSession { shared, events: events_tx, thread: Mutex::new(Some(thread)) })
}

/// Something for the plugin's `events.next`, or the user's answer to a confirmation.
pub enum AppEvent {
    Plugin(Value),
    /// A command or input in the view: stamped when the app sent it (plugin API 1.2, section 4).
    UserAction(Value, Instant),
    ConfirmAnswer { request: u32, confirmed: bool },
    /// The user's answer to an `open.connection` sheet (plugin API 1.2).
    OpenAnswer { request: u32, accept: bool, route: crate::plugin::broker::open::RouteChoice, credential_chosen: bool, save_as_entry: bool },
    /// The app's answer to `exec-go` or `exec-terminal` (plugin API 1.5).
    ExecAnswer(view_exec::ExecAnswer),
    /// The user's answer to a `files.save` panel: the path, or `None` when cancelled.
    SaveAnswer { request: u32, path: Option<String> },
    /// The user's answer to a `library.propose` sheet (plugin API 1.6): how many connections
    /// were saved, or `None` when cancelled.
    LibraryAnswer { request: u32, saved: Option<u32>, credential_linked: bool },
}

struct SessionShared {
    updates: Mutex<VecDeque<Json>>,
    updated: Condvar,
    closing: AtomicBool,
}

impl SessionShared {
    fn push(&self, update: Json) {
        let mut q = self.updates.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() >= MAX_PENDING_UPDATES {
            q.pop_front();
        }
        q.push_back(update);
        self.updated.notify_all();
    }
}

/// An open view, held by the app.
pub struct ViewSession {
    shared: Arc<SessionShared>,
    events: mpsc::SyncSender<AppEvent>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl ViewSession {
    /// The next update for the app, waiting at most `timeout`; `None` when there is none yet.
    /// `{"type":"ended","reason":..}` is the last one.
    pub fn next_update(&self, timeout: Duration) -> Option<Json> {
        let q = self.shared.updates.lock().unwrap_or_else(|e| e.into_inner());
        let (mut q, _) = self.shared.updated.wait_timeout_while(q, timeout, |q| q.is_empty()).unwrap_or_else(|e| e.into_inner());
        q.pop_front()
    }

    /// What the user did, as JSON (see [`event_from_json`]).
    pub fn send_event(&self, event: &Json) -> Result<(), Failure> {
        let event = event_from_json(event)?;
        self.events.try_send(event).map_err(|_| Failure::Invalid("the plugin is not taking events".into()))
    }

    /// Sends `stop`, waits up to 2 s for `run` to return, then kills the helper.
    pub fn close(&self) {
        self.shared.closing.store(true, Ordering::SeqCst);
        let thread = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(thread) = thread {
            let _ = thread.join();
        }
    }
}

impl Drop for ViewSession {
    fn drop(&mut self) {
        self.close();
    }
}

// ---- values ----

fn record(fields: Vec<(&str, Value)>) -> Value {
    Value::Record(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn variant(name: &str, payload: Value) -> Value {
    Value::Variant(name.into(), Some(Box::new(payload)))
}

fn ok_unit() -> Value {
    Value::Result(Ok(None))
}

fn failure_value(f: &Failure) -> Value {
    match f {
        Failure::Denied(r) => variant("denied", Value::String(r.clone())),
        Failure::Invalid(r) => variant("invalid", Value::String(r.clone())),
        Failure::Io(r) => variant("io", Value::String(r.clone())),
        Failure::TimedOut => Value::Variant("timed-out".into(), None),
    }
}

fn err_value(f: &Failure) -> Value {
    Value::Result(Err(Some(Box::new(failure_value(f)))))
}

fn field<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    match v {
        Value::Record(fields) => fields.iter().find(|(k, _)| k == name).map(|(_, v)| v),
        _ => None,
    }
}

fn as_u32(v: Option<&Value>) -> Option<u32> {
    match v {
        Some(Value::U32(n)) => Some(*n),
        _ => None,
    }
}

fn as_u16(v: Option<&Value>) -> Option<u16> {
    match v {
        Some(Value::U16(n)) => Some(*n),
        _ => None,
    }
}

fn as_str(v: Option<&Value>) -> Option<&str> {
    match v {
        Some(Value::String(s)) => Some(s),
        _ => None,
    }
}

/// A WIT value as JSON for the app: records are objects, variants `{"kind":..,"value":..}`,
/// options are the value or `null`, results `{"ok":..}` or `{"err":..}`.
pub fn to_json(v: &Value) -> Json {
    match v {
        Value::Bool(b) => json!(b),
        Value::S8(n) => json!(n),
        Value::U8(n) => json!(n),
        Value::S16(n) => json!(n),
        Value::U16(n) => json!(n),
        Value::S32(n) => json!(n),
        Value::U32(n) => json!(n),
        Value::S64(n) => json!(n),
        Value::U64(n) => json!(n),
        Value::F32(n) => json!(n),
        Value::F64(n) => json!(n),
        Value::Char(c) => json!(c.to_string()),
        Value::String(s) => json!(s),
        Value::Bytes(b) => json!(b),
        Value::List(items) | Value::Tuple(items) => Json::Array(items.iter().map(to_json).collect()),
        Value::Record(fields) => Json::Object(fields.iter().map(|(k, v)| (k.clone(), to_json(v))).collect()),
        Value::Variant(name, payload) => json!({ "kind": name, "value": payload.as_deref().map(to_json) }),
        Value::Enum(name) => json!(name),
        Value::Option(inner) => inner.as_deref().map(to_json).unwrap_or(Json::Null),
        Value::Result(Ok(inner)) => json!({ "ok": inner.as_deref().map(to_json) }),
        Value::Result(Err(inner)) => json!({ "err": inner.as_deref().map(to_json) }),
        Value::Flags(names) => json!(names),
    }
}

/// Reads a node list's ids and parents and its JSON for the app, with the JSON's size.
/// The minor number of an accepted `@1.<minor>.0` suffix.
fn api_minor(api: &str) -> u32 {
    api.strip_prefix("@1.").and_then(|r| r.strip_suffix(".0")).and_then(|m| m.parse().ok()).unwrap_or(0)
}

/// A `ui` event whose input is a tree item's menu item.
fn is_menu_input(event: &Value) -> bool {
    let Value::Variant(name, Some(payload)) = event else { return false };
    name == "ui" && matches!(field(payload, "input"), Some(Value::Variant(kind, _)) if kind == "menu")
}

/// The sidebar view (API 1.3) is exactly one root `tree` node, set with `set-view`.
fn sidebar_nodes(func: &str, view: Option<u32>, nodes: &Value) -> Result<(), Failure> {
    let bad = || Failure::Invalid("the sidebar view is one tree, set with set-view".into());
    if func != "set-view" || view != Some(FIRST_VIEW) {
        return Err(bad());
    }
    let Value::List(items) = nodes else { return Err(bad()) };
    let [node] = items.as_slice() else { return Err(bad()) };
    let is_root = matches!(field(node, "parent"), Some(Value::Option(None)));
    let is_tree = matches!(field(node, "component"), Some(Value::Variant(name, _)) if name == "tree");
    if is_root && is_tree { Ok(()) } else { Err(bad()) }
}

fn node_refs(nodes: &Value) -> Result<(Vec<NodeRef>, Json, usize), Failure> {
    let Value::List(items) = nodes else { return Err(Failure::Invalid("a view is a list of nodes".into())) };
    let refs: Vec<NodeRef> = items
        .iter()
        .map(|n| {
            let id = as_u32(field(n, "id")).ok_or_else(|| Failure::Invalid("a node has no id".into()))?;
            let parent = match field(n, "parent") {
                Some(Value::Option(None)) => None,
                Some(Value::Option(Some(p))) => Some(as_u32(Some(p)).ok_or_else(|| Failure::Invalid("a parent is not a node id".into()))?),
                _ => return Err(Failure::Invalid("a node has no parent field".into())),
            };
            Ok(NodeRef { id, parent })
        })
        .collect::<Result<_, Failure>>()?;
    let json = to_json(nodes);
    let size = serde_json::to_vec(&json).map(|b| b.len()).unwrap_or(usize::MAX);
    Ok((refs, json, size))
}

/// Checks a whole node list with the broker's rules (size, count, ids, parents, cycles, depth)
/// and returns it as JSON for the app.
fn checked_nodes(nodes: &Value) -> Result<Json, Failure> {
    let (refs, json, size) = node_refs(nodes)?;
    check_view(&refs, size)?;
    Ok(json)
}

/// Checks a patch against the view it produces (`current` is the view's tree now) and returns
/// the patch's JSON and the new tree. A patch may resend a child without its parent.
fn checked_patch(current: &[NodeRef], upsert: &Value, remove: Option<&Value>) -> Result<(Json, Vec<NodeRef>), Failure> {
    let (refs, json, size) = node_refs(upsert)?;
    let remove: Vec<u32> = match remove {
        None | Some(Value::Option(None)) => Vec::new(),
        Some(Value::List(ids)) => ids.iter().map(|v| as_u32(Some(v)).ok_or_else(|| Failure::Invalid("a removed id is not a node id".into()))).collect::<Result<_, _>>()?,
        Some(_) => return Err(Failure::Invalid("`remove` is not a list of node ids".into())),
    };
    // The patch alone: no id twice, size and count caps.
    let mut seen = std::collections::HashSet::new();
    if let Some(n) = refs.iter().find(|n| !seen.insert(n.id)) {
        return Err(Failure::Invalid(format!("node id {} is used twice", n.id)));
    }
    let tree = patched_view(current, &refs, &remove);
    check_view(&tree, size)?;
    Ok((json, tree))
}

// ---- events from the app ----

fn str_of<'a>(j: &'a Json, key: &str) -> Result<&'a str, Failure> {
    j.get(key).and_then(Json::as_str).ok_or_else(|| Failure::Invalid(format!("`{key}` is missing")))
}

fn u32_of(j: &Json, key: &str) -> Result<u32, Failure> {
    j.get(key).and_then(Json::as_u64).and_then(|n| u32::try_from(n).ok()).ok_or_else(|| Failure::Invalid(format!("`{key}` is missing")))
}

fn input_from_json(j: &Json) -> Result<Value, Failure> {
    let kind = str_of(j, "kind")?;
    Ok(match kind {
        "pressed" => Value::Variant("pressed".into(), None),
        "text" => variant("text", Value::String(str_of(j, "value")?.into())),
        "run" => variant("run", Value::String(str_of(j, "value")?.into())),
        "number" => variant("number", Value::F64(j.get("value").and_then(Json::as_f64).ok_or_else(|| invalid("`value` is missing"))?)),
        "choice" => variant("choice", Value::U32(u32_of(j, "value")?)),
        "toggled" => variant("toggled", Value::Bool(j.get("value").and_then(Json::as_bool).ok_or_else(|| invalid("`value` is missing"))?)),
        "menu" => variant("menu", Value::Tuple(vec![Value::String(str_of(j, "key")?.into()), Value::String(str_of(j, "item")?.into())])),
        "selected" => {
            let keys = j.get("keys").and_then(Json::as_array).ok_or_else(|| invalid("`keys` is missing"))?;
            let keys = keys.iter().map(|k| k.as_str().map(|s| Value::String(s.into())).ok_or_else(|| invalid("a key is not text"))).collect::<Result<_, _>>()?;
            variant("selected", Value::List(keys))
        }
        "sorted" => variant("sorted", Value::Tuple(vec![Value::U32(u32_of(j, "column")?), Value::Bool(j.get("ascending").and_then(Json::as_bool).unwrap_or(true))])),
        other => return Err(Failure::Invalid(format!("unknown input `{other}`"))),
    })
}

/// The events the app may send, as JSON objects with a `type`. Anything else is refused; in
/// particular the app cannot send `stop` (close does) or a `reply` (only the core answers).
///
/// - `{"type":"open-view","view":2,"name":"settings"}`, `{"type":"close-view","view":2}`
/// - `{"type":"command","id":"...","view":1}` (`view` optional)
/// - `{"type":"ui","view":1,"node":7,"input":{"kind":"pressed"}}`; inputs `text` and `run`
///   (`value` text), `number`, `choice`, `toggled` (`value`), `menu` (`key`, `item`), `selected`
///   (`keys`), `sorted` (`column`, `ascending`)
/// - `{"type":"rows","ask":3,"view":1,"node":7,"offset":0,"count":100}` (count at most 1,000)
/// - `{"type":"children","ask":4,"view":1,"node":7,"parent":"key"}` (`parent` optional)
/// - `{"type":"completions","ask":5,"view":1,"node":7,"text":"sel","offset":3}`
/// - `{"type":"cancel","view":1}`
/// - `{"type":"confirm","request":9,"confirmed":true}`: the user's answer to a confirmation
/// - `{"type":"save","request":9,"path":"/abs/file.csv"}` (or `"path":null`): the answer to a save panel (`view_files.rs`)
/// - `{"type":"library","request":9,"saved":2,"credential_linked":false}` (or `"saved":null`): the answer to a library sheet (`view_library.rs`)
pub fn event_from_json(j: &Json) -> Result<AppEvent, Failure> {
    let kind = str_of(j, "type")?;
    let view = || u32_of(j, "view").map(Value::U32);
    let node = || u32_of(j, "node").map(Value::U32);
    let ask = || u32_of(j, "ask").map(Value::U32);
    let event = match kind {
        "open-view" => variant("open-view", record(vec![("view", view()?), ("name", Value::String(str_of(j, "name")?.into()))])),
        "close-view" => variant("close-view", view()?),
        "command" => variant(
            "command",
            record(vec![("id", Value::String(str_of(j, "id")?.into())), ("view", Value::Option(u32_of(j, "view").ok().map(|v| Box::new(Value::U32(v)))))]),
        ),
        "ui" => {
            let input = input_from_json(j.get("input").ok_or_else(|| invalid("`input` is missing"))?)?;
            variant("ui", record(vec![("view", view()?), ("node", node()?), ("input", input)]))
        }
        "rows" => {
            let count = u32_of(j, "count")?;
            if count > 1_000 {
                return Err(Failure::Invalid("at most 1,000 rows at a time".into()));
            }
            let offset = Value::U64(j.get("offset").and_then(Json::as_u64).unwrap_or(0));
            variant("rows", record(vec![("ask", ask()?), ("view", view()?), ("node", node()?), ("offset", offset), ("count", Value::U32(count))]))
        }
        "children" => {
            let parent = Value::Option(j.get("parent").and_then(Json::as_str).map(|p| Box::new(Value::String(p.into()))));
            variant("children", record(vec![("ask", ask()?), ("view", view()?), ("node", node()?), ("parent", parent)]))
        }
        "completions" => variant(
            "completions",
            record(vec![("ask", ask()?), ("view", view()?), ("node", node()?), ("text", Value::String(str_of(j, "text")?.into())), ("offset", Value::U32(u32_of(j, "offset")?))]),
        ),
        "cancel" => variant("cancel", view()?),
        "open" => return view_open::answer_from_json(j),
        "library" => return view_library::answer_from_json(j),
        "save" => return view_files::answer_from_json(j),
        "exec" => return view_exec::answer_from_json(j),
        "confirm" => {
            let confirmed = j.get("confirmed").and_then(Json::as_bool).ok_or_else(|| invalid("`confirmed` is missing"))?;
            return Ok(AppEvent::ConfirmAnswer { request: u32_of(j, "request")?, confirmed });
        }
        other => return Err(Failure::Invalid(format!("unknown event `{other}`"))),
    };
    if view_open::is_user_action(&event) {
        return Ok(AppEvent::UserAction(event, Instant::now()));
    }
    Ok(AppEvent::Plugin(event))
}

// ---- the dispatch thread ----

/// A confirmation waiting for the user. Keeps the digest the audit record needs, never the
/// plugin's full text, so a plugin cannot grow the core's memory through it (SEC-4).
struct PendingConfirm {
    request: u32,
    kind: ConfirmKind,
    text_sha256: [u8; 32],
    text_cut: bool,
}

/// Confirmations a view may have open at once. One more is a protocol violation: a plugin
/// that loops `ui.confirm` without waiting for answers is stopped (SEC-4).
const MAX_OPEN_CONFIRMS: usize = 4;

/// Whether one more confirmation would go over [`MAX_OPEN_CONFIRMS`].
fn confirms_full(open: usize) -> bool {
    open >= MAX_OPEN_CONFIRMS
}

/// Replies the core keeps for a plugin that has not taken them yet. Each request the plugin
/// makes adds at most one, so past this the plugin is not reading its replies.
const MAX_QUEUED_REPLIES: usize = 1_024;

fn replies_full(queued: usize) -> bool {
    queued >= MAX_QUEUED_REPLIES
}

struct Dispatch {
    slot: Slot,
    grants: HelperGrants,
    storage: Option<EntryStorage>,
    /// The entry's streams; `None` for a view opened on no entry.
    relay: Option<Relay>,
    log: PluginLog,
    /// Passwords released to this helper. Nothing is released before the relay lands.
    released: SecretCheck,
    rate: UpdateRate,
    started: Instant,
    next_request: u32,
    /// Replies to earlier requests, given out through `events.next` before the app's events.
    /// Each with the stream request it answers, if any: the relay keeps that request's room
    /// reserved until the plugin takes the reply.
    replies: VecDeque<(Value, Option<u32>)>,
    confirms: Vec<PendingConfirm>,
    /// A `files.save` waiting for the app's panel.
    pending_save: Option<view_files::PendingSave>,
    /// The `seq` of the `events.next` the plugin waits on.
    waiting_next: Option<u64>,
    /// When the view began closing: `run` must return within `STOP_GRACE`.
    stop_at: Option<Instant>,
    shared: Arc<SessionShared>,
    events: mpsc::Receiver<AppEvent>,
    data_dir: PathBuf,
    entry: Option<EntryBinding>,
    /// The manifest's `[http]` table (API 1.1).
    http: Option<HttpSpec>,
    /// `http.send` requests the relay is serving: for the change audit and the echo check.
    http_pending: std::collections::BTreeMap<u32, HttpPending>,
    http_denied_at: Option<Instant>,
    /// The entry's login for the `[http]` auth header ([`ViewSpec::login`]). Never released to
    /// the helper. `None` when the app gave none, so a request with `with-login` is refused.
    login: Option<HttpLogin>,
    /// The login `credentials.entry-login` releases ([`entry_login`]); taken on release.
    entry_login: Option<EntryLogin>,
    /// Each open view's node ids and parents, as the app has them: a patch is checked against
    /// the tree it produces.
    trees: std::collections::HashMap<u32, Vec<NodeRef>>,
    /// The policy the view was opened under.
    policy: Policy,
    /// `open.connection` (API 1.2): the reported set, the stamp, the rate, the pending sheet.
    open: view_open::OpenState,
    exec: view_exec::ExecState,
    /// `library.propose` (API 1.6): the rate and the pending sheet.
    library: view_library::LibraryState,
    /// The view is the library-sidebar tree (API 1.3): one root `tree` node, no patches, no dialogs.
    sidebar: bool,
}

/// The entry's connection type's login method, from the signed manifest only (design D,
/// review HIGH 1). Nothing the plugin sends can change it.
fn login_method(manifest: &crate::plugin::manifest::Manifest, spec: &ViewSpec) -> Option<LoginMethod> {
    let entry = spec.entry.as_ref()?;
    let named = if entry.connection_type.is_empty() { spec.view_name.as_str() } else { entry.connection_type.as_str() };
    match manifest.connection_types.iter().find(|c| c.id == named) {
        Some(c) => c.login,
        // A stated type the manifest does not have: no login.
        None if !entry.connection_type.is_empty() => None,
        // No type known (a command's view): the header login of a manifest without sessions.
        None => manifest.http.as_ref().filter(|h| h.session.is_none() && h.auth.is_some()).map(|_| LoginMethod::Auth),
    }
}

/// Design D, review MEDIUM 4 and HIGH 1: with a session in the manifest, no plugin POST to the
/// login path or below it (`/sdk/vimService`) may call the server's session methods, whatever the
/// entry's type.
fn refuse_session_call(spec: &HttpSpec, req: &PluginRequest) -> Result<(), Failure> {
    let Some(session) = &spec.session else { return Ok(()) };
    if req.method == http::Method::Post && http_session::targets_login_path(&req.target, &session.login_path) && http_session::calls_session_method(&req.body) {
        return Err(Failure::Denied(http_session::SESSION_CALL_REFUSED.into()));
    }
    Ok(())
}

/// The core's own entry field: the entry's connection type (design D). A manifest field key is
/// a lowercase label, so `:` can never be the plugin's; a saved value under it is dropped.
pub const TYPE_FIELD: &str = ":type";

/// `entry-info`'s fields: the plugin's own, then [`TYPE_FIELD`] when the type is known.
fn entry_fields(e: &EntryBinding) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = e.fields.iter().filter(|(k, _)| !k.starts_with(':')).cloned().collect();
    if !e.connection_type.is_empty() {
        fields.push((TYPE_FIELD.to_string(), e.connection_type.clone()));
    }
    fields
}

/// The login the core keeps for this view: only with an entry, the type's login method, the
/// manifest table that method needs, and a user name and secret.
fn http_login(spec: &ViewSpec, http: Option<&HttpSpec>, method: Option<LoginMethod>) -> Option<HttpLogin> {
    let login = spec.login.as_ref()?;
    let entry = spec.entry.as_ref()?;
    let http = http?;
    if login.secret.is_empty() {
        return None;
    }
    let session = match method? {
        LoginMethod::Auth => {
            http.auth.as_ref()?;
            None
        }
        LoginMethod::Session => Some(SessionState::new(http.session.clone()?, login.user.clone(), login.secret.clone(), &spec.plugin_id, &entry.entry_id)),
    };
    let mut check = SecretCheck::new();
    check.add(&login.secret);
    Some(HttpLogin { user: login.user.clone(), secret: login.secret.clone(), check, method: method?, session })
}

/// The login `credentials.entry-login` may release: only on an entry, only with the permission.
fn entry_login(spec: &ViewSpec, permitted: bool) -> Option<EntryLogin> {
    spec.entry.as_ref()?;
    let login = spec.login.as_ref().filter(|l| permitted && !l.secret.is_empty())?;
    Some(login.clone())
}

/// The release itself: the grant, the gate, the login (taken, so once per helper), then the
/// password joins the released-secret check. The reply is `login(record { user, secret })`.
fn release_entry_login(grants: &mut HelperGrants, gate: Result<(), Failure>, login: &mut Option<EntryLogin>, released: &mut SecretCheck) -> Result<Value, Failure> {
    let no_login = || Failure::Denied("the entry has no saved login, or saved logins are locked".into());
    grants.begin_release(gate, login.is_none()).map_err(|f| match f {
        Failure::Denied(t) if t == "credentials are locked" => no_login(),
        f => f,
    })?;
    let login = login.take().ok_or_else(no_login)?;
    let secret = String::from_utf8(login.secret.to_vec()).map_err(|_| Failure::Invalid("the saved password is not text".into()))?;
    released.add(&login.secret);
    Ok(variant("login", record(vec![("user", Value::String(login.user)), ("secret", Value::String(secret))])))
}

/// A login the core holds for one helper's `http` requests.
struct HttpLogin {
    user: String,
    secret: zeroize::Zeroizing<Vec<u8>>,
    /// The secret alone, for the request check and the echo check.
    check: SecretCheck,
    /// The connection type's one method (design D).
    method: LoginMethod,
    /// With [`LoginMethod::Session`]: the cookies and their secret check, shared with the relay.
    session: Option<Arc<SessionState>>,
}

impl HttpLogin {
    /// The password, and for a session every cookie, in any form the checks know.
    fn matches(&self, bytes: &[u8]) -> bool {
        self.check.matches(bytes) || self.session.as_ref().is_some_and(|s| s.matches(bytes))
    }
}

struct HttpPending {
    method: http::Method,
    path: String,
    with_login: bool,
    /// The whole target and the plugin's headers, for the reported-address echo check (API 1.2).
    /// Kept only when the manifest declares `[open] address_fields`.
    seen: Option<(String, Vec<(String, String)>)>,
}

fn http_request_of(args: &[Value]) -> Result<PluginRequest, Failure> {
    let bad = |what: &str| Failure::Invalid(format!("an http request {what}"));
    let r = args.first().ok_or_else(|| bad("is missing"))?;
    let method = match field(r, "method") {
        Some(Value::Enum(m)) => http::Method::from_wit(m).ok_or_else(|| bad("has an unknown method"))?,
        _ => return Err(bad("has no method")),
    };
    let port = match field(r, "port") {
        Some(Value::Option(None)) | None => None,
        Some(Value::Option(Some(p))) => match **p {
            Value::U16(p) => Some(p),
            _ => return Err(bad("port is not a number")),
        },
        _ => return Err(bad("port is not a number")),
    };
    let target = as_str(field(r, "target")).ok_or_else(|| bad("has no target"))?.to_string();
    let headers = match field(r, "headers") {
        Some(Value::List(items)) => items
            .iter()
            .map(|t| match t {
                Value::Tuple(pair) if pair.len() == 2 => match (&pair[0], &pair[1]) {
                    (Value::String(n), Value::String(v)) => Ok((n.clone(), v.clone())),
                    _ => Err(bad("header is not two strings")),
                },
                _ => Err(bad("header is not two strings")),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(bad("has no headers list")),
    };
    let body = match field(r, "body") {
        Some(Value::Bytes(b)) => b.clone(),
        Some(Value::List(l)) if l.is_empty() => Vec::new(),
        _ => return Err(bad("body is not bytes")),
    };
    let with_login = matches!(field(r, "with-login"), Some(Value::Bool(true)));
    let timeout_ms = match field(r, "timeout-ms") {
        Some(Value::Option(Some(t))) => match **t {
            Value::U32(t) => Some(t),
            _ => return Err(bad("timeout is not a number")),
        },
        _ => None,
    };
    Ok(PluginRequest { method, port, target, headers, body, with_login, timeout_ms })
}

fn http_response_value(resp: http::HttpResponse) -> Value {
    let headers = resp.headers.into_iter().map(|(n, v)| Value::Tuple(vec![Value::String(n), Value::String(v)])).collect();
    variant("http", record(vec![("status", Value::U16(resp.status)), ("headers", Value::List(headers)), ("body", Value::Bytes(resp.body))]))
}

impl Dispatch {
    fn run(mut self) {
        let stopped = self.serve();
        let reason = stopped.reason();
        self.exec_stop_all();
        // Streams shut; abort bytes go only on an ordinary stop.
        if let Some(relay) = self.relay.as_mut() {
            relay.stop(reason);
        }
        // A closed tab is the ordinary end; every other stop is audited.
        if reason != StopReason::TabClosed {
            let detail = match &stopped {
                Stopped::Violation(why) | Stopped::ReadFailed(why) => why.clone(),
                Stopped::Exited(code) => format!("exit {code:?}"),
                _ => String::new(),
            };
            let a = plugin_audit::helper_stopped(self.grants.plugin_id(), self.grants.plugin_version(), self.grants.entry_id(), reason, &detail);
            audit_now(&self.data_dir, &a);
        }
        self.shared.push(json!({ "type": "ended", "reason": reason.as_str() }));
    }

    fn new_request(&mut self) -> u32 {
        let n = self.next_request;
        self.next_request = self.next_request.wrapping_add(1).max(1);
        n
    }

    fn reply_later(&mut self, request: u32, outcome: Result<Value, Failure>) {
        let outcome = match outcome {
            Ok(v) => Value::Result(Ok(Some(Box::new(v)))),
            Err(f) => Value::Result(Err(Some(Box::new(failure_value(&f))))),
        };
        self.replies.push_back((variant("reply", record(vec![("request", Value::U32(request)), ("outcome", outcome)])), None));
    }

    /// Hands the next queued reply to the plugin, freeing the relay's room for it.
    fn pop_reply(&mut self) -> Option<Value> {
        let (reply, stream_request) = self.replies.pop_front()?;
        if let (Some(r), Some(relay)) = (stream_request, self.relay.as_mut()) {
            relay.consumed(r);
        }
        Some(reply)
    }

    /// A plugin that keeps making requests without taking replies is stopped: replies may not
    /// pile up in the core (security review of #1331). Stream data has its own byte bound in
    /// the relay; this bounds the count for every interface.
    fn check_waiting(&self) -> Result<(), Stopped> {
        if replies_full(self.replies.len()) {
            return Err(self.violation("too many replies waiting"));
        }
        Ok(())
    }

    fn answer(&self, seq: u64, results: Vec<Value>) -> Result<(), Stopped> {
        self.slot.helper.send(&ToHelper::Reply { seq, results }).map_err(|_| Stopped::Killed(StopReason::Crash))
    }

    fn violation(&self, why: &str) -> Stopped {
        self.slot.helper.stop(StopReason::ProtocolViolation);
        Stopped::Violation(why.into())
    }

    /// The next event for a waiting plugin: a reply, `stop` when closing, or the user's event.
    fn next_for_plugin(&mut self) -> Option<Value> {
        self.take_stream_replies();
        self.exec_expire();
        if let Some(reply) = self.pop_reply() {
            return Some(reply);
        }
        if self.stop_at.is_some() {
            return Some(Value::Variant("stop".into(), None));
        }
        loop {
            match self.events.try_recv() {
                Ok(AppEvent::Plugin(v)) => return Some(v),
                Ok(AppEvent::UserAction(v, at)) => {
                    // In the sidebar only a tree item's menu (right-click or double-click) is a user
                    // action: selection or expansion there may come without the user meaning it.
                    if !self.sidebar || is_menu_input(&v) {
                        self.open.stamp.stamp(at);
                    }
                    return Some(v);
                }
                Ok(AppEvent::ConfirmAnswer { request, confirmed }) => {
                    // The core's own confirmation of a plugin command (exec, API 1.5), or a
                    // plugin's `ui.confirm`.
                    if self.exec.waits_for(request) {
                        self.exec_confirm_answer(request, confirmed);
                    } else {
                        self.confirm_answer(request, confirmed);
                    }
                    if let Some(reply) = self.pop_reply() {
                        return Some(reply);
                    }
                }
                Ok(AppEvent::ExecAnswer(a)) => {
                    self.exec_answer(a);
                    if let Some(reply) = self.pop_reply() {
                        return Some(reply);
                    }
                }
                Ok(AppEvent::SaveAnswer { request, path }) => {
                    self.save_answer(request, path);
                    if let Some(reply) = self.pop_reply() {
                        return Some(reply);
                    }
                }
                Ok(AppEvent::OpenAnswer { request, accept, route, credential_chosen, save_as_entry }) => {
                    self.open_answer(request, accept, route, credential_chosen, save_as_entry);
                    if let Some(reply) = self.pop_reply() {
                        return Some(reply);
                    }
                }
                Ok(AppEvent::LibraryAnswer { request, saved, credential_linked }) => {
                    self.library_answer(request, saved, credential_linked);
                    if let Some(reply) = self.pop_reply() {
                        return Some(reply);
                    }
                }
                Err(_) => return None,
            }
        }
    }

    /// Serves the plugin until it ends or is stopped. Returns why it stopped.
    fn serve(&mut self) -> Stopped {
        loop {
            if self.stop_at.is_none() && self.shared.closing.load(Ordering::SeqCst) {
                self.stop_at = Some(Instant::now());
            }
            if let Some(at) = self.stop_at {
                if at.elapsed() > STOP_GRACE {
                    self.slot.helper.stop(StopReason::TabClosed);
                    return Stopped::Killed(StopReason::TabClosed);
                }
            }
            if let Some(seq) = self.waiting_next {
                if let Some(event) = self.next_for_plugin() {
                    self.waiting_next = None;
                    if let Err(s) = self.answer(seq, vec![event]) {
                        return s;
                    }
                }
            }
            match self.slot.helper.next_event(POLL) {
                None => {}
                Some(Event::Stopped(s)) => return s,
                Some(Event::Message(ToCore::Ended { error })) => {
                    return match (error, self.stop_at) {
                        (None, _) | (_, Some(_)) => Stopped::Killed(StopReason::TabClosed),
                        (Some(e), None) => Stopped::ReadFailed(e.chars().take(200).collect()),
                    };
                }
                Some(Event::Message(ToCore::Import { seq, name, args })) => {
                    if self.waiting_next.is_some() {
                        return self.violation("an import while waiting for an event");
                    }
                    if let Err(s) = self.import(seq, &name, args) {
                        return s;
                    }
                }
                // Hello, Loaded, Compiled, CompileDone: out of order for a running view.
                Some(Event::Message(_)) => return self.violation("a message out of order"),
            }
        }
    }

    fn import(&mut self, seq: u64, name: &str, args: Vec<Value>) -> Result<(), Stopped> {
        let Some(rest) = name.strip_prefix(API) else { return Err(self.violation("an import outside the plugin API")) };
        let Some((iface, func)) = rest.split_once('#') else { return Err(self.violation("an import without a function")) };
        let Some((iface, api)) = VERSIONS.iter().find_map(|v| iface.strip_suffix(v).map(|i| (i, *v))) else { return Err(self.violation("an import of another API version")) };
        if iface == "http" && api == "@1.0.0" {
            return Err(self.violation("http is API 1.1"));
        }
        if iface == "open" && api_minor(api) < 2 {
            return Err(self.violation("open is API 1.2"));
        }
        if iface == "exec" && api_minor(api) < 5 {
            return Err(self.violation("exec is API 1.5"));
        }
        match (iface, func) {
            ("events", "next") => {
                self.waiting_next = Some(seq);
                Ok(())
            }
            ("host", "entry-info") => {
                let entry = self.entry.as_ref().map(|e| {
                    let fields = entry_fields(e).into_iter().map(|(k, v)| Value::Tuple(vec![Value::String(k), Value::String(v)])).collect();
                    Box::new(record(vec![
                        ("id", Value::String(e.entry_id.clone())),
                        ("name", Value::String(e.name.clone())),
                        ("host", Value::String(e.host.clone())),
                        ("port", Value::U16(e.port)),
                        ("fields", Value::List(fields)),
                    ]))
                });
                self.answer(seq, vec![Value::Option(entry)])
            }
            // The settings page's saved values come with PLUG-06; none are saved yet.
            ("host", "settings") => self.answer(seq, vec![Value::List(Vec::new())]),
            ("log", "line") => {
                let Some(Value::Enum(level)) = args.first() else { return Err(self.violation("log.line without a level")) };
                let text = as_str(args.get(1)).unwrap_or_default();
                if let Err(e) = self.log.line(level, text, &self.released, Instant::now()) {
                    eprintln!("bastion: plugin log write failed: {e}");
                }
                self.answer(seq, vec![])
            }
            ("ui", _) => self.ui(seq, func, &args),
            ("storage", _) => {
                self.check_waiting()?;
                let request = self.new_request();
                let outcome = self.storage(func, &args);
                self.reply_later(request, outcome);
                self.answer(seq, vec![Value::U32(request)])
            }
            ("net", "close") | ("net", "clear-abort") => {
                let Some(stream) = as_u32(args.first()) else { return Err(self.violation("a stream call without a stream")) };
                if let (Ok(()), Some(relay)) = (self.grants.check(Call::Connect), self.relay.as_mut()) {
                    if func == "close" {
                        relay.close(stream);
                    } else {
                        relay.clear_abort(stream);
                    }
                }
                self.answer(seq, vec![])
            }
            ("net", _) => {
                self.check_waiting()?;
                let request = self.new_request();
                if let Err(f) = self.net(request, func, &args) {
                    self.reply_later(request, Err(f));
                }
                self.answer(seq, vec![Value::U32(request)])
            }
            ("http", "send") => {
                self.check_waiting()?;
                let request = self.new_request();
                if let Err((f, step)) = self.http_send(request, &args) {
                    if let Some(step) = step {
                        self.audit_http_denied(step);
                    }
                    self.reply_later(request, Err(f));
                }
                self.answer(seq, vec![Value::U32(request)])
            }
            ("library", "propose") => {
                self.check_waiting()?;
                let request = self.new_request();
                if let Err(f) = self.library_propose(request, &args) {
                    self.reply_later(request, Err(f));
                }
                self.answer(seq, vec![Value::U32(request)])
            }
            ("open", "connection") => {
                self.check_waiting()?;
                let request = self.new_request();
                if let Err(f) = self.open_connection(request, &args) {
                    self.reply_later(request, Err(f));
                }
                self.answer(seq, vec![Value::U32(request)])
            }
            ("exec", "run") | ("exec", "terminal") => {
                self.check_waiting()?;
                let request = self.new_request();
                let outcome = if func == "run" { self.exec_run(request, &args) } else { self.exec_terminal(request, &args) };
                if let Err(f) = outcome {
                    self.reply_later(request, Err(f));
                }
                self.answer(seq, vec![Value::U32(request)])
            }
            ("exec", "cancel") => {
                if let Some(r) = as_u32(args.first()) {
                    self.exec_cancel(r);
                }
                self.answer(seq, vec![])
            }
            ("http", "cancel") => {
                if let (Some(r), Some(relay)) = (as_u32(args.first()), self.relay.as_mut()) {
                    relay.http_cancel(r);
                }
                self.answer(seq, vec![])
            }
            ("credentials", "entry-login") => {
                self.check_waiting()?;
                let request = self.new_request();
                let outcome = self.release_login();
                self.reply_later(request, outcome);
                self.answer(seq, vec![Value::U32(request)])
            }
            ("clipboard", "write-text") => {
                self.check_waiting()?;
                let request = self.new_request();
                let outcome = self.clipboard_write(&args);
                self.reply_later(request, outcome);
                self.answer(seq, vec![Value::U32(request)])
            }
            ("files", "save") => {
                self.check_waiting()?;
                let request = self.new_request();
                if let Err(f) = self.file_save(request, &args) {
                    self.reply_later(request, Err(f));
                }
                self.answer(seq, vec![Value::U32(request)])
            }
            ("credentials", _) | ("clipboard", _) | ("files", _) => {
                let call = match (iface, func) {
                    ("credentials", _) => Call::EntryLogin,
                    ("clipboard", _) => Call::ClipboardWrite,
                    (_, "save") => Call::FileSave,
                    _ => Call::FileOpen,
                };
                self.check_waiting()?;
                let request = self.new_request();
                // Fail closed: the grant is checked, and even a granted call is refused until the
                // relay and the app prompts land.
                let outcome = self.grants.check(call).and(Err(Failure::Denied("not available in this version of Gantry".into())));
                self.reply_later(request, outcome);
                self.answer(seq, vec![Value::U32(request)])
            }
            _ => Err(self.violation("an unknown import")),
        }
    }

    /// `credentials.entry-login`: the grant, the TLS login gate of the open streams, then the
    /// login, once. Audited either way when the view is on an entry; never names the login.
    fn release_login(&mut self) -> Result<Value, Failure> {
        let gate = match self.relay.as_ref() {
            Some(relay) => relay.check_login_all(),
            None => Err(Failure::Denied("this view is not opened on an entry".into())),
        };
        let result = release_entry_login(&mut self.grants, gate, &mut self.entry_login, &mut self.released);
        if let Some(entry) = self.entry.as_ref() {
            let outcome = if result.is_ok() { crate::audit::Outcome::Success } else { crate::audit::Outcome::Denied };
            audit_now(&self.data_dir, &plugin_audit::credential_release(self.grants.plugin_id(), self.grants.plugin_version(), &entry.entry_id, outcome));
        }
        result
    }

    /// Replies from the stream relay, in the order they finished.
    fn take_stream_replies(&mut self) {
        let Some(relay) = self.relay.as_mut() else { return };
        for done in relay.poll() {
            let outcome = done.outcome.map(|o| match o {
                Outcome::Opened(stream) => variant("opened", Value::U32(stream)),
                Outcome::Data(bytes) => variant("data", Value::Bytes(bytes)),
                Outcome::None => Value::Variant("none".into(), None),
                Outcome::Http(resp) => http_response_value(resp),
            });
            let outcome = self.http_finished(done.request, outcome);
            self.reply_later(done.request, outcome);
            if let Some(last) = self.replies.back_mut() {
                last.1 = Some(done.request);
            }
        }
    }

    /// `http.send`: the note's section 5, steps 1 to 8, then the relay (steps 9 and 10).
    /// A refusal names the audited step when the note audits it.
    fn http_send(&mut self, request: u32, args: &[Value]) -> Result<(), (Failure, Option<&'static str>)> {
        self.grants.check(Call::Http).map_err(|f| (f, Some("grant")))?;
        let spec = self.http.clone().ok_or_else(|| (Failure::Denied("the plugin has no http permission".into()), Some("grant")))?;
        let req = http_request_of(args).map_err(|f| (f, None))?;
        let entry = self.entry.clone().ok_or_else(|| (Failure::Denied("this view is not opened on an entry".into()), Some("grant")))?;
        // Steps 2 and 4 to 7, with the login in the secret check when it would be sent.
        let mut secrets = SecretCheck::new();
        for s in self.login.iter().map(|l| &l.secret) {
            secrets.add(s);
        }
        let step = |f: &Failure| match f {
            Failure::Denied(t) if t.contains("method") => Some("method"),
            Failure::Denied(t) if t.contains("path") => Some("path"),
            Failure::Denied(t) if t.contains("password") => Some("secret"),
            _ => None,
        };
        http::check_request(&spec, &req, &secrets).map_err(|f| (f.clone(), step(&f)))?;
        // And against the passwords released to this helper, over the same parts.
        let mut seen = req.target.clone().into_bytes();
        for (n, v) in &req.headers {
            seen.extend_from_slice(format!("\n{n}:{v}").as_bytes());
        }
        self.released.refuse(&seen).and_then(|()| self.released.refuse(&req.body)).map_err(|f| (f, Some("secret")))?;
        // Design D: a session cookie never leaves through the plugin's request either.
        if self.login.as_ref().is_some_and(|l| l.matches(&seen) || l.matches(&req.body)) {
            return Err((Failure::Denied("the request holds a password".into()), Some("secret")));
        }
        refuse_session_call(&spec, &req).map_err(|f| (f, Some("login")))?;
        // Step 3, the port, is the relay's; step 8, the login: the type's one method.
        let no_login = || (Failure::Denied("the entry has no saved login, or saved logins are locked".into()), Some("login"));
        let (auth, session) = match (req.with_login, &self.login) {
            (false, _) => (None, None),
            (true, None) => return Err(no_login()),
            (true, Some(login)) => match (login.method, &spec.auth, &login.session) {
                (LoginMethod::Auth, Some(a), _) => (Some((a.header.clone(), http::auth_value(&a.format, &login.user, &login.secret).map_err(|f| (f, Some("login")))?)), None),
                (LoginMethod::Session, _, Some(s)) => (None, Some(s.clone())),
                _ => return Err(no_login()),
            },
        };
        let tls_on = entry.tls.mode != crate::plugin::broker::stream::TlsMode::Off;
        let port = req.port.unwrap_or(entry.port);
        let host = http::host_header(&entry.host, port, tls_on);
        let wire = http::encode_request(&req, &host, self.grants.plugin_id(), auth.as_ref().map(|(n, v)| (n.as_str(), v.as_str())));
        let job = HttpJob { wire, head: req.method == http::Method::Head, timeout: Duration::from_millis(u64::from(req.timeout_ms())), with_login: req.with_login, session };
        let relay = self.relay.as_mut().ok_or_else(|| (Failure::Denied("this view is not opened on an entry".into()), Some("grant")))?;
        let opened = relay.http(request, req.port, job).map_err(|f| {
            let s = if matches!(&f, Failure::Denied(t) if t.contains("port")) { Some("port") } else { None };
            (f, s)
        })?;
        if opened {
            let route = entry.tls.route.audit_name();
            let mode = format!("{:?}", entry.tls.mode).to_ascii_lowercase();
            audit_now(&self.data_dir, &plugin_audit::http_connect(self.grants.plugin_id(), self.grants.plugin_version(), &entry.entry_id, port, route, &mode));
        }
        let seen = self.open.spec.as_ref().filter(|s| !s.address_fields.is_empty() && req.method == http::Method::Get).map(|_| (req.target.clone(), req.headers.clone()));
        self.http_pending.insert(request, HttpPending { method: req.method, path: req.path().to_string(), with_login: req.with_login, seen });
        Ok(())
    }

    /// An `http.send` finished: the echo check (review of #1332, MEDIUM 2) and the change
    /// audit. Other replies pass through.
    fn http_finished(&mut self, request: u32, outcome: Result<Value, Failure>) -> Result<Value, Failure> {
        let Some(p) = self.http_pending.remove(&request) else { return outcome };
        let outcome = match outcome {
            Ok(v) if p.with_login => {
                let echoed = match (&v, &self.login) {
                    (Value::Variant(_, Some(inner)), Some(login)) => {
                        let status = as_u16(field(inner, "status")).unwrap_or(0);
                        let headers = match field(inner, "headers") {
                            Some(Value::List(h)) => h.iter().filter_map(|t| match t {
                                Value::Tuple(p) => match (p.first(), p.get(1)) {
                                    (Some(Value::String(n)), Some(Value::String(v))) => Some((n.clone(), v.clone())),
                                    _ => None,
                                },
                                _ => None,
                            }).collect(),
                            _ => Vec::new(),
                        };
                        let body = match field(inner, "body") {
                            Some(Value::Bytes(b)) => b.clone(),
                            _ => Vec::new(),
                        };
                        let resp = http::HttpResponse { status, headers, body, keep_alive: false };
                        http::check_echo(&resp, &login.check).is_err() || login.session.as_ref().is_some_and(|s| resp.headers.iter().any(|(n, v)| s.matches(n.as_bytes()) || s.matches(v.as_bytes())) || s.matches(&resp.body))
                    }
                    _ => false,
                };
                if echoed {
                    self.audit_http_denied("echo");
                    Err(Failure::Denied("the server's answer repeated the login, so Gantry withheld it".into()))
                } else {
                    Ok(v)
                }
            }
            other => other,
        };
        if let (Some(spec), Some((target, req_headers)), Ok(Value::Variant(_, Some(inner)))) = (self.open.spec.as_ref(), p.seen.as_ref(), &outcome) {
            let status = as_u16(field(inner, "status")).unwrap_or(0);
            let headers: Vec<(String, String)> = match field(inner, "headers") {
                Some(Value::List(h)) => h
                    .iter()
                    .filter_map(|t| match t {
                        Value::Tuple(pair) => match (pair.first(), pair.get(1)) {
                            (Some(Value::String(n)), Some(Value::String(v))) => Some((n.clone(), v.clone())),
                            _ => None,
                        },
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let body: &[u8] = match field(inner, "body") {
                Some(Value::Bytes(b)) => b,
                _ => &[],
            };
            let seen = crate::plugin::broker::open::SeenRequest { is_get: p.method == http::Method::Get, path: &p.path, target, headers: req_headers };
            let resp = crate::plugin::broker::open::SeenResponse { status, headers: &headers, body };
            self.open.reported.collect(spec, &seen, &resp, Instant::now());
        }
        if p.method.changes() {
            let status = match &outcome {
                Ok(Value::Variant(_, Some(inner))) => as_u16(field(inner, "status")),
                _ => None,
            };
            if let Some(entry_id) = self.grants.entry_id() {
                let a = plugin_audit::http_change(self.grants.plugin_id(), self.grants.plugin_version(), entry_id, p.method.as_str(), &p.path, status, p.with_login);
                audit_now(&self.data_dir, &a);
            }
        }
        outcome
    }

    fn audit_http_denied(&mut self, step: &str) {
        let now = Instant::now();
        if self.http_denied_at.is_some_and(|t| now.duration_since(t) < HTTP_DENIED_AUDIT_EVERY) {
            return;
        }
        self.http_denied_at = Some(now);
        let a = plugin_audit::http_denied(self.grants.plugin_id(), self.grants.plugin_version(), self.grants.entry_id(), step);
        audit_now(&self.data_dir, &a);
    }

    /// `net.*` with a reply: checked here, answered later by [`Self::take_stream_replies`],
    /// or now (`register-abort`, and every refusal).
    fn net(&mut self, request: u32, func: &str, args: &[Value]) -> Result<(), Failure> {
        self.grants.check(Call::Connect)?;
        let relay = self.relay.as_mut().ok_or_else(|| Failure::Denied("this view is not opened on an entry".into()))?;
        let stream = || as_u32(args.first()).ok_or_else(|| Failure::Invalid("a stream is a number".into()));
        let bytes = |i: usize| match args.get(i) {
            Some(Value::Bytes(b)) => Ok(b.clone()),
            _ => Err(Failure::Invalid("data is bytes".into())),
        };
        match func {
            "connect" => {
                let port = match args.first() {
                    Some(Value::Option(None)) | None => None,
                    Some(Value::Option(Some(p))) => match **p {
                        Value::U16(p) => Some(p),
                        _ => return Err(Failure::Invalid("a port is a number".into())),
                    },
                    _ => return Err(Failure::Invalid("a port is a number".into())),
                };
                relay.connect(request, port)
            }
            "read" => relay.read(request, stream()?, as_u32(args.get(1)).ok_or_else(|| Failure::Invalid("a size is a number".into()))?),
            "write" => relay.write(request, stream()?, bytes(1)?, &self.released),
            "start-tls" => relay.start_tls(request, stream()?),
            "register-abort" => {
                relay.register_abort(stream()?, &bytes(1)?, &self.released)?;
                self.reply_later(request, Ok(Value::Variant("none".into(), None)));
                Ok(())
            }
            _ => Err(Failure::Invalid("unknown stream call".into())),
        }
    }

    fn storage(&mut self, func: &str, args: &[Value]) -> Result<Value, Failure> {
        let call = if matches!(func, "set" | "delete") { Call::StorageWrite } else { Call::StorageRead };
        self.grants.check(call)?;
        let storage = self.storage.as_mut().ok_or_else(|| Failure::Denied("this view is not opened on an entry".into()))?;
        let key = as_str(args.first()).unwrap_or_default();
        match func {
            "get" => Ok(variant("value", Value::Option(storage.get(key)?.map(|v| Box::new(Value::Bytes(v)))))),
            "set" => {
                let value = match args.get(1) {
                    Some(Value::Bytes(value)) => value,
                    // The helper sends only the length of a value over the cap (`MAX_STORAGE_VALUE_BYTES`).
                    Some(Value::U64(len)) => return Err(Failure::Invalid(format!("a storage value is at most {MAX_STORAGE_VALUE_BYTES} bytes; this one is {len}"))),
                    _ => return Err(Failure::Invalid("a value is bytes".into())),
                };
                storage.set(key, value, &self.released)?;
                Ok(Value::Variant("none".into(), None))
            }
            "delete" => {
                storage.delete(key)?;
                Ok(Value::Variant("none".into(), None))
            }
            "keys" => Ok(variant("keys", Value::List(storage.keys(key)?.into_iter().map(Value::String).collect()))),
            _ => Err(Failure::Invalid("unknown storage call".into())),
        }
    }

    /// Holds an update back past 30 a second (spec section 5): it is delayed, never lost.
    fn pace(&mut self) {
        let gap = Duration::from_millis(1_000 / MAX_UPDATES_PER_SECOND as u64);
        while !self.rate.admit(self.started.elapsed().as_millis() as u64) {
            std::thread::sleep(gap);
        }
    }

    fn push(&self, kind: &str, mut body: Json) {
        body["type"] = json!(kind);
        self.shared.push(body);
    }

    fn ui(&mut self, seq: u64, func: &str, args: &[Value]) -> Result<(), Stopped> {
        match func {
            "set-view" | "patch-view" | "open-dialog" => {
                let view = as_u32(args.first());
                let nodes = if func == "open-dialog" { args.get(2) } else { args.get(1) };
                let Some(nodes) = nodes else { return Err(self.violation("a view call without nodes")) };
                if self.sidebar {
                    if let Err(f) = sidebar_nodes(func, view, nodes) {
                        return self.answer(seq, vec![err_value(&f)]);
                    }
                }
                let checked = if func == "patch-view" {
                    let current = view.and_then(|v| self.trees.get(&v)).map(Vec::as_slice).unwrap_or(&[]);
                    checked_patch(current, nodes, args.get(2)).map(|(json, tree)| {
                        if let Some(v) = view {
                            self.trees.insert(v, tree);
                        }
                        json
                    })
                } else {
                    let r = node_refs(nodes).and_then(|(refs, json, size)| check_view(&refs, size).map(|_| (refs, json)));
                    r.map(|(refs, json)| {
                        if let (Some(v), "set-view") = (view, func) {
                            self.trees.insert(v, refs);
                        }
                        json
                    })
                };
                let checked = match checked {
                    Ok(j) => j,
                    // Over a limit: refused with `invalid`; the helper keeps running.
                    Err(f) => return self.answer(seq, vec![err_value(&f)]),
                };
                self.pace();
                match func {
                    "set-view" => self.push("set-view", json!({ "view": view, "nodes": checked })),
                    "patch-view" => self.push("patch-view", json!({ "view": view, "upsert": checked, "remove": args.get(2).map(to_json) })),
                    _ => {
                        let dialog = self.new_request();
                        self.push("dialog", json!({ "over": view, "dialog": dialog, "title": as_str(args.get(1)), "nodes": checked }));
                        return self.answer(seq, vec![Value::Result(Ok(Some(Box::new(Value::U32(dialog)))))]);
                    }
                }
                self.answer(seq, vec![ok_unit()])
            }
            "close-dialog" => {
                self.push("close-dialog", json!({ "dialog": as_u32(args.first()) }));
                self.answer(seq, vec![])
            }
            "mark-errors" | "provide-rows" | "provide-children" | "provide-completions" => {
                let mut body = Json::Array(args.iter().map(to_json).collect());
                if func == "provide-completions" {
                    // Checked and capped before the app sees them (PLUG-06c).
                    let items = crate::plugin::highlight::complete::clean_completions(&body[1]);
                    body[1] = crate::plugin::highlight::complete::completions_json(&items);
                }
                let size = serde_json::to_vec(&body).map(|b| b.len()).unwrap_or(usize::MAX);
                if size > MAX_ANSWER_BYTES {
                    return self.answer(seq, vec![err_value(&crate::plugin::broker::caps::result_too_large())]);
                }
                self.push(func, json!({ "args": body }));
                self.answer(seq, vec![ok_unit()])
            }
            "refuse" => {
                self.push("refuse", json!({ "ask": as_u32(args.first()), "message": as_str(args.get(1)) }));
                self.answer(seq, vec![])
            }
            // The sidebar tree has no prompts: expanding an entry must never put one up (API 1.3).
            "confirm" if self.sidebar => {
                let request = self.new_request();
                self.reply_later(request, Err(Failure::Denied("no confirmations from the library sidebar".into())));
                self.answer(seq, vec![Value::U32(request)])
            }
            "confirm" => {
                let Some(Value::Enum(k)) = args.first() else { return Err(self.violation("confirm without a kind")) };
                let kind = match k.as_str() {
                    "drop" => ConfirmKind::Drop,
                    "truncate" => ConfirmKind::Truncate,
                    "end-session" => ConfirmKind::EndSession,
                    "run-statements" => ConfirmKind::RunStatements,
                    _ => ConfirmKind::Other,
                };
                if confirms_full(self.confirms.len()) {
                    return Err(self.violation("too many open confirmations"));
                }
                let kind_name = k.clone();
                let text = as_str(args.get(1)).unwrap_or_default().to_string();
                let request = self.new_request();
                let mut shown = text.len().min(MAX_PROMPT_TEXT_BYTES);
                while !text.is_char_boundary(shown) {
                    shown -= 1;
                }
                let entry = self.entry.as_ref().map(|e| json!({ "name": e.name, "environment": e.environment }));
                let body = json!({ "request": request, "kind": kind_name, "text": &text[..shown], "cut": shown < text.len(), "entry": entry, "plugin": self.grants.plugin_id() });
                self.push("confirm", body);
                let (text_sha256, text_cut) = plugin_audit::confirm_text_digest(&text);
                self.confirms.push(PendingConfirm { request, kind, text_sha256, text_cut });
                self.answer(seq, vec![Value::U32(request)])
            }
            _ => Err(self.violation("an unknown ui call")),
        }
    }

    /// The user answered a confirmation: audit it, then reply to the plugin. An answer to a
    /// request the core never asked, or asked once already, is ignored.
    fn confirm_answer(&mut self, request: u32, confirmed: bool) {
        let Some(at) = self.confirms.iter().position(|c| c.request == request) else { return };
        let pending = self.confirms.remove(at);
        let entry_id = self.grants.entry_id().unwrap_or("").to_string();
        let environment = self.entry.as_ref().map(|e| e.environment.clone()).unwrap_or_default();
        let a = plugin_audit::confirm_from_digest(self.grants.plugin_id(), self.grants.plugin_version(), &entry_id, &environment, pending.kind, confirmed, &pending.text_sha256, pending.text_cut);
        audit_now(&self.data_dir, &a);
        self.reply_later(request, Ok(variant("confirmed", Value::Bool(confirmed))));
    }
}

#[path = "view_open.rs"]
mod view_open;
#[path = "view_exec.rs"]
mod view_exec;
pub use view_exec::ExecAnswer;

#[path = "view_files.rs"]
mod view_files;

#[path = "view_library.rs"]
mod view_library;

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_with(login: Option<&str>, entry: bool) -> ViewSpec {
        ViewSpec {
            data_dir: PathBuf::from("/nonexistent"),
            plugin_id: "dev.bastion.proxmox".into(),
            view_name: "pve".into(),
            entry: entry.then(|| EntryBinding {
                document_id: "d".into(),
                entry_id: "e".into(),
                name: "pve".into(),
                host: "pve.lab".into(),
                port: 8006,
                fields: vec![],
                protected: false,
                environment: String::new(),
                tls: EntryTls::default(),
                connection_type: String::new(),
            }),
            policy: Policy::default(),
            allow_unverified: false,
            safe_mode: false,
            login: login.map(|s| EntryLogin { user: "audit@pve!b".into(), secret: zeroize::Zeroizing::new(s.as_bytes().to_vec()) }),
        }
    }

    #[test]
    fn a_plugin_cannot_call_session_methods_at_or_below_the_login_path() {
        let spec = HttpSpec {
            paths: vec!["/sdk/".into()],
            ports: vec![],
            methods: vec![http::Method::Post],
            auth: None,
            session: Some(http_session::HttpSession { login_path: "/sdk".into(), login_body: "<a>{secret}</a>".into(), content_type: "text/xml".into(), cookie: "c".into(), logout_body: None, ticket: None }),
        };
        let post = |target: &str, body: &str| PluginRequest { method: http::Method::Post, port: None, target: target.into(), headers: vec![], body: body.as_bytes().to_vec(), with_login: true, timeout_ms: None };
        for target in ["/sdk", "/sdk/", "/sdk/vimService", "/sdk/vimService?x=1"] {
            for m in ["Login", "AcquireCloneTicket", "Logout", "TerminateSession"] {
                assert!(refuse_session_call(&spec, &post(target, &format!("<Envelope><Body><{m}/></Body></Envelope>"))).is_err(), "{target} {m}");
            }
            assert!(refuse_session_call(&spec, &post(target, "<Envelope><Body><RetrievePropertiesEx/></Body></Envelope>")).is_ok(), "{target}: inventory calls pass");
        }
        assert!(refuse_session_call(&HttpSpec { session: None, ..spec.clone() }, &post("/sdk/vimService", "<Login/>")).is_ok(), "no session: the rule does not apply");
    }

    #[test]
    fn entry_info_names_the_connection_type_and_a_plugin_cannot_spoof_it() {
        let mut e = spec_with(Some("s3cret"), true).entry.unwrap();
        // A saved `:type` (or any `:` key) is dropped; a plugin field named `type` is the plugin's own.
        e.fields = vec![("allow-changes".into(), "true".into()), (":type".into(), "vcenter".into()), ("type".into(), "vcenter".into()), (":x".into(), "y".into())];
        e.connection_type = "esxi".into();
        assert_eq!(entry_fields(&e), vec![("allow-changes".to_string(), "true".to_string()), ("type".to_string(), "vcenter".to_string()), (":type".to_string(), "esxi".to_string())]);
        e.connection_type.clear();
        assert_eq!(entry_fields(&e), vec![("allow-changes".to_string(), "true".to_string()), ("type".to_string(), "vcenter".to_string())], "no type known: no :type");
    }

    #[test]
    fn the_login_is_kept_only_with_an_entry_and_an_auth_header() {
        let auth = HttpSpec {
            paths: vec!["/api2/json/".into()],
            ports: vec![],
            methods: vec![http::Method::Get],
            auth: Some(http::HttpAuth { header: "Authorization".into(), format: http::AuthFormat::Template("PVEAPIToken={user}={secret}".into()) }),
            session: None,
        };
        let no_auth = HttpSpec { auth: None, ..auth.clone() };
        let kept = http_login(&spec_with(Some("s3cret"), true), Some(&auth), Some(LoginMethod::Auth)).expect("kept");
        assert_eq!((kept.user.as_str(), kept.secret.as_slice()), ("audit@pve!b", &b"s3cret"[..]));
        assert!(kept.check.refuse(b"x s3cret y").is_err(), "the secret is in the request and echo check");
        assert!(http_login(&spec_with(Some("s3cret"), true), Some(&no_auth), Some(LoginMethod::Auth)).is_none(), "no [http] auth");
        assert!(http_login(&spec_with(Some("s3cret"), true), None, Some(LoginMethod::Auth)).is_none(), "no [http]");
        assert!(http_login(&spec_with(Some("s3cret"), false), Some(&auth), Some(LoginMethod::Auth)).is_none(), "no entry");
        assert!(http_login(&spec_with(Some(""), true), Some(&auth), Some(LoginMethod::Auth)).is_none(), "empty secret");
        assert!(http_login(&spec_with(None, true), Some(&auth), Some(LoginMethod::Auth)).is_none());
        // Design D: the type's one method. No method, no login; a session type never gets the
        // header, and a session needs `[http.session]`.
        assert!(http_login(&spec_with(Some("s3cret"), true), Some(&auth), None).is_none(), "no method");
        assert!(http_login(&spec_with(Some("s3cret"), true), Some(&auth), Some(LoginMethod::Session)).is_none(), "session without [http.session]");
        let both = HttpSpec {
            session: Some(http_session::HttpSession { login_path: "/sdk".into(), login_body: "<a>{secret}</a>".into(), content_type: "text/xml".into(), cookie: "c".into(), logout_body: None, ticket: None }),
            ..auth.clone()
        };
        let s = http_login(&spec_with(Some("s3cret"), true), Some(&both), Some(LoginMethod::Session)).expect("session kept");
        assert!(s.method == LoginMethod::Session && s.session.is_some());
        let a = http_login(&spec_with(Some("s3cret"), true), Some(&both), Some(LoginMethod::Auth)).expect("auth kept");
        assert!(a.method == LoginMethod::Auth && a.session.is_none(), "an auth type never gets a session");
        assert!(!format!("{:?}", spec_with(Some("s3cret"), true)).contains("s3cret"), "Debug withholds the secret");
    }

    fn grants_with(credentials: bool) -> HelperGrants {
        let mut p = crate::plugin::Permissions::default();
        p.network_entry = true;
        p.credentials_entry = credentials;
        HelperGrants::new("com.example.pg", "1.0.0", p, Binding::Entry { entry_id: "e".into(), temporary: false })
    }

    fn login(secret: &str) -> Option<EntryLogin> {
        Some(EntryLogin { user: "pgtest".into(), secret: zeroize::Zeroizing::new(secret.as_bytes().to_vec()) })
    }

    #[test]
    fn entry_login_is_kept_only_with_an_entry_and_the_permission() {
        assert!(entry_login(&spec_with(Some("s3cret"), true), true).is_some());
        assert!(entry_login(&spec_with(Some("s3cret"), true), false).is_none(), "no credentials permission");
        assert!(entry_login(&spec_with(Some("s3cret"), false), true).is_none(), "no entry");
        assert!(entry_login(&spec_with(Some(""), true), true).is_none(), "empty secret");
        assert!(entry_login(&spec_with(None, true), true).is_none());
    }

    #[test]
    fn entry_login_is_released_once_after_the_gate_and_joins_the_secret_check() {
        let mut grants = grants_with(true);
        let mut held = login("s3cret-pw");
        let mut released = SecretCheck::new();
        // The TLS gate holds it back and keeps the login for a later try.
        let gate = Err(Failure::Denied("the login waits until TLS is up".into()));
        assert!(release_entry_login(&mut grants, gate, &mut held, &mut released).is_err());
        assert!(held.is_some() && released.refuse(b"s3cret-pw").is_ok());
        let v = release_entry_login(&mut grants, Ok(()), &mut held, &mut released).expect("released");
        let Value::Variant(name, Some(inner)) = v else { panic!("not a variant") };
        assert_eq!(name, "login");
        assert_eq!(field(&inner, "user"), Some(&Value::String("pgtest".into())));
        assert_eq!(field(&inner, "secret"), Some(&Value::String("s3cret-pw".into())));
        assert!(held.is_none(), "taken");
        assert!(released.refuse(b"x s3cret-pw y").is_err(), "in the released-secret check");
        let again = release_entry_login(&mut grants, Ok(()), &mut login("s3cret-pw"), &mut released);
        assert!(matches!(again, Err(Failure::Denied(t)) if t.contains("already released")));
    }

    #[test]
    fn entry_login_is_refused_without_the_grant_or_a_login() {
        let mut released = SecretCheck::new();
        assert!(release_entry_login(&mut grants_with(false), Ok(()), &mut login("pw"), &mut released).is_err(), "no permission");
        let none = release_entry_login(&mut grants_with(true), Ok(()), &mut None, &mut released);
        assert!(matches!(none, Err(Failure::Denied(t)) if t.contains("no saved login")));
        let e = release_entry_login(&mut grants_with(true), Err(Failure::Denied("gate".into())), &mut login("pw-xyz"), &mut released).unwrap_err();
        assert!(!format!("{e:?}").contains("pw-xyz"), "a refusal never names the secret");
    }

    #[test]
    fn an_http_request_from_the_plugin_is_read_strictly() {
        let req = record(vec![
            ("method", Value::Enum("post".into())),
            ("port", Value::Option(Some(Box::new(Value::U16(8006))))),
            ("target", Value::String("/api2/json/x".into())),
            ("headers", Value::List(vec![Value::Tuple(vec![Value::String("Accept".into()), Value::String("application/json".into())])])),
            ("body", Value::Bytes(b"a=1".to_vec())),
            ("with-login", Value::Bool(true)),
            ("timeout-ms", Value::Option(Some(Box::new(Value::U32(5000))))),
        ]);
        let r = http_request_of(&[req]).unwrap();
        assert_eq!((r.method, r.port, r.target.as_str(), r.body.as_slice(), r.with_login, r.timeout_ms), (http::Method::Post, Some(8006), "/api2/json/x", &b"a=1"[..], true, Some(5000)));
        assert_eq!(r.headers, vec![("Accept".to_string(), "application/json".to_string())]);
        let bad_method = record(vec![("method", Value::Enum("trace".into())), ("target", Value::String("/".into())), ("headers", Value::List(vec![])), ("body", Value::Bytes(vec![]))]);
        assert!(http_request_of(&[bad_method]).is_err());
        let bad_header = record(vec![("method", Value::Enum("get".into())), ("target", Value::String("/".into())), ("headers", Value::List(vec![Value::String("x".into())])), ("body", Value::Bytes(vec![]))]);
        assert!(http_request_of(&[bad_header]).is_err());
        assert!(http_request_of(&[]).is_err());
    }

    #[test]
    fn an_http_answer_becomes_the_reply_value() {
        let v = http_response_value(http::HttpResponse { status: 204, headers: vec![("A".into(), "b".into())], body: vec![1, 2], keep_alive: true });
        let Value::Variant(name, Some(inner)) = &v else { panic!("{v:?}") };
        assert_eq!(name, "http");
        assert_eq!(as_u16(field(inner, "status")), Some(204));
        assert!(matches!(field(inner, "body"), Some(Value::Bytes(b)) if b == &vec![1, 2]));
        assert!(field(inner, "keep-alive").is_none(), "connection state stays in the core");
    }

    #[test]
    fn queued_replies_are_capped() {
        assert!(!replies_full(MAX_QUEUED_REPLIES - 1));
        assert!(replies_full(MAX_QUEUED_REPLIES));
    }

    #[test]
    fn open_confirmations_are_capped() {
        for open in 0..MAX_OPEN_CONFIRMS {
            assert!(!confirms_full(open));
        }
        assert!(confirms_full(MAX_OPEN_CONFIRMS));
        assert!(confirms_full(MAX_OPEN_CONFIRMS + 100));
    }

    #[test]
    fn pending_confirm_audit_matches_full_text_audit() {
        let text = "DROP TABLE x; ".repeat(10_000);
        let (digest, cut) = plugin_audit::confirm_text_digest(&text);
        assert!(cut);
        let full = plugin_audit::confirm("p", "1", "e", "Production", ConfirmKind::Drop, true, &text);
        let kept = plugin_audit::confirm_from_digest("p", "1", "e", "Production", ConfirmKind::Drop, true, &digest, cut);
        assert_eq!(full.details, kept.details);
        assert!(std::mem::size_of::<PendingConfirm>() < 64);
    }

    fn node(id: u32, parent: Option<u32>) -> Value {
        record(vec![("id", Value::U32(id)), ("parent", Value::Option(parent.map(|p| Box::new(Value::U32(p))))), ("component", Value::Variant("tabs".into(), None))])
    }

    #[test]
    fn the_sidebar_view_is_one_root_tree() {
        let tree = |id: u32, parent: Option<u32>| record(vec![("id", Value::U32(id)), ("parent", Value::Option(parent.map(|p| Box::new(Value::U32(p))))), ("component", Value::Variant("tree".into(), Some(Box::new(record(vec![("columns", Value::List(vec![]))])))))]);
        assert!(sidebar_nodes("set-view", Some(1), &Value::List(vec![tree(1, None)])).is_ok());
        for (func, nodes, why) in [
            ("patch-view", Value::List(vec![tree(1, None)]), "no patches"),
            ("open-dialog", Value::List(vec![tree(1, None)]), "no dialogs"),
            ("set-view", Value::List(vec![]), "empty"),
            ("set-view", Value::List(vec![tree(1, None), tree(2, Some(1))]), "two nodes"),
            ("set-view", Value::List(vec![node(1, None)]), "not a tree"),
            ("set-view", Value::List(vec![tree(1, Some(0))]), "not a root"),
        ] {
            assert!(matches!(sidebar_nodes(func, Some(1), &nodes), Err(Failure::Invalid(_))), "{why}");
        }
        assert!(sidebar_nodes("set-view", Some(2), &Value::List(vec![tree(1, None)])).is_err(), "only the first view");
        let ui = |kind: &str| variant("ui", record(vec![("view", Value::U32(1)), ("node", Value::U32(1)), ("input", Value::Variant(kind.into(), None))]));
        assert!(is_menu_input(&ui("menu")) && !is_menu_input(&ui("selected")) && !is_menu_input(&ui("pressed")));
        assert_eq!((api_minor("@1.0.0"), api_minor("@1.2.0"), api_minor("@1.3.0"), api_minor("@1.6.0")), (0, 2, 3, 6));
    }

    #[test]
    fn api_16_tiles_and_cells_reach_the_app_as_json() {
        // API 1.6: the `stat` component and the `status` and `meter` cells pass through the
        // generic conversion; the apps read them by kind.
        let stat = variant("stat", record(vec![
            ("title", Value::String("CPU".into())),
            ("value", Value::String("12%".into())),
            ("detail", Value::String("8 cores".into())),
            ("fraction", Value::Option(Some(Box::new(Value::F32(0.5))))),
        ]));
        assert_eq!(to_json(&stat), json!({"kind": "stat", "value": {"title": "CPU", "value": "12%", "detail": "8 cores", "fraction": 0.5}}));
        let status = variant("status", record(vec![("tone", Value::Enum("off".into())), ("text", Value::String("db".into()))]));
        assert_eq!(to_json(&status), json!({"kind": "status", "value": {"tone": "off", "text": "db"}}));
        let meter = variant("meter", record(vec![("fraction", Value::F32(0.25)), ("text", Value::String("1 / 4 GiB".into()))]));
        assert_eq!(to_json(&meter), json!({"kind": "meter", "value": {"fraction": 0.25, "text": "1 / 4 GiB"}}));
        let n = record(vec![("id", Value::U32(1)), ("parent", Value::Option(None)), ("component", stat)]);
        assert!(checked_nodes(&Value::List(vec![n])).is_ok(), "a stat node is an ordinary leaf");
        assert!(VERSIONS.contains(&"@1.6.0"));
    }

    #[test]
    fn a_patch_may_resend_a_child_without_its_parent() {
        let current = [NodeRef { id: 0, parent: None }, NodeRef { id: 1, parent: Some(0) }, NodeRef { id: 2, parent: Some(0) }];
        let (_, tree) = checked_patch(&current, &Value::List(vec![node(2, Some(0))]), None).expect("parent 0 is in the view");
        assert_eq!(tree.len(), 3);
        let (_, tree) = checked_patch(&tree, &Value::List(vec![node(3, Some(1))]), None).expect("a new child of a kept node");
        assert_eq!(tree.len(), 4);
        assert!(matches!(checked_patch(&tree, &Value::List(vec![node(4, Some(9))]), None), Err(Failure::Invalid(_))), "an unknown parent");
        assert!(matches!(checked_patch(&tree, &Value::List(vec![node(0, Some(3))]), None), Err(Failure::Invalid(_))), "a cycle through the view");
        assert!(matches!(checked_patch(&tree, &Value::List(vec![node(5, Some(0)), node(5, Some(0))]), None), Err(Failure::Invalid(_))), "an id twice");
        let (_, tree) = checked_patch(&tree, &Value::List(vec![]), Some(&Value::List(vec![Value::U32(1)]))).expect("remove");
        assert_eq!(tree.iter().map(|n| n.id).collect::<Vec<_>>(), vec![0, 2], "node 3 went with its parent 1");
        assert!(matches!(checked_patch(&tree, &Value::List(vec![node(6, Some(1))]), None), Err(Failure::Invalid(_))), "a removed parent");
        assert!(matches!(checked_patch(&[], &Value::List(vec![node(1, Some(0))]), None), Err(Failure::Invalid(_))), "no view yet");
    }

    #[test]
    fn a_view_list_is_checked_before_the_app_sees_it() {
        assert!(checked_nodes(&Value::List(vec![node(1, None), node(2, Some(1))])).is_ok());
        assert!(matches!(checked_nodes(&Value::List(vec![node(1, Some(2)), node(2, Some(1))])), Err(Failure::Invalid(_))), "a cycle");
        assert!(matches!(checked_nodes(&Value::List(vec![node(1, None), node(1, None)])), Err(Failure::Invalid(_))), "a duplicate id");
        assert!(matches!(checked_nodes(&Value::String("x".into())), Err(Failure::Invalid(_))));
        let many: Vec<Value> = std::iter::once(node(0, None)).chain((1..=2_000).map(|i| node(i, Some(0)))).collect();
        assert!(matches!(checked_nodes(&Value::List(many)), Err(Failure::Invalid(_))), "2,001 nodes");
    }

    #[test]
    fn app_events_become_plugin_events_and_nothing_else() {
        let AppEvent::UserAction(v, _) = event_from_json(&json!({"type":"ui","view":1,"node":7,"input":{"kind":"pressed"}})).unwrap() else { panic!("a stamped user action") };
        assert_eq!(to_json(&v)["kind"], "ui");
        assert!(matches!(event_from_json(&json!({"type":"command","id":"c"})).unwrap(), AppEvent::UserAction(..)), "a command is a user action");
        assert!(matches!(event_from_json(&json!({"type":"open-view","view":2,"name":"x"})).unwrap(), AppEvent::Plugin(_)), "opening a view is not");
        assert!(matches!(event_from_json(&json!({"type":"rows","ask":1,"view":1,"node":2,"offset":0,"count":1})).unwrap(), AppEvent::Plugin(_)), "a rows ask is not");
        assert!(event_from_json(&json!({"type":"rows","ask":1,"view":1,"node":2,"offset":0,"count":1001})).is_err(), "1,000 rows at most");
        assert!(event_from_json(&json!({"type":"rows","ask":1,"view":1,"node":2,"offset":0,"count":1000})).is_ok());
        assert!(event_from_json(&json!({"type":"stop"})).is_err(), "the app cannot send stop: close does");
        assert!(event_from_json(&json!({"type":"reply"})).is_err(), "replies come only from the core");
        assert!(matches!(event_from_json(&json!({"type":"confirm","request":3,"confirmed":true})).unwrap(), AppEvent::ConfirmAnswer { request: 3, confirmed: true }));
        use crate::plugin::broker::open::RouteChoice;
        assert!(matches!(
            event_from_json(&json!({"type":"open","request":4,"accept":true,"route":"direct","credential_chosen":true})).unwrap(),
            AppEvent::OpenAnswer { request: 4, accept: true, route: RouteChoice::Direct, credential_chosen: true, save_as_entry: false }
        ));
        assert!(event_from_json(&json!({"type":"open","request":4,"accept":true,"route":"gateway-2"})).is_err(), "only entry or direct");
        assert!(event_from_json(&json!({"type":"open","request":4})).is_err(), "accept is required");
    }

    #[test]
    fn the_cache_key_follows_the_component_and_the_engine() {
        let a = cache_key(b"one", "wasmtime-48.0.8-x");
        assert_eq!(a, cache_key(b"one", "wasmtime-48.0.8-x"));
        assert_ne!(a, cache_key(b"two", "wasmtime-48.0.8-x"));
        assert_ne!(a, cache_key(b"one", "wasmtime-48.0.8-y"));
    }
}
