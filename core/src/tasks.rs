//! Saved tasks (Royal TS "Tasks"): built-in network checks and custom commands run against a
//! connection. Every task becomes an argument vector; substituted values never pass through a
//! local shell. Over SSH the vector is POSIX-quoted into one remote command line.
use std::collections::BTreeMap;
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::Connection;
use crate::policy::{Action, Policy};
use crate::vars::Variables;

pub const DEFAULT_TIMEOUT_SECS: u32 = 60;
pub const MAX_TIMEOUT_SECS: u32 = 3600;
pub const MAX_ARGS: usize = 64;
pub const MAX_ARG_LEN: usize = 4096;
/// Output kept per stream; the rest is dropped and marked.
pub const MAX_OUTPUT: usize = 1 << 20;
const POLL: Duration = Duration::from_millis(50);
/// How often the output readers are checked for end-of-file.
const READER_POLL: Duration = Duration::from_millis(2);
/// After a kill, how long to wait for the output readers before returning what was read.
const READER_GRACE: Duration = Duration::from_millis(500);
/// Windows: how long `taskkill` may take before the program alone is killed.
#[cfg(windows)]
const TREE_KILL_LIMIT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Builtin {
    Ping,
    TraceRoute,
    DnsLookup,
    TcpCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunOn {
    #[default]
    Local,
    Ssh,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TaskKind {
    Builtin { builtin: Builtin },
    /// `program` and each of `args` may hold `$Host$`, `$Port$`, `$Username$`, `$Name$`, `$Meta.x$`.
    Custom { program: String, args: Vec<String>, #[serde(default)] run_on: RunOn },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskDef {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub favorite: bool,
    pub kind: TaskKind,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u32,
}

fn default_timeout() -> u32 {
    DEFAULT_TIMEOUT_SECS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookWhen {
    BeforeConnect,
    AfterConnect,
    /// B5: once per session end (closed tab, or a dropped link after reconnect gave up). Never on
    /// app quit unless the session was closed first.
    AfterDisconnect,
}

/// What a hook runs (B5). Old documents have no `target` and load as `Task`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookTarget {
    /// The saved task `task_id`, against the connection.
    #[default]
    Task,
    /// The snippet `snippet_id` from this computer's snippet store, sent to the open session.
    /// Only after connect: there is no session before connect or after disconnect.
    Snippet,
    /// The task `task_id` on every connection in the hook's folder (a multi-host run). Only on a
    /// folder hook, so a run across many hosts is always something the user set on that folder.
    MultiHost,
}

/// A task or snippet attached to a connection or a folder (B5).
///
/// Semantics shared by all four apps:
/// - `BeforeConnect`: each hook runs to the end, in `hooks_for` order; a failing, refused or
///   unconfirmed one cancels the connect and its output is shown.
/// - `AfterConnect`: hooks run in the background; only failures are shown.
/// - `AfterDisconnect`: runs once per session end, also when the link is lost for good after
///   reconnect gave up; never on app quit unless the session was closed first. Shows nothing
///   unless one fails.
/// - A hook has its task's own timeout, never asks for confirmation (a task that needs it is
///   refused), and each run, refusal included, writes an audit record.
/// - Trust (T01): a task that starts a local program runs as a hook only when this exact content
///   was saved by the user on this computer (`TrustStore`). A document from someone else cannot
///   make its hooks run by carrying them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskHook {
    /// The connection this hook is on; nil when it is on a folder.
    #[serde(default)]
    pub connection_id: Uuid,
    /// The folder this hook is on: it applies to every connection inside, subfolders included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<Uuid>,
    /// The task run (nil for a snippet hook).
    #[serde(default)]
    pub task_id: Uuid,
    pub when: HookWhen,
    #[serde(default, skip_serializing_if = "is_task_target")]
    pub target: HookTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet_id: Option<String>,
}

fn is_task_target(t: &HookTarget) -> bool {
    *t == HookTarget::Task
}

impl TaskHook {
    /// A task hook on a connection (the shape every document before B5 holds).
    pub fn on_connection(connection_id: Uuid, task_id: Uuid, when: HookWhen) -> TaskHook {
        TaskHook { connection_id, folder_id: None, task_id, when, target: HookTarget::Task, snippet_id: None }
    }

    /// The node (connection or folder) this hook sits on.
    pub fn owner(&self) -> Uuid {
        self.folder_id.unwrap_or(self.connection_id)
    }
}

/// Refuse hooks that cannot work: a snippet outside after-connect, a multi-host run not on a
/// folder, a missing target.
pub fn validate_hook(h: &TaskHook) -> Result<()> {
    let bad = |m: &str| Err(CoreError::Invalid(format!("hook: {m}")));
    if h.folder_id.is_none() && h.connection_id.is_nil() {
        return bad("a connection or a folder is required");
    }
    match h.target {
        HookTarget::Snippet => {
            if h.when != HookWhen::AfterConnect {
                return bad("a snippet can run only after connect");
            }
            match &h.snippet_id {
                Some(s) if !s.trim().is_empty() && s.len() <= 128 && !has_control(s) => {}
                _ => return bad("a snippet is required"),
            }
        }
        HookTarget::MultiHost if h.folder_id.is_none() => return bad("a multi-host run can be set only on a folder"),
        HookTarget::Task | HookTarget::MultiHost if h.task_id.is_nil() => return bad("a task is required"),
        _ => {}
    }
    Ok(())
}

/// One hook to run for a connection, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHook {
    pub hook: TaskHook,
    /// Whether the app may run it now. False for a task hook whose task is unknown, or starts a
    /// local program and is not trusted (`untrusted` is then true).
    pub runnable: bool,
    pub untrusted: bool,
}

/// Whether running `task` as a hook needs the trust check: anything that starts a program on
/// this computer. Built-ins run fixed system tools; SSH tasks run on the remote host.
pub fn needs_trust(task: &TaskDef) -> bool {
    matches!(task.kind, TaskKind::Custom { run_on: RunOn::Local, .. })
}

/// Local tasks the user saved in this app, by exact content (T01). Kept outside any document, so
/// a task arriving in an opened document cannot run as a hook until the user saves it in Tasks;
/// any edit changes the key and needs a new save.
pub struct TrustStore;

impl TrustStore {
    pub const FILE: &'static str = "trusted-local-tasks.json";

    pub fn key(task: &TaskDef) -> String {
        serde_json::to_string(task).unwrap_or_default()
    }

    pub fn load(dir: &std::path::Path) -> Vec<String> {
        std::fs::read(dir.join(Self::FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn is_trusted(keys: &[String], task: &TaskDef) -> bool {
        let key = Self::key(task);
        !key.is_empty() && keys.contains(&key)
    }

    /// Record `task` as saved by the user; an older content of the same task is dropped.
    pub fn trust(dir: &std::path::Path, task: &TaskDef) -> Result<()> {
        let mut list: Vec<String> = Self::load(dir).into_iter().filter(|k| serde_json::from_str::<TaskDef>(k).map_or(true, |t| t.id != task.id)).collect();
        list.push(Self::key(task));
        let json = serde_json::to_vec(&list).map_err(|e| CoreError::Invalid(e.to_string()))?;
        crate::store::write_atomic(&dir.join(Self::FILE), &json)
    }
}

/// The hooks for `connection_id` at `when`, outer folder first, then inner folders, then the
/// connection's own; each hook once. `trusted` is the `TrustStore` content.
pub fn hooks_for(doc: &crate::model::Document, connection_id: Uuid, when: HookWhen, trusted: &[String]) -> Vec<ResolvedHook> {
    let mut chain = vec![connection_id];
    let mut at = connection_id;
    while let Some(p) = doc.parent_of(at) {
        chain.push(p);
        at = p;
    }
    chain.reverse();
    let mut out: Vec<ResolvedHook> = Vec::new();
    for owner in chain {
        for h in doc.task_hooks.iter().filter(|h| h.when == when && h.owner() == owner) {
            if out.iter().any(|r| r.hook == *h) || validate_hook(h).is_err() {
                continue;
            }
            let (runnable, untrusted) = match h.target {
                HookTarget::Snippet => (true, false),
                HookTarget::Task | HookTarget::MultiHost => {
                    match find(doc, h.task_id) {
                        None => (false, false),
                        Some(t) if needs_trust(&t) && !TrustStore::is_trusted(trusted, &t) => (false, true),
                        Some(_) => (true, false),
                    }
                }
            };
            out.push(ResolvedHook { hook: h.clone(), runnable, untrusted });
        }
    }
    out
}

/// Fixed ids so favourites and hooks on built-ins survive restarts.
const BUILTINS: [(u128, &str, Builtin); 4] = [
    (0xb7a5_0000_0000_0000_0000_0000_0000_0001, "Ping", Builtin::Ping),
    (0xb7a5_0000_0000_0000_0000_0000_0000_0002, "Trace Route", Builtin::TraceRoute),
    (0xb7a5_0000_0000_0000_0000_0000_0000_0003, "DNS Lookup", Builtin::DnsLookup),
    (0xb7a5_0000_0000_0000_0000_0000_0000_0004, "TCP Port Check", Builtin::TcpCheck),
];

pub fn builtins() -> Vec<TaskDef> {
    BUILTINS
        .iter()
        .map(|&(id, name, builtin)| TaskDef { id: Uuid::from_u128(id), name: name.into(), favorite: false, kind: TaskKind::Builtin { builtin }, timeout_secs: DEFAULT_TIMEOUT_SECS })
        .collect()
}

/// A built-in edited in place is stored in `doc.tasks` under the built-in's fixed id (a custom
/// task, so it keeps the custom-command confirmation and trust rules). It replaces the default
/// until removed again (Restore Default); the default's hooks and favourite stay.
pub fn find(doc: &crate::model::Document, id: Uuid) -> Option<TaskDef> {
    doc.tasks.iter().find(|t| t.id == id).cloned().or_else(|| builtins().into_iter().find(|t| t.id == id))
}

/// The command a built-in runs, with `$Host$` for the host: what Edit… starts from.
/// None for the TCP port check, which runs no program.
pub fn builtin_command(b: Builtin) -> Option<(String, Vec<String>)> {
    (b != Builtin::TcpCheck).then(|| builtin_argv(b, "$Host$"))
}

pub fn is_builtin(id: Uuid) -> bool {
    BUILTINS.iter().any(|&(b, _, _)| Uuid::from_u128(b) == id)
}

fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

pub fn validate(task: &TaskDef) -> Result<()> {
    let bad = |m: &str| Err(CoreError::Invalid(format!("task `{}`: {m}", task.name)));
    if task.name.trim().is_empty() || task.name.len() > 128 || has_control(&task.name) {
        return bad("a name of up to 128 characters is required");
    }
    if task.timeout_secs == 0 || task.timeout_secs > MAX_TIMEOUT_SECS {
        return bad("timeout must be 1 to 3600 seconds");
    }
    if let TaskKind::Custom { program, args, .. } = &task.kind {
        if program.trim().is_empty() || program.len() > MAX_ARG_LEN || has_control(program) {
            return bad("a program is required");
        }
        if args.len() > MAX_ARGS || args.iter().any(|a| a.len() > MAX_ARG_LEN || has_control(a)) {
            return bad("too many or too long arguments, or control characters");
        }
    }
    Ok(())
}

/// A host name or address safe to hand to ping/traceroute/nslookup as one argument.
fn check_host(host: &str) -> Result<()> {
    if host.is_empty() || host.len() > 253 || host.starts_with('-') || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(CoreError::Invalid(format!("`{host}` is not a usable host name")));
    }
    Ok(())
}

/// Variables for a connection whose settings are already resolved. Secret names are registered
/// (empty), so `$Password$` fails with `SecretLeak` instead of being substituted.
pub fn variables(conn: &Connection) -> Variables {
    let mut v = Variables::default();
    v.set("Host", &conn.host);
    v.set("Name", &conn.name);
    v.set("Port", &conn.settings.port.or(conn.protocol.default_port()).map(|p| p.to_string()).unwrap_or_default());
    v.set("Username", conn.settings.username.as_deref().unwrap_or(""));
    for (k, val) in conn.user_metadata() {
        v.set(&format!("Meta.{k}"), &val);
    }
    for s in ["Password", "Passphrase", "PrivateKey", "Secret", "Token"] {
        v.set_secret(s, "");
    }
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// Run `program` with `args` on this computer (no shell).
    Local { program: String, args: Vec<String> },
    /// Run this already-quoted command line on the connection's SSH session.
    Remote { command: String },
    /// Open (and close) a TCP connection in-process.
    TcpConnect { host: String, port: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub invocation: Invocation,
    pub timeout: Duration,
    /// Custom task on a sensitive (production…) connection: ask before running.
    pub needs_confirmation: bool,
    /// What the output tab shows as the command (no secrets: they cannot be substituted).
    pub display: String,
}

/// Single-quote `s` for a POSIX shell (`'` becomes `'\''`).
pub fn posix_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:=@,+%".contains(c)) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn builtin_argv(b: Builtin, host: &str) -> (String, Vec<String>) {
    let h = host.to_string();
    if cfg!(windows) {
        let sys = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()) + r"\System32\";
        match b {
            Builtin::Ping => (sys + "PING.EXE", vec!["-n".into(), "4".into(), h]),
            Builtin::TraceRoute => (sys + "TRACERT.EXE", vec!["-d".into(), "-h".into(), "30".into(), h]),
            _ => (sys + "nslookup.exe", vec![h]),
        }
    } else {
        match b {
            Builtin::Ping => ("/sbin/ping".into(), vec!["-c".into(), "4".into(), h]),
            Builtin::TraceRoute => ("/usr/sbin/traceroute".into(), vec!["-m".into(), "30".into(), h]),
            _ => ("/usr/bin/nslookup".into(), vec![h]),
        }
    }
}

/// Prefix of a prompt variable: `$Ask:Target IP$` asks the user for "Target IP" when the task runs.
pub const ASK_PREFIX: &str = "Ask:";

/// The labels of a custom task's prompt variables (`$Ask:Label$`), first use first, each once
/// (case-insensitive, as variables are). Built-in tasks have none.
pub fn ask_labels(task: &TaskDef) -> Vec<String> {
    let TaskKind::Custom { program, args, .. } = &task.kind else { return Vec::new() };
    let mut labels: Vec<String> = Vec::new();
    for text in std::iter::once(program).chain(args) {
        let mut rest = text.as_str();
        while let Some(start) = rest.find('$') {
            let after = &rest[start + 1..];
            let Some(end) = after.find('$') else { break };
            let name = &after[..end];
            if let Some(label) = name.strip_prefix(ASK_PREFIX).map(str::trim).filter(|l| !l.is_empty()) {
                if !labels.iter().any(|l| l.eq_ignore_ascii_case(label)) {
                    labels.push(label.to_string());
                }
            }
            rest = &after[end + 1..];
        }
    }
    labels
}

/// Turn a task into what runs for `conn` (resolved settings), applying the policy.
pub fn prepare(task: &TaskDef, conn: &Connection, policy: &Policy) -> Result<Prepared> {
    prepare_with(task, conn, policy, &BTreeMap::new())
}

/// Like [`prepare`], with the run's answers to the task's prompt variables (label → answer; the
/// same answers for every host of one run). A prompt variable without an answer is refused, as
/// is an answer holding control characters.
pub fn prepare_with(task: &TaskDef, conn: &Connection, policy: &Policy, answers: &BTreeMap<String, String>) -> Result<Prepared> {
    validate(task)?;
    let mut vars = variables(conn);
    for label in ask_labels(task) {
        let answer = answers.iter().find(|(k, _)| k.trim().eq_ignore_ascii_case(&label)).map(|(_, v)| v);
        let Some(answer) = answer else { return Err(CoreError::Invalid(format!("task `{}`: no answer for `{label}`", task.name))) };
        if answer.chars().any(char::is_control) {
            return Err(CoreError::Invalid(format!("task `{}`: the answer for `{label}` holds control characters", task.name)));
        }
        vars.set(&format!("{ASK_PREFIX}{label}"), answer);
    }
    prepare_vars(task, conn, policy, &vars)
}

fn prepare_vars(task: &TaskDef, conn: &Connection, policy: &Policy, vars: &Variables) -> Result<Prepared> {
    let timeout = Duration::from_secs(task.timeout_secs.into());
    let (invocation, needs_confirmation) = match &task.kind {
        TaskKind::Builtin { builtin } => {
            check_host(&conn.host)?;
            if *builtin == Builtin::TcpCheck {
                let port = conn.settings.port.or(conn.protocol.default_port()).ok_or_else(|| CoreError::Invalid(format!("{} has no port to check", conn.name)))?;
                (Invocation::TcpConnect { host: conn.host.clone(), port }, false)
            } else {
                let (program, args) = builtin_argv(*builtin, &conn.host);
                (Invocation::Local { program, args }, false)
            }
        }
        TaskKind::Custom { program, args, run_on } => {
            let program = vars.substitute(program, false)?;
            let args = args.iter().map(|a| vars.substitute(a, false)).collect::<Result<Vec<_>>>()?;
            if program.trim().is_empty() {
                return Err(CoreError::Invalid(format!("task `{}`: the program is empty after substitution", task.name)));
            }
            let confirm = policy.requires_confirmation(Action::RunCommand, &conn.classification);
            match run_on {
                RunOn::Local => (Invocation::Local { program, args }, confirm),
                RunOn::Ssh => {
                    if !matches!(conn.protocol, crate::model::Protocol::Ssh) {
                        return Err(CoreError::Invalid(format!("{} is not an SSH connection", conn.name)));
                    }
                    let command = std::iter::once(&program).chain(&args).map(|s| posix_quote(s)).collect::<Vec<_>>().join(" ");
                    (Invocation::Remote { command }, confirm)
                }
            }
        }
    };
    let display = match &invocation {
        Invocation::Local { program, args } => std::iter::once(program).chain(args).map(|s| posix_quote(s)).collect::<Vec<_>>().join(" "),
        Invocation::Remote { command } => format!("ssh {}: {command}", conn.host),
        Invocation::TcpConnect { host, port } => format!("tcp connect {host}:{port}"),
    };
    Ok(Prepared { invocation, timeout, needs_confirmation, display })
}

/// Audit details for a task run (task identity and target, never argument values).
pub fn audit_details(task: &TaskDef, prepared: &Prepared) -> BTreeMap<String, String> {
    let kind = match &task.kind {
        TaskKind::Builtin { builtin } => serde_json::to_value(builtin).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default(),
        TaskKind::Custom { run_on: RunOn::Local, .. } => "custom_local".into(),
        TaskKind::Custom { run_on: RunOn::Ssh, .. } => "custom_ssh".into(),
    };
    BTreeMap::from([("task".into(), task.name.clone()), ("kind".into(), kind), ("timeout_secs".into(), prepared.timeout.as_secs().to_string())])
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TaskOutput {
    pub exit: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub cancelled: bool,
}

impl TaskOutput {
    pub fn succeeded(&self) -> bool {
        self.exit == Some(0) && !self.timed_out && !self.cancelled
    }
}

/// What a reader thread has collected so far. Shared, so a run that stops waiting for the reader
/// (A3-F1) still returns the output read up to then.
#[derive(Default)]
struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
    read_error: Option<String>,
}

impl Captured {
    fn text(&self) -> String {
        let mut s = String::from_utf8_lossy(&self.bytes).into_owned();
        if self.truncated {
            s.push_str("\n[output truncated]\n");
        }
        if let Some(e) = &self.read_error {
            s.push_str(&format!("\n[output incomplete: {e}]\n"));
        }
        s
    }
}

fn lock(shared: &Mutex<Captured>) -> std::sync::MutexGuard<'_, Captured> {
    shared.lock().unwrap_or_else(|e| e.into_inner())
}

/// Read `r` to its end into `into`, keeping at most `MAX_OUTPUT` bytes.
fn read_capped(mut r: impl Read, into: &Mutex<Captured>) {
    let mut chunk = [0u8; 8192];
    loop {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let mut c = lock(into);
                let room = MAX_OUTPUT.saturating_sub(c.bytes.len());
                c.bytes.extend_from_slice(&chunk[..n.min(room)]);
                c.truncated |= n > room;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                lock(into).read_error = Some(e.to_string());
                break;
            }
        }
    }
}

/// One output stream of a running program, read on its own thread.
struct Reader {
    captured: Arc<Mutex<Captured>>,
    thread: std::thread::JoinHandle<()>,
}

impl Reader {
    fn start(stream: impl Read + Send + 'static) -> Self {
        let captured = Arc::new(Mutex::new(Captured::default()));
        let into = captured.clone();
        Reader { captured, thread: std::thread::spawn(move || read_capped(stream, &into)) }
    }

    fn text(&self) -> String {
        lock(&self.captured).text()
    }
}

/// Wait until every reader saw end-of-file, for at most `limit`. True when all are done.
fn readers_done(readers: &[Reader], limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if readers.iter().all(|r| r.thread.is_finished()) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(READER_POLL);
    }
}

/// Run a program (no shell) until it exits, `timeout` passes or `cancel` is set; then it is killed
/// together with every process it started (A3-F1). Returns within `READER_GRACE` of the kill: a
/// descendant that escaped the kill and still holds the output pipes is not waited for.
pub fn run_local(program: &str, args: &[String], timeout: Duration, cancel: &AtomicBool) -> Result<TaskOutput> {
    let mut command = Command::new(program);
    hide_console(&mut command);
    own_process_group(&mut command);
    let spawning = crate::plugin::host::spawn::spawn_guard();
    let mut child = command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| CoreError::Invalid(format!("cannot start `{program}`: {e}")))?;
    drop(spawning);
    // Always [stdout, stderr]: both are piped above.
    let readers: Vec<Reader> = [child.stdout.take().map(Reader::start), child.stderr.take().map(Reader::start)].into_iter().flatten().collect();
    let start = Instant::now();
    let mut result = TaskOutput::default();
    let mut exited = false;
    loop {
        if !exited {
            if let Some(status) = child.try_wait().map_err(|e| CoreError::Invalid(e.to_string()))? {
                result.exit = status.code();
                exited = true;
            }
        }
        // The program is over once it has exited and its output has been read to the end. A
        // process it left behind can keep the pipes open; cancel and the timeout still apply.
        if exited && readers_done(&readers, POLL) {
            break;
        }
        result.cancelled = cancel.load(Ordering::SeqCst);
        result.timed_out = start.elapsed() >= timeout;
        if result.cancelled || result.timed_out {
            kill_tree(&mut child);
            if !exited {
                let _ = child.wait();
            }
            readers_done(&readers, READER_GRACE);
            break;
        }
        if !exited {
            std::thread::sleep(POLL);
        }
    }
    let mut texts = readers.iter().map(Reader::text);
    result.stdout = texts.next().unwrap_or_default();
    result.stderr = texts.next().unwrap_or_default();
    Ok(result)
}

/// Unix: the program leads its own process group, so the whole group can be signalled.
#[cfg(unix)]
fn own_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn own_process_group(_: &mut Command) {}

/// Kill the program and the processes it started. Unix: SIGKILL to its process group (the group
/// id is the program's pid, see `own_process_group`). A group still has that id while any member
/// lives, and this is only called while the program runs or its pipes are still held open.
#[cfg(unix)]
fn kill_tree(child: &mut std::process::Child) {
    if let Ok(pgid) = libc::pid_t::try_from(child.id()) {
        if pgid > 1 {
            // SAFETY: kill(2) takes plain integers and touches no memory of this process.
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
        }
    }
    let _ = child.kill();
}

/// Windows: `taskkill /T /F` ends the process tree; then the program itself, in case taskkill
/// could not run.
#[cfg(windows)]
fn kill_tree(child: &mut std::process::Child) {
    let taskkill = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()) + r"\System32\taskkill.exe";
    let mut command = Command::new(taskkill);
    hide_console(&mut command);
    let started = { let _spawning = crate::plugin::host::spawn::spawn_guard(); command.args(["/T", "/F", "/PID", &child.id().to_string()]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() };
    if let Ok(mut killer) = started {
        let deadline = Instant::now() + TREE_KILL_LIMIT;
        while matches!(killer.try_wait(), Ok(None)) && Instant::now() < deadline {
            std::thread::sleep(READER_POLL);
        }
        if matches!(killer.try_wait(), Ok(None)) {
            let _ = killer.kill();
            let _ = killer.wait();
        }
    }
    let _ = child.kill();
}

#[cfg(not(any(unix, windows)))]
fn kill_tree(child: &mut std::process::Child) {
    let _ = child.kill();
}

/// Owner point W18: a GUI app has no console, so Windows would open a console window for every
/// console program a task starts (ping, nslookup, cmd). Output is captured anyway; keep it hidden.
#[cfg(windows)]
fn hide_console(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn hide_console(_: &mut Command) {}

/// Try a TCP connection to every address `host` resolves to; exit 0 when one accepts.
pub fn tcp_check(host: &str, port: u16, timeout: Duration) -> TaskOutput {
    let t0 = Instant::now();
    let addrs = match (host, port).to_socket_addrs() {
        Ok(a) => a.collect::<Vec<_>>(),
        Err(e) => return TaskOutput { exit: Some(2), stderr: format!("cannot resolve {host}: {e}\n"), ..Default::default() },
    };
    let mut log = String::new();
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout.min(Duration::from_secs(10))) {
            Ok(_) => {
                log.push_str(&format!("{a}: open ({} ms)\n", t0.elapsed().as_millis()));
                return TaskOutput { exit: Some(0), stdout: log, ..Default::default() };
            }
            Err(e) => log.push_str(&format!("{a}: {e}\n")),
        }
    }
    TaskOutput { exit: Some(1), stdout: log, ..Default::default() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;
    use crate::policy::Environment;

    fn conn() -> Connection {
        let mut c = Connection::new("web1", Protocol::Ssh, "127.0.0.1");
        c.settings.port = Some(2222);
        c.settings.username = Some("tester".into());
        c.metadata.insert("user.role".into(), "it's web".into());
        c
    }

    fn custom(program: &str, args: &[&str], run_on: RunOn) -> TaskDef {
        TaskDef { id: Uuid::new_v4(), name: "t".into(), favorite: false, kind: TaskKind::Custom { program: program.into(), args: args.iter().map(|s| s.to_string()).collect(), run_on }, timeout_secs: 5 }
    }

    fn answers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn ask_labels_are_listed_once_in_first_use_order() {
        let t = custom("$Ask:Tool$", &["-t", "$Ask:Target IP$", "$ask:target ip$", "$Host$", "$$Ask:Not$$", "$Ask: $"], RunOn::Local);
        assert_eq!(ask_labels(&t), vec!["Tool".to_string(), "Target IP".to_string()]);
        assert!(ask_labels(&TaskDef { kind: TaskKind::Builtin { builtin: Builtin::Ping }, ..t }).is_empty());
    }

    #[test]
    fn ask_answers_fill_every_use_and_are_quoted_for_ssh() {
        let t = custom("ping", &["-c", "$Ask:Count$", "$Ask:Target IP$"], RunOn::Ssh);
        let a = answers(&[("target ip", "10.0.0.5; reboot"), ("Count", "3")]);
        let p = prepare_with(&t, &conn(), &Policy::default(), &a).unwrap();
        assert_eq!(p.invocation, Invocation::Remote { command: "ping -c 3 '10.0.0.5; reboot'".into() });
        let local = prepare_with(&custom("echo", &["$Ask:X$-$Host$"], RunOn::Local), &conn(), &Policy::default(), &answers(&[("X", "a b")])).unwrap();
        assert_eq!(local.invocation, Invocation::Local { program: "echo".into(), args: vec!["a b-127.0.0.1".into()] });
    }

    #[test]
    fn ask_without_an_answer_or_with_control_characters_is_refused() {
        let t = custom("echo", &["$Ask:Target$"], RunOn::Local);
        assert!(prepare(&t, &conn(), &Policy::default()).unwrap_err().to_string().contains("no answer for `Target`"));
        let err = prepare_with(&t, &conn(), &Policy::default(), &answers(&[("Target", "a\nb")])).unwrap_err();
        assert!(err.to_string().contains("control characters"));
        // An empty answer is an answer.
        assert!(prepare_with(&t, &conn(), &Policy::default(), &answers(&[("Target", "")])).is_ok());
    }

    #[test]
    fn substitutes_each_argument_without_a_shell() {
        let p = prepare(&custom("echo", &["$Host$:$Port$", "$Username$; rm -rf /", "$Meta.role$"], RunOn::Local), &conn(), &Policy::default()).unwrap();
        assert_eq!(p.invocation, Invocation::Local { program: "echo".into(), args: vec!["127.0.0.1:2222".into(), "tester; rm -rf /".into(), "it's web".into()] });
        assert!(!p.needs_confirmation);
    }

    #[test]
    fn remote_command_is_quoted_per_argument() {
        let p = prepare(&custom("echo", &["$Meta.role$", "$$(id)"], RunOn::Ssh), &conn(), &Policy::default()).unwrap();
        assert_eq!(p.invocation, Invocation::Remote { command: r"echo 'it'\''s web' '$(id)'".into() });
    }

    #[test]
    fn secrets_and_unknown_variables_are_refused() {
        assert!(matches!(prepare(&custom("echo", &["$Password$"], RunOn::Local), &conn(), &Policy::default()), Err(CoreError::SecretLeak(_))));
        assert!(prepare(&custom("echo", &["$Nope$"], RunOn::Local), &conn(), &Policy::default()).is_err());
    }

    #[test]
    fn production_custom_tasks_need_confirmation_builtins_do_not() {
        let mut c = conn();
        c.classification.environment = Environment::Production;
        assert!(prepare(&custom("true", &[], RunOn::Local), &c, &Policy::default()).unwrap().needs_confirmation);
        assert!(!prepare(&builtins()[0], &c, &Policy::default()).unwrap().needs_confirmation);
    }

    #[test]
    fn option_like_hosts_are_refused_for_builtins() {
        let mut c = conn();
        c.host = "-oProxyCommand=x".into();
        assert!(prepare(&builtins()[0], &c, &Policy::default()).is_err());
    }

    #[test]
    fn validation_bounds() {
        let mut t = custom("", &[], RunOn::Local);
        assert!(validate(&t).is_err());
        t = custom("x", &[], RunOn::Local);
        t.timeout_secs = 0;
        assert!(validate(&t).is_err());
        assert!(builtins().iter().all(|b| validate(b).is_ok() && is_builtin(b.id)));
    }

    #[cfg(unix)]
    #[test]
    fn runs_times_out_and_cancels() {
        let never = AtomicBool::new(false);
        let ok = run_local("/bin/echo", &["hi".into()], Duration::from_secs(5), &never).unwrap();
        assert_eq!((ok.exit, ok.stdout.as_str()), (Some(0), "hi\n"));
        let slow = run_local("/bin/sleep", &["5".into()], Duration::from_millis(200), &never).unwrap();
        assert!(slow.timed_out && !slow.succeeded());
        let stop = AtomicBool::new(true);
        assert!(run_local("/bin/sleep", &["5".into()], Duration::from_secs(5), &stop).unwrap().cancelled);
    }

    /// Set `flag` after `after` on another thread.
    #[cfg(unix)]
    fn set_after(flag: &std::sync::Arc<AtomicBool>, after: Duration) {
        let flag = flag.clone();
        std::thread::spawn(move || {
            std::thread::sleep(after);
            flag.store(true, Ordering::SeqCst);
        });
    }

    /// A3-F1: the shell's child (`sleep`) inherits the output pipes. Killing only the shell left
    /// the readers waiting for end-of-file until `sleep` exited.
    #[cfg(unix)]
    #[test]
    fn cancel_returns_promptly_when_a_grandchild_holds_the_pipes() {
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        set_after(&stop, Duration::from_millis(200));
        let t0 = Instant::now();
        let out = run_local("/bin/sh", &["-c".into(), "echo started; sleep 30 & wait".into()], Duration::from_secs(60), &stop).unwrap();
        assert!(t0.elapsed() < Duration::from_secs(1), "cancel took {:?}", t0.elapsed());
        assert!(out.cancelled && !out.timed_out && !out.succeeded());
        assert_eq!(out.stdout, "started\n");
    }

    #[cfg(unix)]
    #[test]
    fn timeout_returns_promptly_when_a_grandchild_holds_the_pipes() {
        let never = AtomicBool::new(false);
        let t0 = Instant::now();
        let out = run_local("/bin/sh", &["-c".into(), "sleep 30 & wait".into()], Duration::from_millis(200), &never).unwrap();
        assert!(t0.elapsed() < Duration::from_secs(1), "timeout took {:?}", t0.elapsed());
        assert!(out.timed_out && !out.cancelled);
    }

    /// A descendant that left the process group (its own session) survives the group kill and
    /// keeps the pipes open: the readers get a short grace, then what was read is returned.
    #[cfg(unix)]
    #[test]
    fn cancel_does_not_wait_for_a_descendant_outside_the_group() {
        if !std::path::Path::new("/usr/bin/perl").exists() {
            return eprintln!("SKIPPED cancel_does_not_wait_for_a_descendant_outside_the_group: no /usr/bin/perl");
        }
        let script = "$| = 1; print qq(started\\n); if (fork() == 0) { POSIX::setsid(); sleep 8; exit 0 } sleep 30;";
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        set_after(&stop, Duration::from_millis(200));
        let t0 = Instant::now();
        let out = run_local("/usr/bin/perl", &["-MPOSIX".into(), "-e".into(), script.into()], Duration::from_secs(60), &stop).unwrap();
        assert!(t0.elapsed() < Duration::from_secs(2), "cancel took {:?}", t0.elapsed());
        assert!(out.cancelled);
        assert_eq!(out.stdout, "started\n");
    }

    /// A program that exits while a background child still writes: the exit code is kept and the
    /// run ends at the timeout instead of never.
    #[cfg(unix)]
    #[test]
    fn exit_code_is_kept_when_output_outlives_the_program() {
        let never = AtomicBool::new(false);
        let t0 = Instant::now();
        let out = run_local("/bin/sh", &["-c".into(), "sleep 30 & exit 3".into()], Duration::from_millis(300), &never).unwrap();
        assert!(t0.elapsed() < Duration::from_secs(1), "took {:?}", t0.elapsed());
        assert_eq!((out.exit, out.timed_out), (Some(3), true));
        let quick = run_local("/bin/sh", &["-c".into(), "echo out; echo err >&2; exit 7".into()], Duration::from_secs(5), &never).unwrap();
        assert_eq!((quick.exit, quick.stdout.as_str(), quick.stderr.as_str(), quick.timed_out), (Some(7), "out\n", "err\n", false));
    }

    /// A3-F1 on Windows: `cmd` starts `waitfor`, which inherits the output pipes. Cancel must end
    /// both (`taskkill /T /F`), not only `cmd`.
    #[cfg(windows)]
    #[test]
    fn cancel_kills_the_process_tree_on_windows() {
        let sys = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()) + r"\System32\";
        let tasklist = sys.clone() + "tasklist.exe";
        let child_runs = move || {
            let out = Command::new(&tasklist).args(["/NH", "/FI", "IMAGENAME eq waitfor.exe"]).output().expect("tasklist");
            String::from_utf8_lossy(&out.stdout).to_lowercase().contains("waitfor.exe")
        };
        assert!(!child_runs(), "a waitfor.exe is already running on this machine");
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let seen = std::sync::Arc::new(AtomicBool::new(false));
        let (flag, saw, probe) = (stop.clone(), seen.clone(), child_runs.clone());
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !probe() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
            }
            saw.store(probe(), Ordering::SeqCst);
            flag.store(true, Ordering::SeqCst);
        });
        let out = run_local(&(sys + "cmd.exe"), &["/C".into(), "echo started & waitfor /T 60 BastionA3F1Test".into()], Duration::from_secs(60), &stop).unwrap();
        assert!(seen.load(Ordering::SeqCst), "the child process never started: {out:?}");
        assert!(out.cancelled && !out.timed_out && !out.succeeded());
        assert!(out.stdout.contains("started"), "{out:?}");
        assert!(!child_runs(), "the child process survived the cancel");
    }

    #[test]
    fn tcp_check_open_and_closed() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert_eq!(tcp_check("127.0.0.1", port, Duration::from_secs(2)).exit, Some(0));
        assert_eq!(tcp_check("127.0.0.1", 1, Duration::from_secs(2)).exit, Some(1));
    }

    // ---- B5 hooks ----

    fn folder(name: &str) -> crate::model::Folder {
        crate::model::Folder { id: Uuid::new_v4(), name: name.into(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() }
    }

    fn local_task(name: &str) -> TaskDef {
        TaskDef { id: Uuid::new_v4(), name: name.into(), favorite: false, kind: TaskKind::Custom { program: "/usr/bin/true".into(), args: vec![], run_on: RunOn::Local }, timeout_secs: 5 }
    }

    /// Root › outer › inner › connection, with tasks a (local) and b (ssh).
    fn tree() -> (crate::model::Document, Uuid, Uuid, Uuid, TaskDef, TaskDef) {
        use crate::model::{Document, Node};
        let mut doc = Document::new("t");
        let (outer, inner) = (folder("outer"), folder("inner"));
        let (oid, iid) = (outer.id, inner.id);
        let c = conn();
        let cid = c.id;
        doc.insert(None, Node::Folder(outer)).unwrap();
        doc.insert(Some(oid), Node::Folder(inner)).unwrap();
        doc.insert(Some(iid), Node::Connection(c)).unwrap();
        let a = local_task("a");
        let mut b = local_task("b");
        b.kind = TaskKind::Custom { program: "uptime".into(), args: vec![], run_on: RunOn::Ssh };
        doc.tasks = vec![a.clone(), b.clone()];
        (doc, oid, iid, cid, a, b)
    }

    fn on_folder(folder: Uuid, task: Uuid, when: HookWhen) -> TaskHook {
        TaskHook { connection_id: Uuid::nil(), folder_id: Some(folder), ..TaskHook::on_connection(Uuid::nil(), task, when) }
    }

    #[test]
    fn hooks_run_outer_folder_then_inner_then_connection_once_each() {
        let (mut doc, oid, iid, cid, a, b) = tree();
        let own = TaskHook::on_connection(cid, b.id, HookWhen::BeforeConnect);
        let inner = on_folder(iid, b.id, HookWhen::BeforeConnect);
        let outer = on_folder(oid, a.id, HookWhen::BeforeConnect);
        doc.task_hooks = vec![own.clone(), inner.clone(), outer.clone(), own.clone(), on_folder(oid, a.id, HookWhen::AfterConnect)];
        let keys = vec![TrustStore::key(&a)];
        let got: Vec<TaskHook> = hooks_for(&doc, cid, HookWhen::BeforeConnect, &keys).into_iter().map(|r| r.hook).collect();
        assert_eq!(got, vec![outer, inner, own]);
    }

    #[test]
    fn folder_hooks_reach_connections_in_subfolders_only() {
        let (mut doc, _oid, iid, cid, _a, b) = tree();
        let other = conn();
        let other_id = other.id;
        doc.insert(None, crate::model::Node::Connection(other)).unwrap();
        doc.task_hooks = vec![on_folder(iid, b.id, HookWhen::AfterDisconnect)];
        assert_eq!(hooks_for(&doc, cid, HookWhen::AfterDisconnect, &[]).len(), 1);
        assert!(hooks_for(&doc, other_id, HookWhen::AfterDisconnect, &[]).is_empty());
    }

    #[test]
    fn documents_before_b5_load_and_round_trip_unchanged() {
        let (c, t) = (Uuid::new_v4(), Uuid::new_v4());
        let old = format!(r#"{{"connection_id":"{c}","task_id":"{t}","when":"after_connect"}}"#);
        let h: TaskHook = serde_json::from_str(&old).unwrap();
        assert_eq!(h, TaskHook::on_connection(c, t, HookWhen::AfterConnect));
        assert_eq!(serde_json::to_string(&h).unwrap(), old);
        let d: HookWhen = serde_json::from_str(r#""after_disconnect""#).unwrap();
        assert_eq!(d, HookWhen::AfterDisconnect);
    }

    #[test]
    fn snippet_hooks_only_after_connect_and_multi_host_only_on_folders() {
        let c = Uuid::new_v4();
        let mut s = TaskHook::on_connection(c, Uuid::nil(), HookWhen::AfterConnect);
        s.target = HookTarget::Snippet;
        s.snippet_id = Some("snip-1".into());
        assert!(validate_hook(&s).is_ok());
        for when in [HookWhen::BeforeConnect, HookWhen::AfterDisconnect] {
            assert!(validate_hook(&TaskHook { when, ..s.clone() }).is_err());
        }
        assert!(validate_hook(&TaskHook { snippet_id: None, ..s.clone() }).is_err());
        let mut m = TaskHook::on_connection(c, Uuid::new_v4(), HookWhen::AfterConnect);
        m.target = HookTarget::MultiHost;
        assert!(validate_hook(&m).is_err());
        assert!(validate_hook(&TaskHook { connection_id: Uuid::nil(), folder_id: Some(Uuid::new_v4()), ..m }).is_ok());
        assert!(validate_hook(&TaskHook::on_connection(Uuid::nil(), Uuid::new_v4(), HookWhen::BeforeConnect)).is_err());
    }

    #[test]
    fn untrusted_local_document_hooks_are_not_runnable() {
        let (mut doc, _oid, _iid, cid, a, b) = tree();
        doc.task_hooks = vec![TaskHook::on_connection(cid, a.id, HookWhen::BeforeConnect), TaskHook::on_connection(cid, b.id, HookWhen::BeforeConnect)];
        let r = hooks_for(&doc, cid, HookWhen::BeforeConnect, &[]);
        assert!(!r[0].runnable && r[0].untrusted, "local program from a document must wait for a save");
        assert!(r[1].runnable, "an SSH task runs on the remote host and needs no local trust");
        // Trusted only for the exact content: any edit needs a new save.
        let keys = vec![TrustStore::key(&a)];
        assert!(hooks_for(&doc, cid, HookWhen::BeforeConnect, &keys)[0].runnable);
        doc.tasks[0].kind = TaskKind::Custom { program: "/bin/rm".into(), args: vec![], run_on: RunOn::Local };
        assert!(!hooks_for(&doc, cid, HookWhen::BeforeConnect, &keys)[0].runnable);
        // An unknown task is never runnable.
        doc.task_hooks = vec![TaskHook::on_connection(cid, Uuid::new_v4(), HookWhen::BeforeConnect)];
        assert!(!hooks_for(&doc, cid, HookWhen::BeforeConnect, &keys)[0].runnable);
    }

    #[test]
    fn trust_store_keeps_one_entry_per_task() {
        let dir = std::env::temp_dir().join(format!("bastion-trust-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut a = local_task("a");
        TrustStore::trust(&dir, &a).unwrap();
        assert!(TrustStore::is_trusted(&TrustStore::load(&dir), &a));
        a.name = "a2".into();
        assert!(!TrustStore::is_trusted(&TrustStore::load(&dir), &a));
        TrustStore::trust(&dir, &a).unwrap();
        assert_eq!(TrustStore::load(&dir).len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
