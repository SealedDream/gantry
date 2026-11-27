//! Bridge for saved tasks (`bastion_core::tasks`): list and edit the library's tasks, attach them
//! to connections, and run one against a connection in the background with cancel and timeout.
//! Every run is policy-checked and audited (category `task`); custom tasks on sensitive
//! connections need `confirmed`.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bastion_core::audit::{Category, Outcome};
use bastion_core::error::CoreError;
use bastion_core::tasks::{self, HookTarget, HookWhen, Invocation, RunOn, TaskDef, TaskHook, TaskKind, TaskOutput, TrustStore};
use uuid::Uuid;

use crate::terminal::{SessionManager, RUNTIME};
use crate::{parse_id, FfiError, FfiResult, Library, SshLogin};

const CANCEL_POLL: Duration = Duration::from_millis(100);

#[derive(uniffi::Record, Clone)]
pub struct TaskView {
    /// Empty when saving a new task.
    pub id: String,
    pub name: String,
    pub favorite: bool,
    pub builtin: bool,
    /// `ping`, `trace_route`, `dns_lookup`, `tcp_check` or `custom`.
    pub kind: String,
    pub program: String,
    pub args: Vec<String>,
    /// `local` or `ssh` (custom tasks).
    pub run_on: String,
    pub timeout_secs: u32,
}

#[derive(uniffi::Record, Clone)]
pub struct TaskHookView {
    pub task_id: String,
    /// `before_connect`, `after_connect` or `after_disconnect`.
    pub when: String,
    /// `task` (default), `snippet` (after connect only) or `multi_host` (folders only).
    pub target: String,
    /// The snippet sent for a `snippet` hook.
    pub snippet_id: Option<String>,
}

/// A hook to run for one connection, in order (outer folder first). B5.
#[derive(uniffi::Record, Clone)]
pub struct ResolvedHookView {
    pub hook: TaskHookView,
    /// The connection or folder the hook is set on.
    pub owner_id: String,
    pub runnable: bool,
    /// A local-program task from a document that the user has not saved in Tasks on this computer.
    pub untrusted: bool,
}

fn hook_view(h: &TaskHook) -> TaskHookView {
    TaskHookView { task_id: if h.task_id.is_nil() { String::new() } else { h.task_id.to_string() }, when: enum_str(&h.when), target: enum_str(&h.target), snippet_id: h.snippet_id.clone() }
}

#[derive(uniffi::Record)]
pub struct TaskReviewView {
    pub display: String,
    pub needs_confirmation: bool,
}

#[derive(Clone, uniffi::Record)]
pub struct TaskRunView {
    /// `running`, `done`, `failed`, `timed_out` or `cancelled`.
    pub state: String,
    pub exit: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
    pub millis: u64,
}

fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

fn enum_parse<T: serde::de::DeserializeOwned>(s: &str, what: &str) -> FfiResult<T> {
    serde_json::from_value(serde_json::Value::String(s.into())).map_err(|_| FfiError::failed(format!("unknown {what} `{s}`")))
}

fn view(t: &TaskDef, favorite: bool) -> TaskView {
    let (kind, program, args, run_on) = match &t.kind {
        TaskKind::Builtin { builtin } => {
            let (program, args) = tasks::builtin_command(*builtin).unwrap_or_default();
            (enum_str(builtin), program, args, "local".into())
        }
        TaskKind::Custom { program, args, run_on } => ("custom".into(), program.clone(), args.clone(), enum_str(run_on)),
    };
    TaskView { id: t.id.to_string(), name: t.name.clone(), favorite, builtin: tasks::is_builtin(t.id), kind, program, args, run_on, timeout_secs: t.timeout_secs }
}

fn find(doc: &bastion_core::model::Document, id: Uuid) -> bastion_core::Result<TaskDef> {
    tasks::find(doc, id).ok_or_else(|| CoreError::NotFound(id.to_string()))
}

#[uniffi::export]
impl Library {
    /// Built-in tasks first, then the library's own, each with its favourite flag. A built-in
    /// edited in place shows its edit: `builtin` true with kind `custom`.
    pub fn tasks(&self) -> Vec<TaskView> {
        self.with_doc(|d| {
            let mut out: Vec<TaskView> = tasks::builtins()
                .iter()
                .map(|b| view(d.tasks.iter().find(|t| t.id == b.id).unwrap_or(b), d.favorite_builtin_tasks.contains(&b.id)))
                .collect();
            out.extend(d.tasks.iter().filter(|t| !tasks::is_builtin(t.id)).map(|t| view(t, t.favorite)));
            Ok(out)
        })
        .unwrap_or_default()
    }

    /// Add (empty `id`) or replace a custom task after validating it. Returns its id. A built-in's
    /// id saves an in-place edit of that built-in (a custom task; `remove_task` restores the default).
    pub fn save_task(&self, task: TaskView) -> FfiResult<String> {
        if task.kind != "custom" {
            return Err(FfiError::failed("only custom tasks can be saved".into()));
        }
        let id = if task.id.is_empty() { Uuid::new_v4() } else { parse_id(&task.id)? };
        if task.builtin && !tasks::is_builtin(id) {
            return Err(FfiError::failed("not a built-in task".into()));
        }
        let def = TaskDef {
            id,
            name: task.name.trim().to_string(),
            favorite: task.favorite,
            kind: TaskKind::Custom { program: task.program.trim().to_string(), args: task.args, run_on: enum_parse::<RunOn>(&task.run_on, "run location")? },
            timeout_secs: task.timeout_secs,
        };
        tasks::validate(&def)?;
        self.with_doc(|d| {
            match d.tasks.iter_mut().find(|t| t.id == id) {
                Some(t) => *t = def,
                None => d.tasks.push(def),
            }
            Ok(())
        })?;
        Ok(id.to_string())
    }

    /// Remove a custom task and every hook that used it. On a built-in: Restore Default (drops the
    /// in-place edit; the built-in, its hooks and favourite stay).
    pub fn remove_task(&self, task_id: String) -> FfiResult<()> {
        let id = parse_id(&task_id)?;
        self.with_doc(|d| {
            d.tasks.retain(|t| t.id != id);
            if tasks::is_builtin(id) {
                return Ok(());
            }
            d.task_hooks.retain(|h| h.task_id != id);
            Ok(())
        })
    }

    pub fn set_task_favorite(&self, task_id: String, favorite: bool) -> FfiResult<()> {
        let id = parse_id(&task_id)?;
        self.with_doc(|d| {
            if tasks::is_builtin(id) {
                d.favorite_builtin_tasks.retain(|x| *x != id);
                if favorite {
                    d.favorite_builtin_tasks.push(id);
                }
                return Ok(());
            }
            let t = d.tasks.iter_mut().find(|t| t.id == id).ok_or_else(|| CoreError::NotFound(id.to_string()))?;
            t.favorite = favorite;
            Ok(())
        })
    }

    /// The hooks set on a connection or a folder (not inherited ones).
    pub fn task_hooks(&self, connection_id: String) -> FfiResult<Vec<TaskHookView>> {
        let cid = parse_id(&connection_id)?;
        self.with_doc(|d| Ok(d.task_hooks.iter().filter(|h| h.owner() == cid).map(hook_view).collect()))
    }

    /// Replace the hooks set on a connection or a folder (the Attached Tasks sheet).
    pub fn set_task_hooks(&self, connection_id: String, hooks: Vec<TaskHookView>) -> FfiResult<()> {
        let cid = parse_id(&connection_id)?;
        self.with_doc(|d| {
            let on_folder = d.folder(cid).is_some();
            let mut parsed = Vec::with_capacity(hooks.len());
            for h in &hooks {
                let target = if h.target.is_empty() { HookTarget::Task } else { enum_parse::<HookTarget>(&h.target, "hook target").map_err(|e| CoreError::Invalid(e.to_string()))? };
                let task_id = if h.task_id.is_empty() { Uuid::nil() } else { Uuid::parse_str(&h.task_id).map_err(|_| CoreError::Invalid(format!("bad id `{}`", h.task_id)))? };
                let when = enum_parse::<HookWhen>(&h.when, "hook time").map_err(|e| CoreError::Invalid(e.to_string()))?;
                let mut hook = TaskHook::on_connection(cid, task_id, when);
                if on_folder {
                    hook.connection_id = Uuid::nil();
                    hook.folder_id = Some(cid);
                }
                hook.target = target;
                hook.snippet_id = h.snippet_id.clone().filter(|s| !s.is_empty());
                tasks::validate_hook(&hook)?;
                if target != HookTarget::Snippet {
                    find(d, hook.task_id)?;
                }
                parsed.push(hook);
            }
            d.task_hooks.retain(|h| h.owner() != cid);
            d.task_hooks.extend(parsed);
            Ok(())
        })
    }

    /// The hooks to run for `connection_id` at `when` (folder hooks inherited, outer first),
    /// each marked runnable or not under the trust rule read from `data_dir`.
    pub fn resolved_task_hooks(&self, connection_id: String, when: String, data_dir: String) -> FfiResult<Vec<ResolvedHookView>> {
        let cid = parse_id(&connection_id)?;
        let when = enum_parse::<HookWhen>(&when, "hook time")?;
        let trusted = TrustStore::load(std::path::Path::new(&data_dir));
        self.with_doc(|d| {
            Ok(tasks::hooks_for(d, cid, when, &trusted)
                .into_iter()
                .map(|r| ResolvedHookView { owner_id: r.hook.owner().to_string(), hook: hook_view(&r.hook), runnable: r.runnable, untrusted: r.untrusted })
                .collect())
        })
    }

    /// Record a custom task as saved by the user on this computer (T01), so it may run as a
    /// hook. Call only from the user's own Save in the task editor.
    pub fn trust_task(&self, task_id: String, data_dir: String) -> FfiResult<()> {
        let id = parse_id(&task_id)?;
        let task = self.with_doc(|d| find(d, id))?;
        TrustStore::trust(std::path::Path::new(&data_dir), &task)?;
        Ok(())
    }
}

fn prepare(library: &Library, task_id: &str, connection_id: &str, answers: &HashMap<String, String>) -> FfiResult<(TaskDef, bastion_core::model::Connection, tasks::Prepared)> {
    let tid = parse_id(task_id)?;
    let task = library.with_doc(|d| find(d, tid))?;
    let conn = library.resolve(parse_id(connection_id)?)?;
    let answers: std::collections::BTreeMap<String, String> = answers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let prepared = tasks::prepare_with(&task, &conn, &crate::policy::effective()?, &answers)?;
    Ok((task, conn, prepared))
}

/// The labels a run must ask for (`$Ask:Label$`), once per run, first use first.
#[uniffi::export]
pub fn task_ask_labels(library: Arc<Library>, task_id: String) -> FfiResult<Vec<String>> {
    let tid = parse_id(&task_id)?;
    let task = library.with_doc(|d| find(d, tid))?;
    Ok(tasks::ask_labels(&task))
}

/// What a run would execute with these prompt answers, and whether the user must confirm it first.
#[uniffi::export]
pub fn review_task(library: Arc<Library>, task_id: String, connection_id: String, answers: HashMap<String, String>) -> FfiResult<TaskReviewView> {
    let (_, _, p) = prepare(&library, &task_id, &connection_id, &answers)?;
    Ok(TaskReviewView { display: p.display, needs_confirmation: p.needs_confirmation })
}

#[derive(uniffi::Object)]
pub struct TaskRun {
    display: String,
    state: Arc<Mutex<TaskRunView>>,
    cancel: Arc<AtomicBool>,
}

fn running() -> TaskRunView {
    TaskRunView { state: "running".into(), exit: None, stdout: String::new(), stderr: String::new(), error: None, millis: 0 }
}

#[uniffi::export]
impl TaskRun {
    /// Start `task_id` against `connection_id` on a background thread. `username`/`login` are used
    /// only by SSH tasks (dialled like a terminal: broker, strict host keys). Refused when the
    /// review asks for confirmation and `confirmed` is false.
    #[uniffi::constructor]
    pub fn start(manager: Arc<SessionManager>, library: Arc<Library>, task_id: String, connection_id: String, username: String, login: SshLogin, confirmed: bool, answers: HashMap<String, String>) -> FfiResult<Arc<Self>> {
        let (task, conn, prepared) = match prepare(&library, &task_id, &connection_id, &answers) {
            Ok(p) => p,
            Err(e) => {
                // A refused run (secret variable, unknown variable, policy) is audited too.
                let tid = parse_id(&task_id).ok();
                let name = tid.and_then(|id| library.with_doc(|d| find(d, id)).ok()).map(|t| t.name).unwrap_or_default();
                let target = parse_id(&connection_id).ok().and_then(|id| library.resolve(id).ok()).map(|c| c.name);
                let details = [("task".to_string(), name), ("error".to_string(), e.to_string())].into_iter().collect();
                manager.record_audit(Category::Task, "task.run", target.as_deref(), Outcome::Denied, details);
                return Err(e);
            }
        };
        let details = tasks::audit_details(&task, &prepared);
        if prepared.needs_confirmation && !confirmed {
            manager.record_audit(Category::Task, "task.run", Some(&conn.name), Outcome::Denied, details);
            return Err(FfiError::failed(format!("Confirm running `{}` on {}", task.name, conn.name)));
        }
        let run = Arc::new(TaskRun { display: prepared.display.clone(), state: Arc::new(Mutex::new(running())), cancel: Arc::new(AtomicBool::new(false)) });
        let (state, cancel) = (run.state.clone(), run.cancel.clone());
        std::thread::spawn(move || {
            let t0 = Instant::now();
            let result = execute(&manager, &library, &connection_id, username, login, &prepared, &cancel);
            let view = finish(result, t0.elapsed().as_millis() as u64);
            let outcome = if view.state == "done" && view.exit == Some(0) { Outcome::Success } else { Outcome::Failure };
            let mut details = details;
            details.insert("state".into(), view.state.clone());
            if let Some(code) = view.exit {
                details.insert("exit".into(), code.to_string());
            }
            // A3-F1: a cancelled run reports at once. Its audit record can have to wait: a dial
            // that was abandoned still holds the audit lock until it ends (`Dialer::dial`).
            let cancelled = view.state == "cancelled";
            if cancelled {
                *state.lock().unwrap_or_else(|e| e.into_inner()) = view.clone();
            }
            manager.record_audit(Category::Task, "task.run", Some(&conn.name), outcome, details);
            if !cancelled {
                *state.lock().unwrap_or_else(|e| e.into_inner()) = view;
            }
        });
        Ok(run)
    }

    /// The command line shown in the output tab.
    pub fn display(&self) -> String {
        self.display.clone()
    }

    /// Kill the local program, or stop waiting for the remote one (its channel is closed).
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    pub fn is_finished(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).state != "running"
    }

    pub fn output(&self) -> TaskRunView {
        let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        TaskRunView { state: s.state.clone(), exit: s.exit, stdout: s.stdout.clone(), stderr: s.stderr.clone(), error: s.error.clone(), millis: s.millis }
    }
}

fn execute(manager: &Arc<SessionManager>, library: &Arc<Library>, connection_id: &str, username: String, login: SshLogin, p: &tasks::Prepared, cancel: &Arc<AtomicBool>) -> FfiResult<TaskOutput> {
    match &p.invocation {
        Invocation::Local { program, args } => Ok(tasks::run_local(program, args, p.timeout, cancel)?),
        Invocation::TcpConnect { host, port } => Ok(tasks::tcp_check(host, *port, p.timeout)),
        Invocation::Remote { command } => {
            let (manager, library, connection_id, command, timeout, flag) = (manager.clone(), library.clone(), connection_id.to_string(), command.clone(), p.timeout, cancel.clone());
            until_cancelled(cancel, move || run_remote(&manager, &library, &connection_id, username, login, &command, timeout, &flag))
        }
    }
}

/// Run `work` on its own thread and return its result, or "cancelled" as soon as `cancel` is set.
/// A3-F1: the SSH dial is one blocking call that cannot be interrupted, so a cancel during it used
/// to be seen only after the dial ended. `work` watches the same flag and stops by itself.
fn until_cancelled(cancel: &AtomicBool, work: impl FnOnce() -> FfiResult<TaskOutput> + Send + 'static) -> FfiResult<TaskOutput> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // The receiver is gone once the run was cancelled; the result is then not needed.
        let _ = tx.send(work());
    });
    loop {
        match rx.recv_timeout(CANCEL_POLL) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) if cancel.load(Ordering::SeqCst) => return Ok(TaskOutput { cancelled: true, ..Default::default() }),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err(FfiError::failed("the task stopped before it reported a result".into())),
        }
    }
}

/// Dial the connection and run `command` on it. On cancel or timeout the exec future is dropped,
/// which closes its channel; the session is dropped on return, so the remote command is not
/// waited for.
#[allow(clippy::too_many_arguments)]
fn run_remote(manager: &SessionManager, library: &Library, connection_id: &str, username: String, login: SshLogin, command: &str, timeout: Duration, cancel: &AtomicBool) -> FfiResult<TaskOutput> {
    let session = manager.dial_ssh(library, connection_id, username, login, None, HashMap::new(), HashMap::new())?;
    if cancel.load(Ordering::SeqCst) {
        return Ok(TaskOutput { cancelled: true, ..Default::default() });
    }
    RUNTIME.block_on(async {
        let watch = async {
            while !cancel.load(Ordering::SeqCst) {
                tokio::time::sleep(CANCEL_POLL).await;
            }
        };
        tokio::select! {
            r = session.exec(command) => {
                let out = r?;
                Ok(TaskOutput {
                    exit: out.exit_status.map(|c| c as i32),
                    stdout: bastion_core::multiexec::capture(&out.stdout),
                    stderr: bastion_core::multiexec::capture(&out.stderr),
                    ..Default::default()
                })
            }
            _ = tokio::time::sleep(timeout) => Ok(TaskOutput { timed_out: true, ..Default::default() }),
            _ = watch => Ok(TaskOutput { cancelled: true, ..Default::default() }),
        }
    })
}

fn finish(result: FfiResult<TaskOutput>, millis: u64) -> TaskRunView {
    match result {
        Ok(o) => {
            let state = if o.cancelled { "cancelled" } else if o.timed_out { "timed_out" } else { "done" };
            TaskRunView { state: state.into(), exit: o.exit, stdout: o.stdout, stderr: o.stderr, error: None, millis }
        }
        Err(e) => {
            let message = match e {
                FfiError::HostKeyUnknown { .. } => "host key not trusted yet: connect once and verify it first".into(),
                e => e.to_string(),
            };
            TaskRunView { state: "failed".into(), exit: None, stdout: String::new(), stderr: String::new(), error: Some(message), millis }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bastion_core::model::{Connection, Node, Protocol};

    fn setup() -> (std::path::PathBuf, Arc<Library>, Arc<SessionManager>, String) {
        let dir = std::env::temp_dir().join(format!("bastion-tasks-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let lib = Arc::new(Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap());
        let mut c = Connection::new("sshd", Protocol::Ssh, "127.0.0.1");
        c.settings.port = Some(2222);
        let id = c.id.to_string();
        lib.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();
        let mgr = SessionManager::new(dir.to_string_lossy().into_owned()).unwrap();
        (dir, lib, mgr, id)
    }

    fn wait(run: &TaskRun) -> TaskRunView {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !run.is_finished() {
            assert!(Instant::now() < deadline, "timed out");
            std::thread::sleep(Duration::from_millis(50));
        }
        run.output()
    }

    fn custom(program: &str, args: &[&str], run_on: &str) -> TaskView {
        TaskView { id: String::new(), name: "echo".into(), favorite: false, builtin: false, kind: "custom".into(), program: program.into(), args: args.iter().map(|s| s.to_string()).collect(), run_on: run_on.into(), timeout_secs: 10 }
    }

    #[test]
    fn builtin_edits_in_place_and_restores_default() {
        let (dir, lib, _mgr, cid) = setup();
        let ping = tasks::builtins()[0].id.to_string();
        let shown = lib.tasks().into_iter().find(|t| t.id == ping).unwrap();
        assert!(shown.builtin && shown.kind == "ping" && shown.args.contains(&"$Host$".to_string()), "Edit… starts from the command");
        lib.set_task_favorite(ping.clone(), true).unwrap();
        let hook = TaskHookView { when: "after_connect".into(), task_id: ping.clone(), target: String::new(), snippet_id: None };
        lib.set_task_hooks(cid.clone(), vec![hook]).unwrap();

        let edit = TaskView { id: ping.clone(), builtin: true, name: "Ping 10".into(), ..custom("/sbin/ping", &["-c", "10", "$Host$"], "local") };
        assert_eq!(lib.save_task(edit).unwrap(), ping);
        let all = lib.tasks();
        assert_eq!(all.iter().filter(|t| t.id == ping).count(), 1, "no second row for the edit");
        let edited = all.iter().find(|t| t.id == ping).unwrap();
        assert!(edited.builtin && edited.kind == "custom" && edited.name == "Ping 10" && edited.favorite);
        assert!(lib.with_doc(|d| Ok(tasks::find(d, Uuid::parse_str(&ping).unwrap()).unwrap().name)).unwrap() == "Ping 10", "runs and hooks use the edit");

        lib.remove_task(ping.clone()).unwrap();
        let restored = lib.tasks().into_iter().find(|t| t.id == ping).unwrap();
        assert!(restored.kind == "ping" && restored.name == "Ping" && restored.favorite, "Restore Default");
        assert_eq!(lib.task_hooks(cid).unwrap().len(), 1, "restoring keeps the built-in's hooks");
        assert!(lib.save_task(TaskView { id: Uuid::new_v4().to_string(), builtin: true, ..custom("x", &[], "local") }).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn edits_favourites_hooks_and_runs_locally_with_audit() {
        let (dir, lib, mgr, cid) = setup();
        #[cfg(windows)]
        let echo = custom("cmd.exe", &["/c", "echo", "$Host$", "$Port$"], "local");
        #[cfg(not(windows))]
        let echo = custom("/bin/echo", &["$Host$", "$Port$"], "local");
        let tid = lib.save_task(echo).unwrap();
        lib.set_task_favorite(tasks::builtins()[0].id.to_string(), true).unwrap();
        let all = lib.tasks();
        assert_eq!(all.len(), 5);
        assert!(all[0].favorite && all[0].builtin && !all[4].builtin);
        lib.set_task_hooks(cid.clone(), vec![TaskHookView { task_id: tid.clone(), when: "before_connect".into(), target: "task".into(), snippet_id: None }]).unwrap();
        assert_eq!(lib.task_hooks(cid.clone()).unwrap().len(), 1);
        let run = TaskRun::start(mgr.clone(), lib.clone(), tid.clone(), cid.clone(), String::new(), SshLogin::Agent, false, HashMap::new()).unwrap();
        let out = wait(&run);
        assert_eq!((out.state.as_str(), out.exit, out.stdout.replace("\r\n", "\n").as_str()), ("done", Some(0), "127.0.0.1 2222\n"));
        let tcp = TaskRun::start(mgr, lib.clone(), tasks::builtins()[3].id.to_string(), cid.clone(), String::new(), SshLogin::Agent, false, HashMap::new()).unwrap();
        assert_eq!(wait(&tcp).state, "done");
        lib.remove_task(tid).unwrap();
        assert!(lib.task_hooks(cid).unwrap().is_empty());
        let audit = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(audit.matches("task.run").count() >= 2);
        assert!(lib.save_task(custom("", &[], "local")).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn ask_labels_and_answers_reach_the_review() {
        let (dir, lib, _mgr, cid) = setup();
        let tid = lib.save_task(custom("/bin/echo", &["$Ask:Target IP$", "$Host$"], "local")).unwrap();
        assert_eq!(task_ask_labels(lib.clone(), tid.clone()).unwrap(), vec!["Target IP".to_string()]);
        assert!(review_task(lib.clone(), tid.clone(), cid.clone(), HashMap::new()).is_err());
        let answers: HashMap<String, String> = [("Target IP".to_string(), "10.1.1.1".to_string())].into();
        assert!(review_task(lib, tid, cid, answers).unwrap().display.contains("10.1.1.1"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn refused_runs_are_audited_as_denied() {
        let (dir, lib, mgr, cid) = setup();
        let tid = lib.save_task(custom("/bin/echo", &["$Password$"], "local")).unwrap();
        assert!(review_task(lib.clone(), tid.clone(), cid.clone(), HashMap::new()).is_err());
        assert!(TaskRun::start(mgr, lib, tid, cid, String::new(), SshLogin::Agent, false, HashMap::new()).is_err());
        let audit = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        let line = audit.lines().find(|l| l.contains("task.run")).expect("audited");
        assert!(line.contains("\"outcome\":\"denied\"") && line.contains("\"target\":\"sshd\"") && line.contains("Password"));
        std::fs::remove_dir_all(dir).ok();
    }

    /// A3-F1: work that never finishes (a dial to a host that does not answer) must not hold the
    /// run in "running" after Cancel.
    #[test]
    fn cancel_returns_without_waiting_for_the_work() {
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            flag.store(true, Ordering::SeqCst);
        });
        let t0 = Instant::now();
        let out = until_cancelled(&cancel, move || {
            let _ = blocked.recv();
            Ok(TaskOutput { exit: Some(0), ..Default::default() })
        })
        .unwrap();
        assert!(t0.elapsed() < Duration::from_secs(1), "cancel took {:?}", t0.elapsed());
        assert!(out.cancelled && out.exit.is_none());
        drop(release);
        let done = until_cancelled(&AtomicBool::new(false), || Ok(TaskOutput { exit: Some(4), ..Default::default() })).unwrap();
        assert_eq!((done.exit, done.cancelled), (Some(4), false));
        assert!(until_cancelled(&AtomicBool::new(false), || Err(FfiError::failed("no".into()))).is_err());
    }

    /// An SSH task against a port that takes the connection (listen backlog) and then says nothing:
    /// the dial blocks, and Cancel must still end the run at once.
    #[test]
    fn ssh_task_cancel_during_the_dial_is_prompt() {
        let (dir, lib, mgr, _) = setup();
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = Connection::new("silent", Protocol::Ssh, "127.0.0.1");
        c.settings.port = Some(silent.local_addr().unwrap().port());
        let cid = c.id.to_string();
        lib.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();
        let tid = lib.save_task(custom("sleep", &["30"], "ssh")).unwrap();
        let run = TaskRun::start(mgr, lib, tid, cid, "tester".into(), SshLogin::Agent, false, HashMap::new()).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(run.output().state, "running");
        let t0 = Instant::now();
        run.cancel();
        while !run.is_finished() && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(t0.elapsed() < Duration::from_secs(1), "cancel took {:?}", t0.elapsed());
        assert_eq!(run.output().state, "cancelled");
        std::fs::remove_dir_all(dir).ok();
    }

    #[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
    #[test]
    fn runs_over_ssh_on_the_test_server() {
        assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
        if std::env::var("BASTION_SSH_TEST").is_err() {
            return eprintln!("SKIPPED runs_over_ssh_on_the_test_server: set BASTION_SSH_TEST=1");
        }
        let (dir, lib, mgr, cid) = setup();
        let keys = std::process::Command::new("sh").arg("-c").arg("ssh-keyscan -p 2222 127.0.0.1 2>/dev/null").output().unwrap().stdout;
        std::fs::write(dir.join("known_hosts"), keys).unwrap();
        let tid = lib.save_task(custom("echo", &["it's $Host$", "$$(id)"], "ssh")).unwrap();
        let login = SshLogin::Password { password: "test-pass-123".into() };
        let out = wait(&TaskRun::start(mgr.clone(), lib.clone(), tid, cid.clone(), "tester".into(), login.clone(), false, HashMap::new()).unwrap());
        assert_eq!((out.state.as_str(), out.exit, out.stdout.as_str()), ("done", Some(0), "it's 127.0.0.1 $(id)\n"));
        let slow = lib.save_task(custom("sleep", &["30"], "ssh")).unwrap();
        let run = TaskRun::start(mgr, lib, slow, cid, "tester".into(), login, false, HashMap::new()).unwrap();
        std::thread::sleep(Duration::from_secs(2));
        run.cancel();
        assert_eq!(wait(&run).state, "cancelled");
        std::fs::remove_dir_all(dir).ok();
    }
}
