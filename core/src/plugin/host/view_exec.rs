//! `exec.run`, `exec.cancel` and `exec.terminal` (plugin API 1.5; `docs/specs/plugins.md`,
//! section 19): a declared command on the entry's host over the entry's SSH login and route.
//!
//! The core checks the template and the arguments (`broker::exec`), builds and quotes the
//! command, and asks the app to run it:
//!
//! - `{"type":"exec-go","request":n,"template":id,"command":"docker ps ...","timeout_ms":t,"max_bytes":b}`
//! - `{"type":"exec-cancel","request":n}`: the plugin cancelled, or the time ran out.
//! - `{"type":"exec-terminal","request":n,"template":id,"command":"docker exec -it web sh","label":"..."}`:
//!   open a terminal tab on the entry running the command in a PTY.
//!
//! The app answers `{"type":"exec","request":n,"exit":0,"stdout":"...","stderr":"...","error":null}`
//! for `exec-go` (`exit` null when the command did not finish, `error` the app's own words when
//! it could not run it), and `{"type":"exec","request":n,"opened":true}` for `exec-terminal`.
//! The app never runs anything but the command the core sent, on the entry the view is bound to.
//!
//! A template with `changes = true` first goes to the user as the core's own `confirm` update
//! (`"source":"core"`), showing the entry and the exact command line the core built. Only the
//! user's yes to that confirmation lets it run; the plugin's own `ui.confirm` text never does
//! (security review, HIGH 1).

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use serde_json::{json, Value as Json};

use super::*;
use crate::audit::Outcome;
use crate::plugin::broker::exec::{self as rules, ExecSpec};
use crate::plugin::broker::open::MAX_LABEL_CHARS;

/// One command the app is running for the plugin.
struct Running {
    template: String,
    args: Vec<(String, String)>,
    interactive: bool,
    deadline: Option<Instant>,
    /// Set by a cancel or a timeout: the plugin has its reply, but the command keeps its slot
    /// until the app answers or the grace time passes, so cancel-and-rerun cannot open more than
    /// `MAX_RUNNING` SSH sessions (security review, MEDIUM 5).
    ended_at: Option<Instant>,
}

/// A change waiting for the user's answer to the core's confirmation.
struct Pending {
    template: rules::Template,
    command: String,
    args: Vec<(String, String)>,
    timeout: Duration,
    label: String,
}

/// How long a cancelled or timed-out command keeps its slot while the app stops it.
const CANCEL_GRACE: Duration = Duration::from_secs(10);
/// Changes waiting for the user at once.
const MAX_PENDING: usize = 2;
/// Denied-call audits: at most one a second.
const DENIED_AUDIT_EVERY: Duration = Duration::from_secs(1);

/// The exec state of one helper.
#[derive(Default)]
pub(super) struct ExecState {
    pub(super) spec: Option<ExecSpec>,
    running: BTreeMap<u32, Running>,
    pending: BTreeMap<u32, Pending>,
    times: VecDeque<Instant>,
    denied_at: Option<Instant>,
}

impl ExecState {
    pub(super) fn new(spec: Option<ExecSpec>) -> ExecState {
        ExecState { spec, ..ExecState::default() }
    }

    fn admit(&mut self, now: Instant) -> bool {
        while self.times.front().is_some_and(|t| now.duration_since(*t).as_secs() >= 60) {
            self.times.pop_front();
        }
        if self.times.len() >= rules::MAX_PER_MINUTE {
            return false;
        }
        self.times.push_back(now);
        true
    }

    /// Whether `request` is a change waiting for the core's confirmation.
    pub(super) fn waits_for(&self, request: u32) -> bool {
        self.pending.contains_key(&request)
    }
}

/// The app's answer to `exec-go` or `exec-terminal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecAnswer {
    pub request: u32,
    pub exit: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub error: Option<String>,
    pub opened: Option<bool>,
}

pub(super) fn answer_from_json(j: &Json) -> Result<AppEvent, Failure> {
    let request = u32_of(j, "request")?;
    // Cut before copying: the app's string is held at most once more, at the cap.
    let text = |k: &str| j.get(k).and_then(Json::as_str).map(|s| s.as_bytes()[..s.len().min(rules::MAX_OUTPUT_BYTES + 1)].to_vec()).unwrap_or_default();
    let exit = match j.get("exit") {
        None | Some(Json::Null) => None,
        Some(v) => Some(v.as_i64().and_then(|n| i32::try_from(n).ok()).ok_or_else(|| invalid("`exit` is not a number"))?),
    };
    let error = j.get("error").and_then(Json::as_str).map(|s| s.chars().filter(|c| !c.is_control()).take(300).collect());
    let opened = j.get("opened").and_then(Json::as_bool);
    Ok(AppEvent::ExecAnswer(ExecAnswer { request, exit, stdout: text("stdout"), stderr: text("stderr"), error, opened }))
}

/// The plugin's `(template, args)`.
fn args_of(args: &[Value]) -> Result<(String, Vec<(String, String)>), Failure> {
    let template = as_str(args.first()).ok_or_else(|| invalid("an exec call without a template"))?.to_string();
    let Some(Value::List(items)) = args.get(1) else { return Err(invalid("an exec call without arguments")) };
    if items.len() > rules::MAX_ARGV {
        return Err(invalid("too many arguments"));
    }
    let mut out = Vec::new();
    for item in items {
        let Value::Tuple(kv) = item else { return Err(invalid("an argument is not a pair")) };
        match (kv.first(), kv.get(1)) {
            (Some(Value::String(k)), Some(Value::String(v))) => out.push((k.clone(), v.clone())),
            _ => return Err(invalid("an argument is not a pair of strings")),
        }
    }
    Ok((template, out))
}

type Checked = (rules::Template, String, Vec<(String, String)>);

impl Dispatch {
    fn audit_exec(&self, template: &str, args: &[(String, String)], outcome: Outcome, detail: (&str, String)) {
        let entry = self.entry.as_ref().map(|e| e.entry_id.as_str());
        audit_now(&self.data_dir, &plugin_audit::exec(self.grants.plugin_id(), self.grants.plugin_version(), entry, template, args, outcome, detail));
    }

    /// A refusal: the template id only when the manifest declares it, and never the plugin's
    /// argument values; at most one record a second (security review, LOW 6).
    fn audit_exec_denied(&mut self, template: &str, step: &str) {
        let now = Instant::now();
        if self.exec.denied_at.is_some_and(|t| now.duration_since(t) < DENIED_AUDIT_EVERY) {
            return;
        }
        self.exec.denied_at = Some(now);
        let known = self.exec.spec.as_ref().is_some_and(|s| s.get(template).is_some());
        self.audit_exec(if known { template } else { "?" }, &[], Outcome::Denied, ("step", step.into()));
    }

    fn slots_used(&self) -> usize {
        self.exec.running.values().filter(|r| !r.interactive).count() + self.exec.pending.len()
    }

    /// The checks every exec call makes, in order: rate, grant, entry, policy, template, the
    /// interactive flag, arguments, and for a change the entry's "Allow changes". Returns the
    /// template, the command line and the checked arguments.
    fn exec_checks(&mut self, args: &[Value], interactive: bool) -> Result<Checked, (Failure, &'static str, String)> {
        if !self.exec.admit(Instant::now()) {
            return Err((Failure::Denied(format!("rate-limited: at most {} commands a minute", rules::MAX_PER_MINUTE)), "rate", String::new()));
        }
        let (template_id, given) = args_of(args).map_err(|f| (f, "args", String::new()))?;
        let fail = |f: Failure, step: &'static str| (f, step, template_id.clone());
        self.grants.check(Call::Exec).map_err(|f| fail(f, "grant"))?;
        let entry = self.entry.as_ref().ok_or_else(|| fail(Failure::Denied("this view is not opened on an entry".into()), "grant"))?;
        if self.policy.plugin_exec_disabled {
            return Err(fail(Failure::Denied("policy does not let plugins run commands".into()), "policy"));
        }
        let template = self.exec.spec.as_ref().and_then(|s| s.get(&template_id)).cloned().ok_or_else(|| fail(Failure::Denied("the manifest declares no such command".into()), "template"))?;
        if template.interactive != interactive {
            let why = if interactive { "the command is not an interactive one" } else { "an interactive command opens only in a terminal" };
            return Err(fail(Failure::Invalid(why.into()), "template"));
        }
        let argv = template.build(&given).map_err(|f| fail(f, "args"))?;
        if template.changes && !rules::changes_allowed(&entry.fields) {
            return Err(fail(Failure::Denied("turn on Allow changes in the entry's properties first".into()), "changes"));
        }
        if !interactive && self.slots_used() >= rules::MAX_RUNNING {
            return Err(fail(Failure::Denied(format!("busy: at most {} commands at once", rules::MAX_RUNNING)), "busy"));
        }
        Ok((template, rules::command_line(&argv), given))
    }

    fn exec_call(&mut self, request: u32, args: &[Value], interactive: bool) -> Result<(), Failure> {
        let timeout = if interactive { Duration::ZERO } else { rules::timeout_of(as_u32(args.get(2))) };
        let label: String = if interactive { as_str(args.get(2)).unwrap_or_default().chars().filter(|c| !c.is_control()).take(MAX_LABEL_CHARS).collect() } else { String::new() };
        let (template, command, given) = match self.exec_checks(args, interactive) {
            Ok(v) => v,
            Err((f, step, template)) => {
                self.audit_exec_denied(&template, step);
                return Err(f);
            }
        };
        let p = Pending { template, command, args: given, timeout, label };
        if p.template.changes {
            return self.ask_core_confirm(request, p);
        }
        self.start(request, p);
        Ok(())
    }

    /// `exec.run(template, args, timeout-ms)`.
    pub(super) fn exec_run(&mut self, request: u32, args: &[Value]) -> Result<(), Failure> {
        self.exec_call(request, args, false)
    }

    /// `exec.terminal(template, args, label)`: a terminal tab on the entry.
    pub(super) fn exec_terminal(&mut self, request: u32, args: &[Value]) -> Result<(), Failure> {
        self.exec_call(request, args, true)
    }

    /// The core's own confirmation for a change: the entry and the exact command line, in the
    /// core's words. The plugin writes none of it.
    fn ask_core_confirm(&mut self, request: u32, p: Pending) -> Result<(), Failure> {
        if self.exec.pending.len() >= MAX_PENDING {
            self.audit_exec_denied(&p.template.id, "busy");
            return Err(Failure::Denied("busy: a change is already waiting for the user".into()));
        }
        let entry = self.entry.as_ref().map(|e| json!({ "name": e.name, "environment": e.environment }));
        let host = self.entry.as_ref().map(|e| e.host.clone()).unwrap_or_default();
        let what = if p.template.interactive { "Open a terminal on" } else { "Run on" };
        let text = format!("{what} {host}:\n{}", p.command);
        self.push("confirm", json!({ "request": request, "kind": "other", "text": text, "cut": false, "entry": entry, "plugin": self.grants.plugin_id(), "source": "core" }));
        self.exec.pending.insert(request, p);
        Ok(())
    }

    /// The user's answer to the core's confirmation of a change.
    pub(super) fn exec_confirm_answer(&mut self, request: u32, confirmed: bool) {
        let Some(p) = self.exec.pending.remove(&request) else { return };
        if !confirmed {
            self.audit_exec(&p.template.id, &p.args, Outcome::Denied, ("step", "declined".into()));
            self.reply_later(request, Err(Failure::Denied("the user declined".into())));
            return;
        }
        self.audit_exec(&p.template.id, &p.args, Outcome::Success, ("state", if p.template.interactive { "terminal" } else { "started" }.into()));
        self.start(request, p);
    }

    fn start(&mut self, request: u32, p: Pending) {
        let interactive = p.template.interactive;
        let deadline = (!interactive).then(|| Instant::now() + p.timeout);
        self.exec.running.insert(request, Running { template: p.template.id.clone(), args: p.args, interactive, deadline, ended_at: None });
        if interactive {
            self.push("exec-terminal", json!({ "request": request, "template": p.template.id, "command": p.command, "label": p.label }));
        } else {
            self.push(
                "exec-go",
                json!({ "request": request, "template": p.template.id, "command": p.command, "timeout_ms": p.timeout.as_millis() as u64, "max_bytes": rules::MAX_OUTPUT_BYTES }),
            );
        }
    }

    /// `exec.cancel(request)`: the plugin gets `invalid("cancelled")`; the slot stays taken until
    /// the app answers or the grace time passes.
    pub(super) fn exec_cancel(&mut self, request: u32) {
        if let Some(p) = self.exec.pending.remove(&request) {
            self.audit_exec(&p.template.id, &p.args, Outcome::Denied, ("step", "cancelled".into()));
            self.reply_later(request, Err(Failure::Invalid("cancelled".into())));
            return;
        }
        let Some(r) = self.exec.running.get_mut(&request) else { return };
        if r.interactive || r.ended_at.is_some() {
            return;
        }
        r.ended_at = Some(Instant::now());
        self.push("exec-cancel", json!({ "request": request }));
        self.reply_later(request, Err(Failure::Invalid("cancelled".into())));
    }

    /// Commands past their time get `timed-out` and are stopped in the app; ended commands the
    /// app never answered free their slot after the grace time.
    pub(super) fn exec_expire(&mut self) {
        let now = Instant::now();
        let late: Vec<u32> = self.exec.running.iter().filter(|(_, r)| r.ended_at.is_none() && r.deadline.is_some_and(|d| now >= d)).map(|(k, _)| *k).collect();
        for request in late {
            let Some(r) = self.exec.running.get_mut(&request) else { continue };
            r.ended_at = Some(now);
            let (template, args) = (r.template.clone(), r.args.clone());
            self.push("exec-cancel", json!({ "request": request }));
            self.audit_exec(&template, &args, Outcome::Failure, ("state", "timed-out".into()));
            self.reply_later(request, Err(Failure::TimedOut));
        }
        self.exec.running.retain(|_, r| r.ended_at.is_none_or(|t| now.duration_since(t) < CANCEL_GRACE));
    }

    /// The app's answer. One for a command already cancelled or timed out frees its slot and is
    /// dropped; one the core is not waiting for is dropped.
    pub(super) fn exec_answer(&mut self, a: ExecAnswer) {
        let Some(r) = self.exec.running.remove(&a.request) else { return };
        if r.ended_at.is_some() {
            return;
        }
        if r.interactive {
            let opened = a.opened.unwrap_or(false) && a.error.is_none();
            self.reply_later(a.request, Ok(variant("connection", Value::Bool(opened))));
            return;
        }
        if let Some(e) = a.error {
            self.audit_exec(&r.template, &r.args, Outcome::Failure, ("error", e.clone()));
            self.reply_later(a.request, Err(Failure::Io(e)));
            return;
        }
        let (stdout, cut_out) = rules::cap_output(a.stdout);
        let (stderr, cut_err) = rules::cap_output(a.stderr);
        let exit = a.exit;
        if self.exec.spec.as_ref().and_then(|s| s.get(&r.template)).is_some_and(|t| t.changes) {
            self.audit_exec(&r.template, &r.args, Outcome::Success, ("exit", exit.map_or("none".into(), |e| e.to_string())));
        }
        let out = record(vec![
            ("exit", Value::Option(exit.map(|e| Box::new(Value::S32(e))))),
            ("stdout", Value::Bytes(stdout)),
            ("stderr", Value::Bytes(stderr)),
            ("truncated", Value::Bool(cut_out || cut_err)),
        ]);
        self.reply_later(a.request, Ok(variant("exec", out)));
    }

    /// On stop: every running command is cancelled in the app.
    pub(super) fn exec_stop_all(&mut self) {
        self.exec.pending.clear();
        let all: Vec<u32> = self.exec.running.iter().filter(|(_, r)| !r.interactive && r.ended_at.is_none()).map(|(k, _)| *k).collect();
        self.exec.running.clear();
        for request in all {
            self.push("exec-cancel", json!({ "request": request }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_apps_answer_is_read_strictly() {
        let AppEvent::ExecAnswer(a) = answer_from_json(&json!({"type":"exec","request":3,"exit":1,"stdout":"{}","stderr":"no"})).unwrap() else { panic!() };
        assert_eq!((a.request, a.exit, a.stdout.as_slice(), a.error), (3, Some(1), b"{}".as_slice(), None));
        assert!(answer_from_json(&json!({"type":"exec","request":3,"exit":"1"})).is_err());
        assert!(answer_from_json(&json!({"type":"exec"})).is_err());
        let AppEvent::ExecAnswer(a) = answer_from_json(&json!({"type":"exec","request":4,"exit":null,"error":"permission\ndenied"})).unwrap() else { panic!() };
        assert_eq!(a.error.as_deref(), Some("permissiondenied"), "no control characters");
    }

    #[test]
    fn arguments_are_pairs_of_strings() {
        let pair = |k: &str, v: &str| Value::Tuple(vec![Value::String(k.into()), Value::String(v.into())]);
        let (t, a) = args_of(&[Value::String("logs".into()), Value::List(vec![pair("id", "web")])]).unwrap();
        assert_eq!((t.as_str(), a), ("logs", vec![("id".to_string(), "web".to_string())]));
        assert!(args_of(&[Value::String("logs".into())]).is_err());
        assert!(args_of(&[Value::String("logs".into()), Value::List(vec![Value::String("id=web".into())])]).is_err());
    }
}
