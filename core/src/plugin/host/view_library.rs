//! `library.propose` (plugin API 1.6; `docs/specs/plugins-amendment-5.md`): the plugin proposes
//! connections, the core checks them, the app shows the core's sheet, and on the user's yes the
//! app saves normal library connections. The plugin learns only how many were saved.
//!
//! Update to the app:
//! - `{"type":"library-propose","request":n,"plugin":id,"entry":{"id","name"},"items":[{"label",
//!   "host":string|null,"reported":bool,"protocol":"ssh"|"rdp"|"vnc","port","os_hint":string|null}]}`
//!   shows the sheet. `host` is canonical; `label` is text from the plugin.
//!
//! The app answers `{"type":"library","request":n,"saved":k|null,"credential_linked":bool}`:
//! `saved` null when the user cancelled, else how many connections it saved.

use std::time::Instant;

use serde_json::json;

use super::{audit_now, field, record, variant, AppEvent, Dispatch};
use crate::plugin::broker::audit as plugin_audit;
use crate::plugin::broker::grants::Call;
use crate::plugin::broker::open::{check_class, check_label, parse_host, Protocol, Rate, RouteChoice};
use crate::plugin::broker::Failure;
use crate::plugin::host::proto::Value;

/// Proposals in one call.
pub const MAX_PROPOSALS: usize = 100;
/// The operating system hints the sheet knows.
pub const OS_HINTS: [&str; 5] = ["windows", "linux", "bsd", "macos", "other"];
/// Denied-request audits per helper: at most one a second.
const DENIED_AUDIT_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

/// The library state of one helper.
#[derive(Default)]
pub(super) struct LibraryState {
    rate: Rate,
    pending: Option<u32>,
    denied_at: Option<Instant>,
}

/// One proposal after the checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub label: String,
    pub host: Option<String>,
    pub reported: bool,
    pub protocol: Protocol,
    pub os_hint: Option<String>,
}

/// One proposal as the plugin sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawProposal {
    pub label: String,
    pub host: Option<String>,
    pub protocol: String,
    pub os_hint: Option<String>,
}

fn bad(what: &str) -> Failure {
    Failure::Invalid(format!("a proposal {what}"))
}

fn opt_string(v: Option<&Value>, name: &str) -> Result<Option<String>, Failure> {
    match v {
        Some(Value::Option(None)) => Ok(None),
        Some(Value::Option(Some(s))) => match &**s {
            Value::String(s) => Ok(Some(s.clone())),
            _ => Err(bad(&format!("{name} is not text"))),
        },
        _ => Err(bad(&format!("has no {name}"))),
    }
}

pub(super) fn raw_of(args: &[Value]) -> Result<Vec<RawProposal>, Failure> {
    let Some(Value::List(items)) = args.first() else { return Err(Failure::Invalid("the proposals are missing".into())) };
    if items.is_empty() || items.len() > MAX_PROPOSALS {
        return Err(Failure::Invalid(format!("between 1 and {MAX_PROPOSALS} proposals at a time")));
    }
    items
        .iter()
        .map(|r| {
            let label = match field(r, "label") {
                Some(Value::String(s)) => s.clone(),
                _ => return Err(bad("has no label")),
            };
            let protocol = match field(r, "protocol") {
                Some(Value::Enum(p)) => p.clone(),
                _ => return Err(bad("has no protocol")),
            };
            Ok(RawProposal { label, host: opt_string(field(r, "host"), "host")?, protocol, os_hint: opt_string(field(r, "os-hint"), "os-hint")? })
        })
        .collect()
}

/// The checks of one proposal: label, protocol, host syntax and class, OS hint. The library
/// entry is saved on the plugin entry's own route rules, so loopback is refused outright: a
/// saved connection to `localhost` would point at the user's own machine.
pub fn check(raw: &RawProposal, mut reported: impl FnMut(&crate::plugin::broker::open::Host) -> bool) -> Result<Checked, Failure> {
    check_label(&raw.label)?;
    let protocol = Protocol::parse(&raw.protocol).ok_or_else(|| Failure::Denied("the protocol is not ssh, rdp or vnc".into()))?;
    let (host, was_reported) = match &raw.host {
        None => (None, false),
        Some(h) => {
            let parsed = parse_host(h)?;
            let no_loopback = crate::plugin::broker::open::LoopbackRule { entry_target_loopback: false, entry_direct: false };
            check_class(&parsed, RouteChoice::Entry, false, &no_loopback)?;
            let r = reported(&parsed);
            (Some(parsed.canonical()), r)
        }
    };
    let os_hint = match &raw.os_hint {
        None => None,
        Some(o) if OS_HINTS.contains(&o.as_str()) => Some(o.clone()),
        Some(_) => return Err(Failure::Invalid(format!("os-hint is one of {}", OS_HINTS.join(", ")))),
    };
    Ok(Checked { label: raw.label.clone(), host, reported: was_reported, protocol, os_hint })
}

/// The app's answer to the sheet.
pub(super) fn answer_from_json(j: &serde_json::Value) -> Result<AppEvent, Failure> {
    let request = j.get("request").and_then(serde_json::Value::as_u64).and_then(|r| u32::try_from(r).ok()).ok_or_else(|| Failure::Invalid("`request` is missing".into()))?;
    let saved = match j.get("saved") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(v.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(|| Failure::Invalid("`saved` is a count".into()))?),
    };
    let credential_linked = j.get("credential_linked").and_then(serde_json::Value::as_bool).unwrap_or(false);
    Ok(AppEvent::LibraryAnswer { request, saved, credential_linked })
}

impl Dispatch {
    fn audit_library_denied(&mut self, step: &str) {
        let now = Instant::now();
        if self.library.denied_at.is_some_and(|t| now.duration_since(t) < DENIED_AUDIT_EVERY) {
            return;
        }
        self.library.denied_at = Some(now);
        audit_now(&self.data_dir, &plugin_audit::library_denied(self.grants.plugin_id(), self.grants.plugin_version(), self.grants.entry_id(), step));
    }

    /// `library.propose`. On `Ok` the sheet is up and the reply waits for the user; on `Err`
    /// the refusal is audited and the caller replies with it.
    pub(super) fn library_propose(&mut self, request: u32, args: &[Value]) -> Result<(), Failure> {
        match self.library_checks(request, args, Instant::now()) {
            Ok(()) => Ok(()),
            Err((f, step)) => {
                self.audit_library_denied(step);
                Err(f)
            }
        }
    }

    fn library_checks(&mut self, request: u32, args: &[Value], now: Instant) -> Result<(), (Failure, &'static str)> {
        if !self.library.rate.admit(now) {
            return Err((Failure::Denied("rate-limited: at most 10 library proposals a minute".into()), "rate"));
        }
        self.grants.check(Call::LibraryPropose).map_err(|f| (f, "grant"))?;
        if self.policy.plugin_open_disabled {
            return Err((Failure::Denied("policy does not let plugins propose connections".into()), "policy"));
        }
        // The same user-action stamp as `open.connection`: one request per user action.
        if !self.open.stamp.take(now) {
            return Err((Failure::Denied("not-now: a plugin may ask only right after a user action".into()), "stamp"));
        }
        if self.library.pending.is_some() {
            return Err((Failure::Denied("busy: a library sheet is already waiting for the user".into()), "busy"));
        }
        let raws = raw_of(args).map_err(|f| (f, "syntax"))?;
        let mut items = Vec::with_capacity(raws.len());
        for raw in &raws {
            let reported = |h: &crate::plugin::broker::open::Host| self.open.reported.contains(h, now);
            items.push(check(raw, reported).map_err(|f| (f, "check"))?);
        }
        let entry = self.entry.as_ref().ok_or((Failure::Denied("this view is not opened on an entry".into()), "grant"))?;
        let json_items: Vec<_> = items
            .iter()
            .map(|c| json!({ "label": c.label, "host": c.host, "reported": c.reported, "protocol": c.protocol.as_str(), "port": c.protocol.default_port(), "os_hint": c.os_hint }))
            .collect();
        let mut protocols: Vec<&str> = items.iter().map(|c| c.protocol.as_str()).collect();
        protocols.sort_unstable();
        protocols.dedup();
        let entry_id = entry.entry_id.clone();
        self.push("library-propose", json!({ "request": request, "plugin": self.grants.plugin_id(), "entry": { "id": entry.entry_id, "name": entry.name }, "items": json_items }));
        audit_now(&self.data_dir, &plugin_audit::library_request(self.grants.plugin_id(), self.grants.plugin_version(), &entry_id, request, items.len(), &protocols.join(",")));
        self.library.pending = Some(request);
        Ok(())
    }

    /// The user's answer. An answer to a request the core did not ask, or asked once already,
    /// is ignored. `saved` is capped at nothing: the app saves, the core only reports it.
    pub(super) fn library_answer(&mut self, request: u32, saved: Option<u32>, credential_linked: bool) {
        if self.library.pending != Some(request) {
            return;
        }
        self.library.pending = None;
        let entry_id = self.grants.entry_id().unwrap_or("").to_string();
        audit_now(&self.data_dir, &plugin_audit::library_answer(self.grants.plugin_id(), self.grants.plugin_version(), &entry_id, request, saved, credential_linked));
        match saved {
            Some(n) => self.reply_later(request, Ok(variant("created", Value::U32(n)))),
            None => {
                // The WIT `failure.cancelled`, as `files.save` sends it.
                let cancelled = Value::Result(Err(Some(Box::new(Value::Variant("cancelled".into(), None)))));
                self.replies.push_back((variant("reply", record(vec![("request", Value::U32(request)), ("outcome", cancelled)])), None));
            }
        }
    }
}

#[cfg(test)]
#[path = "view_library_tests.rs"]
mod tests;
