//! `open.connection` (plugin API 1.2; `docs/specs/plugins-amendment-3.md`): the plugin
//! proposes, the core checks (sections 4 and 5), the app shows the core's sheet (section 6),
//! and on the user's yes the app opens the connection through its own open path (section 7).
//!
//! Updates to the app:
//! - `{"type":"open-request","request":n,"plugin":id,"entry":{"id","name"},"protocol","host",
//!   "port","label","reported":bool,"route":"entry"|"direct","entry_route":"direct"|"tunnel"|…}`
//!   shows the sheet. `host` is canonical; `label` is text from the plugin.
//! - `{"type":"open-go","request":n,"protocol","host","port","label","route","check_resolved":bool,
//!   "loopback_ok":bool}` after the user's yes passed the checks: the app opens the connection.
//!   With `check_resolved` the app resolves the name and calls
//!   [`crate::plugin::broker::open::check_resolved`] on every address before connecting.
//! - `{"type":"open-refused","request":n,"reason"}` when a route change failed the checks.
//!
//! The app answers `{"type":"open","request":n,"accept":bool,"route":"entry"|"direct",
//! "credential_chosen":bool,"save_as_entry":bool}`.

use std::time::Instant;

use serde_json::json;

use super::{audit_now, field, variant, AppEvent, Dispatch};
use crate::plugin::broker::audit::{self as plugin_audit, OpenAuditRequest};
use crate::plugin::broker::grants::Call;
use crate::plugin::broker::open::{self as rules, check_class, check_label, parse_host, Host, LoopbackRule, OpenPolicy, OpenSpec, Protocol, Rate, ReportedSet, RouteChoice, Stamp};
use crate::plugin::broker::Failure;
use crate::plugin::host::proto::Value;
use crate::plugin::host::relay::EntryRoute;

/// Denied-request audits per helper: at most one a second (note section 8).
const DENIED_AUDIT_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

/// The open state of one helper.
#[derive(Default)]
pub(super) struct OpenState {
    pub(super) spec: Option<OpenSpec>,
    pub(super) reported: ReportedSet,
    pub(super) stamp: Stamp,
    rate: Rate,
    pending: Option<PendingOpen>,
    denied_at: Option<Instant>,
}

impl OpenState {
    pub(super) fn new(spec: Option<OpenSpec>) -> OpenState {
        OpenState { spec, ..OpenState::default() }
    }
}

struct PendingOpen {
    request: u32,
    protocol: Protocol,
    host: Host,
    port: u16,
    label: String,
    reported: bool,
    route: RouteChoice,
}

/// The parts of an `open-request` record, as the plugin sent them.
struct Raw {
    protocol: Option<String>,
    host: String,
    port: Option<u16>,
    label: String,
    via_entry_route: bool,
}

fn raw_of(args: &[Value]) -> Result<Raw, Failure> {
    let bad = |what: &str| Failure::Invalid(format!("an open request {what}"));
    let r = args.first().ok_or_else(|| bad("is missing"))?;
    let protocol = match field(r, "protocol") {
        Some(Value::Enum(p)) => Some(p.clone()),
        _ => return Err(bad("has no protocol")),
    };
    let text = |name: &str| match field(r, name) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(bad(&format!("has no {name}"))),
    };
    let port = match field(r, "port") {
        Some(Value::Option(None)) => None,
        Some(Value::Option(Some(p))) => match **p {
            Value::U16(p) => Some(p),
            _ => return Err(bad("port is not a number")),
        },
        _ => return Err(bad("port is not a number")),
    };
    let via_entry_route = match field(r, "via-entry-route") {
        Some(Value::Bool(b)) => *b,
        _ => return Err(bad("has no route choice")),
    };
    Ok(Raw { protocol, host: text("host")?, port, label: text("label")?, via_entry_route })
}

fn route_name(r: RouteChoice) -> &'static str {
    match r {
        RouteChoice::Entry => "entry",
        RouteChoice::Direct => "direct",
    }
}

/// A user action the core stamps (section 4): a command, or input in the plugin's view.
pub(super) fn is_user_action(event: &Value) -> bool {
    matches!(event, Value::Variant(name, _) if name == "command" || name == "ui")
}

/// The app's answer to the sheet.
pub(super) fn answer_from_json(j: &serde_json::Value) -> Result<AppEvent, Failure> {
    let request = j.get("request").and_then(serde_json::Value::as_u64).and_then(|r| u32::try_from(r).ok()).ok_or_else(|| Failure::Invalid("`request` is missing".into()))?;
    let accept = j.get("accept").and_then(serde_json::Value::as_bool).ok_or_else(|| Failure::Invalid("`accept` is missing".into()))?;
    let route = match j.get("route").and_then(serde_json::Value::as_str) {
        Some("entry") | None => RouteChoice::Entry,
        Some("direct") => RouteChoice::Direct,
        Some(_) => return Err(Failure::Invalid("`route` is entry or direct".into())),
    };
    let flag = |k: &str| j.get(k).and_then(serde_json::Value::as_bool).unwrap_or(false);
    Ok(AppEvent::OpenAnswer { request, accept, route, credential_chosen: flag("credential_chosen"), save_as_entry: flag("save_as_entry") })
}

impl Dispatch {
    fn loopback_rule(&self) -> LoopbackRule {
        match self.entry.as_ref() {
            None => LoopbackRule { entry_target_loopback: false, entry_direct: false },
            Some(e) => match &e.tls.route {
                EntryRoute::Direct => LoopbackRule { entry_target_loopback: rules::is_loopback_literal(&e.host), entry_direct: true },
                EntryRoute::Forward { target, .. } => LoopbackRule { entry_target_loopback: rules::is_loopback_literal(target), entry_direct: false },
                EntryRoute::Socks { .. } | EntryRoute::NotDirect => LoopbackRule { entry_target_loopback: false, entry_direct: false },
            },
        }
    }

    fn entry_direct(&self) -> bool {
        self.entry.as_ref().is_some_and(|e| e.tls.route == EntryRoute::Direct)
    }

    fn audit_open_denied(&mut self, step: &str, protocol: &str, host: &str, port: Option<u16>) {
        let now = Instant::now();
        if self.open.denied_at.is_some_and(|t| now.duration_since(t) < DENIED_AUDIT_EVERY) {
            return;
        }
        self.open.denied_at = Some(now);
        let r = OpenAuditRequest { protocol, host, port, reported: None };
        audit_now(&self.data_dir, &plugin_audit::open_denied(self.grants.plugin_id(), self.grants.plugin_version(), self.grants.entry_id(), step, &r));
    }

    /// `open.connection`: sections 4 and 5. On `Ok` the sheet is up and the reply waits for the
    /// user; on `Err` the refusal is audited and the caller replies with it.
    pub(super) fn open_connection(&mut self, request: u32, args: &[Value]) -> Result<(), Failure> {
        let now = Instant::now();
        let raw = raw_of(args);
        let (p, h, port) = match &raw {
            Ok(r) => (r.protocol.clone().unwrap_or_default(), r.host.clone(), r.port),
            Err(_) => (String::new(), String::new(), None),
        };
        match self.open_checks(request, raw, now) {
            Ok(()) => Ok(()),
            Err((f, step)) => {
                self.audit_open_denied(step, &p, &h, port);
                Err(f)
            }
        }
    }

    fn open_checks(&mut self, request: u32, raw: Result<Raw, Failure>, now: Instant) -> Result<(), (Failure, &'static str)> {
        // Section 4: the rate counts every request, refused ones included.
        if !self.open.rate.admit(now) {
            return Err((Failure::Denied("rate-limited: at most 10 open requests a minute".into()), "rate"));
        }
        // Step 1: grant, entry, policy.
        self.grants.check(Call::Open).map_err(|f| (f, "grant"))?;
        let policy = OpenPolicy::from_policy(&self.policy);
        if policy == OpenPolicy::Off {
            return Err((Failure::Denied("policy does not let plugins open connections".into()), "policy"));
        }
        // Section 4: a fresh user action, one request at a time.
        if !self.open.stamp.take(now) {
            return Err((Failure::Denied("not-now: a plugin may ask only right after a user action".into()), "stamp"));
        }
        if self.open.pending.is_some() {
            return Err((Failure::Denied("busy: an open request is already waiting for the user".into()), "busy"));
        }
        let raw = raw.map_err(|f| (f, "syntax"))?;
        let protocol = raw.protocol.as_deref().and_then(Protocol::parse).ok_or((Failure::Denied("the protocol is not one the plugin may open".into()), "grant"))?;
        if !self.grants.permissions().opens(protocol) {
            return Err((Failure::Denied(format!("the plugin may not open {}", protocol.as_str())), "grant"));
        }
        // Step 2: syntax.
        let host = parse_host(&raw.host).map_err(|f| (f, "syntax"))?;
        check_label(&raw.label).map_err(|f| (f, "syntax"))?;
        let port = raw.port.unwrap_or(protocol.default_port());
        if port == 0 {
            return Err((Failure::Denied("the port is 0".into()), "syntax"));
        }
        // Step 3: address class and the loopback exception.
        let route = if raw.via_entry_route { RouteChoice::Entry } else { RouteChoice::Direct };
        check_class(&host, route, false, &self.loopback_rule()).map_err(|f| (f, "class"))?;
        // Steps 4 and 5: reported, and the policy for not reported.
        let reported = self.open.reported.contains(&host, now);
        if !reported && policy == OpenPolicy::ReportedOnly {
            return Err((Failure::Denied("not-reported: policy allows only addresses the entry's server reported".into()), "reported"));
        }
        let entry = self.entry.as_ref().ok_or((Failure::Denied("this view is not opened on an entry".into()), "grant"))?;
        let canonical = host.canonical();
        self.push(
            "open-request",
            json!({
                "request": request, "plugin": self.grants.plugin_id(), "entry": { "id": entry.entry_id, "name": entry.name },
                "protocol": protocol.as_str(), "host": canonical, "port": port, "label": raw.label, "reported": reported,
                "route": route_name(route), "entry_route": entry.tls.route.audit_name(),
            }),
        );
        let r = OpenAuditRequest { protocol: protocol.as_str(), host: &canonical, port: Some(port), reported: Some(reported) };
        audit_now(&self.data_dir, &plugin_audit::open_request(self.grants.plugin_id(), self.grants.plugin_version(), &entry.entry_id, request, &r));
        self.open.pending = Some(PendingOpen { request, protocol, host, port, label: raw.label, reported, route });
        Ok(())
    }

    /// The user's answer. An answer to a request the core did not ask, or asked once already,
    /// is ignored. A route change runs step 3 again and refuses loopback.
    pub(super) fn open_answer(&mut self, request: u32, accept: bool, route: RouteChoice, credential_chosen: bool, save_as_entry: bool) {
        if self.open.pending.as_ref().map(|p| p.request) != Some(request) {
            return;
        }
        let Some(p) = self.open.pending.take() else { return };
        let canonical = p.host.canonical();
        let entry_id = self.grants.entry_id().unwrap_or("").to_string();
        let r = OpenAuditRequest { protocol: p.protocol.as_str(), host: &canonical, port: Some(p.port), reported: Some(p.reported) };
        let audit = |me: &Self, opened: bool, route: RouteChoice| {
            let a = plugin_audit::open_answer(me.grants.plugin_id(), me.grants.plugin_version(), &entry_id, request, &r, opened, route_name(route), credential_chosen, save_as_entry);
            audit_now(&me.data_dir, &a);
        };
        if !accept {
            audit(self, false, p.route);
            self.reply_later(request, Ok(variant("connection", Value::Bool(false))));
            return;
        }
        let changed = route != p.route;
        let rule = self.loopback_rule();
        if let Err(f) = check_class(&p.host, route, changed, &rule) {
            self.audit_open_denied("route", p.protocol.as_str(), &canonical, Some(p.port));
            self.push("open-refused", json!({ "request": request, "reason": f.to_string() }));
            self.reply_later(request, Err(f));
            return;
        }
        let loopback_ok = matches!(rules::class_of(&p.host), rules::Class::Loopback);
        let direct = route == RouteChoice::Direct || self.entry_direct();
        let check_resolved = direct && matches!(p.host, Host::Name(_));
        self.push(
            "open-go",
            json!({ "request": request, "protocol": p.protocol.as_str(), "host": canonical, "port": p.port, "label": p.label, "route": route_name(route), "check_resolved": check_resolved, "loopback_ok": loopback_ok }),
        );
        audit(self, true, route);
        self.reply_later(request, Ok(variant("connection", Value::Bool(true))));
    }
}
