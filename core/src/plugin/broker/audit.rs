//! The `Category::Plugin` audit events the broker's decisions produce (T18.26).
//!
//! Each builder returns the action, the target and the details for
//! [`crate::audit::AuditLog::record`]. Details never hold a secret, a statement's text or
//! another entry's name. Writing them is PLUG-02b's.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::audit::{Category, Outcome};

use super::StopReason;

/// One audit record, ready for `AuditLog::record`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginAudit {
    pub category: Category,
    pub action: &'static str,
    pub target: Option<String>,
    pub outcome: Outcome,
    pub details: BTreeMap<String, String>,
}

fn base(action: &'static str, plugin_id: &str, version: &str, entry_id: Option<&str>, outcome: Outcome) -> PluginAudit {
    let mut details = BTreeMap::new();
    details.insert("plugin".into(), plugin_id.to_string());
    details.insert("plugin_version".into(), version.to_string());
    PluginAudit { category: Category::Plugin, action, target: entry_id.map(str::to_string), outcome, details }
}

/// `credential.release.plugin`: the entry's own login was released (or refused) to a helper.
/// The record names the plugin and the entry, never the login's user or password.
pub fn credential_release(plugin_id: &str, version: &str, entry_id: &str, outcome: Outcome) -> PluginAudit {
    let mut a = base("credential.release.plugin", plugin_id, version, Some(entry_id), outcome);
    a.category = Category::CredentialAccess;
    a
}

/// `plugin.helper.stop`: a helper was killed for a protocol violation, a missing sandbox, or
/// stopped for any other reason that withdraws trust.
pub fn helper_stopped(plugin_id: &str, version: &str, entry_id: Option<&str>, reason: StopReason, detail: &str) -> PluginAudit {
    let mut a = base("plugin.helper.stop", plugin_id, version, entry_id, if reason.withdraws_trust() { Outcome::Denied } else { Outcome::Success });
    a.details.insert("reason".into(), reason.as_str().into());
    a.details.insert("detail".into(), detail.chars().take(200).collect());
    a
}

/// `plugin.http.connect`: the core opened a connection for a plugin's `http.send` (API 1.1).
pub fn http_connect(plugin_id: &str, version: &str, entry_id: &str, port: u16, route: &str, tls_mode: &str) -> PluginAudit {
    let mut a = base("plugin.http.connect", plugin_id, version, Some(entry_id), Outcome::Success);
    a.details.insert("port".into(), port.to_string());
    a.details.insert("route".into(), route.into());
    a.details.insert("tls_mode".into(), tls_mode.into());
    a
}

/// `plugin.http.change`: a request whose method can change the server. The path is recorded
/// without its query string, which may hold data.
pub fn http_change(plugin_id: &str, version: &str, entry_id: &str, method: &str, path: &str, status: Option<u16>, with_login: bool) -> PluginAudit {
    let outcome = match status {
        Some(s) if (200..400).contains(&s) => Outcome::Success,
        _ => Outcome::Failure,
    };
    let mut a = base("plugin.http.change", plugin_id, version, Some(entry_id), outcome);
    a.details.insert("method".into(), method.into());
    a.details.insert("path".into(), path.chars().take(256).collect());
    a.details.insert("status".into(), status.map_or_else(|| "none".into(), |s| s.to_string()));
    a.details.insert("login".into(), with_login.to_string());
    a
}

/// `plugin.http.denied`: the core refused a plugin's request (no grant, method, port, path,
/// the secret check, or a response that echoed the login). `step` names which.
pub fn http_denied(plugin_id: &str, version: &str, entry_id: Option<&str>, step: &str) -> PluginAudit {
    let mut a = base("plugin.http.denied", plugin_id, version, entry_id, Outcome::Denied);
    a.details.insert("step".into(), step.into());
    a
}

/// `plugin.cache.mismatch`: stored compiled code did not match the recorded hash.
pub fn cache_mismatch(plugin_id: &str, version: &str, component_sha256: &str) -> PluginAudit {
    let mut a = base("plugin.cache.mismatch", plugin_id, version, None, Outcome::Failure);
    a.details.insert("component_sha256".into(), component_sha256.to_string());
    a
}

/// `plugin.abort.sent`: abort bytes went out after an ordinary stop.
pub fn abort_sent(plugin_id: &str, version: &str, entry_id: &str, reason: StopReason, bytes: usize) -> PluginAudit {
    let mut a = base("plugin.abort.sent", plugin_id, version, Some(entry_id), Outcome::Success);
    a.details.insert("reason".into(), reason.as_str().into());
    a.details.insert("bytes".into(), bytes.to_string());
    a
}

/// The kind of risky action a plugin asks the core to confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmKind {
    Drop,
    Truncate,
    EndSession,
    RunStatements,
    Other,
}

impl ConfirmKind {
    fn as_str(self) -> &'static str {
        match self {
            ConfirmKind::Drop => "drop",
            ConfirmKind::Truncate => "truncate",
            ConfirmKind::EndSession => "end-session",
            ConfirmKind::RunStatements => "run-statements",
            ConfirmKind::Other => "other",
        }
    }
}

/// The most plugin text a core prompt shows (C11); the rest scrolls out of reach and the core
/// says the text was cut.
pub const MAX_PROMPT_TEXT_BYTES: usize = 64 * 1024;

/// `plugin.confirm`: the user's answer to a core-drawn confirmation. Holds a SHA-256 of the
/// whole text the plugin sent (not the text, which can hold customer data) and whether the
/// shown text was cut.
#[allow(clippy::too_many_arguments)]
pub fn confirm(plugin_id: &str, version: &str, entry_id: &str, environment: &str, kind: ConfirmKind, confirmed: bool, plugin_text: &str) -> PluginAudit {
    let mut a = base("plugin.confirm", plugin_id, version, Some(entry_id), if confirmed { Outcome::Success } else { Outcome::Denied });
    a.details.insert("environment".into(), environment.to_string());
    a.details.insert("kind".into(), kind.as_str().into());
    a.details.insert("answer".into(), if confirmed { "confirmed" } else { "cancelled" }.into());
    a.details.insert("text_sha256".into(), hex::encode(Sha256::digest(plugin_text.as_bytes())));
    a.details.insert("text_cut".into(), (plugin_text.len() > MAX_PROMPT_TEXT_BYTES).to_string());
    a
}

/// The SHA-256 and the "cut" flag that [`confirm`] records for a prompt text. A pending
/// confirmation keeps only these, never the full text (SEC-4).
pub fn confirm_text_digest(plugin_text: &str) -> ([u8; 32], bool) {
    (Sha256::digest(plugin_text.as_bytes()).into(), plugin_text.len() > MAX_PROMPT_TEXT_BYTES)
}

/// [`confirm`] from a digest kept by [`confirm_text_digest`]; the record is identical.
#[allow(clippy::too_many_arguments)]
pub fn confirm_from_digest(plugin_id: &str, version: &str, entry_id: &str, environment: &str, kind: ConfirmKind, confirmed: bool, text_sha256: &[u8; 32], text_cut: bool) -> PluginAudit {
    let mut a = base("plugin.confirm", plugin_id, version, Some(entry_id), if confirmed { Outcome::Success } else { Outcome::Denied });
    a.details.insert("environment".into(), environment.to_string());
    a.details.insert("kind".into(), kind.as_str().into());
    a.details.insert("answer".into(), if confirmed { "confirmed" } else { "cancelled" }.into());
    a.details.insert("text_sha256".into(), hex::encode(text_sha256));
    a.details.insert("text_cut".into(), text_cut.to_string());
    a
}

/// The fields every `plugin.open.*` record carries about the request. Values from the plugin
/// are escaped and cut ([`super::open::audit_escape`]) before they reach the log.
#[derive(Debug, Clone)]
pub struct OpenAuditRequest<'a> {
    pub protocol: &'a str,
    pub host: &'a str,
    pub port: Option<u16>,
    pub reported: Option<bool>,
}

fn open_base(action: &'static str, plugin_id: &str, version: &str, entry_id: Option<&str>, outcome: Outcome, r: &OpenAuditRequest<'_>) -> PluginAudit {
    let mut a = base(action, plugin_id, version, entry_id, outcome);
    a.details.insert("protocol".into(), super::open::audit_escape(r.protocol));
    a.details.insert("host".into(), super::open::audit_escape(r.host));
    if let Some(p) = r.port {
        a.details.insert("port".into(), p.to_string());
    }
    if let Some(rep) = r.reported {
        a.details.insert("reported".into(), rep.to_string());
    }
    a
}

/// `plugin.open.request`: a request that reached the sheet (API 1.2).
pub fn open_request(plugin_id: &str, version: &str, entry_id: &str, request: u32, r: &OpenAuditRequest<'_>) -> PluginAudit {
    let mut a = open_base("plugin.open.request", plugin_id, version, Some(entry_id), Outcome::Success, r);
    a.details.insert("request".into(), request.to_string());
    a
}

/// `plugin.open.answer`: the user's answer. Names whether a saved credential was chosen, never
/// which one.
#[allow(clippy::too_many_arguments)]
pub fn open_answer(plugin_id: &str, version: &str, entry_id: &str, request: u32, r: &OpenAuditRequest<'_>, opened: bool, route: &str, credential_chosen: bool, saved_as_entry: bool) -> PluginAudit {
    let mut a = open_base("plugin.open.answer", plugin_id, version, Some(entry_id), if opened { Outcome::Success } else { Outcome::Denied }, r);
    a.details.insert("request".into(), request.to_string());
    a.details.insert("answer".into(), if opened { "opened" } else { "declined" }.into());
    a.details.insert("route".into(), route.into());
    a.details.insert("credential_chosen".into(), credential_chosen.to_string());
    a.details.insert("saved_as_entry".into(), saved_as_entry.to_string());
    a
}

/// `plugin.library.request`: a `library.propose` that reached the sheet (API 1.6). Names how
/// many proposals and the protocols, never the hosts or labels (they go to the library only if
/// the user saves them, and the library's own audit records those).
pub fn library_request(plugin_id: &str, version: &str, entry_id: &str, request: u32, count: usize, protocols: &str) -> PluginAudit {
    let mut a = base("plugin.library.request", plugin_id, version, Some(entry_id), Outcome::Success);
    a.details.insert("request".into(), request.to_string());
    a.details.insert("count".into(), count.to_string());
    a.details.insert("protocols".into(), protocols.into());
    a
}

/// `plugin.library.answer`: the user's answer. Names how many connections were saved and
/// whether a saved credential was linked, never which one.
pub fn library_answer(plugin_id: &str, version: &str, entry_id: &str, request: u32, saved: Option<u32>, credential_linked: bool) -> PluginAudit {
    let mut a = base("plugin.library.answer", plugin_id, version, Some(entry_id), if saved.is_some() { Outcome::Success } else { Outcome::Denied });
    a.details.insert("request".into(), request.to_string());
    a.details.insert("answer".into(), if saved.is_some() { "saved" } else { "cancelled" }.into());
    a.details.insert("saved".into(), saved.unwrap_or(0).to_string());
    a.details.insert("credential_linked".into(), credential_linked.to_string());
    a
}

/// `plugin.library.denied`: a proposal the core refused, with the rule that refused it.
pub fn library_denied(plugin_id: &str, version: &str, entry_id: Option<&str>, step: &str) -> PluginAudit {
    let mut a = base("plugin.library.denied", plugin_id, version, entry_id, Outcome::Denied);
    a.details.insert("step".into(), step.into());
    a
}

/// `plugin.open.denied`: a request the core refused, with the rule (note section 4) or step
/// (section 5) that refused it.
pub fn open_denied(plugin_id: &str, version: &str, entry_id: Option<&str>, step: &str, r: &OpenAuditRequest<'_>) -> PluginAudit {
    let mut a = open_base("plugin.open.denied", plugin_id, version, entry_id, Outcome::Denied, r);
    a.details.insert("step".into(), step.into());
    a
}

/// `plugin.exec`: a declared command (API 1.5) was refused, started, finished or timed out.
/// Records the template and its typed arguments (ids and counts only, by the kinds' patterns),
/// and the exit status; never the output.
pub fn exec(plugin_id: &str, version: &str, entry_id: Option<&str>, template: &str, args: &[(String, String)], outcome: Outcome, detail: (&str, String)) -> PluginAudit {
    let mut a = base("plugin.exec", plugin_id, version, entry_id, outcome);
    let clip = |s: &str| -> String { s.chars().filter(|c| !c.is_control()).take(128).collect() };
    a.details.insert("template".into(), clip(template));
    for (k, v) in args.iter().take(super::exec::MAX_ARGV) {
        a.details.insert(format!("arg.{}", clip(k)), clip(v));
    }
    a.details.insert(detail.0.into(), clip(&detail.1));
    a
}
