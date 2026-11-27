//! What the core binds a plugin view to when it is opened on a library entry (PLUG-03b,
//! PLUG-PVE-01): the entry's address, its inherited settings, and its TLS settings.
//!
//! TLS settings are core-owned entry properties, never plugin fields: stored in the entry under
//! [`TLS_KEY`] as `{"mode": "verify-full" | "pinned", "pin_sha256": "<64 hex>"}`. Anything the
//! core cannot read there means verify-full with no pin, the safe default. TLS off is not offered
//! in this version.
//!
//! The route is direct only when no gateway applies to the entry (its own or a folder's): every
//! other route is refused by the relay in this build, so a gateway is reported, not ignored.
use serde_json::{json, Value};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::{Connection, Document, Folder, Node, Settings};
use crate::plugin::broker::stream::TlsMode;
use crate::plugin::host::relay::{EntryRoute, EntryTls};
use crate::properties::is_plugin_entry;

/// Where an entry keeps its TLS settings.
pub const TLS_KEY: &str = "plugin_tls";

/// A lowercase or uppercase 64-character hex SHA-256 of a DER certificate.
pub fn is_pin(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The entry's TLS mode and pin as stored; the safe default when absent or malformed.
pub fn entry_tls(c: &Connection) -> (TlsMode, Option<String>) {
    let stored = c.extra.get(TLS_KEY).and_then(Value::as_object);
    let pin = stored.and_then(|o| o.get("pin_sha256")).and_then(Value::as_str).filter(|p| is_pin(p)).map(str::to_ascii_lowercase);
    match (stored.and_then(|o| o.get("mode")).and_then(Value::as_str), pin) {
        (Some("pinned"), Some(pin)) => (TlsMode::Pinned, Some(pin)),
        _ => (TlsMode::VerifyFull, None),
    }
}

/// The stored setting asks for a pin but holds no usable one. The entry then uses verify-full
/// (safe), and the app shows that the pin needs trusting again rather than dropping it silently.
pub fn entry_tls_damaged(c: &Connection) -> bool {
    let stored = c.extra.get(TLS_KEY);
    let asked_pinned = stored.and_then(Value::as_object).and_then(|o| o.get("mode")).and_then(Value::as_str) == Some("pinned");
    stored.is_some() && entry_tls(c).0 != TlsMode::Pinned && (asked_pinned || stored.and_then(Value::as_object).is_none())
}

/// Set the entry's TLS mode: `verify-full` (any pin is dropped) or `pinned` with a pin.
pub fn set_entry_tls(c: &mut Connection, mode: &str, pin: Option<&str>) -> Result<()> {
    if !is_plugin_entry(c) {
        return Err(CoreError::Invalid("TLS settings apply to plugin entries only".into()));
    }
    let value = match (mode, pin.map(str::trim)) {
        ("verify-full", _) => json!({ "mode": "verify-full" }),
        ("pinned", Some(p)) if is_pin(p) => json!({ "mode": "pinned", "pin_sha256": p.to_ascii_lowercase() }),
        ("pinned", _) => return Err(CoreError::Invalid("Certificate pin: a SHA-256 of 64 hex characters.".into())),
        _ => return Err(CoreError::Invalid(format!("TLS mode `{mode}` is not offered"))),
    };
    c.extra.insert(TLS_KEY.to_string(), value);
    Ok(())
}

/// A plugin entry and its settings inherited from its folders (no type defaults: a plugin
/// type has none in the core).
pub fn plugin_entry_settings(doc: &Document, id: Uuid) -> Option<(&Connection, Settings)> {
    fn find<'a>(f: &'a Folder, above: &Settings, id: Uuid) -> Option<(&'a Connection, Settings)> {
        let here = f.defaults.inherit_from(above);
        f.children.iter().find_map(|n| match n {
            Node::Connection(c) if c.id == id && is_plugin_entry(c) => Some((c, c.settings.inherit_from(&here))),
            Node::Connection(_) => None,
            Node::Folder(sub) => find(sub, &here, id),
        })
    }
    find(&doc.root, &Settings::default(), id)
}

/// The TLS settings the relay uses for this entry. "Allow unencrypted" stays off.
pub fn binding_tls(c: &Connection, effective: &Settings) -> EntryTls {
    let (mode, pin_sha256) = entry_tls(c);
    let route = if effective.gateway_id.is_none() { EntryRoute::Direct } else { EntryRoute::NotDirect };
    EntryTls { mode, pin_sha256, allow_unencrypted: false, route }
}

#[cfg(test)]
#[path = "pluginentry_tests.rs"]
mod tests;
