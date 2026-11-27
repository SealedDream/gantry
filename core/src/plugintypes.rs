//! Plugin connection types and their fields (PLUG-03b; `docs/specs/plugins.md`, sections 5, 6
//! and 10).
//!
//! A plugin's manifest declares connection types (`[[connection_types]]`). In the library such an
//! entry is stored under the namespaced type name `<plugin id>/<type id>`, for example
//! `dev.bastion.postgres/postgres`. The model keeps it as it keeps every type it does not build
//! in: `Protocol::Unsupported` with the stored name in `Connection::unknown_protocol` (PLUG-03a).
//! So no built-in connect path, `match` on `Protocol` or binding ever treats a plugin entry as a
//! type it knows, and an app without the plugin keeps the entry unchanged.
//!
//! What this module adds on top:
//! - [`Registry`]: the connection types of the installed plugins, built from verified manifests.
//! - [`availability`]: built in, a plugin type that is installed, a plugin that is missing, or
//!   unknown. Only an installed plugin type is usable; it is opened through the plugin, never
//!   through `Document::resolve`, which still refuses every entry of a type it does not build in.
//! - The entry's plugin fields: stored in the entry under [`FIELDS_KEY`] as an object of strings,
//!   booleans and whole numbers within ±(2^53 − 1) (section 10, step 6), shown in the property
//!   editor as one group headed in the core's words ([`PluginType::group_heading`]), and
//!   checked here when the user saves one ([`set_field`]).
//!
//! Plugin fields are per entry. They are not inherited from folders or type defaults.
use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::{Connection, Document, Protocol, NEEDS_NEWER};
use crate::plugin::{canonical_plugin_id, check_text, is_label, is_plugin_id, Field, FieldKind, Manifest, TextFault, Tier};
use crate::properties::PropKind;

/// Where an entry keeps its plugin field values.
pub const FIELDS_KEY: &str = "plugin_fields";
/// The longest value of a text field, in characters.
pub const MAX_TEXT_FIELD_CHARS: usize = 1024;
/// The largest whole number a `number` field holds, 2^53 − 1 (spec section 10, step 6).
pub const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;
/// The core's warning when a field value holds the entry's saved password (spec section 5).
pub const PASSWORD_MATCH_WARNING: &str = "This matches the entry's saved password. Fields are stored without encryption.";

/// The badge text of a tier, in the core's words.
pub fn tier_label(tier: Tier) -> &'static str {
    match tier {
        Tier::Official => "Official",
        Tier::External => "External",
        Tier::Unverified => "Unverified",
    }
}

/// The library name of a plugin connection type.
pub fn qualified(plugin_id: &str, type_id: &str) -> String {
    format!("{plugin_id}/{type_id}")
}

/// `(plugin id, type id)` when `name` is a well-formed plugin type name. Says nothing about
/// whether that plugin is installed; the name comes from the library and is untrusted.
pub fn split_type_name(name: &str) -> Option<(&str, &str)> {
    let (plugin, ty) = name.split_once('/')?;
    (is_plugin_id(plugin) && is_label(ty)).then_some((plugin, ty))
}

/// One connection type of an installed plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginType {
    /// `<plugin id>/<type id>`, as stored in the library.
    pub id: String,
    pub plugin_id: String,
    pub plugin_name: String,
    pub tier: Tier,
    pub name: String,
    pub default_port: Option<u16>,
    pub fields: Vec<Field>,
    /// The entry shows the plugin's tree in the library sidebar (API 1.3, `sidebar = "tree"`).
    pub sidebar_tree: bool,
}

impl PluginType {
    /// The heading of the plugin's group in the property editor and Quick connect, in the core's
    /// words, with the plugin's name in quotes and its tier (spec sections 5 and 14).
    pub fn group_heading(&self) -> String {
        format!("Fields from the plugin \"{}\" ({})", self.plugin_name, tier_label(self.tier))
    }

    fn field(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.key == key)
    }
}

/// The connection types of the installed plugins that are turned on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registry {
    types: BTreeMap<String, PluginType>,
}

impl Registry {
    pub fn new() -> Self {
        Registry::default()
    }

    /// Add (or replace) the connection types of one plugin. `manifest` passed every install
    /// check (it can only be built by `parse_manifest`), and `tier` is the one its signatures
    /// gave. The types of an earlier version of the same plugin are dropped first.
    pub fn add(&mut self, manifest: &Manifest, tier: Tier) {
        self.remove(&manifest.id);
        for ct in &manifest.connection_types {
            let id = qualified(&manifest.id, &ct.id);
            let ty = PluginType { id: id.clone(), plugin_id: manifest.id.clone(), plugin_name: manifest.name.clone(), tier, name: ct.name.clone(), default_port: ct.default_port, fields: ct.fields.clone(), sidebar_tree: ct.sidebar_tree };
            self.types.insert(id, ty);
        }
    }

    /// Forget a plugin's types (removed or turned off). Its entries stay in the library unchanged.
    /// A legacy `dev.bastion.*` id and its `dev.gantry.*` name are the same plugin.
    pub fn remove(&mut self, plugin_id: &str) {
        let wanted = canonical_plugin_id(plugin_id);
        self.types.retain(|_, t| canonical_plugin_id(&t.plugin_id) != wanted);
    }

    /// The type for `id`. Entries saved before the rename name `dev.bastion.*` types and
    /// resolve to the renamed pack, and the other way round while an old pack is installed.
    pub fn get(&self, id: &str) -> Option<&PluginType> {
        self.types.get(id).or_else(|| {
            let wanted = canonical_plugin_id(id);
            self.types.iter().find(|(k, _)| canonical_plugin_id(k) == wanted).map(|(_, t)| t)
        })
    }

    /// Every type, by library name: for the New Connection menu.
    pub fn types(&self) -> impl Iterator<Item = &PluginType> {
        self.types.values()
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
}

/// Whether an entry can be used, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability<'a> {
    /// A type built into the core.
    Builtin,
    /// A type of an installed plugin. The entry opens through that plugin.
    Plugin(&'a PluginType),
    /// A plugin type name whose plugin is not installed (or is turned off). The id is untrusted
    /// text from the library: Install looks it up in the signed index only (spec section 10).
    NeedsPlugin { plugin_id: &'a str },
    /// A type this app does not know at all.
    NeedsNewer,
}

impl Availability<'_> {
    /// The fixed text the apps show on an entry that cannot be used; `None` when it can. Every
    /// app checks this before it dispatches on the entry's type.
    pub fn unavailable(&self) -> Option<&'static str> {
        match self {
            Availability::Builtin | Availability::Plugin(_) => None,
            Availability::NeedsPlugin { .. } | Availability::NeedsNewer => Some(NEEDS_NEWER),
        }
    }
}

pub fn availability<'a>(c: &'a Connection, registry: &'a Registry) -> Availability<'a> {
    if c.protocol != Protocol::Unsupported {
        return Availability::Builtin;
    }
    let Some(name) = c.unknown_protocol.as_deref() else { return Availability::NeedsNewer };
    if let Some(ty) = registry.get(name) {
        return Availability::Plugin(ty);
    }
    match split_type_name(name) {
        Some((plugin_id, _)) => Availability::NeedsPlugin { plugin_id },
        None => Availability::NeedsNewer,
    }
}

/// A new entry of a plugin type, with the type's default port and no field values.
pub fn new_entry(name: impl Into<String>, host: impl Into<String>, ty: &PluginType) -> Connection {
    let mut c = Connection::new(name, Protocol::Unsupported, host);
    c.unknown_protocol = Some(ty.id.clone());
    c.settings.port = ty.default_port;
    c
}

/// The entry `id` and its plugin type, for opening it through the plugin. Refused with the
/// fixed text when the entry's plugin is not installed, and when the entry is of a built-in
/// type (those open through `Document::resolve`).
pub fn plugin_entry<'a>(doc: &'a Document, id: Uuid, registry: &'a Registry) -> Result<(&'a Connection, &'a PluginType)> {
    let c = doc.unavailable_entry(id).ok_or_else(|| CoreError::NotFound(id.to_string()))?;
    match availability(c, registry) {
        Availability::Plugin(ty) => Ok((c, ty)),
        _ => Err(CoreError::Invalid(NEEDS_NEWER.into())),
    }
}

/// One plugin field as the property editor shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginField {
    pub key: String,
    pub label: String,
    pub kind: PropKind,
    /// The stored value as text; `None` when unset, or when the stored value is not of the
    /// field's kind (it is kept, and replaced only when the user sets the field).
    pub value: Option<String>,
}

/// The plugin's group in the property editor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginFieldGroup {
    pub heading: String,
    /// The library name of the type.
    pub type_id: String,
    pub fields: Vec<PluginField>,
}

/// Within ±(2^53 − 1). A range check, not `abs()`, which overflows on `i64::MIN`.
fn in_safe_range(n: i64) -> bool {
    (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n)
}

fn prop_kind(kind: FieldKind) -> PropKind {
    match kind {
        FieldKind::Text => PropKind::Text,
        FieldKind::Number => PropKind::Number,
        FieldKind::Toggle => PropKind::Toggle,
    }
}

fn stored(c: &Connection) -> Option<&Map<String, Value>> {
    c.extra.get(FIELDS_KEY).and_then(Value::as_object)
}

fn as_text(value: &Value, kind: FieldKind) -> Option<String> {
    match (kind, value) {
        (FieldKind::Text, Value::String(s)) => Some(s.clone()),
        (FieldKind::Toggle, Value::Bool(b)) => Some(b.to_string()),
        (FieldKind::Number, Value::Number(n)) => n.as_i64().filter(|n| in_safe_range(*n)).map(|n| n.to_string()),
        _ => None,
    }
}

fn check_type(c: &Connection, ty: &PluginType) -> Result<()> {
    if c.protocol == Protocol::Unsupported && c.unknown_protocol.as_deref() == Some(ty.id.as_str()) {
        Ok(())
    } else {
        Err(CoreError::Invalid(format!("this entry is not of the type {}", ty.name)))
    }
}

/// The entry's fields of its plugin type, in the manifest's order. Stored values for keys the
/// manifest does not declare (an older or newer plugin version) are kept but not shown.
pub fn field_group(c: &Connection, ty: &PluginType) -> Result<PluginFieldGroup> {
    check_type(c, ty)?;
    let values = stored(c);
    let fields = ty.fields.iter().map(|f| PluginField { key: f.key.clone(), label: f.label.clone(), kind: prop_kind(f.kind), value: values.and_then(|m| m.get(&f.key)).and_then(|v| as_text(v, f.kind)) }).collect();
    Ok(PluginFieldGroup { heading: ty.group_heading(), type_id: ty.id.clone(), fields })
}

/// The outcome of [`set_field`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldSave {
    Saved,
    /// Nothing was saved: the value holds the entry's saved password. Show the text with Cancel
    /// and Save anyway; Save anyway calls [`set_field`] again with `confirmed`.
    ConfirmPassword(&'static str),
}

/// Parse a value the user typed into the stored form of `kind`. An empty value clears the field.
fn parse(kind: FieldKind, text: &str) -> Result<Option<Value>> {
    if text.is_empty() {
        return Ok(None);
    }
    Ok(Some(match kind {
        FieldKind::Text => match check_text(text, MAX_TEXT_FIELD_CHARS) {
            Ok(()) => Value::String(text.to_string()),
            Err(TextFault::Empty) => return Ok(None),
            Err(TextFault::ControlChar) => return Err(CoreError::Invalid("a plugin field cannot hold control characters or hidden text".into())),
            Err(TextFault::TooLong) => return Err(CoreError::Invalid(format!("a plugin field holds at most {MAX_TEXT_FIELD_CHARS} characters"))),
        },
        FieldKind::Number => {
            let n: i64 = text.trim().parse().map_err(|_| CoreError::Invalid("enter a whole number".into()))?;
            if !in_safe_range(n) {
                return Err(CoreError::Invalid(format!("enter a whole number between -{MAX_SAFE_INTEGER} and {MAX_SAFE_INTEGER}")));
            }
            Value::from(n)
        }
        FieldKind::Toggle => match text {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => return Err(CoreError::Invalid("a toggle is true or false".into())),
        },
    }))
}

/// Set (`Some`) or clear (`None` or empty) one plugin field, as the user typed it in the core's
/// property editor. API 1 gives plugins no call that writes fields; this is the user's road.
///
/// `saved_password` is the entry's own saved password when credentials are unlocked (`None`
/// when locked or when the entry has none). When the value holds it and `confirmed` is false,
/// nothing is saved and the caller shows [`PASSWORD_MATCH_WARNING`] (spec section 5).
pub fn set_field(c: &mut Connection, ty: &PluginType, key: &str, value: Option<&str>, saved_password: Option<&str>, confirmed: bool) -> Result<FieldSave> {
    check_type(c, ty)?;
    let field = ty.field(key).ok_or_else(|| CoreError::Invalid(format!("{} has no field {key:?}", ty.name)))?;
    let parsed = parse(field.kind, value.unwrap_or(""))?;
    if let (Some(text), Some(pw)) = (value, saved_password.filter(|p| !p.is_empty())) {
        if parsed.is_some() && text.contains(pw) && !confirmed {
            return Ok(FieldSave::ConfirmPassword(PASSWORD_MATCH_WARNING));
        }
    }
    let map = match c.extra.get_mut(FIELDS_KEY) {
        Some(Value::Object(map)) => map,
        Some(_) => return Err(CoreError::Invalid("this entry's plugin fields were saved in a form this app does not read; they are kept unchanged".into())),
        None => {
            if parsed.is_none() {
                return Ok(FieldSave::Saved);
            }
            c.extra.entry(FIELDS_KEY.to_string()).or_insert_with(|| Value::Object(Map::new())).as_object_mut().expect("just inserted an object")
        }
    };
    match parsed {
        Some(v) => {
            map.insert(key.to_string(), v);
        }
        None => {
            map.remove(key);
        }
    }
    if map.is_empty() {
        c.extra.remove(FIELDS_KEY);
    }
    Ok(FieldSave::Saved)
}

/// Plugin fields that let a plugin change a server: "Allow changes" (every plugin) and VMware's
/// snapshot before connect. Only the user turns them on, on this device.
pub const CHANGE_FLAGS: &[&str] = &["allow-changes", "snapshot-before-connect"];

/// Turns every plugin change flag off on an entry that came from outside: a file import, a
/// library or document import, or a received document (security review of #1439, HIGH 2).
/// Called by [`crate::logins::mark_received`], which every such path runs.
pub fn clear_change_flags(c: &mut Connection) {
    let Some(Value::Object(map)) = c.extra.get_mut(FIELDS_KEY) else { return };
    for k in CHANGE_FLAGS {
        map.remove(*k);
    }
    if map.is_empty() {
        c.extra.remove(FIELDS_KEY);
    }
}

#[cfg(test)]
#[path = "plugintypes_tests.rs"]
mod tests;
