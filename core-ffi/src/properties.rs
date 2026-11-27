//! Bridge for the property editor (`bastion_core::properties`) and the Add-menu catalogue.
use bastion_core::catalog::{self, Support};
use bastion_core::model::Protocol;
use bastion_core::properties::{self, PropertyDef, PropertyValue, ValueSource};

use crate::{parse_id, FfiError, FfiResult, Library};

#[derive(uniffi::Record)]
pub struct PropertyDefView {
    pub key: String,
    pub label: String,
    pub category: String,
    /// `text`, `port`, `seconds`, `multiline`, `tags`, `choice` or `toggle`.
    pub kind: String,
    pub help: String,
    pub inheritable: bool,
    /// For `choice`: the allowed values in display order.
    pub options: Vec<PropertyOptionView>,
}

#[derive(uniffi::Record)]
pub struct PropertyOptionView {
    pub id: String,
    pub label: String,
}

/// One user-defined property of a connection (Organization › Custom Properties).
#[derive(uniffi::Record)]
pub struct CustomPropertyView {
    pub name: String,
    pub value: String,
}

/// One connection's colour, for `Library::host_colors`.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct HostColorEntry {
    pub id: String,
    pub color: HostColorView,
}

/// A connection's per-host colour (`hostcolors::HostColor`).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct HostColorView {
    pub accent: String,
    pub text: String,
    pub tint: String,
    /// Nearest preset label, privileged flag and text-safe tones (UI-01).
    pub named: String,
    pub privileged: bool,
    pub fg_light: String,
    pub bg_light: String,
    pub fg_dark: String,
    pub bg_dark: String,
}

impl From<bastion_core::hostcolors::HostColor> for HostColorView {
    fn from(c: bastion_core::hostcolors::HostColor) -> Self {
        HostColorView { accent: c.accent, text: c.text, tint: c.tint, named: c.named, privileged: c.privileged, fg_light: c.fg_light, bg_light: c.bg_light, fg_dark: c.fg_dark, bg_dark: c.bg_dark }
    }
}

#[derive(uniffi::Record)]
pub struct PropertyValueView {
    pub key: String,
    pub own: Option<String>,
    pub effective: Option<String>,
    /// `own`, `inherited`, `typedefault`, `builtin` or `unset`.
    pub source: String,
    pub from: Option<String>,
}

#[derive(uniffi::Record)]
pub struct TypeDescriptorView {
    pub id: String,
    pub label: String,
    pub group: String,
    pub summary: String,
    /// `connects`, `store-only` or `planned`.
    pub support: String,
}

fn wire<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default().trim_matches('"').to_string()
}

pub(crate) fn def_view(d: PropertyDef) -> PropertyDefView {
    PropertyDefView {
        key: d.key.into(),
        label: d.label.into(),
        category: d.category.into(),
        kind: wire(&d.kind),
        help: d.help.into(),
        inheritable: d.inheritable,
        options: d.options.iter().map(|(id, label)| PropertyOptionView { id: id.to_string(), label: label.to_string() }).collect(),
    }
}

fn value_view(v: PropertyValue) -> PropertyValueView {
    let source = wire::<ValueSource>(&v.source);
    PropertyValueView { key: v.key, own: v.own, effective: v.effective, source, from: v.from }
}

fn protocol(name: &str) -> FfiResult<Protocol> {
    serde_json::from_value(serde_json::Value::String(name.to_lowercase())).map_err(|_| FfiError::failed(format!("unknown protocol `{name}`")))
}

/// Properties for a connection type (`ssh`, `rdp`, …), or with `defaults_only` the inheritable
/// subset used by folder and type Default Settings.
#[uniffi::export]
pub fn property_schema(protocol_name: Option<String>, defaults_only: bool) -> FfiResult<Vec<PropertyDefView>> {
    // A plugin type (`<plugin id>/<type id>`): the core-owned address and login.
    if !defaults_only && protocol_name.as_deref().and_then(bastion_core::plugintypes::split_type_name).is_some() {
        return Ok(properties::plugin_entry_schema().into_iter().map(def_view).collect());
    }
    let p = protocol_name.as_deref().map(protocol).transpose()?;
    let defs = match (p, defaults_only) {
        (Some(p), false) => properties::schema(p),
        (p, _) => properties::default_schema(p),
    };
    Ok(defs.into_iter().map(def_view).collect())
}

/// `(id, label)` of the local shells offered on this platform, default first (`localshell`).
/// Windows adds `wsl:<distro>` entries from its WSL discovery.
#[uniffi::export]
pub fn local_shell_options() -> Vec<PropertyOptionView> {
    bastion_core::localshell::shells().iter().map(|(id, label)| PropertyOptionView { id: id.to_string(), label: label.to_string() }).collect()
}

#[uniffi::export]
pub fn connection_catalog() -> Vec<TypeDescriptorView> {
    catalog::catalog().into_iter().map(descriptor_view).collect()
}

/// The catalogue for this app: `handled` lists the type ids it can open (`rdp`, `vnc`, …), which
/// are shown as connecting; everything else keeps the shared status (H15).
#[uniffi::export]
pub fn connection_catalog_for(handled: Vec<String>) -> Vec<TypeDescriptorView> {
    let handled: Vec<&str> = handled.iter().map(String::as_str).collect();
    catalog::catalog_for(&handled).into_iter().map(descriptor_view).collect()
}

fn descriptor_view(t: catalog::TypeDescriptor) -> TypeDescriptorView {
    TypeDescriptorView { id: t.id.into(), label: t.label.into(), group: t.group.into(), summary: t.summary.into(), support: wire::<Support>(&t.support) }
}

#[uniffi::export]
impl Library {
    /// A connection's custom properties (`user.*` metadata), by name. Names that look secret are
    /// refused when set, so these never hold a password.
    pub fn custom_properties(&self, id: String) -> FfiResult<Vec<CustomPropertyView>> {
        let id = crate::parse_id(&id)?;
        self.with_doc(|d| Ok(d.user_metadata_of(id)?.into_iter().map(|(name, value)| CustomPropertyView { name, value }).collect()))
    }

    /// Set (`Some`) or remove (`None`) one custom property of a connection.
    pub fn set_custom_property(&self, id: String, name: String, value: Option<String>) -> FfiResult<()> {
        let id = crate::parse_id(&id)?;
        self.with_doc(|d| d.set_user_metadata(id, name.trim(), value.as_deref()))
    }

    /// Values for a connection, or a folder's defaults, with where each comes from.
    pub fn property_values(&self, id: String) -> FfiResult<Vec<PropertyValueView>> {
        let id = parse_id(&id)?;
        let values = self.with_doc(|d| properties::connection_values(d, id).or_else(|_| properties::folder_values(d, id)))?;
        Ok(values.into_iter().map(value_view).collect())
    }

    /// Default Settings for a connection type.
    pub fn type_default_values(&self, protocol_name: String) -> FfiResult<Vec<PropertyValueView>> {
        let p = protocol(&protocol_name)?;
        Ok(self.with_doc(|d| Ok(properties::type_values(d, p)))?.into_iter().map(value_view).collect())
    }

    /// Effective per-host colour of a connection (own, else nearest folder), or `None`.
    pub fn host_color(&self, id: String) -> FfiResult<Option<HostColorView>> {
        let id = parse_id(&id)?;
        let c = self.with_doc(|d| bastion_core::hostcolors::for_connection(d, id))?;
        Ok(c.map(HostColorView::from))
    }

    /// Every coloured connection's colour by id, in one call (the tree asks after every edit).
    pub fn host_colors(&self) -> FfiResult<Vec<HostColorEntry>> {
        let all = self.with_doc(|d| Ok(bastion_core::hostcolors::all(d)))?;
        Ok(all.into_iter().map(|(id, c)| HostColorEntry { id: id.to_string(), color: c.into() }).collect())
    }

    /// Set a property on a connection or folder; `None` or blank resets it to inherited.
    pub fn set_property(&self, id: String, key: String, value: Option<String>) -> FfiResult<()> {
        let id = parse_id(&id)?;
        self.with_doc(|d| properties::set_value(d, id, &key, value.as_deref()))
    }

    /// "Allow for this host" after `NoCommonAlgorithm`: `kind` and `names` as the error gave them.
    pub fn allow_weak_algorithms(&self, id: String, kind: String, names: Vec<String>) -> FfiResult<()> {
        let id = parse_id(&id)?;
        let kind: bastion_core::algorithms::AlgoKind = serde_json::from_value(serde_json::Value::String(kind.clone())).map_err(|_| FfiError::failed(format!("unknown algorithm kind `{kind}`")))?;
        self.with_doc(|d| properties::allow_weak_algorithms(d, id, kind, &names))
    }

    pub fn set_type_default(&self, protocol_name: String, key: String, value: Option<String>) -> FfiResult<()> {
        let p = protocol(&protocol_name)?;
        self.with_doc(|d| properties::set_type_value(d, p, &key, value.as_deref()))
    }

    /// Connections that a change to this default would affect (folder id, or a type when `folder_id` is `None`).
    pub fn affected_by_default(&self, folder_id: Option<String>, protocol_name: Option<String>, key: String) -> FfiResult<Vec<String>> {
        let folder = folder_id.as_deref().map(parse_id).transpose()?;
        let p = protocol_name.as_deref().map(protocol).transpose()?;
        self.with_doc(|d| Ok(properties::affected_by(d, folder, p, &key)))
    }

    pub fn set_favorite(&self, id: String, favorite: bool) -> FfiResult<()> {
        let id = parse_id(&id)?;
        self.with_doc(|d| d.set_favorite(id, favorite))
    }

    /// Drag-and-drop: move a connection or folder into `parent` (root when `None`).
    pub fn move_node(&self, id: String, parent: Option<String>) -> FfiResult<()> {
        let id = parse_id(&id)?;
        let parent = parent.as_deref().map(parse_id).transpose()?;
        self.with_doc(|d| d.move_node(id, parent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choice_properties_carry_their_options() {
        let defs = property_schema(Some("rdp".into()), false).unwrap();
        let env = defs.iter().find(|d| d.key == "environment").unwrap();
        assert_eq!((env.kind.as_str(), env.category.as_str()), ("choice", "Security"));
        assert_eq!(env.options.iter().map(|o| o.id.as_str()).collect::<Vec<_>>(), ["unclassified", "test", "development", "staging", "production"]);
        assert_eq!(defs.iter().find(|d| d.key == "privileged").unwrap().kind, "toggle");
        assert!(property_schema(None, true).unwrap().iter().filter(|d| d.kind != "choice").all(|d| d.options.is_empty()));
        let color = property_schema(None, true).unwrap().into_iter().find(|d| d.key == "tab_group_color").unwrap();
        assert!(!color.options.is_empty());
    }
}
