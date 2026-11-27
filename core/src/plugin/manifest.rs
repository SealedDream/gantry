//! `plugin.toml` (section 6), typed, with the limits of section 5.
//!
//! The file is parsed to a TOML table and then walked by hand, so every unknown key, wrong type
//! and bad value gets its own error and nothing from the file is echoed at length. A manifest
//! cannot state a tier: there is no key for it, and unknown keys are refused.
use toml::{Table, Value};

use super::broker::http::{self, HttpSpec};
use super::broker::http_session;
use super::broker::exec::{self as exec_rules, ExecSpec};
use super::broker::open::{self as open_rules, AddressField, OpenSpec};
use super::error::{Excerpt, PluginError};

/// `plugin.toml` is small; anything larger is refused before parsing.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Section 5, "Size limits". Counted in characters, not bytes.
pub const MAX_NAME_CHARS: usize = 32;
pub const MAX_COMMAND_TITLE_CHARS: usize = 40;
pub const MAX_FIELD_LABEL_CHARS: usize = 32;
pub const MAX_DESCRIPTION_CHARS: usize = 120;
// The spec gives no limit for these three; they are shown in the app, so they get one.
const MAX_PUBLISHER_CHARS: usize = 64;
const MAX_LICENSE_CHARS: usize = 64;
pub(super) const MAX_REPOSITORY_CHARS: usize = 256;
const MAX_PLUGIN_ID_BYTES: usize = 64;
const MAX_LOCAL_ID_BYTES: usize = 32;
const SCHEMA: i64 = 1;
/// Ids under this name are reserved for Official plugins (section 6).
/// The official plugin namespace since the product rename (owner 2026-11-23).
pub const RESERVED_ID: &str = "dev.gantry";
/// The namespace official plugins used before the rename. Still reserved, and an installed pack
/// under it keeps working: [`canonical_plugin_id`] maps it onto `dev.gantry`.
pub const LEGACY_RESERVED_ID: &str = "dev.bastion";

/// A plugin version: `major.minor.patch`, digits only, no leading zeros, no suffix. Ordered, so
/// a revocation can name a range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub fn parse(text: &str) -> Option<Version> {
        let mut parts = text.split('.');
        let version = Version { major: number(parts.next()?)?, minor: number(parts.next()?)?, patch: number(parts.next()?)? };
        parts.next().is_none().then_some(version)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// A plugin API version: `major.minor` (section 5, "API versions").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApiVersion {
    pub major: u32,
    pub minor: u32,
}

impl ApiVersion {
    pub fn parse(text: &str) -> Option<ApiVersion> {
        let mut parts = text.split('.');
        let version = ApiVersion { major: number(parts.next()?)?, minor: number(parts.next()?)? };
        parts.next().is_none().then_some(version)
    }
}

fn number(text: &str) -> Option<u32> {
    let plain = !text.is_empty() && text.len() <= 9 && text.bytes().all(|b| b.is_ascii_digit()) && (text.len() == 1 || !text.starts_with('0'));
    if plain {
        text.parse().ok()
    } else {
        None
    }
}

/// The permissions of section 5, exactly: each is either granted in its one allowed form or not
/// asked for. A manifest and a release record are compared through this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Permissions {
    /// `network = "entry"`
    pub network_entry: bool,
    /// `credentials = "entry"`
    pub credentials_entry: bool,
    /// `storage = true`
    pub storage: bool,
    /// `clipboard = "write"`
    pub clipboard_write: bool,
    /// `files` contains `"save"`
    pub files_save: bool,
    /// `files` contains `"open"`
    pub files_open: bool,
    /// `http = "entry"` (API 1.1; `docs/specs/plugins-amendment-2.md`)
    pub http_entry: bool,
    /// `open` lists `"ssh"`, `"rdp"`, `"vnc"` (API 1.2; `docs/specs/plugins-amendment-3.md`)
    pub open_ssh: bool,
    pub open_rdp: bool,
    pub open_vnc: bool,
    /// `exec = "entry"` (API 1.5; `docs/specs/plugins.md`, section 19): the manifest's
    /// `[[exec]]` commands on the entry's host over SSH.
    pub exec_entry: bool,
    /// `library = "propose"` (API 1.6): propose library connections the user confirms
    pub library_propose: bool,
}

impl Permissions {
    /// Build from the raw values of a manifest or a release record. An error names the key
    /// whose value is not one section 5 lists.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_parts(network: Option<&str>, credentials: Option<&str>, storage: Option<bool>, clipboard: Option<&str>, files: Option<&[&str]>, http: Option<&str>, open: Option<&[&str]>, library: Option<&str>) -> Result<Permissions, &'static str> {
        let only = |value: Option<&str>, allowed: &str, key: &'static str| match value {
            None => Ok(false),
            Some(v) if v == allowed => Ok(true),
            Some(_) => Err(key),
        };
        let mut permissions = Permissions { network_entry: only(network, "entry", "network")?, credentials_entry: only(credentials, "entry", "credentials")?, storage: storage.unwrap_or(false), clipboard_write: only(clipboard, "write", "clipboard")?, http_entry: only(http, "entry", "http")?, library_propose: only(library, "propose", "library")?, ..Permissions::default() };
        for file in files.unwrap_or_default() {
            let slot = match *file {
                "save" => &mut permissions.files_save,
                "open" => &mut permissions.files_open,
                _ => return Err("files"),
            };
            if std::mem::replace(slot, true) {
                return Err("files");
            }
        }
        if open.is_some_and(<[&str]>::is_empty) {
            return Err("open");
        }
        for protocol in open.unwrap_or_default() {
            let slot = match *protocol {
                "ssh" => &mut permissions.open_ssh,
                "rdp" => &mut permissions.open_rdp,
                "vnc" => &mut permissions.open_vnc,
                _ => return Err("open"),
            };
            if std::mem::replace(slot, true) {
                return Err("open");
            }
        }
        Ok(permissions)
    }

    /// Whether the plugin may ask to open any connection (API 1.2).
    /// `exec = "entry"` or nothing.
    pub(super) fn exec_word(value: Option<&str>) -> Result<bool, &'static str> {
        match value {
            None => Ok(false),
            Some("entry") => Ok(true),
            Some(_) => Err("exec"),
        }
    }

    pub fn opens_any(&self) -> bool {
        self.open_ssh || self.open_rdp || self.open_vnc
    }

    /// Whether the plugin may ask to open `protocol`.
    pub fn opens(&self, protocol: super::broker::open::Protocol) -> bool {
        use super::broker::open::Protocol;
        match protocol {
            Protocol::Ssh => self.open_ssh,
            Protocol::Rdp => self.open_rdp,
            Protocol::Vnc => self.open_vnc,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Number,
    Toggle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Field {
    pub key: String,
    pub label: String,
    pub kind: FieldKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConnectionType {
    /// Local to the plugin; the library uses `<plugin id>/<id>` (section 6).
    pub id: String,
    pub name: String,
    pub default_port: Option<u16>,
    pub fields: Vec<Field>,
    /// `sidebar = "tree"` (API 1.3, `docs/plans/PLUG-API-13.md`): the entry shows the plugin's
    /// tree under it in the library sidebar, from a view named [`SIDEBAR_VIEW`].
    pub sidebar_tree: bool,
    /// How this type's requests carry the entry's login (`login = "auth" | "session"`), resolved
    /// at install from the signed manifest (design D, `docs/design/VMW-ESXI.md` section 8).
    pub login: Option<http_session::LoginMethod>,
}

/// The view name the app opens for a connection type's library-sidebar tree (API 1.3).
pub const SIDEBAR_VIEW: &str = "sidebar";

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Command {
    pub id: String,
    pub title: String,
    /// The id of the connection type whose context menu shows the command; `None` puts it in
    /// the command palette only.
    pub on: Option<String>,
}

/// A manifest that passed every check. It can only be built by [`parse_manifest`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: Version,
    /// The lowest API version the plugin needs.
    pub api: ApiVersion,
    pub publisher: String,
    pub description: String,
    pub license: String,
    pub repository: String,
    pub permissions: Permissions,
    /// The `[http]` table, when the plugin holds `http = "entry"` (API 1.1).
    pub http: Option<HttpSpec>,
    /// The `[open]` table, when the plugin holds `open` (API 1.2). Without it, nothing the
    /// server sends counts as reported.
    pub open: Option<OpenSpec>,
    /// The `[[exec]]` command templates, when the plugin holds `exec = "entry"` (API 1.5).
    pub exec: Option<ExecSpec>,
    pub connection_types: Vec<ConnectionType>,
    pub commands: Vec<Command>,
}

fn under(id: &str, ns: &str) -> bool {
    id == ns || id.strip_prefix(ns).is_some_and(|rest| rest.starts_with('.'))
}

/// True for `dev.gantry`, the legacy `dev.bastion`, and every id under either.
pub fn is_reserved_id(id: &str) -> bool {
    under(id, RESERVED_ID) || under(id, LEGACY_RESERVED_ID)
}

/// The current name of a plugin id or qualified type id: `dev.bastion.x[/t]` becomes
/// `dev.gantry.x[/t]`; every other id is returned unchanged.
pub fn canonical_plugin_id(id: &str) -> std::borrow::Cow<'_, str> {
    match id.strip_prefix(LEGACY_RESERVED_ID) {
        Some(rest) if rest.is_empty() || rest.starts_with('.') || rest.starts_with('/') => format!("{RESERVED_ID}{rest}").into(),
        _ => id.into(),
    }
}

/// One label of an id: a lower-case letter, then lower-case letters, digits or hyphens, not
/// ending in a hyphen.
pub(crate) fn is_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let inner = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-';
    bytes.len() <= MAX_LOCAL_ID_BYTES && bytes.first().is_some_and(u8::is_ascii_lowercase) && bytes.iter().all(inner) && bytes.last() != Some(&b'-')
}

/// Reverse DNS, lower case: at least two labels joined by dots.
pub(crate) fn is_plugin_id(id: &str) -> bool {
    id.len() <= MAX_PLUGIN_ID_BYTES && id.split('.').count() >= 2 && id.split('.').all(is_label)
}

/// Control characters, and the characters that hide or reorder text (zero-width, bidirectional
/// controls, line and paragraph separators, the byte-order mark).
fn is_forbidden(c: char) -> bool {
    c.is_control() || matches!(c, '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

pub(crate) enum TextFault {
    Empty,
    ControlChar,
    TooLong,
}

/// Plugin text is plain text: not empty, no control characters, at most `max` characters.
pub(crate) fn check_text(value: &str, max: usize) -> Result<(), TextFault> {
    if value.is_empty() {
        Err(TextFault::Empty)
    } else if value.chars().any(is_forbidden) {
        Err(TextFault::ControlChar)
    } else if value.chars().count() > max {
        Err(TextFault::TooLong)
    } else {
        Ok(())
    }
}

/// An `https://` address without spaces, as plain text.
pub(super) fn is_https_address(value: &str) -> bool {
    check_text(value, MAX_REPOSITORY_CHARS).is_ok() && value.len() > "https://".len() && value.starts_with("https://") && !value.contains(char::is_whitespace)
}

fn text(value: &str, field: &'static str, max: usize) -> Result<String, PluginError> {
    match check_text(value, max) {
        Ok(()) => Ok(value.to_string()),
        Err(TextFault::Empty) => Err(PluginError::TextEmpty(field)),
        Err(TextFault::ControlChar) => Err(PluginError::TextControlChar(field)),
        Err(TextFault::TooLong) => Err(PluginError::TextTooLong { field, max }),
    }
}

fn only_keys(table: &Table, allowed: &[&str]) -> Result<(), PluginError> {
    match table.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(unknown) => Err(PluginError::ManifestUnknownKey(Excerpt::new(unknown.as_bytes()))),
        None => Ok(()),
    }
}

/// A required string. `field` is the name used in errors (`connection_types.name`).
fn string<'a>(table: &'a Table, key: &str, field: &'static str) -> Result<&'a str, PluginError> {
    match table.get(key) {
        None => Err(PluginError::ManifestMissingKey(field)),
        Some(Value::String(value)) => Ok(value),
        Some(_) => Err(PluginError::ManifestWrongType(field)),
    }
}

/// An optional array of tables (`[[connection_types]]`).
fn tables<'a>(table: &'a Table, key: &str, field: &'static str) -> Result<Vec<&'a Table>, PluginError> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|item| item.as_table().ok_or(PluginError::ManifestWrongType(field))).collect(),
        Some(_) => Err(PluginError::ManifestWrongType(field)),
    }
}

fn local_id(table: &Table, key: &str, field: &'static str) -> Result<String, PluginError> {
    let id = string(table, key, field)?;
    if is_label(id) {
        Ok(id.to_string())
    } else {
        Err(PluginError::BadId(field))
    }
}

fn unique<'a>(ids: impl Iterator<Item = &'a String>, field: &'static str) -> Result<(), PluginError> {
    let mut seen: Vec<&String> = Vec::new();
    for id in ids {
        if seen.contains(&id) {
            return Err(PluginError::DuplicateId(field));
        }
        seen.push(id);
    }
    Ok(())
}

fn permissions(root: &Table) -> Result<Permissions, PluginError> {
    let table = match root.get("permissions") {
        None => return Ok(Permissions::default()),
        Some(Value::Table(table)) => table,
        Some(_) => return Err(PluginError::ManifestWrongType("permissions")),
    };
    only_keys(table, &["network", "credentials", "storage", "clipboard", "files", "http", "open", "exec", "library"])?;
    let word = |key: &'static str| match table.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(_) => Err(PluginError::BadPermission(key)),
    };
    let storage = match table.get("storage") {
        None => None,
        Some(Value::Boolean(value)) => Some(*value),
        Some(_) => return Err(PluginError::BadPermission("storage")),
    };
    let files: Option<Vec<&str>> = match table.get("files") {
        None => None,
        Some(Value::Array(items)) => Some(items.iter().map(|item| item.as_str().ok_or(PluginError::BadPermission("files"))).collect::<Result<_, _>>()?),
        Some(_) => return Err(PluginError::BadPermission("files")),
    };
    let open: Option<Vec<&str>> = match table.get("open") {
        None => None,
        Some(Value::Array(items)) => Some(items.iter().map(|item| item.as_str().ok_or(PluginError::BadPermission("open"))).collect::<Result<_, _>>()?),
        Some(_) => return Err(PluginError::BadPermission("open")),
    };
    let mut p = Permissions::from_parts(word("network")?, word("credentials")?, storage, word("clipboard")?, files.as_deref(), word("http")?, open.as_deref(), word("library")?).map_err(PluginError::BadPermission)?;
    p.exec_entry = Permissions::exec_word(word("exec")?).map_err(PluginError::BadPermission)?;
    Ok(p)
}

/// The `exec` permission and its `[[exec]]` list need API 1.5; the list is required with the
/// permission and refused without it.
fn exec_spec(root: &Table, permissions: &Permissions, api: ApiVersion) -> Result<Option<ExecSpec>, PluginError> {
    let items = match root.get("exec") {
        None if permissions.exec_entry => return Err(PluginError::ManifestMissingKey("exec")),
        None => return Ok(None),
        Some(_) if !permissions.exec_entry => return Err(PluginError::BadPermission("exec")),
        Some(Value::Array(items)) => items,
        Some(_) => return Err(PluginError::ManifestWrongType("exec")),
    };
    if api < (ApiVersion { major: 1, minor: 5 }) {
        return Err(PluginError::BadVersion("api"));
    }
    if items.is_empty() || items.len() > exec_rules::MAX_TEMPLATES {
        return Err(PluginError::BadValue("exec"));
    }
    let mut templates = Vec::new();
    for item in items {
        let Value::Table(t) = item else { return Err(PluginError::ManifestWrongType("exec")) };
        only_keys(t, &["id", "argv", "args", "changes", "interactive"])?;
        let id = local_id(t, "id", "exec.id")?;
        let argv = match t.get("argv") {
            Some(Value::Array(a)) => a.iter().map(|v| v.as_str().and_then(exec_rules::parse_part).ok_or(PluginError::BadValue("exec.argv"))).collect::<Result<Vec<_>, _>>()?,
            None => return Err(PluginError::ManifestMissingKey("exec.argv")),
            Some(_) => return Err(PluginError::ManifestWrongType("exec.argv")),
        };
        let args = match t.get("args") {
            None => Default::default(),
            Some(Value::Table(a)) => a.iter().map(|(k, v)| v.as_str().and_then(exec_rules::ArgKind::parse).map(|kind| (k.clone(), kind)).ok_or(PluginError::BadValue("exec.args"))).collect::<Result<_, _>>()?,
            Some(_) => return Err(PluginError::ManifestWrongType("exec.args")),
        };
        let flag = |key: &'static str| match t.get(key) {
            None => Ok(false),
            Some(Value::Boolean(b)) => Ok(*b),
            Some(_) => Err(PluginError::ManifestWrongType(key)),
        };
        let template = exec_rules::Template { id, argv, args, changes: flag("changes")?, interactive: flag("interactive")? };
        template.check().map_err(PluginError::BadValue)?;
        templates.push(template);
    }
    unique(templates.iter().map(|t| &t.id), "exec.id")?;
    Ok(Some(ExecSpec { templates }))
}

/// The `library` permission needs API 1.6 (`docs/specs/plugins-amendment-5.md`).
pub const LIBRARY_API: ApiVersion = ApiVersion { major: 1, minor: 6 };

/// The `open` permission and the `[open]` table need API 1.2. The table is optional: without
/// `address_fields` no address counts as reported (`docs/specs/plugins-amendment-3.md`).
fn open_spec(root: &Table, permissions: &Permissions, api: ApiVersion) -> Result<Option<OpenSpec>, PluginError> {
    if permissions.opens_any() && api < (ApiVersion { major: 1, minor: 2 }) {
        return Err(PluginError::BadVersion("api"));
    }
    let table = match root.get("open") {
        None => return Ok(None),
        Some(_) if !permissions.opens_any() => return Err(PluginError::BadPermission("open")),
        Some(Value::Table(table)) => table,
        Some(_) => return Err(PluginError::ManifestWrongType("open")),
    };
    only_keys(table, &["address_fields"])?;
    let items = match table.get("address_fields") {
        None => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => return Err(PluginError::ManifestWrongType("open.address_fields")),
    };
    if items.len() > open_rules::MAX_ADDRESS_FIELDS {
        return Err(PluginError::BadValue("open.address_fields"));
    }
    let mut address_fields = Vec::new();
    for item in &items {
        let Value::Table(t) = item else { return Err(PluginError::ManifestWrongType("open.address_fields")) };
        only_keys(t, &["path", "fields"])?;
        let path = string(t, "path", "open.address_fields.path")?;
        if !open_rules::valid_path_pattern(path) || !permissions.http_entry {
            return Err(PluginError::BadValue("open.address_fields.path"));
        }
        let fields = match t.get("fields") {
            Some(Value::Array(f)) => f.iter().map(|v| v.as_str().map(str::to_string).ok_or(PluginError::ManifestWrongType("open.address_fields.fields"))).collect::<Result<Vec<_>, _>>()?,
            None => return Err(PluginError::ManifestMissingKey("open.address_fields.fields")),
            Some(_) => return Err(PluginError::ManifestWrongType("open.address_fields.fields")),
        };
        if fields.is_empty() || fields.len() > open_rules::MAX_FIELDS_PER_PATH || !fields.iter().all(|f| open_rules::valid_field_path(f)) {
            return Err(PluginError::BadValue("open.address_fields.fields"));
        }
        unique(fields.iter(), "open.address_fields.fields")?;
        address_fields.push(AddressField { path: path.to_string(), fields });
    }
    unique(address_fields.iter().map(|a| &a.path), "open.address_fields.path")?;
    Ok(Some(OpenSpec { address_fields }))
}

/// The `[http]` table (API 1.1). Present exactly when the `http` permission is.
fn http_spec(root: &Table, permissions: &Permissions, api: ApiVersion) -> Result<Option<HttpSpec>, PluginError> {
    let table = match root.get("http") {
        None if permissions.http_entry => return Err(PluginError::ManifestMissingKey("http")),
        None => return Ok(None),
        Some(_) if !permissions.http_entry => return Err(PluginError::BadPermission("http")),
        Some(Value::Table(table)) => table,
        Some(_) => return Err(PluginError::ManifestWrongType("http")),
    };
    if api < (ApiVersion { major: 1, minor: 1 }) {
        return Err(PluginError::BadVersion("api"));
    }
    only_keys(table, &["paths", "ports", "methods", "auth", "session"])?;
    let strings = |key: &'static str| -> Result<Option<Vec<&str>>, PluginError> {
        match table.get(key) {
            None => Ok(None),
            Some(Value::Array(items)) => items.iter().map(|i| i.as_str().ok_or(PluginError::ManifestWrongType(key))).collect::<Result<Vec<_>, _>>().map(Some),
            Some(_) => Err(PluginError::ManifestWrongType(key)),
        }
    };
    let paths: Vec<String> = strings("paths")?.ok_or(PluginError::ManifestMissingKey("http.paths"))?.into_iter().map(str::to_string).collect();
    if paths.is_empty() || paths.len() > http::MAX_PATHS || !paths.iter().all(|p| http::valid_prefix(p)) {
        return Err(PluginError::BadValue("http.paths"));
    }
    unique(paths.iter(), "http.paths")?;
    let ports = match table.get("ports") {
        None => Vec::new(),
        Some(Value::Array(items)) => items.iter().map(|i| match i {
            Value::Integer(n) => u16::try_from(*n).ok().filter(|p| *p != 0).ok_or(PluginError::BadValue("http.ports")),
            _ => Err(PluginError::ManifestWrongType("http.ports")),
        }).collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(PluginError::ManifestWrongType("http.ports")),
    };
    if ports.len() > http::MAX_PORTS {
        return Err(PluginError::BadValue("http.ports"));
    }
    if (1..ports.len()).any(|i| ports[..i].contains(&ports[i])) {
        return Err(PluginError::BadValue("http.ports"));
    }
    let methods = match strings("methods")? {
        None => vec![http::Method::Get, http::Method::Head],
        Some(list) => list.into_iter().map(|m| http::Method::parse(m).ok_or(PluginError::BadValue("http.methods"))).collect::<Result<Vec<_>, _>>()?,
    };
    if methods.is_empty() {
        return Err(PluginError::BadValue("http.methods"));
    }
    if (1..methods.len()).any(|i| methods[..i].contains(&methods[i])) {
        return Err(PluginError::BadValue("http.methods"));
    }
    let auth = match table.get("auth") {
        None => None,
        Some(Value::Table(a)) => {
            only_keys(a, &["header", "format"])?;
            let header = string(a, "header", "http.auth.header")?;
            if !http::valid_auth_header(header) {
                return Err(PluginError::BadValue("http.auth.header"));
            }
            let format = http::parse_auth_format(string(a, "format", "http.auth.format")?).ok_or(PluginError::BadValue("http.auth.format"))?;
            Some(http::HttpAuth { header: header.to_string(), format })
        }
        Some(_) => return Err(PluginError::ManifestWrongType("http.auth")),
    };
    let session = match table.get("session") {
        None => None,
        Some(Value::Table(t)) => Some(http_session_table(t, &paths, api)?),
        Some(_) => return Err(PluginError::ManifestWrongType("http.session")),
    };
    Ok(Some(HttpSpec { paths, ports, methods, auth, session }))
}

/// `[http.session]` (API 1.3): every rule of `docs/design/VMW-ESXI.md` section 8, item 6.
fn http_session_table(t: &Table, paths: &[String], api: ApiVersion) -> Result<http_session::HttpSession, PluginError> {
    if api < (ApiVersion { major: 1, minor: 3 }) {
        return Err(PluginError::BadVersion("api"));
    }
    only_keys(t, &["login_path", "login_body", "content_type", "cookie", "logout_body", "ticket"])?;
    let login_path = string(t, "login_path", "http.session.login_path")?;
    if !http_session::valid_login_path(login_path, paths) {
        return Err(PluginError::BadValue("http.session.login_path"));
    }
    let content_type = string(t, "content_type", "http.session.content_type")?;
    if !http_session::valid_content_type(content_type) {
        return Err(PluginError::BadValue("http.session.content_type"));
    }
    let cookie = string(t, "cookie", "http.session.cookie")?;
    if !http_session::valid_cookie_name(cookie) {
        return Err(PluginError::BadValue("http.session.cookie"));
    }
    let login_body = string(t, "login_body", "http.session.login_body")?;
    if !http_session::valid_template(login_body, content_type, true) {
        return Err(PluginError::BadValue("http.session.login_body"));
    }
    let logout_body = match t.get("logout_body") {
        None => None,
        Some(Value::String(b)) if http_session::valid_template(b, content_type, false) => Some(b.clone()),
        Some(Value::String(_)) => return Err(PluginError::BadValue("http.session.logout_body")),
        Some(_) => return Err(PluginError::ManifestWrongType("http.session.logout_body")),
    };
    // API 1.4: the session value comes from the login answer's JSON body (Proxmox VE tickets).
    let ticket = match t.get("ticket") {
        None => None,
        Some(_) if api < (ApiVersion { major: 1, minor: 4 }) => return Err(PluginError::BadVersion("api")),
        Some(Value::String(p)) if content_type == "application/json" && http_session::valid_ticket_path(p) => Some(p.clone()),
        Some(Value::String(_)) => return Err(PluginError::BadValue("http.session.ticket")),
        Some(_) => return Err(PluginError::ManifestWrongType("http.session.ticket")),
    };
    Ok(http_session::HttpSession { login_path: login_path.to_string(), login_body: login_body.to_string(), content_type: content_type.to_string(), cookie: cookie.to_string(), logout_body, ticket })
}

fn field(table: &Table) -> Result<Field, PluginError> {
    only_keys(table, &["key", "label", "kind"])?;
    let key = local_id(table, "key", "connection_types.fields.key")?;
    let label = text(string(table, "label", "connection_types.fields.label")?, "connection_types.fields.label", MAX_FIELD_LABEL_CHARS)?;
    let kind = match string(table, "kind", "connection_types.fields.kind")? {
        "text" => FieldKind::Text,
        "number" => FieldKind::Number,
        "toggle" => FieldKind::Toggle,
        _ => return Err(PluginError::BadValue("connection_types.fields.kind")),
    };
    for text in [&key, &label] {
        if looks_like_secret(text) {
            return Err(PluginError::SecretLikeField(Excerpt::new(text.as_bytes())));
        }
    }
    Ok(Field { key, label, kind })
}

/// Words that name a secret (section 6, A1-C1.5). A plugin that needs a secret asks for
/// `credentials = "entry"`; this list is a speed bump, not the defence.
const SECRET_WORDS: [&str; 11] = ["password", "passwd", "pwd", "passphrase", "secret", "token", "apikey", "privatekey", "credential", "dsn", "connectionstring"];

/// True when a field key or label, lower-cased and without spaces, `_` and `-`, contains a
/// word of [`SECRET_WORDS`]. "Security mode" passes: it contains none of them.
pub(crate) fn looks_like_secret(text: &str) -> bool {
    let folded: String = text.chars().filter(|c| !matches!(c, ' ' | '_' | '-')).flat_map(char::to_lowercase).collect();
    SECRET_WORDS.iter().any(|word| folded.contains(word))
}

/// True when `text` contains "gantry" or the old product name "bastion", ignoring case
/// (section 6, A1-C11): such a name or publisher needs the official signature.
pub(crate) fn names_bastion(text: &str) -> bool {
    let folded = fold_for_name_check(text);
    folded.contains("gantry") || folded.contains("bastion")
}

/// Lower-case `text`, map full-width Latin and the Cyrillic and Greek letters that look like
/// Latin ones to ASCII, and drop everything that is not a letter or digit (spaces, punctuation,
/// zero-width and other format characters). Not a full confusables table: letters outside it
/// (for example from other scripts) still pass; the evidence file states this.
fn fold_for_name_check(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars().flat_map(char::to_lowercase) {
        let c = match c {
            '\u{FF41}'..='\u{FF5A}' => char::from_u32(c as u32 - 0xFF41 + 'a' as u32).unwrap_or(c),
            '\u{FF10}'..='\u{FF19}' => char::from_u32(c as u32 - 0xFF10 + '0' as u32).unwrap_or(c),
            'а' | 'α' => 'a',
            'в' | 'β' | 'ь' => 'b',
            'ѕ' => 's',
            'т' | 'τ' => 't',
            'і' | 'ї' | 'ι' | 'ı' | 'ӏ' => 'i',
            'о' | 'ο' | 'σ' | '0' => 'o',
            'п' | 'η' | 'ո' => 'n',
            '1' | 'l' | '|' => 'i',
            _ => c,
        };
        if c.is_alphanumeric() {
            out.push(c);
        }
    }
    out
}

fn connection_type(table: &Table, api: ApiVersion, http: Option<&HttpSpec>) -> Result<ConnectionType, PluginError> {
    only_keys(table, &["id", "name", "default_port", "fields", "sidebar", "login"])?;
    let id = local_id(table, "id", "connection_types.id")?;
    let name = text(string(table, "name", "connection_types.name")?, "connection_types.name", MAX_NAME_CHARS)?;
    let default_port = match table.get("default_port") {
        None => None,
        Some(Value::Integer(port)) => Some(u16::try_from(*port).ok().filter(|port| *port != 0).ok_or(PluginError::BadValue("connection_types.default_port"))?),
        Some(_) => return Err(PluginError::ManifestWrongType("connection_types.default_port")),
    };
    let fields = tables(table, "fields", "connection_types.fields")?.into_iter().map(field).collect::<Result<Vec<_>, _>>()?;
    unique(fields.iter().map(|f| &f.key), "connection_types.fields.key")?;
    let sidebar_tree = match table.get("sidebar") {
        None => false,
        Some(Value::String(s)) if s == "tree" => true,
        Some(Value::String(_)) => return Err(PluginError::BadValue("connection_types.sidebar")),
        Some(_) => return Err(PluginError::ManifestWrongType("connection_types.sidebar")),
    };
    if sidebar_tree && api < (ApiVersion { major: 1, minor: 3 }) {
        return Err(PluginError::BadVersion("api"));
    }
    if id == SIDEBAR_VIEW {
        return Err(PluginError::BadValue("connection_types.id"));
    }
    let named = match table.get("login") {
        None => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return Err(PluginError::ManifestWrongType("connection_types.login")),
    };
    let (has_auth, has_session) = (http.is_some_and(|h| h.auth.is_some()), http.is_some_and(|h| h.session.is_some()));
    let login = http_session::resolve_login(named, has_auth, has_session).map_err(PluginError::BadValue)?;
    Ok(ConnectionType { id, name, default_port, fields, sidebar_tree, login })
}

fn command(table: &Table, types: &[ConnectionType]) -> Result<Command, PluginError> {
    only_keys(table, &["id", "title", "on"])?;
    let id = local_id(table, "id", "commands.id")?;
    let title = text(string(table, "title", "commands.title")?, "commands.title", MAX_COMMAND_TITLE_CHARS)?;
    let on = match table.get("on") {
        None => None,
        Some(Value::String(target)) => {
            let type_id = target.strip_prefix("connection:").filter(|type_id| types.iter().any(|t| t.id == *type_id));
            Some(type_id.ok_or(PluginError::BadValue("commands.on"))?.to_string())
        }
        Some(_) => return Err(PluginError::ManifestWrongType("commands.on")),
    };
    Ok(Command { id, title, on })
}

/// Parse and check `plugin.toml`. Unknown keys are refused at every level.
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, PluginError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(PluginError::ManifestTooLarge);
    }
    let source = std::str::from_utf8(bytes).map_err(|_| PluginError::FileNotText("plugin.toml"))?;
    let root: Table = toml::from_str(source).map_err(|e| PluginError::ManifestSyntax(Excerpt::new(e.message().as_bytes())))?;
    only_keys(&root, &["schema", "id", "name", "version", "api", "publisher", "description", "license", "repository", "permissions", "http", "open", "exec", "connection_types", "commands"])?;
    match root.get("schema") {
        None => return Err(PluginError::ManifestMissingKey("schema")),
        Some(Value::Integer(SCHEMA)) => {}
        Some(Value::Integer(_)) => return Err(PluginError::ManifestSchema),
        Some(_) => return Err(PluginError::ManifestWrongType("schema")),
    }
    let id = string(&root, "id", "id")?;
    if !is_plugin_id(id) {
        return Err(PluginError::BadId("id"));
    }
    let name = text(string(&root, "name", "name")?, "name", MAX_NAME_CHARS)?;
    let version = Version::parse(string(&root, "version", "version")?).ok_or(PluginError::BadVersion("version"))?;
    let api = ApiVersion::parse(string(&root, "api", "api")?).ok_or(PluginError::BadVersion("api"))?;
    let publisher = text(string(&root, "publisher", "publisher")?, "publisher", MAX_PUBLISHER_CHARS)?;
    let description = text(string(&root, "description", "description")?, "description", MAX_DESCRIPTION_CHARS)?;
    let license = text(string(&root, "license", "license")?, "license", MAX_LICENSE_CHARS)?;
    let repository = text(string(&root, "repository", "repository")?, "repository", MAX_REPOSITORY_CHARS)?;
    if !is_https_address(&repository) {
        return Err(PluginError::BadValue("repository"));
    }
    let permissions = permissions(&root)?;
    if permissions.library_propose && api < LIBRARY_API {
        return Err(PluginError::BadVersion("api"));
    }
    let http = http_spec(&root, &permissions, api)?;
    let open = open_spec(&root, &permissions, api)?;
    let exec = exec_spec(&root, &permissions, api)?;
    let connection_types = tables(&root, "connection_types", "connection_types")?.into_iter().map(|t| connection_type(t, api, http.as_ref())).collect::<Result<Vec<_>, _>>()?;
    unique(connection_types.iter().map(|t| &t.id), "connection_types.id")?;
    let commands = tables(&root, "commands", "commands")?.into_iter().map(|table| command(table, &connection_types)).collect::<Result<Vec<_>, _>>()?;
    unique(commands.iter().map(|c| &c.id), "commands.id")?;
    Ok(Manifest { id: id.to_string(), name, version, api, publisher, description, license, repository, permissions, http, open, exec, connection_types, commands })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_http(api: &str, permissions: &str, http: &str) -> Result<Manifest, PluginError> {
        let text = format!(
            "schema = 1\nid = \"com.example.pve\"\nname = \"PVE\"\nversion = \"1.0.0\"\napi = \"{api}\"\npublisher = \"Ex\"\ndescription = \"d\"\nlicense = \"MIT\"\nrepository = \"https://example.com/r\"\n[permissions]\n{permissions}\n{http}"
        );
        parse_manifest(text.as_bytes())
    }

    const EXEC: &str = "[[exec]]\nid = \"ps\"\nargv = [\"docker\", \"ps\", \"--format\", \"{{json .}}\"]\n[[exec]]\nid = \"stop\"\nargv = [\"docker\", \"stop\", \"{id}\"]\nargs = { id = \"name\" }\nchanges = true\n";

    #[test]
    fn exec_templates_need_api_1_5_the_permission_and_valid_argv() {
        let m = with_http("1.5", "exec = \"entry\"", EXEC).unwrap();
        assert!(m.permissions.exec_entry);
        let spec = m.exec.unwrap();
        assert_eq!(spec.templates.len(), 2);
        assert!(spec.get("stop").unwrap().changes);
        assert_eq!(spec.get("ps").unwrap().display(), "docker ps --format '{{json .}}'");
        assert!(with_http("1.4", "exec = \"entry\"", EXEC).is_err(), "before API 1.5");
        assert!(with_http("1.5", "", EXEC).is_err(), "templates without the permission");
        assert!(with_http("1.5", "exec = \"entry\"", "").is_err(), "the permission without templates");
        assert!(with_http("1.5", "exec = \"any\"", EXEC).is_err());
        let bad = |t: &str| with_http("1.5", "exec = \"entry\"", &format!("[[exec]]\nid = \"x\"\n{t}")).is_err();
        assert!(bad("argv = [\"{id}\"]\nargs = { id = \"name\" }"), "program is a placeholder");
        assert!(bad("argv = [\"docker\", \"{id}\"]"), "placeholder without a kind");
        assert!(bad("argv = [\"docker\", \"{id}\"]\nargs = { id = \"shell\" }"), "unknown kind");
        assert!(bad("argv = [\"docker\", \"a\\tb\"]"), "control character");
        assert!(bad("argv = [\"docker\", \"exec\", \"-it\", \"{id}\", \"sh\"]\nargs = { id = \"name\" }\ninteractive = true"), "a shell must be marked as a change");
        assert!(bad("argv = [\"docker\"]\nshell = true"), "unknown key");
        assert!(with_http("1.5", "exec = \"entry\"", &format!("{EXEC}[[exec]]\nid = \"ps\"\nargv = [\"docker\"]\n")).is_err(), "duplicate id");
    }

    #[test]
    fn a_sidebar_tree_needs_api_1_3_and_the_word_tree() {
        let ty = |extra: &str| format!("[[connection_types]]\nid = \"vc\"\nname = \"VC\"\n{extra}");
        let m = with_http("1.3", "", &ty("sidebar = \"tree\"")).unwrap();
        assert!(m.connection_types[0].sidebar_tree);
        assert!(!with_http("1.3", "", &ty("")).unwrap().connection_types[0].sidebar_tree, "off by default");
        assert!(with_http("1.2", "", &ty("sidebar = \"tree\"")).is_err(), "before API 1.3");
        assert!(with_http("1.3", "", &ty("sidebar = \"list\"")).is_err(), "only tree");
        assert!(with_http("1.3", "", &ty("sidebar = true")).is_err(), "a string");
        assert!(with_http("1.3", "", "[[connection_types]]\nid = \"sidebar\"\nname = \"S\"\n").is_err(), "the view name is reserved");
    }

    const SOAP_LOGIN: &str = "<Envelope><Body><Login><userName>{user}</userName><password>{secret}</password></Login></Body></Envelope>";

    fn session_http(session_extra: &str, types: &str) -> String {
        format!(
            "[http]\npaths = [\"/api/vcenter/\", \"/sdk/\"]\nmethods = [\"GET\", \"POST\"]\nauth = {{ header = \"Authorization\", format = \"basic\" }}\n[http.session]\nlogin_path = \"/sdk\"\nlogin_body = \"{SOAP_LOGIN}\"\ncontent_type = \"text/xml\"\ncookie = \"vmware_soap_session\"\n{session_extra}{types}"
        )
    }

    #[test]
    fn each_connection_type_resolves_to_one_login_method() {
        let types = "[[connection_types]]\nid = \"vcenter\"\nname = \"V\"\nlogin = \"auth\"\n[[connection_types]]\nid = \"esxi\"\nname = \"E\"\nlogin = \"session\"\n";
        let m = with_http("1.3", "http = \"entry\"", &session_http("", types)).unwrap();
        assert_eq!(m.connection_types[0].login, Some(http_session::LoginMethod::Auth), "a vcenter type never gets the session");
        assert_eq!(m.connection_types[1].login, Some(http_session::LoginMethod::Session), "an esxi type never gets Basic");
        assert_eq!(m.http.unwrap().session.unwrap().cookie, "vmware_soap_session");
        // Both defined and no choice; an unknown method.
        assert!(with_http("1.3", "http = \"entry\"", &session_http("", "[[connection_types]]\nid = \"x\"\nname = \"X\"\n")).is_err());
        assert!(with_http("1.3", "http = \"entry\"", &session_http("", "[[connection_types]]\nid = \"x\"\nname = \"X\"\nlogin = \"cookie\"\n")).is_err());
        assert!(with_http("1.3", "http = \"entry\"", &session_http("", "[[connection_types]]\nid = \"x\"\nname = \"X\"\nlogin = 1\n")).is_err());
        // Session without [http.session]; auth without auth.
        let plain = "[http]\npaths = [\"/sdk/\"]\nauth = { header = \"Authorization\", format = \"basic\" }\n[[connection_types]]\nid = \"x\"\nname = \"X\"\nlogin = \"session\"\n";
        assert!(with_http("1.3", "http = \"entry\"", plain).is_err());
        // No http at all: no login.
        assert_eq!(with_http("1.3", "", "[[connection_types]]\nid = \"x\"\nname = \"X\"\n").unwrap().connection_types[0].login, None);
        // An auth-only manifest keeps working as before.
        let pve = "[http]\npaths = [\"/api2/json/\"]\nauth = { header = \"Authorization\", format = \"bearer\" }\n[[connection_types]]\nid = \"x\"\nname = \"X\"\n";
        assert_eq!(with_http("1.1", "http = \"entry\"", pve).unwrap().connection_types[0].login, Some(http_session::LoginMethod::Auth));
    }

    #[test]
    fn the_official_vmware_manifest_passes_with_one_method_per_type() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../plugins/official/vmware/plugin.toml");
        let m = parse_manifest(&std::fs::read(path).unwrap()).unwrap();
        let login = |id: &str| m.connection_types.iter().find(|t| t.id == id).unwrap().login;
        assert_eq!(login("vcenter"), Some(http_session::LoginMethod::Auth));
        assert_eq!(login("esxi"), Some(http_session::LoginMethod::Session));
        let s = m.http.unwrap().session.unwrap();
        assert_eq!((s.login_path.as_str(), s.cookie.as_str()), ("/sdk", "vmware_soap_session"));
        assert!(s.logout_body.is_some());
    }

    #[test]
    fn the_official_docker_manifest_passes_with_changes_marked() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../plugins/official/docker/plugin.toml");
        let m = parse_manifest(&std::fs::read(path).unwrap()).unwrap();
        assert!(m.permissions.exec_entry && !m.permissions.http_entry && !m.permissions.network_entry && !m.permissions.credentials_entry);
        let spec = m.exec.unwrap();
        for id in ["start", "stop", "restart", "remove", "shell"] {
            assert!(spec.get(id).unwrap().changes, "{id}");
        }
        for id in ["version", "ps", "stats", "images", "volumes", "networks", "logs"] {
            assert!(!spec.get(id).unwrap().changes, "{id}");
        }
        assert!(spec.get("shell").unwrap().interactive);
        assert_eq!(spec.get("logs").unwrap().display(), "docker logs --timestamps --tail <count> <name>");
        // The exact lines the app sends; `plugins/official/docker/tests/live.rs` runs the same ones.
        let line = |id: &str, args: &[(&str, &str)]| {
            let args: Vec<(String, String)> = args.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            exec_rules::command_line(&spec.get(id).unwrap().build(&args).unwrap())
        };
        assert_eq!(line("version", &[]), "docker version --format '{{json .Server.Version}}'");
        assert_eq!(line("ps", &[]), "docker ps --all --no-trunc --format '{{json .}}'");
        assert_eq!(line("stats", &[]), "docker stats --no-stream --no-trunc --format '{{json .}}'");
        assert_eq!(line("images", &[]), "docker image ls --no-trunc --format '{{json .}}'");
        assert_eq!(line("volumes", &[]), "docker volume ls --format '{{json .}}'");
        assert_eq!(line("networks", &[]), "docker network ls --no-trunc --format '{{json .}}'");
        assert_eq!(line("logs", &[("lines", "500"), ("id", "web")]), "docker logs --timestamps --tail 500 web");
        assert_eq!(line("shell", &[("id", "web")]), "docker exec -it web sh");
    }

    #[test]
    fn the_official_proxmox_manifest_offers_changes_only_on_token_entries() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../plugins/official/proxmox/plugin.toml");
        let m = parse_manifest(&std::fs::read(path).unwrap()).unwrap();
        let ty = |id: &str| m.connection_types.iter().find(|t| t.id == id).unwrap();
        assert!(ty("pve").fields.iter().any(|f| f.key == "allow-changes"));
        assert!(ty("pve-password").fields.is_empty(), "no CSRF token for ticket logins, so no changes");
        assert_eq!(m.http.unwrap().methods, vec![http::Method::Get, http::Method::Post, http::Method::Delete]);
    }

    #[test]
    fn the_official_kubernetes_manifest_passes_with_bearer_and_patch() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../plugins/official/kubernetes/plugin.toml");
        let m = parse_manifest(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(m.connection_types[0].login, Some(http_session::LoginMethod::Auth));
        let h = m.http.unwrap();
        assert!(h.methods.contains(&http::Method::Patch) && !h.methods.contains(&http::Method::Post));
        assert!(h.session.is_none());
    }

    #[test]
    fn a_json_ticket_session_needs_api_1_4() {
        let pve = |api: &str, ticket: &str| {
            let http = format!("[http]\npaths = [\"/api2/json/\"]\nmethods = [\"GET\"]\n[http.session]\nlogin_path = \"/api2/json/access/ticket\"\nlogin_body = '{{\"username\":\"{{user}}\",\"password\":\"{{secret}}\"}}'\ncontent_type = \"application/json\"\ncookie = \"PVEAuthCookie\"\n{ticket}[[connection_types]]\nid = \"pve-password\"\nname = \"P\"\nlogin = \"session\"\n");
            with_http(api, "http = \"entry\"", &http)
        };
        let m = pve("1.4", "ticket = \"data.ticket\"\n").unwrap();
        assert_eq!(m.http.unwrap().session.unwrap().ticket.as_deref(), Some("data.ticket"));
        assert!(pve("1.3", "ticket = \"data.ticket\"\n").is_err(), "before API 1.4");
        assert!(pve("1.4", "ticket = \"data[0]\"\n").is_err());
        assert!(pve("1.4", "ticket = 1\n").is_err());
        assert!(pve("1.4", "").unwrap().http.unwrap().session.unwrap().ticket.is_none());
    }

    #[test]
    fn malicious_session_tables_are_refused() {
        let t = "[[connection_types]]\nid = \"esxi\"\nname = \"E\"\nlogin = \"session\"\n";
        assert!(with_http("1.2", "http = \"entry\"", &session_http("", t)).is_err(), "before API 1.3");
        let swap = |from: &str, to: &str| session_http("", t).replacen(from, to, 1);
        let bad = [
            swap("login_path = \"/sdk\"", "login_path = \"/other\""),
            swap("login_path = \"/sdk\"", "login_path = \"/sdk/../x\""),
            swap("content_type = \"text/xml\"", "content_type = \"text/html\""),
            swap("cookie = \"vmware_soap_session\"", "cookie = \"a b\""),
            swap("<password>{secret}</password>", "<password a='{secret}'/>"),
            swap("<Envelope>", "<!DOCTYPE x [<!ENTITY e 'y'>]><Envelope>"),
            swap("<password>{secret}</password>", "<password>&e;{secret}</password>"),
            swap("<password>{secret}</password>", "<password>{secret}{secret}</password>"),
            swap("<password>{secret}</password>", "<password></password>"),
            swap("</Envelope>", ""),
        ];
        for b in &bad {
            assert!(with_http("1.3", "http = \"entry\"", b).is_err(), "{b}");
        }
        assert!(with_http("1.3", "http = \"entry\"", &session_http("logout_body = \"<Logout>{secret}</Logout>\"\n", t)).is_err(), "a logout never holds the password");
        assert!(with_http("1.3", "http = \"entry\"", &session_http("logout_body = \"<Logout/>\"\n", t)).unwrap().http.unwrap().session.unwrap().logout_body.is_some());
        assert!(with_http("1.3", "http = \"entry\"", &session_http("extra = 1\n", t)).is_err(), "unknown key");
    }

    #[test]
    fn the_open_permission_and_table_need_api_1_2_and_strict_fields() {
        let http = "[http]\npaths = [\"/api2/json/\"]\n";
        let fields = "[open]\naddress_fields = [{ path = \"/api2/json/nodes/*/qemu/*/agent/network-get-interfaces\", fields = [\"data.result[].ip-addresses[].ip-address\"] }]\n";
        let m = with_http("1.2", "http = \"entry\"\nopen = [\"ssh\", \"rdp\"]", &format!("{http}{fields}")).unwrap();
        assert!(m.permissions.open_ssh && m.permissions.open_rdp && !m.permissions.open_vnc);
        assert_eq!(m.open.unwrap().address_fields[0].fields, vec!["data.result[].ip-addresses[].ip-address".to_string()]);
        // Without the table: allowed, with nothing reported.
        assert!(with_http("1.2", "http = \"entry\"\nopen = [\"vnc\"]", http).unwrap().open.is_none());
        // Before API 1.2, an unknown or repeated protocol, an empty list, a table without the
        // permission, fields without http, bad paths or fields.
        assert!(with_http("1.1", "http = \"entry\"\nopen = [\"ssh\"]", http).is_err());
        for bad in ["open = [\"telnet\"]", "open = [\"ssh\", \"ssh\"]", "open = []", "open = \"ssh\""] {
            assert!(with_http("1.2", &format!("http = \"entry\"\n{bad}"), http).is_err(), "{bad}");
        }
        assert!(with_http("1.2", "http = \"entry\"", &format!("{http}{fields}")).is_err(), "[open] without the permission");
        assert!(with_http("1.2", "open = [\"ssh\"]", fields).is_err(), "address fields need http");
        for bad_fields in [
            "[open]\naddress_fields = [{ path = \"/a/../b\", fields = [\"x\"] }]\n",
            "[open]\naddress_fields = [{ path = \"/a\", fields = [] }]\n",
            "[open]\naddress_fields = [{ path = \"/a\", fields = [\"a..b\"] }]\n",
            "[open]\naddress_fields = [{ path = \"/a\", fields = [\"x\"], extra = 1 }]\n",
            "[open]\nother = 1\n",
        ] {
            assert!(with_http("1.2", "http = \"entry\"\nopen = [\"ssh\"]", &format!("{http}{bad_fields}")).is_err(), "{bad_fields}");
        }
    }

    #[test]
    fn the_http_table_goes_with_the_http_permission_and_api_1_1() {
        let pve = "[http]\npaths = [\"/api2/json/\"]\nports = [8006]\nmethods = [\"GET\", \"POST\", \"DELETE\"]\nauth = { header = \"Authorization\", format = \"PVEAPIToken={user}={secret}\" }\n";
        let m = with_http("1.1", "http = \"entry\"", pve).unwrap();
        assert!(m.permissions.http_entry);
        let h = m.http.unwrap();
        assert_eq!(h.paths, vec!["/api2/json/".to_string()]);
        assert_eq!(h.ports, vec![8006]);
        assert!(h.may_change());
        assert_eq!(h.auth.unwrap().header, "Authorization");
        let read_only = with_http("1.1", "http = \"entry\"", "[http]\npaths = [\"/api/\"]\n").unwrap().http.unwrap();
        assert_eq!(read_only.methods, vec![http::Method::Get, http::Method::Head], "GET and HEAD by default");
        assert!(!read_only.may_change() && read_only.auth.is_none());
        // Without the permission, without the table, before API 1.1, or a wrong value.
        assert!(with_http("1.1", "", pve).is_err());
        assert!(with_http("1.1", "http = \"entry\"", "").is_err());
        assert!(with_http("1.0", "http = \"entry\"", pve).is_err());
        assert!(with_http("1.1", "http = \"any\"", pve).is_err());
        for bad in [
            "[http]\npaths = []\n",
            "[http]\npaths = [\"/a\"]\n",
            "[http]\npaths = [\"/a/../\"]\n",
            "[http]\npaths = [\"/a/\", \"/a/\"]\n",
            "[http]\npaths = [\"/a/\"]\nmethods = [\"TRACE\"]\n",
            "[http]\npaths = [\"/a/\"]\nmethods = [\"get\"]\n",
            "[http]\npaths = [\"/a/\"]\nmethods = []\n",
            "[http]\npaths = [\"/a/\"]\nmethods = [\"GET\", \"GET\"]\n",
            "[http]\npaths = [\"/a/\"]\nports = [0]\n",
            "[http]\npaths = [\"/a/\"]\nports = [80, 80]\n",
            "[http]\npaths = [\"/a/\"]\nauth = { header = \"Cookie\", format = \"bearer\" }\n",
            "[http]\npaths = [\"/a/\"]\nauth = { header = \"Authorization\", format = \"{user}\" }\n",
            "[http]\npaths = [\"/a/\"]\nauth = { header = \"Authorization\", format = \"bearer\", kind = \"x\" }\n",
            "[http]\npaths = [\"/a/\"]\nhosts = [\"evil.example\"]\n",
        ] {
            assert!(with_http("1.1", "http = \"entry\"", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_bastion_name_check_sees_through_spacing_homoglyphs_and_zero_width() {
        for name in ["Bastion", "BASTION Tools", "Bаstion", "Bas tion", "B.a.s.t.i.o.n", "Bas\u{200B}tion", "Ｂａｓｔｉｏｎ", "Bast1on", "Bastiοn", "Ваstion"] {
            assert!(names_bastion(name), "{name}");
        }
        for name in ["Example Tools", "Postgres", "Bastide", "Sebastian"] {
            assert!(!names_bastion(name), "{name}");
        }
        for name in ["Gantry", "GANTRY Tools", "Gan try", "G.a.n.t.r.y"] {
            assert!(names_bastion(name), "{name}");
        }
    }

    #[test]
    fn the_legacy_namespace_maps_onto_dev_gantry() {
        assert!(is_reserved_id("dev.gantry") && is_reserved_id("dev.gantry.proxmox") && !is_reserved_id("dev.gantryx.a"));
        assert_eq!(canonical_plugin_id("dev.bastion.postgres"), "dev.gantry.postgres");
        assert_eq!(canonical_plugin_id("dev.bastion.postgres/postgres"), "dev.gantry.postgres/postgres");
        assert_eq!(canonical_plugin_id("dev.gantry.vmware"), "dev.gantry.vmware");
        assert_eq!(canonical_plugin_id("dev.bastionx.a"), "dev.bastionx.a");
        assert_eq!(canonical_plugin_id("com.example.tool"), "com.example.tool");
    }

    #[test]
    fn versions_parse_strictly_and_order_numerically() {
        assert_eq!(Version::parse("1.2.3"), Some(Version { major: 1, minor: 2, patch: 3 }));
        assert_eq!(Version::parse("0.0.0"), Some(Version { major: 0, minor: 0, patch: 0 }));
        assert!(Version::parse("0.10.0") > Version::parse("0.9.9"));
        assert!(Version::parse("2.0.0") > Version::parse("1.99.99"));
        for bad in ["", "1", "1.2", "1.2.3.4", "1.2.3-rc1", "1.2.3+b", "01.2.3", "1.2.", ".1.2", "1..2", "1.2.x", " 1.2.3", "1.2.3 ", "+1.2.3", "1.2.4294967296", "1.2.1000000000"] {
            assert_eq!(Version::parse(bad), None, "`{bad}`");
        }
        assert_eq!(Version::parse("1.2.999999999").map(|v| v.to_string()).as_deref(), Some("1.2.999999999"));
        assert_eq!(ApiVersion::parse("1.0"), Some(ApiVersion { major: 1, minor: 0 }));
        assert!(ApiVersion::parse("1.10") > ApiVersion::parse("1.9"));
        assert_eq!(ApiVersion::parse("1.0.0"), None);
    }

    #[test]
    fn ids_follow_the_reverse_dns_rule() {
        for good in ["dev.bastion.postgres", "com.example.tool", "io.github.some-author.tool2", "a.b"] {
            assert!(is_plugin_id(good), "{good}");
        }
        for bad in ["", "tool", "com.", ".com", "com..x", "Com.example", "com.Example", "com.1x", "com.x-", "com.-x", "com.x_y", "com.x y", "com.x\n", "com.é"] {
            assert!(!is_plugin_id(bad), "`{bad}`");
        }
        assert!(is_plugin_id(&format!("com.{}", "a".repeat(32))) && !is_plugin_id(&format!("com.{}", "a".repeat(33))));
        assert!(!is_plugin_id(&["abcdefgh"; 8].join(".")), "longer than 64 bytes");
        assert!(is_reserved_id("dev.bastion") && is_reserved_id("dev.bastion.postgres") && is_reserved_id("dev.bastion.a.b"));
        assert!(!is_reserved_id("dev.bastionx.tool") && !is_reserved_id("dev.bastio") && !is_reserved_id("com.dev.bastion.tool"));
    }

    #[test]
    fn permissions_accept_only_the_listed_values() {
        let all = Permissions::from_parts(Some("entry"), Some("entry"), Some(true), Some("write"), Some(&["open", "save"]), None, None, None).unwrap();
        assert!(all.network_entry && all.credentials_entry && all.storage && all.clipboard_write && all.files_save && all.files_open);
        assert_eq!(Permissions::from_parts(None, None, None, None, None, None, None, None), Ok(Permissions::default()));
        assert_eq!(Permissions::from_parts(None, None, Some(false), None, Some(&[]), None, None, None), Ok(Permissions::default()));
        assert_eq!(Permissions::from_parts(Some("Entry"), None, None, None, None, None, None, None), Err("network"));
        assert_eq!(Permissions::from_parts(None, Some("any"), None, None, None, None, None, None), Err("credentials"));
        assert_eq!(Permissions::from_parts(None, None, None, Some("read"), None, None, None, None), Err("clipboard"));
        assert_eq!(Permissions::from_parts(None, None, None, None, Some(&["open", "open"]), None, None, None), Err("files"));
        assert_eq!(Permissions::from_parts(None, None, None, None, Some(&["all"]), None, None, None), Err("files"));
    }

    #[test]
    fn hidden_and_reordering_characters_count_as_control_characters() {
        for c in ['\0', '\n', '\t', '\u{7f}', '\u{85}', '\u{200B}', '\u{200E}', '\u{202E}', '\u{2028}', '\u{2066}', '\u{FEFF}'] {
            assert!(is_forbidden(c), "{c:?}");
        }
        for c in [' ', 'a', 'é', '日', '-', '\u{2019}'] {
            assert!(!is_forbidden(c), "{c:?}");
        }
        assert!(is_https_address("https://example.test/x") && !is_https_address("https://") && !is_https_address("https://a b") && !is_https_address("http://example.test"));
    }

    #[test]
    fn the_windows_exec_fixture_manifest_parses() {
        let m = parse_manifest(include_bytes!("../../../apps/windows/tests/fixtures/exec-plugin/plugin.toml")).expect("exec fixture manifest");
        assert_eq!(m.exec.as_ref().unwrap().templates.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(), ["hello", "wait", "term"]);
    }

    /// Every Windows test fixture manifest parses, and an unsigned one (an id outside
    /// `dev.gantry` or the legacy `dev.bastion`) uses no reserved name in its name or publisher:
    /// "Gantry", nor the old "Bastion". Either would make the app refuse to install it.
    #[test]
    fn every_windows_fixture_manifest_installs_unsigned_or_is_official() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../apps/windows/tests/fixtures");
        let mut checked = 0;
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let toml = e.path().join("plugin.toml");
            let Ok(bytes) = std::fs::read(&toml) else { continue };
            let m = parse_manifest(&bytes).unwrap_or_else(|err| panic!("{}: {err}", toml.display()));
            checked += 1;
            if is_reserved_id(&m.id) {
                continue;
            }
            for text in [&m.name, &m.publisher] {
                let folded = fold_for_name_check(text);
                assert!(!names_bastion(text) && !folded.contains("gantry"), "{}: unsigned fixture uses a reserved name: {text}", toml.display());
            }
        }
        assert!(checked >= 2, "fixtures found: {checked}");
    }

    #[test]
    fn library_permission_needs_api_1_6_and_one_value() {
        let m = |api: &str, perm: &str| with_http(api, perm, "");
        assert!(m("1.6", "library = \"propose\"").unwrap().permissions.library_propose);
        assert!(matches!(m("1.5", "library = \"propose\""), Err(PluginError::BadVersion("api"))));
        assert!(matches!(m("1.6", "library = \"write\""), Err(PluginError::BadPermission("library"))));
        assert!(!m("1.6", "").unwrap().permissions.library_propose);
    }


    /// The Windows Docker fixture runs the official plugin's wasm with a test id: its commands must
    /// stay exactly the official ones.
    #[test]
    fn the_windows_docker_fixture_declares_the_official_commands() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let read = |p: &str| parse_manifest(&std::fs::read(root.join(p)).unwrap()).unwrap();
        let official = read("plugins/official/docker/plugin.toml");
        let fixture = read("apps/windows/tests/fixtures/docker-plugin/plugin.toml");
        let lines = |m: &Manifest| m.exec.as_ref().unwrap().templates.iter().map(|t| (t.id.clone(), t.display(), t.changes, t.interactive)).collect::<Vec<_>>();
        assert_eq!(lines(&fixture), lines(&official));
        assert_eq!(fixture.connection_types.len(), official.connection_types.len());
    }
}
