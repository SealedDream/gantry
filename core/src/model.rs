//! Connection document model and folder-default inheritance.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::error::{CoreError, Result};
pub use crate::unknown::{Extra, TypeDefaults, NEEDS_NEWER};

#[path = "model_serde.rs"]
mod serde_io;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Ssh,
    Rdp,
    Vnc,
    Sftp,
    Scp,
    Ftp,
    Ftps,
    Web,
    Telnet,
    Serial,
    /// A shell on this computer (`localshell`); `host` is unused.
    Local,
    /// Read-only service list over SSH (`sysview`, Linux systemd or Windows).
    Services,
    /// Read-only, auto-refreshing process list over SSH (`sysview`).
    Processes,
    /// Live, read-only log tail over SSH: journal on Linux, event log on Windows (`sysview`).
    EventLog,
    /// Stands in for a connection type this app does not know (written by a newer Bastion or a
    /// plugin, PLUG-03a). It has no name of its own on the wire: the entry keeps the stored name
    /// in `Connection::unknown_protocol`. It is not in [`Protocol::ALL`], cannot be created by
    /// name, and nothing connects to it.
    #[serde(skip)]
    Unsupported,
}

impl Protocol {
    /// Every variant, in declaration order.
    pub const ALL: [Protocol; 14] = [
        Protocol::Ssh, Protocol::Rdp, Protocol::Vnc, Protocol::Sftp, Protocol::Scp, Protocol::Ftp, Protocol::Ftps,
        Protocol::Web, Protocol::Telnet, Protocol::Serial, Protocol::Local, Protocol::Services, Protocol::Processes, Protocol::EventLog,
    ];

    /// The known connection type with this wire name; `None` for a name this app does not know.
    /// The type a request names (Test Connection sends the name from the dialog or the row),
    /// in any case. A name this app does not know gets the fixed text, like every other use of
    /// an entry of an unknown type.
    pub fn for_request(name: &str) -> Result<Protocol> {
        Protocol::from_wire(&name.to_ascii_lowercase()).ok_or_else(|| CoreError::Invalid(NEEDS_NEWER.into()))
    }

    pub fn from_wire(name: &str) -> Option<Protocol> {
        Some(match name {
            "ssh" => Protocol::Ssh,
            "rdp" => Protocol::Rdp,
            "vnc" => Protocol::Vnc,
            "sftp" => Protocol::Sftp,
            "scp" => Protocol::Scp,
            "ftp" => Protocol::Ftp,
            "ftps" => Protocol::Ftps,
            "web" => Protocol::Web,
            "telnet" => Protocol::Telnet,
            "serial" => Protocol::Serial,
            "local" => Protocol::Local,
            "services" => Protocol::Services,
            "processes" => Protocol::Processes,
            "eventlog" => Protocol::EventLog,
            _ => return None,
        })
    }

    /// The wire name, identical to the serde encoding (`Protocol::EventLog` → `eventlog`, H16).
    /// `Unsupported` has no wire name; an entry's stored name is `Connection::protocol_name`.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Ssh => "ssh",
            Protocol::Rdp => "rdp",
            Protocol::Vnc => "vnc",
            Protocol::Sftp => "sftp",
            Protocol::Scp => "scp",
            Protocol::Ftp => "ftp",
            Protocol::Ftps => "ftps",
            Protocol::Web => "web",
            Protocol::Telnet => "telnet",
            Protocol::Serial => "serial",
            Protocol::Local => "local",
            Protocol::Services => "services",
            Protocol::Processes => "processes",
            Protocol::EventLog => "eventlog",
            Protocol::Unsupported => "unsupported",
        }
    }

    pub fn default_port(self) -> Option<u16> {
        Some(match self {
            Protocol::Ssh | Protocol::Sftp | Protocol::Scp | Protocol::Services | Protocol::Processes | Protocol::EventLog => 22,
            Protocol::Rdp => 3389,
            Protocol::Vnc => 5900,
            Protocol::Ftp | Protocol::Ftps => 21,
            Protocol::Web => 443,
            Protocol::Telnet => 23,
            Protocol::Serial | Protocol::Local | Protocol::Unsupported => return None,
        })
    }

    /// The icon shown for a connection that has none of its own.
    pub fn default_icon(self) -> &'static str {
        match self {
            Protocol::Rdp | Protocol::Vnc => "desktop",
            Protocol::Web => "globe",
            Protocol::Sftp | Protocol::Scp | Protocol::Ftp | Protocol::Ftps => "storage",
            Protocol::Serial | Protocol::Unsupported => "network",
            Protocol::Services | Protocol::Processes | Protocol::EventLog => "cluster",
            Protocol::Ssh | Protocol::Telnet | Protocol::Local => "terminal",
        }
    }
}

/// Icon names a connection may carry. Every UI maps a name to its own glyph; anything else in
/// `Connection.icon` (older or hand-edited files) is ignored and the protocol default is shown.
pub const ICONS: &[&str] = &["server", "desktop", "terminal", "database", "network", "cloud", "container", "globe", "shield", "storage"];

/// Prefix that marks user-editable metadata. Every other `metadata` key is an internal binding
/// (`VaultwardenItem`, `SshKeyFile`, `SshConfigIdentity`, `ProxyJump`, …) that only the code
/// owning it may change, so a free-form editor can never rewrite credential or source bindings.
pub const USER_METADATA_PREFIX: &str = "user.";
pub const MAX_USER_METADATA: usize = 32;
/// Connection metadata: `password` or `ssh-key` when the connection has an inline secret in the
/// vault (`vault::Vault::inline`). Only a marker, so the UI knows without opening the vault;
/// the secret itself is never in the library, and exports drop the marker.
pub const INLINE_CREDENTIAL_KEY: &str = "InlineCredential";
pub const MAX_USER_METADATA_KEY: usize = 64;
pub const MAX_USER_METADATA_VALUE: usize = 1024;

/// Settings that may be set on a connection or inherited from an ancestor folder.
/// `None` means "inherit".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct Settings {
    pub port: Option<u16>,
    pub username: Option<String>,
    pub credential_id: Option<Uuid>,
    /// Name of a vault credential, looked up when connecting (Royal TS "Specify a credential
    /// name"): survives sharing a library with someone whose vault has other ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_name: Option<String>,
    pub gateway_id: Option<Uuid>,
    pub auto_reconnect: Option<bool>,
    pub keepalive_secs: Option<u32>,
    /// Terminal colour theme id (`termthemes`), overriding the app-wide one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_theme: Option<String>,
    /// Terminal font family (`termfonts`), overriding `terminal.font-family`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_font_family: Option<String>,
    /// Terminal font size in points, overriding `terminal.font-size`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_font_size: Option<u32>,
    /// Programming ligatures on or off, overriding `terminal.ligatures`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_ligatures: Option<bool>,
    /// Opt-in: write this connection's terminal output to a session log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_log: Option<bool>,
    /// Folder that holds this connection's session logs, overriding `logging.session-log-folder` (LOG-CORE-02).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_log_folder: Option<String>,
    /// Days this folder's session logs are kept, overriding `logging.session-log-keep-days`
    /// (0: forever; LOG-CORE-02).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_log_keep_days: Option<u32>,
    /// Hide this connection's tab hover preview and Overview tile image (B11): sensitive hosts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_preview: Option<bool>,
    /// Web: offer "Fill sign-in" in the tab (B13). Off unless set; managed policy can forbid it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_autofill: Option<bool>,
    /// RDP: refuse servers that do not offer Network Level Authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_nla_only: Option<bool>,
    /// RDP: share text copied on either side (built-in default on, like mstsc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_clipboard: Option<bool>,
    /// RDP: play the server's sound on this computer (built-in default on, like mstsc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_audio: Option<bool>,
    /// RDP: absolute path of a local folder shared with the server as drive "Gantry".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdp_shared_folder: Option<String>,
    /// Colour of the automatic tab group for this folder's connections (`tabgroups::GroupColor` id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tab_group_color: Option<String>,
    /// Per-host accent `#rrggbb` (`hostcolors`) for the tab, terminal border and tree badge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_color: Option<String>,
    /// SSH: algorithm lists and weak opt-in (Advanced → Algorithms), inherited as a unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_algorithms: Option<crate::algorithms::AlgorithmSettings>,
    /// Wake-on-LAN: the host's MAC address (`wol::Mac` form). No MAC means no Wake action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_mac: Option<String>,
    /// Wake-on-LAN: LAN broadcast address or subnet (`wol::parse_broadcast`); unset is 255.255.255.255.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_broadcast: Option<String>,
    /// Wake-on-LAN: UDP port; unset is 9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_port: Option<u16>,
    /// Wake-on-LAN: SecureOn password, six hex bytes. Sent in clear on the LAN by design.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_secureon: Option<String>,
    /// Wake-on-LAN: send the packet and wait for the host before connecting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_before_connect: Option<bool>,
    /// Wake-on-LAN: seconds to wait for the host after waking it; unset is 60.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wol_wait_secs: Option<u32>,
    /// Opt-in: show this connection on the host status dashboard (`hoststatus`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_status: Option<bool>,
    /// Serial: port to open (`/dev/cu.*`, `COM3`). Checked by `serial::validate_port` on open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_port: Option<String>,
    /// Serial: baud rate; unset is 9600.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_baud: Option<u32>,
    /// Serial: data bits 5-8; unset is 8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_data_bits: Option<u8>,
    /// Serial: `none`, `odd` or `even`; unset is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_parity: Option<String>,
    /// Serial: stop bits 1 or 2; unset is 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_stop_bits: Option<u8>,
    /// Serial: `none`, `software` or `hardware`; unset is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_flow: Option<String>,
    /// Serial: show typed characters locally; unset is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_local_echo: Option<bool>,
    /// Serial: what Enter sends, `cr`, `lf` or `crlf`; unset is cr.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_enter: Option<String>,
    /// Telnet: type the saved password after the login prompt (cleartext). Connections only;
    /// never inherited, so a folder or type default cannot turn it on (B7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telnet_send_password: Option<bool>,
    /// A connection's other saved logins besides `credential_id` (its default), in the order they
    /// were added (`logins`, owner point W23). Connections only; never inherited.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logins: Vec<Uuid>,
    /// Folders only: saved logins are not shared across this folder's edge (`logins`, A1-CORE-01).
    /// A connection inside is offered logins saved for the same host only by connections that
    /// are inside too. Every top-level folder is such an edge without it. Never inherited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_boundary: Option<bool>,
    /// The credential reference on this node (`credential_id`, `credential_name`, `logins`)
    /// came with a received library and the user has not chosen it yet: it is offered, never
    /// used automatically (`logins`, A1-CORE-01-FU1). Never inherited; not written when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_unconfirmed: Option<bool>,
    /// On a node that carries `credential_unconfirmed`: the credentials the user has chosen
    /// for it since. Those are used without asking; the rest of what arrived stays offered.
    /// Never inherited; not written when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_confirmed: Vec<Uuid>,
    /// Settings this app does not know, kept as read and written back unchanged (PLUG-03a).
    /// Never inherited and never interpreted.
    #[serde(flatten, skip_deserializing)]
    pub extra: Extra,
}

crate::unknown::keeps_unknown_fields!(Settings);

impl Settings {
    /// Fill unset fields from `parent`, returning a new value.
    pub fn inherit_from(&self, parent: &Settings) -> Settings {
        Settings {
            port: self.port.or(parent.port),
            username: self.username.clone().or_else(|| parent.username.clone()),
            credential_id: self.credential_id.or(parent.credential_id),
            credential_name: self.credential_name.clone().or_else(|| parent.credential_name.clone()),
            gateway_id: self.gateway_id.or(parent.gateway_id),
            auto_reconnect: self.auto_reconnect.or(parent.auto_reconnect),
            keepalive_secs: self.keepalive_secs.or(parent.keepalive_secs),
            terminal_theme: self.terminal_theme.clone().or_else(|| parent.terminal_theme.clone()),
            terminal_font_family: self.terminal_font_family.clone().or_else(|| parent.terminal_font_family.clone()),
            terminal_font_size: self.terminal_font_size.or(parent.terminal_font_size),
            terminal_ligatures: self.terminal_ligatures.or(parent.terminal_ligatures),
            session_log: self.session_log.or(parent.session_log),
            session_log_folder: self.session_log_folder.clone().or_else(|| parent.session_log_folder.clone()),
            session_log_keep_days: self.session_log_keep_days.or(parent.session_log_keep_days),
            no_preview: self.no_preview.or(parent.no_preview),
            web_autofill: self.web_autofill.or(parent.web_autofill),
            rdp_nla_only: self.rdp_nla_only.or(parent.rdp_nla_only),
            rdp_clipboard: self.rdp_clipboard.or(parent.rdp_clipboard),
            rdp_audio: self.rdp_audio.or(parent.rdp_audio),
            rdp_shared_folder: self.rdp_shared_folder.clone().or_else(|| parent.rdp_shared_folder.clone()),
            tab_group_color: self.tab_group_color.clone().or_else(|| parent.tab_group_color.clone()),
            host_color: self.host_color.clone().or_else(|| parent.host_color.clone()),
            ssh_algorithms: self.ssh_algorithms.clone().or_else(|| parent.ssh_algorithms.clone()),
            wol_mac: self.wol_mac.clone().or_else(|| parent.wol_mac.clone()),
            wol_broadcast: self.wol_broadcast.clone().or_else(|| parent.wol_broadcast.clone()),
            wol_port: self.wol_port.or(parent.wol_port),
            wol_secureon: self.wol_secureon.clone().or_else(|| parent.wol_secureon.clone()),
            wol_before_connect: self.wol_before_connect.or(parent.wol_before_connect),
            wol_wait_secs: self.wol_wait_secs.or(parent.wol_wait_secs),
            host_status: self.host_status.or(parent.host_status),
            serial_port: self.serial_port.clone().or_else(|| parent.serial_port.clone()),
            serial_baud: self.serial_baud.or(parent.serial_baud),
            serial_data_bits: self.serial_data_bits.or(parent.serial_data_bits),
            serial_parity: self.serial_parity.clone().or_else(|| parent.serial_parity.clone()),
            serial_stop_bits: self.serial_stop_bits.or(parent.serial_stop_bits),
            serial_flow: self.serial_flow.clone().or_else(|| parent.serial_flow.clone()),
            serial_local_echo: self.serial_local_echo.or(parent.serial_local_echo),
            serial_enter: self.serial_enter.clone().or_else(|| parent.serial_enter.clone()),
            telnet_send_password: self.telnet_send_password,
            logins: self.logins.clone(),
            credential_boundary: self.credential_boundary,
            credential_unconfirmed: self.credential_unconfirmed,
            credential_confirmed: self.credential_confirmed.clone(),
            extra: self.extra.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Connection {
    pub id: Uuid,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub settings: Settings,
    pub tags: Vec<String>,
    pub notes: String,
    pub icon: Option<String>,
    pub favorite: bool,
    pub classification: crate::policy::Classification,
    pub metadata: BTreeMap<String, String>,
    /// Fields this app does not know, kept as read and written back unchanged (PLUG-03a).
    pub extra: Extra,
    /// The connection type as stored, when this app does not know it. `protocol` is then
    /// [`Protocol::Unsupported`] and the entry cannot be connected to.
    pub unknown_protocol: Option<String>,
}

impl Connection {
    pub fn new(name: impl Into<String>, protocol: Protocol, host: impl Into<String>) -> Self {
        Connection {
            id: Uuid::new_v4(),
            name: name.into(),
            protocol,
            host: host.into(),
            settings: Settings::default(),
            tags: vec![],
            notes: String::new(),
            icon: None,
            favorite: false,
            classification: Default::default(),
            metadata: BTreeMap::new(),
            extra: Extra::new(),
            unknown_protocol: None,
        }
    }

    /// [`NEEDS_NEWER`] when this app does not know the connection's type: the apps show it on
    /// the entry, and it is the answer to any attempt to connect.
    pub fn unavailable(&self) -> Option<&'static str> {
        (self.protocol == Protocol::Unsupported).then_some(NEEDS_NEWER)
    }

    /// The connection type as stored: the wire name, or the stored name of an unknown type.
    /// For display only; an unknown name is untrusted text.
    pub fn protocol_name(&self) -> &str {
        match (self.protocol, &self.unknown_protocol) {
            (Protocol::Unsupported, Some(name)) => name,
            (p, _) => p.as_str(),
        }
    }

    /// The icon to show: the connection's own when it is a known name, else the protocol default.
    pub fn effective_icon(&self) -> &str {
        self.icon.as_deref().filter(|i| ICONS.contains(i)).unwrap_or(self.protocol.default_icon())
    }

    /// User-editable metadata, keyed without the namespace prefix.
    pub fn user_metadata(&self) -> BTreeMap<String, String> {
        self.metadata.iter().filter_map(|(k, v)| k.strip_prefix(USER_METADATA_PREFIX).map(|k| (k.to_string(), v.clone()))).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct Folder {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub defaults: Settings,
    #[serde(default)]
    pub children: Vec<Node>,
    /// B15: the saved task whose Royal JSON output fills this folder (a dynamic folder). Runs
    /// only on the user's Refresh, under policy and local trust (`dynfolder`, `tasktrust`).
    /// Exports and imports never carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_task_id: Option<Uuid>,
    /// Fields this app does not know, kept as read and written back unchanged (PLUG-03a).
    #[serde(flatten, skip_deserializing)]
    pub extra: Extra,
}

crate::unknown::keeps_unknown_fields!(Folder);

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Node {
    Folder(Folder),
    Connection(Connection),
}

impl Node {
    pub fn id(&self) -> Uuid {
        match self {
            Node::Folder(f) => f.id,
            Node::Connection(c) => c.id,
        }
    }
}

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct Document {
    pub schema: u32,
    pub id: Uuid,
    pub name: String,
    /// Monotonic counter used for optimistic-concurrency conflict detection.
    pub revision: u64,
    pub root: Folder,
    /// Default Settings per connection type, below every folder in the inheritance chain.
    /// Defaults stored for a type this app does not know are kept and written back (PLUG-03a).
    #[serde(default, skip_serializing_if = "TypeDefaults::is_empty")]
    pub type_defaults: TypeDefaults,
    /// Shared gateway definitions (`gateway` module), referenced by `Settings::gateway_id`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateways: Vec<crate::gateway::Gateway>,
    /// Saved tunnels for the Tunnel Manager (`tunneldefs` module).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tunnels: Vec<crate::tunneldefs::TunnelDef>,
    /// Saved custom tasks (`tasks` module); the built-ins are not stored, only their favourite flag.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tasks: Vec<crate::tasks::TaskDef>,
    /// Built-in task ids the user starred.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub favorite_builtin_tasks: Vec<Uuid>,
    /// Tasks attached to connections, run before or after connecting.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub task_hooks: Vec<crate::tasks::TaskHook>,
    /// Connection templates (B9). Kept outside the tree, so they are never connected to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<crate::templates::Template>,
    /// Recently Deleted (B10): removed subtrees kept until the retention passes. Nothing that
    /// walks `root` sees them, and every export strips them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deleted: Vec<DeletedItem>,
    /// Fields this app does not know, kept as read and written back unchanged (PLUG-03a).
    #[serde(flatten, skip_deserializing)]
    pub extra: Extra,
}

crate::unknown::keeps_unknown_fields!(Document);

/// One entry of Recently Deleted: a whole removed subtree with where it came from (B10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeletedItem {
    pub node: Node,
    /// Original parent folder; `None` means the library root.
    #[serde(default)]
    pub parent: Option<Uuid>,
    /// Position among the original siblings; best effort on restore.
    #[serde(default)]
    pub index: usize,
    /// Unix seconds when it was deleted.
    pub deleted_at: i64,
}

/// Where a restored item landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreResult {
    /// The folder it went into; `None` = the library root.
    pub landed_in: Option<Uuid>,
    /// True when the original folder was gone (or too deep), so it went to the root instead.
    pub at_root_because_parent_missing: bool,
}

const SECONDS_PER_DAY: i64 = 86_400;

/// A connection with every inherited setting resolved.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedConnection {
    pub connection: Connection,
    pub effective: Settings,
    pub path: Vec<String>,
}

impl Document {
    pub fn new(name: impl Into<String>) -> Self {
        Document {
            schema: SCHEMA_VERSION,
            id: Uuid::new_v4(),
            name: name.into(),
            revision: 0,
            root: Folder { id: Uuid::new_v4(), name: "Root".into(), color: None, defaults: Settings::default(), children: vec![], dynamic_task_id: None, extra: Extra::new() },
            type_defaults: TypeDefaults::default(),
            gateways: Vec::new(),
            tunnels: Vec::new(),
            tasks: Vec::new(),
            favorite_builtin_tasks: Vec::new(),
            task_hooks: Vec::new(),
            templates: Vec::new(),
            deleted: Vec::new(),
            extra: Extra::new(),
        }
    }

    /// Visit every connection with its resolved settings and folder path.
    pub fn connections(&self) -> Vec<ResolvedConnection> {
        self.resolve_where(|_, _| true)
    }

    /// Resolve only the connections `keep` accepts (given the raw connection and its folder
    /// path), in tree order. Connections that are not kept are never cloned (H04/H06).
    pub fn resolve_where(&self, mut keep: impl FnMut(&Connection, &[String]) -> bool) -> Vec<ResolvedConnection> {
        let mut out = Vec::new();
        walk(&self.root, &Settings::default(), &mut Vec::new(), &mut |c, path| keep(c, path), false, &mut out);
        self.finish(out)
    }

    /// Precedence: connection, nearest folder … root, type defaults, protocol built-in.
    fn finish(&self, mut out: Vec<ResolvedConnection>) -> Vec<ResolvedConnection> {
        for r in &mut out {
            if let Some(t) = self.type_defaults.get(&r.connection.protocol) {
                r.effective = r.effective.inherit_from(t);
            }
            r.effective.port = r.effective.port.or(r.connection.protocol.default_port());
        }
        out
    }

    /// One connection, resolved without materialising the rest of the library (H04).
    /// Every connect path starts here (or at [`Self::resolve_many`]), and neither ever returns
    /// an entry of an unknown type: asking for one by id is refused with [`NEEDS_NEWER`].
    pub fn resolve(&self, id: Uuid) -> Result<ResolvedConnection> {
        let mut out = Vec::new();
        walk(&self.root, &Settings::default(), &mut Vec::new(), &mut |c, _| c.id == id, true, &mut out);
        self.finish(out).pop().ok_or_else(|| self.unresolved(id))
    }

    /// The entry `id` when its type is one this app does not know. It never resolves; this is
    /// for showing it (tree, menu), never for connecting.
    pub fn unavailable_entry(&self, id: Uuid) -> Option<&Connection> {
        fn find(f: &Folder, id: Uuid) -> Option<&Connection> {
            f.children.iter().find_map(|n| match n {
                Node::Connection(c) => (c.id == id && c.protocol == Protocol::Unsupported).then_some(c),
                Node::Folder(sub) => find(sub, id),
            })
        }
        find(&self.root, id)
    }

    /// Why `id` did not resolve: it is an entry of an unknown type, or it is not there.
    fn unresolved(&self, id: Uuid) -> CoreError {
        match self.unavailable_entry(id) {
            Some(_) => CoreError::Invalid(NEEDS_NEWER.into()),
            None => CoreError::NotFound(id.to_string()),
        }
    }

    /// Resolve `ids` in one pass, in the order given. Fails on the first unknown id, like
    /// resolving each in turn (H04: MultiExec plans for many hosts).
    pub fn resolve_many(&self, ids: &[Uuid]) -> Result<Vec<ResolvedConnection>> {
        let wanted: std::collections::HashSet<Uuid> = ids.iter().copied().collect();
        let mut found = std::collections::HashMap::new();
        for r in self.resolve_where(|c, _| wanted.contains(&c.id)) {
            found.entry(r.connection.id).or_insert(r); // first in tree order, like `resolve`
        }
        ids.iter().map(|id| found.get(id).cloned().ok_or_else(|| self.unresolved(*id))).collect()
    }

    /// Insert `node` under folder `parent` (root if `None`).
    pub fn insert(&mut self, parent: Option<Uuid>, node: Node) -> Result<()> {
        self.check_nesting(parent, height(&node))?;
        let folder = match parent {
            None => &mut self.root,
            Some(id) => find_folder_mut(&mut self.root, id).ok_or_else(|| CoreError::NotFound(id.to_string()))?,
        };
        folder.children.push(node);
        Ok(())
    }

    /// Refuse placing something `levels` folders high in `parent` when that nests folders
    /// deeper than a library may (see [`crate::unknown::MAX_FOLDER_DEPTH`]): such a library
    /// could not be saved.
    fn check_nesting(&self, parent: Option<Uuid>, levels: usize) -> Result<()> {
        let at = parent.and_then(|id| depth_of(&self.root, id, 0)).unwrap_or(0);
        if at + levels > crate::unknown::MAX_FOLDER_DEPTH {
            return Err(CoreError::Invalid(crate::unknown::folders_too_deep()));
        }
        Ok(())
    }

    pub fn remove(&mut self, id: Uuid) -> Result<Node> {
        take(&mut self.root, id).ok_or_else(|| CoreError::NotFound(id.to_string()))
    }

    /// Delete a folder or connection the way a user does (B10). With `retention_days` > 0 the
    /// subtree goes to Recently Deleted; with 0 (Off) it is dropped at once. Returns the
    /// connection ids dropped for good, whose inline secrets the caller prunes.
    pub fn trash(&mut self, id: Uuid, now: i64, retention_days: u32) -> Result<Vec<Uuid>> {
        if id == self.root.id {
            return Err(CoreError::Invalid("the library root cannot be deleted".into()));
        }
        let parent = self.parent_of(id).filter(|p| *p != self.root.id);
        let siblings = match parent {
            Some(p) => &self.folder(p).expect("parent exists").children,
            None => &self.root.children,
        };
        let index = siblings.iter().position(|n| n.id() == id).unwrap_or(0);
        let node = self.remove(id)?;
        if retention_days == 0 {
            let mut gone = Vec::new();
            connection_ids_in(&node, &mut gone);
            return Ok(gone);
        }
        self.deleted.push(DeletedItem { node, parent, index, deleted_at: now });
        Ok(Vec::new())
    }

    /// Recently Deleted, oldest first.
    pub fn deleted_items(&self) -> &[DeletedItem] {
        &self.deleted
    }

    /// Put a Recently Deleted item back: into its original folder, or the root when that folder
    /// is gone or the result would be too deep.
    pub fn restore(&mut self, id: Uuid) -> Result<RestoreResult> {
        let pos = self.deleted.iter().position(|d| d.node.id() == id).ok_or_else(|| CoreError::NotFound(id.to_string()))?;
        let mut ids = Vec::new();
        all_ids_in(&self.deleted[pos].node, &mut ids);
        let mut present = vec![self.root.id];
        self.root.children.iter().for_each(|n| all_ids_in(n, &mut present));
        let present: std::collections::BTreeSet<Uuid> = present.into_iter().collect();
        if ids.iter().any(|i| present.contains(i)) {
            return Err(CoreError::Invalid("an item with the same id is already in the library".into()));
        }
        let levels = height(&self.deleted[pos].node);
        let wanted = self.deleted[pos].parent.filter(|p| self.folder(*p).is_some());
        let landed_in = wanted.filter(|p| self.check_nesting(Some(*p), levels).is_ok());
        if landed_in.is_none() {
            self.check_nesting(None, levels)?;
        }
        let item = self.deleted.remove(pos);
        let folder = match landed_in {
            Some(p) => find_folder_mut(&mut self.root, p).expect("checked above"),
            None => &mut self.root,
        };
        let at = item.index.min(folder.children.len());
        folder.children.insert(at, item.node);
        Ok(RestoreResult { landed_in, at_root_because_parent_missing: item.parent.is_some() && landed_in.is_none() })
    }

    /// Drop one Recently Deleted item now. Returns its connection ids.
    pub fn delete_permanently(&mut self, id: Uuid) -> Result<Vec<Uuid>> {
        let pos = self.deleted.iter().position(|d| d.node.id() == id).ok_or_else(|| CoreError::NotFound(id.to_string()))?;
        let mut gone = Vec::new();
        connection_ids_in(&self.deleted.remove(pos).node, &mut gone);
        Ok(gone)
    }

    /// Empty Recently Deleted. Returns the connection ids dropped.
    pub fn empty_deleted(&mut self) -> Vec<Uuid> {
        let mut gone = Vec::new();
        for d in self.deleted.drain(..) {
            connection_ids_in(&d.node, &mut gone);
        }
        gone
    }

    /// Drop items older than `retention_days` (0 = Off: drop all). An item dated in the
    /// future (clock moved back) is kept. Returns the connection ids dropped.
    pub fn purge_deleted(&mut self, now: i64, retention_days: u32) -> Vec<Uuid> {
        let keep_for = i64::from(retention_days) * SECONDS_PER_DAY;
        let mut gone = Vec::new();
        self.deleted.retain(|d| {
            let expired = retention_days == 0 || now.saturating_sub(d.deleted_at) >= keep_for;
            if expired {
                connection_ids_in(&d.node, &mut gone);
            }
            !expired
        });
        gone
    }

    /// Every connection id in the tree and in Recently Deleted: the live set for pruning
    /// inline secrets, so a trashed connection keeps its password until it is purged.
    pub fn all_connection_ids(&self) -> std::collections::BTreeSet<Uuid> {
        let mut ids = Vec::new();
        for n in &self.root.children {
            connection_ids_in(n, &mut ids);
        }
        for d in &self.deleted {
            connection_ids_in(&d.node, &mut ids);
        }
        ids.into_iter().collect()
    }

    /// Move a node into another folder (drag-and-drop). Refuses moving a folder into itself.
    pub fn move_node(&mut self, id: Uuid, new_parent: Option<Uuid>) -> Result<()> {
        self.move_node_before(id, new_parent, None)
    }

    /// Move a node into `new_parent` (root if `None`), placed before sibling `before`, or last
    /// when `before` is `None`. This is how drag-and-drop reorders; the order is persisted.
    /// The tree is unchanged when the move is refused.
    pub fn move_node_before(&mut self, id: Uuid, new_parent: Option<Uuid>, before: Option<Uuid>) -> Result<()> {
        if id == self.root.id {
            return Err(CoreError::Invalid("the library root cannot be moved".into()));
        }
        if let Some(target) = new_parent {
            if target == id || self.is_descendant(id, target) {
                return Err(CoreError::Invalid("cannot move a folder into itself".into()));
            }
            if self.folder(target).is_none() {
                return Err(CoreError::NotFound(target.to_string()));
            }
        }
        if before == Some(id) {
            return Ok(());
        }
        if let Some(moved) = find_folder(&self.root, id) {
            self.check_nesting(new_parent, 1 + moved.children.iter().map(height).max().unwrap_or(0))?;
        }
        if let Some(b) = before {
            let parent = self.folder(new_parent.unwrap_or(self.root.id)).ok_or_else(|| CoreError::NotFound("parent".into()))?;
            if !parent.children.iter().any(|n| n.id() == b) {
                return Err(CoreError::Invalid("drop target is not in that folder".into()));
            }
        }
        let node = self.remove(id)?;
        let folder = match new_parent {
            None => &mut self.root,
            Some(p) => find_folder_mut(&mut self.root, p).expect("checked above"),
        };
        let at = before.and_then(|b| folder.children.iter().position(|n| n.id() == b)).unwrap_or(folder.children.len());
        folder.children.insert(at, node);
        Ok(())
    }

    /// The folder with `id` (the root included).
    pub fn folder(&self, id: Uuid) -> Option<&Folder> {
        find_folder(&self.root, id)
    }

    /// Parent folder of a node; `None` for the root or an unknown id.
    pub fn parent_of(&self, id: Uuid) -> Option<Uuid> {
        fn find(f: &Folder, id: Uuid) -> Option<Uuid> {
            if f.children.iter().any(|n| n.id() == id) {
                return Some(f.id);
            }
            f.children.iter().find_map(|n| match n {
                Node::Folder(sub) => find(sub, id),
                _ => None,
            })
        }
        find(&self.root, id)
    }

    /// Rename a folder or connection. Blank names are refused.
    pub fn rename(&mut self, id: Uuid, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(CoreError::Invalid("name must not be empty".into()));
        }
        if let Some(f) = find_folder_mut(&mut self.root, id) {
            f.name = name.to_string();
            return Ok(());
        }
        self.connection_mut(id)?.name = name.to_string();
        Ok(())
    }

    /// Copy a folder with its whole subtree (fresh ids everywhere), placed right after the original.
    pub fn duplicate_folder(&mut self, id: Uuid) -> Result<Uuid> {
        if id == self.root.id {
            return Err(CoreError::Invalid("the library root cannot be duplicated".into()));
        }
        let original = self.folder(id).ok_or_else(|| CoreError::NotFound(id.to_string()))?;
        let mut copy = reidentify(original.clone());
        copy.name = format!("{} (copy)", original.name);
        let new_id = copy.id;
        let parent = self.parent_of(id).expect("a non-root folder has a parent");
        let siblings = &mut find_folder_mut(&mut self.root, parent).expect("parent exists").children;
        let at = siblings.iter().position(|n| n.id() == id).map_or(siblings.len(), |p| p + 1);
        siblings.insert(at, Node::Folder(copy));
        Ok(new_id)
    }

    /// Sort a folder's direct children: folders first, then connections, each by name
    /// (case-insensitive). With `recursive`, every descendant folder too.
    pub fn sort_folder(&mut self, id: Uuid, recursive: bool) -> Result<()> {
        let f = find_folder_mut(&mut self.root, id).ok_or_else(|| CoreError::NotFound(id.to_string()))?;
        sort_children(f, recursive);
        Ok(())
    }

    /// Replace a connection's free-text notes.
    pub fn set_notes(&mut self, id: Uuid, notes: &str) -> Result<()> {
        self.connection_mut(id)?.notes = notes.to_string();
        Ok(())
    }

    pub fn duplicate(&mut self, id: Uuid, parent: Option<Uuid>) -> Result<Uuid> {
        let original = self.resolve(id)?.connection;
        let copy = Connection { id: Uuid::new_v4(), name: format!("{} (copy)", original.name), ..original };
        let new_id = copy.id;
        self.insert(parent, Node::Connection(copy))?;
        Ok(new_id)
    }

    /// Mark a connection as a favourite (shown in the sidebar's Favourites section).
    pub fn set_favorite(&mut self, id: Uuid, favorite: bool) -> Result<()> {
        self.connection_mut(id)?.favorite = favorite;
        Ok(())
    }

    /// Assign (or with `None`, clear) the vault credential a connection uses.
    pub fn set_credential(&mut self, id: Uuid, credential: Option<Uuid>) -> Result<()> {
        self.connection_mut(id)?.settings.credential_id = credential;
        Ok(())
    }

    /// Set (or with `None`, remove) one metadata entry of a connection.
    pub fn set_metadata(&mut self, id: Uuid, key: &str, value: Option<String>) -> Result<()> {
        let c = self.connection_mut(id)?;
        match value {
            Some(v) => c.metadata.insert(key.to_string(), v),
            None => c.metadata.remove(key),
        };
        Ok(())
    }

    /// Set (or with `None`, clear) a connection's icon; only names in [`ICONS`] are accepted.
    pub fn set_icon(&mut self, id: Uuid, icon: Option<&str>) -> Result<()> {
        if let Some(i) = icon {
            if !ICONS.contains(&i) {
                return Err(CoreError::Invalid(format!("unknown icon {i:?}")));
            }
        }
        self.connection_mut(id)?.icon = icon.map(str::to_string);
        Ok(())
    }

    /// Set (or with `None`, remove) one user metadata entry. Keys live under
    /// [`USER_METADATA_PREFIX`], so internal bindings are out of reach; names that look secret
    /// are refused (secrets belong in the vault, and export would drop them).
    pub fn set_user_metadata(&mut self, id: Uuid, key: &str, value: Option<&str>) -> Result<()> {
        let key = key.trim();
        let key_ok = !key.is_empty()
            && key.chars().count() <= MAX_USER_METADATA_KEY
            && key.chars().all(|ch| ch.is_alphanumeric() || matches!(ch, ' ' | '-' | '_' | '.'));
        if !key_ok {
            return Err(CoreError::Invalid(format!("metadata names are 1–{MAX_USER_METADATA_KEY} letters, digits, spaces, '-', '_' or '.'")));
        }
        if crate::audit::is_sensitive_key(key) {
            return Err(CoreError::Invalid(format!("{key:?} looks like a secret; store it in the vault instead")));
        }
        let full = format!("{USER_METADATA_PREFIX}{key}");
        let c = self.connection_mut(id)?;
        match value {
            Some(v) => {
                if v.chars().count() > MAX_USER_METADATA_VALUE || v.chars().any(|ch| ch.is_control() && ch != '\n') {
                    return Err(CoreError::Invalid(format!("metadata values are at most {MAX_USER_METADATA_VALUE} characters")));
                }
                if !c.metadata.contains_key(&full) && c.user_metadata().len() >= MAX_USER_METADATA {
                    return Err(CoreError::Invalid(format!("at most {MAX_USER_METADATA} metadata entries per connection")));
                }
                c.metadata.insert(full, v.to_string());
            }
            None => {
                c.metadata.remove(&full);
            }
        }
        Ok(())
    }

    /// Entry `id`'s custom properties. Unlike [`Document::resolve`] this does not refuse an entry
    /// of a type this app cannot open: a plugin entry's Properties show them too (PVE-TLS).
    pub fn user_metadata_of(&self, id: Uuid) -> Result<BTreeMap<String, String>> {
        crate::properties::find_connection(&self.root, id).map(Connection::user_metadata).ok_or_else(|| CoreError::NotFound(id.to_string()))
    }

    fn connection_mut(&mut self, id: Uuid) -> Result<&mut Connection> {
        fn find(f: &mut Folder, id: Uuid) -> Option<&mut Connection> {
            f.children.iter_mut().find_map(|n| match n {
                Node::Connection(c) if c.id == id => Some(c),
                Node::Folder(sub) => find(sub, id),
                _ => None,
            })
        }
        find(&mut self.root, id).ok_or_else(|| CoreError::NotFound(id.to_string()))
    }

    fn is_descendant(&self, ancestor: Uuid, candidate: Uuid) -> bool {
        fn find(f: &Folder, id: Uuid) -> Option<&Folder> {
            if f.id == id {
                return Some(f);
            }
            f.children.iter().find_map(|n| match n {
                Node::Folder(sub) => find(sub, id),
                _ => None,
            })
        }
        find(&self.root, ancestor).map_or(false, |a| find(a, candidate).is_some())
    }
}

/// Depth-first, in tree order. Returns true once `first_only` has found its match.
fn walk(
    folder: &Folder,
    inherited: &Settings,
    path: &mut Vec<String>,
    keep: &mut dyn FnMut(&Connection, &[String]) -> bool,
    first_only: bool,
    out: &mut Vec<ResolvedConnection>,
) -> bool {
    let here = folder.defaults.inherit_from(inherited);
    for child in &folder.children {
        match child {
            Node::Folder(sub) => {
                path.push(sub.name.clone());
                let done = walk(sub, &here, path, keep, first_only, out);
                path.pop();
                if done {
                    return true;
                }
            }
            // An entry of a type this app does not know is never resolved, so nothing that
            // connects, runs or exports can reach it (PLUG-03a).
            Node::Connection(c) if c.protocol == Protocol::Unsupported => {}
            Node::Connection(c) if keep(c, path) => {
                let effective = c.settings.inherit_from(&here);
                out.push(ResolvedConnection { connection: c.clone(), effective, path: path.clone() });
                if first_only {
                    return true;
                }
            }
            Node::Connection(_) => {}
        }
    }
    false
}

fn find_folder(folder: &Folder, id: Uuid) -> Option<&Folder> {
    if folder.id == id {
        return Some(folder);
    }
    folder.children.iter().find_map(|n| match n {
        Node::Folder(sub) => find_folder(sub, id),
        _ => None,
    })
}

/// A copy of `f` and its subtree with new ids, so it can live next to the original.
/// How many folders the folder `id` is below `f`, which is `depth` below the root.
fn depth_of(f: &Folder, id: Uuid, depth: usize) -> Option<usize> {
    if f.id == id {
        return Some(depth);
    }
    f.children.iter().find_map(|n| match n {
        Node::Folder(sub) => depth_of(sub, id, depth + 1),
        Node::Connection(_) => None,
    })
}

/// How many folder levels `node` adds where it is placed: 0 for a connection.
fn height(node: &Node) -> usize {
    match node {
        Node::Connection(_) => 0,
        Node::Folder(f) => 1 + f.children.iter().map(height).max().unwrap_or(0),
    }
}

/// A copy of `f` with fresh ids. Entries of an unknown type are left out: Duplicate is
/// refused on such an entry, because its own data may hold references this app cannot renew.
fn reidentify(f: Folder) -> Folder {
    Folder {
        id: Uuid::new_v4(),
        children: f
            .children
            .into_iter()
            .filter(|n| !matches!(n, Node::Connection(c) if c.protocol == Protocol::Unsupported))
            .map(|n| match n {
                Node::Folder(sub) => Node::Folder(reidentify(sub)),
                Node::Connection(c) => Node::Connection(Connection { id: Uuid::new_v4(), ..c }),
            })
            .collect(),
        ..f
    }
}

fn sort_children(f: &mut Folder, recursive: bool) {
    f.children.sort_by(|a, b| match (a, b) {
        (Node::Folder(_), Node::Connection(_)) => std::cmp::Ordering::Less,
        (Node::Connection(_), Node::Folder(_)) => std::cmp::Ordering::Greater,
        (Node::Folder(x), Node::Folder(y)) => x.name.to_lowercase().cmp(&y.name.to_lowercase()),
        (Node::Connection(x), Node::Connection(y)) => x.name.to_lowercase().cmp(&y.name.to_lowercase()),
    });
    if recursive {
        for n in &mut f.children {
            if let Node::Folder(sub) = n {
                sort_children(sub, true);
            }
        }
    }
}

fn find_folder_mut(folder: &mut Folder, id: Uuid) -> Option<&mut Folder> {
    if folder.id == id {
        return Some(folder);
    }
    folder.children.iter_mut().find_map(|n| match n {
        Node::Folder(sub) => find_folder_mut(sub, id),
        _ => None,
    })
}

fn connection_ids_in(node: &Node, out: &mut Vec<Uuid>) {
    match node {
        Node::Connection(c) => out.push(c.id),
        Node::Folder(f) => f.children.iter().for_each(|n| connection_ids_in(n, out)),
    }
}

fn all_ids_in(node: &Node, out: &mut Vec<Uuid>) {
    out.push(node.id());
    if let Node::Folder(f) = node {
        f.children.iter().for_each(|n| all_ids_in(n, out));
    }
}

fn take(folder: &mut Folder, id: Uuid) -> Option<Node> {
    if let Some(pos) = folder.children.iter().position(|n| n.id() == id) {
        return Some(folder.children.remove(pos));
    }
    folder.children.iter_mut().find_map(|n| match n {
        Node::Folder(sub) => take(sub, id),
        _ => None,
    })
}
