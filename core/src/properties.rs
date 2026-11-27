//! Property schema and inheritance explanation for the property editor.
//!
//! Only settings the core actually honours are described here, so frontends never offer a
//! setting that does nothing. Inheritance order for a connection: its own value, the nearest
//! folder's default up to the root, the connection type's Default Settings, then the
//! protocol's built-in value.
use std::collections::BTreeMap;

use serde::Serialize;
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::{Connection, Document, Folder, Node, Protocol, Settings};
use crate::policy::Environment;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PropKind {
    Text,
    Port,
    Seconds,
    Multiline,
    Tags,
    /// One of `PropertyDef::options`, stored as the id.
    Choice,
    /// `"true"` / `"false"`.
    Toggle,
    /// The id of one of the library's gateways (`gateway` module); frontends list them.
    Gateway,
    /// A terminal theme id (`termthemes`): bundled or the user's own; frontends list them.
    TerminalTheme,
    /// A terminal font family (`termfonts`): frontends list the bundled and installed ones.
    TerminalFont,
    /// The id of a credential in the local vault; frontends list them (names only).
    Credential,
    /// A whole number within ±(2^53 − 1). Only plugin fields use it (PLUG-03b).
    Number,
}

/// One editable property and where it appears in the editor.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PropertyDef {
    pub key: &'static str,
    pub label: &'static str,
    pub category: &'static str,
    pub kind: PropKind,
    pub help: &'static str,
    /// Can be set on folders and type defaults and inherited by connections.
    pub inheritable: bool,
    /// `(id, label)` for `Choice`.
    pub options: &'static [(&'static str, &'static str)],
}

/// Where a property's effective value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueSource {
    /// Set on this item.
    Own,
    /// Inherited from an ancestor folder (`from` = folder name).
    Inherited,
    /// From the connection type's Default Settings.
    TypeDefault,
    /// The protocol's built-in value.
    Builtin,
    /// Nothing set anywhere.
    Unset,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PropertyValue {
    pub key: String,
    /// The value stored on this item, if any.
    pub own: Option<String>,
    /// The value that applies (own or inherited).
    pub effective: Option<String>,
    pub source: ValueSource,
    /// Folder name for `Inherited`, protocol name for `TypeDefault`.
    pub from: Option<String>,
}

type Fallback = (Option<String>, ValueSource, Option<String>);
const NONE: Fallback = (None, ValueSource::Unset, None);

const fn def(key: &'static str, label: &'static str, category: &'static str, kind: PropKind, help: &'static str, inheritable: bool) -> PropertyDef {
    PropertyDef { key, label, category, kind, help, inheritable, options: &[] }
}

/// A per-connection setting kept in the connection's metadata under `key` (not inherited).
/// Keys contain a `.`, which keeps them apart from `Settings` fields.
const fn meta(key: &'static str, label: &'static str, category: &'static str, kind: PropKind, help: &'static str, options: &'static [(&'static str, &'static str)]) -> PropertyDef {
    PropertyDef { key, label, category, kind, help, inheritable: false, options }
}

const OFF_ON: &[(&str, &str)] = &[("off", "Off"), ("on", "On")];
/// OSC 52 clipboard writes from programs on the host (THREAT_MODEL T14); reads are never allowed.
pub const OSC52_WRITE: &str = "terminal.osc52_write";
/// Connection metadata: log in with the system SSH agent (set by the app's Authentication choice).
pub const SSH_AGENT: &str = "ssh.agent";
pub const RDP_RESOLUTION: &str = "rdp.resolution";
/// RDP and VNC: how the remote desktop meets the tab: `fit` (default), `fixed` or `scale`.
pub const DISPLAY_FIT: &str = "display.fit";
pub const RDP_COLOR_DEPTH: &str = "rdp.color_depth";
pub const VNC_VIEW_ONLY: &str = "vnc.view_only";
/// RDP: read Services, Processes and Event Log over SSH to the same host (owner point 11).
pub const RDP_SSH_MANAGEMENT: &str = "rdp.ssh_management";
/// RDP: SSH port for management; empty uses 22.
pub const RDP_SSH_PORT: &str = "rdp.ssh_port";
/// RDP: SSH username for management; empty reuses the RDP login.
pub const RDP_SSH_USER: &str = "rdp.ssh_user";
pub const VNC_CLIPBOARD: &str = "vnc.clipboard";
pub const WEB_USER_AGENT: &str = "web.user_agent";
const MAX_USER_AGENT: usize = 256;

const OSC52: PropertyDef = meta(
    OSC52_WRITE,
    "Remote clipboard writes (OSC 52)",
    "Security",
    PropKind::Choice,
    "Let programs on this host put text on your clipboard. Reading your clipboard is never allowed. Your organisation's policy can forbid it.",
    OFF_ON,
);
const TMUX_ATTACH: PropertyDef = meta(
    crate::remoteshell::TMUX,
    "tmux",
    "Terminal",
    PropKind::Choice,
    "Attach or create a tmux session on the host instead of a plain shell, so a reconnect lands back where you were. tmux must be installed on the host.",
    crate::remoteshell::TMUX_MODES,
);
const TMUX_SESSION: PropertyDef = meta(crate::remoteshell::TMUX_SESSION, "tmux session", "Terminal", PropKind::Text, "Name of the tmux session; empty uses `bastion`.", &[]);
const TRANSPORT: PropertyDef = meta(
    crate::remoteshell::TRANSPORT,
    "Transport",
    "Connection",
    PropKind::Choice,
    "Mosh roams between networks and survives sleep; it needs `mosh` on this computer and `mosh-server` on the host, logs in with your SSH keys or agent, and cannot use gateways or jump hosts.",
    crate::remoteshell::TRANSPORTS,
);
const RDP_SIZE: PropertyDef = meta(
    RDP_RESOLUTION,
    "Desktop size",
    "Display",
    PropKind::Choice,
    "The remote desktop's size for Fixed size and Scale; Window uses the tab's size when connecting.",
    &[("window", "Window"), ("1280x720", "1280 × 720"), ("1366x768", "1366 × 768"), ("1440x900", "1440 × 900"), ("1600x900", "1600 × 900"), ("1920x1080", "1920 × 1080"), ("2560x1440", "2560 × 1440")],
);
const DISPLAY_FIT_DEF: PropertyDef = meta(
    DISPLAY_FIT,
    "Fit",
    "Display",
    PropKind::Choice,
    "Fit to tab resizes the remote desktop to the tab (servers that refuse keep their size, scaled). Fixed size shows it 1:1; Scale shrinks or grows it to fit.",
    &[("fit", "Fit to tab"), ("fixed", "Fixed size"), ("scale", "Scale")],
);
const RDP_DEPTH: PropertyDef = meta(
    RDP_COLOR_DEPTH,
    "Colour depth",
    "Display",
    PropKind::Choice,
    "Bits per pixel for servers that send bitmaps. The graphics pipeline (H.264, RemoteFX) is always 32-bit.",
    &[("32", "32-bit"), ("24", "24-bit"), ("16", "16-bit"), ("15", "15-bit")],
);
const VNC_VIEW: PropertyDef = meta(VNC_VIEW_ONLY, "View only", "Input", PropKind::Choice, "Show the remote screen without sending mouse or keyboard input.", OFF_ON);
const VNC_CLIP: PropertyDef =
    meta(VNC_CLIPBOARD, "Share clipboard", "Input", PropKind::Choice, "Text the server copies goes to your clipboard, and ⌘V sends yours to the server.", OFF_ON);
const RDP_SSH_MGMT: PropertyDef = meta(
    RDP_SSH_MANAGEMENT,
    "Management via SSH",
    "Management",
    PropKind::Choice,
    "Shows Services, Processes and Event Log for this host, read with PowerShell over OpenSSH on the same computer name.",
    OFF_ON,
);
const RDP_SSH_PORT_DEF: PropertyDef = meta(RDP_SSH_PORT, "SSH port", "Management", PropKind::Port, "Empty uses 22.", &[]);
const RDP_SSH_USER_DEF: PropertyDef = meta(RDP_SSH_USER, "SSH username", "Management", PropKind::Text, "Empty reuses the RDP login.", &[]);
const WEB_UA: PropertyDef = meta(WEB_USER_AGENT, "User agent", "Browser", PropKind::Text, "Sent instead of the built-in browser's own; empty keeps it.", &[]);

const NAME: PropertyDef = def("name", "Display name", "General", PropKind::Text, "Shown in the library and on tabs.", false);
const HOST: PropertyDef = def("host", "Computer name", "General", PropKind::Text, "IP address or FQDN.", false);
const PORT: PropertyDef = def("port", "Port", "General", PropKind::Port, "Leave empty to inherit.", true);
const USER: PropertyDef = def("username", "User name", "Credentials", PropKind::Text, "Pre-filled when connecting.", true);
const KEEPALIVE: PropertyDef =
    def("keepalive_secs", "Keep-alive interval", "Connection", PropKind::Seconds, "Seconds between SSH keep-alive messages; empty disables them.", true);
const SSH_ALGORITHMS: PropertyDef = def(
    "ssh_algorithms",
    "Algorithms",
    "Advanced",
    PropKind::Multiline,
    "Key exchange, cipher, MAC and host key lists in OpenSSH syntax (+add, -remove, ^first), as JSON. Weak algorithms stay off unless allowed for this host; policy can forbid them.",
    true,
);
const AUTO_RECONNECT: PropertyDef = def(
    "auto_reconnect",
    "Reconnect automatically",
    "Connection",
    PropKind::Toggle,
    "When the link drops, reconnect up to 5 times with back-off using the still-unlocked credential; also pause on system sleep and resume on wake. Failed sign-ins are never retried.",
    true,
);
const GATEWAY: PropertyDef = def(
    "gateway_id",
    "Gateway",
    "Gateway",
    PropKind::Gateway,
    "Reach this host through a shared SSH gateway from the Gateway Manager. It is the first hop, before any ProxyJump from an imported SSH config.",
    true,
);
/// The same setting for RDP, VNC and web, which reach their host over a forwarded port.
const GATEWAY_ROUTED: PropertyDef = def(
    "gateway_id",
    "Gateway",
    "Gateway",
    PropKind::Gateway,
    "Reach this host through a shared SSH gateway from the Gateway Manager: Gantry signs in to the gateway and forwards a local port to the host (RDP, VNC) or opens a local SOCKS proxy through it (web).",
    true,
);
/// The same setting for a plugin entry (PLUG-08): the plugin's streams go over a forwarded port.
const GATEWAY_PLUGIN: PropertyDef = def(
    "gateway_id",
    "Gateway",
    "Gateway",
    PropKind::Gateway,
    "Reach this host through a shared SSH gateway from the Gateway Manager: Gantry signs in to the gateway and forwards a local port to the host; the plugin's connection goes through it, with the same TLS checks.",
    true,
);
const TAB_GROUP_COLOR: PropertyDef = PropertyDef {
    key: crate::tabgroups::TAB_GROUP_COLOR_KEY,
    label: "Tab group colour",
    category: "Tabs",
    kind: PropKind::Choice,
    help: "Colour of the tab group that two or more open connections from this folder form. Empty picks a colour per folder.",
    inheritable: true,
    options: crate::tabgroups::GROUP_COLORS,
};
const HOST_COLOR: PropertyDef = PropertyDef {
    key: "host_color",
    label: "Host colour",
    category: "Tabs",
    kind: PropKind::Choice,
    help: "Accent for this connection's tab, terminal border and tree badge; set it on a folder to mark a customer's or production servers. A preset or #rrggbb. Empty uses none.",
    inheritable: true,
    options: crate::hostcolors::PRESETS,
};
const TERMINAL_THEME: PropertyDef = def(
    "terminal_theme",
    "Terminal theme",
    "Terminal",
    PropKind::TerminalTheme,
    "Colours for this connection's terminals; set it on a folder to mark a customer's servers. Empty uses the app theme.",
    true,
);
const TERMINAL_FONT_FAMILY: PropertyDef = def(
    "terminal_font_family",
    "Terminal font",
    "Terminal",
    PropKind::TerminalFont,
    "Font of this connection's terminals. Empty uses the app font (Settings › Terminal).",
    true,
);
const TERMINAL_FONT_SIZE: PropertyDef = def(
    "terminal_font_size",
    "Terminal font size",
    "Terminal",
    PropKind::Text,
    "Points, 9 to 24. Empty uses the app font size.",
    true,
);
const TERMINAL_LIGATURES: PropertyDef = def(
    "terminal_ligatures",
    "Font ligatures",
    "Terminal",
    PropKind::Toggle,
    "Joins character pairs such as -> and != where the font has ligatures.",
    true,
);
const SESSION_LOG: PropertyDef = def(
    "session_log",
    "Log session output",
    "Terminal",
    PropKind::Toggle,
    "Saves what the server prints (not your keystrokes) to an owner-only file in the session-logs folder.",
    true,
);
const SESSION_LOG_FOLDER: PropertyDef = def(
    "session_log_folder",
    "Session log folder",
    "Terminal",
    PropKind::Text,
    "Full path of the folder for this connection's session logs. Empty uses the app setting.",
    true,
);
const SESSION_LOG_KEEP_DAYS: PropertyDef = def(
    "session_log_keep_days",
    "Keep session logs for (days)",
    "Terminal",
    PropKind::Text,
    "Whole days, 0 to 3650 (0 keeps them forever). Empty uses the app setting.",
    true,
);
const NO_PREVIEW: PropertyDef = def(
    "no_preview",
    "Hide tab preview",
    "General",
    PropKind::Toggle,
    "The tab preview and the Show Tab Overview tile show only the icon and name, never the remote screen.",
    true,
);
const WEB_AUTOFILL: PropertyDef = def(
    "web_autofill",
    "Fill sign-in",
    "Browser",
    PropKind::Toggle,
    "Shows a Fill sign-in button that enters this connection's saved login, only on its exact https address.",
    true,
);
const HOST_STATUS: PropertyDef =
    def("host_status", "Show on host status", "General", PropKind::Toggle, "Checks now and then that the host answers, while the dashboard is open.", true);
const NLA_ONLY: PropertyDef = def(
    "rdp_nla_only",
    "Require Network Level Authentication",
    "Security",
    PropKind::Toggle,
    "Sign in before a desktop session starts (CredSSP); servers that only offer their own login screen are refused.",
    true,
);
const RDP_CLIPBOARD: PropertyDef =
    def("rdp_clipboard", "Share clipboard", "Redirection", PropKind::Toggle, "Text copied on either side can be pasted on the other. Text only: no files or images.", true);
/// Redirection wording names the machine the app runs on.
const RDP_AUDIO_LABEL: &str = if cfg!(windows) { "Play sound on this PC" } else { "Play sound on this Mac" };
const RDP_SHARED_FOLDER_HELP: &str = if cfg!(windows) {
    "A folder on this PC the server sees as drive \"Gantry\" (\\\\tsclient\\Gantry). The server can read, change and delete what is inside. Empty shares nothing."
} else {
    "A folder on this Mac the server sees as drive \"Gantry\" (\\\\tsclient\\Gantry). The server can read, change and delete what is inside. Empty shares nothing."
};
const RDP_AUDIO: PropertyDef = def("rdp_audio", RDP_AUDIO_LABEL, "Redirection", PropKind::Toggle, "The server's sound plays here.", true);
const RDP_SHARED_FOLDER: PropertyDef = def(
    "rdp_shared_folder",
    "Shared folder",
    "Redirection",
    PropKind::Text,
    RDP_SHARED_FOLDER_HELP,
    true,
);
const CREDENTIAL: PropertyDef = def(
    "credential_id",
    "Credential",
    "Credentials",
    PropKind::Credential,
    "A saved credential from the Credential Manager. Set it on a folder and every connection inside uses it unless it sets its own.",
    true,
);
const CREDENTIAL_NAME: PropertyDef = def(
    "credential_name",
    "Credential name",
    "Credentials",
    PropKind::Text,
    "Looked up by name in the vault when connecting, for libraries shared with people whose vault holds a credential of the same name.",
    true,
);
/// Folders only (`Settings::credential_boundary`): where sharing of saved logins stops.
pub const CREDENTIAL_BOUNDARY_KEY: &str = "credential_boundary";

const CREDENTIAL_BOUNDARY: PropertyDef = def(
    CREDENTIAL_BOUNDARY_KEY,
    "Keep saved logins inside this folder",
    "Credentials",
    PropKind::Toggle,
    "A login saved for a connection in this folder is offered only to connections to the same host inside it, and logins saved outside it are not offered here. Every top-level folder already works this way.",
    false,
);

/// What a folder's editor offers: the inheritable settings, and the ones only a folder has.
pub fn folder_schema() -> Vec<PropertyDef> {
    default_schema(None).into_iter().chain([CREDENTIAL_BOUNDARY]).collect()
}

const LOCAL_SHELL: PropertyDef = meta(
    crate::localshell::SHELL,
    "Shell",
    "Terminal",
    PropKind::Choice,
    "The program this connection starts on this computer.",
    crate::localshell::SHELL_OPTIONS,
);
const LOCAL_PATH: PropertyDef = meta(crate::localshell::PATH, "Program", "Terminal", PropKind::Text, "Full path of the program, for Custom program.", &[]);
const LOCAL_ARGS: PropertyDef =
    meta(crate::localshell::ARGS, "Arguments", "Terminal", PropKind::Text, "Passed to the program as written; quote an argument that contains spaces. No variables are expanded.", &[]);
const LOCAL_CWD: PropertyDef = meta(crate::localshell::CWD, "Start folder", "Terminal", PropKind::Text, "Full path or ~/…; empty starts in your home folder.", &[]);
const NOTES: PropertyDef = def("notes", "Notes", "Organization", PropKind::Multiline, "Free text, stored with the connection.", false);
const TAGS: PropertyDef = def("tags", "Tags", "Organization", PropKind::Tags, "Comma separated.", false);

/// Classification (`policy::Classification`): any of these makes a connection sensitive, which
/// the delete confirmation states and the policy's sensitive-write confirmation uses. The
/// `customer` scope is not offered: no credential can be scoped to a customer yet.
pub const ENVIRONMENTS: &[(&str, &str)] =
    &[("unclassified", "Unclassified"), ("test", "Test"), ("development", "Development"), ("staging", "Staging"), ("production", "Production")];
const ENVIRONMENT: PropertyDef = PropertyDef {
    options: ENVIRONMENTS,
    ..def("environment", "Environment", "Security", PropKind::Choice, "Production connections are treated as sensitive.", false)
};
const CUSTOMER_SENSITIVE: PropertyDef =
    def("customer_sensitive", "Customer-sensitive", "Security", PropKind::Toggle, "Treated as sensitive, like production.", false);
const PRIVILEGED: PropertyDef =
    def("privileged", "Privileged infrastructure", "Security", PropKind::Toggle, "Domain controllers, hypervisors, backup servers: treated as sensitive.", false);

const WOL_MAC: PropertyDef = def(
    "wol_mac",
    "MAC address",
    "Wake-on-LAN",
    PropKind::Text,
    "The host's network card, such as 00:11:22:33:44:55. Set it to offer Wake.",
    false,
);
const WOL_BROADCAST: PropertyDef = def(
    "wol_broadcast",
    "Broadcast address",
    "Wake-on-LAN",
    PropKind::Text,
    "LAN broadcast or subnet, such as 192.168.1.255 or 192.168.1.0/24. Empty uses 255.255.255.255.",
    true,
);
const WOL_PORT: PropertyDef = def("wol_port", "Wake port", "Wake-on-LAN", PropKind::Port, "UDP port. Empty uses 9.", true);
const WOL_SECUREON: PropertyDef = def(
    "wol_secureon",
    "SecureOn password",
    "Wake-on-LAN",
    PropKind::Text,
    "Six hex bytes, only if the network card asks for one. Sent unencrypted on the LAN.",
    true,
);
const WOL_BEFORE_CONNECT: PropertyDef =
    def("wol_before_connect", "Wake before connect", "Wake-on-LAN", PropKind::Toggle, "Wake the host and wait for it before connecting.", true);
const WOL_WAIT: PropertyDef = def("wol_wait_secs", "Wake wait", "Wake-on-LAN", PropKind::Seconds, "Seconds to wait for the host, 1 to 300. Empty uses 60.", true);

pub const SERIAL_PARITIES: &[(&str, &str)] = &[("none", "None"), ("odd", "Odd"), ("even", "Even")];
pub const SERIAL_FLOWS: &[(&str, &str)] = &[("none", "None"), ("software", "Software (XON/XOFF)"), ("hardware", "Hardware (RTS/CTS)")];
pub const SERIAL_ENTERS: &[(&str, &str)] = &[("cr", "CR"), ("lf", "LF"), ("crlf", "CR LF")];
pub const SERIAL_DATA_BITS: &[(&str, &str)] = &[("5", "5"), ("6", "6"), ("7", "7"), ("8", "8")];
pub const SERIAL_STOP_BITS: &[(&str, &str)] = &[("1", "1"), ("2", "2")];
/// Shown beside the Telnet password opt-in and on the Telnet connection page.
pub const TELNET_PASSWORD_WARNING: &str =
    "The password is sent in clear text. A fake prompt from the server or anyone on the network can capture it.";
/// The warning band on every Telnet form and connection page.
pub const TELNET_WARNING: &str = "Telnet is not encrypted. Anyone on the network can read what you type, including passwords.";

const SERIAL_PORT: PropertyDef =
    def("serial_port", "Port", "Serial", PropKind::Text, "The serial port, such as /dev/cu.usbserial-A1 or COM3. Pick one or type it.", false);
const SERIAL_BAUD: PropertyDef = def("serial_baud", "Baud rate", "Serial", PropKind::Text, "50 to 4000000. Empty uses 9600.", true);
const SERIAL_DATA: PropertyDef =
    PropertyDef { options: SERIAL_DATA_BITS, ..def("serial_data_bits", "Data bits", "Serial", PropKind::Choice, "Empty uses 8.", true) };
const SERIAL_PARITY: PropertyDef =
    PropertyDef { options: SERIAL_PARITIES, ..def("serial_parity", "Parity", "Serial", PropKind::Choice, "Empty uses none.", true) };
const SERIAL_STOP: PropertyDef =
    PropertyDef { options: SERIAL_STOP_BITS, ..def("serial_stop_bits", "Stop bits", "Serial", PropKind::Choice, "Empty uses 1.", true) };
const SERIAL_FLOW: PropertyDef =
    PropertyDef { options: SERIAL_FLOWS, ..def("serial_flow", "Flow control", "Serial", PropKind::Choice, "Empty uses none.", true) };
const SERIAL_ECHO: PropertyDef = def("serial_local_echo", "Local echo", "Serial", PropKind::Toggle, "Show what you type when the device does not echo it.", true);
const SERIAL_ENTER: PropertyDef =
    PropertyDef { options: SERIAL_ENTERS, ..def("serial_enter", "Enter sends", "Serial", PropKind::Choice, "Empty sends CR.", true) };
const TELNET_SEND_PASSWORD: PropertyDef = def(
    "telnet_send_password",
    "Type the saved password after the login prompt (unencrypted)",
    "Telnet",
    PropKind::Toggle,
    TELNET_PASSWORD_WARNING,
    false,
);

/// An entry of a plugin connection type (`<plugin id>/<type id>`, PLUG-03b): it opens through
/// the plugin, never through `Document::resolve`, but its address and login are the core's.
pub fn is_plugin_entry(c: &Connection) -> bool {
    c.protocol == Protocol::Unsupported && c.unknown_protocol.as_deref().and_then(crate::plugintypes::split_type_name).is_some()
}

/// What the editor shows for a plugin entry: the core-owned address and login, plus what every
/// entry has. The plugin's own fields are a separate group (`plugintypes::field_group`).
pub fn plugin_entry_schema() -> Vec<PropertyDef> {
    vec![NAME, HOST, PORT, CREDENTIAL, CREDENTIAL_NAME, GATEWAY_PLUGIN, ENVIRONMENT, NOTES, TAGS]
}

/// The properties of this connection, in editor order.
pub fn schema_of(c: &Connection) -> Vec<PropertyDef> {
    if is_plugin_entry(c) {
        plugin_entry_schema()
    } else {
        schema(c.protocol)
    }
}

/// Properties for a connection type, in editor order. Settings the core ignores for that type
/// (keep-alive outside SSH) are left out.
pub fn schema(protocol: Protocol) -> Vec<PropertyDef> {
    // A type this app does not know (PLUG-03a): only what every entry has. Its own settings
    // are kept in the library but are not shown and cannot be edited here.
    if protocol == Protocol::Unsupported {
        return vec![NAME, NOTES, TAGS];
    }
    let common_tail = [NO_PREVIEW, TAB_GROUP_COLOR, HOST_COLOR, ENVIRONMENT, CUSTOMER_SENSITIVE, PRIVILEGED, NOTES, TAGS];
    let head: &[PropertyDef] = match protocol {
        Protocol::Local => &[NAME, LOCAL_SHELL, LOCAL_PATH, LOCAL_ARGS, LOCAL_CWD, TERMINAL_THEME, SESSION_LOG, SESSION_LOG_FOLDER, SESSION_LOG_KEEP_DAYS],
        Protocol::Services | Protocol::Processes | Protocol::EventLog => &[NAME, HOST, PORT, USER, CREDENTIAL, CREDENTIAL_NAME, GATEWAY],
        Protocol::Ssh => &[NAME, HOST, PORT, USER, CREDENTIAL, CREDENTIAL_NAME, KEEPALIVE, AUTO_RECONNECT, GATEWAY, TERMINAL_THEME, TERMINAL_FONT_FAMILY, TERMINAL_FONT_SIZE, TERMINAL_LIGATURES, SESSION_LOG, SESSION_LOG_FOLDER, SESSION_LOG_KEEP_DAYS, OSC52, SSH_ALGORITHMS, TRANSPORT, TMUX_ATTACH, TMUX_SESSION],
        Protocol::Sftp => &[NAME, HOST, PORT, USER, CREDENTIAL, CREDENTIAL_NAME, KEEPALIVE, AUTO_RECONNECT, GATEWAY, TERMINAL_THEME, TERMINAL_FONT_FAMILY, TERMINAL_FONT_SIZE, TERMINAL_LIGATURES, SESSION_LOG, SESSION_LOG_FOLDER, SESSION_LOG_KEEP_DAYS, OSC52, SSH_ALGORITHMS],
        Protocol::Rdp => &[NAME, HOST, PORT, USER, CREDENTIAL, CREDENTIAL_NAME, NLA_ONLY, GATEWAY_ROUTED, DISPLAY_FIT_DEF, RDP_SIZE, RDP_DEPTH, RDP_CLIPBOARD, RDP_AUDIO, RDP_SHARED_FOLDER, RDP_SSH_MGMT, RDP_SSH_PORT_DEF, RDP_SSH_USER_DEF],
        Protocol::Vnc => &[NAME, HOST, PORT, USER, CREDENTIAL, CREDENTIAL_NAME, GATEWAY_ROUTED, DISPLAY_FIT_DEF, VNC_VIEW, VNC_CLIP],
        Protocol::Web => &[NAME, HOST, PORT, USER, CREDENTIAL, CREDENTIAL_NAME, GATEWAY_ROUTED, WEB_UA, WEB_AUTOFILL],
        Protocol::Telnet => &[NAME, HOST, PORT, USER, CREDENTIAL, CREDENTIAL_NAME, TELNET_SEND_PASSWORD, TERMINAL_THEME, TERMINAL_FONT_FAMILY, TERMINAL_FONT_SIZE, TERMINAL_LIGATURES, SESSION_LOG, SESSION_LOG_FOLDER, SESSION_LOG_KEEP_DAYS],
        Protocol::Serial => &[NAME, SERIAL_PORT, SERIAL_BAUD, SERIAL_DATA, SERIAL_PARITY, SERIAL_STOP, SERIAL_FLOW, SERIAL_ECHO, SERIAL_ENTER, TERMINAL_THEME, TERMINAL_FONT_FAMILY, TERMINAL_FONT_SIZE, TERMINAL_LIGATURES, SESSION_LOG, SESSION_LOG_FOLDER, SESSION_LOG_KEEP_DAYS],
        _ => &[NAME, HOST, PORT, USER, CREDENTIAL, CREDENTIAL_NAME],
    };
    // Host status needs a host and port this computer can connect to.
    let status = (!matches!(protocol, Protocol::Web | Protocol::Local | Protocol::Serial)).then_some(HOST_STATUS);
    let wol: &[PropertyDef] = match protocol {
        Protocol::Local | Protocol::Serial => &[],
        _ => &[WOL_MAC, WOL_BROADCAST, WOL_PORT, WOL_SECUREON, WOL_BEFORE_CONNECT, WOL_WAIT],
    };
    head.iter().cloned().chain(wol.iter().cloned()).chain(status).chain(common_tail).collect()
}

/// Wire id of an environment (`production`), as in `ENVIRONMENTS`.
fn environment_id(e: Environment) -> String {
    serde_json::to_value(e).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_else(|| "unclassified".into())
}

fn parse_toggle(label: &str, v: Option<&str>) -> Result<bool> {
    match v.unwrap_or("false") {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(CoreError::Invalid(format!("{label}: `{other}` is not on or off."))),
    }
}

/// Inheritable subset, used by folder and type Default Settings. Folders take the SSH set,
/// the widest one.
pub fn default_schema(protocol: Option<Protocol>) -> Vec<PropertyDef> {
    schema(protocol.unwrap_or(Protocol::Ssh)).into_iter().filter(|d| d.inheritable).collect()
}

fn get(s: &Settings, key: &str) -> Option<String> {
    match key {
        "port" => s.port.map(|v| v.to_string()),
        "username" => s.username.clone(),
        "credential_id" => s.credential_id.map(|v| v.to_string()),
        "credential_name" => s.credential_name.clone(),
        "keepalive_secs" => s.keepalive_secs.map(|v| v.to_string()),
        "auto_reconnect" => s.auto_reconnect.map(|v| v.to_string()),
        "gateway_id" => s.gateway_id.map(|v| v.to_string()),
        "terminal_theme" => s.terminal_theme.clone(),
        "terminal_font_family" => s.terminal_font_family.clone(),
        "terminal_font_size" => s.terminal_font_size.map(|v| v.to_string()),
        "terminal_ligatures" => s.terminal_ligatures.map(|v| v.to_string()),
        "session_log" => s.session_log.map(|v| v.to_string()),
        "session_log_folder" => s.session_log_folder.clone(),
        "session_log_keep_days" => s.session_log_keep_days.map(|v| v.to_string()),
        "no_preview" => s.no_preview.map(|v| v.to_string()),
        "web_autofill" => s.web_autofill.map(|v| v.to_string()),
        "host_status" => s.host_status.map(|v| v.to_string()),
        "rdp_nla_only" => s.rdp_nla_only.map(|v| v.to_string()),
        "rdp_clipboard" => s.rdp_clipboard.map(|v| v.to_string()),
        "rdp_audio" => s.rdp_audio.map(|v| v.to_string()),
        "rdp_shared_folder" => s.rdp_shared_folder.clone(),
        "tab_group_color" => s.tab_group_color.clone(),
        "host_color" => s.host_color.clone(),
        "ssh_algorithms" => s.ssh_algorithms.as_ref().and_then(|a| serde_json::to_string(a).ok()),
        "wol_mac" => s.wol_mac.clone(),
        "wol_broadcast" => s.wol_broadcast.clone(),
        "wol_port" => s.wol_port.map(|v| v.to_string()),
        "wol_secureon" => s.wol_secureon.clone(),
        "wol_before_connect" => s.wol_before_connect.map(|v| v.to_string()),
        "wol_wait_secs" => s.wol_wait_secs.map(|v| v.to_string()),
        "serial_port" => s.serial_port.clone(),
        "serial_baud" => s.serial_baud.map(|v| v.to_string()),
        "serial_data_bits" => s.serial_data_bits.map(|v| v.to_string()),
        "serial_parity" => s.serial_parity.clone(),
        "serial_stop_bits" => s.serial_stop_bits.map(|v| v.to_string()),
        "serial_flow" => s.serial_flow.clone(),
        "serial_local_echo" => s.serial_local_echo.map(|v| v.to_string()),
        "serial_enter" => s.serial_enter.clone(),
        "telnet_send_password" => s.telnet_send_password.map(|v| v.to_string()),
        _ => None,
    }
}

fn set(s: &Settings, key: &str, value: Option<&str>) -> Result<Settings> {
    let mut out = s.clone();
    match key {
        "port" => out.port = value.map(parse_port).transpose()?,
        "username" => out.username = value.map(str::to_string),
        // A credential the user sets here is their choice for this node. On a node whose
        // references arrived with a received library (`Settings::credential_unconfirmed`,
        // A1-CORE-01-FU1) it confirms that credential only; a reset chooses nothing.
        "credential_id" => {
            out.credential_id =
                value.map(|v| Uuid::parse_str(v).map_err(|_| CoreError::Invalid("Credential: choose one from the Credential Manager.".into()))).transpose()?;
            if let Some(id) = out.credential_id {
                crate::logins::confirm(&mut out, id);
            }
        }
        "credential_name" => {
            if let Some(v) = value {
                check_len("Credential name", v, MAX_NAME_LEN)?;
            }
            out.credential_name = value.map(str::to_string);
            // A name is confirmed only as the node's whole reference: with an id beside it
            // that the sender wrote, the name could not be told from the sender's.
            if value.is_some() && out.credential_id.is_none() && out.logins.is_empty() {
                crate::logins::confirm_all(&mut out);
            }
        }
        "keepalive_secs" => out.keepalive_secs = value.map(parse_seconds).transpose()?,
        "auto_reconnect" => out.auto_reconnect = value.map(|v| parse_toggle("Reconnect automatically", Some(v))).transpose()?,
        "rdp_nla_only" => out.rdp_nla_only = value.map(|v| parse_toggle("Require Network Level Authentication", Some(v))).transpose()?,
        "terminal_ligatures" => out.terminal_ligatures = value.map(|v| parse_toggle("Font ligatures", Some(v))).transpose()?,
        "terminal_font_size" => out.terminal_font_size = value.map(parse_font_size).transpose()?,
        "terminal_font_family" => {
            out.terminal_font_family = match value {
                Some(v) if crate::termfonts::is_family(v) => Some(v.to_string()),
                Some(v) => return Err(CoreError::Invalid(format!("Terminal font: `{v}` is not a font family."))),
                None => None,
            }
        }
        "session_log" => out.session_log = value.map(|v| parse_toggle("Log session output", Some(v))).transpose()?,
        "session_log_folder" => out.session_log_folder = value.map(parse_log_folder).transpose()?,
        "session_log_keep_days" => out.session_log_keep_days = value.map(parse_keep_days).transpose()?,
        "no_preview" => out.no_preview = value.map(|v| parse_toggle("Hide tab preview", Some(v))).transpose()?,
        "web_autofill" => out.web_autofill = value.map(|v| parse_toggle("Fill sign-in", Some(v))).transpose()?,
        "host_status" => out.host_status = value.map(|v| parse_toggle("Show on host status", Some(v))).transpose()?,
        "rdp_clipboard" => out.rdp_clipboard = value.map(|v| parse_toggle("Share clipboard", Some(v))).transpose()?,
        "rdp_audio" => out.rdp_audio = value.map(|v| parse_toggle(RDP_AUDIO_LABEL, Some(v))).transpose()?,
        "rdp_shared_folder" => out.rdp_shared_folder = value.map(parse_shared_folder).transpose()?,
        "tab_group_color" => {
            out.tab_group_color = match value {
                Some(v) if crate::tabgroups::GroupColor::parse(v).is_some() => Some(v.to_string()),
                Some(v) => return Err(CoreError::Invalid(format!("Tab group colour: `{v}` is not a group colour."))),
                None => None,
            }
        }
        "host_color" => out.host_color = value.map(crate::hostcolors::normalize).transpose()?,
        "ssh_algorithms" => out.ssh_algorithms = value.map(parse_algorithms).transpose()?,
        "wol_mac" => out.wol_mac = value.map(|v| crate::wol::Mac::parse(v).map(|m| m.to_string())).transpose()?,
        "wol_broadcast" => out.wol_broadcast = value.map(|v| crate::wol::parse_broadcast(v).map(|_| v.trim().to_string())).transpose()?,
        "wol_port" => out.wol_port = value.map(crate::wol::parse_port).transpose()?,
        "wol_secureon" => out.wol_secureon = value.map(|v| crate::wol::SecureOn::parse(v).map(|_| v.trim().to_ascii_lowercase())).transpose()?,
        "wol_before_connect" => out.wol_before_connect = value.map(|v| parse_toggle("Wake before connect", Some(v))).transpose()?,
        "wol_wait_secs" => out.wol_wait_secs = value.map(crate::wol::parse_wait_secs).transpose()?,
        "serial_port" => out.serial_port = value.map(parse_serial_port).transpose()?,
        "serial_baud" => out.serial_baud = value.map(parse_baud).transpose()?,
        "serial_data_bits" => out.serial_data_bits = value.map(|v| parse_small("Data bits", v, 5, 8)).transpose()?,
        "serial_parity" => out.serial_parity = value.map(|v| crate::serial::parse_parity(Some(v)).map(|_| v.to_string())).transpose()?,
        "serial_stop_bits" => out.serial_stop_bits = value.map(|v| parse_small("Stop bits", v, 1, 2)).transpose()?,
        "serial_flow" => out.serial_flow = value.map(|v| crate::serial::parse_flow(Some(v)).map(|_| v.to_string())).transpose()?,
        "serial_local_echo" => out.serial_local_echo = value.map(|v| parse_toggle("Local echo", Some(v))).transpose()?,
        "serial_enter" => out.serial_enter = value.map(|v| crate::serial::parse_enter(Some(v)).map(|_| v.to_string())).transpose()?,
        "telnet_send_password" => out.telnet_send_password = value.map(|v| parse_toggle("Type the saved password", Some(v))).transpose()?,
        "terminal_theme" => {
            out.terminal_theme = match value {
                Some(v) if crate::termthemes::is_theme_id(v) => Some(v.to_string()),
                Some(v) => return Err(CoreError::Invalid(format!("Terminal theme: `{v}` is not a theme."))),
                None => None,
            }
        }
        "gateway_id" => {
            out.gateway_id = value.map(|v| Uuid::parse_str(v).map_err(|_| CoreError::Invalid("Gateway: not a gateway id.".into()))).transpose()?
        }
        _ => return Err(CoreError::Invalid(format!("`{key}` is not a default setting"))),
    }
    Ok(out)
}

/// A port name as typed: the shape only (`COMn` or an absolute `/dev/` name). Whether it exists
/// and is a serial device is checked when opening (`serial::validate_port`); it may be unplugged now.
fn parse_serial_port(v: &str) -> Result<String> {
    let v = v.trim();
    let ok = crate::serial::validate_windows_port(v).is_ok() || crate::serial::is_serial_device_path(v);
    if !ok || v.len() > 256 {
        return Err(CoreError::Invalid(format!("Port: `{v}` is not a serial port name (COM1 to COM256, /dev/cu.* or /dev/tty.*).")));
    }
    Ok(v.to_string())
}

fn parse_baud(v: &str) -> Result<u32> {
    use crate::serial::{MAX_BAUD, MIN_BAUD};
    v.trim().parse::<u32>().ok().filter(|b| (MIN_BAUD..=MAX_BAUD).contains(b)).ok_or_else(|| CoreError::Invalid(format!("Baud rate must be {MIN_BAUD} to {MAX_BAUD}.")))
}

fn parse_small(label: &str, v: &str, min: u8, max: u8) -> Result<u8> {
    v.trim().parse::<u8>().ok().filter(|n| (min..=max).contains(n)).ok_or_else(|| CoreError::Invalid(format!("{label} must be {min} to {max}.")))
}

pub(crate) fn parse_port(v: &str) -> Result<u16> {
    v.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| CoreError::Invalid("Port must be a number from 1 to 65535.".into()))
}

fn parse_font_size(v: &str) -> Result<u32> {
    use crate::termfonts::{MAX_SIZE, MIN_SIZE};
    v.trim()
        .parse::<u32>()
        .ok()
        .filter(|s| (MIN_SIZE..=MAX_SIZE).contains(s))
        .ok_or_else(|| CoreError::Invalid(format!("Terminal font size must be {MIN_SIZE} to {MAX_SIZE} points.")))
}

const MAX_KEEPALIVE_SECS: u32 = 86_400;

fn parse_seconds(v: &str) -> Result<u32> {
    v.parse::<u32>()
        .ok()
        .filter(|s| (1..=MAX_KEEPALIVE_SECS).contains(s))
        .ok_or_else(|| CoreError::Invalid(format!("Keep-alive must be 1 to {MAX_KEEPALIVE_SECS} seconds.")))
}

/// Blank input means "not set" (inherit).
fn normalise(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

/// Folders from the root down to `id`: including `id` when it is a folder, its parent chain
/// when it is a connection. `None` when `id` is not in the document.
fn ancestors(doc: &Document, id: Uuid) -> Option<Vec<&Folder>> {
    fn walk<'a>(f: &'a Folder, id: Uuid, path: &mut Vec<&'a Folder>) -> bool {
        path.push(f);
        if f.id == id {
            return true;
        }
        for n in &f.children {
            match n {
                Node::Connection(c) if c.id == id => return true,
                Node::Folder(sub) if walk(sub, id, path) => return true,
                _ => {}
            }
        }
        path.pop();
        false
    }
    let mut path = Vec::new();
    walk(&doc.root, id, &mut path).then_some(path)
}

pub(crate) fn find_connection(f: &Folder, id: Uuid) -> Option<&Connection> {
    f.children.iter().find_map(|n| match n {
        Node::Connection(c) if c.id == id => Some(c),
        Node::Folder(sub) => find_connection(sub, id),
        _ => None,
    })
}

/// Algorithm settings as JSON; rejected when a list would leave nothing to offer.
fn parse_algorithms(v: &str) -> Result<crate::algorithms::AlgorithmSettings> {
    let a: crate::algorithms::AlgorithmSettings = serde_json::from_str(v).map_err(|e| CoreError::Invalid(format!("Algorithms: {e}")))?;
    a.resolve(false)?;
    Ok(a)
}

/// "Allow for this host" after [`CoreError::NoCommonAlgorithm`]: the connection's own settings
/// become its effective ones plus `names`, with the weak opt-in set. Policy is still checked when
/// connecting, so a forbidding policy keeps refusing.
pub fn allow_weak_algorithms(doc: &mut Document, id: Uuid, kind: crate::algorithms::AlgoKind, names: &[String]) -> Result<()> {
    if names.is_empty() || names.iter().any(|n| !crate::algorithms::is_weak(kind, n) || !crate::algorithms::is_implemented(kind, n)) {
        return Err(CoreError::Invalid("only weak algorithms Gantry implements can be allowed for a host".into()));
    }
    let current = doc.resolve(id)?.effective.ssh_algorithms.unwrap_or_default();
    let next = serde_json::to_string(&current.allowing(kind, names)).map_err(|e| CoreError::Invalid(e.to_string()))?;
    set_value(doc, id, "ssh_algorithms", Some(&next))
}

/// A local folder to share over RDP: an absolute path, never the whole disk. Whether it exists is
/// checked when connecting (an external disk may be unplugged now).
/// A full folder path: `/…` (macOS) or a drive-letter path `C:\…` / `C:/…` (Windows).
fn parse_shared_folder(v: &str) -> Result<String> {
    let v = v.trim();
    let bad = |why: &str| Err(CoreError::Invalid(format!("Shared folder: {why}")));
    let b = v.as_bytes();
    let drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
    if !v.starts_with('/') && !drive {
        return bad(if cfg!(windows) { "use the folder's full path, such as C:\\Users\\you\\Share." } else { "use the folder's full path, starting with /." });
    }
    let rest = if drive { &v[2..] } else { v };
    if rest.trim_end_matches(['/', '\\']).is_empty() {
        return bad("share a folder, not the whole disk.");
    }
    if v.len() > 1024 || v.chars().any(char::is_control) || rest.split(['/', '\\']).any(|c| c == "..") {
        return bad("not a usable folder path.");
    }
    Ok(v.to_string())
}

/// A session log folder: a full path, no `..`, no control characters (LOG-CORE-02).
fn parse_log_folder(v: &str) -> Result<String> {
    crate::sessionlog::validate_log_folder(v).map_err(|e| CoreError::Invalid(format!("Session log folder: {e}")))
}

/// Session log keep time in whole days, 0 (forever) to 3650 (LOG-CORE-02).
fn parse_keep_days(v: &str) -> Result<u32> {
    v.trim()
        .parse::<u32>()
        .ok()
        .filter(|d| *d <= crate::sessionlog::MAX_KEEP_DAYS)
        .ok_or_else(|| CoreError::Invalid(format!("Keep session logs for: enter a whole number of days from 0 to {}", crate::sessionlog::MAX_KEEP_DAYS)))
}

fn builtin(protocol: Protocol, key: &str) -> Fallback {
    match (key, protocol.default_port()) {
        ("port", Some(p)) => (Some(p.to_string()), ValueSource::Builtin, None),
        ("auto_reconnect", _) => (Some("true".into()), ValueSource::Builtin, None),
        ("session_log" | "no_preview" | "host_status" | "rdp_nla_only" | "web_autofill", _) => (Some("false".into()), ValueSource::Builtin, None),
        ("rdp_clipboard" | "rdp_audio", _) => (Some("true".into()), ValueSource::Builtin, None),
        ("wol_before_connect" | "serial_local_echo" | "telnet_send_password", _) => (Some("false".into()), ValueSource::Builtin, None),
        ("serial_baud", _) => (Some(crate::serial::DEFAULT_BAUD.to_string()), ValueSource::Builtin, None),
        ("serial_data_bits", _) => (Some("8".into()), ValueSource::Builtin, None),
        ("serial_stop_bits", _) => (Some("1".into()), ValueSource::Builtin, None),
        ("serial_parity" | "serial_flow", _) => (Some("none".into()), ValueSource::Builtin, None),
        ("serial_enter", _) => (Some("cr".into()), ValueSource::Builtin, None),
        ("wol_broadcast", _) => (Some("255.255.255.255".into()), ValueSource::Builtin, None),
        ("wol_port", _) => (Some(crate::wol::DEFAULT_PORT.to_string()), ValueSource::Builtin, None),
        ("wol_wait_secs", _) => (Some(crate::wol::DEFAULT_WAIT_SECS.to_string()), ValueSource::Builtin, None),
        _ => NONE,
    }
}

/// Resolve an inheritable key through `folders` (nearest last), type defaults and built-ins.
fn inherited(doc: &Document, folders: &[&Folder], protocol: Option<Protocol>, key: &str) -> Fallback {
    // Never inherited: only the connection's own opt-in counts (B7).
    if key == "telnet_send_password" {
        return protocol.map_or(NONE, |p| builtin(p, key));
    }
    if let Some((f, v)) = folders.iter().rev().find_map(|f| get(&f.defaults, key).map(|v| (f, v))) {
        let name = if f.id == doc.root.id { "Library".to_string() } else { f.name.clone() };
        return (Some(v), ValueSource::Inherited, Some(name));
    }
    let Some(p) = protocol else { return NONE };
    match doc.type_defaults.get(&p).and_then(|t| get(t, key)) {
        Some(v) => (Some(v), ValueSource::TypeDefault, Some(protocol_name(p))),
        None => builtin(p, key),
    }
}

pub fn protocol_name(p: Protocol) -> String {
    p.as_str().to_string()
}

fn value(key: &str, own: Option<String>, fallback: Fallback) -> PropertyValue {
    match own {
        Some(v) => PropertyValue { key: key.into(), own: Some(v.clone()), effective: Some(v), source: ValueSource::Own, from: None },
        None => PropertyValue { key: key.into(), own: None, effective: fallback.0, source: fallback.1, from: fallback.2 },
    }
}

/// Every schema property of a connection with its effective value and source.
pub fn connection_values(doc: &Document, id: Uuid) -> Result<Vec<PropertyValue>> {
    let c = find_connection(&doc.root, id).ok_or_else(|| CoreError::NotFound(id.to_string()))?;
    let folders = ancestors(doc, id).unwrap_or_default();
    Ok(schema_of(c)
        .into_iter()
        .map(|d| match d.key {
            "name" => value(d.key, Some(c.name.clone()), NONE),
            "host" => value(d.key, Some(c.host.clone()), NONE),
            "notes" => value(d.key, Some(c.notes.clone()).filter(|n| !n.is_empty()), NONE),
            "tags" => value(d.key, Some(c.tags.join(", ")).filter(|t| !t.is_empty()), NONE),
            "environment" => value(d.key, Some(environment_id(c.classification.environment)), NONE),
            "customer_sensitive" => value(d.key, Some(c.classification.customer_sensitive.to_string()), NONE),
            "privileged" => value(d.key, Some(c.classification.privileged_infrastructure.to_string()), NONE),
            key if key.contains('.') => {
                let builtin = d.options.first().map_or(NONE, |(o, _)| (Some(o.to_string()), ValueSource::Builtin, None));
                value(key, c.metadata.get(key).cloned(), builtin)
            }
            key => value(key, get(&c.settings, key), inherited(doc, &folders, Some(c.protocol), key)),
        })
        .collect())
}

/// A connection's credential assignment and where it comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialRef {
    Id(Uuid),
    /// Looked up by name in the vault when connecting.
    Name(String),
}

/// The credential a connection connects with: the nearest level (the connection, its folders
/// up to the root, then the type's Default Settings) that sets an id or a name; at one level an
/// id wins over a name. With the source as in `PropertyValue` (`from` = folder or type name).
/// Inline secrets (`vault::Vault::inline`) take precedence over all of this and are checked by
/// the caller, which holds the vault.
pub fn effective_credential(doc: &Document, id: Uuid) -> Result<Option<(CredentialRef, ValueSource, Option<String>)>> {
    let c = find_connection(&doc.root, id).ok_or_else(|| CoreError::NotFound(id.to_string()))?;
    let folders = ancestors(doc, id).unwrap_or_default();
    Ok(effective_credential_with_ancestors(doc, &folders, c))
}

/// [`effective_credential`] when the caller already holds the connection's folder chain
/// (root first), e.g. while walking the whole tree: no per-connection search.
pub fn effective_credential_with_ancestors(
    doc: &Document,
    folders: &[&Folder],
    c: &Connection,
) -> Option<(CredentialRef, ValueSource, Option<String>)> {
    let pick = |s: &Settings| s.credential_id.map(CredentialRef::Id).or_else(|| s.credential_name.clone().map(CredentialRef::Name));
    if let Some(r) = pick(&c.settings) {
        return Some((r, ValueSource::Own, None));
    }
    if let Some((f, r)) = folders.iter().rev().find_map(|f| pick(&f.defaults).map(|r| (f, r))) {
        let name = if f.id == doc.root.id { "Library".to_string() } else { f.name.clone() };
        return Some((r, ValueSource::Inherited, Some(name)));
    }
    doc.type_defaults.get(&c.protocol).and_then(pick).map(|r| (r, ValueSource::TypeDefault, Some(protocol_name(c.protocol))))
}

/// Folder defaults with what each would inherit from further up when unset.
pub fn folder_values(doc: &Document, folder_id: Uuid) -> Result<Vec<PropertyValue>> {
    let chain = ancestors(doc, folder_id).filter(|c| c.last().is_some_and(|f| f.id == folder_id));
    let chain = chain.ok_or_else(|| CoreError::NotFound(folder_id.to_string()))?;
    let (here, above) = chain.split_last().expect("chain ends at the folder");
    let inheritable = default_schema(None).into_iter().map(|d| value(d.key, get(&here.defaults, d.key), inherited(doc, above, None, d.key)));
    // The root is no folder to fence, and a top-level folder is a boundary whatever it says.
    let boundary = (!above.is_empty()).then(|| {
        let builtin = (Some((above.len() == 1).to_string()), ValueSource::Builtin, None);
        value(CREDENTIAL_BOUNDARY_KEY, here.defaults.credential_boundary.map(|b| b.to_string()), builtin)
    });
    Ok(inheritable.chain(boundary).collect())
}

/// A connection type's Default Settings over the protocol's built-ins.
pub fn type_values(doc: &Document, protocol: Protocol) -> Vec<PropertyValue> {
    let own = doc.type_defaults.get(&protocol).cloned().unwrap_or_default();
    default_schema(Some(protocol)).into_iter().map(|d| value(d.key, get(&own, d.key), builtin(protocol, d.key))).collect()
}

const MAX_NAME_LEN: usize = 256;
/// Longest DNS name (RFC 1035); IPv6 literals are far shorter.
const MAX_HOST_LEN: usize = 253;
const MAX_NOTES_LEN: usize = 64 * 1024;

fn check_len(label: &str, v: &str, max: usize) -> Result<()> {
    if v.len() > max {
        return Err(CoreError::Invalid(format!("{label} is longer than {max} characters.")));
    }
    Ok(())
}

/// A host is passed to name resolution and shown in prompts: one token, no control characters,
/// and never something that could read as a command-line option.
pub(crate) fn check_host(v: &str) -> Result<()> {
    check_len("Computer name", v, MAX_HOST_LEN)?;
    if v.starts_with('-') || v.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(CoreError::Invalid("Computer name must be a single host name or address without spaces.".into()));
    }
    Ok(())
}

/// One field edit with the normal rules and messages, without a document (B9 templates).
pub(crate) fn apply_field(c: &Connection, key: &str, value: Option<&str>) -> Result<Connection> {
    edit_connection(c, key, value)
}

/// A host written as a URL must be `http` or `https` on a web connection; no other connection
/// type takes a URL (B9: `file://` and the like are refused).
pub(crate) fn check_url_scheme(c: &Connection) -> Result<()> {
    let Some((scheme, _)) = c.host.split_once("://") else { return Ok(()) };
    let scheme = scheme.to_ascii_lowercase();
    if c.protocol != Protocol::Web || !(scheme == "http" || scheme == "https") {
        return Err(CoreError::Invalid("Address must start with http:// or https://.".into()));
    }
    Ok(())
}

/// Tags as stored: trimmed, lower case, no blanks, no duplicates, first spelling's order kept.
pub fn normalize_tags<'a>(tags: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in tags.into_iter().map(|t| t.trim().to_lowercase()).filter(|t| !t.is_empty()) {
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

fn edit_connection(c: &Connection, key: &str, value: Option<&str>) -> Result<Connection> {
    let plugin_key = is_plugin_entry(c) && plugin_entry_schema().iter().any(|d| d.key == key);
    if c.protocol == Protocol::Unsupported && !plugin_key && !matches!(key, "name" | "notes" | "tags") {
        return Err(CoreError::Invalid(crate::unknown::NEEDS_NEWER.into()));
    }
    let mut next = c.clone();
    match key {
        "name" => {
            let v = value.ok_or_else(|| CoreError::Invalid("Display name is required.".into()))?;
            check_len("Display name", v, MAX_NAME_LEN)?;
            next.name = v.to_string();
        }
        "host" => {
            let v = value.ok_or_else(|| CoreError::Invalid("Computer name is required.".into()))?;
            check_host(v)?;
            next.host = v.to_string();
        }
        "protocol" => next = change_protocol(c, value)?,
        "notes" => {
            let v = value.unwrap_or_default();
            check_len("Notes", v, MAX_NOTES_LEN)?;
            next.notes = v.to_string();
        }
        "tags" => next.tags = normalize_tags(value.unwrap_or_default().split(',')),
        "environment" => {
            let id = value.unwrap_or("unclassified");
            if !ENVIRONMENTS.iter().any(|(e, _)| *e == id) {
                return Err(CoreError::Invalid(format!("Environment: `{id}` is not one of the options.")));
            }
            next.classification.environment =
                serde_json::from_value(serde_json::Value::String(id.into())).map_err(|_| CoreError::Invalid(format!("Environment: `{id}`")))?;
        }
        "customer_sensitive" => next.classification.customer_sensitive = parse_toggle("Customer-sensitive", value)?,
        "privileged" => next.classification.privileged_infrastructure = parse_toggle("Privileged infrastructure", value)?,
        key if !schema_of(c).iter().any(|d| d.key == key) => {
            return Err(CoreError::Invalid(format!("`{key}` does not apply to this connection type")))
        }
        key if key.contains('.') => {
            let d = schema_of(c).into_iter().find(|d| d.key == key).expect("checked above");
            match value {
                None => {
                    next.metadata.remove(key);
                }
                Some(v) => {
                    check_meta(&d, v)?;
                    next.metadata.insert(key.to_string(), v.to_string());
                }
            }
        }
        _ => next.settings = set(&c.settings, key, value)?,
    }
    Ok(next)
}

/// Protocols a host connection can be switched between (owner 2026-11-07: RDP <-> SSH).
pub const SWITCHABLE_PROTOCOLS: [Protocol; 4] = [Protocol::Ssh, Protocol::Rdp, Protocol::Vnc, Protocol::Telnet];

/// The connection under another protocol. A port left at the old protocol's default follows the
/// new one (cleared); a custom port stays. Settings of the old type stay in metadata, unused.
fn change_protocol(c: &Connection, value: Option<&str>) -> Result<Connection> {
    let name = value.unwrap_or_default().to_lowercase();
    let to = SWITCHABLE_PROTOCOLS.into_iter().find(|p| p.as_str() == name);
    let to = to.ok_or_else(|| CoreError::Invalid(format!("Protocol: `{name}` is not one of ssh, rdp, vnc, telnet.")))?;
    if !SWITCHABLE_PROTOCOLS.contains(&c.protocol) {
        return Err(CoreError::Invalid(format!("A {} connection's protocol cannot be changed.", c.protocol.as_str())));
    }
    let mut next = c.clone();
    if next.settings.port.is_some() && next.settings.port == c.protocol.default_port() {
        next.settings.port = None;
    }
    next.protocol = to;
    Ok(next)
}

#[cfg(test)]
mod protocol_change_tests {
    use super::*;

    #[test]
    fn ssh_becomes_rdp_and_default_port_follows() {
        let mut c = Connection::new("box", Protocol::Ssh, "10.0.0.5");
        c.settings.port = Some(22);
        let next = edit_connection(&c, "protocol", Some("RDP")).unwrap();
        assert_eq!(next.protocol, Protocol::Rdp);
        assert_eq!(next.settings.port, None);
        assert_eq!(next.host, "10.0.0.5");
    }

    #[test]
    fn custom_port_is_kept() {
        let mut c = Connection::new("box", Protocol::Rdp, "h");
        c.settings.port = Some(4000);
        assert_eq!(edit_connection(&c, "protocol", Some("ssh")).unwrap().settings.port, Some(4000));
    }

    #[test]
    fn rejects_unknown_and_non_host_protocols() {
        let c = Connection::new("box", Protocol::Ssh, "h");
        assert!(edit_connection(&c, "protocol", Some("ftp")).is_err());
        assert!(edit_connection(&c, "protocol", None).is_err());
        let local = Connection::new("sh", Protocol::Local, "");
        assert!(edit_connection(&local, "protocol", Some("ssh")).is_err());
    }
}

fn check_meta(d: &PropertyDef, v: &str) -> Result<()> {
    // `local.shell` also takes `wsl:<distro>`, which no fixed list can hold; `localshell::check` decides it below.
    let open_choice = d.key == crate::localshell::SHELL;
    if d.kind == PropKind::Choice && !open_choice && !d.options.iter().any(|(id, _)| *id == v) {
        let ids: Vec<&str> = d.options.iter().map(|(id, _)| *id).collect();
        return Err(CoreError::Invalid(format!("{} must be one of: {}.", d.label, ids.join(", "))));
    }
    if [crate::remoteshell::TMUX, crate::remoteshell::TMUX_SESSION, crate::remoteshell::TRANSPORT].contains(&d.key) {
        crate::remoteshell::check(d.key, v)?;
    }
    if d.key == RDP_SSH_PORT {
        parse_port(v)?;
    }
    if d.key == RDP_SSH_USER {
        check_len("SSH username", v, MAX_NAME_LEN)?;
        if v.trim().is_empty() || v.chars().any(char::is_control) {
            return Err(CoreError::Invalid("SSH username: leave it empty or type a username.".into()));
        }
    }
    if d.key.starts_with("local.") {
        crate::localshell::check(d.key, v)?;
    }
    if d.key == WEB_USER_AGENT && (v.len() > MAX_USER_AGENT || !v.chars().all(|ch| (' '..='~').contains(&ch))) {
        return Err(CoreError::Invalid(format!("User agent must be printable ASCII, at most {MAX_USER_AGENT} characters.")));
    }
    Ok(())
}

/// A connection's own value of a per-connection (metadata) setting, or its built-in value.
pub fn meta_value(c: &Connection, key: &str) -> Option<String> {
    let d = schema_of(c).into_iter().find(|d| d.key == key)?;
    c.metadata.get(key).filter(|v| check_meta(&d, v).is_ok()).cloned().or_else(|| d.options.first().map(|(o, _)| o.to_string()))
}

/// A folder's defaults with `key` set: an inheritable setting, or one only a folder has.
fn set_folder_default(s: &Settings, key: &str, value: Option<&str>) -> Result<Settings> {
    if key != CREDENTIAL_BOUNDARY_KEY {
        return set(s, key, value);
    }
    let credential_boundary = value.map(|v| parse_toggle(CREDENTIAL_BOUNDARY.label, Some(v))).transpose()?;
    Ok(Settings { credential_boundary, ..s.clone() })
}

/// Edit `key` on the connection or folder `id`; `None` when no such node exists.
fn edit_node(folder: &mut Folder, id: Uuid, key: &str, value: Option<&str>) -> Option<Result<()>> {
    if folder.id == id {
        return Some(set_folder_default(&folder.defaults, key, value).map(|next| folder.defaults = next));
    }
    folder.children.iter_mut().find_map(|n| match n {
        Node::Connection(c) if c.id == id => Some(edit_connection(c, key, value).map(|next| *c = next)),
        Node::Folder(sub) => edit_node(sub, id, key, value),
        _ => None,
    })
}

/// Set one property on a connection or folder; `None` or blank resets it to inherited.
/// On error the document is unchanged.
pub fn set_value(doc: &mut Document, id: Uuid, key: &str, value: Option<&str>) -> Result<()> {
    check_gateway(doc, key, normalise(value))?;
    if key == CREDENTIAL_BOUNDARY_KEY && id == doc.root.id {
        return Err(CoreError::Invalid(format!("{}: set it on a folder, not on the library itself.", CREDENTIAL_BOUNDARY.label)));
    }
    edit_node(&mut doc.root, id, key, normalise(value)).unwrap_or_else(|| Err(CoreError::NotFound(id.to_string())))
}

/// A gateway reference must name a gateway of this library.
fn check_gateway(doc: &Document, key: &str, value: Option<&str>) -> Result<()> {
    match (key, value) {
        ("gateway_id", Some(v)) if !doc.gateways.iter().any(|g| g.id.to_string() == v) => {
            Err(CoreError::Invalid("Gateway: choose one from the Gateway Manager.".into()))
        }
        _ => Ok(()),
    }
}

/// Set or reset one Default Setting for a connection type.
pub fn set_type_value(doc: &mut Document, protocol: Protocol, key: &str, value: Option<&str>) -> Result<()> {
    if protocol == Protocol::Unsupported {
        return Err(CoreError::Invalid(crate::unknown::NEEDS_NEWER.into()));
    }
    if !default_schema(Some(protocol)).iter().any(|d| d.key == key) {
        return Err(CoreError::Invalid(format!("`{key}` is not a default setting for this type")));
    }
    check_gateway(doc, key, normalise(value))?;
    let current = doc.type_defaults.get(&protocol).cloned().unwrap_or_default();
    let next = set(&current, key, normalise(value))?;
    if next == Settings::default() {
        doc.type_defaults.remove(&protocol);
    } else {
        doc.type_defaults.insert(protocol, next);
    }
    Ok(())
}

/// Names of connections whose `key` would change if the default at `folder` (or, with `None`,
/// the type default for `protocol`) changed: those that neither set it themselves nor get it
/// from somewhere nearer.
pub fn affected_by(doc: &Document, folder: Option<Uuid>, protocol: Option<Protocol>, key: &str) -> Vec<String> {
    // One walk carrying whether the edited default reaches this folder (H02): for a folder
    // default, from that folder down until a nearer folder sets the key; for the root
    // (`None`), from the root down under the same rule.
    struct Walk<'a> {
        folder: Option<Uuid>,
        protocol: Option<Protocol>,
        key: &'a str,
        has_key: BTreeMap<Protocol, bool>,
        out: Vec<String>,
    }
    fn visit(w: &mut Walk, f: &Folder, parent_reaches: bool) {
        let reaches = w.folder == Some(f.id) || (parent_reaches && get(&f.defaults, w.key).is_none());
        for n in &f.children {
            match n {
                Node::Folder(sub) => visit(w, sub, reaches),
                Node::Connection(c) if reaches && w.protocol.map_or(true, |p| c.protocol == p) => {
                    let key = w.key;
                    let in_schema = *w.has_key.entry(c.protocol).or_insert_with(|| schema(c.protocol).iter().any(|d| d.key == key));
                    if in_schema && get(&c.settings, key).is_none() {
                        w.out.push(c.name.clone());
                    }
                }
                Node::Connection(_) => {}
            }
        }
    }
    let mut w = Walk { folder, protocol, key, has_key: BTreeMap::new(), out: Vec::new() };
    visit(&mut w, &doc.root, folder.is_none());
    w.out
}

#[cfg(test)]
mod shared_folder_tests {
    use super::parse_shared_folder;

    #[test]
    fn shared_folder_accepts_unix_and_drive_paths() {
        assert_eq!(parse_shared_folder("/Users/me/Share").unwrap(), "/Users/me/Share");
        assert_eq!(parse_shared_folder(r"C:\Users\me\Share").unwrap(), r"C:\Users\me\Share");
        assert_eq!(parse_shared_folder("d:/work/share").unwrap(), "d:/work/share");
        for bad in ["relative", "/", r"C:\", "C:/", r"C:\a\..\b", "/a/../b", "C:share"] {
            assert!(parse_shared_folder(bad).is_err(), "{bad}");
        }
    }
}
