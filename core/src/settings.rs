//! Application settings shared by both frontends: the definitions (category, label, control,
//! default, validation), search across them, and the per-user `settings.json` next to the library.
//!
//! Only settings that persist and take effect are defined here. A `Link` entry is a page or
//! command the frontend provides (the Credential Manager, per-type connection defaults, …); like
//! actions, frontends pass the link targets they handle and see only those.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::error::{CoreError, Result};
use crate::store::write_atomic;

/// Settings categories in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    General,
    Appearance,
    Terminal,
    ConnectionDefaults,
    Ssh,
    Credentials,
    Vaultwarden,
    Workspaces,
    Keyboard,
    Security,
    Updates,
    About,
}

impl Category {
    pub const ALL: [Category; 12] = [
        Category::General,
        Category::Appearance,
        Category::Terminal,
        Category::ConnectionDefaults,
        Category::Ssh,
        Category::Credentials,
        Category::Vaultwarden,
        Category::Workspaces,
        Category::Keyboard,
        Category::Security,
        Category::Updates,
        Category::About,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Category::General => "general",
            Category::Appearance => "appearance",
            Category::Terminal => "terminal",
            Category::ConnectionDefaults => "connection-defaults",
            Category::Ssh => "ssh",
            Category::Credentials => "credentials",
            Category::Vaultwarden => "vaultwarden",
            Category::Workspaces => "workspaces",
            Category::Keyboard => "keyboard",
            Category::Security => "security",
            Category::Updates => "updates",
            Category::About => "about",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Category::General => "General",
            Category::Appearance => "Appearance",
            Category::Terminal => "Terminal",
            Category::ConnectionDefaults => "Connection Defaults",
            Category::Ssh => "SSH",
            Category::Credentials => "Credentials",
            Category::Vaultwarden => "Vaultwarden",
            Category::Workspaces => "Workspaces",
            Category::Keyboard => "Keyboard",
            Category::Security => "Security",
            Category::Updates => "Updates",
            Category::About => "About",
        }
    }

    /// Icon id (see `icons.rs`) for the category list.
    pub fn icon(self) -> &'static str {
        match self {
            Category::General => "settings",
            Category::Appearance => "appearance",
            Category::Terminal => "local-terminal",
            Category::ConnectionDefaults => "defaults",
            Category::Ssh => "ssh",
            Category::Credentials => "credential",
            Category::Vaultwarden => "vault",
            Category::Workspaces => "workspace",
            Category::Keyboard => "keyboard",
            Category::Security => "security",
            Category::Updates => "update",
            Category::About => "about",
        }
    }
}

/// The control a setting uses and the values it accepts.
#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// One of `(id, label)`; stored as the id.
    Choice(&'static [(&'static str, &'static str)]),
    /// `"true"` / `"false"`.
    Toggle,
    /// Whole number in `min..=max`.
    Integer { min: i64, max: i64, unit: &'static str },
    /// A page or command the frontend provides; holds no value.
    Link(&'static str),
    /// Free text of at most `max_len` bytes; `multiline` allows one entry per line.
    Text { max_len: usize, multiline: bool },
}

#[derive(Debug, Clone, PartialEq)]
pub struct SettingDef {
    pub id: &'static str,
    pub category: Category,
    pub label: &'static str,
    /// One short sentence for the tooltip / help popover. Never a paragraph.
    pub help: &'static str,
    pub kind: Kind,
    /// Stored form of the default value (empty for links).
    pub default: &'static str,
    /// Extra words search should match.
    pub keywords: &'static [&'static str],
    /// A link target or capability the frontend must handle for this setting to mean anything
    /// (links require their own target).
    pub requires: Option<&'static str>,
}

impl SettingDef {
    pub fn link_target(&self) -> Option<&'static str> {
        match self.kind {
            Kind::Link(t) => Some(t),
            _ => None,
        }
    }

    fn requiring(mut self, capability: &'static str) -> Self {
        self.requires = Some(capability);
        self
    }

    /// Check a value against the control's rules; returns the stored form.
    pub fn validate(&self, value: &str) -> Result<String> {
        let bad = |why: String| CoreError::Invalid(format!("{}: {why}", self.label));
        match &self.kind {
            Kind::Choice(options) => options
                .iter()
                .find(|(id, _)| *id == value)
                .map(|(id, _)| id.to_string())
                .ok_or_else(|| bad(format!("`{value}` is not one of the options"))),
            Kind::Toggle => match value {
                "true" | "false" => Ok(value.to_string()),
                _ => Err(bad(format!("`{value}` is not on or off"))),
            },
            Kind::Integer { min, max, .. } => match value.trim().parse::<i64>() {
                Ok(n) if (*min..=*max).contains(&n) => Ok(n.to_string()),
                _ => Err(bad(format!("enter a whole number from {min} to {max}"))),
            },
            Kind::Link(_) => Err(bad("holds no value".into())),
            Kind::Text { max_len, multiline } => {
                let v = value.trim();
                if v.len() > *max_len {
                    return Err(bad(format!("at most {max_len} characters")));
                }
                if v.chars().any(|c| c.is_control() && !(*multiline && (c == '\n' || c == '\r'))) {
                    return Err(bad("contains control characters".into()));
                }
                Ok(v.to_string())
            }
        }
    }

    fn matches(&self, terms: &[String]) -> bool {
        let mut hay = format!("{} {} {} {}", self.label, self.help, self.category.label(), self.keywords.join(" "));
        if let Kind::Choice(options) = self.kind {
            for (_, label) in options {
                hay.push(' ');
                hay.push_str(label);
            }
        }
        let hay = hay.to_lowercase();
        terms.iter().all(|t| hay.contains(t.as_str()))
    }
}

pub const MODES: &[(&str, &str)] = &[("system", "System"), ("light", "Light"), ("dark", "Dark"), ("high-contrast", "High Contrast")];
pub const ACCENTS: &[(&str, &str)] = &[
    ("electric", "Electric Blue"),
    ("cyan", "Cyan"),
    ("violet", "Violet"),
    ("emerald", "Emerald"),
    ("amber", "Amber"),
    ("rose", "Rose"),
];
/// Same ids as `theme::Density`.
/// Whole-window zoom steps in percent; frontends that scale their UI report the `ui-zoom` capability.
pub const ZOOMS: &[(&str, &str)] = &[("80", "80%"), ("90", "90%"), ("100", "100%"), ("110", "110%"), ("125", "125%"), ("150", "150%"), ("175", "175%"), ("200", "200%")];
pub const HEADER_STYLES: &[(&str, &str)] = &[("compact", "Compact"), ("classic", "Classic")];
pub const DENSITIES: &[(&str, &str)] = &[("compact", "Compact"), ("comfortable", "Comfortable"), ("spacious", "Spacious")];
/// Same ids and order as `termthemes::BUNDLED`; user themes (`custom-…`) are accepted too.
pub const TERMINAL_THEMES: &[(&str, &str)] = &[
    (crate::termthemes::MATCH_APP, "Match app theme"),
    ("bastion-dark", "Gantry Dark"),
    ("bastion-light", "Gantry Light"),
    ("high-contrast", "High Contrast"),
    ("catppuccin-mocha", "Catppuccin Mocha"),
    ("catppuccin-latte", "Catppuccin Latte"),
    ("dracula", "Dracula"),
    ("tokyo-night", "Tokyo Night"),
    ("nord", "Nord"),
    ("gruvbox-dark", "Gruvbox Dark"),
    ("solarized-dark", "Solarized Dark"),
    ("solarized-light", "Solarized Light"),
    ("one-dark", "One Dark"),
    ("monokai", "Monokai"),
];
/// OSC 52 (a remote program copying to the local clipboard); reading the clipboard is never allowed.
/// Names the machine the app runs on.
const OSC52_HELP: &str = if cfg!(windows) {
    "Programs on a server may put text on this PC's clipboard; they can never read it."
} else {
    "Programs on a server may put text on this Mac's clipboard; they can never read it."
};
pub const OSC52: &[(&str, &str)] = &[("off", "Off"), ("ask", "Ask each time"), ("allow", "Allow")];
/// Terminal fonts a Windows frontend offers; `bundled` is the Nerd Font shipped with the app (Powerline and icon glyphs).
pub const TERMINAL_FONTS: &[(&str, &str)] = &[
    ("bundled", "CaskaydiaMono Nerd Font Mono (bundled)"),
    ("cascadia-mono", "Cascadia Mono"),
    ("consolas", "Consolas"),
    ("courier-new", "Courier New"),
];
/// What the terminal does when a program rings the bell (BEL).
pub const BELL: &[(&str, &str)] = &[("off", "Off"), ("visual", "Flash the terminal"), ("sound", "Play the system sound"), ("both", "Flash and sound")];
/// How the main window opens (owner 2026-11-15). Only frontends that declare `window-launch` show these settings.
pub const WINDOW_LAUNCH: &[(&str, &str)] = &[("remember", "Remember last size and position"), ("fixed", "Fixed size"), ("maximized", "Maximised"), ("full-screen", "Full screen")];
pub const DOUBLE_CLICK: &[(&str, &str)] = &[("connect", "Connect"), ("properties", "Open Properties")];
/// What the New terminal button opens (W27). Only shells that declare `terminal-new-tab` show the setting.
pub const NEW_TAB_SHELLS: &[(&str, &str)] = &[("local", "Default shell"), ("powershell", "PowerShell"), ("cmd", "Command Prompt"), ("wsl", "WSL (default distribution)")];
pub const CURSOR_STYLES: &[(&str, &str)] = &[("block", "Block"), ("bar", "Bar"), ("underline", "Underline")];
/// Minutes without keyboard or mouse input before credentials lock; `off` never.
pub const AUTO_LOCK: &[(&str, &str)] = &[("off", "Off"), ("5", "5 minutes"), ("15", "15 minutes"), ("30", "30 minutes"), ("60", "1 hour")];
/// Seconds a copied password stays on the clipboard before the app clears its own copy (A3-S1).
/// Frontends that clear it report the `secret-clipboard-lifetime` capability.
pub const SECRET_CLIPBOARD_SECONDS: &[(&str, &str)] = &[("30", "30 seconds"), ("45", "45 seconds"), ("60", "60 seconds")];
pub const SECRET_CLIPBOARD_SETTING: &str = "security.clipboard-clear-seconds";
/// "Allow Telnet" (B7): off by default; frontends confirm once when it is turned on.
pub const ALLOW_TELNET_SETTING: &str = "security.allow-telnet";
/// Minutes an app may reuse the login it remembers for a connection (0: until Lock or quit).
pub const SESSION_LOGIN_REUSE_SETTING: &str = "security.session-login-reuse-minutes";
/// Used when the setting cannot be read or holds something else: the shortest choice, never longer.
pub const SECRET_CLIPBOARD_FALLBACK_SECONDS: u64 = 30;
/// Names what may keep its own copy on the machine the app runs on.
const SECRET_CLIPBOARD_HELP: &str = if cfg!(windows) {
    "Only while it is still the latest copy; clipboard tools that ignore the history exclusion may keep theirs."
} else {
    "Only while it is still the latest copy; Universal Clipboard and managers that ignore the concealed mark may keep theirs."
};
/// `security.confirm-vault-open` names the platform's own owner check (PARITY.md: Touch ID on the Mac,
/// Windows Hello on Windows). Frontends that ask for it report the `vault-open-confirm` capability.
const VAULT_CONFIRM_LABEL: &str = if cfg!(windows) { "Require Windows Hello to open the vault" } else { "Require Touch ID to open the vault" };
const VAULT_CONFIRM_HELP: &str = if cfg!(windows) {
    "Face, fingerprint or PIN each time the local vault opens."
} else {
    "Touch ID or the login password each time the local vault opens."
};
const VAULT_CONFIRM_KEYWORDS: &[&str] = if cfg!(windows) {
    &["biometric", "windows hello", "face", "fingerprint", "pin"]
} else {
    &["biometric", "touch id", "fingerprint", "password"]
};
/// Days the session history (`activity`) is kept; `0` keeps it forever.
/// Recently Deleted keep time in days (B10); "0" is Off.
pub const DELETED_RETENTION: &[(&str, &str)] = &[("0", "Off"), ("7", "7 days"), ("30", "30 days"), ("90", "90 days")];
pub const DELETED_RETENTION_SETTING: &str = "library.deleted-retention-days";

pub const ACTIVITY_RETENTION: &[(&str, &str)] = &[("30", "30 days"), ("90", "90 days"), ("365", "1 year"), ("0", "Forever")];

/// Every setting, in display order within its category.
/// Setting id of the Detailed logging switch (LOG-ERRCODES).
pub const DETAILED_LOG: &str = "diagnostics.detailed-log";
/// Detailed logging turns itself off this long after it was turned on.
pub const DETAILED_LOG_MAX_SECS: u64 = 24 * 60 * 60;

/// True when Detailed logging, on since `since_unix`, has run its 24 hours at `now_unix`.
/// A start time in the future (clock moved back) also counts as expired.
pub fn detailed_log_expired(since_unix: u64, now_unix: u64) -> bool {
    now_unix < since_unix || now_unix - since_unix >= DETAILED_LOG_MAX_SECS
}

pub fn definitions() -> Vec<SettingDef> {
    use Category::*;
    let d = |id, category, label, help, kind: Kind, default, keywords| {
        let requires = match kind {
            Kind::Link(t) => Some(t),
            _ => None,
        };
        SettingDef { id, category, label, help, kind, default, keywords, requires }
    };
    vec![
        // `terminal-*` capabilities: frontends report the terminal features they implement.
        // Frontends that collapse the library panel report the `library-auto-hide` capability.
        d("tree.auto-hide", General, "Hide the library while sessions are open", "Collapses the tree while sessions are open; the toolbar button or left screen edge shows it.", Kind::Toggle, "false", &["sidebar", "navigation", "collapse", "panel"])
            .requiring("library-auto-hide"),
        d("tree.full-screen-dock", General, "Dock the library at the screen edge in full screen", "In full screen with auto-hide on, the pointer at the left edge slides the library in over your sessions.", Kind::Toggle, "true", &["sidebar", "auto-dock", "fullscreen", "edge", "panel"])
            .requiring("full-screen-dock"),
        d("tabs.auto-group", General, "Group tabs by folder", "Two or more open connections from the same folder join a tab group named and coloured after the folder.", Kind::Toggle, "true", &["tab groups", "folder", "colour", "color"])
            .requiring("tab-groups"),
        d("tabs.vertical", General, "Vertical tabs", "Show open tabs in a list down the side of the window instead of in the title bar.", Kind::Toggle, "false", &["tab list", "side", "sidebar", "tab strip"])
            .requiring("vertical-tabs"),
        d("tabs.previews", General, "Show tab previews", "Resting the pointer on a tab shows a small picture of the session. Never shown while locked.", Kind::Toggle, "true", &["hover", "thumbnail", "overview", "preview"])
            .requiring("tab-previews"),
        d("window.launch", General, "Window at launch", "How the main window opens. The size is fitted to the screen it opens on.", Kind::Choice(WINDOW_LAUNCH), "remember", &["size", "position", "maximised", "maximized", "full screen", "startup", "geometry"])
            .requiring("window-launch"),
        d("window.launch-width", General, "Launch width", "Width of the main window when Window at launch is Fixed size.", Kind::Integer { min: 640, max: 7680, unit: "px" }, "1280", &["size", "window", "startup"])
            .requiring("window-launch"),
        d("window.launch-height", General, "Launch height", "Height of the main window when Window at launch is Fixed size.", Kind::Integer { min: 400, max: 4320, unit: "px" }, "800", &["size", "window", "startup"])
            .requiring("window-launch"),
        d("window.use-current-size", General, "Use current size", "Copies the main window's size into Launch width and height.", Kind::Link("window-current-size"), "", &["size", "window", "startup"]),
        d("session.restore-on-launch", General, "Restore sessions on launch", "Reopen the tabs you had open when Gantry last quit. After a crash they always come back.", Kind::Toggle, "true", &["restore", "reopen", "tabs", "startup", "crash"]),
        d("ui.tips", General, "Panel tips", "One short rotating tip under the library and inspector.", Kind::Toggle, "true", &["hints", "help", "footer"]),
        d("tree.double-click", General, "Double-click a connection", "What double-clicking a connection in the tree does.", Kind::Choice(DOUBLE_CLICK), "connect", &["open", "tree", "mouse"]),
        d("appearance.mode", Appearance, "Appearance", "Follow the system, or always use light, dark or high contrast.", Kind::Choice(MODES), "system", &["theme", "dark mode", "light mode", "colour", "color"]),
        d("appearance.accent", Appearance, "Accent colour", "Colour of selections, primary buttons and focus rings.", Kind::Choice(ACCENTS), "electric", &["color", "tint", "highlight"]),
        d("appearance.density", Appearance, "Density", "Row height and control size in the tree, inspector and editors.", Kind::Choice(DENSITIES), "comfortable", &["compact", "spacing", "size"]),
        d("appearance.header-style", Appearance, "Header style", "Compact puts the library switcher, tabs and + in one title-bar row; Classic keeps the full toolbar.", Kind::Choice(HEADER_STYLES), "compact", &["toolbar", "title bar", "tabs", "classic"])
            .requiring("header-style"),
        d("appearance.window-follows-terminal", Appearance, "Match window colours to the terminal theme", "Sidebar, tab strip and toolbar take tones from the active tab's terminal theme.", Kind::Toggle, "false", &["color", "chrome", "sidebar", "tabs", "tint"])
            .requiring("window-tones"),
        d("appearance.zoom", Appearance, "Zoom", "Size of the whole window: text, controls and panels. Ctrl+= and Ctrl+- step it, Ctrl+0 resets.", Kind::Choice(ZOOMS), "100", &["scale", "size", "bigger", "smaller", "magnify"])
            .requiring("ui-zoom"),
        d("terminal.theme", Terminal, "Colour theme", "Colours of terminal sessions. Match app theme: Gantry Light in a light app, Gantry Dark in a dark one.", Kind::Choice(TERMINAL_THEMES), crate::termthemes::MATCH_APP, &["color", "palette", "scheme"]),
        d("terminal.osc52", Terminal, "Remote clipboard copy (OSC 52)", OSC52_HELP, Kind::Choice(OSC52), "ask", &["clipboard", "copy", "tmux", "vim", "osc"]),
        d("terminal.themes", Terminal, "Edit themes", "Bundled themes and your own: colours, preview and contrast.", Kind::Link("terminal-themes"), "", &["color", "palette", "scheme", "editor"]),
        d("terminal.font-size", Terminal, "Font size", "Text size of terminal sessions; open sessions resize at once.", Kind::Integer { min: 9, max: 24, unit: "pt" }, "13", &["text", "zoom"]),
        d("terminal.font-family", Terminal, "Font", "Typeface of terminal sessions; the bundled Nerd Font has Powerline and icon glyphs.", Kind::Choice(TERMINAL_FONTS), "bundled", &["text", "typeface", "nerd", "powerline", "glyphs"])
            .requiring("terminal-font-family"),
        d("terminal.ligatures", Terminal, "Font ligatures", "Joins character pairs such as -> and != where the font has ligatures.", Kind::Toggle, "true", &["font", "programming"])
            .requiring("terminal-ligatures"),
        d("terminal.new-tab", Terminal, "New tab opens", "What the New terminal button and Ctrl+Shift+T open.", Kind::Choice(NEW_TAB_SHELLS), "local", &["shell", "powershell", "cmd", "wsl", "profile", "default"])
            .requiring("terminal-new-tab"),
        d("terminal.cursor-style", Terminal, "Cursor", "Shape of the cursor when the program does not choose one.", Kind::Choice(CURSOR_STYLES), "block", &["caret", "beam", "shape"])
            .requiring("terminal-cursor-style"),
        d("terminal.bell", Terminal, "Bell", "What happens when a program rings the bell.", Kind::Choice(BELL), "visual", &["beep", "alert", "flash", "sound"])
            .requiring("terminal-bell"),
        d("terminal.program-notifications", Terminal, "Program notifications", "Programs may show a desktop notification (OSC 9 and 777). Text is cleaned and limited to one every 2 seconds.", Kind::Toggle, "true", &["osc", "notify", "alert", "toast"])
            .requiring("terminal-program-notifications"),
        d("terminal.scrollback", Terminal, "Scrollback", "Lines kept above the screen for scrolling and search.", Kind::Integer { min: 1000, max: crate::terminal::MAX_SCROLLBACK_LINES as i64, unit: "lines" }, "10000", &["history", "buffer", "lines"])
            .requiring("terminal-scrollback"),
        d("terminal.copy-on-select", Terminal, "Copy on select", "Selected text goes to the clipboard at once.", Kind::Toggle, "false", &["clipboard", "selection", "mouse"])
            .requiring("terminal-copy-on-select"),
        d("terminal.confirm-close", Terminal, "Confirm before closing an active session", "Asks before closing a tab or pane that is still connected or running a program.", Kind::Toggle, "true", &["quit", "close", "tab", "pane", "warn"])
            .requiring("terminal-confirm-close"),
        d("terminal.session-bar", Terminal, "Session bar", "The name, status and Reconnect line above a saved connection's session. Unpin hides it; turn it back on here.", Kind::Toggle, "true", &["title", "status", "reconnect", "pin", "header"])
            .requiring("terminal-session-bar"),
        d("defaults.ssh", ConnectionDefaults, "SSH defaults", "Settings every SSH connection inherits unless a folder or connection overrides them.", Kind::Link("defaults:ssh"), "", &["inherit", "port", "user"]),
        d("defaults.rdp", ConnectionDefaults, "RDP defaults", "Settings every RDP connection inherits unless overridden.", Kind::Link("defaults:rdp"), "", &["inherit", "remote desktop"]),
        d("defaults.vnc", ConnectionDefaults, "VNC defaults", "Settings every VNC connection inherits unless overridden.", Kind::Link("defaults:vnc"), "", &["inherit"]),
        d("defaults.web", ConnectionDefaults, "Web defaults", "Settings every web connection inherits unless overridden.", Kind::Link("defaults:web"), "", &["inherit", "browser"]),
        d("ssh.sources", Ssh, "SSH config sources", "OpenSSH config files Gantry reads hosts from and watches for changes.", Kind::Link("ssh-sources"), "", &["openssh", "config", "hosts"]),
        d("ssh.import", Ssh, "Import SSH config", "Add hosts from an OpenSSH config file once.", Kind::Link("ssh-import"), "", &["openssh", "hosts"]),
        d("credentials.manager", Credentials, "Credential Manager", "Saved passwords and SSH keys in the local vault.", Kind::Link("credential-manager"), "", &["password", "key", "vault", "keychain"]),
        d("vaultwarden.provider", Vaultwarden, "Vaultwarden account", "Server, sign-in and lock state of the Vaultwarden provider.", Kind::Link("vaultwarden"), "", &["bitwarden", "server", "password manager"]),
        d("document.auto-lock-minutes", Security, "Lock the document when idle", "Idle minutes before the open document locks (0: never on idle). Screen lock and sleep always lock it.", Kind::Integer { min: 0, max: 1440, unit: "min" }, "15", &["timeout", "inactivity", "document", "lock"]),
        d("document.close-sessions-on-lock", Security, "Close sessions on lock", "When the document locks, also disconnect its sessions. Off keeps them running behind the unlock screen.", Kind::Toggle, "false", &["lock", "disconnect", "document"]),
        d("document.remember-unlock", Security, "Remember unlock until I quit", "Skip the idle lock until Gantry quits. Screen lock and sleep still lock the document.", Kind::Toggle, "false", &["lock", "unlock", "document", "idle"]),
        d("security.auto-lock", Security, "Lock credentials when idle", "Locks the local vault and Vaultwarden after no keyboard or mouse input for this long.", Kind::Choice(AUTO_LOCK), "off", &["timeout", "inactivity", "vault", "vaultwarden"]),
        d("security.lock-on-screen-lock", Security, "Lock credentials when the screen locks", "Also on fast user switching. Open sessions keep running; reconnects need a new sign-in.", Kind::Toggle, "true", &["sleep", "screen saver", "session", "vault"]),
        d("security.confirm-vault-open", Security, VAULT_CONFIRM_LABEL, VAULT_CONFIRM_HELP, Kind::Toggle, "false", VAULT_CONFIRM_KEYWORDS)
            .requiring("vault-open-confirm"),
        // macOS only: the library key in the Secure Enclave. Windows keeps it in a DPAPI key file, with no biometric step.
        d("security.touch-id-unlock", Security, "Unlock with Touch ID", "Opens the library with Touch ID instead of a key file only your account can read (takes effect at next launch).", Kind::Toggle, "true", &["biometric", "fingerprint", "secure enclave", "personal", "library"])
            .requiring("touch-id-library-unlock"),
        d(SESSION_LOGIN_REUSE_SETTING, Security, "Ask for the login again after", "Minutes a connection reuses its last successful login without asking (0: until you lock or quit).", Kind::Integer { min: 0, max: 1440, unit: "min" }, "0", &["reconnect", "remember", "login", "password", "expiry", "session", "timeout"])
            .requiring("session-login-reuse"),
        d(SECRET_CLIPBOARD_SETTING, Security, "Clear copied passwords after", SECRET_CLIPBOARD_HELP, Kind::Choice(SECRET_CLIPBOARD_SECONDS), "60", &["clipboard", "pasteboard", "password", "generator", "copy", "seconds", "timeout"])
            .requiring("secret-clipboard-lifetime"),
        d(ALLOW_TELNET_SETTING, Security, "Allow Telnet", "Telnet is not encrypted: anyone on the network can read what you type, including passwords.", Kind::Toggle, "false", &["legacy", "telnet", "unencrypted", "cleartext", "protocol"])
            .requiring("allow-telnet"),
        // Session history (`activity`). Shown by frontends that have a history view (`activity-log`).
        d("logging.activity-enabled", Security, "Keep a history of sessions", "Records when each session started and ended, as which user, and why it ended. Never what was typed or shown.", Kind::Toggle, "true", &["activity", "history", "log", "sessions", "audit"])
            .requiring("activity-log"),
        d("logging.activity-retention-days", Security, "Keep session history for", "Session history older than this is deleted when Gantry starts.", Kind::Choice(ACTIVITY_RETENTION), "365", &["activity", "history", "log", "retention", "delete", "days"])
            .requiring("activity-log"),
        // Session logs v2 (LOG-CORE-02). Shown by frontends that use `session_log_plan` (`session-log-v2`).
        d(crate::sessionlog::FOLDER_SETTING, Security, "Session log folder", "Where session logs are saved. Empty uses the session-logs folder in the app data folder.", Kind::Text { max_len: 1024, multiline: false }, "", &["log", "session", "folder", "path", "output"])
            .requiring("session-log-v2"),
        d(crate::sessionlog::TIMESTAMPS_SETTING, Security, "Time stamp each log line", "Starts every line of a session log with the time it was printed.", Kind::Toggle, "false", &["log", "session", "time", "timestamp"])
            .requiring("session-log-v2"),
        d(crate::sessionlog::KEEP_DAYS_SETTING, Security, "Keep session logs for", "Days before a session log is deleted (0: keep forever).", Kind::Integer { min: 0, max: crate::sessionlog::MAX_KEEP_DAYS as i64, unit: "days" }, "0", &["log", "session", "retention", "delete", "days"])
            .requiring("session-log-v2"),
        d(crate::sessionlog::MAX_GB_SETTING, Security, "Limit session logs to", "Oldest session logs are deleted above this size (0: no limit).", Kind::Integer { min: 0, max: 10_000, unit: "GB" }, "0", &["log", "session", "size", "disk", "limit"])
            .requiring("session-log-v2"),
        d(crate::sessionlog::REDACT_SETTING, Security, "Hide matching text in session logs", "Regular expressions, one per line; matching text is saved as [redacted].", Kind::Text { max_len: 8192, multiline: true }, "", &["log", "session", "redact", "secret", "pattern", "regex"])
            .requiring("session-log-v2"),
        d(DELETED_RETENTION_SETTING, General, "Keep deleted items for", "Deleted folders and connections can be restored until this time has passed. Off deletes them at once.", Kind::Choice(DELETED_RETENTION), "30", &["deleted", "trash", "restore", "recycle", "retention", "days", "undo"])
            .requiring("restore-deleted"),
        d("workspaces.manager", Workspaces, "Saved workspaces", "Open, rename, duplicate or delete saved session layouts.", Kind::Link("workspace-manager"), "", &["layout", "sessions", "tabs"]),
        d("keyboard.shortcuts", Keyboard, "Keyboard shortcuts", "Change or remove the shortcut of any menu command.", Kind::Link("keyboard-shortcuts"), "", &["keys", "hotkey", "keybinding", "menu"]),
        d("security.lock-now", Security, "Lock credentials now", "Locks the local vault and Vaultwarden until they are next used.", Kind::Link("lock-credentials"), "", &["vault"]),
        // Only meaningful in a build with an update channel; the frontend reports it as `check-updates`.
        d("updates.check-at-launch", Updates, "Check for updates at launch", "Checks the signed release information when Gantry starts; nothing is downloaded.", Kind::Toggle, "false", &["version", "release", "automatic"])
            .requiring("check-updates"),
        d("updates.check-now", Updates, "Check for updates now", "Fetches and verifies the signed release information.", Kind::Link("check-updates"), "", &["version", "release"]),
        // LOG-ERRCODES: frontends that write debug lines (and turn them off after 24 h) report `detailed-log`.
        d(DETAILED_LOG, About, "Detailed logging", "Records more detail in the app log for troubleshooting. Turn off when done.", Kind::Toggle, "false", &["debug", "diagnostics", "log", "support", "troubleshoot"])
            .requiring("detailed-log"),
    ]
}

/// Definitions a frontend can show: those without a requirement, and those whose link target or
/// capability the frontend handles.
pub fn visible(handled_links: &[&str]) -> Vec<SettingDef> {
    definitions().into_iter().filter(|d| d.requires.is_none_or(|t| handled_links.contains(&t))).collect()
}

/// Categories with at least one visible setting, plus About (a frontend page).
pub fn categories(handled_links: &[&str]) -> Vec<Category> {
    let defs = visible(handled_links);
    Category::ALL.into_iter().filter(|c| *c == Category::About || defs.iter().any(|d| d.category == *c)).collect()
}

/// Visible settings whose label, help, category, options or keywords contain every word of `query`.
pub fn search(query: &str, handled_links: &[&str]) -> Vec<SettingDef> {
    let terms: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    if terms.is_empty() {
        return Vec::new();
    }
    visible(handled_links).into_iter().filter(|d| d.matches(&terms)).collect()
}

pub fn definition(id: &str) -> Option<SettingDef> {
    definitions().into_iter().find(|d| d.id == id)
}

/// Seconds a copied password may stay on the clipboard, from the stored value of
/// `SECRET_CLIPBOARD_SETTING`. `None` (settings could not be read) and anything that is not one
/// of the choices give the shortest lifetime, so a fault never leaves a password there longer.
pub fn secret_clipboard_seconds(stored: Option<&str>) -> u64 {
    stored
        .filter(|v| SECRET_CLIPBOARD_SECONDS.iter().any(|(id, _)| id == v))
        .and_then(|v| v.parse().ok())
        .unwrap_or(SECRET_CLIPBOARD_FALLBACK_SECONDS)
}

/// The user's reuse time for a remembered login, in minutes, from the stored value of
/// [`SESSION_LOGIN_REUSE_SETTING`]. Anything that is not a whole number in range reads as 0,
/// which never relaxes a managed maximum (`policy::effective_session_login_reuse_minutes`).
pub fn session_login_reuse_user_minutes(stored: &str) -> u32 {
    definition(SESSION_LOGIN_REUSE_SETTING).and_then(|d| d.validate(stored).ok()).and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// Whether credentials should lock now, for the `security.auto-lock` value and the seconds since
/// the last keyboard or mouse input.
pub fn auto_lock_due(value: &str, idle_secs: u64) -> bool {
    value.parse::<u64>().is_ok_and(|minutes| idle_secs >= minutes * 60)
}

/// [`auto_lock_due`], also due once `idle_secs` reaches the policy's `inactivity_lock_secs`
/// whatever the user chose (including "off"), so a managed limit locks the whole vault and
/// providers, not just broker leases (TM-03).
pub fn auto_lock_due_under(value: &str, idle_secs: u64, policy: &crate::policy::Policy) -> bool {
    auto_lock_due(value, idle_secs) || policy.inactivity_lock_secs.is_some_and(|max| idle_secs >= max)
}

/// Stored values by setting id. Unknown ids are kept (a newer version may have written them).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub values: BTreeMap<String, String>,
}

impl Settings {
    /// The stored value when it is still valid, else the default.
    pub fn get(&self, id: &str) -> Result<String> {
        let def = definition(id).ok_or_else(|| CoreError::NotFound(format!("setting `{id}`")))?;
        Ok(self.values.get(id).and_then(|v| checked(&def, v).ok()).unwrap_or_else(|| def.default.to_string()))
    }

    /// Recently Deleted keep time in days; 0 is Off (B10).
    pub fn deleted_retention_days(&self) -> u32 {
        self.get(DELETED_RETENTION_SETTING).ok().and_then(|v| v.parse().ok()).unwrap_or(30)
    }

    pub fn set(&mut self, id: &str, value: &str) -> Result<()> {
        let def = definition(id).ok_or_else(|| CoreError::NotFound(format!("setting `{id}`")))?;
        let value = checked(&def, value)?;
        if value == def.default {
            self.values.remove(id);
        } else {
            self.values.insert(id.to_string(), value);
        }
        Ok(())
    }

    /// True when the file has no value for `id` (it uses the default).
    pub fn is_default(&self, id: &str) -> bool {
        !self.values.contains_key(id)
    }
}

/// A value's stored form. A user theme's id and an installed font family are not in the static
/// option lists; whether they exist is the frontend's to check.
fn checked(def: &SettingDef, value: &str) -> Result<String> {
    match def.id {
        "terminal.theme" if crate::termthemes::is_theme_id(value) => Ok(value.to_string()),
        "terminal.font-family" if crate::termfonts::is_family(value) => Ok(value.to_string()),
        crate::sessionlog::REDACT_SETTING => {
            let v = def.validate(value)?;
            crate::sessionlog::compile_patterns(&v)?;
            Ok(v)
        }
        crate::sessionlog::FOLDER_SETTING => {
            let v = def.validate(value)?;
            if v.is_empty() { Ok(v) } else { crate::sessionlog::validate_log_folder(&v).map_err(|e| CoreError::Invalid(format!("{}: {e}", def.label))) }
        }
        _ => def.validate(value),
    }
}

pub struct SettingsStore {
    path: PathBuf,
}

impl SettingsStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        SettingsStore { path: path.into() }
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// The saved settings; defaults when the file is missing. An unreadable file is an error, so
    /// a damaged file is never silently replaced by defaults on the next save.
    pub fn load(&self) -> Result<Settings> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| CoreError::Invalid(format!("settings.json: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, settings: &Settings) -> Result<()> {
        let json = serde_json::to_vec_pretty(settings).map_err(|e| CoreError::Invalid(e.to_string()))?;
        write_atomic(&self.path, &json)
    }
}
