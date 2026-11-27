//! Icon identifiers shared by every frontend. The core names an icon, its full label (tooltips,
//! screen readers) and its tint token; each platform maps the id to its own licensed vector set
//! (SF Symbols on macOS, Segoe Fluent Icons on Windows), so both show the same picture language
//! without shipping artwork in the core.
use serde::Serialize;

use crate::model::Protocol;

/// Colour role of an icon; frontends resolve it through the theme tokens (`theme::tokens`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tint {
    Terminal,
    Desktop,
    Vnc,
    Web,
    Files,
    Legacy,
    Infrastructure,
    Folder,
    Neutral,
    Running,
    Stopped,
    Suspended,
}

impl Tint {
    /// Token name in `theme::tokens`, e.g. `icon.terminal`.
    pub fn token(self) -> String {
        format!("icon.{}", serde_json::to_string(&self).unwrap_or_default().trim_matches('"'))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Icon {
    /// Stable id that frontends map to a glyph (`ssh`, `folder`, `credential`, …).
    pub id: &'static str,
    /// Full name for tooltips and accessibility (`SSH Terminal`), never a lowercase wire name.
    pub label: &'static str,
    pub tint: Tint,
}

const fn icon(id: &'static str, label: &'static str, tint: Tint) -> Icon {
    Icon { id, label, tint }
}

/// Every icon id a frontend must map.
pub const ALL: &[Icon] = &[
    icon("ssh", "SSH Terminal", Tint::Terminal),
    icon("rdp", "Remote Desktop (RDP)", Tint::Desktop),
    icon("vnc", "VNC", Tint::Vnc),
    icon("web", "Web Page", Tint::Web),
    icon("sftp", "SFTP File Transfer", Tint::Files),
    icon("scp", "SCP File Transfer", Tint::Files),
    icon("ftp", "FTP File Transfer", Tint::Legacy),
    icon("ftps", "FTPS File Transfer", Tint::Files),
    icon("telnet", "Telnet", Tint::Legacy),
    icon("serial", "Serial Console", Tint::Terminal),
    icon("powershell", "PowerShell", Tint::Terminal),
    icon("local-terminal", "Local Terminal", Tint::Terminal),
    icon("services", "Services", Tint::Infrastructure),
    icon("processes", "Processes", Tint::Infrastructure),
    icon("eventlog", "Event Log", Tint::Infrastructure),
    icon("wsl", "WSL", Tint::Terminal),
    icon("esxi", "VMware ESXi Host", Tint::Infrastructure),
    icon("vcenter", "VMware vCenter", Tint::Infrastructure),
    icon("proxmox", "Proxmox VE", Tint::Infrastructure),
    icon("hyperv", "Hyper-V", Tint::Infrastructure),
    icon("docker", "Docker", Tint::Infrastructure),
    icon("kubernetes", "Kubernetes", Tint::Infrastructure),
    icon("cluster", "Cluster", Tint::Infrastructure),
    icon("datacenter", "Datacenter", Tint::Infrastructure),
    icon("storage", "Storage", Tint::Infrastructure),
    icon("network", "Network", Tint::Infrastructure),
    icon("container", "LXC Container", Tint::Infrastructure),
    icon("credential", "Credential", Tint::Neutral),
    icon("task", "Task", Tint::Neutral),
    icon("gateway", "Gateway", Tint::Neutral),
    icon("folder", "Folder", Tint::Folder),
    icon("favorite", "Favorite", Tint::Neutral),
    icon("workspace", "Workspace", Tint::Neutral),
    icon("keyboard", "Keyboard", Tint::Neutral),
    icon("settings", "Settings", Tint::Neutral),
    icon("appearance", "Appearance", Tint::Neutral),
    icon("defaults", "Connection Defaults", Tint::Neutral),
    icon("vault", "Vault", Tint::Neutral),
    icon("security", "Security", Tint::Neutral),
    icon("update", "Updates", Tint::Neutral),
    icon("about", "About", Tint::Neutral),
];

pub fn by_id(id: &str) -> Option<Icon> {
    ALL.iter().copied().find(|i| i.id == id)
}

/// Icon of a connection type.
pub fn for_protocol(p: Protocol) -> Icon {
    let id = match p {
        // A type this app does not know: a neutral glyph every app has, labelled with the one
        // fixed text (PLUG-03a), so the tooltip says why the entry cannot be opened.
        Protocol::Unsupported => return Icon { id: "network", label: crate::unknown::NEEDS_NEWER, tint: Tint::Neutral },
        Protocol::Ssh => "ssh",
        Protocol::Rdp => "rdp",
        Protocol::Vnc => "vnc",
        Protocol::Web => "web",
        Protocol::Sftp => "sftp",
        Protocol::Scp => "scp",
        Protocol::Ftp => "ftp",
        Protocol::Ftps => "ftps",
        Protocol::Telnet => "telnet",
        Protocol::Serial => "serial",
        Protocol::Local => "local-terminal",
        Protocol::Services => "services",
        Protocol::Processes => "processes",
        Protocol::EventLog => "eventlog",
    };
    by_id(id).expect("every protocol has an icon")
}
