//! Connection-type descriptors shared by every frontend's Add menu and editors, so the
//! platforms agree on what each type is called, where it is grouped and how far it works.
use serde::Serialize;

/// How far a type works today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Support {
    /// Can be created, edited and opened.
    Connects,
    /// Can be created and edited; opening a session is not implemented yet.
    StoreOnly,
    /// Not implemented; shown as a labelled future item and cannot be created.
    Planned,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TypeDescriptor {
    /// Protocol wire name for connection types (`ssh`), or a stable id for other items.
    pub id: &'static str,
    pub label: &'static str,
    pub group: &'static str,
    pub summary: &'static str,
    pub support: Support,
}

const fn t(id: &'static str, label: &'static str, group: &'static str, summary: &'static str, support: Support) -> TypeDescriptor {
    TypeDescriptor { id, label, group, summary, support }
}

/// Add-menu catalogue in display order. Groups: Organization, Remote Connections,
/// File Transfer, Management, Gateways, Tasks.
pub fn catalog() -> Vec<TypeDescriptor> {
    use Support::*;
    vec![
        t("folder", "Folder", "Organization", "Groups connections and carries default settings.", Connects),
        t("credential", "Credential", "Organization", "Reusable login stored in a vault.", Planned),
        t("ssh", "SSH Terminal", "Remote Connections", "Interactive shell with strict host keys and jump hosts.", Connects),
        t("rdp", "Remote Desktop", "Remote Connections", "Saved and editable; RDP sessions are not implemented yet.", StoreOnly),
        t("vnc", "VNC", "Remote Connections", "Saved and editable; VNC sessions are not implemented yet.", StoreOnly),
        t("web", "Web Page", "Remote Connections", "Saved and editable; the embedded browser is not implemented yet.", StoreOnly),
        t("local", "Local Terminal", "Remote Connections", "A shell on this computer: zsh, bash, fish or a program of your choice (Windows: PowerShell, cmd, WSL).", Connects),
        t("services", "Services", "Management", "Read-only list of a Linux (systemd) or Windows host's services over SSH; nothing is started or stopped.", Connects),
        t("processes", "Processes", "Management", "Read-only, auto-refreshing process list of a Linux or Windows host over SSH; nothing is ended.", Connects),
        t("eventlog", "Event Log", "Management", "Live, read-only tail of the systemd journal (Linux) or an event log (Windows) over SSH, with filters.", Connects),
        t("telnet", "Telnet", "Remote Connections", "Not implemented.", Planned),
        t("serial", "Serial Port", "Remote Connections", "Not implemented.", Planned),
        t("sftp", "SFTP Browser", "File Transfer", "Opened from an SSH connection with Browse Files.", Planned),
        t("ftp", "FTP / FTPS", "File Transfer", "Not implemented.", Planned),
        t("hyperv", "Hyper-V", "Management", "Not implemented.", Planned),
        t("powershell", "PowerShell", "Management", "Not implemented.", Planned),
        t("gateway", "SSH Gateway", "Gateways", "Any SSH connection can be the gateway of a connection or folder (core gateway); no separate type is needed.", Planned),
        t("command-task", "Command Task", "Tasks", "Not implemented.", Planned),
    ]
}

/// What a type does once a host app actually ships its handler (H15). The shared catalogue
/// cannot know which app it runs in, so each app passes the type ids it can open.
fn connecting_summary(id: &str) -> Option<&'static str> {
    Some(match id {
        "rdp" => "Remote Desktop session with NLA, clipboard and display scaling.",
        "vnc" => "VNC session to a desktop or virtual machine console.",
        "web" => "Web page opened in the app's own browser view.",
        "telnet" => "Telnet terminal session (unencrypted; for legacy devices).",
        "serial" => "Terminal on a local serial port.",
        "sftp" => "File browser over SSH (SFTP).",
        "ftp" => "File browser over FTP or FTPS.",
        _ => return None,
    })
}

/// The catalogue as one host app sees it: types in `handled` (by id) connect, with a summary
/// describing the working session; every other type keeps the shared, conservative status.
/// Unknown ids in `handled` are ignored, so a host cannot invent catalogue rows.
pub fn catalog_for(handled: &[&str]) -> Vec<TypeDescriptor> {
    catalog()
        .into_iter()
        .map(|mut t| {
            if t.support != Support::Connects && handled.contains(&t.id) {
                if let Some(summary) = connecting_summary(t.id) {
                    t.support = Support::Connects;
                    t.summary = summary;
                }
            }
            t
        })
        .collect()
}
