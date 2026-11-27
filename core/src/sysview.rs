//! Read-only system views over SSH (Royal TS "Windows Services / Processes / Events" and their
//! Linux equivalents): services, processes and a live log tail. Nothing here starts, stops or
//! kills anything.
//!
//! Every request is a fixed command. Linux: an argument vector of `systemctl`, `ps` or
//! `journalctl` with each argument POSIX-quoted. Windows (OpenSSH): a fixed PowerShell script sent
//! as `-EncodedCommand` (UTF-16LE base64), so no value is parsed as code by cmd.exe or PowerShell.
//! The only inputs (unit, priority, event log, level, cursor) are validated before use.
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{CoreError, Result};
use crate::model::Protocol;
use crate::scp::shell_quote;

/// Rows kept from one services or processes listing.
pub const MAX_ROWS: usize = 20_000;
/// Events returned by one fetch, at most (the first fetch shows the newest this many).
pub const MAX_EVENTS_PER_FETCH: u32 = 500;
/// Events a viewer keeps; older ones are dropped as new ones arrive.
pub const MAX_EVENTS_KEPT: usize = 5_000;
/// Longest event message kept, in characters.
pub const MAX_MESSAGE: usize = 8_192;
/// Event logs that can be read on Windows; others are refused rather than passed through.
pub const WINDOWS_LOGS: &[&str] = &["System", "Application", "Security", "Setup"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Linux,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum View {
    Services,
    Processes,
    Events,
}

/// The view a connection type opens, if it is one of the system views.
pub fn view_for(p: Protocol) -> Option<View> {
    match p {
        Protocol::Services => Some(View::Services),
        Protocol::Processes => Some(View::Processes),
        Protocol::EventLog => Some(View::Events),
        _ => None,
    }
}

/// The SSH connection that reads an RDP connection's Services, Processes and Event Log, when it
/// opts in (`rdp.ssh_management` on): same host, `rdp.ssh_port` or 22, and `rdp.ssh_user` as the
/// username when set (else the caller's RDP login). The id is the RDP connection's.
pub fn ssh_management(c: &crate::model::Connection) -> Option<(crate::model::Connection, Option<String>)> {
    use crate::properties::{meta_value, RDP_SSH_MANAGEMENT, RDP_SSH_PORT, RDP_SSH_USER};
    if c.protocol != Protocol::Rdp || meta_value(c, RDP_SSH_MANAGEMENT).as_deref() != Some("on") {
        return None;
    }
    let mut ssh = c.clone();
    ssh.protocol = Protocol::Ssh;
    ssh.settings.port = Some(c.metadata.get(RDP_SSH_PORT).and_then(|p| p.trim().parse().ok()).unwrap_or(22));
    let user = c.metadata.get(RDP_SSH_USER).map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
    if let Some(u) = &user {
        ssh.settings.username = Some(u.clone());
        ssh.settings.credential_id = None;
        ssh.settings.credential_name = None;
    }
    Some((ssh, user))
}

/// Filters for the log tail. Linux uses `unit` and `priority` (0 emerg … 7 debug: that level and
/// more severe); Windows uses `log` (default System) and `level` (1 critical … 5 verbose: that
/// level and more severe).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFilter {
    pub unit: Option<String>,
    pub priority: Option<u8>,
    pub log: Option<String>,
    pub level: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Which OS answers: Linux runs `uname -s`; Windows answers the PowerShell probe.
    ProbeLinux,
    ProbeWindows,
    /// `plain` = the fallback for systemd without `--output=json` (before v246).
    Services { plain: bool },
    /// `busybox` = the fallback for a `ps` without `-e`/`--sort` (Alpine, BusyBox).
    Processes { busybox: bool },
    /// Newest `max` events, or only those after `after` (a journal cursor or Windows RecordId).
    Events { filter: EventFilter, after: Option<String>, max: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRow {
    pub name: String,
    pub description: String,
    /// Linux `active` (active, inactive, failed…); Windows `Status` (Running, Stopped…).
    pub state: String,
    /// Linux `sub` (running, exited, dead…); Windows empty.
    pub sub: String,
    /// Windows `StartType` (Automatic, Manual, Disabled); Linux empty.
    pub start_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessRow {
    pub pid: u32,
    pub user: String,
    /// Linux `ps` %CPU (lifetime average); not on Windows or BusyBox.
    pub cpu_percent: Option<f64>,
    /// Windows processor seconds used so far.
    pub cpu_seconds: Option<f64>,
    pub mem_bytes: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRow {
    /// Journal `__CURSOR` or Windows `RecordId`: pass the last one as `after`.
    pub cursor: String,
    /// ISO 8601, UTC.
    pub time: String,
    /// Linux priority name (err, warning, info…); Windows `LevelDisplayName`.
    pub level: String,
    /// Linux unit or syslog identifier; Windows provider.
    pub source: String,
    pub message: String,
}

fn invalid(msg: String) -> CoreError {
    CoreError::Invalid(msg)
}

/// systemd unit names: letters, digits and `@ . _ : - \`, as systemd allows.
fn check_unit(u: &str) -> Result<()> {
    let ok = !u.is_empty() && u.len() <= 256 && !u.starts_with('-') && u.chars().all(|c| c.is_ascii_alphanumeric() || "@._:-\\".contains(c));
    if ok { Ok(()) } else { Err(invalid(format!("`{u}` is not a valid unit name"))) }
}

/// Journal cursors (`s=…;i=…;b=…`) and Windows record ids: nothing that could be an option or code.
fn check_cursor(os: Os, c: &str) -> Result<()> {
    let ok = match os {
        Os::Linux => !c.is_empty() && c.len() <= 512 && !c.starts_with('-') && c.chars().all(|ch| ch.is_ascii_alphanumeric() || "=;_-".contains(ch)),
        Os::Windows => c.parse::<u64>().is_ok(),
    };
    if ok { Ok(()) } else { Err(invalid("the log position is not valid".into())) }
}

fn argv(args: &[&str]) -> String {
    args.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ")
}

const PS_PREAMBLE: &str = "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';";

fn powershell(body: &str) -> String {
    let utf16: Vec<u8> = format!("{PS_PREAMBLE}{body}").encode_utf16().flat_map(u16::to_le_bytes).collect();
    format!("powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {}", base64::engine::general_purpose::STANDARD.encode(utf16))
}

/// The SSH exec command line for `request` on `os`, after validating its inputs.
pub fn command(os: Os, request: &Request) -> Result<String> {
    match (os, request) {
        (_, Request::ProbeLinux) => Ok(argv(&["uname", "-s"])),
        (_, Request::ProbeWindows) => Ok(powershell("[string][Environment]::OSVersion.Platform")),
        (Os::Linux, Request::Services { plain: false }) => Ok(argv(&["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--output=json"])),
        (Os::Linux, Request::Services { plain: true }) => Ok(argv(&["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain"])),
        (Os::Linux, Request::Processes { busybox: false }) => Ok(argv(&["ps", "-eo", "pid=,user=,pcpu=,rss=,comm=", "--sort=-pcpu"])),
        (Os::Linux, Request::Processes { busybox: true }) => Ok(argv(&["ps", "-o", "pid,user,rss,comm"])),
        (Os::Linux, Request::Events { filter, after, max }) => {
            let n = (*max).clamp(1, MAX_EVENTS_PER_FETCH).to_string();
            let mut a: Vec<String> = ["journalctl", "-o", "json", "--no-pager", "-n", &n].iter().map(|s| s.to_string()).collect();
            if let Some(u) = &filter.unit {
                check_unit(u)?;
                a.push(format!("--unit={u}"));
            }
            if let Some(p) = filter.priority {
                if p > 7 {
                    return Err(invalid("priority must be 0 (emerg) to 7 (debug)".into()));
                }
                a.push(format!("--priority={p}"));
            }
            if let Some(c) = after {
                check_cursor(os, c)?;
                a.push(format!("--after-cursor={c}"));
            }
            Ok(argv(&a.iter().map(String::as_str).collect::<Vec<_>>()))
        }
        (Os::Windows, Request::Services { .. }) => Ok(powershell(
            "ConvertTo-Json -Compress -InputObject @(Get-Service | Select-Object Name,DisplayName,@{n='Status';e={[string]$_.Status}},@{n='StartType';e={[string]$_.StartType}})",
        )),
        (Os::Windows, Request::Processes { .. }) => Ok(powershell(
            "ConvertTo-Json -Compress -InputObject @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,UserName,@{n='Cpu';e={[double]$_.CPU}},@{n='WorkingSet';e={[int64]$_.WorkingSet64}})",
        )),
        (Os::Windows, Request::Events { filter, after, max }) => {
            let log = filter.log.as_deref().unwrap_or("System");
            if !WINDOWS_LOGS.contains(&log) {
                return Err(invalid(format!("event log `{log}` is not one of {}", WINDOWS_LOGS.join(", "))));
            }
            let mut conds = vec![];
            if let Some(l) = filter.level {
                if !(1..=5).contains(&l) {
                    return Err(invalid("level must be 1 (critical) to 5 (verbose)".into()));
                }
                conds.push(format!("Level<={l} and Level>0"));
            }
            if let Some(c) = after {
                check_cursor(os, c)?;
                conds.push(format!("EventRecordID>{c}"));
            }
            let xpath = if conds.is_empty() { "*".to_string() } else { format!("*[System[{}]]", conds.join(" and ")) };
            let max = (*max).clamp(1, MAX_EVENTS_PER_FETCH);
            // No events matching is an error from Get-WinEvent: answer an empty list instead.
            Ok(powershell(&format!(
                "$e=@(Get-WinEvent -LogName '{log}' -FilterXPath '{xpath}' -MaxEvents {max} -ErrorAction SilentlyContinue | Sort-Object RecordId | Select-Object @{{n='Cursor';e={{[string]$_.RecordId}}}},@{{n='Time';e={{$_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')}}}},@{{n='Level';e={{[string]$_.LevelDisplayName}}}},@{{n='Source';e={{[string]$_.ProviderName}}}},@{{n='Message';e={{[string]$_.Message}}}});ConvertTo-Json -Compress -InputObject $e"
            )))
        }
    }
}

/// The OS from the two probes' standard output (`uname -s` first).
pub fn detect(uname: Option<&str>, windows_probe: Option<&str>) -> Option<Os> {
    if uname.is_some_and(|s| s.trim() == "Linux") {
        return Some(Os::Linux);
    }
    windows_probe.filter(|s| s.trim().trim_start_matches('\u{feff}').starts_with("Win")).map(|_| Os::Windows)
}

fn clip(s: &str) -> String {
    if s.chars().count() <= MAX_MESSAGE { s.to_string() } else { s.chars().take(MAX_MESSAGE).collect::<String>() + "…" }
}

fn ps_json(stdout: &str) -> Result<Vec<Value>> {
    let text = stdout.trim().trim_start_matches('\u{feff}');
    if text.is_empty() {
        return Ok(vec![]);
    }
    match serde_json::from_str(text).map_err(|e| invalid(format!("unexpected PowerShell output: {e}")))? {
        Value::Array(v) => Ok(v),
        v @ Value::Object(_) => Ok(vec![v]),
        _ => Ok(vec![]),
    }
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

pub fn parse_services(os: Os, plain: bool, stdout: &str) -> Result<Vec<ServiceRow>> {
    let rows: Vec<ServiceRow> = match (os, plain) {
        (Os::Windows, _) => ps_json(stdout)?
            .iter()
            .map(|v| ServiceRow { name: s(v, "Name"), description: s(v, "DisplayName"), state: s(v, "Status"), sub: String::new(), start_type: s(v, "StartType") })
            .collect(),
        (Os::Linux, false) => {
            let v: Vec<Value> = serde_json::from_str(stdout.trim()).map_err(|e| invalid(format!("unexpected systemctl output: {e}")))?;
            v.iter().map(|u| ServiceRow { name: s(u, "unit"), description: s(u, "description"), state: s(u, "active"), sub: s(u, "sub"), start_type: String::new() }).collect()
        }
        (Os::Linux, true) => stdout
            .lines()
            .filter_map(|l| {
                // UNIT LOAD ACTIVE SUB DESCRIPTION… (a leading ● marks failed units on some versions)
                let mut it = l.trim_start_matches(['●', '*', ' ']).split_whitespace();
                let (name, _load, state, sub) = (it.next()?, it.next()?, it.next()?, it.next()?);
                Some(ServiceRow { name: name.into(), description: it.collect::<Vec<_>>().join(" "), state: state.into(), sub: sub.into(), start_type: String::new() })
            })
            .collect(),
    };
    Ok(rows.into_iter().take(MAX_ROWS).collect())
}

/// Whether `systemctl`'s failure means it has no `--output=json` (so try the plain listing).
pub fn wants_plain_services(stderr: &str) -> bool {
    let e = stderr.to_ascii_lowercase();
    e.contains("--output") || e.contains("unrecognized option") || e.contains("unknown option") || e.contains("invalid argument")
}

/// Whether `ps` refused the procps options (so try the BusyBox form).
pub fn wants_busybox_ps(stderr: &str) -> bool {
    let e = stderr.to_ascii_lowercase();
    e.contains("unrecognized option") || e.contains("invalid option") || e.contains("unknown option") || e.contains("usage")
}

pub fn parse_processes(os: Os, busybox: bool, stdout: &str) -> Result<Vec<ProcessRow>> {
    let rows: Vec<ProcessRow> = match os {
        Os::Windows => ps_json(stdout)?
            .iter()
            .map(|v| ProcessRow {
                pid: v.get("Id").and_then(Value::as_u64).unwrap_or(0) as u32,
                user: s(v, "UserName"),
                cpu_percent: None,
                cpu_seconds: v.get("Cpu").and_then(Value::as_f64),
                mem_bytes: v.get("WorkingSet").and_then(Value::as_u64).unwrap_or(0),
                name: s(v, "ProcessName"),
            })
            .collect(),
        Os::Linux => stdout
            .lines()
            .skip(usize::from(busybox)) // BusyBox prints a header line
            .filter_map(|l| {
                let mut it = l.split_whitespace();
                let pid = it.next()?.parse().ok()?;
                let user = it.next()?.to_string();
                let cpu_percent = if busybox { None } else { it.next()?.parse().ok() };
                let rss = it.next()?;
                // BusyBox shows large RSS as `12m` / `1.2g`.
                let kib = rss.parse::<f64>().ok().or_else(|| {
                    let (n, unit) = rss.split_at(rss.len().checked_sub(1)?);
                    let mult = match unit {
                        "k" => 1.0,
                        "m" => 1024.0,
                        "g" => 1024.0 * 1024.0,
                        _ => return None,
                    };
                    n.parse::<f64>().ok().map(|n| n * mult)
                })?;
                Some(ProcessRow { pid, user, cpu_percent, cpu_seconds: None, mem_bytes: (kib * 1024.0) as u64, name: it.collect::<Vec<_>>().join(" ") })
            })
            .collect(),
    };
    Ok(rows.into_iter().take(MAX_ROWS).collect())
}

const PRIORITIES: [&str; 8] = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];

/// A journal field that may be a string or, for non-UTF-8 data, an array of bytes.
fn journal_text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(bytes)) => String::from_utf8_lossy(&bytes.iter().filter_map(|b| b.as_u64().map(|b| b as u8)).collect::<Vec<_>>()).into_owned(),
        _ => String::new(),
    }
}

/// `yyyy-mm-ddThh:mm:ss.mmmZ` from microseconds since the Unix epoch.
pub fn iso_utc(micros: i64) -> String {
    let secs = micros.div_euclid(1_000_000);
    let ms = micros.rem_euclid(1_000_000) / 1000;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Days to civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

pub fn parse_events(os: Os, stdout: &str) -> Result<Vec<EventRow>> {
    let rows: Vec<EventRow> = match os {
        Os::Windows => ps_json(stdout)?
            .iter()
            .map(|v| EventRow { cursor: s(v, "Cursor"), time: s(v, "Time"), level: s(v, "Level"), source: s(v, "Source"), message: clip(s(v, "Message").trim()) })
            .collect(),
        // One JSON object per line; a line that is not one (a journalctl warning) is skipped.
        Os::Linux => stdout
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .map(|v| {
                let micros = s(&v, "__REALTIME_TIMESTAMP").parse::<i64>().unwrap_or(0);
                let level = s(&v, "PRIORITY").parse::<usize>().ok().and_then(|p| PRIORITIES.get(p)).map(|p| p.to_string()).unwrap_or_default();
                let unit = s(&v, "_SYSTEMD_UNIT");
                let source = if unit.is_empty() { s(&v, "SYSLOG_IDENTIFIER") } else { unit };
                EventRow { cursor: s(&v, "__CURSOR"), time: iso_utc(micros), level, source, message: clip(&journal_text(v.get("MESSAGE"))) }
            })
            .collect(),
    };
    Ok(rows.into_iter().take(MAX_EVENTS_PER_FETCH as usize).collect())
}

/// A readable error from the remote side's stderr (PowerShell CLIXML or plain text).
pub fn error_message(stderr: &str) -> String {
    let plain: String = if stderr.contains("#< CLIXML") {
        stderr.split("<S S=\"Error\">").skip(1).filter_map(|s| s.split("</S>").next()).collect::<Vec<_>>().join("").replace("_x000D__x000A_", "\n")
    } else {
        stderr.to_string()
    };
    plain.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("the remote command reported an error").to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn rdp_management_uses_same_host_port_22_and_optional_user() {
        use crate::model::Connection;
        let mut c = Connection::new("win", Protocol::Rdp, "192.168.1.20");
        assert!(super::ssh_management(&c).is_none(), "off by default");
        c.metadata.insert("rdp.ssh_management".into(), "on".into());
        let (ssh, user) = super::ssh_management(&c).unwrap();
        assert_eq!((ssh.protocol, ssh.host.as_str(), ssh.settings.port, user), (Protocol::Ssh, "192.168.1.20", Some(22), None));
        c.metadata.insert("rdp.ssh_port".into(), "2222".into());
        c.metadata.insert("rdp.ssh_user".into(), "admin".into());
        let (ssh, user) = super::ssh_management(&c).unwrap();
        assert_eq!((ssh.settings.port, user.as_deref(), ssh.settings.username.as_deref()), (Some(2222), Some("admin"), Some("admin")));
        assert!(super::ssh_management(&Connection::new("s", Protocol::Ssh, "h")).is_none());
    }

    use super::*;

    fn decode(cmd: &str) -> String {
        let b64 = cmd.rsplit(' ').next().unwrap();
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        String::from_utf16(&bytes.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>()).unwrap()
    }

    fn events(f: EventFilter, after: Option<&str>) -> Request {
        Request::Events { filter: f, after: after.map(str::to_string), max: 9999 }
    }

    #[test]
    fn linux_commands_are_quoted_argument_vectors() {
        assert_eq!(command(Os::Linux, &Request::Services { plain: false }).unwrap(), "'systemctl' 'list-units' '--type=service' '--all' '--no-pager' '--output=json'");
        assert_eq!(command(Os::Linux, &Request::Processes { busybox: false }).unwrap(), "'ps' '-eo' 'pid=,user=,pcpu=,rss=,comm=' '--sort=-pcpu'");
        let f = EventFilter { unit: Some("ssh@1.service".into()), priority: Some(3), ..Default::default() };
        assert_eq!(
            command(Os::Linux, &events(f, Some("s=ab12;i=3f;b=9;m=1;t=2;x=3"))).unwrap(),
            "'journalctl' '-o' 'json' '--no-pager' '-n' '500' '--unit=ssh@1.service' '--priority=3' '--after-cursor=s=ab12;i=3f;b=9;m=1;t=2;x=3'"
        );
    }

    #[test]
    fn hostile_inputs_are_refused() {
        for u in ["x'; rm -rf / #", "a b", "-fx", "$(id)", "", "a\nb", "a;b"] {
            assert!(command(Os::Linux, &events(EventFilter { unit: Some(u.into()), ..Default::default() }, None)).is_err(), "{u:?}");
        }
        assert!(command(Os::Linux, &events(EventFilter { priority: Some(8), ..Default::default() }, None)).is_err());
        assert!(command(Os::Linux, &events(EventFilter::default(), Some("--output=x"))).is_err());
        assert!(command(Os::Linux, &events(EventFilter::default(), Some("s=1 x"))).is_err());
        assert!(command(Os::Windows, &events(EventFilter { log: Some("System'; Remove-Item C:\\".into()), ..Default::default() }, None)).is_err());
        assert!(command(Os::Windows, &events(EventFilter { level: Some(0), ..Default::default() }, None)).is_err());
        assert!(command(Os::Windows, &events(EventFilter::default(), Some("12 or 1=1"))).is_err());
    }

    #[test]
    fn windows_commands_are_encoded_fixed_read_only_scripts() {
        let c = command(Os::Windows, &Request::Services { plain: false }).unwrap();
        assert!(c.starts_with("powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand "));
        assert!(decode(&c).contains("Get-Service"));
        let e = decode(&command(Os::Windows, &events(EventFilter { log: Some("Application".into()), level: Some(3), ..Default::default() }, Some("4711"))).unwrap());
        assert!(e.contains("-LogName 'Application' -FilterXPath '*[System[Level<=3 and Level>0 and EventRecordID>4711]]' -MaxEvents 500"), "{e}");
        for r in [Request::Services { plain: false }, Request::Processes { busybox: false }, events(EventFilter::default(), None)] {
            let script = decode(&command(Os::Windows, &r).unwrap());
            for verb in ["Start-", "Stop-", "Restart-", "Set-", "Remove-", "Invoke-", "Clear-"] {
                assert!(!script.contains(verb), "{verb} in {script}");
            }
        }
    }

    #[test]
    fn detects_the_os_from_the_probes() {
        assert_eq!(detect(Some("Linux\n"), None), Some(Os::Linux));
        assert_eq!(detect(Some("Darwin\n"), Some("")), None);
        assert_eq!(detect(None, Some("\u{feff}Win32NT\r\n")), Some(Os::Windows));
        assert_eq!(detect(Some("'uname' is not recognized"), Some("Win32NT")), Some(Os::Windows));
    }

    #[test]
    fn parses_systemctl_json_and_plain() {
        let j = r#"[{"unit":"ssh.service","load":"loaded","active":"active","sub":"running","description":"OpenBSD Secure Shell server"}]"#;
        let r = parse_services(Os::Linux, false, j).unwrap();
        assert_eq!((r[0].name.as_str(), r[0].state.as_str(), r[0].sub.as_str()), ("ssh.service", "active", "running"));
        let p = "ssh.service loaded active running OpenBSD Secure Shell server\n● x.service loaded failed failed X\n";
        let r = parse_services(Os::Linux, true, p).unwrap();
        assert_eq!((r[0].description.as_str(), r[1].name.as_str(), r[1].state.as_str()), ("OpenBSD Secure Shell server", "x.service", "failed"));
        assert!(wants_plain_services("systemctl: unrecognized option '--output=json'"));
        assert!(parse_services(Os::Linux, false, "not json").is_err());
    }

    #[test]
    fn parses_ps_procps_busybox_and_windows() {
        let r = parse_processes(Os::Linux, false, "    1 root      0.0  1234 systemd\n  420 tester   12.5 20480 my prog\n").unwrap();
        assert_eq!((r[1].pid, r[1].cpu_percent, r[1].mem_bytes, r[1].name.as_str()), (420, Some(12.5), 20480 * 1024, "my prog"));
        let b = parse_processes(Os::Linux, true, "PID   USER     RSS  COMMAND\n    1 root      12m s6-svscan\n   77 abc     900 sshd\n").unwrap();
        assert_eq!((b[0].mem_bytes, b[1].cpu_percent, b[1].name.as_str()), (12 * 1024 * 1024, None, "sshd"));
        let w = parse_processes(Os::Windows, false, r#"{"Id":4,"ProcessName":"System","UserName":null,"Cpu":12.5,"WorkingSet":155648}"#).unwrap();
        assert_eq!((w[0].pid, w[0].cpu_seconds, w[0].user.as_str()), (4, Some(12.5), ""));
    }

    #[test]
    fn parses_journal_lines_and_windows_events() {
        let l = concat!(
            r#"{"__CURSOR":"s=1;i=2","__REALTIME_TIMESTAMP":"1762186571123456","PRIORITY":"3","_SYSTEMD_UNIT":"ssh.service","MESSAGE":"boom"}"#,
            "\n-- No entries --\n",
            r#"{"__CURSOR":"s=1;i=3","__REALTIME_TIMESTAMP":"0","PRIORITY":"6","SYSLOG_IDENTIFIER":"kernel","MESSAGE":[104,105,255]}"#
        );
        let e = parse_events(Os::Linux, l).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].level.as_str(), e[0].source.as_str(), e[0].time.as_str()), ("err", "ssh.service", "2025-11-03T16:16:11.123Z"));
        assert_eq!((e[1].source.as_str(), e[1].message.as_str(), e[1].time.as_str()), ("kernel", "hi\u{fffd}", "1970-01-01T00:00:00.000Z"));
        let w = parse_events(Os::Windows, r#"[{"Cursor":"10","Time":"2026-11-03T16:16:11.000Z","Level":"Error","Source":"Disk","Message":"x"}]"#).unwrap();
        assert_eq!((w[0].cursor.as_str(), w[0].level.as_str()), ("10", "Error"));
        assert!(parse_events(Os::Windows, "").unwrap().is_empty());
        let long = format!(r#"{{"__CURSOR":"c","MESSAGE":"{}"}}"#, "a".repeat(MAX_MESSAGE + 10));
        assert_eq!(parse_events(Os::Linux, &long).unwrap()[0].message.chars().count(), MAX_MESSAGE + 1);
    }

    #[test]
    fn iso_dates_match_known_values() {
        assert_eq!(iso_utc(951_782_400_000_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(iso_utc(4_102_444_799_999_000), "2099-12-31T23:59:59.999Z");
    }

    #[test]
    fn clixml_errors_are_readable() {
        let e = "#< CLIXML\r\n<Objs><S S=\"Error\">Access is denied_x000D__x000A_</S></Objs>";
        assert_eq!(error_message(e), "Access is denied");
        assert_eq!(error_message("\n  journalctl: command not found\n"), "journalctl: command not found");
    }
}
