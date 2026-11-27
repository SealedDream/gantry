//! Bridge for the read-only system views (`bastion_core::sysview`): Services, Processes and Event
//! Log connections. One `SystemView` holds one SSH session (dialled like a terminal: policy,
//! broker, strict host keys, audit), detects the OS once, and answers listings and the log tail on
//! the caller's thread (call it off the main thread). Nothing here changes the remote host.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bastion_core::audit::{Category, Outcome};
use bastion_core::ssh::SshSession;
use bastion_core::model::Protocol;
use bastion_core::sysview::{self, EventFilter, Os, Request, View};

use crate::terminal::{SessionManager, RUNTIME};
use crate::{parse_id, FfiError, FfiResult, Library, SshLogin};

#[derive(uniffi::Record, Clone)]
pub struct SysServiceView {
    pub name: String,
    pub description: String,
    pub state: String,
    pub sub: String,
    pub start_type: String,
}

#[derive(uniffi::Record, Clone)]
pub struct SysProcessView {
    pub pid: u32,
    pub user: String,
    pub cpu_percent: Option<f64>,
    pub cpu_seconds: Option<f64>,
    pub mem_bytes: u64,
    pub name: String,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct SysEventView {
    pub cursor: String,
    pub time: String,
    pub level: String,
    pub source: String,
    pub message: String,
}

/// Linux: `unit`, `priority` (0–7). Windows: `log` (System, Application, Security, Setup), `level` (1–5).
#[derive(uniffi::Record, Clone, Default, PartialEq)]
pub struct SysEventFilter {
    pub unit: Option<String>,
    pub priority: Option<u8>,
    pub log: Option<String>,
    pub level: Option<u8>,
}

#[derive(uniffi::Record)]
pub struct SysViewLimits {
    /// Events a viewer keeps before dropping the oldest.
    pub max_events_kept: u32,
    pub max_rows: u32,
}

#[uniffi::export]
pub fn sys_view_limits() -> SysViewLimits {
    SysViewLimits { max_events_kept: sysview::MAX_EVENTS_KEPT as u32, max_rows: sysview::MAX_ROWS as u32 }
}

impl SysEventFilter {
    fn core(&self) -> EventFilter {
        let blank = |s: &Option<String>| s.as_ref().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        EventFilter { unit: blank(&self.unit), priority: self.priority, log: blank(&self.log), level: self.level }
    }
}

#[derive(Default)]
struct Fallbacks {
    plain_services: bool,
    busybox_ps: bool,
}

#[derive(uniffi::Object)]
pub struct SystemView {
    session: SshSession,
    os: Os,
    view: View,
    fallbacks: Mutex<Fallbacks>,
    /// The filter of the running tail and the cursor of the last event it returned.
    tail: Mutex<(EventFilter, Option<String>)>,
}

struct Output {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn failed(message: String) -> FfiError {
    FfiError::failed(message)
}

fn run(session: &SshSession, os: Os, request: &Request) -> FfiResult<Output> {
    let command = sysview::command(os, request)?;
    let out = RUNTIME.block_on(session.exec(&command))?;
    Ok(Output { ok: out.exit_status == Some(0), stdout: String::from_utf8_lossy(&out.stdout).into_owned(), stderr: String::from_utf8_lossy(&out.stderr).into_owned() })
}

fn checked(out: Output) -> FfiResult<String> {
    if out.ok { Ok(out.stdout) } else { Err(failed(sysview::error_message(&out.stderr))) }
}

fn detect(session: &SshSession) -> FfiResult<Os> {
    let linux = run(session, Os::Linux, &Request::ProbeLinux)?;
    if let Some(os) = sysview::detect(linux.ok.then_some(linux.stdout.as_str()), None) {
        return Ok(os);
    }
    let windows = run(session, Os::Windows, &Request::ProbeWindows)?;
    sysview::detect(None, windows.ok.then_some(windows.stdout.as_str()))
        .ok_or_else(|| failed(format!("the host is neither Linux nor Windows with PowerShell (uname: {})", linux.stdout.trim())))
}

/// The view to open: the connection's own for a system-view connection, else the asked one of an SSH connection.
fn resolve_view(protocol: Protocol, asked: Option<&str>) -> Option<sysview::View> {
    if let Some(own) = sysview::view_for(protocol) {
        return Some(own);
    }
    let asked = match asked? {
        "services" => Protocol::Services,
        "processes" => Protocol::Processes,
        "eventlog" => Protocol::EventLog,
        _ => return None,
    };
    matches!(protocol, Protocol::Ssh | Protocol::Rdp).then(|| sysview::view_for(asked)).flatten()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[uniffi::export]
impl SystemView {
    /// Sign in to a Services, Processes or Event Log connection and detect its OS. Errors as for an
    /// SSH connect (`HostKeyUnknown { fingerprint }`: retry with `trust_fingerprint`). Audited as
    /// `sysview.open` with the view and OS.
    #[uniffi::constructor]
    pub fn open(manager: Arc<SessionManager>, library: Arc<Library>, connection_id: String, username: String, login: SshLogin, trust_fingerprint: Option<String>) -> FfiResult<Arc<Self>> {
        Self::open_view(manager, library, connection_id, None, username, login, trust_fingerprint)
    }

    /// `open` for a view of an SSH connection (owner 2026-11-07: Services, Processes and Event Log
    /// are children of a connection). `view` is `services`, `processes` or `eventlog`; `None`
    /// takes it from the connection's own protocol, as `open` does.
    #[uniffi::constructor]
    pub fn open_view(manager: Arc<SessionManager>, library: Arc<Library>, connection_id: String, view: Option<String>, username: String, login: SshLogin, trust_fingerprint: Option<String>) -> FfiResult<Arc<Self>> {
        let conn = library.resolve(parse_id(&connection_id)?)?;
        let managed = conn.protocol != Protocol::Rdp || sysview::ssh_management(&conn).is_some();
        let view = resolve_view(conn.protocol, view.as_deref()).filter(|_| managed).ok_or_else(|| failed(format!("{} has no Services, Processes or Event Log view", conn.name)))?;
        let session = match sysview::ssh_management(&conn) {
            // An RDP connection's tools read over SSH to the same host (owner point 11).
            Some((ssh, user)) => manager.dial_ssh_to(&library, ssh, user.unwrap_or(username), login, trust_fingerprint)?,
            None => manager.dial_ssh(&library, &connection_id, username, login, trust_fingerprint, Default::default(), Default::default())?,
        };
        let os = detect(&session);
        let view_name = serde_json::to_value(view).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        let mut details = BTreeMap::from([("view".to_string(), view_name)]);
        match &os {
            Ok(os) => details.insert("os".into(), format!("{os:?}").to_lowercase()),
            Err(e) => details.insert("error".into(), e.to_string()),
        };
        manager.record_audit(Category::Connection, "sysview.open", Some(&conn.name), if os.is_ok() { Outcome::Success } else { Outcome::Failure }, details);
        Ok(Arc::new(SystemView { session, os: os?, view, fallbacks: Mutex::default(), tail: Mutex::new((EventFilter::default(), None)) }))
    }

    /// `linux` or `windows`.
    pub fn os(&self) -> String {
        format!("{:?}", self.os).to_lowercase()
    }

    /// `services`, `processes` or `events`.
    pub fn view(&self) -> String {
        serde_json::to_value(self.view).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
    }

    /// Every service (systemd units of type service, or Windows services), at most `max_rows`.
    pub fn services(&self) -> FfiResult<Vec<SysServiceView>> {
        let mut plain = lock(&self.fallbacks).plain_services;
        let mut out = run(&self.session, self.os, &Request::Services { plain })?;
        if !out.ok && !plain && self.os == Os::Linux && sysview::wants_plain_services(&out.stderr) {
            plain = true;
            lock(&self.fallbacks).plain_services = true;
            out = run(&self.session, self.os, &Request::Services { plain })?;
        }
        let rows = sysview::parse_services(self.os, plain, &checked(out)?)?;
        Ok(rows.into_iter().map(|r| SysServiceView { name: r.name, description: r.description, state: r.state, sub: r.sub, start_type: r.start_type }).collect())
    }

    /// Every process, busiest first on Linux with procps.
    pub fn processes(&self) -> FfiResult<Vec<SysProcessView>> {
        let mut busybox = lock(&self.fallbacks).busybox_ps;
        let mut out = run(&self.session, self.os, &Request::Processes { busybox })?;
        if !out.ok && !busybox && self.os == Os::Linux && sysview::wants_busybox_ps(&out.stderr) {
            busybox = true;
            lock(&self.fallbacks).busybox_ps = true;
            out = run(&self.session, self.os, &Request::Processes { busybox })?;
        }
        let rows = sysview::parse_processes(self.os, busybox, &checked(out)?)?;
        Ok(rows.into_iter().map(|r| SysProcessView { pid: r.pid, user: r.user, cpu_percent: r.cpu_percent, cpu_seconds: r.cpu_seconds, mem_bytes: r.mem_bytes, name: r.name }).collect())
    }

    /// Events new since the previous call with the same filter, oldest first. The first call (or
    /// the first after the filter changed) returns the newest events, at most 500.
    pub fn tail(&self, filter: SysEventFilter) -> FfiResult<Vec<SysEventView>> {
        let filter = filter.core();
        let after = {
            let mut t = lock(&self.tail);
            if t.0 != filter {
                *t = (filter.clone(), None);
            }
            t.1.clone()
        };
        let out = run(&self.session, self.os, &Request::Events { filter: filter.clone(), after, max: sysview::MAX_EVENTS_PER_FETCH })?;
        let rows = sysview::parse_events(self.os, &checked(out)?)?;
        if let Some(last) = rows.last() {
            let mut t = lock(&self.tail);
            if t.0 == filter {
                t.1 = Some(last.cursor.clone());
            }
        }
        Ok(rows.into_iter().map(|r| SysEventView { cursor: r.cursor, time: r.time, level: r.level, source: r.source, message: r.message }).collect())
    }

    pub fn close(&self) {
        RUNTIME.block_on(self.session.disconnect()).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bastion_core::model::{Connection, Node};
    use uuid::Uuid;

    #[test]
    fn ssh_connections_open_any_view_others_only_their_own() {
        assert_eq!(resolve_view(Protocol::Ssh, Some("eventlog")), Some(View::Events));
        assert_eq!(resolve_view(Protocol::Ssh, Some("services")), Some(View::Services));
        assert_eq!(resolve_view(Protocol::Ssh, None), None);
        assert_eq!(resolve_view(Protocol::Rdp, Some("processes")), Some(View::Processes), "RDP with management via SSH");
        assert_eq!(resolve_view(Protocol::Vnc, Some("processes")), None);
        assert_eq!(resolve_view(Protocol::Ssh, Some("bogus")), None);
        assert_eq!(resolve_view(Protocol::Processes, Some("services")), Some(View::Processes));
    }

    fn setup(protocol: Protocol, port: u16) -> (std::path::PathBuf, Arc<Library>, Arc<SessionManager>, String) {
        let dir = std::env::temp_dir().join(format!("bastion-sysview-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let lib = Arc::new(Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap());
        let mut c = Connection::new("sshd", protocol, "127.0.0.1");
        c.settings.port = Some(port);
        let id = c.id.to_string();
        lib.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();
        let mgr = SessionManager::new(dir.to_string_lossy().into_owned()).unwrap();
        let keys = std::process::Command::new("ssh-keyscan").args(["-p", &port.to_string(), "127.0.0.1"]).stderr(std::process::Stdio::null()).output().unwrap().stdout;
        std::fs::write(dir.join("known_hosts"), keys).unwrap();
        (dir, lib, mgr, id)
    }

    #[test]
    fn refuses_connections_that_are_not_system_views() {
        let (dir, lib, mgr, id) = setup(Protocol::Ssh, 1);
        let e = SystemView::open(mgr, lib, id, "tester".into(), SshLogin::Agent, None).err().unwrap();
        assert!(e.to_string().contains("has no Services"), "{e}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn rdp_without_ssh_management_has_no_views() {
        let (dir, lib, mgr, id) = setup(Protocol::Rdp, 1);
        let e = SystemView::open_view(mgr, lib, id, Some("services".into()), "tester".into(), SshLogin::Agent, None).err().unwrap();
        assert!(e.to_string().contains("has no Services"), "{e}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn filters_ignore_blank_fields() {
        let f = SysEventFilter { unit: Some("  ".into()), priority: Some(3), log: Some("".into()), level: None }.core();
        assert_eq!(f, EventFilter { unit: None, priority: Some(3), log: None, level: None });
    }

    /// Live (owner point 11): an RDP connection with management via SSH reads Services,
    /// Processes and the System event log of a Windows host over OpenSSH + PowerShell.
    /// `BASTION_WIN_SSH=host,user,keyfile` (e.g. the Win11 test VM).
    #[test]
    fn rdp_connection_reads_windows_views_over_ssh_management() {
        let Ok(spec) = std::env::var("BASTION_WIN_SSH") else {
            return eprintln!("SKIPPED rdp_connection_reads_windows_views_over_ssh_management: set BASTION_WIN_SSH");
        };
        let [host, user, key]: [&str; 3] = spec.split(',').collect::<Vec<_>>().try_into().expect("host,user,keyfile");
        let dir = std::env::temp_dir().join(format!("bastion-sysview-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let lib = Arc::new(Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap());
        let mut c = Connection::new("win", Protocol::Rdp, host);
        c.settings.port = Some(3389);
        c.metadata.insert("rdp.ssh_management".into(), "on".into());
        c.metadata.insert("rdp.ssh_user".into(), user.into());
        let id = c.id.to_string();
        lib.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();
        let keys = std::process::Command::new("sh").arg("-c").arg(format!("ssh-keyscan -p 22 {host} 2>/dev/null")).output().unwrap().stdout;
        std::fs::write(dir.join("known_hosts"), keys).unwrap();
        let login = || SshLogin::KeyFile { path: key.into(), passphrase: None };
        let mgr = SessionManager::new(dir.to_string_lossy().into_owned()).unwrap();
        // The RDP login's username is replaced by the management username.
        let v = SystemView::open_view(mgr.clone(), lib.clone(), id.clone(), Some("services".into()), "rdp-login".into(), login(), None).unwrap();
        assert_eq!(v.os(), "windows");
        assert!(v.services().unwrap().iter().any(|s| s.name.eq_ignore_ascii_case("sshd")));
        v.close();
        let p = SystemView::open_view(mgr.clone(), lib.clone(), id.clone(), Some("processes".into()), "rdp-login".into(), login(), None).unwrap();
        assert!(p.processes().unwrap().len() > 10);
        p.close();
        let e = SystemView::open_view(mgr, lib, id, Some("eventlog".into()), "rdp-login".into(), login(), None).unwrap();
        assert!(!e.tail(SysEventFilter { unit: None, priority: None, log: Some("System".into()), level: None }).unwrap().is_empty());
        e.close();
        std::fs::remove_dir_all(dir).ok();
    }

    /// Live: bastion-sshd (Alpine, BusyBox `ps`, no systemd) on 2222, tester's password in
    /// `BASTION_SSH_PASSWORD`.
    #[test]
    fn reads_processes_on_the_test_server() {
        let Ok(password) = std::env::var("BASTION_SSH_PASSWORD") else {
            return eprintln!("SKIPPED reads_processes_on_the_test_server: set BASTION_SSH_PASSWORD");
        };
        let (dir, lib, mgr, id) = setup(Protocol::Processes, 2222);
        let v = SystemView::open(mgr, lib, id, "tester".into(), SshLogin::Password { password }, None).unwrap();
        assert_eq!((v.os().as_str(), v.view().as_str()), ("linux", "processes"));
        let p = v.processes().unwrap();
        assert!(p.iter().any(|p| p.name.contains("sshd")), "{:?}", p.iter().map(|p| &p.name).collect::<Vec<_>>());
        assert!(v.services().is_err(), "no systemd on the test server");
        v.close();
        let audit = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(audit.contains("\"sysview.open\"") && audit.contains("\"os\":\"linux\""));
        std::fs::remove_dir_all(dir).ok();
    }

    /// Live: a throwaway systemd container with sshd (TESTING.md), port in `BASTION_SYSTEMD_PORT`,
    /// root's password in `BASTION_SYSTEMD_PASSWORD`.
    #[test]
    fn reads_services_and_tails_the_journal_on_systemd() {
        let (Ok(port), Ok(password)) = (std::env::var("BASTION_SYSTEMD_PORT"), std::env::var("BASTION_SYSTEMD_PASSWORD")) else {
            return eprintln!("SKIPPED reads_services_and_tails_the_journal_on_systemd: set BASTION_SYSTEMD_PORT/PASSWORD");
        };
        let login = SshLogin::Password { password };
        let (dir, lib, mgr, id) = setup(Protocol::Services, port.parse().unwrap());
        let v = SystemView::open(mgr.clone(), lib.clone(), id.clone(), "root".into(), login.clone(), None).unwrap();
        let s = v.services().unwrap();
        assert!(s.iter().any(|s| s.name == "ssh.service" && s.state == "active"), "{} services", s.len());
        let first = v.tail(SysEventFilter::default()).unwrap();
        assert!(!first.is_empty());
        // Nothing new yet, then one line written with logger shows up on the next call.
        let quiet = v.tail(SysEventFilter::default()).unwrap();
        let marker = format!("bastion-tail-{}", Uuid::new_v4());
        RUNTIME.block_on(v.session.exec(&format!("logger -t bastiontest {marker}"))).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let next = v.tail(SysEventFilter::default()).unwrap();
        assert!(quiet.len() <= 2 && next.iter().any(|e| e.message == marker), "{quiet:?} {:?}", next.iter().map(|e| &e.message).collect::<Vec<_>>());
        let errs = v.tail(SysEventFilter { priority: Some(3), ..Default::default() }).unwrap();
        assert!(errs.iter().all(|e| ["emerg", "alert", "crit", "err"].contains(&e.level.as_str())));
        let unit = v.tail(SysEventFilter { unit: Some("ssh.service".into()), ..Default::default() }).unwrap();
        // `-u` also lists systemd's own lines about the unit (source init.scope).
        assert!(unit.iter().any(|e| e.source == "ssh.service") && unit.iter().all(|e| e.source == "ssh.service" || e.source == "init.scope"), "{:?}", unit.iter().map(|e| &e.source).collect::<Vec<_>>());
        v.close();
        std::fs::remove_dir_all(dir).ok();
    }
}
