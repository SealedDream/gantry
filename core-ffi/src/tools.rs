//! Bridge for terminal tools: OSC 52 clipboard requests, opt-in session logs, snippets
//! (`bastion_core::snippets`) and broadcast input to several terminals.
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bastion_core::snippets::SnippetStore;
use bastion_core::terminal::ClipboardPolicy;

/// See `TerminalSession::foreground_process`.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct ForegroundProcessView {
    pub pid: u32,
    pub name: Option<String>,
    pub busy: bool,
}

use crate::{parse_id, FfiError, FfiResult, Library, SessionManager, Terminal};

#[derive(uniffi::Record)]
pub struct ClipboardRequestView {
    pub text: String,
    /// The policy is "ask": show the request and copy only on Allow.
    pub ask: bool,
}

/// What happened in a terminal since the last poll (see `bastion_core::terminal::TerminalEvents`).
#[derive(uniffi::Record)]
pub struct TerminalEventsView {
    /// New output arrived (unread dot on a background tab).
    pub activity: bool,
    /// A command of 10 s or more finished (OSC 133 marks): exit code, if reported.
    pub finished: bool,
    pub finished_exit_code: Option<i32>,
    pub finished_duration_ms: u64,
    /// A program's OSC 9 / 777 notification, sanitized and rate-limited.
    pub notification_title: Option<String>,
    pub notification_body: Option<String>,
    /// `ssh [user@]host[:port]` typed in the local shell; no password.
    pub typed_ssh_host: Option<String>,
    pub typed_ssh_user: Option<String>,
    pub typed_ssh_port: Option<u16>,
}

/// Whether tags mark a connection as production (`production` or `prod`, any case): red tab accent.
#[uniffi::export]
pub fn tags_is_production(tags: Vec<String>) -> bool {
    bastion_core::shellmarks::is_production(&tags)
}

#[uniffi::export]
impl Terminal {
    /// Unread output, long-command finish, program notification and typed ssh, each taken once.
    pub fn take_events(&self) -> TerminalEventsView {
        let e = self.session().take_events();
        TerminalEventsView {
            activity: e.activity,
            finished: e.finished.is_some(),
            finished_exit_code: e.finished.as_ref().and_then(|f| f.exit_code),
            finished_duration_ms: e.finished.as_ref().map_or(0, |f| f.duration_ms),
            notification_title: e.notification.as_ref().map(|n| n.title.clone()),
            notification_body: e.notification.map(|n| n.body),
            typed_ssh_host: e.typed_ssh.as_ref().map(|s| s.host.clone()),
            typed_ssh_user: e.typed_ssh.as_ref().and_then(|s| s.user.clone()),
            typed_ssh_port: e.typed_ssh.and_then(|s| s.port),
        }
    }

    /// Scroll to the previous or next shell prompt (OSC 133); false when there is none.
    pub fn jump_prompt(&self, forward: bool) -> bool {
        self.session().jump_prompt(forward)
    }

    /// `off`, `ask` or `allow` (the `terminal.osc52` setting).
    pub fn set_clipboard_policy(&self, policy: String) {
        self.session().set_clipboard_policy(match policy.as_str() {
            "allow" => ClipboardPolicy::Allow,
            "off" => ClipboardPolicy::Off,
            _ => ClipboardPolicy::Ask,
        });
    }

    /// The program's latest OSC 52 copy, taken once.
    pub fn take_clipboard_request(&self) -> Option<ClipboardRequestView> {
        self.session().take_clipboard_request().map(|r| ClipboardRequestView { text: r.text, ask: r.ask })
    }

    /// The shell's working directory from its latest OSC 7 (file panel "follow folder").
    pub fn cwd(&self) -> Option<String> {
        self.session().cwd()
    }

    /// Whether the program rang the bell since the last call.
    pub fn take_bell(&self) -> bool {
        self.session().take_bell()
    }

    /// Drop the scrollback; the visible screen stays.
    pub fn clear_scrollback(&self) {
        self.session().clear_scrollback();
    }

    /// Reconnect: keep `old`'s text above this terminal's new prompt.
    pub fn carry_over(&self, old: Arc<Terminal>) {
        self.session().carry_over(old.session());
    }

    /// The foreground process of a local terminal's pty (per-pane close check); `None` when it
    /// cannot be told (remote terminals, Windows, exited).
    pub fn foreground_process(&self) -> Option<ForegroundProcessView> {
        self.session().foreground_process().map(|f| ForegroundProcessView { pid: f.pid, name: f.name, busy: f.busy })
    }

    /// Start an opt-in session log in `dir` (created owner-only) for `label`; returns the file.
    /// Rotates at 10 MB keeping 5, redacts answers echoed after secret prompts.
    pub fn start_log(&self, dir: String, label: String) -> FfiResult<String> {
        let d = bastion_core::sessionlog::LogOptions::default();
        self.start_log_with(dir, label, d.max_bytes, d.keep as u32, d.strip_ansi)
    }

    /// [`Self::start_log`] with rotation size, rotated files kept and ANSI stripping.
    pub fn start_log_with(&self, dir: String, label: String, max_bytes: u64, keep: u32, strip_ansi: bool) -> FfiResult<String> {
        let opts = bastion_core::sessionlog::LogOptions { max_bytes, keep: keep as usize, strip_ansi, redact_prompts: true, ..Default::default() };
        let dir = PathBuf::from(dir);
        bastion_core::store::create_private_dir(&dir)?;
        let safe: String = label.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' }).take(60).collect();
        let stamp = chrono_like_stamp();
        let path = dir.join(format!("{safe}-{stamp}.log"));
        self.session().start_log_with(&path, &format!("# Gantry session log: {label}, started {stamp}. Output only; keystrokes are not recorded."), opts)?;
        Ok(path.display().to_string())
    }

    pub fn stop_log(&self) {
        self.session().stop_log()
    }

    pub fn is_logging(&self) -> bool {
        self.session().is_logging()
    }
}

/// `YYYYMMDD-HHMMSS` in UTC, plus milliseconds so two logs in one second do not collide.
fn chrono_like_stamp() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}{m:02}{d:02}-{:02}{:02}{:02}-{:03}", rem / 3600, rem / 60 % 60, rem % 60, now.subsec_millis())
}

#[derive(uniffi::Record)]
pub struct SnippetView {
    pub id: String,
    pub name: String,
    pub text: String,
    pub multiline: bool,
}

#[derive(uniffi::Object)]
pub struct SnippetLibrary {
    store: Mutex<SnippetStore>,
}

#[uniffi::export]
impl SnippetLibrary {
    #[uniffi::constructor]
    pub fn open(data_dir: String) -> FfiResult<Arc<Self>> {
        Ok(Arc::new(SnippetLibrary { store: Mutex::new(SnippetStore::open(SnippetStore::file(std::path::Path::new(&data_dir)))?) }))
    }

    pub fn search(&self, query: String) -> Vec<SnippetView> {
        self.store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .search(&query)
            .into_iter()
            .map(|s| SnippetView { multiline: s.is_multiline(), id: s.id, name: s.name, text: s.text })
            .collect()
    }

    /// Add (no `id`) or replace; returns the id.
    pub fn put(&self, name: String, text: String, id: Option<String>) -> FfiResult<String> {
        Ok(self.store.lock().unwrap_or_else(|e| e.into_inner()).put(&name, &text, id.as_deref())?)
    }

    pub fn remove(&self, id: String) -> FfiResult<()> {
        Ok(self.store.lock().unwrap_or_else(|e| e.into_inner()).remove(&id)?)
    }

    /// Type snippet `id` into each terminal like a paste (bracketed when the program asked for
    /// it). A multi-line snippet, or one going to more than one tab, needs `confirmed` (ask the
    /// user first); without it nothing is sent and `NeedsConfirm` comes back. Each send is written
    /// to `audit`'s log with the snippet name and tab count only, never the text.
    pub fn send(&self, id: String, terminals: Vec<Arc<Terminal>>, confirmed: bool, audit: Option<Arc<SessionManager>>) -> FfiResult<SnippetSend> {
        if terminals.is_empty() || terminals.len() > SNIPPET_MAX_TARGETS {
            return Err(FfiError::failed(format!("Send to 1 to {SNIPPET_MAX_TARGETS} tabs.")));
        }
        let snippet = self.store.lock().unwrap_or_else(|e| e.into_inner()).list().into_iter().find(|s| s.id == id).ok_or_else(|| FfiError::failed("unknown snippet".into()))?;
        if (snippet.is_multiline() || terminals.len() > 1) && !confirmed {
            return Ok(SnippetSend::NeedsConfirm);
        }
        let tabs = terminals.iter().filter(|t| t.paste(snippet.text.clone()).is_ok()).count() as u32;
        if let Some(m) = audit {
            let details = std::collections::BTreeMap::from([("tabs".to_string(), tabs.to_string()), ("lines".to_string(), snippet.text.lines().count().to_string())]);
            m.record_audit(bastion_core::audit::Category::BulkOperation, "snippet.send", Some(&snippet.name), bastion_core::audit::Outcome::Success, details);
        }
        Ok(SnippetSend::Sent { tabs })
    }
}

/// Tabs one snippet send may reach (same limit as the C ABI and the Tauri app).
pub const SNIPPET_MAX_TARGETS: usize = 64;

/// What `SnippetLibrary::send` did.
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum SnippetSend {
    /// Multi-line or several tabs: ask the user, then send again with `confirmed`. Nothing was sent.
    NeedsConfirm,
    /// How many tabs received it (ended terminals are skipped).
    Sent { tabs: u32 },
}

/// Broadcast input: what is typed in one terminal also goes to the others. The frontend asks for
/// confirmation before starting and shows the group in every member.
#[derive(uniffi::Object, Default)]
pub struct BroadcastGroup {
    members: Mutex<Vec<Arc<Terminal>>>,
}

#[uniffi::export]
impl BroadcastGroup {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(BroadcastGroup::default())
    }

    pub fn set_members(&self, terminals: Vec<Arc<Terminal>>) {
        *self.members.lock().unwrap_or_else(|e| e.into_inner()) = terminals;
    }

    pub fn count(&self) -> u32 {
        self.members.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|t| t.is_alive()).count() as u32
    }

    /// Write `bytes` to every live member except `source` (which got them already); returns how
    /// many received them. Ended terminals are skipped, never an error.
    pub fn send(&self, bytes: Vec<u8>, source: Option<Arc<Terminal>>) -> FfiResult<u32> {
        let members = self.members.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut sent = 0;
        for t in members.iter().filter(|t| t.is_alive()) {
            if source.as_ref().is_some_and(|s| Arc::ptr_eq(s, t)) {
                continue;
            }
            t.write(bytes.clone()).map_err(|e| FfiError::failed(format!("broadcast: {e}")))?;
            sent += 1;
        }
        Ok(sent)
    }
}

/// What an RDP connect asks the adapter for (see the Redirection properties).
#[derive(uniffi::Record, Debug, PartialEq)]
pub struct RdpOptionsView {
    pub nla_only: bool,
    pub clipboard: bool,
    pub audio: bool,
    /// Absolute path of a folder on this Mac to share; nil shares nothing.
    pub shared_folder: Option<String>,
}

#[uniffi::export]
impl Library {
    /// RDP: whether only Network Level Authentication is acceptable (own or inherited).
    pub fn rdp_nla_only(&self, connection_id: String) -> FfiResult<bool> {
        Ok(self.resolve(parse_id(&connection_id)?)?.settings.rdp_nla_only == Some(true))
    }

    /// RDP session options that apply to the connection (own, inherited or built-in).
    pub fn rdp_options(&self, connection_id: String) -> FfiResult<RdpOptionsView> {
        let s = self.resolve(parse_id(&connection_id)?)?.settings;
        Ok(RdpOptionsView {
            nla_only: s.rdp_nla_only == Some(true),
            clipboard: s.rdp_clipboard != Some(false),
            audio: s.rdp_audio != Some(false),
            shared_folder: s.rdp_shared_folder,
        })
    }

    /// Whether the connection opts in to session logging (own or inherited).
    pub fn session_log(&self, connection_id: String) -> FfiResult<bool> {
        Ok(self.resolve(parse_id(&connection_id)?)?.settings.session_log == Some(true))
    }

    /// Whether the connection hides its tab preview and Overview tile image (own or inherited, B11).
    pub fn no_preview(&self, connection_id: String) -> FfiResult<bool> {
        Ok(self.resolve(parse_id(&connection_id)?)?.settings.no_preview == Some(true))
    }
}

/// Write selected log lines to a new owner-only `<name>.log` in `dir` (never overwrites; escape
/// sequences removed when `strip_ansi`). Returns the path written.
#[uniffi::export]
pub fn export_log_snippet(dir: String, name: String, header: String, text: String, strip_ansi: bool) -> FfiResult<String> {
    let path = bastion_core::logexport::export_snippet(std::path::Path::new(&dir), &name, &header, &text, strip_ansi)?;
    Ok(path.to_string_lossy().into_owned())
}

/// Selected log lines as plain text for the clipboard (same cleaning as the exported file).
#[uniffi::export]
pub fn clean_log_snippet(text: String, strip_ansi: bool) -> String {
    bastion_core::logexport::clean_snippet(&text, strip_ansi)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_send_checks_targets_and_ids_before_typing() {
        let d = tempfile::tempdir().unwrap();
        let lib = SnippetLibrary::open(d.path().to_string_lossy().into_owned()).unwrap();
        let id = lib.put("uptime".into(), "uptime".into(), None).unwrap();
        assert!(lib.send(id.clone(), Vec::new(), true, None).is_err(), "no tabs");
        assert!(lib.send("nope".into(), Vec::new(), true, None).is_err());
        let multi = lib.put("two".into(), "echo a\necho b".into(), None).unwrap();
        let (t1, t2) = (shell(), shell());
        assert_eq!(lib.send(multi, vec![t1.clone()], false, None).unwrap(), SnippetSend::NeedsConfirm, "multi-line asks first");
        assert_eq!(lib.send(id.clone(), vec![t1.clone(), t2.clone()], false, None).unwrap(), SnippetSend::NeedsConfirm, "several tabs ask first");
        let mgr = SessionManager::new(d.path().to_string_lossy().into_owned()).unwrap();
        assert_eq!(lib.send(id, vec![t1.clone()], false, Some(mgr)).unwrap(), SnippetSend::Sent { tabs: 1 });
        let audit = std::fs::read_to_string(d.path().join("audit.jsonl")).unwrap();
        assert!(audit.contains("snippet.send") && audit.contains("uptime"));
        t1.close();
        t2.close();
    }

    #[test]
    fn log_snippet_export_is_owner_only_and_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("bastion-ffi-snippet-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.to_string_lossy().to_string();
        let a = export_log_snippet(d.clone(), "web 1".into(), "# host".into(), "\x1b[31mok\x1b[0m\r\n".into(), true).unwrap();
        let b = export_log_snippet(d.clone(), "web 1".into(), String::new(), "two".into(), true).unwrap();
        assert!(a.ends_with("web-1.log") && b.ends_with("web-1-2.log"));
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "# host\nok\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&a).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // Windows: a protected DACL (nothing inherited from the folder) with one allow entry,
        // for the current user only. No SYSTEM, Administrators or Users entry.
        #[cfg(windows)]
        {
            let me = bastion_core::winacl::current_user_sid().unwrap();
            let r = bastion_core::winacl::dacl_report(std::path::Path::new(&a)).unwrap();
            assert!(r.protected, "the DACL inherits from the folder: {r:?}");
            assert_eq!(r.aces.len(), 1, "{r:?}");
            assert_eq!((r.aces[0].sid.as_str(), r.aces[0].ace_type), (me.as_str(), 0), "{r:?}");
        }
        assert!(export_log_snippet(d, "x".into(), String::new(), "  \n".into(), true).is_err());
        assert_eq!(clean_log_snippet("a  \r\nb\n\n".into(), true), "a\nb");
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn shell() -> Arc<Terminal> {
        let program = if cfg!(windows) { "cmd.exe" } else { "/bin/sh" };
        Terminal::local_program(program.into(), vec![], 80, 24).unwrap()
    }

    /// A command whose output (bc-25) differs from its echoed input, so `wait` sees the output.
    const BC_COMMAND: &[u8] =
        if cfg!(windows) { b"echo bc-%COMSPEC:~0,0%25\r" } else { b"echo bc-$((5*5))\r" };

    fn wait(t: &Terminal, text: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !t.screen().cells.iter().map(|c| c.text.as_str()).collect::<String>().contains(text) {
            assert!(std::time::Instant::now() < deadline, "timed out waiting for {text}");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn broadcast_reaches_every_live_member_but_the_source() {
        let (a, b, c) = (shell(), shell(), shell());
        let group = BroadcastGroup::new();
        group.set_members(vec![a.clone(), b.clone(), c.clone()]);
        c.close();
        assert_eq!(group.count(), 2);
        a.write(BC_COMMAND.to_vec()).unwrap();
        assert_eq!(group.send(BC_COMMAND.to_vec(), Some(a.clone())).unwrap(), 1, "only b; c has ended");
        wait(&a, "bc-25");
        wait(&b, "bc-25");
    }

    #[test]
    fn log_file_names_are_safe() {
        let dir = std::env::temp_dir().join(format!("bastion-log-{}", uuid::Uuid::new_v4()));
        let t = shell();
        let path = t.start_log(dir.to_string_lossy().into_owned(), "../../etc/web 01".into()).unwrap();
        assert!(PathBuf::from(&path).starts_with(&dir), "{path}");
        assert!(path.contains(".._.._etc_web_01-"), "{path}");
        assert!(t.is_logging());
        t.stop_log();
        std::fs::remove_dir_all(dir).ok();
    }
}

#[cfg(test)]
mod rdp_option_tests {
    use bastion_core::model::{Connection, Node, Protocol};
    use uuid::Uuid;

    use super::RdpOptionsView;
    use crate::Library;

    #[test]
    fn rdp_options_follow_the_properties_and_survive_a_reopen() {
        let dir = std::env::temp_dir().join(format!("bastion-ffi-rdpopt-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lib.json").to_string_lossy().into_owned();
        let lib = Library::open(path.clone()).unwrap();
        let c = Connection::new("win", Protocol::Rdp, "win.lan");
        let id = c.id.to_string();
        lib.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();
        let defaults = RdpOptionsView { nla_only: false, clipboard: true, audio: true, shared_folder: None };
        assert_eq!(lib.rdp_options(id.clone()).unwrap(), defaults);
        lib.set_property(id.clone(), "rdp_clipboard".into(), Some("false".into())).unwrap();
        lib.set_property(id.clone(), "rdp_shared_folder".into(), Some("/Users/me/Transfer".into())).unwrap();
        assert!(lib.set_property(id.clone(), "rdp_shared_folder".into(), Some("/".into())).is_err());
        lib.save().unwrap();
        let reopened = Library::open(path).unwrap();
        let o = reopened.rdp_options(id).unwrap();
        assert_eq!((o.clipboard, o.audio, o.shared_folder.as_deref()), (false, true, Some("/Users/me/Transfer")));
        std::fs::remove_dir_all(dir).ok();
    }
}

// ---------------------------------------------------------------------------------------------
// Session log v2 (LOG-CORE-02): core decides path, options and header; the app passes its data
// folder (settings and the default `session-logs` root), name, version and UTC offset.

/// What `session_log_plan` decided for a connection.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct SessionLogPlanView {
    /// The log root (retention runs on it).
    pub root: String,
    /// The planned file; the started file may carry `-2` … when the name was taken.
    pub path: String,
    /// The header lines written first.
    pub header: String,
    pub timestamps: bool,
}

/// A terminal's session log: `off`, `active` (with `path`) or `stopped` (with `reason`).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct LogStateView {
    pub state: String,
    pub path: Option<String>,
    pub reason: Option<String>,
}

impl From<bastion_core::sessionlog::LogState> for LogStateView {
    fn from(s: bastion_core::sessionlog::LogState) -> Self {
        use bastion_core::sessionlog::LogState;
        match s {
            LogState::Off => LogStateView { state: "off".into(), path: None, reason: None },
            LogState::Active { path } => LogStateView { state: "active".into(), path: Some(path), reason: None },
            LogState::Stopped { reason } => LogStateView { state: "stopped".into(), path: None, reason: Some(reason) },
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PurgeReportView {
    pub deleted_files: u32,
    pub freed_bytes: u64,
    pub removed_folders: u32,
}

fn load_settings(data_dir: &str) -> FfiResult<bastion_core::settings::Settings> {
    Ok(bastion_core::settings::SettingsStore::new(std::path::Path::new(data_dir).join("settings.json")).load()?)
}

/// The default session log root in an app data folder.
pub(crate) fn default_log_root(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir).join("session-logs")
}

impl Library {
    pub(crate) fn log_plan(&self, connection_id: &str, data_dir: &str, app: String, version: String, utc_offset_minutes: i32) -> FfiResult<bastion_core::sessionlog::LogPlan> {
        let settings = load_settings(data_dir)?;
        let ctx = bastion_core::sessionlog::PlanContext { default_root: default_log_root(data_dir), app, version, now_ms: bastion_core::sessionlog::now_ms(), utc_offset_minutes };
        Ok(bastion_core::sessionlog::session_log_plan(&self.lock(), &settings, parse_id(connection_id)?, &ctx)?)
    }
}

#[uniffi::export]
impl Library {
    /// Where and how a session of `connection_id` would be logged (LOG-CORE-02).
    pub fn session_log_plan(&self, connection_id: String, data_dir: String, app: String, version: String, utc_offset_minutes: i32) -> FfiResult<SessionLogPlanView> {
        let p = self.log_plan(&connection_id, &data_dir, app, version, utc_offset_minutes)?;
        Ok(SessionLogPlanView { root: p.root.display().to_string(), path: p.path.display().to_string(), header: p.header.render(), timestamps: p.options.timestamps })
    }
}

#[uniffi::export]
impl Terminal {
    /// Start the session log core plans for a saved connection; returns the file used.
    pub fn start_planned_log(&self, library: Arc<Library>, connection_id: String, data_dir: String, app: String, version: String, utc_offset_minutes: i32) -> FfiResult<String> {
        let plan = library.log_plan(&connection_id, &data_dir, app, version, utc_offset_minutes)?;
        Ok(self.session().start_log_plan(&plan)?.display().to_string())
    }

    /// Whether the session log runs, stopped by itself (with why), or is off.
    pub fn log_state(&self) -> LogStateView {
        self.session().log_state().into()
    }

    /// Stop logging with an end reason for the footer (empty: `unknown`); returns the file's
    /// SHA-256 for the session record, `None` when no log was running.
    pub fn finish_log(&self, reason: String) -> FfiResult<Option<String>> {
        Ok(self.session().finish_log(&reason)?)
    }
}

/// Apply the retention settings (`logging.session-log-keep-days`, `logging.session-log-max-gb`)
/// to the session logs under `root` (empty: the default root in `data_dir`). Without a library
/// the folders' `session_log_keep_days` are not known; use `Library.purge_session_logs`.
#[uniffi::export]
pub fn purge_session_logs(root: String, data_dir: String) -> FfiResult<PurgeReportView> {
    let rules = bastion_core::sessionlog::PurgeRules::from_settings(&load_settings(&data_dir)?);
    purge_with(&root, &data_dir, &rules)
}

fn purge_root(root: &str, data_dir: &str) -> PathBuf {
    if root.trim().is_empty() { default_log_root(data_dir) } else { PathBuf::from(root) }
}

fn purge_with(root: &str, data_dir: &str, rules: &bastion_core::sessionlog::PurgeRules) -> FfiResult<PurgeReportView> {
    let r = bastion_core::sessionlog::purge_session_logs(&purge_root(root, data_dir), rules, bastion_core::sessionlog::now_ms())?;
    Ok(PurgeReportView { deleted_files: r.deleted_files, freed_bytes: r.freed_bytes, removed_folders: r.removed_folders })
}

#[uniffi::export]
impl Library {
    /// [`purge_session_logs`] with each folder's own `session_log_keep_days` applied.
    pub fn purge_session_logs(&self, root: String, data_dir: String) -> FfiResult<PurgeReportView> {
        let settings = load_settings(&data_dir)?;
        let rules = bastion_core::sessionlog::PurgeRules::for_library(&self.lock(), &settings, &purge_root(&root, &data_dir), &default_log_root(&data_dir));
        purge_with(&root, &data_dir, &rules)
    }
}

#[cfg(test)]
mod session_log_v2_tests {
    use super::*;

    #[test]
    fn log_state_view_names_each_state() {
        use bastion_core::sessionlog::LogState;
        assert_eq!(LogStateView::from(LogState::Off).state, "off");
        assert_eq!(LogStateView::from(LogState::Active { path: "/p".into() }).path.as_deref(), Some("/p"));
        assert_eq!(LogStateView::from(LogState::Stopped { reason: "r".into() }).reason.as_deref(), Some("r"));
    }

    #[test]
    fn purge_with_defaults_keeps_everything() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap().to_string();
        let logs = default_log_root(&d);
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(logs.join("a.log"), format!("{}\n", bastion_core::sessionlog::LOG_MAGIC)).unwrap();
        assert_eq!(purge_session_logs(String::new(), d).unwrap(), PurgeReportView { deleted_files: 0, freed_bytes: 0, removed_folders: 0 });
        assert!(logs.join("a.log").exists());
    }
}
