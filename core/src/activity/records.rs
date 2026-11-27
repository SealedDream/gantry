//! Activity store: the records, the filters and the rules for what text is stored.
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::audit::is_sensitive_key;
use crate::connection_history::short_error;
use crate::error::{CoreError, Result};

use super::*;

pub type SessionId = Uuid;

/// Why a session ended. `Unknown` is only ever read (a value written by a newer build).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    ClosedByUser,
    RemoteClosed,
    NetworkLost,
    AuthFailed,
    HostKey,
    Timeout,
    AppQuit,
    AppCrashed,
    Failed,
    #[serde(other)]
    Unknown,
}

impl EndReason {
    /// A normal end, as opposed to a failure.
    pub fn is_ok(self) -> bool {
        matches!(self, EndReason::ClosedByUser | EndReason::RemoteClosed | EndReason::AppQuit)
    }
}

/// What happened inside a session. `Unknown` is only ever read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Reconnect,
    HostKey,
    Certificate,
    Resize,
    Clipboard,
    SharedFolder,
    FileTransfer,
    Tunnel,
    Task,
    Snippet,
    Broadcast,
    SessionLog,
    Trigger,
    #[serde(other)]
    Unknown,
}

impl EventKind {
    /// The detail keys an event of this kind may carry. A detail under any other key is
    /// dropped, so free text (a command line, an error from somewhere else) cannot ride along
    /// under a harmless-looking name.
    pub fn detail_keys(self) -> &'static [&'static str] {
        match self {
            EventKind::Reconnect => &["attempt", "delay_ms", "result", "error"],
            EventKind::HostKey => &["decision", "fingerprint", "algorithm", "host"],
            EventKind::Certificate => &["decision", "fingerprint", "subject", "issuer", "host"],
            EventKind::Resize => &["width", "height", "cols", "rows", "scale", "size"],
            EventKind::Clipboard => &["direction", "bytes", "kind"],
            EventKind::SharedFolder => &["name", "path", "mode", "state"],
            EventKind::FileTransfer => &["name", "bytes", "direction", "result", "error"],
            EventKind::Tunnel => &["state", "kind", "name", "local_port", "remote_host", "remote_port", "error"],
            EventKind::Task => &["name", "exit_code", "result", "duration_ms", "error"],
            EventKind::Snippet => &["name", "tabs"],
            EventKind::Broadcast => &["state", "tabs"],
            EventKind::SessionLog => &["state", "path", "error"],
            // `action` is the name of the trigger's action kind (an enum name), never the text
            // the trigger sends or runs.
            EventKind::Trigger => &["name", "action"],
            EventKind::Unknown => &[],
        }
    }
}

/// Where the login of a session came from. `Unknown` is only ever read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoginSource {
    Own,
    Inherited,
    SameHost,
    Typed,
    Agent,
    Key,
    #[serde(other)]
    Unknown,
}

/// The app that ran the session. `Unknown` is only ever read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum App {
    NativeMac,
    NativeWindows,
    Tauri,
    #[serde(other)]
    Unknown,
}

/// One folder on the way from the library root to a connection, as it was at connect time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderRef {
    pub id: Uuid,
    pub name: String,
}

/// What is known when a session starts. Times are Unix milliseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStart {
    pub connection_id: Uuid,
    pub connection_name: String,
    /// Root first. The folder filter matches on these ids, so history survives a move or delete.
    #[serde(default)]
    pub folder_path: Vec<FolderRef>,
    /// The model's protocol name (`ssh`, `rdp`, …).
    pub protocol: String,
    /// A host name or address. A URL is reduced to its host (and port).
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub username: Option<String>,
    /// Names of the gateway or jump hosts, in order.
    #[serde(default)]
    pub route: Vec<String>,
    pub login_source: LoginSource,
    pub started_at: u64,
    pub app: App,
    pub app_version: String,
    pub device_name: String,
}

/// What is known when a session ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionEnd {
    /// `None` when the session never connected.
    #[serde(default)]
    pub connected_at: Option<u64>,
    pub ended_at: u64,
    pub end_reason: EndReason,
    /// `None`: the number of `reconnect` events recorded for the session.
    #[serde(default)]
    pub reconnects: Option<u32>,
    #[serde(default)]
    pub transcript_path: Option<String>,
    /// 64 hex digits.
    #[serde(default)]
    pub transcript_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResultFilter {
    /// Ended normally (closed by the user, by the remote side, or at app quit).
    Ok,
    /// Ended for any other reason.
    Failed,
    /// No end yet.
    Open,
}

/// Which sessions a query returns; every field that is set must match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Filter {
    pub connection: Option<Uuid>,
    /// Sessions whose recorded folder path contains this folder (so subfolders are included).
    pub folder: Option<Uuid>,
    /// Started at or after this time.
    pub from: Option<u64>,
    /// Started at or before this time.
    pub to: Option<u64>,
    pub protocol: Option<String>,
    /// Compared without regard to case.
    pub user: Option<String>,
    pub result: Option<ResultFilter>,
}

impl Filter {
    pub(super) fn matches(&self, s: &StartLine, end: Option<&EndLine>) -> bool {
        self.connection.is_none_or(|c| c == s.connection_id)
            && self.folder.is_none_or(|f| s.folder_path.iter().any(|p| p.id == f))
            && self.from.is_none_or(|t| s.started_at >= t)
            && self.to.is_none_or(|t| s.started_at <= t)
            && self.protocol.as_deref().is_none_or(|p| p.eq_ignore_ascii_case(&s.protocol))
            && self.user.as_deref().is_none_or(|u| s.username.as_deref().is_some_and(|n| n.to_lowercase() == u.to_lowercase()))
            && self.result.is_none_or(|r| match (r, end) {
                (ResultFilter::Open, end) => end.is_none(),
                (ResultFilter::Ok, Some(e)) => e.end_reason.is_ok(),
                (ResultFilter::Failed, Some(e)) => !e.end_reason.is_ok(),
                (_, None) => false,
            })
    }
}

/// `limit` is capped at [`MAX_PAGE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page {
    pub offset: usize,
    pub limit: usize,
}

/// One session for a history list: its start, and its end once it has one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub session_id: SessionId,
    pub connection_id: Uuid,
    pub connection_name: String,
    pub folder_path: Vec<FolderRef>,
    pub protocol: String,
    pub host: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub route: Vec<String>,
    pub login_source: LoginSource,
    pub started_at: u64,
    pub app: App,
    pub app_version: String,
    pub device_name: String,
    /// True while the session has no end record.
    pub open: bool,
    pub connected_at: Option<u64>,
    pub ended_at: Option<u64>,
    pub duration_ms: Option<u64>,
    pub end_reason: Option<EndReason>,
    pub reconnects: Option<u32>,
    pub transcript_path: Option<String>,
    pub transcript_sha256: Option<String>,
}

/// One event of a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    pub at: u64,
    pub kind: EventKind,
    pub details: BTreeMap<String, String>,
}

// The stored lines. Field names and order are the file format.

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum Line {
    SessionStart(StartLine),
    SessionEnd(EndLine),
    Event(EventLine),
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct StartLine {
    pub(super) session_id: SessionId,
    /// The `ActivityLog` handle that wrote the start; see [`ActivityLog::close_orphans`].
    #[serde(default)]
    pub(super) run_id: Option<Uuid>,
    pub(super) connection_id: Uuid,
    pub(super) connection_name: String,
    #[serde(default)]
    pub(super) folder_path: Vec<FolderRef>,
    pub(super) protocol: String,
    pub(super) host: String,
    #[serde(default)]
    pub(super) port: Option<u16>,
    #[serde(default)]
    pub(super) username: Option<String>,
    #[serde(default)]
    pub(super) route: Vec<String>,
    pub(super) login_source: LoginSource,
    pub(super) started_at: u64,
    pub(super) app: App,
    pub(super) app_version: String,
    pub(super) device_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct EndLine {
    pub(super) session_id: SessionId,
    #[serde(default)]
    pub(super) connected_at: Option<u64>,
    pub(super) ended_at: u64,
    pub(super) duration_ms: u64,
    pub(super) end_reason: EndReason,
    #[serde(default)]
    pub(super) reconnects: u32,
    #[serde(default)]
    pub(super) transcript_path: Option<String>,
    #[serde(default)]
    pub(super) transcript_sha256: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct EventLine {
    pub(super) session_id: SessionId,
    pub(super) at: u64,
    pub(super) kind: EventKind,
    #[serde(default)]
    pub(super) details: BTreeMap<String, String>,
}

pub(super) fn summary(s: StartLine, end: Option<EndLine>) -> SessionSummary {
    SessionSummary {
        session_id: s.session_id,
        connection_id: s.connection_id,
        connection_name: s.connection_name,
        folder_path: s.folder_path,
        protocol: s.protocol,
        host: s.host,
        port: s.port,
        username: s.username,
        route: s.route,
        login_source: s.login_source,
        started_at: s.started_at,
        app: s.app,
        app_version: s.app_version,
        device_name: s.device_name,
        open: end.is_none(),
        connected_at: end.as_ref().and_then(|e| e.connected_at),
        ended_at: end.as_ref().map(|e| e.ended_at),
        duration_ms: end.as_ref().map(|e| e.duration_ms),
        end_reason: end.as_ref().map(|e| e.end_reason),
        reconnects: end.as_ref().map(|e| e.reconnects),
        transcript_path: end.as_ref().and_then(|e| e.transcript_path.clone()),
        transcript_sha256: end.and_then(|e| e.transcript_sha256),
    }
}

/// A time given by a caller, no later than tomorrow: a wrong clock or a bad argument must not
/// create a monthly file far in the future, which would sort first and never be purged.
pub(super) fn bounded(at: u64) -> u64 {
    at.min(now_ms().saturating_add(DAY_MS)).min(MAX_MS)
}

/// Now, in Unix milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis().min(u128::from(MAX_MS)) as u64).unwrap_or(0)
}

/// This computer's name, for [`SessionStart::device_name`]. Empty when the system gives none.
pub fn device_name() -> String {
    #[cfg(unix)]
    {
        let mut name = [0u8; 256];
        // SAFETY: `name` is writable for its whole length, which is the length passed.
        if unsafe { libc::gethostname(name.as_mut_ptr().cast(), name.len()) } != 0 {
            return String::new();
        }
        let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
        String::from_utf8_lossy(&name[..end]).into_owned()
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    }
}

/// One bounded line of text: control characters become spaces, then trimmed and cut.
pub(super) fn clean(text: &str, max_chars: usize) -> String {
    let flat: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let flat = flat.trim();
    if flat.chars().count() <= max_chars {
        return flat.to_string();
    }
    let cut: String = flat.chars().take(max_chars - 1).collect();
    format!("{cut}…")
}

/// The host (and port) of what may be a URL: the scheme, `user:password@`, path, query string
/// and fragment are dropped, because they can carry credentials and tokens.
///
/// User-info ends at the LAST `@` of the whole text (a password may itself hold `:` or `@`).
/// When a `/`, `?` or `#` comes before that `@`, the text cannot be told apart: it is either a
/// password holding that character, or a path or query string holding an `@` (a signature, a
/// token). Either way something secret may sit on one side, so nothing is stored. What remains
/// must look like a host, or nothing of it is stored either. A bare `user:password` (no `@`) is
/// host-shaped; `is_host_and_port` refuses it where it can be told from a host and a port.
pub(super) fn clean_host(host: &str) -> String {
    let rest = host.split_once("://").map_or(host, |(_, rest)| rest);
    let rest = match rest.rsplit_once('@') {
        Some((before, _)) if before.contains(['/', '?', '#']) => return HIDDEN.to_string(),
        Some((_, after)) => after,
        None => rest,
    };
    let rest = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = clean(rest, MAX_TEXT_CHARS);
    if host.chars().all(|c| c.is_alphanumeric() || HOST_PUNCTUATION.contains(c)) && is_host_and_port(&host) {
        host
    } else {
        HIDDEN.to_string()
    }
}

/// Whether host-shaped text is a host, optionally with a port, and not `user:password` (review
/// note N2 of LOG-CORE-01). What follows the host must be a port number (1 to 65535):
/// `name:22` is a host and a port, `name:word` is not and is not stored. Without brackets, text
/// with several colons must be an IPv6 address.
///
/// What cannot be told apart: a password made only of digits in the port range (`admin:8080`)
/// looks like a host and a port and is kept. So the rule for every caller stays: **never pass
/// a bare `user:password` as the host.**
fn is_host_and_port(text: &str) -> bool {
    if let Some(rest) = text.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((_, "")) => true,
            Some((_, after)) => after.strip_prefix(':').is_some_and(is_port),
            None => false,
        };
    }
    match text.matches(':').count() {
        0 => true,
        1 => text.split_once(':').is_some_and(|(name, port)| !name.is_empty() && is_port(port)),
        _ => text.split('%').next().unwrap_or_default().parse::<std::net::Ipv6Addr>().is_ok(),
    }
}

fn is_port(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_digit()) && text.parse::<u16>().is_ok_and(|port| port != 0)
}

/// Whether a detail value may hold a secret: it names one.
pub(super) fn looks_secret(value: &str) -> bool {
    let lower = value.to_lowercase();
    SECRET_VALUE_WORDS.iter().any(|w| lower.contains(w))
}

/// The details of an event as they are stored: only the keys the kind lists
/// ([`EventKind::detail_keys`]), plus any key that names a secret, kept with its value masked so
/// the mistake is visible. No value that names a secret is stored under any key.
pub(super) fn clean_details(kind: EventKind, details: BTreeMap<String, String>) -> BTreeMap<String, String> {
    details
        .into_iter()
        .filter_map(|(k, v)| {
            let key = clean(&k, MAX_KEY_CHARS);
            // Checked on the whole key: a cut key must not hide the word that marks a secret.
            if is_sensitive_key(&k) {
                return Some((key, MASK.to_string()));
            }
            if !kind.detail_keys().contains(&k.as_str()) {
                return None;
            }
            if kind == EventKind::Tunnel && k == TUNNEL_HOST_KEY {
                return Some((key, clean_host(&v)));
            }
            let is_error = ERROR_KEYS.contains(&k.as_str());
            let value = match (looks_secret(&v), is_error) {
                (true, true) => ERROR_HIDDEN.to_string(),
                (true, false) => HIDDEN.to_string(),
                (false, true) => short_error(&v),
                (false, false) => clean(&v, MAX_VALUE_CHARS),
            };
            Some((key, value))
        })
        .take(MAX_DETAILS)
        .collect()
}

pub(super) fn clean_sha256(hash: &str) -> Result<String> {
    let hash = hash.trim().to_ascii_lowercase();
    if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(hash)
    } else {
        Err(CoreError::Invalid("transcript hash is not 64 hex digits".into()))
    }
}

/// A monthly file: `YYYY-MM.jsonl` (part 1) or `YYYY-MM.<part>.jsonl`. Ordered oldest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FileKey {
    pub(super) year: u32,
    pub(super) month: u32,
    pub(super) part: u32,
}

impl FileKey {
    pub(super) fn name(self) -> String {
        match self.part {
            1 => format!("{:04}-{:02}.jsonl", self.year, self.month),
            part => format!("{:04}-{:02}.{part}.jsonl", self.year, self.month),
        }
    }

    /// `None` for any name that is not exactly a monthly file's.
    pub(super) fn parse(name: &str) -> Option<FileKey> {
        let stem = name.strip_suffix(".jsonl")?;
        let (month_text, part) = match stem.split_once('.') {
            Some((m, p)) => (m, p.parse::<u32>().ok().filter(|n| *n >= 2 && n.to_string() == p)?),
            None => (stem, 1),
        };
        let b = month_text.as_bytes();
        if b.len() != 7 || b[4] != b'-' || !b[..4].iter().chain(&b[5..]).all(u8::is_ascii_digit) {
            return None;
        }
        let (year, month) = (month_text[..4].parse().ok()?, month_text[5..].parse().ok()?);
        (1..=12).contains(&month).then_some(FileKey { year, month, part })
    }
}

/// The UTC year and month of a time.
pub(super) fn month_of(ms: u64) -> (u32, u32) {
    let iso = crate::sysview::iso_utc(ms.min(MAX_MS) as i64 * 1000);
    (iso[..4].parse().unwrap_or(1970), iso[5..7].parse().unwrap_or(1))
}

/// Unix milliseconds of the first instant of a UTC month.
pub(super) fn month_start_ms(year: u32, month: u32) -> u64 {
    // Civil date to days since 1970-01-01 (Howard Hinnant's algorithm), for day 1.
    let y = i64::from(year) - i64::from(month <= 2);
    let (era, year_of_era) = (y.div_euclid(400), y.rem_euclid(400));
    let day_of_year = (153 * ((i64::from(month) + 9) % 12) + 2) / 5;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    days.max(0) as u64 * DAY_MS
}

pub(super) fn next_month(year: u32, month: u32) -> (u32, u32) {
    if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    }
}

pub(super) fn parse(line: &[u8]) -> Option<Line> {
    serde_json::from_slice(line).ok()
}
