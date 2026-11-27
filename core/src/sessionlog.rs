//! Session logging to file: everything a terminal prints, appended line by line to an owner-only
//! file with size rotation (`log`, `log.1` … `log.N`, oldest dropped), optional ANSI stripping,
//! optional per-line time stamps, and redaction of whatever follows a password, passphrase, token
//! or secret prompt on the same line, of private-key blocks, `Authorization:` values and of text
//! matching the user's patterns.
//!
//! Session log v2 (LOG-CORE-02): [`session_log_plan`] decides the path, options and header for a
//! saved connection; [`LogWriter`] moves formatting and disk I/O off the terminal's output path
//! onto a writer thread with a bounded queue; [`LogState`] tells the app when logging stopped;
//! [`purge_session_logs`] applies the retention settings.
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use regex::{Regex, RegexBuilder};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::logexport::{create_owner_only, strip_escapes};

/// Rotate when the current file would grow past this many bytes (default).
pub const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Rotated files kept besides the current one (default).
pub const DEFAULT_KEEP: usize = 5;
/// A line longer than this is written out without waiting for its newline.
const MAX_PENDING_BYTES: usize = 64 * 1024;
/// Smallest rotation size accepted, so a bad setting cannot rotate on every line.
const MIN_MAX_BYTES: u64 = 4 * 1024;
/// Most rotated files accepted.
const MAX_KEEP: usize = 100;
/// What replaces a secret after a prompt.
pub const REDACTED: &str = "[redacted]";
const PROMPT_WORDS: [&str; 5] = ["password", "passphrase", "passcode", "token", "secret"];

/// First line of every session log file, also of a file started by rotation. Retention only
/// deletes files that start with it.
pub const LOG_MAGIC: &str = "# Gantry session log";
/// The first line of logs written before the product rename; they still count as session logs.
pub const LEGACY_LOG_MAGIC: &str = "# Bastion session log";

/// Settings (`settings.rs`) read by [`session_log_plan`] and [`PurgeRules::from_settings`].
pub const FOLDER_SETTING: &str = "logging.session-log-folder";
pub const TIMESTAMPS_SETTING: &str = "logging.session-log-timestamps";
pub const KEEP_DAYS_SETTING: &str = "logging.session-log-keep-days";
pub const MAX_GB_SETTING: &str = "logging.session-log-max-gb";
pub const REDACT_SETTING: &str = "logging.redact-patterns";

/// Longest keep time a setting or property accepts, in days (10 years).
pub const MAX_KEEP_DAYS: u32 = 3650;
/// Bytes the writer thread may have waiting before logging stops rather than block the terminal.
pub const QUEUE_BYTES: usize = 4 * 1024 * 1024;
/// The writer flushes at least this often while output keeps coming.
const FLUSH_EVERY: Duration = Duration::from_secs(1);
/// Longest path [`session_log_plan`] returns before it drops middle folders.
const MAX_PATH_CHARS: usize = 240;
/// User redaction patterns: how many, how long, and the compiled-size limit of each.
const MAX_PATTERNS: usize = 32;
const MAX_PATTERN_LEN: usize = 512;
const PATTERN_SIZE_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogOptions {
    pub max_bytes: u64,
    pub keep: usize,
    pub strip_ansi: bool,
    pub redact_prompts: bool,
    /// Start every line with `HH:MM:SS.mmm ` (local time, see `utc_offset_minutes`).
    pub timestamps: bool,
    /// The local time's offset from UTC, for time stamps, header and footer.
    pub utc_offset_minutes: i32,
    /// User regular expressions (setting `logging.redact-patterns`); matches become `[redacted]`.
    pub redact_patterns: Vec<String>,
}

impl Default for LogOptions {
    fn default() -> Self {
        LogOptions {
            max_bytes: DEFAULT_MAX_BYTES,
            keep: DEFAULT_KEEP,
            strip_ansi: false,
            redact_prompts: true,
            timestamps: false,
            utc_offset_minutes: 0,
            redact_patterns: Vec::new(),
        }
    }
}

impl LogOptions {
    fn validated(self) -> Result<Self> {
        if self.max_bytes < MIN_MAX_BYTES {
            return Err(CoreError::Invalid(format!("log rotation size must be at least {MIN_MAX_BYTES} bytes")));
        }
        if self.keep > MAX_KEEP {
            return Err(CoreError::Invalid(format!("at most {MAX_KEEP} rotated logs can be kept")));
        }
        if self.utc_offset_minutes.abs() > 18 * 60 {
            return Err(CoreError::Invalid("the UTC offset is out of range".into()));
        }
        Ok(self)
    }
}

/// Compile the user's redaction patterns (one per line, blank lines ignored). Refuses more than
/// 32 patterns, a pattern over 512 characters, and one whose compiled form is too large.
pub fn compile_patterns(text: &str) -> Result<Vec<Regex>> {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.len() > MAX_PATTERNS {
        return Err(CoreError::Invalid(format!("at most {MAX_PATTERNS} redaction patterns")));
    }
    lines
        .into_iter()
        .map(|l| {
            if l.len() > MAX_PATTERN_LEN {
                return Err(CoreError::Invalid(format!("a redaction pattern may have at most {MAX_PATTERN_LEN} characters")));
            }
            RegexBuilder::new(l)
                .size_limit(PATTERN_SIZE_LIMIT)
                .dfa_size_limit(PATTERN_SIZE_LIMIT)
                .build()
                .map_err(|e| CoreError::Invalid(format!("redaction pattern `{l}` is not valid: {}", first_line(&e.to_string()))))
        })
        .collect()
}

fn first_line(s: &str) -> &str {
    s.lines().last().unwrap_or(s).trim()
}

/// A session log folder as stored: a full path, at most 1024 characters, no `..`, no control
/// characters.
pub fn validate_log_folder(v: &str) -> std::result::Result<String, String> {
    let v = v.trim();
    let b = v.as_bytes();
    let drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
    if !(v.starts_with('/') || v.starts_with("\\\\") || drive) {
        return Err("use the folder's full path".into());
    }
    if v.len() > 1024 || v.chars().any(char::is_control) || v.split(['/', '\\']).any(|c| c == "..") {
        return Err("not a usable folder path".into());
    }
    Ok(v.to_string())
}

/// Unix time in milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// `(year, month, day, hour, minute, second, millisecond)` of `ms` shifted by `offset_minutes`.
fn civil(ms: u64, offset_minutes: i32) -> (i64, i64, i64, i64, i64, i64, i64) {
    let total = ms as i64 + i64::from(offset_minutes) * 60_000;
    let (secs, milli) = (total.div_euclid(1000), total.rem_euclid(1000));
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
    (y, m, d, rem / 3600, rem / 60 % 60, rem % 60, milli)
}

fn fmt_datetime(ms: u64, offset_minutes: i32) -> String {
    let (y, mo, d, h, mi, s, _) = civil(ms, offset_minutes);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

fn fmt_offset(offset_minutes: i32) -> String {
    let sign = if offset_minutes < 0 { '-' } else { '+' };
    let a = offset_minutes.unsigned_abs();
    format!("{sign}{:02}:{:02}", a / 60, a % 60)
}

/// `UTC time (local time ±HH:MM)` for header and footer lines.
fn fmt_moment(ms: u64, offset_minutes: i32) -> String {
    format!("{} UTC (local {} {})", fmt_datetime(ms, 0), fmt_datetime(ms, offset_minutes), fmt_offset(offset_minutes))
}

/// `HH:MM:SS.mmm ` line prefix.
fn fmt_stamp(ms: u64, offset_minutes: i32) -> String {
    let (_, _, _, h, mi, s, milli) = civil(ms, offset_minutes);
    format!("{h:02}:{mi:02}:{s:02}.{milli:03} ")
}

fn fmt_duration(ms: u64) -> String {
    let s = ms / 1000;
    format!("{}h {:02}m {:02}s ({} s)", s / 3600, s / 60 % 60, s % 60, s)
}

/// One header value on one line: control characters become spaces.
fn header_value(v: &str) -> String {
    v.chars().map(|c| if c.is_control() { ' ' } else { c }).collect::<String>().trim().to_string()
}

/// What a session log's header says about the session (lines starting with `# `).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogHeader {
    pub name: String,
    pub connection_id: String,
    pub host: String,
    pub port: Option<u16>,
    pub user: String,
    /// `direct`, or `via gateway <name>`.
    pub route: String,
    pub app: String,
    pub version: String,
    pub start_ms: u64,
    pub utc_offset_minutes: i32,
}

impl LogHeader {
    pub fn render(&self) -> String {
        let port = self.port.map_or_else(String::new, |p| p.to_string());
        let mut out = format!("{LOG_MAGIC}\n");
        for (k, v) in [
            ("name", self.name.as_str()),
            ("connection", self.connection_id.as_str()),
            ("host", self.host.as_str()),
            ("port", port.as_str()),
            ("user", self.user.as_str()),
            ("route", self.route.as_str()),
        ] {
            out.push_str(&format!("# {k}: {}\n", header_value(v)));
        }
        out.push_str(&format!("# app: {} {}\n", header_value(&self.app), header_value(&self.version)));
        out.push_str(&format!("# started: {}\n", fmt_moment(self.start_ms, self.utc_offset_minutes)));
        out.push_str("# Output only; keystrokes are not recorded.");
        out
    }
}

/// How a session ended, for the footer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEnd {
    /// Passed in by the app; `unknown` when empty.
    pub reason: String,
    pub end_ms: u64,
}

impl LogEnd {
    pub fn now(reason: &str) -> LogEnd {
        LogEnd { reason: reason.to_string(), end_ms: now_ms() }
    }
}

pub struct SessionLog {
    path: PathBuf,
    /// `None` only while rotating (Windows cannot rename an open file).
    file: Option<BufWriter<File>>,
    written: u64,
    pending: Vec<u8>,
    opts: LogOptions,
    patterns: Vec<Regex>,
    /// The next byte written starts a new line (time stamps go there).
    at_line_start: bool,
    /// Inside a `-----BEGIN … PRIVATE KEY-----` block: every line is redacted.
    in_key_block: bool,
    start_ms: u64,
}

impl SessionLog {
    /// Start a new log at `path` (refused if it exists) and write `header` as its first line(s).
    pub fn create(path: &Path, header: &str, opts: LogOptions) -> Result<SessionLog> {
        Self::create_at(path, header, opts, now_ms())
    }

    fn create_at(path: &Path, header: &str, opts: LogOptions, start_ms: u64) -> Result<SessionLog> {
        let opts = opts.validated()?;
        let patterns = compile_patterns(&opts.redact_patterns.join("\n"))?;
        let mut file = BufWriter::new(create_owner_only(path)?);
        let header = format!("{}\n", header.trim_end());
        file.write_all(header.as_bytes())?;
        file.flush()?;
        Ok(SessionLog {
            path: path.to_path_buf(),
            file: Some(file),
            written: header.len() as u64,
            pending: Vec::new(),
            opts,
            patterns,
            at_line_start: true,
            in_key_block: false,
            start_ms,
        })
    }

    /// Start the log a [`LogPlan`] describes, creating its folders owner-only. When the planned
    /// file exists (two sessions in the same second), `-2`, `-3` … is added; never overwrites.
    pub fn create_planned(plan: &LogPlan) -> Result<SessionLog> {
        if let Some(dir) = plan.path.parent() {
            crate::store::create_private_dir(dir)?;
            // The root and the folder levels above the connection are owner-only too: their names
            // say which folders, connections and users were logged.
            for up in dir.ancestors().skip(1).take_while(|a| a.starts_with(&plan.root)) {
                crate::store::create_private_dir(up)?;
            }
        }
        let header = plan.header.render();
        let stem = plan.path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        for n in 1..=999u32 {
            let path = if n == 1 { plan.path.clone() } else { plan.path.with_file_name(format!("{stem}-{n}.log")) };
            match Self::create_at(&path, &header, plan.options.clone(), plan.header.start_ms) {
                Err(CoreError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                other => return other,
            }
        }
        Err(CoreError::Invalid("too many session logs started in the same second".into()))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append program output. Complete lines are written now; a partial line waits for its
    /// newline (so a prompt and its echoed answer are judged together) up to 64 KiB.
    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.pending.extend_from_slice(bytes);
        while let Some(i) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=i).collect();
            self.emit(&line)?;
        }
        if self.pending.len() > MAX_PENDING_BYTES {
            let line = std::mem::take(&mut self.pending);
            self.emit(&line)?;
        }
        Ok(())
    }

    /// Push buffered bytes to the file.
    pub fn flush(&mut self) -> Result<()> {
        self.open()?.flush()?;
        Ok(())
    }

    /// Write any partial line and flush to disk.
    pub fn finish(&mut self) -> Result<()> {
        self.flush_pending()?;
        let f = self.open()?;
        f.flush()?;
        f.get_ref().sync_all()?;
        Ok(())
    }

    /// [`Self::finish`] with a footer (end time, duration, end reason); returns the SHA-256 of
    /// the current file (lowercase hex) for the session record.
    pub fn finish_with(&mut self, end: &LogEnd) -> Result<String> {
        self.flush_pending()?;
        let reason = header_value(&end.reason);
        let reason = if reason.is_empty() { "unknown".to_string() } else { reason };
        let footer = format!(
            "# ended: {}\n# duration: {}\n# end reason: {reason}\n",
            fmt_moment(end.end_ms, self.opts.utc_offset_minutes),
            fmt_duration(end.end_ms.saturating_sub(self.start_ms))
        );
        let f = self.open()?;
        f.write_all(footer.as_bytes())?;
        f.flush()?;
        f.get_ref().sync_all()?;
        self.written += footer.len() as u64;
        file_sha256(&self.path)
    }

    fn flush_pending(&mut self) -> Result<()> {
        if !self.pending.is_empty() {
            let mut line = std::mem::take(&mut self.pending);
            line.push(b'\n');
            self.emit(&line)?;
        }
        Ok(())
    }

    fn open(&mut self) -> Result<&mut BufWriter<File>> {
        self.file.as_mut().ok_or_else(|| CoreError::Invalid("the session log failed to rotate".into()))
    }

    fn emit(&mut self, raw: &[u8]) -> Result<()> {
        let mut line = render(&String::from_utf8_lossy(raw), &self.opts, &self.patterns, &mut self.in_key_block);
        if self.opts.timestamps && self.at_line_start {
            line.insert_str(0, &fmt_stamp(now_ms(), self.opts.utc_offset_minutes));
        }
        self.at_line_start = line.ends_with('\n');
        if self.written > 0 && self.written + line.len() as u64 > self.opts.max_bytes {
            self.rotate()?;
        }
        self.open()?.write_all(line.as_bytes())?;
        self.written += line.len() as u64;
        Ok(())
    }

    fn rotate(&mut self) -> Result<()> {
        if let Some(mut f) = self.file.take() {
            f.flush()?;
            f.get_ref().sync_all()?;
        }
        rotate_files(&self.path, self.opts.keep)?;
        let mut f = BufWriter::new(create_owner_only(&self.path)?);
        let head = format!("{LOG_MAGIC} (continued after rotation)\n");
        f.write_all(head.as_bytes())?;
        self.file = Some(f);
        self.written = head.len() as u64;
        Ok(())
    }
}

/// SHA-256 of a file, lowercase hex.
pub fn file_sha256(path: &Path) -> Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Shift `path` → `path.1` → … → `path.keep`, dropping the oldest. With `keep` 0 the current
/// file is simply removed.
fn rotate_files(path: &Path, keep: usize) -> Result<()> {
    let numbered = |n: usize| PathBuf::from(format!("{}.{n}", path.display()));
    if keep == 0 {
        std::fs::remove_file(path)?;
        return Ok(());
    }
    match std::fs::remove_file(numbered(keep)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    for n in (1..keep).rev() {
        match std::fs::rename(numbered(n), numbered(n + 1)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    std::fs::rename(path, numbered(1))?;
    Ok(())
}

fn authorization_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)((?:proxy-)?authorization\s*:\s*)[^\r\n]*\S").expect("built-in pattern"))
}

fn is_key_begin(plain: &str) -> bool {
    plain.contains("-----BEGIN") && plain.contains("PRIVATE KEY-----")
}

fn is_key_end(plain: &str) -> bool {
    plain.contains("-----END") && plain.contains("PRIVATE KEY-----")
}

/// One output line as it goes into the log. Any line a redaction rule touches is written
/// escape-free.
fn render(line: &str, opts: &LogOptions, patterns: &[Regex], in_key_block: &mut bool) -> String {
    let nl = if line.ends_with('\n') { "\n" } else { "" };
    let plain = strip_escapes(line);
    if opts.redact_prompts {
        if *in_key_block {
            if is_key_end(&plain) {
                *in_key_block = false;
                return plain;
            }
            return format!("{REDACTED}{nl}");
        }
        if is_key_begin(&plain) {
            if !is_key_end(&plain) {
                *in_key_block = true;
                return plain;
            }
            return format!("{REDACTED}{nl}");
        }
        if let Some(redacted) = redact_after_prompt(&plain) {
            return redacted;
        }
        if authorization_re().is_match(&plain) {
            return apply_patterns(&authorization_re().replace_all(&plain, format!("${{1}}{REDACTED}")), patterns);
        }
    }
    if patterns.iter().any(|p| p.is_match(&plain)) {
        return apply_patterns(&plain, patterns);
    }
    if opts.strip_ansi { plain } else { line.to_string() }
}

fn apply_patterns(text: &str, patterns: &[Regex]) -> String {
    let mut out = text.to_string();
    for p in patterns {
        if p.is_match(&out) {
            out = p.replace_all(&out, regex::NoExpand(REDACTED)).into_owned();
        }
    }
    out
}

/// `Some(line)` with the answer replaced when `line` holds a secret prompt (`Password:`,
/// `Enter passphrase for key '…':`, `API token: `) followed by text; `None` otherwise.
pub fn redact_after_prompt(line: &str) -> Option<String> {
    let lower = line.to_lowercase();
    if lower.len() != line.len() {
        // Lowercasing changed byte offsets (rare scripts); redact the whole line to be safe.
        return PROMPT_WORDS.iter().any(|w| lower.contains(w)).then(|| format!("{REDACTED}\n"));
    }
    let word_end = PROMPT_WORDS.iter().filter_map(|w| lower.find(w).map(|i| i + w.len())).min()?;
    let colon = word_end + line[word_end..].find(':')?;
    let (head, answer) = line.split_at(colon + 1);
    if answer.trim().is_empty() {
        return None;
    }
    Some(format!("{head} {REDACTED}\n"))
}

// ---------------------------------------------------------------------------------------------
// Plan: one place decides path, options and header.

/// Where and how a saved connection's session is logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogPlan {
    /// The log folder root the path is inside (retention runs on it).
    pub root: PathBuf,
    pub path: PathBuf,
    pub options: LogOptions,
    pub header: LogHeader,
}

/// What the app passes besides the library and settings.
#[derive(Debug, Clone)]
pub struct PlanContext {
    /// The default root: the `session-logs` folder in the app data folder.
    pub default_root: PathBuf,
    /// App name and version for the header, such as `Bastion for Mac`, `1.4.0`.
    pub app: String,
    pub version: String,
    pub now_ms: u64,
    pub utc_offset_minutes: i32,
}

/// The log root for a connection's resolved settings: its `session_log_folder`, else the setting,
/// else `default_root`.
fn log_root(s: &crate::model::Settings, settings: &crate::settings::Settings, default_root: &Path) -> Result<PathBuf> {
    let bad = |e: String| CoreError::Invalid(format!("Session log folder: {e}"));
    match s.session_log_folder.as_deref().filter(|v| !v.trim().is_empty()) {
        Some(v) => Ok(PathBuf::from(validate_log_folder(v).map_err(bad)?)),
        None => match settings.get(FOLDER_SETTING).unwrap_or_default() {
            v if v.trim().is_empty() => Ok(default_root.to_path_buf()),
            v => Ok(PathBuf::from(validate_log_folder(&v).map_err(bad)?)),
        },
    }
}

/// A path part through `safe_stem`, with `fallback` when nothing usable is left.
fn part(s: &str, fallback: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return fallback.to_string();
    }
    let stem = crate::logexport::safe_stem(s);
    if stem == "snippet" && !s.eq_ignore_ascii_case("snippet") { fallback.to_string() } else { stem }
}

/// `<root>/<Folder>/<Subfolder>/<Connection>/<YYYY-MM-DD_HH-MM-SS>_<user>.log`, each part made
/// safe. The root is the connection's (or a folder's) `session_log_folder`, else the setting
/// `logging.session-log-folder`, else `ctx.default_root`. A path longer than 240 characters
/// loses middle folders first.
pub fn session_log_plan(doc: &crate::model::Document, settings: &crate::settings::Settings, connection_id: Uuid, ctx: &PlanContext) -> Result<LogPlan> {
    let r = doc.resolve(connection_id)?;
    let s = &r.effective;
    let setting = |id: &str| settings.get(id).unwrap_or_default();
    let root = log_root(s, settings, &ctx.default_root)?;
    let user = s.username.clone().unwrap_or_default();
    let (y, mo, d, h, mi, sec, _) = civil(ctx.now_ms, ctx.utc_offset_minutes);
    let file = format!("{y:04}-{mo:02}-{d:02}_{h:02}-{mi:02}-{sec:02}_{}.log", part(&user, "nouser"));
    let mut folders: Vec<String> = r.path.iter().map(|f| part(f, "folder")).collect();
    let conn = part(&r.connection.name, "connection");
    let build = |folders: &[String]| {
        let mut p = root.clone();
        for f in folders {
            p.push(f);
        }
        p.push(&conn);
        p.push(&file);
        p
    };
    let mut path = build(&folders);
    while path.as_os_str().len() > MAX_PATH_CHARS && !folders.is_empty() {
        folders.remove(folders.len() / 2);
        path = build(&folders);
    }
    let route = match s.gateway_id.and_then(|g| doc.gateways.iter().find(|x| x.id == g)) {
        Some(g) => format!("via gateway {}", g.name),
        None => "direct".to_string(),
    };
    let options = LogOptions {
        // Logs are read as text: escape codes are always stripped (LOG-01; both apps).
        strip_ansi: true,
        timestamps: setting(TIMESTAMPS_SETTING) == "true",
        utc_offset_minutes: ctx.utc_offset_minutes,
        redact_patterns: setting(REDACT_SETTING).lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect(),
        ..LogOptions::default()
    };
    compile_patterns(&options.redact_patterns.join("\n"))?;
    let header = LogHeader {
        name: r.connection.name.clone(),
        connection_id: connection_id.to_string(),
        host: r.connection.host.clone(),
        port: s.port,
        user,
        route,
        app: ctx.app.clone(),
        version: ctx.version.clone(),
        start_ms: ctx.now_ms,
        utc_offset_minutes: ctx.utc_offset_minutes,
    };
    Ok(LogPlan { root, path, options, header })
}

// ---------------------------------------------------------------------------------------------
// Writer thread and state.

/// What the app shows about a terminal's session log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogState {
    Off,
    Active { path: String },
    /// Logging stopped by itself (disk error, the disk could not keep up). The file so far is kept.
    Stopped { reason: String },
}

/// Reason given when the queue overflows.
pub const OVERFLOW_REASON: &str = "the disk did not keep up with the output; logging stopped so the terminal stays responsive";

enum Msg {
    Data(Vec<u8>),
    Finish(LogEnd, mpsc::Sender<Result<String>>),
}

type Hook = Arc<dyn Fn() + Send + Sync>;

/// A [`SessionLog`] on its own thread. `write` never blocks on the disk: it queues at most
/// [`QUEUE_BYTES`] and refuses (setting [`LogState::Stopped`]) beyond that.
pub struct LogWriter {
    /// `None` once finishing or dropped.
    tx: Option<mpsc::Sender<Msg>>,
    queued: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
    state: Arc<Mutex<LogState>>,
    thread: Option<std::thread::JoinHandle<()>>,
    path: PathBuf,
}

fn set_state(state: &Mutex<LogState>, s: LogState) {
    *state.lock().unwrap_or_else(|p| p.into_inner()) = s;
}

impl LogWriter {
    /// Move `log` to a writer thread; `state` becomes `Active`.
    pub fn spawn(log: SessionLog, state: Arc<Mutex<LogState>>) -> Result<LogWriter> {
        Self::spawn_with_hook(log, state, None)
    }

    /// [`Self::spawn`] with a function the thread calls before each write (tests: a slow disk).
    #[doc(hidden)]
    pub fn spawn_with_hook(mut log: SessionLog, state: Arc<Mutex<LogState>>, hook: Option<Hook>) -> Result<LogWriter> {
        let (tx, rx) = mpsc::channel::<Msg>();
        let queued = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicBool::new(false));
        let path = log.path().to_path_buf();
        set_state(&state, LogState::Active { path: path.display().to_string() });
        let (q, st, sta) = (queued.clone(), stopped.clone(), state.clone());
        let thread = std::thread::Builder::new()
            .name("bastion-session-log".into())
            .spawn(move || {
                let mut failed = false;
                let mut last_flush = Instant::now();
                let fail = |e: CoreError, failed: &mut bool| {
                    *failed = true;
                    st.store(true, Ordering::SeqCst);
                    set_state(&sta, LogState::Stopped { reason: format!("writing the session log failed: {e}") });
                };
                loop {
                    match rx.recv_timeout(FLUSH_EVERY) {
                        Ok(Msg::Data(bytes)) => {
                            if let Some(h) = &hook {
                                h();
                            }
                            q.fetch_sub(bytes.len(), Ordering::SeqCst);
                            if !failed {
                                if let Err(e) = log.write(&bytes) {
                                    fail(e, &mut failed);
                                }
                            }
                        }
                        Ok(Msg::Finish(end, reply)) => {
                            let r = if failed { Err(CoreError::Invalid("the session log had already stopped".into())) } else { log.finish_with(&end) };
                            let _ = reply.send(r);
                            return;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            if !failed {
                                let reason = match &*sta.lock().unwrap_or_else(|p| p.into_inner()) {
                                    LogState::Stopped { reason } => reason.clone(),
                                    _ => "logging stopped".into(),
                                };
                                let _ = log.finish_with(&LogEnd::now(&reason));
                            }
                            return;
                        }
                    }
                    if !failed && last_flush.elapsed() >= FLUSH_EVERY {
                        if let Err(e) = log.flush() {
                            fail(e, &mut failed);
                        }
                        last_flush = Instant::now();
                    }
                }
            })
            .map_err(CoreError::Io)?;
        Ok(LogWriter { tx: Some(tx), queued, stopped, state, thread: Some(thread), path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Queue program output. False when logging has stopped (disk error or queue full); the
    /// caller then drops the writer.
    pub fn write(&self, bytes: &[u8]) -> bool {
        if self.stopped.load(Ordering::SeqCst) {
            return false;
        }
        let n = bytes.len();
        if self.queued.fetch_add(n, Ordering::SeqCst) + n > QUEUE_BYTES {
            self.queued.fetch_sub(n, Ordering::SeqCst);
            self.stopped.store(true, Ordering::SeqCst);
            set_state(&self.state, LogState::Stopped { reason: OVERFLOW_REASON.into() });
            return false;
        }
        self.tx.as_ref().is_some_and(|tx| tx.send(Msg::Data(bytes.to_vec())).is_ok())
    }

    /// Write what is queued, the footer, and close; returns the file's SHA-256. The state
    /// becomes `Off` (or stays `Stopped` when logging had stopped).
    pub fn finish(mut self, end: LogEnd) -> Result<String> {
        let (rtx, rrx) = mpsc::channel();
        let sent = self.tx.take().is_some_and(|tx| tx.send(Msg::Finish(end, rtx)).is_ok());
        let r = if sent { rrx.recv_timeout(Duration::from_secs(30)).unwrap_or_else(|_| Err(CoreError::Invalid("the session log writer did not finish".into()))) } else { Err(CoreError::Invalid("the session log writer has ended".into())) };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if !self.stopped.load(Ordering::SeqCst) {
            set_state(&self.state, LogState::Off);
        }
        r
    }

    /// Let the thread write what is queued and the footer on its own, without waiting for it
    /// (the terminal's output path after an overflow must not wait for a slow disk).
    pub fn abandon(mut self) {
        self.tx = None;
        self.thread = None;
    }
}

impl Drop for LogWriter {
    /// Dropping the writer writes what is queued and a footer, and waits for the thread, so a
    /// dropped terminal leaves a complete file.
    fn drop(&mut self) {
        self.tx = None;
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Retention.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeRules {
    /// Delete logs last written more than this many days ago; 0 keeps them forever.
    pub keep_days: u32,
    /// Delete the oldest logs while all of them together are larger; 0 is no limit.
    pub max_bytes: u64,
    /// Keep days for logs below a folder (property `session_log_keep_days`); the longest
    /// matching folder wins over `keep_days`. 0 keeps them forever.
    pub folder_keep_days: Vec<(PathBuf, u32)>,
}

impl PurgeRules {
    pub fn from_settings(settings: &crate::settings::Settings) -> PurgeRules {
        let num = |id: &str| settings.get(id).ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        PurgeRules { keep_days: num(KEEP_DAYS_SETTING) as u32, max_bytes: num(MAX_GB_SETTING).saturating_mul(1024 * 1024 * 1024), folder_keep_days: Vec::new() }
    }

    /// [`Self::from_settings`] plus a keep time for every connection's log folder under `root`
    /// whose own or inherited `session_log_keep_days` is set. The folders are the planned ones
    /// before any shortening, so a very long path (over 240 characters) falls back to the setting.
    pub fn for_library(doc: &crate::model::Document, settings: &crate::settings::Settings, root: &Path, default_root: &Path) -> PurgeRules {
        let mut rules = PurgeRules::from_settings(settings);
        for r in doc.connections() {
            let Some(days) = r.effective.session_log_keep_days else { continue };
            if log_root(&r.effective, settings, default_root).ok().as_deref() != Some(root) {
                continue;
            }
            let mut dir = root.to_path_buf();
            for f in &r.path {
                dir.push(part(f, "folder"));
            }
            dir.push(part(&r.connection.name, "connection"));
            rules.folder_keep_days.push((dir, days.min(MAX_KEEP_DAYS)));
        }
        rules
    }

    /// Keep days for a file: the longest matching folder override, else `keep_days`.
    fn keep_days_for(&self, path: &Path) -> u32 {
        self.folder_keep_days.iter().filter(|(d, _)| path.starts_with(d)).max_by_key(|(d, _)| d.components().count()).map_or(self.keep_days, |(_, n)| *n)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub deleted_files: u32,
    pub freed_bytes: u64,
    pub removed_folders: u32,
}

struct Found {
    path: PathBuf,
    modified_ms: u64,
    size: u64,
}

/// Whether `path` is a session log: named `*.log` or `*.log.N`, and its first line starts with
/// [`LOG_MAGIC`] (or [`LEGACY_LOG_MAGIC`]).
fn is_session_log(path: &Path) -> bool {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let named = name.ends_with(".log") || name.rsplit_once(".log.").is_some_and(|(_, n)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    if !named {
        return false;
    }
    // Both markers have the same length.
    let mut buf = [0u8; LOG_MAGIC.len()];
    File::open(path).and_then(|mut f| f.read_exact(&mut buf)).is_ok() && (buf == LOG_MAGIC.as_bytes() || buf == LEGACY_LOG_MAGIC.as_bytes())
}

fn collect(dir: &Path, depth: usize, files: &mut Vec<Found>, dirs: &mut Vec<PathBuf>) {
    if depth > 32 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        // Never follow links: nothing outside the root is touched.
        let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
        if meta.is_dir() {
            dirs.push(p.clone());
            collect(&p, depth + 1, files, dirs);
        } else if meta.is_file() && is_session_log(&p) {
            let modified_ms = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_millis() as u64);
            files.push(Found { path: p, modified_ms, size: meta.len() });
        }
    }
}

/// Apply retention under `root`: delete session logs older than `keep_days`, then the oldest
/// until the rest fit in `max_bytes`, then remove empty folders below the root. Files that are
/// not session logs, links and anything outside the root are left alone.
pub fn purge_session_logs(root: &Path, rules: &PurgeRules, now_ms: u64) -> Result<PurgeReport> {
    let mut report = PurgeReport::default();
    if !std::fs::symlink_metadata(root).is_ok_and(|m| m.is_dir()) {
        return Ok(report);
    }
    let (mut files, mut dirs) = (Vec::new(), Vec::new());
    let root = root.to_path_buf();
    let root = root.as_path();
    collect(root, 0, &mut files, &mut dirs);
    files.sort_by_key(|f| f.modified_ms);
    let mut emptied: Vec<PathBuf> = Vec::new();
    let mut remove = |f: &Found, report: &mut PurgeReport| {
        if std::fs::remove_file(&f.path).is_ok() {
            report.deleted_files += 1;
            report.freed_bytes += f.size;
            emptied.extend(f.path.parent().map(Path::to_path_buf));
            true
        } else {
            false
        }
    };
    let mut kept = Vec::new();
    for f in files {
        let days = rules.keep_days_for(&f.path);
        let cutoff = (days > 0).then(|| now_ms.saturating_sub(u64::from(days) * 86_400_000));
        if cutoff.is_some_and(|c| f.modified_ms < c) && remove(&f, &mut report) {
            continue;
        }
        kept.push(f);
    }
    if rules.max_bytes > 0 {
        let mut total: u64 = kept.iter().map(|f| f.size).sum();
        for f in &kept {
            if total <= rules.max_bytes {
                break;
            }
            if remove(f, &mut report) {
                total -= f.size;
            }
        }
    }
    // Folders left empty by a deletion go, up to (not including) the root. Folders the purge
    // did not empty are not touched.
    emptied.sort();
    emptied.dedup();
    for mut d in emptied {
        while d != root && d.starts_with(root) && dirs.contains(&d) {
            if !std::fs::read_dir(&d).is_ok_and(|mut it| it.next().is_none()) || std::fs::remove_dir(&d).is_err() {
                break;
            }
            report.removed_folders += 1;
            match d.parent() {
                Some(p) => d = p.to_path_buf(),
                None => break,
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
#[path = "sessionlog_tests.rs"]
mod tests;
