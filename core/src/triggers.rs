//! Triggers: regex rules that highlight matching terminal text or raise a notification.
//!
//! Bounded so they never slow a terminal down:
//! - The `regex` crate runs in linear time (no backtracking); each pattern is at most
//!   [`MAX_PATTERN`] characters and compiles under [`REGEX_SIZE_LIMIT`]. Patterns that match the
//!   empty string are refused (they would match everywhere).
//! - Highlights are applied only to the visible rows when a screen is drawn, so their cost does
//!   not depend on how much scrollback there is.
//! - Notifications scan each new output line once, after escape sequences are removed, and only
//!   the first [`SCAN_LINE_MAX`] bytes of a line. One trigger notifies at most once per
//!   [`NOTIFY_COOLDOWN`], and at most [`MAX_EVENTS`] wait to be taken.
//!
//! Triggers are personal and hold no secrets: they live in `triggers.json` beside the library.
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::store::write_atomic;

pub const MAX_TRIGGERS: usize = 64;
pub const MAX_PATTERN: usize = 256;
pub const MAX_NAME: usize = 80;
/// Compiled size cap per pattern, in bytes (the combined set gets four times this).
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// Bytes of a line that triggers look at.
pub const SCAN_LINE_MAX: usize = 4096;
pub const NOTIFY_COOLDOWN: Duration = Duration::from_secs(2);
pub const MAX_EVENTS: usize = 32;
/// Characters of the matching line kept in a notification.
const EVENT_LINE_MAX: usize = 200;
/// Largest file `TriggerStore` and `import_json` accept.
const MAX_FILE: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Highlight {
    /// Text colour 0xRRGGBB; `None` keeps the program's.
    #[serde(default)]
    pub fg: Option<u32>,
    /// Background 0xRRGGBB; `None` keeps the program's.
    #[serde(default)]
    pub bg: Option<u32>,
    #[serde(default)]
    pub bold: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Trigger {
    pub id: Uuid,
    pub name: String,
    pub pattern: String,
    #[serde(default)]
    pub case_insensitive: bool,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub highlight: Option<Highlight>,
    /// Raise a notification when a new line matches.
    #[serde(default)]
    pub notify: bool,
}

fn compile(pattern: &str, case_insensitive: bool) -> Result<Regex> {
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| CoreError::Invalid(format!("pattern: {}", last_line(&e.to_string()))))
}

fn last_line(s: &str) -> String {
    s.lines().last().unwrap_or(s).trim().chars().take(120).collect()
}

impl Trigger {
    pub fn new(name: &str, pattern: &str) -> Self {
        Trigger { id: Uuid::new_v4(), name: name.trim().into(), pattern: pattern.into(), case_insensitive: false, enabled: true, highlight: None, notify: false }
    }

    pub fn validate(&self) -> Result<()> {
        let n = self.name.trim().chars().count();
        if n == 0 || n > MAX_NAME {
            return Err(CoreError::Invalid(format!("trigger name must be 1–{MAX_NAME} characters")));
        }
        if self.pattern.is_empty() || self.pattern.chars().count() > MAX_PATTERN {
            return Err(CoreError::Invalid(format!("pattern must be 1–{MAX_PATTERN} characters")));
        }
        if self.highlight.is_none() && !self.notify {
            return Err(CoreError::Invalid("choose a highlight, a notification or both".into()));
        }
        if let Some(h) = self.highlight {
            if [h.fg, h.bg].into_iter().flatten().any(|c| c > 0xFF_FFFF) {
                return Err(CoreError::Invalid("colours are 0xRRGGBB".into()));
            }
        }
        if compile(&self.pattern, self.case_insensitive)?.is_match("") {
            return Err(CoreError::Invalid("pattern matches empty text, so it would match everywhere".into()));
        }
        Ok(())
    }
}

/// A highlighted part of a line: byte range and the trigger's highlight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub highlight: Highlight,
}

/// Compiled enabled triggers.
#[derive(Debug)]
pub struct TriggerSet {
    triggers: Vec<Trigger>,
    set: RegexSet,
    regexes: Vec<Regex>,
}

/// The first `max` bytes of `s`, cut on a character boundary.
fn head(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

impl TriggerSet {
    /// Compile the enabled triggers; an invalid one is an error naming it.
    pub fn compile(triggers: &[Trigger]) -> Result<Self> {
        let on: Vec<Trigger> = triggers.iter().filter(|t| t.enabled).take(MAX_TRIGGERS).cloned().collect();
        let mut regexes = Vec::with_capacity(on.len());
        for t in &on {
            t.validate().map_err(|e| CoreError::Invalid(format!("trigger {}: {e}", t.name)))?;
            regexes.push(compile(&t.pattern, t.case_insensitive)?);
        }
        let patterns = on.iter().map(|t| if t.case_insensitive { format!("(?i:{})", t.pattern) } else { format!("(?:{})", t.pattern) });
        let set = RegexSetBuilder::new(patterns)
            .size_limit(REGEX_SIZE_LIMIT * 4)
            .dfa_size_limit(REGEX_SIZE_LIMIT * 4)
            .build()
            .map_err(|e| CoreError::Invalid(format!("triggers: {}", last_line(&e.to_string()))))?;
        Ok(TriggerSet { triggers: on, set, regexes })
    }

    pub fn is_empty(&self) -> bool {
        self.triggers.is_empty()
    }

    pub fn has_highlights(&self) -> bool {
        self.triggers.iter().any(|t| t.highlight.is_some())
    }

    pub fn has_notifications(&self) -> bool {
        self.triggers.iter().any(|t| t.notify)
    }

    /// Highlighted ranges of `line` (its first [`SCAN_LINE_MAX`] bytes), in trigger order: a later
    /// trigger's colour wins where two overlap.
    pub fn spans(&self, line: &str) -> Vec<Span> {
        let line = head(line, SCAN_LINE_MAX);
        let mut out = Vec::new();
        for i in self.set.matches(line).iter() {
            let Some(h) = self.triggers[i].highlight else { continue };
            out.extend(self.regexes[i].find_iter(line).map(|m| Span { start: m.start(), end: m.end(), highlight: h }));
        }
        out
    }

    /// Indexes of notifying triggers that match `line`.
    fn notifying(&self, line: &str) -> Vec<usize> {
        let line = head(line, SCAN_LINE_MAX);
        self.set.matches(line).into_iter().filter(|i| self.triggers[*i].notify).collect()
    }
}

/// A notification raised by a trigger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerEvent {
    pub trigger_id: Uuid,
    pub name: String,
    /// The matching line, shortened.
    pub line: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Esc {
    #[default]
    Text,
    Esc,
    Csi,
    /// OSC / DCS / APC … string, ended by BEL or ESC \.
    Str,
    StrEsc,
}

/// Turns output bytes into complete lines without escape sequences, for notifications.
#[derive(Debug, Default)]
pub struct LineScanner {
    buf: Vec<u8>,
    state: Esc,
}

impl LineScanner {
    /// Feed bytes; `line` is called with each completed line (lossy UTF-8).
    pub fn feed(&mut self, bytes: &[u8], mut line: impl FnMut(&str)) {
        for &b in bytes {
            self.state = match (self.state, b) {
                (Esc::Text, 0x1b) => Esc::Esc,
                (Esc::Text, b'\n') => {
                    line(&String::from_utf8_lossy(&self.buf));
                    self.buf.clear();
                    Esc::Text
                }
                (Esc::Text, b) if b < 0x20 && b != b'\t' => Esc::Text,
                (Esc::Text, b) => {
                    if self.buf.len() < SCAN_LINE_MAX {
                        self.buf.push(b);
                    }
                    Esc::Text
                }
                (Esc::Esc, b'[') => Esc::Csi,
                (Esc::Esc, b']' | b'P' | b'_' | b'^' | b'X') => Esc::Str,
                (Esc::Esc, _) => Esc::Text,
                (Esc::Csi, 0x40..=0x7e) => Esc::Text,
                (Esc::Csi, _) => Esc::Csi,
                (Esc::Str, 0x07) => Esc::Text,
                (Esc::Str, 0x1b) => Esc::StrEsc,
                (Esc::Str, _) => Esc::Str,
                (Esc::StrEsc, b'\\') => Esc::Text,
                (Esc::StrEsc, _) => Esc::Str,
            };
        }
    }
}

/// Notification state for one terminal: scanner, cooldowns and the waiting events.
#[derive(Debug, Default)]
pub struct Notifier {
    scanner: LineScanner,
    last: Vec<Option<Instant>>,
    events: VecDeque<TriggerEvent>,
}

impl Notifier {
    pub fn feed(&mut self, set: &TriggerSet, bytes: &[u8]) {
        if !set.has_notifications() {
            return;
        }
        self.last.resize(set.triggers.len(), None);
        let (last, events) = (&mut self.last, &mut self.events);
        self.scanner.feed(bytes, |line| {
            for i in set.notifying(line) {
                let now = Instant::now();
                if last[i].is_some_and(|t| now.duration_since(t) < NOTIFY_COOLDOWN) {
                    continue;
                }
                last[i] = Some(now);
                if events.len() >= MAX_EVENTS {
                    events.pop_front();
                }
                let t = &set.triggers[i];
                events.push_back(TriggerEvent { trigger_id: t.id, name: t.name.clone(), line: line.trim().chars().take(EVENT_LINE_MAX).collect() });
            }
        });
    }

    /// Forget cooldowns (the triggers changed).
    pub fn reset(&mut self) {
        self.last.clear();
    }

    pub fn take(&mut self) -> Vec<TriggerEvent> {
        self.events.drain(..).collect()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    triggers: Vec<Trigger>,
}

fn parse(bytes: &[u8]) -> Result<Vec<Trigger>> {
    if bytes.len() > MAX_FILE {
        return Err(CoreError::Invalid("triggers file is too large".into()));
    }
    let f: File = serde_json::from_slice(bytes).map_err(|e| CoreError::Corrupt(format!("triggers: {e}")))?;
    if f.triggers.len() > MAX_TRIGGERS {
        return Err(CoreError::Invalid(format!("at most {MAX_TRIGGERS} triggers")));
    }
    for t in &f.triggers {
        t.validate().map_err(|e| CoreError::Corrupt(format!("trigger {}: {e}", t.name)))?;
    }
    Ok(f.triggers)
}

/// The per-user triggers on disk (`triggers.json`).
pub struct TriggerStore {
    path: PathBuf,
    triggers: Vec<Trigger>,
}

impl TriggerStore {
    /// Open `path`; a missing file is empty, an invalid one is an error (never silently reset).
    pub fn open(path: &Path) -> Result<Self> {
        let triggers = match fs::read(path) {
            Ok(bytes) => parse(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(TriggerStore { path: path.to_path_buf(), triggers })
    }

    pub fn list(&self) -> &[Trigger] {
        &self.triggers
    }

    /// Insert or replace (by id) and save. Names are unique, ignoring case.
    pub fn save(&mut self, t: Trigger) -> Result<()> {
        let t = Trigger { name: t.name.trim().into(), ..t };
        t.validate()?;
        if self.triggers.iter().any(|o| o.id != t.id && o.name.eq_ignore_ascii_case(&t.name)) {
            return Err(CoreError::Invalid(format!("a trigger named {} already exists", t.name)));
        }
        let exists = self.triggers.iter().any(|o| o.id == t.id);
        if !exists && self.triggers.len() >= MAX_TRIGGERS {
            return Err(CoreError::Invalid(format!("at most {MAX_TRIGGERS} triggers")));
        }
        let next = if exists {
            self.triggers.iter().map(|o| if o.id == t.id { t.clone() } else { o.clone() }).collect()
        } else {
            self.triggers.iter().cloned().chain([t]).collect()
        };
        self.persist(next)
    }

    pub fn remove(&mut self, id: Uuid) -> Result<()> {
        if !self.triggers.iter().any(|t| t.id == id) {
            return Err(CoreError::NotFound(format!("trigger {id}")));
        }
        let next = self.triggers.iter().filter(|t| t.id != id).cloned().collect();
        self.persist(next)
    }

    /// The triggers as a JSON file another computer can import.
    pub fn export_json(&self) -> String {
        serde_json::to_string_pretty(&File { triggers: self.triggers.clone() }).unwrap_or_default()
    }

    /// Add triggers from an exported file: an id or name already here is replaced, so importing
    /// twice adds nothing. All or nothing: one invalid trigger rejects the file. Returns how many.
    pub fn import_json(&mut self, json: &str) -> Result<usize> {
        let incoming = parse(json.as_bytes())?;
        let mut next = self.triggers.clone();
        for t in &incoming {
            next.retain(|o| o.id != t.id && !o.name.eq_ignore_ascii_case(t.name.trim()));
            next.push(t.clone());
        }
        if next.len() > MAX_TRIGGERS {
            return Err(CoreError::Invalid(format!("at most {MAX_TRIGGERS} triggers")));
        }
        self.persist(next)?;
        Ok(incoming.len())
    }

    fn persist(&mut self, triggers: Vec<Trigger>) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&File { triggers }).map_err(|e| CoreError::Corrupt(e.to_string()))?;
        write_atomic(&self.path, &bytes)?;
        self.triggers = serde_json::from_slice::<File>(&bytes).map_err(|e| CoreError::Corrupt(e.to_string()))?.triggers;
        Ok(())
    }
}
