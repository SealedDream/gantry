//! Shell-integration marks and program notifications read from terminal output:
//! OSC 133 (prompt/command marks, FinalTerm), OSC 9 (iTerm2 notification) and
//! OSC 777;notify (rxvt/urxvt notification). Everything here is remote-controlled text, so it is
//! sanitized, length-capped and rate-limited; nothing is ever executed.
//!
//! Also: the `ssh [user@]host[:port]` line a user types in a local terminal (offered as
//! "Save as connection"), and the production-tag check for the red tab accent.

/// Longest OSC payload kept; longer ones are skipped whole.
const MAX_PAYLOAD: usize = 1024;
/// Longest notification title and body shown, in characters.
pub const MAX_NOTIFY_TITLE: usize = 80;
pub const MAX_NOTIFY_BODY: usize = 256;
/// A command must run at least this long before its finish is announced.
pub const COMMAND_NOTICE_MIN_MS: u64 = 10_000;
/// At most one program notification per this many milliseconds per terminal; extras are dropped.
pub const NOTIFY_MIN_INTERVAL_MS: u64 = 2_000;
/// Prompt marks kept per terminal (oldest dropped first).
pub const MAX_PROMPT_MARKS: usize = 2_000;
/// Longest typed line tracked for the ssh offer.
const MAX_TYPED_LINE: usize = 512;

/// One OSC sequence this module cares about, found at `end` (the byte index just past its terminator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OscHit {
    pub end: usize,
    pub kind: OscKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OscKind {
    /// OSC 133;A — a prompt starts here.
    PromptStart,
    /// OSC 133;C — the typed command starts running.
    CommandStart,
    /// OSC 133;D[;exit] — the command finished.
    CommandEnd(Option<i32>),
    /// OSC 9 or OSC 777;notify — a program asks for a desktop notification.
    Notify { title: String, body: String },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum State {
    #[default]
    Ground,
    Esc,
    Number,
    Payload,
    PayloadEsc,
    Skip,
    SkipEsc,
}

/// Streaming scanner over raw output; keeps state across chunks. Allocation-free unless it is
/// inside one of the OSCs it reads (payload buffer, capped).
#[derive(Debug, Default)]
pub struct OscScanner {
    state: State,
    num: u16,
    digits: u8,
    buf: Vec<u8>,
}

fn wanted(num: u16) -> bool {
    matches!(num, 9 | 133 | 777)
}

impl OscScanner {
    /// Feed output bytes; returns the marks and notifications found, in order.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<OscHit> {
        let mut hits = Vec::new();
        for (i, &b) in bytes.iter().enumerate() {
            self.state = match (self.state, b) {
                (State::Ground, 0x1b) => State::Esc,
                (State::Ground, _) => State::Ground,
                (State::Esc, b']') | (State::PayloadEsc, b']') | (State::SkipEsc, b']') => {
                    self.num = 0;
                    self.digits = 0;
                    State::Number
                }
                (State::Esc, 0x1b) => State::Esc,
                (State::Esc, _) => State::Ground,
                (State::Number, b'0'..=b'9') if self.digits < 4 => {
                    self.num = self.num * 10 + u16::from(b - b'0');
                    self.digits += 1;
                    State::Number
                }
                (State::Number, b';') if wanted(self.num) => {
                    self.buf.clear();
                    State::Payload
                }
                (State::Number, 0x07) => State::Ground,
                (State::Number, 0x1b) => State::SkipEsc,
                (State::Number, _) => State::Skip,
                (State::Payload, 0x07) => {
                    self.finish(i + 1, &mut hits);
                    State::Ground
                }
                (State::Payload, 0x1b) => State::PayloadEsc,
                (State::Payload, _) if self.buf.len() < MAX_PAYLOAD => {
                    self.buf.push(b);
                    State::Payload
                }
                (State::Payload, _) => State::Skip,
                (State::PayloadEsc, b'\\') => {
                    self.finish(i + 1, &mut hits);
                    State::Ground
                }
                (State::PayloadEsc, _) => State::Ground,
                (State::Skip, 0x07) => State::Ground,
                (State::Skip, 0x1b) => State::SkipEsc,
                (State::Skip, _) => State::Skip,
                (State::SkipEsc, 0x1b) => State::SkipEsc,
                (State::SkipEsc, b'\\') => State::Ground,
                (State::SkipEsc, _) => State::Skip,
            };
        }
        hits
    }

    fn finish(&mut self, end: usize, hits: &mut Vec<OscHit>) {
        if let Some(kind) = classify(self.num, &self.buf) {
            hits.push(OscHit { end, kind });
        }
        self.buf.clear();
    }
}

fn classify(num: u16, payload: &[u8]) -> Option<OscKind> {
    let text = String::from_utf8_lossy(payload);
    match num {
        133 => {
            let mut parts = text.split(';');
            match parts.next()? {
                "A" => Some(OscKind::PromptStart),
                "C" => Some(OscKind::CommandStart),
                "D" => Some(OscKind::CommandEnd(parts.next().and_then(|c| c.trim().parse().ok()))),
                _ => None,
            }
        }
        9 => {
            // ConEmu uses OSC 9;<n>;... for progress and other commands: not a notification.
            let first = text.split(';').next().unwrap_or("");
            if !first.is_empty() && first.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            notify("", &text)
        }
        777 => {
            let mut parts = text.splitn(3, ';');
            if parts.next()? != "notify" {
                return None;
            }
            let title = parts.next().unwrap_or("");
            notify(title, parts.next().unwrap_or(""))
        }
        _ => None,
    }
}

fn notify(title: &str, body: &str) -> Option<OscKind> {
    let title = sanitize(title, MAX_NOTIFY_TITLE);
    let body = sanitize(body, MAX_NOTIFY_BODY);
    if title.is_empty() && body.is_empty() {
        return None;
    }
    Some(OscKind::Notify { title, body })
}

/// Unicode format (Cf) characters: invisible, so they could disguise remote text (zero-width,
/// bidi controls, word joiner, BOM, Arabic letter mark, tag characters and the rest of Cf).
fn is_format(c: char) -> bool {
    matches!(c,
        '\u{00ad}' | '\u{0600}'..='\u{0605}' | '\u{061c}' | '\u{06dd}' | '\u{070f}' | '\u{0890}'..='\u{0891}'
        | '\u{08e2}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}'
        | '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}' | '\u{1d173}'..='\u{1d17a}' | '\u{e0001}'
        | '\u{e0020}'..='\u{e007f}')
}

/// Remote text made safe to show: control and bidi-override characters removed, whitespace
/// collapsed, at most `max` characters (an ellipsis marks a cut).
pub fn sanitize(text: &str, max: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut space = false;
    for c in text.chars() {
        let c = if c.is_whitespace() { ' ' } else { c };
        if c.is_control() || is_format(c) {
            continue;
        }
        if c == ' ' {
            if space || count == 0 {
                continue;
            }
            space = true;
        } else {
            space = false;
        }
        if count == max {
            out.pop();
            out.push('…');
            return out.trim_end().to_string();
        }
        out.push(c);
        count += 1;
    }
    out.trim_end().to_string()
}

/// A finished command, announced when it ran at least `COMMAND_NOTICE_MIN_MS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandFinished {
    /// The exit code the shell reported, if any (0 is success).
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
}

/// A program's notification request, already sanitized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramNotification {
    pub title: String,
    pub body: String,
}

/// The target of an `ssh` command the user typed in a local terminal. No password is ever part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedSsh {
    pub host: String,
    pub user: Option<String>,
    pub port: Option<u16>,
}

fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && !h.starts_with('-')
        && h.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
}

fn valid_user(u: &str) -> bool {
    !u.is_empty() && u.len() <= 64 && !u.starts_with('-') && u.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Parses `ssh [-p port] [-l user] [user@]host[:port]` exactly; anything else (other options, a
/// remote command, a pipe) is not offered.
pub fn parse_ssh_line(line: &str) -> Option<TypedSsh> {
    let mut words = line.split_whitespace();
    if words.next()? != "ssh" {
        return None;
    }
    let (mut user, mut port, mut target) = (None, None, None);
    while let Some(w) = words.next() {
        match w {
            "-p" => port = Some(words.next()?.parse::<u16>().ok().filter(|p| *p > 0)?),
            "-l" => user = Some(words.next()?.to_string()),
            _ if w.starts_with('-') => return None,
            _ if target.is_none() => target = Some(w),
            _ => return None,
        }
    }
    let mut target = target?;
    if let Some(rest) = target.strip_prefix("ssh://") {
        target = rest.trim_end_matches('/');
    }
    let (u, hostport) = match target.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_string()), h),
        None => (None, target),
    };
    let user = u.or(user);
    let (host, p) = match hostport.strip_prefix('[') {
        Some(v6) => {
            let (h, rest) = v6.split_once(']')?;
            (h, rest.strip_prefix(':'))
        }
        None if hostport.matches(':').count() == 1 => {
            let (h, p) = hostport.split_once(':')?;
            (h, Some(p))
        }
        None => (hostport, None),
    };
    if let Some(p) = p {
        port = Some(p.parse::<u16>().ok().filter(|p| *p > 0)?);
    }
    if !valid_host(host) || user.as_deref().is_some_and(|u| !valid_user(u)) {
        return None;
    }
    Some(TypedSsh { host: host.to_string(), user, port })
}

/// Tracks the line the user is typing in a local terminal, from the keystrokes sent to the shell.
/// Any cursor, history or completion key makes the line unknown until the next Enter, so a
/// recalled or edited line is never guessed.
/// The buffer may hold a password typed at a local prompt, so it is zeroed on every clear and on drop.
#[derive(Debug, Default)]
pub struct TypedLine {
    buf: String,
    unknown: bool,
}

impl TypedLine {
    fn wipe(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.buf);
    }
}

impl Drop for TypedLine {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl TypedLine {
    /// Feed input bytes; returns the ssh target when Enter ends an `ssh` line.
    pub fn feed(&mut self, bytes: &[u8]) -> Option<TypedSsh> {
        let mut found = None;
        let text = String::from_utf8_lossy(bytes);
        for c in text.chars() {
            match c {
                '\r' | '\n' => {
                    if !self.unknown {
                        found = parse_ssh_line(&self.buf).or(found);
                    }
                    self.wipe();
                    self.unknown = false;
                }
                '\u{7f}' | '\u{8}' => {
                    self.buf.pop();
                }
                '\u{15}' | '\u{3}' => {
                    self.wipe();
                    self.unknown = false;
                }
                c if c.is_control() => self.unknown = true,
                c if self.buf.len() < MAX_TYPED_LINE => self.buf.push(c),
                _ => self.unknown = true,
            }
        }
        found
    }
}

/// Whether a connection's tags mark it as production (red tab accent): a tag named
/// `production` or `prod`, any case.
pub fn is_production(tags: &[String]) -> bool {
    tags.iter().any(|t| {
        let t = t.trim();
        t.eq_ignore_ascii_case("production") || t.eq_ignore_ascii_case("prod")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_osc133_marks_with_both_terminators_across_chunks() {
        let mut s = OscScanner::default();
        let hits = s.feed(b"\x1b]133;A\x07$ ls\x1b]133;C\x1b\\out\x1b]133;D;2");
        assert_eq!(hits.iter().map(|h| h.kind.clone()).collect::<Vec<_>>(), vec![OscKind::PromptStart, OscKind::CommandStart]);
        assert_eq!(hits[0].end, 8);
        let hits = s.feed(b"\x07");
        assert_eq!(hits, vec![OscHit { end: 1, kind: OscKind::CommandEnd(Some(2)) }]);
        assert_eq!(s.feed(b"\x1b]133;D\x07")[0].kind, OscKind::CommandEnd(None));
        assert!(s.feed(b"\x1b]133;B\x07\x1b]1337;A\x07\x1b]13;A\x07").is_empty());
    }

    #[test]
    fn notifications_are_sanitized_capped_and_conemu_is_ignored() {
        let mut s = OscScanner::default();
        // ESC inside the payload that is not ST ends it: the sequence is dropped, never shown raw.
        assert!(s.feed(b"\x1b]9;build \x1b[31mdone\x07").is_empty());
        let hits = s.feed(b"\x1b]9;build\tdone\x07\x1b]9;4;1;50\x07");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, OscKind::Notify { title: String::new(), body: "build done".into() });
        let hits = s.feed(b"\x1b]777;notify;Title\xe2\x80\xae;Body text\x07\x1b]777;preexec\x07");
        assert_eq!(hits, vec![OscHit { end: 32, kind: OscKind::Notify { title: "Title".into(), body: "Body text".into() } }]);
        let long = [b"\x1b]9;".as_slice(), &[b'x'; 600], b"\x07"].concat();
        let OscKind::Notify { body, .. } = &s.feed(&long)[0].kind else { panic!("no notify") };
        assert_eq!(body.chars().count(), MAX_NOTIFY_BODY);
        assert!(body.ends_with('…'));
        let huge = [b"\x1b]9;".as_slice(), &vec![b'x'; 5000], b"\x07"].concat();
        assert!(s.feed(&huge).is_empty(), "over-long payload skipped");
        assert!(s.buf.capacity() <= 4 * MAX_PAYLOAD);
        assert!(s.feed(b"\x1b]9;  \x07").is_empty(), "empty notification dropped");
    }

    #[test]
    fn plain_output_finds_nothing_and_allocates_nothing() {
        let mut s = OscScanner::default();
        assert!(s.feed(b"\x1b]0;title\x07\x1b[1mhello\x1b]7;file://h/x\x07").is_empty());
        assert_eq!(s.buf.capacity(), 0);
    }

    #[test]
    fn parses_typed_ssh_lines() {
        let t = |h: &str, u: Option<&str>, p: Option<u16>| Some(TypedSsh { host: h.into(), user: u.map(Into::into), port: p });
        assert_eq!(parse_ssh_line("ssh web1"), t("web1", None, None));
        assert_eq!(parse_ssh_line("  ssh  root@10.0.0.5:2222 "), t("10.0.0.5", Some("root"), Some(2222)));
        assert_eq!(parse_ssh_line("ssh -p 22 -l admin db.example.org"), t("db.example.org", Some("admin"), Some(22)));
        assert_eq!(parse_ssh_line("ssh me@[fe80::1]:23"), t("fe80::1", Some("me"), Some(23)));
        assert_eq!(parse_ssh_line("ssh ssh://u@h:2/"), t("h", Some("u"), Some(2)));
        for bad in ["ssh", "ssh -i key h", "ssh h ls", "ssh h; rm -rf /", "ssh u@-oProxyCommand=x", "ssh h:0", "ssh h:99999", "sshd h", "echo ssh h", "ssh 'a b'"] {
            assert_eq!(parse_ssh_line(bad), None, "{bad}");
        }
    }

    #[test]
    fn typed_line_only_offers_cleanly_typed_lines() {
        let mut l = TypedLine::default();
        assert_eq!(l.feed(b"ssh webx\x7f1"), None);
        assert_eq!(l.feed(b"\r").map(|s| s.host), Some("web1".into()));
        assert_eq!(l.feed(b"\x1b[Assh h\r"), None, "history recall makes the line unknown");
        assert_eq!(l.feed(b"ssh h\r").map(|s| s.host), Some("h".into()), "recovers after Enter");
        assert_eq!(l.feed(b"junk\x15ssh h2\r").map(|s| s.host), Some("h2".into()));
        assert_eq!(l.feed(b"ssh h\t\r"), None, "tab completion unknown");
    }

    #[test]
    fn sanitize_strips_and_caps() {
        assert_eq!(sanitize("  a\x00b\u{202e}c \n\n d ", 10), "abc d");
        assert_eq!(sanitize("abcdef", 3), "ab…");
        assert_eq!(sanitize("abc", 3), "abc");
        assert_eq!(sanitize("p\u{200b}a\u{200d}y\u{2060}p\u{feff}a\u{061c}l\u{e0041}\u{00ad}", 20), "paypal", "Cf characters dropped");
    }

    #[test]
    fn production_tags() {
        assert!(is_production(&["Prod".into()]));
        assert!(is_production(&["x".into(), " PRODUCTION ".into()]));
        assert!(!is_production(&["preprod".into(), "staging".into()]));
    }
}
