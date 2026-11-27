//! Terminal sessions: an embedded `alacritty_terminal` emulator fed by a byte backend
//! (a local PTY or an SSH shell channel). Alacritty is used as a library only; the grid is
//! exposed as plain snapshots that native views draw themselves.
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Boundary, Column, Direction, Line, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionType};
use alacritty_terminal::term::search::{Match, RegexIter, RegexSearch};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Config, Osc52, TermMode};

use crate::termmouse::{MouseAction, MouseButton, MouseMods};
use alacritty_terminal::vte::ansi::{Color, NamedColor, Processor, Rgb};
use alacritty_terminal::Term;
use russh::client;
use russh::{Channel, ChannelMsg};
use tokio::sync::{mpsc, oneshot};

use crate::error::{CoreError, Result};
use crate::session::LinkEnd;

pub const DEFAULT_FG: u32 = 0xd8d8d8;
pub const DEFAULT_BG: u32 = 0x1c1c1e;
pub const SCROLLBACK_LINES: usize = 10_000;
/// Largest scrollback a terminal keeps (`terminal.scrollback`).
pub const MAX_SCROLLBACK_LINES: usize = 100_000;
const READ_BUF: usize = 16 * 1024;
/// Upper bound on a grid side; protects against absurd sizes coming from a UI bug.
const MAX_DIMENSION: u16 = 1000;

#[derive(Clone, Copy)]
struct Size {
    cols: usize,
    rows: usize,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.rows
    }
    fn screen_lines(&self) -> usize {
        self.rows
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

fn checked_size(cols: u16, rows: u16) -> Result<Size> {
    if cols == 0 || rows == 0 || cols > MAX_DIMENSION || rows > MAX_DIMENSION {
        return Err(CoreError::Invalid(format!("terminal size {cols}x{rows} out of range")));
    }
    Ok(Size { cols: cols as usize, rows: rows as usize })
}

/// Collects what the emulator wants to send back to the program (device-attribute replies,
/// cursor-position reports) plus the window title.
#[derive(Clone, Default)]
struct Listener {
    replies: Arc<Mutex<Vec<u8>>>,
    title: Arc<Mutex<Option<String>>>,
    /// The latest OSC 52 copy request from the program (never a paste: reading the clipboard
    /// is disabled in the emulator).
    clipboard: Arc<Mutex<Option<String>>>,
    /// Set by BEL; the frontend takes it once and rings (visual, sound or nothing).
    bell: Arc<AtomicBool>,
}

/// Largest OSC 52 copy that is offered to the user; longer ones are dropped.
pub const MAX_OSC52_BYTES: usize = 64 * 1024;
/// The same limit under the name the Tauri frontend uses.
pub const MAX_OSC52_WRITE: usize = MAX_OSC52_BYTES;

/// What happens when a program asks to copy text to the local clipboard (OSC 52).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardPolicy {
    /// Ignored.
    Off,
    /// Held for the user to allow or deny.
    Ask,
    /// Copied without asking.
    Allow,
}

/// A program's OSC 52 copy request, for the frontend to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardRequest {
    pub text: String,
    /// True when the policy is `Ask`.
    pub ask: bool,
}

impl EventListener for Listener {
    fn send_event(&self, event: Event) {
        match event {
            Event::PtyWrite(text) => {
                if let Ok(mut r) = self.replies.lock() {
                    r.extend_from_slice(text.as_bytes());
                }
            }
            Event::Title(t) => {
                if let Ok(mut s) = self.title.lock() {
                    *s = Some(t);
                }
            }
            Event::ResetTitle => {
                if let Ok(mut s) = self.title.lock() {
                    *s = None;
                }
            }
            Event::Bell => self.bell.store(true, Ordering::SeqCst),
            Event::ClipboardStore(_, text) if text.len() <= MAX_OSC52_BYTES => {
                if let Ok(mut c) = self.clipboard.lock() {
                    *c = Some(text);
                }
            }
            _ => {}
        }
    }
}

/// Longest find-bar query, in characters. The search engine is a size-limited lazy DFA (linear in
/// the text, no backtracking), so this only keeps a pasted wall of text from building a huge automaton.
pub const FIND_QUERY_MAX: usize = 1024;

/// Most matches the find bar counts; past this it shows "1000+".
pub const FIND_COUNT_CAP: u32 = 1000;

/// Find-bar options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FindOptions {
    pub match_case: bool,
    pub regex: bool,
}

/// Where the current match is: `index` 1-based among `total` (both 0 when nothing matched;
/// `index` 0 with `capped` when the match lies past the count cap).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FindResult {
    pub index: u32,
    pub total: u32,
    pub capped: bool,
}

/// The regex for a find-bar query: escaped unless it is a regex, with case forced either way
/// (the search engine alone would be case-sensitive only when the query has capitals).
pub fn find_pattern(query: &str, opts: FindOptions) -> String {
    let body = if opts.regex { query.to_string() } else { regex::escape(query) };
    format!("{}{body}", if opts.match_case { "(?-i)" } else { "(?i)" })
}

struct Emulator {
    term: Term<Listener>,
    parser: Processor,
    listener: Listener,
    /// Current search hit, highlighted in snapshots.
    search_match: Option<Match>,
    /// Working directory announced by the shell (OSC 7), for the file panel's follow folder.
    osc7: crate::filepanel::Osc7Scanner,
    cwd: Option<String>,
    /// Highlight and notification rules (`triggers`); `None` when there are none.
    triggers: Option<Arc<crate::triggers::TriggerSet>>,
    notifier: crate::triggers::Notifier,
    marks: Marks,
    /// Raw output since the terminal opened, kept until `carry_over` replays it under an earlier
    /// terminal's text (Reconnect). `None` once used or once it outgrew `EARLY_OUTPUT_CAP`.
    early: Option<Vec<u8>>,
}

/// Most raw output a new terminal keeps for `carry_over`; a reconnect is carried within a second,
/// long before a shell prompt reaches this.
const EARLY_OUTPUT_CAP: usize = 256 * 1024;

/// Shell-integration state (`shellmarks`): prompt lines for jumping, the running command's start,
/// and what the UI takes on its next poll.
#[derive(Default)]
struct Marks {
    scanner: crate::shellmarks::OscScanner,
    /// Absolute line of each prompt start (OSC 133;A), oldest first. A line's absolute number is
    /// `dropped + history_size + screen_line`, stable while the line stays in scrollback.
    prompts: std::collections::VecDeque<i64>,
    /// Lines that have scrolled off the top of a full history.
    dropped: i64,
    command_start: Option<std::time::Instant>,
    finished: Option<crate::shellmarks::CommandFinished>,
    notification: Option<crate::shellmarks::ProgramNotification>,
    last_notification: Option<std::time::Instant>,
    activity: bool,
    /// The scrollback limit last given to the grid.
    history_limit: usize,
}

/// The line being typed in the local shell and the last `ssh` target found in it.
type TypedState = (crate::shellmarks::TypedLine, Option<crate::shellmarks::TypedSsh>);

/// What happened in a terminal since the UI last asked (`TerminalSession::take_events`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TerminalEvents {
    /// New output arrived (for the unread dot on a background tab).
    pub activity: bool,
    /// A command that ran at least `COMMAND_NOTICE_MIN_MS` finished (needs OSC 133 marks).
    pub finished: Option<crate::shellmarks::CommandFinished>,
    /// A program's OSC 9 / OSC 777 notification, sanitized and rate-limited.
    pub notification: Option<crate::shellmarks::ProgramNotification>,
    /// The user typed `ssh [user@]host[:port]` and Enter in a local shell.
    pub typed_ssh: Option<crate::shellmarks::TypedSsh>,
}

impl Emulator {
    fn new(size: Size) -> Self {
        let listener = Listener::default();
        // Copy only: a remote program may offer text for the clipboard (subject to the policy) but
        // can never read it.
        let config = Config { scrolling_history: SCROLLBACK_LINES, osc52: Osc52::OnlyCopy, ..Default::default() };
        Emulator { term: Term::new(config, &size, listener.clone()), parser: Processor::new(), listener, search_match: None, osc7: Default::default(), cwd: None, triggers: None, notifier: Default::default(), marks: Marks { history_limit: SCROLLBACK_LINES, ..Default::default() }, early: Some(Vec::new()) }
    }

    /// Feed program output; returns bytes the terminal must answer with.
    fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        if let Some(buf) = &mut self.early {
            if buf.len() + bytes.len() <= EARLY_OUTPUT_CAP { buf.extend_from_slice(bytes) } else { self.early = None }
        }
        if !bytes.is_empty() {
            self.marks.activity = true;
        }
        let hits = self.marks.scanner.feed(bytes);
        let mut at = 0;
        for hit in hits {
            self.advance(&bytes[at..hit.end]);
            at = hit.end;
            self.on_mark(hit.kind);
        }
        self.advance(&bytes[at..]);
        if let Some(dir) = self.osc7.feed(bytes) {
            self.cwd = Some(dir);
        }
        if let Some(set) = self.triggers.clone() {
            self.notifier.feed(&set, bytes);
        }
        self.listener.replies.lock().map(|mut r| std::mem::take(&mut *r)).unwrap_or_default()
    }

    /// Run the parser over `bytes`, counting lines that leave a full history so prompt marks keep
    /// pointing at their lines.
    fn advance(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let alt = self.term.mode().contains(TermMode::ALT_SCREEN);
        let full = {
            let g = self.term.grid();
            g.history_size() >= self.history_limit()
        };
        if alt || !full || self.marks.prompts.is_empty() {
            self.parser.advance(&mut self.term, bytes);
            return;
        }
        // The history is full: each line feed at the bottom row drops the oldest line. Count the
        // feeds that did not just move the cursor down. Only runs while marks exist.
        let line0 = self.term.grid().cursor.point.line.0;
        self.parser.advance(&mut self.term, bytes);
        if self.term.mode().contains(TermMode::ALT_SCREEN) {
            return;
        }
        let line1 = self.term.grid().cursor.point.line.0;
        let feeds = bytes.iter().filter(|&&b| b == b'\n').count() as i64;
        let scrolled = (feeds - i64::from(line1 - line0)).max(0);
        self.marks.dropped += scrolled;
        let top = self.marks.dropped;
        while self.marks.prompts.front().is_some_and(|&l| l < top) {
            self.marks.prompts.pop_front();
        }
    }

    fn history_limit(&self) -> usize {
        // alacritty keeps the configured limit private, so it is mirrored here.
        self.marks.history_limit
    }

    fn cursor_abs_line(&self) -> i64 {
        let g = self.term.grid();
        self.marks.dropped + g.history_size() as i64 + i64::from(g.cursor.point.line.0)
    }

    fn on_mark(&mut self, kind: crate::shellmarks::OscKind) {
        use crate::shellmarks::{OscKind, ProgramNotification, CommandFinished, COMMAND_NOTICE_MIN_MS, MAX_PROMPT_MARKS, NOTIFY_MIN_INTERVAL_MS};
        let now = std::time::Instant::now();
        match kind {
            OscKind::PromptStart if !self.term.mode().contains(TermMode::ALT_SCREEN) => {
                let line = self.cursor_abs_line();
                if self.marks.prompts.back() != Some(&line) {
                    self.marks.prompts.push_back(line);
                    if self.marks.prompts.len() > MAX_PROMPT_MARKS {
                        self.marks.prompts.pop_front();
                    }
                }
            }
            OscKind::PromptStart => {}
            OscKind::CommandStart => self.marks.command_start = Some(now),
            OscKind::CommandEnd(exit_code) => {
                if let Some(start) = self.marks.command_start.take() {
                    let duration_ms = now.duration_since(start).as_millis().min(u128::from(u64::MAX)) as u64;
                    if duration_ms >= COMMAND_NOTICE_MIN_MS {
                        self.marks.finished = Some(CommandFinished { exit_code, duration_ms });
                    }
                }
            }
            OscKind::Notify { title, body } => {
                let recent = self.marks.last_notification.is_some_and(|t| now.duration_since(t).as_millis() < u128::from(NOTIFY_MIN_INTERVAL_MS));
                if !recent {
                    self.marks.last_notification = Some(now);
                    self.marks.notification = Some(ProgramNotification { title, body });
                }
            }
        }
    }

    /// Scroll so the previous (`forward == false`) or next prompt mark is the top line.
    fn jump_prompt(&mut self, forward: bool) -> bool {
        if self.term.mode().contains(TermMode::ALT_SCREEN) {
            return false;
        }
        let history = self.term.grid().history_size() as i64;
        let offset = self.term.grid().display_offset() as i64;
        let top = self.marks.dropped + history - offset;
        let first = self.marks.dropped;
        let target = if forward {
            self.marks.prompts.iter().copied().find(|&l| l > top)
        } else {
            self.marks.prompts.iter().rev().copied().find(|&l| l < top && l >= first)
        };
        let Some(line) = target else {
            if forward && offset > 0 {
                self.term.scroll_display(Scroll::Bottom);
                return true;
            }
            return false;
        };
        let new_offset = (self.marks.dropped + history - line).clamp(0, history);
        self.term.scroll_display(Scroll::Delta((new_offset - offset) as i32));
        true
    }
}

/// Where a terminal's bytes go. Implementations must be cheap to call from any thread.
trait Backend: Send + Sync {
    fn write(&self, bytes: &[u8]) -> Result<()>;
    fn resize(&self, size: Size) -> Result<()>;
    fn close(&self);
    /// Show typed input on the screen too (serial ports whose device does not echo).
    fn local_echo(&self) -> bool {
        false
    }
    /// The pty's foreground process, where the backend can tell (local PTYs on macOS/Linux).
    fn foreground(&self) -> Option<ForegroundProcess> {
        None
    }
}

/// The process in the foreground of a local terminal's pty (the close check: a shell sitting at
/// its prompt is idle; anything else it started is busy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundProcess {
    pub pid: u32,
    /// Short process name (`vim`, `top`); `None` when the system would not say.
    pub name: Option<String>,
    /// True when the foreground process is not the terminal's own shell.
    pub busy: bool,
}

#[cfg(target_os = "macos")]
fn process_name(pid: u32) -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is valid for `buf.len()` bytes; proc_name writes at most that many.
    let n = unsafe { libc::proc_name(pid as libc::c_int, buf.as_mut_ptr().cast(), buf.len() as u32) };
    (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn process_name(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// The most recently started child process of `parent` (pid, exe name), from a Toolhelp snapshot.
#[cfg(windows)]
fn newest_child_process(parent: u32) -> Option<(u32, String)> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    // SAFETY: the snapshot handle is checked and closed below; `entry` is sized as the API requires.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        let mut ok = Process32FirstW(snap, &mut entry) != 0;
        while ok {
            if entry.th32ParentProcessID == parent && entry.th32ProcessID != parent {
                let len = entry.szExeFile.iter().position(|c| *c == 0).unwrap_or(entry.szExeFile.len());
                let exe = String::from_utf16_lossy(&entry.szExeFile[..len]);
                // conhost.exe belongs to the console itself, not to a program the user started.
                if !exe.eq_ignore_ascii_case("conhost.exe") {
                    let name = exe.strip_suffix(".exe").or_else(|| exe.strip_suffix(".EXE")).unwrap_or(&exe).to_string();
                    found = Some((entry.th32ProcessID, name));
                }
            }
            ok = Process32NextW(snap, &mut entry) != 0;
        }
        CloseHandle(snap);
        found
    }
}

#[path = "terminal_b7.rs"]
mod b7;
pub use b7::{connect_telnet_stream, PORT_DISCONNECTED};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellStyle {
    pub fg: u32,
    pub bg: u32,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
}

/// How a mouse selection grows: by cell, by word (double click) or by line (triple click).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectKind {
    Cell,
    Word,
    Line,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenCell {
    /// The grapheme drawn in this cell; empty for the trailing half of a wide character.
    pub text: String,
    pub style: CellStyle,
    pub selected: bool,
    /// Part of the current search match.
    pub matched: bool,
}

/// A copy of the visible grid, row-major, with colours already resolved to 0xRRGGBB.
#[derive(Debug, Clone)]
pub struct Screen {
    pub cols: u16,
    pub rows: u16,
    pub cells: Vec<ScreenCell>,
    pub cursor_row: u16,
    pub cursor_col: u16,
    pub cursor_visible: bool,
    pub app_cursor: bool,
    pub title: Option<String>,
    /// The theme background, for painting margins and cells with the default background.
    pub background: u32,
}

impl Screen {
    /// Text of one row with trailing blanks removed (handy for tests and copy).
    pub fn row_text(&self, row: u16) -> String {
        let start = row as usize * self.cols as usize;
        self.cells[start..start + self.cols as usize].iter().map(|c| c.text.as_str()).collect::<String>().trim_end().to_string()
    }

    pub fn text(&self) -> String {
        (0..self.rows).map(|r| self.row_text(r)).collect::<Vec<_>>().join("\n")
    }
}

/// One terminal: emulator state plus the backend that feeds it.
pub struct TerminalSession {
    emu: Arc<Mutex<Emulator>>,
    backend: Arc<dyn Backend>,
    /// The same backend as `backend` for SSH terminals, so a supervisor can move it to a new channel.
    ssh: Option<Arc<SshBackend>>,
    /// The channel backend of a Telnet terminal, so `reattach_telnet` can move it to a new stream.
    telnet: Option<Arc<SshBackend>>,
    /// The backend of a serial terminal, for `reopen_serial` and its status line.
    serial: Option<Arc<b7::SerialBackend>>,
    generation: Arc<Generation>,
    alive: Arc<AtomicBool>,
    theme: Arc<Mutex<TerminalTheme>>,
    clipboard_policy: Arc<Mutex<ClipboardPolicy>>,
    log: Arc<Mutex<Option<crate::sessionlog::LogWriter>>>,
    /// What the app shows about the session log (LOG-CORE-02); the writer thread updates it too.
    log_state: Arc<Mutex<crate::sessionlog::LogState>>,
    /// The line being typed and the last `ssh` target typed; only for local PTY programs.
    typed: Option<Arc<Mutex<TypedState>>>,
}

impl TerminalSession {
    fn new(size: Size, backend: Arc<dyn Backend>) -> Self {
        TerminalSession {
            emu: Arc::new(Mutex::new(Emulator::new(size))),
            backend,
            ssh: None,
            telnet: None,
            serial: None,
            generation: Arc::new(Generation::default()),
            alive: Arc::new(AtomicBool::new(true)),
            theme: Arc::new(Mutex::new(TerminalTheme::default())),
            clipboard_policy: Arc::new(Mutex::new(ClipboardPolicy::Ask)),
            log: Arc::new(Mutex::new(None)),
            log_state: Arc::new(Mutex::new(crate::sessionlog::LogState::Off)),
            typed: None,
        }
    }

    /// Bookkeeping shared with the backend reader: feed output, answer queries, bump the generation.
    fn sink(&self) -> OutputSink {
        OutputSink { emu: self.emu.clone(), backend: self.backend.clone(), generation: self.generation.clone(), alive: self.alive.clone(), log: self.log.clone() }
    }

    /// Start the user's login shell in a local PTY. The shell starts exactly as it would in any
    /// terminal: we do not touch rc files or history, we only set `TERM`/`COLORTERM`.
    pub fn spawn_local(cols: u16, rows: u16) -> Result<TerminalSession> {
        Self::spawn_local_command(portable_pty::CommandBuilder::new_default_prog(), cols, rows)
    }

    /// Start `program args…` in a local PTY (used by tests and later by WSL/local tools).
    pub fn spawn_program(program: &str, args: &[&str], cols: u16, rows: u16) -> Result<TerminalSession> {
        let mut cmd = portable_pty::CommandBuilder::new(program);
        cmd.args(args);
        Self::spawn_local_command(cmd, cols, rows)
    }

    /// Like `spawn_program`, starting in `cwd` (the user's home when `None`). A start folder that
    /// does not exist is an error rather than a silent fallback.
    pub fn spawn_program_in(program: &str, args: &[&str], cwd: Option<&str>, cols: u16, rows: u16) -> Result<TerminalSession> {
        let mut cmd = portable_pty::CommandBuilder::new(program);
        cmd.args(args);
        if let Some(dir) = cwd {
            if !std::path::Path::new(dir).is_dir() {
                return Err(CoreError::Invalid(format!("The start folder {dir} does not exist.")));
            }
        }
        Self::spawn_command_in(cmd, cwd, cols, rows)
    }

    fn spawn_local_command(cmd: portable_pty::CommandBuilder, cols: u16, rows: u16) -> Result<TerminalSession> {
        Self::spawn_command_in(cmd, None, cols, rows)
    }

    fn spawn_command_in(mut cmd: portable_pty::CommandBuilder, cwd: Option<&str>, cols: u16, rows: u16) -> Result<TerminalSession> {
        let size = checked_size(cols, rows)?;
        let pty = portable_pty::native_pty_system()
            .openpty(pty_size(size))
            .map_err(|e| CoreError::Io(std::io::Error::other(format!("cannot open pty: {e}"))))?;
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        // Start in the user's home: $HOME on Unix; %USERPROFILE% on Windows, where HOME is
        // usually unset and, when a POSIX layer (Git Bash, MSYS) sets it, may be a POSIX-style
        // path that CreateProcess cannot use as a working directory.
        let home_vars: [&str; 2] = if cfg!(windows) { ["USERPROFILE", "HOME"] } else { ["HOME", "USERPROFILE"] };
        if let Some(dir) = cwd {
            cmd.cwd(dir);
        } else if let Some(home) = home_vars.iter().find_map(|v| std::env::var_os(v).filter(|h| !h.is_empty() && std::path::Path::new(h).is_dir())) {
            cmd.cwd(home);
        }
        let child = {
            let _spawning = crate::plugin::host::spawn::spawn_guard();
            pty.slave.spawn_command(cmd)
        }.map_err(|e| CoreError::Io(std::io::Error::other(format!("cannot start shell: {e}"))))?;
        drop(pty.slave);
        let reader = pty.master.try_clone_reader().map_err(|e| CoreError::Io(std::io::Error::other(e.to_string())))?;
        let writer = pty.master.take_writer().map_err(|e| CoreError::Io(std::io::Error::other(e.to_string())))?;
        let backend = Arc::new(LocalPty { master: Mutex::new(Some(pty.master)), writer: Mutex::new(writer), child: Arc::new(Mutex::new(child)) });
        #[cfg(windows)]
        watch_child_exit(backend.clone());
        let mut session = TerminalSession::new(size, backend);
        // A local program the user types into: watch for a typed `ssh` line (the UI offers it only in unsaved tabs).
        session.typed = Some(Arc::new(Mutex::new(Default::default())));
        let sink = session.sink();
        std::thread::Builder::new().name("bastion-pty-reader".into()).spawn(move || pump_reader(reader, sink))?;
        Ok(session)
    }

    /// Run a terminal over an SSH shell channel (from `SshSession::open_shell`). The channel
    /// is driven by a task on `runtime`; the session lives until the remote shell exits or
    /// `close` is called.
    pub fn attach_ssh(channel: Channel<client::Msg>, cols: u16, rows: u16, runtime: &tokio::runtime::Handle) -> Result<TerminalSession> {
        let size = checked_size(cols, rows)?;
        let (tx, rx) = mpsc::unbounded_channel();
        let session = TerminalSession::new(size, Arc::new(SshBackend { tx: Mutex::new(tx) }));
        let sink = session.sink();
        runtime.spawn(drive_ssh_channel(channel, rx, sink, None));
        Ok(session)
    }

    /// Like `attach_ssh`, but a dropped connection does not end the terminal. The receiver says
    /// how the channel ended: `Finished` (the shell exited; the terminal has ended) or `Lost`
    /// (the link dropped; the screen and scrollback stay and `reattach_ssh` continues on a new
    /// channel).
    pub fn attach_ssh_supervised(
        channel: Channel<client::Msg>,
        cols: u16,
        rows: u16,
        runtime: &tokio::runtime::Handle,
    ) -> Result<(TerminalSession, oneshot::Receiver<LinkEnd>)> {
        let size = checked_size(cols, rows)?;
        let (tx, rx) = mpsc::unbounded_channel();
        let backend = Arc::new(SshBackend { tx: Mutex::new(tx) });
        let mut session = TerminalSession::new(size, backend.clone());
        session.ssh = Some(backend);
        let (end_tx, end_rx) = oneshot::channel();
        runtime.spawn(drive_ssh_channel(channel, rx, session.sink(), Some(end_tx)));
        Ok((session, end_rx))
    }

    /// Continue a supervised SSH terminal on a new shell channel after its link was lost.
    pub fn reattach_ssh(&self, channel: Channel<client::Msg>, runtime: &tokio::runtime::Handle) -> Result<oneshot::Receiver<LinkEnd>> {
        let backend = self.ssh.as_ref().ok_or_else(|| CoreError::Invalid("not a supervised SSH terminal".into()))?;
        let (tx, rx) = mpsc::unbounded_channel();
        *backend.tx.lock().map_err(|_| CoreError::Invalid("ssh backend poisoned".into()))? = tx;
        let (end_tx, end_rx) = oneshot::channel();
        runtime.spawn(drive_ssh_channel(channel, rx, self.sink(), Some(end_tx)));
        Ok(end_rx)
    }

    /// The process in the foreground of this terminal's local pty, or `None` when that cannot be
    /// told (SSH, Telnet and serial terminals, Windows, or the program has exited).
    pub fn foreground_process(&self) -> Option<ForegroundProcess> {
        if !self.is_alive() {
            return None;
        }
        self.backend.foreground()
    }

    /// Current grid size, for opening a replacement channel of the same size.
    pub fn size(&self) -> (u16, u16) {
        self.emu.lock().map(|e| (e.term.grid().columns() as u16, e.term.grid().screen_lines() as u16)).unwrap_or((80, 24))
    }

    /// Show a status line from Bastion itself (dim, on its own line). It is drawn locally and never
    /// sent to the remote side.
    pub fn notice(&self, text: &str) {
        let clean: String = text.chars().filter(|c| !c.is_control()).collect();
        self.sink().output(format!("\r\n\x1b[2m[{clean}]\x1b[0m\r\n").as_bytes());
    }

    pub fn set_clipboard_policy(&self, policy: ClipboardPolicy) {
        *self.clipboard_policy.lock().unwrap_or_else(|p| p.into_inner()) = policy;
    }

    /// The program's pending OSC 52 copy, taken once; `None` under `Off`.
    pub fn take_clipboard_request(&self) -> Option<ClipboardRequest> {
        let text = self.emu.lock().ok()?.listener.clipboard.lock().ok()?.take()?;
        match *self.clipboard_policy.lock().unwrap_or_else(|p| p.into_inner()) {
            ClipboardPolicy::Off => None,
            ClipboardPolicy::Ask => Some(ClipboardRequest { text, ask: true }),
            ClipboardPolicy::Allow => Some(ClipboardRequest { text, ask: false }),
        }
    }

    /// Whether the program rang the bell since the last call (several rings count as one).
    /// The shell's working directory from its latest OSC 7, if it sends them.
    pub fn cwd(&self) -> Option<String> {
        self.emu.lock().ok()?.cwd.clone()
    }

    /// Unread output, a long command's finish, a program notification and a typed `ssh` target,
    /// each taken once.
    pub fn take_events(&self) -> TerminalEvents {
        let mut ev = TerminalEvents::default();
        if let Ok(mut e) = self.emu.lock() {
            ev.activity = std::mem::take(&mut e.marks.activity);
            ev.finished = e.marks.finished.take();
            ev.notification = e.marks.notification.take();
        }
        if let Some(typed) = &self.typed {
            ev.typed_ssh = typed.lock().ok().and_then(|mut t| t.1.take());
        }
        ev
    }

    /// Scroll to the previous (`forward == false`) or next shell prompt (OSC 133 marks). Returns
    /// false when there is no such prompt.
    pub fn jump_prompt(&self, forward: bool) -> bool {
        let moved = self.emu.lock().map(|mut e| e.jump_prompt(forward)).unwrap_or(false);
        if moved {
            self.generation.bump();
        }
        moved
    }

    pub fn take_bell(&self) -> bool {
        self.emu.lock().map(|e| e.listener.bell.swap(false, Ordering::SeqCst)).unwrap_or(false)
    }

    /// Lines of history kept above the screen (`terminal.scrollback`); shrinking drops the oldest.
    pub fn set_scrollback(&self, lines: usize) {
        self.with_term(|e| {
            let lines = lines.min(MAX_SCROLLBACK_LINES);
            let cut = e.term.grid().history_size().saturating_sub(lines) as i64;
            e.term.grid_mut().update_history(lines);
            e.marks.dropped += cut;
            let top = e.marks.dropped;
            e.marks.prompts.retain(|&l| l >= top);
            e.marks.history_limit = lines;
        });
    }

    /// Reconnect: put `old`'s scrollback and screen text above this terminal's output, so the
    /// earlier session stays readable above the new prompt. Text only (no colours); a dim
    /// `[Reconnected]` line separates the two. Does nothing once this terminal's early output was
    /// already used or outgrew its cap, or when `old` is this terminal.
    pub fn carry_over(&self, old: &TerminalSession) {
        if Arc::ptr_eq(&self.emu, &old.emu) {
            return;
        }
        let text = match old.emu.lock() {
            Ok(o) => {
                let g = o.term.grid();
                let (top, bottom) = (Point::new(g.topmost_line(), Column(0)), Point::new(g.bottommost_line(), g.last_column()));
                o.term.bounds_to_string(top, bottom)
            }
            Err(_) => return,
        };
        let text = text.trim_end();
        self.with_term(|e| {
            let Some(early) = e.early.take() else { return };
            if text.is_empty() {
                return;
            }
            let size = Size { cols: e.term.grid().columns(), rows: e.term.grid().screen_lines() };
            let mut fresh = Emulator::new(size);
            fresh.early = None;
            fresh.triggers = e.triggers.clone();
            fresh.term.grid_mut().update_history(e.marks.history_limit);
            fresh.marks.history_limit = e.marks.history_limit;
            let old_lines: String = text.lines().map(|l| l.chars().filter(|c| !c.is_control()).collect::<String>()).collect::<Vec<_>>().join("\r\n");
            fresh.advance(old_lines.as_bytes());
            fresh.advance(b"\r\n\x1b[2m[Reconnected]\x1b[0m\r\n");
            // Replies to the replayed output were already sent when it first arrived.
            let _ = fresh.feed(&early);
            fresh.marks.activity = false;
            *e = fresh;
        });
    }

    /// Clear Scrollback (⌘K): history goes, the screen and the program's state stay.
    pub fn clear_scrollback(&self) {
        self.with_term(|e| {
            e.term.grid_mut().clear_history();
            e.search_match = None;
            e.marks.prompts.clear();
        });
    }

    /// The http or https URL under a viewport cell, if any (⌘-click opens it).
    pub fn url_at(&self, row: u16, col: u16) -> Option<String> {
        let screen = self.screen();
        if row >= screen.rows || col >= screen.cols {
            return None;
        }
        let start = row as usize * screen.cols as usize;
        let cells: Vec<&str> = screen.cells[start..start + screen.cols as usize].iter().map(|c| c.text.as_str()).collect();
        url_at_column(&cells, col as usize)
    }

    /// Opt-in session log: from now on, everything the program prints is appended to a new
    /// owner-only file at `path` (refused if it exists), rotated at 10 MB with 5 kept, and with
    /// answers echoed after password/passphrase/token prompts redacted. Keystrokes are not logged.
    /// Manual logging of unsaved tabs; saved connections use [`Self::start_log_plan`].
    pub fn start_log(&self, path: &std::path::Path, header: &str) -> Result<()> {
        self.start_log_with(path, header, crate::sessionlog::LogOptions::default())
    }

    /// [`Self::start_log`] with explicit rotation, ANSI and redaction options.
    pub fn start_log_with(&self, path: &std::path::Path, header: &str, opts: crate::sessionlog::LogOptions) -> Result<()> {
        let log = crate::sessionlog::SessionLog::create(path, header, opts)?;
        self.install_log(log)
    }

    /// Start the session log a plan describes (`sessionlog::session_log_plan`); returns the file
    /// actually used (`-2` … added when another session took the name in the same second).
    pub fn start_log_plan(&self, plan: &crate::sessionlog::LogPlan) -> Result<std::path::PathBuf> {
        let log = crate::sessionlog::SessionLog::create_planned(plan)?;
        let path = log.path().to_path_buf();
        self.install_log(log)?;
        Ok(path)
    }

    fn install_log(&self, log: crate::sessionlog::SessionLog) -> Result<()> {
        let old = self.log.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(old) = old {
            let _ = old.finish(crate::sessionlog::LogEnd::now("a new log was started"));
        }
        let writer = crate::sessionlog::LogWriter::spawn(log, self.log_state.clone())?;
        *self.log.lock().unwrap_or_else(|p| p.into_inner()) = Some(writer);
        Ok(())
    }

    /// Stop logging: writes what is queued and a footer with end reason `unknown`.
    pub fn stop_log(&self) {
        let _ = self.finish_log("");
    }

    /// Stop logging with the footer's end reason (empty: `unknown`). Returns the file's SHA-256
    /// for the session record, `None` when no log was running.
    pub fn finish_log(&self, reason: &str) -> Result<Option<String>> {
        let writer = self.log.lock().unwrap_or_else(|p| p.into_inner()).take();
        match writer {
            Some(w) => w.finish(crate::sessionlog::LogEnd::now(reason)).map(Some),
            None => {
                let mut st = self.log_state.lock().unwrap_or_else(|p| p.into_inner());
                if matches!(*st, crate::sessionlog::LogState::Active { .. }) {
                    *st = crate::sessionlog::LogState::Off;
                }
                Ok(None)
            }
        }
    }

    /// `Active`, `Stopped` (with the reason, until the next start) or `Off`.
    pub fn log_state(&self) -> crate::sessionlog::LogState {
        self.log_state.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn is_logging(&self) -> bool {
        matches!(self.log_state(), crate::sessionlog::LogState::Active { .. })
    }

    /// Mark the terminal ended (a supervised link that will not come back).
    pub fn end(&self) {
        self.sink().ended();
    }

    /// Send keyboard input (already encoded as bytes by the UI) to the program.
    pub fn write(&self, bytes: &[u8]) -> Result<()> {
        self.scroll_to_bottom();
        if let Some(typed) = &self.typed {
            if let Ok(mut t) = typed.lock() {
                if let Some(found) = t.0.feed(bytes) {
                    t.1 = Some(found);
                }
            }
        }
        if self.backend.local_echo() {
            let echoed: Vec<u8> = bytes.iter().flat_map(|&b| if b == b'\r' { vec![b'\r', b'\n'] } else { vec![b] }).collect();
            self.sink().output(&echoed);
        }
        self.backend.write(bytes)
    }

    /// Paste text, wrapped in bracketed-paste markers when the program asked for them so a
    /// pasted newline is never executed as a keystroke by an aware shell.
    pub fn paste(&self, text: &str) -> Result<()> {
        let bracketed = self.emu.lock().map(|e| e.term.mode().contains(TermMode::BRACKETED_PASTE)).unwrap_or(false);
        self.write(paste_bytes(text, bracketed).as_bytes())
    }

    /// Whether the program enabled bracketed paste (DECSET 2004). When it has not, a pasted newline
    /// runs as a keystroke, so UIs should confirm multi-line pastes.
    pub fn bracketed_paste(&self) -> bool {
        self.emu.lock().map(|e| e.term.mode().contains(TermMode::BRACKETED_PASTE)).unwrap_or(false)
    }

    /// Whether the program enabled mouse reporting (DECSET 1000/1002/1003).
    pub fn mouse_reporting(&self) -> bool {
        self.emu.lock().map(|e| crate::termmouse::reporting(*e.term.mode())).unwrap_or(false)
    }

    /// Send a mouse event to the program when its mouse mode wants it; returns whether it was sent.
    pub fn mouse(&self, button: MouseButton, action: MouseAction, row: u16, col: u16, mods: MouseMods) -> Result<bool> {
        let mode = match self.emu.lock() {
            Ok(e) => *e.term.mode(),
            Err(_) => return Ok(false),
        };
        match crate::termmouse::encode(mode, button, action, row, col, mods) {
            Some(bytes) => self.backend.write(&bytes).map(|_| true),
            None => Ok(false),
        }
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let size = checked_size(cols, rows)?;
        if let Ok(mut e) = self.emu.lock() {
            // A width change rewraps lines, so prompt marks would point at the wrong lines.
            if usize::from(cols) != e.term.grid().columns() {
                e.marks.prompts.clear();
            }
            e.term.resize(size);
        }
        self.generation.bump();
        self.backend.resize(size)
    }

    /// Scroll the viewport through scrollback; positive values go up.
    pub fn scroll(&self, lines: i32) {
        if let Ok(mut e) = self.emu.lock() {
            e.term.scroll_display(Scroll::Delta(lines));
        }
        self.generation.bump();
    }

    fn scroll_to_bottom(&self) {
        if let Ok(mut e) = self.emu.lock() {
            if e.term.grid().display_offset() != 0 {
                e.term.scroll_display(Scroll::Bottom);
                self.generation.bump();
            }
        }
    }

    /// Start a selection at a visible cell (`row`/`col` in viewport coordinates).
    pub fn select_start(&self, row: u16, col: u16, kind: SelectKind) {
        self.with_term(|e| {
            let p = viewport_point(&e.term, row, col);
            let ty = match kind {
                SelectKind::Cell => SelectionType::Simple,
                SelectKind::Word => SelectionType::Semantic,
                SelectKind::Line => SelectionType::Lines,
            };
            e.term.selection = Some(Selection::new(ty, p, Side::Left));
        });
    }

    /// Extend the selection to a visible cell (mouse drag).
    pub fn select_extend(&self, row: u16, col: u16) {
        self.with_term(|e| {
            let p = viewport_point(&e.term, row, col);
            if let Some(sel) = e.term.selection.as_mut() {
                sel.update(p, Side::Right);
            }
        });
    }

    /// Select All: the whole scrollback and screen.
    pub fn select_all(&self) {
        self.with_term(|e| {
            let grid = e.term.grid();
            let (top, bottom) = (Point::new(grid.topmost_line(), Column(0)), Point::new(grid.bottommost_line(), grid.last_column()));
            let mut sel = Selection::new(SelectionType::Simple, top, Side::Left);
            sel.update(bottom, Side::Right);
            e.term.selection = Some(sel);
        });
    }

    pub fn clear_selection(&self) {
        self.with_term(|e| e.term.selection = None);
    }

    /// Selected text, with soft-wrapped lines joined and trailing blanks trimmed by the library.
    pub fn selection_text(&self) -> Option<String> {
        self.emu.lock().ok()?.term.selection_to_string().filter(|s| !s.is_empty())
    }

    /// Find the next (`forward`) or previous match of a regex in screen + scrollback, scroll it
    /// into view and highlight it. Repeated calls step from the last match. Returns whether
    /// anything matched; an invalid pattern is an error.
    pub fn search(&self, pattern: &str, forward: bool) -> Result<bool> {
        let mut regex = RegexSearch::new(pattern).map_err(|e| CoreError::Invalid(format!("search pattern: {e}")))?;
        let found = self.with_term(|e| {
            let term = &e.term;
            let dir = if forward { Direction::Right } else { Direction::Left };
            let origin = match (&e.search_match, forward) {
                (Some(m), true) => m.end().add(term, Boundary::None, 1),
                (Some(m), false) => m.start().sub(term, Boundary::None, 1),
                (None, true) => Point::new(term.grid().topmost_line(), Column(0)),
                (None, false) => Point::new(term.grid().bottommost_line(), term.grid().last_column()),
            };
            let m = term.search_next(&mut regex, origin, dir, Side::Left, None);
            if let Some(m) = &m {
                e.term.scroll_to_point(*m.start());
            }
            e.search_match = m;
            e.search_match.is_some()
        });
        Ok(found)
    }

    pub fn clear_search(&self) {
        self.with_term(|e| e.search_match = None);
    }

    /// Find-bar search: like [`Self::search`], with the find bar's options, and reports where the
    /// match is among all matches in screen + scrollback. Plain text unless `opts.regex`; case
    /// is ignored unless `opts.match_case`. An empty query clears the search.
    pub fn find(&self, query: &str, forward: bool, opts: FindOptions) -> Result<FindResult> {
        if query.is_empty() {
            self.clear_search();
            return Ok(FindResult::default());
        }
        if query.chars().count() > FIND_QUERY_MAX {
            return Err(CoreError::Invalid(format!("search text is longer than {FIND_QUERY_MAX} characters")));
        }
        let pattern = find_pattern(query, opts);
        if !self.search(&pattern, forward)? {
            return Ok(FindResult::default());
        }
        let mut regex = RegexSearch::new(&pattern).map_err(|e| CoreError::Invalid(format!("search pattern: {e}")))?;
        Ok(self.with_term(|e| {
            let Some(current) = e.search_match.as_ref().map(|m| *m.start()) else { return FindResult::default() };
            let term = &e.term;
            let start = Point::new(term.grid().topmost_line(), Column(0));
            let end = Point::new(term.grid().bottommost_line(), term.grid().last_column());
            let mut result = FindResult { index: 0, total: 0, capped: false };
            for m in RegexIter::new(start, end, Direction::Right, term, &mut regex) {
                if result.total == FIND_COUNT_CAP {
                    result.capped = true;
                    break;
                }
                result.total += 1;
                if *m.start() == current {
                    result.index = result.total;
                }
            }
            result
        }))
    }

    /// Use these triggers (an empty or `None` set turns them off). Highlights apply to the
    /// visible rows of each `screen()`; notifications to output that arrives from now on.
    pub fn set_triggers(&self, set: Option<Arc<crate::triggers::TriggerSet>>) {
        self.with_term(|e| {
            e.triggers = set.filter(|s| !s.is_empty());
            e.notifier.reset();
        });
    }

    /// Notifications raised since the last call, oldest first.
    pub fn take_trigger_events(&self) -> Vec<crate::triggers::TriggerEvent> {
        self.emu.lock().map(|mut e| e.notifier.take()).unwrap_or_default()
    }

    /// Mutate the emulator and mark the screen dirty.
    fn with_term<T>(&self, f: impl FnOnce(&mut Emulator) -> T) -> T {
        let mut e = self.emu.lock().unwrap_or_else(|p| p.into_inner());
        let out = f(&mut e);
        self.generation.bump();
        out
    }

    /// Increases whenever the screen may have changed; UIs redraw when it moves.
    pub fn theme(&self) -> TerminalTheme {
        *self.theme.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Change the colours used for default, named and the first 16 indexed colours. Colours a
    /// program set explicitly (OSC 4/10/11, truecolour) are left alone.
    pub fn set_theme(&self, theme: TerminalTheme) {
        *self.theme.lock().unwrap_or_else(|p| p.into_inner()) = theme;
        self.generation.bump();
    }

    pub fn generation(&self) -> u64 {
        self.generation.get()
    }

    /// Block until the generation differs from `after` or `timeout` passes; returns the current
    /// generation. Lets a UI wake on output at once instead of polling on a frame timer.
    pub fn wait_change(&self, after: u64, timeout: std::time::Duration) -> u64 {
        self.generation.wait_change(after, timeout)
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    pub fn close(&self) {
        self.backend.close();
        self.alive.store(false, Ordering::SeqCst);
        self.generation.bump();
    }

    pub fn screen(&self) -> Screen {
        let e = self.emu.lock().unwrap_or_else(|p| p.into_inner());
        let term = &e.term;
        let grid = term.grid();
        let (cols, rows) = (grid.columns(), grid.screen_lines());
        let offset = grid.display_offset() as i32;
        let colors = term.colors();
        let theme = self.theme();
        let resolve = |c: Color| -> u32 {
            match c {
                Color::Spec(rgb) => rgb_u32(rgb),
                Color::Indexed(i) => colors[i as usize].map(rgb_u32).unwrap_or_else(|| palette(&theme, i as usize)),
                Color::Named(n) => colors[n].map(rgb_u32).unwrap_or_else(|| named(&theme, n)),
            }
        };
        let selection = term.selection.as_ref().and_then(|s| s.to_range(term));
        let mut cells = Vec::with_capacity(cols * rows);
        for r in 0..rows {
            let row = &grid[Line(r as i32 - offset)];
            for c in 0..cols {
                let cell = &row[Column(c)];
                let (mut fg, mut bg) = (resolve(cell.fg), resolve(cell.bg));
                if cell.flags.contains(Flags::INVERSE) {
                    std::mem::swap(&mut fg, &mut bg);
                }
                let spacer = cell.flags.intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER);
                let mut text = String::new();
                if !spacer && !cell.flags.contains(Flags::HIDDEN) {
                    text.push(cell.c);
                    if let Some(zw) = cell.zerowidth() {
                        text.extend(zw);
                    }
                }
                let point = Point::new(Line(r as i32 - offset), Column(c));
                cells.push(ScreenCell {
                    selected: selection.as_ref().is_some_and(|s| s.contains(point)),
                    matched: e.search_match.as_ref().is_some_and(|m| m.contains(&point)),
                    text,
                    style: CellStyle {
                        fg,
                        bg,
                        bold: cell.flags.contains(Flags::BOLD),
                        italic: cell.flags.contains(Flags::ITALIC),
                        underline: cell.flags.intersects(Flags::ALL_UNDERLINES),
                    },
                });
            }
        }
        if let Some(set) = e.triggers.as_ref().filter(|s| s.has_highlights()) {
            highlight_rows(set, &mut cells, cols);
        }
        let cursor = term.renderable_content().cursor;
        let cursor_line = cursor.point.line.0 + offset;
        let mode = term.mode();
        Screen {
            cols: cols as u16,
            rows: rows as u16,
            cells,
            cursor_row: cursor_line.clamp(0, rows as i32 - 1) as u16,
            cursor_col: cursor.point.column.0.min(cols - 1) as u16,
            cursor_visible: mode.contains(TermMode::SHOW_CURSOR) && cursor_line >= 0 && cursor_line < rows as i32,
            app_cursor: mode.contains(TermMode::APP_CURSOR),
            title: e.listener.title.lock().ok().and_then(|t| t.clone()),
            background: theme.background,
        }
    }
}

/// Apply trigger highlights to the visible rows only, so the cost never depends on scrollback.
fn highlight_rows(set: &crate::triggers::TriggerSet, cells: &mut [ScreenCell], cols: usize) {
    for row in cells.chunks_mut(cols.max(1)) {
        let mut text = String::new();
        // Byte range of each cell in `text`; a wide character's trailing half (no text of its
        // own) takes the range of the cell before it.
        let mut ranges = Vec::with_capacity(row.len());
        for c in row.iter() {
            let range = if c.text.is_empty() {
                ranges.last().copied().unwrap_or((text.len(), text.len()))
            } else {
                let at = text.len();
                text.push_str(&c.text);
                (at, text.len())
            };
            ranges.push(range);
        }
        for span in set.spans(&text) {
            for (cell, &(start, end)) in row.iter_mut().zip(&ranges) {
                if start < span.end && end > span.start {
                    if let Some(fg) = span.highlight.fg {
                        cell.style.fg = fg;
                    }
                    if let Some(bg) = span.highlight.bg {
                        cell.style.bg = bg;
                    }
                    cell.style.bold |= span.highlight.bold;
                }
            }
        }
    }
}

/// Characters that end a URL in terminal text (besides whitespace and control characters).
const URL_STOP: &[char] = &['<', '>', '"', '\'', '`', '|', '{', '}', '^', '\\'];
/// Trailing punctuation that belongs to the sentence, not the URL.
const URL_TRAILING: &[char] = &['.', ',', ';', ':', '!', '?', ')', ']'];

/// The http(s) URL covering column `col` of a row given as one text per cell (wide-character
/// spacers are empty). Other schemes are never returned, so a click cannot run `file:` or app links.
pub fn url_at_column(cells: &[&str], col: usize) -> Option<String> {
    // Text with the cell each character came from.
    let mut chars: Vec<(char, usize)> = Vec::new();
    for (i, t) in cells.iter().enumerate() {
        chars.extend(t.chars().map(|c| (c, i)));
    }
    let text: String = chars.iter().map(|(c, _)| *c).collect();
    let idx: Vec<usize> = text.char_indices().map(|(b, _)| b).collect();
    let mut from = 0;
    while let Some(pos) = text[from..].find("http").map(|p| p + from) {
        let rest = &text[pos..];
        let scheme = if rest.starts_with("https://") { 8 } else if rest.starts_with("http://") { 7 } else { 0 };
        if scheme == 0 {
            from = pos + 4;
            continue;
        }
        let end = rest.find(|c: char| c.is_whitespace() || c.is_control() || URL_STOP.contains(&c)).map_or(text.len(), |e| pos + e);
        let mut url = &text[pos..end];
        // A closing bracket stays when the URL opened one (Wikipedia-style links).
        while let Some(last) = url.chars().last().filter(|c| URL_TRAILING.contains(c)) {
            let keep = (last == ')' && url.matches('(').count() >= url.matches(')').count())
                || (last == ']' && url.matches('[').count() >= url.matches(']').count());
            if keep {
                break;
            }
            url = &url[..url.len() - last.len_utf8()];
        }
        let first = idx.iter().position(|b| *b == pos)?;
        let count = url.chars().count();
        if url.len() > scheme && first + count > 0 {
            let (lo, hi) = (chars[first].1, chars[first + count - 1].1);
            if (lo..=hi).contains(&col) {
                return Some(url.to_string());
            }
        }
        from = end.max(pos + 4);
    }
    None
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        self.backend.close();
    }
}

/// The screen's change counter, with a condition variable so a waiter wakes on each bump.
#[derive(Default)]
struct Generation {
    value: AtomicU64,
    lock: Mutex<()>,
    changed: Condvar,
}

impl Generation {
    fn get(&self) -> u64 {
        self.value.load(Ordering::SeqCst)
    }

    fn bump(&self) {
        // Bump under the lock so a waiter between its check and its wait cannot miss it.
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        self.value.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_all();
    }

    fn wait_change(&self, after: u64, timeout: std::time::Duration) -> u64 {
        let deadline = std::time::Instant::now() + timeout;
        let mut g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            let now = self.get();
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if now != after || left.is_zero() {
                return now;
            }
            g = self.changed.wait_timeout(g, left).unwrap_or_else(|p| p.into_inner()).0;
        }
    }
}

#[derive(Clone)]
struct OutputSink {
    emu: Arc<Mutex<Emulator>>,
    backend: Arc<dyn Backend>,
    generation: Arc<Generation>,
    alive: Arc<AtomicBool>,
    log: Arc<Mutex<Option<crate::sessionlog::LogWriter>>>,
}

impl OutputSink {
    fn output(&self, bytes: &[u8]) {
        if let Ok(mut log) = self.log.lock() {
            // Only queues the bytes (the writer thread does the disk I/O). A failed or overflowing
            // log stops logging, not the session; the writer has set `LogState::Stopped`.
            if log.as_ref().is_some_and(|l| !l.write(bytes)) {
                if let Some(w) = log.take() {
                    w.abandon();
                }
            }
        }
        let replies = match self.emu.lock() {
            Ok(mut e) => e.feed(bytes),
            Err(_) => return,
        };
        if !replies.is_empty() {
            let _ = self.backend.write(&replies);
        }
        self.generation.bump();
    }

    fn ended(&self) {
        self.alive.store(false, Ordering::SeqCst);
        self.generation.bump();
    }
}

fn viewport_point(term: &Term<Listener>, row: u16, col: u16) -> Point {
    let grid = term.grid();
    let row = (row as usize).min(grid.screen_lines() - 1) as i32;
    Point::new(Line(row - grid.display_offset() as i32), Column((col as usize).min(grid.columns() - 1)))
}

fn pump_reader(mut reader: Box<dyn Read + Send>, sink: OutputSink) {
    let mut buf = vec![0u8; READ_BUF];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => sink.output(&buf[..n]),
        }
    }
    sink.ended();
}

fn pty_size(size: Size) -> portable_pty::PtySize {
    portable_pty::PtySize { rows: size.rows as u16, cols: size.cols as u16, pixel_width: 0, pixel_height: 0 }
}

struct LocalPty {
    /// `None` once the pseudoconsole has been closed (Windows, after the child exits).
    master: Mutex<Option<Box<dyn portable_pty::MasterPty + Send>>>,
    writer: Mutex<Box<dyn Write + Send>>,
    /// Shared so `close` can reap it on a background thread (portable-pty's unix `kill` sends
    /// SIGHUP and then polls in 50 ms sleeps, ~200 ms for a login shell).
    child: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>,
}

/// ConPTY keeps its output pipe open after the child exits until the pseudoconsole itself is
/// closed, so the reader never sees EOF and the session would stay "alive" (and leak its
/// reader thread) forever. Once the child is gone, give ConPTY a moment to flush its last
/// output, then drop the master: that closes the pseudoconsole and ends the reader.
#[cfg(windows)]
fn watch_child_exit(backend: Arc<LocalPty>) {
    let spawned = std::thread::Builder::new().name("bastion-pty-exit".into()).spawn(move || {
        loop {
            let exited = backend.child.lock().map(|mut c| !matches!(c.try_wait(), Ok(None))).unwrap_or(true);
            if exited {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        if let Ok(mut master) = backend.master.lock() {
            master.take();
        }
    });
    drop(spawned);
}

impl Backend for LocalPty {
    fn write(&self, bytes: &[u8]) -> Result<()> {
        let mut w = self.writer.lock().map_err(|_| CoreError::Invalid("pty writer poisoned".into()))?;
        w.write_all(bytes)?;
        w.flush()?;
        Ok(())
    }

    fn resize(&self, size: Size) -> Result<()> {
        let m = self.master.lock().map_err(|_| CoreError::Invalid("pty poisoned".into()))?;
        match m.as_ref() {
            Some(master) => master.resize(pty_size(size)).map_err(|e| CoreError::Io(std::io::Error::other(e.to_string()))),
            // The program has exited and the pseudoconsole is closed; nothing to resize.
            None => Ok(()),
        }
    }

    #[cfg(unix)]
    fn foreground(&self) -> Option<ForegroundProcess> {
        let shell = self.child.lock().ok()?.process_id()?;
        let group = self.master.lock().ok()?.as_ref()?.process_group_leader()?;
        let pid = u32::try_from(group).ok().filter(|p| *p > 0)?;
        Some(ForegroundProcess { pid, name: process_name(pid), busy: pid != shell })
    }

    /// ConPTY has no foreground process group: the shell counts as busy while it has a child
    /// process (the program it started); the newest child is named.
    #[cfg(windows)]
    fn foreground(&self) -> Option<ForegroundProcess> {
        let shell = self.child.lock().ok()?.process_id()?;
        Some(match newest_child_process(shell) {
            Some((pid, name)) => ForegroundProcess { pid, name: Some(name), busy: true },
            None => ForegroundProcess { pid: shell, name: None, busy: false },
        })
    }

    fn close(&self) {
        // Only our own child is signalled; nothing else on the system is touched. The kill's grace
        // period and the reap run off the caller's thread (the UI thread in every app), so closing
        // a tab no longer blocks for ~200 ms.
        let child = self.child.clone();
        let reap = move || {
            if let Ok(mut c) = child.lock() {
                if matches!(c.try_wait(), Ok(None)) {
                    let _ = c.kill();
                }
                let _ = c.wait();
            }
        };
        if std::thread::Builder::new().name("bastion-pty-close".into()).spawn(reap.clone()).is_err() {
            reap();
        }
    }
}

enum SshCommand {
    Input(Vec<u8>),
    Resize(Size),
    Close,
}

struct SshBackend {
    /// Replaced when a supervised terminal moves to a new channel.
    tx: Mutex<mpsc::UnboundedSender<SshCommand>>,
}

impl SshBackend {
    fn send(&self, cmd: SshCommand) -> Result<()> {
        let tx = self.tx.lock().map_err(|_| CoreError::Ssh("shell channel poisoned".into()))?;
        tx.send(cmd).map_err(|_| CoreError::Ssh("shell channel closed".into()))
    }
}

impl Backend for SshBackend {
    fn write(&self, bytes: &[u8]) -> Result<()> {
        self.send(SshCommand::Input(bytes.to_vec()))
    }
    fn resize(&self, size: Size) -> Result<()> {
        self.send(SshCommand::Resize(size))
    }
    fn close(&self) {
        let _ = self.send(SshCommand::Close);
    }
}

/// Pump one shell channel. Without `end` any ending ends the terminal. With `end` (supervised),
/// only a deliberate ending (shell exit, close) ends it; a vanished channel reports `Lost`.
async fn drive_ssh_channel(
    mut channel: Channel<client::Msg>,
    mut rx: mpsc::UnboundedReceiver<SshCommand>,
    sink: OutputSink,
    end: Option<oneshot::Sender<LinkEnd>>,
) {
    let outcome = loop {
        tokio::select! {
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => sink.output(&data),
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) => break LinkEnd::Finished,
                None => break LinkEnd::Lost("connection lost".into()),
                Some(_) => {}
            },
            cmd = rx.recv() => match cmd {
                Some(SshCommand::Input(bytes)) => {
                    if channel.data(&bytes[..]).await.is_err() { break LinkEnd::Lost("connection lost while sending".into()); }
                }
                Some(SshCommand::Resize(s)) => {
                    let _ = channel.window_change(s.cols as u32, s.rows as u32, 0, 0).await;
                }
                Some(SshCommand::Close) => {
                    let _ = channel.close().await;
                    break LinkEnd::Finished;
                }
                // The backend moved to a new channel; this one is abandoned.
                None => break LinkEnd::Lost("replaced".into()),
            },
        }
    };
    match end {
        Some(end) => {
            if outcome == LinkEnd::Finished {
                sink.ended();
            }
            let _ = end.send(outcome);
        }
        None => sink.ended(),
    }
}

fn rgb_u32(c: Rgb) -> u32 {
    (c.r as u32) << 16 | (c.g as u32) << 8 | c.b as u32
}

/// Terminal colours: default foreground/background, selection and the 16 ANSI colours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalTheme {
    pub foreground: u32,
    pub background: u32,
    pub ansi: [u32; 16],
}

impl Default for TerminalTheme {
    fn default() -> Self {
        Self::BASTION_DARK
    }
}

impl TerminalTheme {
    pub const BASTION_DARK: TerminalTheme = TerminalTheme {
        foreground: DEFAULT_FG,
        background: DEFAULT_BG,
        ansi: [
            0x1c1c1e, 0xe0605c, 0x7fbf6a, 0xd9b45a, 0x5f9ae0, 0xb87fd9, 0x56b6c2, 0xc8c8c8, //
            0x6c6c70, 0xff7b72, 0x9ad97f, 0xf0cc74, 0x82b4ff, 0xd2a0f0, 0x76d4e0, 0xffffff,
        ],
    };
    pub const BASTION_LIGHT: TerminalTheme = TerminalTheme {
        foreground: 0x1f2328,
        background: 0xfafafa,
        ansi: [
            0x24292f, 0xcf222e, 0x116329, 0x7d4e00, 0x0550ae, 0x8250df, 0x1b7c83, 0x6e7781, //
            0x57606a, 0xa40e26, 0x1a7f37, 0x633c01, 0x218bff, 0xa475f9, 0x3192aa, 0x8c959f,
        ],
    };
    pub const SOLARIZED_DARK: TerminalTheme = TerminalTheme {
        foreground: 0x839496,
        background: 0x002b36,
        ansi: [
            0x073642, 0xdc322f, 0x859900, 0xb58900, 0x268bd2, 0xd33682, 0x2aa198, 0xeee8d5, //
            0x002b36, 0xcb4b16, 0x586e75, 0x657b83, 0x839496, 0x6c71c4, 0x93a1a1, 0xfdf6e3,
        ],
    };
    pub const HIGH_CONTRAST: TerminalTheme = TerminalTheme {
        foreground: 0xffffff,
        background: 0x000000,
        ansi: [
            0x000000, 0xff5555, 0x55ff55, 0xffff55, 0x5599ff, 0xff55ff, 0x55ffff, 0xe5e5e5, //
            0x7f7f7f, 0xff8080, 0x80ff80, 0xffff80, 0x80b3ff, 0xff80ff, 0x80ffff, 0xffffff,
        ],
    };

    /// A bundled theme by id (`termthemes::BUNDLED`); user themes resolve through `termthemes::ThemeStore`.
    pub fn preset(id: &str) -> Option<TerminalTheme> {
        crate::termthemes::bundled(id).map(|b| b.theme)
    }
}

/// xterm 256-colour palette: 16 theme colours, a 6×6×6 cube, then a 24-step grey ramp.
fn palette(theme: &TerminalTheme, i: usize) -> u32 {
    match i {
        0..=15 => theme.ansi[i],
        16..=231 => {
            let i = i - 16;
            let level = |v: usize| if v == 0 { 0 } else { 55 + v as u32 * 40 };
            level(i / 36) << 16 | level((i / 6) % 6) << 8 | level(i % 6)
        }
        232..=255 => {
            let v = 8 + (i as u32 - 232) * 10;
            v << 16 | v << 8 | v
        }
        _ => theme.foreground,
    }
}

fn named(theme: &TerminalTheme, n: NamedColor) -> u32 {
    let i = n as usize;
    match n {
        NamedColor::Background => theme.background,
        NamedColor::Foreground | NamedColor::BrightForeground | NamedColor::Cursor => theme.foreground,
        NamedColor::DimForeground => theme.ansi[7],
        _ if i < 16 => theme.ansi[i],
        // Dim variants follow the eight base colours.
        _ => theme.ansi[(i - NamedColor::DimBlack as usize) % 8],
    }
}

/// Whether a pasted character survives sanitizing: tab, newline and carriage return are the only
/// control characters kept. ESC, every other C0 control, DEL and the C1 range (which includes the
/// 8-bit CSI U+009B) are dropped, so no escape sequence — a bracketed-paste end marker included —
/// can reach the program from pasted text, however the fragments are nested (audit TE-01).
fn paste_char_allowed(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || !(c.is_control())
}

/// Pasted text with every escape-capable control removed (see [`paste_char_allowed`]). One pass
/// over characters, not marker replacement, so removing a byte can never join its neighbours into
/// a new sequence: the result contains no ESC at all.
pub fn sanitize_paste(text: &str) -> String {
    text.chars().filter(|&c| paste_char_allowed(c)).collect()
}

/// The bytes a paste sends: sanitized by [`sanitize_paste`], then wrapped in bracketed-paste
/// markers when the program asked for them, otherwise with newlines sent as Return.
pub fn paste_bytes(text: &str, bracketed: bool) -> String {
    let clean = sanitize_paste(text);
    if bracketed {
        format!("\x1b[200~{clean}\x1b[201~")
    } else {
        clean.replace("\r\n", "\r").replace('\n', "\r")
    }
}

/// What a paste confirmation shows (THREAT_MODEL T15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasteConfirmation {
    pub lines: usize,
    /// The first lines, each cut to a readable width, control characters shown as `·`.
    pub preview: String,
}

const PASTE_PREVIEW_LINES: usize = 5;
const PASTE_PREVIEW_WIDTH: usize = 80;

/// Whether pasting `text` needs the user's confirmation first: multi-line text when the program
/// has not enabled bracketed paste (each newline would run as Return), and any paste on a
/// production connection. `None` means paste straight away.
pub fn paste_confirmation(text: &str, bracketed: bool, production: bool) -> Option<PasteConfirmation> {
    let runs_lines = text.contains(['\n', '\r']);
    if !production && (bracketed || !runs_lines) {
        return None;
    }
    let body = text.strip_suffix("\r\n").or_else(|| text.strip_suffix('\n')).unwrap_or(text);
    let lines: Vec<&str> = body.split('\n').collect();
    let shown = |l: &str| -> String {
        let l = l.trim_end_matches('\r');
        let mut out: String = l.chars().map(|c| if c.is_control() && c != '\t' { '·' } else { c }).take(PASTE_PREVIEW_WIDTH).collect();
        if l.chars().count() > PASTE_PREVIEW_WIDTH {
            out.push('…');
        }
        out
    };
    let mut preview: Vec<String> = lines.iter().take(PASTE_PREVIEW_LINES).map(|l| shown(l)).collect();
    if lines.len() > PASTE_PREVIEW_LINES {
        preview.push(format!("… {} more line(s)", lines.len() - PASTE_PREVIEW_LINES));
    }
    Some(PasteConfirmation { lines: lines.len(), preview: preview.join("\n") })
}

#[cfg(test)]
mod link_tests {
    use super::url_at_column;

    fn cells(s: &str) -> Vec<String> {
        s.chars().map(|c| c.to_string()).collect()
    }

    fn at(s: &str, col: usize) -> Option<String> {
        let c = cells(s);
        url_at_column(&c.iter().map(String::as_str).collect::<Vec<_>>(), col)
    }

    #[test]
    fn finds_http_and_https_under_the_column() {
        let line = "see https://example.com/a?b=1 and http://x.test/";
        assert_eq!(at(line, 6).as_deref(), Some("https://example.com/a?b=1"));
        assert_eq!(at(line, 28).as_deref(), Some("https://example.com/a?b=1"));
        assert_eq!(at(line, 30), None);
        assert_eq!(at(line, 40).as_deref(), Some("http://x.test/"));
    }

    #[test]
    fn other_schemes_and_bare_scheme_are_ignored() {
        assert_eq!(at("file:///etc/passwd", 3), None);
        assert_eq!(at("javascript:alert(1)", 3), None);
        assert_eq!(at("https:// nothing", 2), None);
        assert_eq!(at("httpx://a.b", 2), None);
    }

    #[test]
    fn trailing_punctuation_and_brackets() {
        assert_eq!(at("(see https://a.test/x).", 6).as_deref(), Some("https://a.test/x"));
        assert_eq!(at("https://en.wikipedia.org/wiki/A_(b)", 3).as_deref(), Some("https://en.wikipedia.org/wiki/A_(b)"));
        assert_eq!(at("<https://a.test>", 3).as_deref(), Some("https://a.test"));
    }

    #[test]
    fn wide_characters_keep_column_mapping() {
        // "界" takes two cells: its spacer cell is empty.
        let c = ["界", "", " ", "h", "t", "t", "p", ":", "/", "/", "a", ".", "b"];
        assert_eq!(url_at_column(&c, 3).as_deref(), Some("http://a.b"));
        assert_eq!(url_at_column(&c, 1), None);
    }
}

#[cfg(test)]
mod scrollback_tests {
    use super::*;

    #[test]
    fn bell_scrollback_and_clear() {
        // Any child that stays alive for a few seconds; the test drives the emulator directly.
        #[cfg(windows)]
        let t = TerminalSession::spawn_program("cmd.exe", &["/c", "ping -n 6 127.0.0.1 >nul"], 20, 5).unwrap();
        #[cfg(not(windows))]
        let t = TerminalSession::spawn_program("/bin/sh", &["-c", "sleep 5"], 20, 5).unwrap();
        t.sink().output(b"\x07");
        assert!(t.take_bell());
        assert!(!t.take_bell());
        t.set_scrollback(1000);
        for i in 0..50 {
            t.sink().output(format!("line {i}\r\n").as_bytes());
        }
        assert!(t.emu.lock().unwrap().term.grid().history_size() > 0);
        t.select_all();
        assert!(t.selection_text().unwrap().contains("line 0"));
        t.clear_scrollback();
        assert_eq!(t.emu.lock().unwrap().term.grid().history_size(), 0);
        t.close();
    }

    fn idle_terminal() -> TerminalSession {
        #[cfg(windows)]
        return TerminalSession::spawn_program("cmd.exe", &["/c", "ping -n 6 127.0.0.1 >nul"], 30, 5).unwrap();
        #[cfg(not(windows))]
        return TerminalSession::spawn_program("/bin/sh", &["-c", "sleep 5"], 30, 5).unwrap();
    }

    fn all_text(t: &TerminalSession) -> String {
        t.select_all();
        t.selection_text().unwrap_or_default()
    }

    #[test]
    fn carry_over_puts_old_text_above_the_new_prompt() {
        let old = idle_terminal();
        for i in 0..20 {
            old.sink().output(format!("old {i}\r\n").as_bytes());
        }
        let new = idle_terminal();
        new.sink().output(b"new-prompt$ ");
        new.carry_over(&old);
        let text = all_text(&new);
        let (a, b, c) = (text.find("old 0").unwrap(), text.find("[Reconnected]").unwrap(), text.find("new-prompt$").unwrap());
        assert!(a < b && b < c, "{text}");
        assert!(text.contains("old 19"));
        // Output after the carry lands under the prompt as usual; a second carry does nothing.
        new.sink().output(b"ls\r\n");
        new.carry_over(&old);
        let again = all_text(&new);
        assert_eq!(again.matches("[Reconnected]").count(), 1);
        assert!(again.find("ls").unwrap() > again.find("new-prompt$").unwrap());
        old.close();
        new.close();
    }

    #[test]
    fn carry_over_skips_when_early_output_is_gone_or_old_is_empty() {
        let old = idle_terminal();
        let new = idle_terminal();
        new.sink().output(b"prompt$ ");
        new.carry_over(&old);
        assert!(!all_text(&new).contains("[Reconnected]"));
        let big = idle_terminal();
        big.sink().output(&vec![b'x'; EARLY_OUTPUT_CAP + 1]);
        old.sink().output(b"old\r\n");
        big.carry_over(&old);
        assert!(!all_text(&big).contains("old"));
        new.carry_over(&new);
        old.close();
        new.close();
        big.close();
    }
}

#[cfg(all(test, unix))]
mod foreground_tests {
    use super::*;

    fn wait_for(t: &TerminalSession, want: impl Fn(&ForegroundProcess) -> bool) -> Option<ForegroundProcess> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(f) = t.foreground_process().filter(|f| want(f)) {
                return Some(f);
            }
            if std::time::Instant::now() > deadline {
                return t.foreground_process();
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    #[test]
    fn idle_shell_is_not_busy_and_a_running_program_is() {
        let t = TerminalSession::spawn_program("/bin/sh", &[], 40, 10).unwrap();
        let idle = wait_for(&t, |f| !f.busy).expect("foreground known");
        assert!(!idle.busy, "{idle:?}");
        t.write(b"exec_sleep_marker=1 sleep 30\n").unwrap();
        let busy = wait_for(&t, |f| f.busy).expect("foreground known");
        assert!(busy.busy, "{busy:?}");
        assert_eq!(busy.name.as_deref(), Some("sleep"));
        t.write(b"\x03").unwrap();
        assert!(!wait_for(&t, |f| !f.busy).unwrap().busy);
        t.close();
    }

    #[test]
    fn an_exited_terminal_reports_nothing() {
        // A closed terminal no longer reports a foreground process.
        let t = TerminalSession::spawn_program("/bin/sh", &["-c", "exit 0"], 40, 10).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while t.is_alive() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(t.foreground_process(), None);
    }
}

#[cfg(test)]
mod paste_tests {
    use super::{paste_bytes, sanitize_paste};

    const START: &str = "\x1b[200~";
    const END: &str = "\x1b[201~";

    /// The delivered stream holds exactly one outer framing pair and nothing escape-capable inside.
    fn assert_single_frame(out: &str) {
        assert!(out.starts_with(START) && out.ends_with(END), "outer framing missing: {out:?}");
        let inner = &out[START.len()..out.len() - END.len()];
        assert!(!inner.contains('\x1b') && !inner.contains('\u{9b}'), "escape inside paste: {out:?}");
        assert_eq!(out.matches(END).count(), 1, "extra end marker: {out:?}");
        assert_eq!(out.matches(START).count(), 1, "extra start marker: {out:?}");
    }

    #[test]
    fn nested_end_marker_cannot_be_rebuilt() {
        // The exact TE-01 payload: removing the inner marker used to join `\x1b[2` + `01~`.
        let out = paste_bytes("A\x1b[2\x1b[201~01~BEND_R3", true);
        assert_single_frame(&out);
        assert_eq!(out, format!("{START}A[2[201~01~BEND_R3{END}"));
    }

    #[test]
    fn reversed_and_deeply_nested_markers_are_inert() {
        let payloads = [
            "x\x1b[20\x1b[200~1~y",
            "x\x1b[2\x1b[2\x1b[201~01~01~y",
            "\x1b\x1b[201~[201~rm -rf ~\n",
            "a\x1b[200\x1b[201~~b\x1b[201\x1b[200~~c",
            "line1\n\x1b[2\x1b[201~01~\nwhoami\r\n",
            "8bit\u{9b}201~csi",
        ];
        for p in payloads {
            assert_single_frame(&paste_bytes(p, true));
            let raw = paste_bytes(p, false);
            assert!(!raw.contains('\x1b') && !raw.contains('\u{9b}'), "escape in raw paste: {raw:?}");
        }
    }

    #[test]
    fn arbitrary_nesting_depth_never_leaves_an_escape() {
        let mut p = String::from("Z");
        for _ in 0..40 {
            p = format!("\x1b[2{p}01~");
        }
        assert_single_frame(&paste_bytes(&p, true));
    }

    #[test]
    fn keeps_tab_newline_and_text_and_drops_other_controls() {
        assert_eq!(sanitize_paste("a\tb\nc\r\nd\u{7}e\u{7f}f\u{3}g é"), "a\tb\nc\r\ndefg é");
        assert_eq!(paste_bytes("a\nb", false), "a\rb");
        assert_eq!(paste_bytes("a\r\nb", true), format!("{START}a\r\nb{END}"));
    }
}

#[cfg(test)]
mod generation_tests {
    use super::Generation;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[test]
    fn wait_change_returns_at_once_when_already_changed() {
        let g = Generation::default();
        g.bump();
        assert_eq!(g.wait_change(0, Duration::from_secs(5)), 1);
    }

    #[test]
    fn wait_change_times_out_without_a_bump() {
        let g = Generation::default();
        let t0 = Instant::now();
        assert_eq!(g.wait_change(0, Duration::from_millis(30)), 0);
        assert!(t0.elapsed() >= Duration::from_millis(30));
    }

    #[test]
    fn wait_change_wakes_on_bump_from_another_thread() {
        let g = Arc::new(Generation::default());
        let g2 = g.clone();
        let t0 = Instant::now();
        let h = std::thread::spawn(move || g2.wait_change(0, Duration::from_secs(5)));
        std::thread::sleep(Duration::from_millis(20));
        g.bump();
        assert_eq!(h.join().unwrap(), 1);
        assert!(t0.elapsed() < Duration::from_secs(1));
    }

    /// Native Windows closes a tab's terminal before it frees it, so the UI thread does not wait out a wake thread's
    /// wait_change slice (TerminalSession.Dispose). That relies on close waking a waiter at once.
    #[test]
    fn close_wakes_a_waiting_thread_at_once() {
        struct NullBackend;
        impl super::Backend for NullBackend {
            fn write(&self, _: &[u8]) -> crate::error::Result<()> {
                Ok(())
            }
            fn resize(&self, _: super::Size) -> crate::error::Result<()> {
                Ok(())
            }
            fn close(&self) {}
        }
        let t = Arc::new(super::TerminalSession::new(super::checked_size(40, 5).unwrap(), Arc::new(NullBackend)));
        let seen = t.generation();
        let waiter = t.clone();
        let h = std::thread::spawn(move || {
            let t0 = Instant::now();
            let gen = waiter.wait_change(seen, Duration::from_secs(5));
            (gen, t0.elapsed())
        });
        std::thread::sleep(Duration::from_millis(20));
        t.close();
        let (gen, waited) = h.join().unwrap();
        assert_ne!(gen, seen);
        assert!(waited < Duration::from_secs(1), "close left the waiter blocked for {waited:?}");
        assert!(!t.is_alive());
    }
}

#[cfg(test)]
#[path = "terminal_marks_tests.rs"]
mod terminal_marks_tests;
