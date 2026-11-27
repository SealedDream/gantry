//! Terminal bridge: local shells and SSH shells as `Terminal` objects whose grid the native
//! view polls (by generation) and draws. SSH goes through `connect::Orchestrator`, so policy,
//! the broker, strict host keys and the audit log apply exactly as in the core.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use bastion_core::activity::{EndReason, SessionId};
use bastion_core::audit::{AuditLog, Category, Outcome};
use bastion_core::broker::{Broker, LeaseLimits, SystemClock};
use bastion_core::forwards::ForwardSet;
use bastion_core::connect::{ActivitySink, CredentialRef, JumpHop, Orchestrator, SecretUse};
use bastion_core::model::Connection;
use bastion_core::provider::{CredentialProvider, ProviderStatus};
use bastion_core::session::{spawn_supervised, AttemptError, Link, LinkEnd, ReconnectPolicy, SessionEvent, SessionState};
use bastion_core::ssh::SshSession;
use bastion_core::terminal::{FindOptions, SelectKind, TerminalSession, TerminalTheme};
use bastion_core::termmouse;
use bastion_core::vault::{CredentialKind, Secret};
use bastion_core::CoreError;
use uuid::Uuid;

use crate::{parse_id, recording, CredentialVault, FfiError, FfiResult, Library, VaultwardenSession};

pub(crate) static RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Builder::new_multi_thread().enable_all().thread_name("bastion-io").build().expect("tokio runtime"));

/// One jump host of a connection's ProxyJump chain, in connect order.
/// Where the find bar's current match is: `index` 1-based among `total` (0 and 0 when nothing
/// matched); `capped` when there are more matches than were counted.
#[derive(uniffi::Record)]
pub struct FindResultView {
    pub index: u32,
    pub total: u32,
    pub capped: bool,
}

#[derive(uniffi::Record)]
pub struct JumpHostView {
    /// `host:port`, the key for `jump_trust` and `jump_logins`.
    pub key: String,
    pub username: String,
}

#[derive(uniffi::Record)]
pub struct TermCell {
    pub text: String,
    pub fg: u32,
    pub bg: u32,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub selected: bool,
    pub matched: bool,
}

#[derive(uniffi::Record)]
pub struct TermScreen {
    pub cols: u16,
    pub rows: u16,
    /// Row-major, `cols * rows` cells.
    pub cells: Vec<TermCell>,
    pub cursor_row: u16,
    pub cursor_col: u16,
    pub cursor_visible: bool,
    /// Arrow keys must be sent as `ESC O x` instead of `ESC [ x`.
    pub app_cursor: bool,
    pub title: Option<String>,
    /// Theme background (0xRRGGBB) for margins and default-background cells.
    pub background: u32,
    pub generation: u64,
    pub alive: bool,
}

/// `TermScreen` with the cells packed into one byte buffer, which crosses the FFI as a single
/// blob instead of one record (and one string) per cell: on a 200x60 grid that is ~0.4 ms
/// instead of ~15 ms on the Swift side. Per cell, in order: fg (u32 LE), bg (u32 LE), flags
/// (bit 0 bold, 1 italic, 2 underline, 3 selected, 4 matched), text length (u8), text (UTF-8).
#[derive(uniffi::Record)]
pub struct TermScreenPacked {
    pub cols: u16,
    pub rows: u16,
    pub cells: Vec<u8>,
    pub cursor_row: u16,
    pub cursor_col: u16,
    pub cursor_visible: bool,
    pub app_cursor: bool,
    pub title: Option<String>,
    pub background: u32,
    pub generation: u64,
    pub alive: bool,
}

/// Bytes per cell before its text in `TermScreenPacked::cells`.
pub const PACKED_CELL_HEADER: usize = 10;

fn pack_cell(out: &mut Vec<u8>, c: &bastion_core::terminal::ScreenCell) {
    out.extend_from_slice(&c.style.fg.to_le_bytes());
    out.extend_from_slice(&c.style.bg.to_le_bytes());
    let flags = u8::from(c.style.bold)
        | u8::from(c.style.italic) << 1
        | u8::from(c.style.underline) << 2
        | u8::from(c.selected) << 3
        | u8::from(c.matched) << 4;
    out.push(flags);
    // A cell is one grapheme; cap it at 255 bytes on a char boundary.
    let mut end = c.text.len().min(u8::MAX as usize);
    while !c.text.is_char_boundary(end) {
        end -= 1;
    }
    out.push(end as u8);
    out.extend_from_slice(&c.text.as_bytes()[..end]);
}

/// Ids of the built-in terminal themes, in display order.
#[uniffi::export]
pub fn terminal_theme_ids() -> Vec<String> {
    bastion_core::termthemes::BUNDLED.iter().map(|b| b.id.to_string()).collect()
}

/// The SSH connection a terminal runs on. A supervisor swaps in the new connection after a
/// reconnect, so panes split later open on the live one.
type SshSlot = Arc<Mutex<Arc<SshSession>>>;

/// Split panes beside a supervised SSH terminal. They follow its link: after a reconnect each
/// pane still open gets a new shell channel on the new connection; when reconnecting stops they
/// end with it.
type Siblings = Arc<Mutex<Vec<Weak<TerminalSession>>>>;

fn live_siblings(siblings: &Siblings) -> Vec<Arc<TerminalSession>> {
    let mut list = siblings.lock().unwrap_or_else(|e| e.into_inner());
    list.retain(|w| w.upgrade().is_some_and(|t| t.is_alive()));
    list.iter().filter_map(Weak::upgrade).collect()
}

#[derive(uniffi::Object)]
pub struct Terminal {
    inner: Arc<TerminalSession>,
    /// Keeps the SSH connection (and any jump hosts) open for as long as any terminal on it exists.
    ssh: Option<SshSlot>,
    /// Lifecycle of a supervised SSH terminal (reconnect, sleep/wake); `None` for local shells and split panes.
    supervision: Option<Supervision>,
    /// Panes split from a supervised terminal (shared by it and its panes); `None` otherwise.
    siblings: Option<Siblings>,
    /// Tunnels on this terminal's SSH connection (shared with its split panes); `None` for local shells.
    pub(crate) forwards: Option<Arc<ForwardSet>>,
    /// Telnet and serial terminals: how to reconnect and how the link last ended (B7).
    pub(crate) remote: Option<crate::telnet_serial::RemoteLink>,
}

struct Supervision {
    events: tokio::sync::mpsc::UnboundedSender<SessionEvent>,
    state: tokio::sync::watch::Receiver<SessionState>,
    /// Set by `Terminal::close`, so the session's end is recorded as closed by the user.
    user_closed: Arc<std::sync::atomic::AtomicBool>,
    /// The session's record in the activity store and the audit log.
    record: Arc<SessionRecord>,
}

impl Terminal {
    /// The terminal's own reconnect supervisor (events in, state out), for the C ABI's
    /// supervisor handle: reconnects reuse this connection's prepared credentials and leases
    /// and follow its `auto_reconnect` setting (F06). `None` for an unsupervised terminal.
    #[doc(hidden)]
    pub fn supervision_channels(&self) -> Option<(tokio::sync::mpsc::UnboundedSender<SessionEvent>, tokio::sync::watch::Receiver<SessionState>)> {
        self.supervision.as_ref().map(|s| (s.events.clone(), s.state.clone()))
    }
}

/// A live shell channel as seen by the supervisor: it ends when the channel driver reports.
struct ShellLink(tokio::sync::oneshot::Receiver<LinkEnd>);

impl Link for ShellLink {
    fn closed(&mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = LinkEnd> + Send + '_>> {
        Box::pin(async move { (&mut self.0).await.unwrap_or_else(|_| LinkEnd::Lost("connection lost".into())) })
    }
}

impl Terminal {
    pub(crate) fn with_remote(session: TerminalSession, remote: crate::telnet_serial::RemoteLink) -> Self {
        Terminal { inner: Arc::new(session), ssh: None, supervision: None, siblings: None, forwards: None, remote: Some(remote) }
    }

    /// The SSH connection this terminal currently runs on (it changes after a reconnect).
    pub(crate) fn ssh_session(&self) -> Option<Arc<SshSession>> {
        self.ssh.as_ref().map(|slot| slot.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }

    /// True once this terminal's SSH transport is gone; false for local shells.
    #[cfg(test)]
    pub(crate) fn transport_closed(&self) -> bool {
        self.ssh_session().is_some_and(|s| s.is_closed())
    }

    pub(crate) fn session(&self) -> &TerminalSession {
        &self.inner
    }

    pub(crate) fn apply_theme(&self, theme: TerminalTheme) {
        self.inner.set_theme(theme);
    }

    /// The core grid with its generation (read first) and liveness, for adapters that pack it
    /// themselves (the C snapshot) instead of going through [`TermScreen`]'s cell vector.
    pub fn core_screen(&self) -> (u64, bool, bastion_core::terminal::Screen) {
        let generation = self.inner.generation();
        (generation, self.inner.is_alive(), self.inner.screen())
    }

    /// The theme background (0xRRGGBB) without taking a snapshot.
    pub fn background(&self) -> u32 {
        self.inner.theme().background
    }
}

#[uniffi::export]
impl Terminal {
    /// The user's login shell in a local PTY.
    #[uniffi::constructor]
    pub fn local_shell(cols: u16, rows: u16) -> FfiResult<Arc<Self>> {
        Ok(Arc::new(Terminal { inner: Arc::new(TerminalSession::spawn_local(cols, rows)?), ssh: None, supervision: None, siblings: None, forwards: None, remote: None }))
    }

    /// A specific local program in a PTY (for example `powershell.exe` or `wsl.exe`). The program
    /// is started directly, not through a shell, so `args` are passed as given.
    #[uniffi::constructor]
    pub fn local_program(program: String, args: Vec<String>, cols: u16, rows: u16) -> FfiResult<Arc<Self>> {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        Ok(Arc::new(Terminal { inner: Arc::new(TerminalSession::spawn_program(&program, &args, cols, rows)?), ssh: None, supervision: None, siblings: None, forwards: None, remote: None }))
    }

    /// A saved local terminal connection (`localshell`): the shell, arguments and start folder
    /// set in its properties.
    #[uniffi::constructor]
    pub fn local_connection(library: Arc<crate::Library>, connection_id: String, cols: u16, rows: u16) -> FfiResult<Arc<Self>> {
        let spec = library.local_shell_spec(&connection_id)?;
        let args: Vec<&str> = spec.args.iter().map(String::as_str).collect();
        let session = TerminalSession::spawn_program_in(&spec.program, &args, spec.cwd.as_deref(), cols, rows)?;
        Ok(Arc::new(Terminal { inner: Arc::new(session), ssh: None, supervision: None, siblings: None, forwards: None, remote: None }))
    }

    /// An SSH connection whose transport is Mosh (`remoteshell`): the local `mosh` client in a
    /// PTY, attaching its tmux session when that is on. Mosh roams and reconnects on its own.
    #[uniffi::constructor]
    pub fn mosh_connection(library: Arc<crate::Library>, connection_id: String, cols: u16, rows: u16) -> FfiResult<Arc<Self>> {
        let spec = library.mosh_spec(&connection_id)?;
        let args: Vec<&str> = spec.args.iter().map(String::as_str).collect();
        let session = TerminalSession::spawn_program_in(&spec.program, &args, spec.cwd.as_deref(), cols, rows)?;
        Ok(Arc::new(Terminal { inner: Arc::new(session), ssh: None, supervision: None, siblings: None, forwards: None, remote: None }))
    }

    pub fn generation(&self) -> u64 {
        self.inner.generation()
    }

    /// Block (off the main thread) until the generation differs from `after` or `timeout_ms`
    /// passes; returns the current generation.
    pub fn wait_change(&self, after: u64, timeout_ms: u32) -> u64 {
        self.inner.wait_change(after, std::time::Duration::from_millis(timeout_ms.into()))
    }

    pub fn screen(&self) -> TermScreen {
        // Read the generation first so a change racing with the copy triggers another redraw.
        let generation = self.inner.generation();
        let s = self.inner.screen();
        TermScreen {
            cols: s.cols,
            rows: s.rows,
            cells: s
                .cells
                .into_iter()
                .map(|c| TermCell {
                    text: c.text,
                    fg: c.style.fg,
                    bg: c.style.bg,
                    bold: c.style.bold,
                    italic: c.style.italic,
                    underline: c.style.underline,
                    selected: c.selected,
                    matched: c.matched,
                })
                .collect(),
            cursor_row: s.cursor_row,
            cursor_col: s.cursor_col,
            cursor_visible: s.cursor_visible,
            app_cursor: s.app_cursor,
            title: s.title,
            background: s.background,
            generation,
            alive: self.inner.is_alive(),
        }
    }

    /// `screen` in the packed layout (see `TermScreenPacked`); what the native views draw from.
    pub fn screen_packed(&self) -> TermScreenPacked {
        let generation = self.inner.generation();
        let s = self.inner.screen();
        let mut cells = Vec::with_capacity(s.cells.len() * (PACKED_CELL_HEADER + 1));
        for c in &s.cells {
            pack_cell(&mut cells, c);
        }
        TermScreenPacked {
            cols: s.cols,
            rows: s.rows,
            cells,
            cursor_row: s.cursor_row,
            cursor_col: s.cursor_col,
            cursor_visible: s.cursor_visible,
            app_cursor: s.app_cursor,
            title: s.title,
            background: s.background,
            generation,
            alive: self.inner.is_alive(),
        }
    }

    /// Switch to a built-in theme by id (see `terminal_theme_ids`).
    pub fn set_theme(&self, id: String) -> FfiResult<()> {
        let theme = TerminalTheme::preset(&id).ok_or_else(|| FfiError::failed(format!("unknown terminal theme {id}")))?;
        self.inner.set_theme(theme);
        Ok(())
    }

    pub fn write(&self, bytes: Vec<u8>) -> FfiResult<()> {
        Ok(self.inner.write(&bytes)?)
    }

    pub fn paste(&self, text: String) -> FfiResult<()> {
        Ok(self.inner.paste(&text)?)
    }

    /// Whether the program enabled bracketed paste; confirm multi-line pastes when it has not.
    pub fn bracketed_paste(&self) -> bool {
        self.inner.bracketed_paste()
    }

    /// Whether the program enabled mouse reporting; the view then sends clicks, drags and wheel
    /// with `mouse` instead of selecting (Shift still selects).
    pub fn mouse_reporting(&self) -> bool {
        self.inner.mouse_reporting()
    }

    /// Report a mouse event at a viewport cell; returns false when the program's mode ignores it.
    pub fn mouse(&self, button: MouseButtonView, action: MouseActionView, row: u16, col: u16, shift: bool, alt: bool, ctrl: bool) -> FfiResult<bool> {
        let mods = termmouse::MouseMods { shift, alt, ctrl };
        Ok(self.inner.mouse(button.into(), action.into(), row, col, mods)?)
    }

    pub fn resize(&self, cols: u16, rows: u16) -> FfiResult<()> {
        Ok(self.inner.resize(cols, rows)?)
    }

    pub fn scroll(&self, lines: i32) {
        self.inner.scroll(lines)
    }

    pub fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }

    /// `clicks`: 1 selects by cell, 2 by word, 3 by line.
    pub fn select_start(&self, row: u16, col: u16, clicks: u8) {
        let kind = match clicks {
            2 => SelectKind::Word,
            3.. => SelectKind::Line,
            _ => SelectKind::Cell,
        };
        self.inner.select_start(row, col, kind)
    }

    pub fn select_extend(&self, row: u16, col: u16) {
        self.inner.select_extend(row, col)
    }

    pub fn select_all(&self) {
        self.inner.select_all()
    }

    pub fn clear_selection(&self) {
        self.inner.clear_selection()
    }

    pub fn selection_text(&self) -> Option<String> {
        self.inner.selection_text()
    }

    /// Regex search through screen and scrollback; `forward` false searches upwards.
    pub fn search(&self, pattern: String, forward: bool) -> FfiResult<bool> {
        Ok(self.inner.search(&pattern, forward)?)
    }

    pub fn clear_search(&self) {
        self.inner.clear_search()
    }

    /// Find-bar search: plain text unless `regex`, case ignored unless `match_case`; reports the
    /// match's place among all matches. An empty query clears the search.
    pub fn find(&self, query: String, forward: bool, match_case: bool, regex: bool) -> FfiResult<FindResultView> {
        let r = self.inner.find(&query, forward, FindOptions { match_case, regex })?;
        Ok(FindResultView { index: r.index, total: r.total, capped: r.capped })
    }

    /// Lines of history kept above the screen (`terminal.scrollback`).
    pub fn set_scrollback(&self, lines: u32) {
        self.inner.set_scrollback(lines as usize)
    }

    /// The http or https URL under a viewport cell (⌘-click), if any.
    pub fn url_at(&self, row: u16, col: u16) -> Option<String> {
        self.inner.url_at(row, col)
    }

    /// A new shell beside this one: a second shell channel on the same SSH connection (no new
    /// login, no secret kept), or a new local shell when this terminal is local.
    pub fn open_sibling(&self, cols: u16, rows: u16) -> FfiResult<Arc<Terminal>> {
        let Some(slot) = self.ssh.clone() else { return Terminal::local_shell(cols, rows) };
        let session = slot.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let channel = RUNTIME.block_on(session.open_shell("xterm-256color", cols.into(), rows.into()))?;
        let Some(siblings) = self.siblings.clone() else {
            let inner = Arc::new(TerminalSession::attach_ssh(channel, cols, rows, RUNTIME.handle())?);
            return Ok(Arc::new(Terminal { inner, ssh: Some(slot), supervision: None, siblings: None, forwards: self.forwards.clone(), remote: None }));
        };
        // A lost link leaves the pane open for the group's reconnect; an exited shell ends it.
        let (inner, _end) = TerminalSession::attach_ssh_supervised(channel, cols, rows, RUNTIME.handle())?;
        let inner = Arc::new(inner);
        siblings.lock().unwrap_or_else(|e| e.into_inner()).push(Arc::downgrade(&inner));
        Ok(Arc::new(Terminal { inner, ssh: Some(slot), supervision: None, siblings: Some(siblings), forwards: self.forwards.clone(), remote: None }))
    }

    /// Connection state of a supervised SSH terminal for the tab: `None` while connected (and
    /// for terminals without supervision), else a short label such as "Reconnecting (2)".
    pub fn link_status(&self) -> Option<String> {
        if self.remote.is_some() {
            return self.remote_status();
        }
        let sup = self.supervision.as_ref()?;
        let state = sup.state.borrow().clone();
        match state {
            SessionState::Reconnecting { attempt } => Some(format!("Reconnecting ({attempt})")),
            SessionState::Suspended => Some("Paused".into()),
            SessionState::Connecting | SessionState::Authenticating => Some("Connecting".into()),
            SessionState::Failed(_) if self.inner.is_alive() => Some("Connection lost".into()),
            _ => None,
        }
    }

    /// An SFTP browser on this terminal's SSH connection (no new login, no secret kept). Fails for
    /// a local terminal. Used by the Windows C ABI.
    pub fn open_sftp(&self) -> FfiResult<Arc<crate::sftp::FilesBrowser>> {
        let Some(slot) = self.ssh.clone() else {
            return Err(crate::FfiError::failed("SFTP needs an SSH session".into()));
        };
        let session = slot.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let opened = crate::sftp::FilesBrowser::open(session, crate::sftp::SshFiles::Sftp, None);
        // The browser shares the terminal's connection and its session: it writes its own
        // connect and disconnect events with that session's id, and ends nothing.
        if let Some(record) = self.supervision.as_ref().map(|s| s.record.clone()) {
            record.audit_now("sftp.connect", if opened.is_ok() { Outcome::Success } else { Outcome::Failure }, file_details("sftp", None));
            if let Ok(browser) = &opened {
                browser.on_close(Box::new(move |connected, _| record.audit_now("sftp.disconnect", Outcome::Success, file_details("sftp", Some(files_end_reason(connected))))));
            }
        }
        opened
    }

    pub fn close(&self) {
        if let Some(sup) = &self.supervision {
            sup.user_closed.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = sup.events.send(SessionEvent::Cancel);
        }
        self.inner.close();
        // PR-1289 HIGH: the user ended the session, so end its SSH transport too. A disconnected tab keeps this
        // terminal for its scrollback, and an SFTP browser or tunnel holds its own reference: without this the
        // authenticated connection stayed open behind a tab shown as disconnected. Split panes (no supervision)
        // share the connection and leave it to the terminal that owns the session.
        if self.supervision.is_some() {
            if let Some(session) = self.ssh_session() {
                drop(RUNTIME.spawn(async move { let _ = session.disconnect().await; }));
            }
        }
    }
}

/// What the user typed into the connect sheet. The secret is handed to the broker once and
/// is never stored by the bridge.
#[derive(uniffi::Enum, Clone)]
pub enum SshLogin {
    Password { password: String },
    /// `passphrase` empty or absent means the key file is not encrypted.
    KeyFile { path: String, passphrase: Option<String> },
    /// A credential from the vault set with `SessionManager::set_vault`; its secret never
    /// crosses the FFI.
    Vault { credential_id: String },
    /// A login item of the unlocked Vaultwarden session set with `SessionManager::set_vaultwarden`.
    Vaultwarden { item_id: String },
    /// Keys in the user's SSH agent (`SSH_AUTH_SOCK`); no secret is typed or brokered.
    Agent,
    /// Password plus a one-time second-factor code for keyboard-interactive logins, after a
    /// connect failed with `TwoFactorRequired`. The code is used for one dial only.
    PasswordAndCode { password: String, code: String },
    /// `"<provider id>:<item>"` from a registered credential provider (1Password, KeePass,
    /// Vault); the secret is read inside the core at dial time and never crosses the FFI.
    Provider { reference: String },
}

impl SshLogin {
    /// True when the login itself carries a typed secret (password, passphrase or code).
    pub(crate) fn carries_typed_secret(&self) -> bool {
        match self {
            SshLogin::Password { .. } | SshLogin::PasswordAndCode { .. } => true,
            SshLogin::KeyFile { passphrase, .. } => passphrase.as_deref().is_some_and(|p| !p.is_empty()),
            _ => false,
        }
    }

    /// Overwrite typed secrets in place.
    pub(crate) fn wipe(&mut self) {
        use zeroize::Zeroize;
        match self {
            SshLogin::Password { password } => password.zeroize(),
            SshLogin::PasswordAndCode { password, code } => {
                password.zeroize();
                code.zeroize();
            }
            SshLogin::KeyFile { passphrase: Some(p), .. } => p.zeroize(),
            _ => {}
        }
    }
}

/// The `host:port` a jump host's trust and login are keyed by.
fn hop_key(hop: &Connection) -> String {
    format!("{}:{}", hop.host, hop.settings.port.unwrap_or(22))
}

/// One-shot provider for secrets the user just typed. Each hop of each attempt gets a fresh
/// item id, so the broker leases it creates are never reused by a different connection.
#[derive(Default)]
struct PromptProvider {
    secrets: Mutex<HashMap<String, Secret>>,
}

impl PromptProvider {
    /// Register a typed login; returns the item id and how the secret is used.
    /// Register one login. The third value is `Some(scope)` for a saved vault credential: its
    /// own customer scope, which the broker must check instead of the destination's (F01).
    fn add(&self, login: SshLogin, vault: Option<&CredentialVault>, vw: Option<&VaultwardenSession>) -> FfiResult<(String, SecretUse, Option<Option<String>>)> {
        let item = Uuid::new_v4().to_string();
        let mut saved_scope = None;
        let (secret, usage) = match login {
            SshLogin::Agent => return Ok((item, SecretUse::Agent(None), None)),
            // The code itself is taken by `prepare` and never reaches the broker.
            SshLogin::PasswordAndCode { password, .. } | SshLogin::Password { password } => (Secret::new(password), SecretUse::Password),
            SshLogin::KeyFile { path, passphrase } => (Secret::new(passphrase.unwrap_or_default()), SecretUse::KeyFilePassphrase(PathBuf::from(path))),
            SshLogin::Vault { credential_id } => {
                let vault = vault.ok_or_else(|| FfiError::failed("the credential vault is not open".into()))?;
                saved_scope = Some(vault.scope_for(&credential_id)?);
                match vault.secret_for(&credential_id)?.0 {
                    CredentialKind::Password { password, .. } => (password, SecretUse::Password),
                    CredentialKind::SshKey { private_key, .. } => (private_key, SecretUse::KeyPem),
                }
            }
            SshLogin::Vaultwarden { item_id } => {
                let vw = vw.ok_or_else(|| FfiError::failed("Vaultwarden is not set up".into()))?;
                (vw.secret_for(&item_id)?.0, SecretUse::Password)
            }
            SshLogin::Provider { reference } => (crate::providers::resolve(&reference)?, SecretUse::Password),
        };
        if let Ok(mut m) = self.secrets.lock() {
            m.insert(item.clone(), secret);
        }
        Ok((item, usage, saved_scope))
    }
}

impl CredentialProvider for PromptProvider {
    fn id(&self) -> &'static str {
        "prompt"
    }
    fn status(&self) -> ProviderStatus {
        ProviderStatus::Available
    }
    fn fetch(&self, item: &str) -> bastion_core::Result<Secret> {
        self.secrets.lock().ok().and_then(|mut m| m.remove(item)).ok_or_else(|| CoreError::NotFound(format!("prompted secret `{item}` not available")))
    }
    fn store(&self, _: &str, _: &Secret) -> bastion_core::Result<()> {
        Err(CoreError::Invalid("prompted secrets are never stored".into()))
    }
    fn delete(&self, _: &str) -> bastion_core::Result<()> {
        Ok(())
    }
}

/// Opens sessions for saved connections. Holds the broker, audit log and known_hosts for one
/// app data directory.
#[derive(uniffi::Object)]
pub struct SessionManager {
    data_dir: PathBuf,
    dialer: Arc<Dialer>,
    vault: Mutex<Option<Arc<CredentialVault>>>,
    vaultwarden: Mutex<Option<Arc<VaultwardenSession>>>,
    /// Event senders of supervised terminals, for sleep/wake. Closed ones are pruned on use.
    supervised: Mutex<Vec<tokio::sync::mpsc::UnboundedSender<SessionEvent>>>,
    /// Bumped by `lock_credentials`; objects holding typed logins (MultiExec) compare it (F05).
    credentials_epoch: std::sync::atomic::AtomicU64,
}

/// Dials prepared connections through the orchestrator; shared with supervisors for reconnects.
struct Dialer {
    data_dir: PathBuf,
    broker: Arc<Broker>,
    /// One audit writer at a time: the log is a hash chain.
    audit_lock: tokio::sync::Mutex<()>,
}

/// A connection ready to dial: resolved target, jump hops and credential references. No secret
/// is kept here: the first dial takes the typed secrets from the one-shot provider, and later
/// dials (reconnects) get them only from the broker's leases, within its inactivity and
/// absolute limits. Once those expire a reconnect fails and the user signs in again.
struct Prepared {
    conn: Connection,
    cred: CredentialRef,
    hops: Vec<JumpHop>,
    provider: Arc<PromptProvider>,
    /// One-time second-factor code for the first dial only; a reconnect needs a fresh one.
    code: Mutex<Option<Secret>>,
}

impl Dialer {
    /// Dial without a record in the activity store: reconnects of a session that has one, and
    /// the connections that are not recorded (tasks, multi-host exec, tunnels, system views,
    /// gateway routes).
    async fn dial(&self, p: &Prepared, trust: Option<&str>) -> bastion_core::Result<SshSession> {
        Ok(self.connect(p, trust, None).await?.0)
    }

    async fn connect(&self, p: &Prepared, trust: Option<&str>, sink: Option<ActivitySink>) -> bastion_core::Result<(SshSession, Orchestrator)> {
        let _guard = self.audit_lock.lock().await;
        let audit = AuditLog::open(self.data_dir.join("audit.jsonl"))?;
        let mut orchestrator = Orchestrator::new(crate::policy::effective()?, self.broker.clone(), vec![p.provider.clone()], audit, self.data_dir.join("known_hosts"));
        orchestrator.verification_code = p.code.lock().unwrap_or_else(|e| e.into_inner()).take();
        orchestrator.activity = sink;
        let session = orchestrator.connect_ssh_via(&p.hops, &p.conn, &p.cred, trust).await?;
        // The orchestrator may now outlive the dial (see `SessionRecord`): it keeps no code.
        orchestrator.verification_code = None;
        Ok((session, orchestrator))
    }

    /// Dial an interactive terminal or a file session. With `sink` set the connect is recorded
    /// in the activity store (a failed one with its reason); the record that comes back ends
    /// the session, once. The first write of a run can wait up to two seconds for another
    /// instance (the store's gate), so this runs off the UI thread, like every connect.
    async fn dial_recorded(self: &Arc<Self>, p: &Prepared, trust: Option<&str>, sink: Option<ActivitySink>) -> bastion_core::Result<(SshSession, Arc<SessionRecord>)> {
        let (session, orchestrator) = self.connect(p, trust, sink).await?;
        let record = SessionRecord { session: orchestrator.activity_session(), target: p.conn.name.clone(), orchestrator, dialer: self.clone() };
        Ok((session, Arc::new(record)))
    }

    /// Append one record to the audit log, one writer at a time. A failed write is reported on
    /// stderr and does not fail what was already done.
    async fn audit(&self, action: &str, target: &str, outcome: Outcome, details: std::collections::BTreeMap<String, String>, correlation: Option<SessionId>) {
        let _guard = self.audit_lock.lock().await;
        if let Err(e) = AuditLog::open(self.data_dir.join("audit.jsonl")).and_then(|mut log| log.record_correlated(Category::Connection, action, Some(target), outcome, details, correlation)) {
            eprintln!("bastion: audit log write failed for {action}: {e}");
        }
    }
}

/// Run `work` to its end: at once on a thread outside the runtime (the UI's worker threads,
/// where sessions are closed), as a task when called from inside it.
fn run_now(work: impl std::future::Future<Output = ()> + Send + 'static) {
    match tokio::runtime::Handle::try_current() {
        Ok(_) => drop(RUNTIME.spawn(work)),
        Err(_) => RUNTIME.block_on(work),
    }
}

/// The details of a file session's audit events: the protocol and, for a disconnect, why.
fn file_details(protocol: &str, reason: Option<EndReason>) -> std::collections::BTreeMap<String, String> {
    let mut details = std::collections::BTreeMap::from([("protocol".to_string(), protocol.to_string())]);
    if let Some(reason) = reason {
        details.insert("reason".to_string(), recording::reason_text(reason));
    }
    details
}

/// Why a file session ended when its browser was closed: by the user, unless its link had
/// already dropped.
fn files_end_reason(connected: bool) -> EndReason {
    if connected {
        EndReason::ClosedByUser
    } else {
        EndReason::NetworkLost
    }
}

/// The record of one connected session: the orchestrator that opened it (it writes the
/// session's end to the activity store and `ssh.disconnect` to the audit log) and the id that
/// ties the session's audit events together. It holds no secret: the typed logins were taken
/// by the dial and the one-time code is cleared.
pub(crate) struct SessionRecord {
    orchestrator: Orchestrator,
    dialer: Arc<Dialer>,
    /// `None` while the history is off.
    session: Option<SessionId>,
    target: String,
}

impl SessionRecord {
    /// The session has ended. Only the first call writes; later ones do nothing.
    async fn end(&self, reason: EndReason, reconnects: Option<u32>) {
        let _guard = self.dialer.audit_lock.lock().await;
        self.orchestrator.session_ended(reason, reconnects, None, None);
    }

    fn end_now(self: &Arc<Self>, reason: EndReason, reconnects: Option<u32>) {
        let record = self.clone();
        run_now(async move { record.end(reason, reconnects).await });
    }

    /// An audit event of this session (`sftp.connect`, `sftp.disconnect`), with its id.
    fn audit_now(self: &Arc<Self>, action: &'static str, outcome: Outcome, details: std::collections::BTreeMap<String, String>) {
        let record = self.clone();
        run_now(async move { record.dialer.audit(action, &record.target, outcome, details, record.session).await });
    }

    /// A file session of its own was closed: its disconnect event, then the session's end.
    fn close_files_now(self: &Arc<Self>, protocol: &'static str, reason: EndReason, reconnects: u32) {
        let record = self.clone();
        run_now(async move {
            record.dialer.audit("sftp.disconnect", &record.target, Outcome::Success, file_details(protocol, Some(reason)), record.session).await;
            record.end(reason, Some(reconnects)).await;
        });
    }
}

/// Reconnect attempts that cannot succeed without the user are not retried.
fn attempt_error(e: CoreError) -> AttemptError {
    let no_retry = matches!(
        e,
        CoreError::AuthFailed | CoreError::TwoFactorRequired | CoreError::HostKeyUnknown { .. } | CoreError::JumpHostKeyUnknown { .. } | CoreError::HostKeyChanged { .. } | CoreError::NotFound(_)
    );
    let reason = match e {
        CoreError::NotFound(_) => "the credential lease has expired or was locked; reconnect to sign in again".to_string(),
        e => e.to_string(),
    };
    AttemptError { reason, auth: no_retry }
}

#[uniffi::export]
impl SessionManager {
    #[uniffi::constructor]
    pub fn new(data_dir: String) -> FfiResult<Arc<Self>> {
        let data_dir = PathBuf::from(data_dir);
        std::fs::create_dir_all(&data_dir).map_err(CoreError::from)?;
        let broker = Arc::new(Broker::for_policy(crate::policy::effective_or_default(), Arc::new(SystemClock)));
        let dialer = Arc::new(Dialer { data_dir: data_dir.clone(), broker, audit_lock: tokio::sync::Mutex::new(()) });
        Ok(Arc::new(SessionManager { data_dir, dialer, vault: Mutex::new(None), vaultwarden: Mutex::new(None), supervised: Mutex::new(Vec::new()), credentials_epoch: Default::default() }))
    }

    /// The system is about to sleep: supervised terminals with automatic reconnect drop their
    /// link on purpose (no failure, no retry storm) and wait for `system_did_wake`.
    pub fn system_will_sleep(&self) {
        self.broadcast(SessionEvent::Sleep);
    }

    /// The system woke up: suspended terminals reconnect with their brokered credentials.
    pub fn system_did_wake(&self) {
        self.broadcast(SessionEvent::Wake);
    }

    /// The network path changed (Wi-Fi switch, VPN up/down, new address): supervised terminals
    /// with automatic reconnect replace their link at once instead of waiting for keep-alive to
    /// notice. Others are left alone.
    pub fn network_changed(&self) {
        self.broadcast(SessionEvent::NetworkChanged);
    }

    /// The resolved jump hosts for `connection_id` (empty for a direct connection), so the UI can
    /// collect a separate login per hop. Secrets are not involved.
    pub fn jump_hosts(&self, library: Arc<Library>, connection_id: String) -> FfiResult<Vec<JumpHostView>> {
        let mut conn = library.resolve(parse_id(&connection_id)?)?;
        let mut username = String::new();
        let jumps = crate::workflow::prepare_connection(&self.data_dir, &library, &mut conn, &mut username)?;
        Ok(jumps
            .into_iter()
            .map(|j| JumpHostView { key: format!("{}:{}", j.conn.host, j.conn.settings.port.unwrap_or(22)), username: j.username })
            .collect())
    }

    /// Connect `connection_id` and open a shell in a terminal of `cols`×`rows`.
    /// An unknown host key fails with `FfiError::HostKeyUnknown { fingerprint }`; retry with
    /// `trust_fingerprint` set to that value only after the user verified it independently.
    pub fn connect_ssh(
        &self,
        library: Arc<Library>,
        connection_id: String,
        username: String,
        login: SshLogin,
        trust_fingerprint: Option<String>,
        jump_trust: HashMap<String, String>,
        jump_logins: HashMap<String, SshLogin>,
        cols: u16,
        rows: u16,
    ) -> FfiResult<Arc<Terminal>> {
        let sink = self.activity_sink(&library, &connection_id, &login);
        let mut prepared = self.prepare(&library, &connection_id, username, login, jump_trust, jump_logins)?;
        let (session, record) = RUNTIME.block_on(self.dialer.dial_recorded(&prepared, trust_fingerprint.as_deref(), sink))?;
        // Trust given for this dial is now in known_hosts; reconnects verify strictly.
        prepared.hops.iter_mut().for_each(|h| h.trust = None);
        // A terminal that cannot be opened on the new connection ends the session it began.
        self.open_terminal(&library, &connection_id, prepared, session, record.clone(), cols, rows).inspect_err(|_| record.end_now(EndReason::Failed, None))
    }

    /// Connect like `connect_ssh` but open an SFTP browser instead of a shell.
    pub fn connect_sftp(
        &self,
        library: Arc<Library>,
        connection_id: String,
        username: String,
        login: SshLogin,
        trust_fingerprint: Option<String>,
        jump_trust: HashMap<String, String>,
        jump_logins: HashMap<String, SshLogin>,
    ) -> FfiResult<Arc<crate::sftp::FilesBrowser>> {
        let sink = self.activity_sink(&library, &connection_id, &login);
        let mut prepared = self.prepare(&library, &connection_id, username, login, jump_trust, jump_logins)?;
        let (session, record) = RUNTIME.block_on(self.dialer.dial_recorded(&prepared, trust_fingerprint.as_deref(), sink))?;
        // SCP connections (servers without the SFTP subsystem) browse over `scp` and POSIX commands.
        let (kind, protocol) = if prepared.conn.protocol == bastion_core::model::Protocol::Scp { (crate::sftp::SshFiles::Scp, "scp") } else { (crate::sftp::SshFiles::Sftp, "sftp") };
        // Same rules as a supervised terminal: opt-in, strict host keys, brokered leases only.
        let redial: Option<crate::sftp::Redial> = (prepared.conn.settings.auto_reconnect != Some(false)).then(|| {
            prepared.hops.iter_mut().for_each(|h| h.trust = None);
            let (dialer, prepared) = (self.dialer.clone(), Arc::new(prepared));
            Box::new(move || Ok(RUNTIME.block_on(dialer.dial(&prepared, None))?)) as crate::sftp::Redial
        });
        // The file session's own audit events, tied to the session by its id. A browser that
        // cannot be opened on the new connection ends the session it began.
        let opened = crate::sftp::FilesBrowser::open(session, kind, redial);
        record.audit_now("sftp.connect", if opened.is_ok() { Outcome::Success } else { Outcome::Failure }, file_details(protocol, None));
        match &opened {
            Ok(browser) => browser.on_close(Box::new(move |connected, reconnects| record.close_files_now(protocol, files_end_reason(connected), reconnects))),
            Err(_) => record.end_now(EndReason::Failed, None),
        }
        opened
    }

    /// Sign in to an FTPS connection (explicit TLS; plain FTP is refused by policy) and open a
    /// files browser. An untrusted certificate fails with `HostKeyUnknown { fingerprint }`; retry
    /// with `trusted_fingerprint` once the user verified it. The password is used for this sign-in
    /// only and never stored.
    pub fn connect_ftps(&self, library: Arc<Library>, connection_id: String, username: String, password: String, trusted_fingerprint: Option<String>) -> FfiResult<Arc<crate::sftp::FilesBrowser>> {
        use bastion_core::model::Protocol;
        let conn = library.resolve(parse_id(&connection_id)?)?;
        if conn.protocol != Protocol::Ftps {
            return Err(FfiError::failed(format!("{} is not an FTPS connection", conn.name)));
        }
        crate::policy::effective()?.check_protocol(Protocol::Ftps)?;
        let user = if username.trim().is_empty() { conn.settings.username.clone().unwrap_or_default() } else { username };
        if user.trim().is_empty() {
            return Err(FfiError::failed("a username is required".into()));
        }
        let port = conn.settings.port.unwrap_or(bastion_core::ftps::DEFAULT_PORT);
        let secret = Secret::new(password);
        // The session is recorded from here: the password was typed for this sign-in (the
        // bridge is not told where the UI took it from) and is in no record.
        let sink = recording::sink(&self.data_dir, &library, conn.id, bastion_core::activity::LoginSource::Typed);
        let session = sink.as_ref().and_then(|sink| recording::begin(sink, &conn, port, &user));
        let result = RUNTIME.block_on(bastion_core::ftps::Ftps::connect(&conn.host, port, &user, &secret, trusted_fingerprint.as_deref()));
        let outcome = match &result {
            Ok(_) => Outcome::Success,
            Err(_) => Outcome::Failure,
        };
        let details = std::collections::BTreeMap::from([("protocol".to_string(), "ftps".to_string()), ("port".to_string(), port.to_string())]);
        // One audit writer at a time: the log is a hash chain (see `Dialer`).
        RUNTIME.block_on(self.dialer.audit("ftps.connect", &conn.name, outcome, details, session));
        let ftps = match result {
            Ok(ftps) => ftps,
            Err(e) => {
                if let (Some(sink), Some(session)) = (&sink, session) {
                    recording::end(sink, session, None, recording::end_reason_for(&e));
                }
                return Err(e.into());
            }
        };
        let connected_at = bastion_core::activity::now_ms();
        let browser = crate::sftp::FilesBrowser::ftps(ftps);
        let (dialer, target) = (self.dialer.clone(), conn.name.clone());
        browser.on_close(Box::new(move |_, _| {
            // FTPS has no link state to ask: a closed browser is closed by the user.
            let reason = EndReason::ClosedByUser;
            run_now(async move {
                dialer.audit("ftps.disconnect", &target, Outcome::Success, file_details("ftps", Some(reason)), session).await;
                if let (Some(sink), Some(session)) = (&sink, session) {
                    recording::end(sink, session, Some(connected_at), reason);
                }
            });
        }));
        Ok(browser)
    }

    /// The vault that `SshLogin::Vault` logins read from.
    pub fn set_vault(&self, vault: Arc<CredentialVault>) {
        *self.vault.lock().unwrap_or_else(|e| e.into_inner()) = Some(vault);
    }

    /// The Vaultwarden session that `SshLogin::Vaultwarden` logins read from.
    pub fn set_vaultwarden(&self, session: Arc<VaultwardenSession>) {
        *self.vaultwarden.lock().unwrap_or_else(|e| e.into_inner()) = Some(session);
    }

    /// Forget every unlocked credential now (the "Lock Credentials" action), Vaultwarden included.
    pub fn lock_credentials(&self) -> FfiResult<()> {
        if let Some(vw) = self.vaultwarden.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            vw.lock();
        }
        // Release the decrypted local vault; the next use opens it again (Keychain read).
        *self.vault.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.credentials_epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.dialer.broker.lock_all()?;
        Ok(())
    }
}

impl SessionManager {
    /// Changes every time credentials are locked.
    pub(crate) fn credentials_epoch(&self) -> u64 {
        self.credentials_epoch.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl SessionManager {
    /// Where a connect to `connection_id` with `login` is recorded; `None` while the history
    /// is off (or the id is not one, which the connect itself reports).
    fn activity_sink(&self, library: &Library, connection_id: &str, login: &SshLogin) -> Option<ActivitySink> {
        let connection = parse_id(connection_id).ok()?;
        let vault = self.vault.lock().unwrap_or_else(|e| e.into_inner()).clone();
        recording::sink(&self.data_dir, library, connection, recording::login_source(login, library, vault.as_deref(), connection))
    }

    /// Open the shell of a freshly dialled connection and supervise it.
    #[allow(clippy::too_many_arguments)]
    fn open_terminal(&self, library: &Arc<Library>, connection_id: &str, prepared: Prepared, session: SshSession, record: Arc<SessionRecord>, cols: u16, rows: u16) -> FfiResult<Arc<Terminal>> {
        let prepared = Arc::new(prepared);
        let tmux = crate::pluginexec::terminal_command(prepared.conn.id).or_else(|| bastion_core::remoteshell::tmux_command(&prepared.conn));
        let channel = RUNTIME.block_on(session.open_terminal("xterm-256color", cols.into(), rows.into(), tmux.as_deref()))?;
        let (inner, end) = TerminalSession::attach_ssh_supervised(channel, cols, rows, RUNTIME.handle())?;
        let inner = Arc::new(inner);
        let session = Arc::new(session);
        let forwards = Arc::new(parse_id(connection_id).map(ForwardSet::for_connection).unwrap_or_default());
        crate::forwards::start_with_connection(library, connection_id, &session, &forwards);
        let slot: SshSlot = Arc::new(Mutex::new(session));
        let policy = ReconnectPolicy::from_settings(&prepared.conn.settings);
        let siblings: Siblings = Arc::default();
        let supervision = self.supervise(policy, prepared, inner.clone(), slot.clone(), siblings.clone(), forwards.clone(), end, record);
        Ok(Arc::new(Terminal { inner, ssh: Some(slot), supervision: Some(supervision), siblings: Some(siblings), forwards: Some(forwards), remote: None }))
    }

    /// The app's known_hosts (host keys and `@cert-authority` lines).
    pub(crate) fn known_hosts_path(&self) -> PathBuf {
        self.data_dir.join("known_hosts")
    }

    /// Append one record to the hash-chained audit log, one writer at a time (see `Dialer`). A
    /// failed write is reported on stderr and does not fail the action that was already taken.
    /// This app's data directory (audit log, trust files).
    pub(crate) fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    pub fn record_audit(&self, category: bastion_core::audit::Category, action: &str, target: Option<&str>, outcome: bastion_core::audit::Outcome, details: std::collections::BTreeMap<String, String>) {
        let _guard = RUNTIME.block_on(self.dialer.audit_lock.lock());
        if let Err(e) = AuditLog::open(self.data_dir.join("audit.jsonl")).and_then(|mut log| log.record(category, action, target, outcome, details)) {
            eprintln!("bastion: audit log write failed for {action}: {e}");
        }
    }

    /// Data directory and the open vaults, for Test Connection (`probe`).
    pub(crate) fn probe_context(&self) -> (PathBuf, Option<Arc<CredentialVault>>, Option<Arc<VaultwardenSession>>) {
        let vault = self.vault.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let vw = self.vaultwarden.lock().unwrap_or_else(|e| e.into_inner()).clone();
        (self.data_dir.clone(), vault, vw)
    }

    /// Prepare and dial `connection_id` once (tunnels, exec): no terminal, no supervision.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dial_ssh(
        &self,
        library: &Library,
        connection_id: &str,
        username: String,
        login: SshLogin,
        trust_fingerprint: Option<String>,
        jump_trust: HashMap<String, String>,
        jump_logins: HashMap<String, SshLogin>,
    ) -> FfiResult<SshSession> {
        let prepared = self.prepare(library, connection_id, username, login, jump_trust, jump_logins)?;
        Ok(RUNTIME.block_on(self.dialer.dial(&prepared, trust_fingerprint.as_deref()))?)
    }

    fn broadcast(&self, event: SessionEvent) {
        let mut list = self.supervised.lock().unwrap_or_else(|e| e.into_inner());
        list.retain(|tx| tx.send(event).is_ok());
    }

    /// Supervise a connected SSH terminal: report state changes as notices in the terminal,
    /// redial through the orchestrator (policy, broker leases, strict host keys, audit) when the
    /// link drops or the system wakes, and end the terminal once reconnecting stops. When the
    /// supervisor stops, the session's end is written once through `record`: closed by the user,
    /// closed by the remote side (the shell exited) or network lost (the link dropped and
    /// reconnecting is off or was given up). Reconnects stay inside the one session.
    #[allow(clippy::too_many_arguments)]
    fn supervise(
        &self,
        policy: ReconnectPolicy,
        prepared: Arc<Prepared>,
        term: Arc<TerminalSession>,
        slot: SshSlot,
        siblings: Siblings,
        forwards: Arc<ForwardSet>,
        first: tokio::sync::oneshot::Receiver<LinkEnd>,
        record: Arc<SessionRecord>,
    ) -> Supervision {
        let _rt = RUNTIME.enter();
        let first = Arc::new(Mutex::new(Some(first)));
        let (dialer, t, sibs, fwd) = (self.dialer.clone(), term.clone(), siblings.clone(), forwards.clone());
        let sup = spawn_supervised(policy, move || {
            let first = first.lock().unwrap_or_else(|e| e.into_inner()).take();
            let (dialer, prepared, term, slot, siblings, forwards) = (dialer.clone(), prepared.clone(), t.clone(), slot.clone(), sibs.clone(), fwd.clone());
            async move {
                if let Some(end) = first {
                    return Ok(ShellLink(end));
                }
                let session = dialer.dial(&prepared, None).await.map_err(attempt_error)?;
                let (cols, rows) = term.size();
                // A tmux connection re-attaches to the same session, so its programs carry on.
                let tmux = crate::pluginexec::terminal_command(prepared.conn.id).or_else(|| bastion_core::remoteshell::tmux_command(&prepared.conn));
                let channel = session.open_terminal("xterm-256color", cols.into(), rows.into(), tmux.as_deref()).await.map_err(attempt_error)?;
                let end = term.reattach_ssh(channel, &tokio::runtime::Handle::current()).map_err(attempt_error)?;
                // Split panes continue on the new connection; one that cannot get a channel ends.
                for pane in live_siblings(&siblings) {
                    let (cols, rows) = pane.size();
                    let attached = match session.open_shell("xterm-256color", cols.into(), rows.into()).await {
                        Ok(ch) => pane.reattach_ssh(ch, &tokio::runtime::Handle::current()).is_ok(),
                        Err(_) => false,
                    };
                    if !attached {
                        pane.notice("Gantry: this pane could not be reopened after reconnecting");
                        pane.end();
                    }
                }
                let session = Arc::new(session);
                *slot.lock().unwrap_or_else(|e| e.into_inner()) = session.clone();
                // Tunnels follow the connection, on the ports they had.
                if !forwards.is_empty() {
                    forwards.restart(&session).await;
                }
                Ok(ShellLink(end))
            }
        });
        let mut watch = sup.state.clone();
        let user_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (closed, ended) = (user_closed.clone(), record.clone());
        RUNTIME.spawn(async move {
            let mut connected_once = false;
            let mut reconnects = 0u32;
            let mut last = SessionState::Idle;
            while watch.changed().await.is_ok() {
                last = watch.borrow_and_update().clone();
                let text = match &last {
                    SessionState::Connected if connected_once => {
                        reconnects += 1;
                        Some("Gantry: reconnected".to_string())
                    }
                    SessionState::Connected => {
                        connected_once = true;
                        None
                    }
                    SessionState::Failed(reason) => Some(format!("Gantry: connection lost: {reason}")),
                    SessionState::Reconnecting { attempt } => Some(format!("Gantry: reconnecting (attempt {attempt})…")),
                    SessionState::Suspended => Some("Gantry: paused while the system sleeps; reconnecting on wake".to_string()),
                    _ => None,
                };
                if let Some(text) = text {
                    term.notice(&text);
                    live_siblings(&siblings).iter().for_each(|p| p.notice(&text));
                }
            }
            // The supervisor stopped: closed by the user or the shell, or it gave up. Split panes
            // have no link of their own, so they end too.
            let panes = live_siblings(&siblings);
            if matches!(last, SessionState::Failed(_)) {
                term.notice("Gantry: disconnected. Use Reconnect to sign in again.");
                panes.iter().for_each(|p| p.notice("Gantry: disconnected. Use Reconnect to sign in again."));
            }
            panes.iter().for_each(|p| p.end());
            forwards.stop_all().await;
            term.end();
            let reason = if closed.load(std::sync::atomic::Ordering::SeqCst) {
                EndReason::ClosedByUser
            } else if matches!(last, SessionState::Failed(_)) {
                EndReason::NetworkLost
            } else {
                EndReason::RemoteClosed
            };
            ended.end(reason, Some(reconnects)).await;
        });
        self.supervised.lock().unwrap_or_else(|e| e.into_inner()).push(sup.events.clone());
        Supervision { events: sup.events, state: sup.state, user_closed, record }
    }

    /// `dial_ssh` to an already-resolved connection (an RDP connection's SSH management target).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dial_ssh_to(&self, library: &Library, conn: Connection, username: String, login: SshLogin, trust_fingerprint: Option<String>) -> FfiResult<SshSession> {
        let prepared = self.prepare_resolved(library, conn, username, login, HashMap::new(), HashMap::new())?;
        Ok(RUNTIME.block_on(self.dialer.dial(&prepared, trust_fingerprint.as_deref()))?)
    }

    /// Resolve `connection_id` and register the typed logins. `jump_trust` is kept per hop for
    /// the first dial only; `jump_logins` are keyed by `host:port` of a jump host, and a hop
    /// without its own login uses a copy of the target's login.
    fn prepare(
        &self,
        library: &Library,
        connection_id: &str,
        username: String,
        login: SshLogin,
        jump_trust: HashMap<String, String>,
        jump_logins: HashMap<String, SshLogin>,
    ) -> FfiResult<Prepared> {
        let conn = library.resolve(parse_id(connection_id)?)?;
        self.prepare_resolved(library, conn, username, login, jump_trust, jump_logins)
    }

    /// Every SSH connect to a library entry comes through here. `conn` carries the entry's id
    /// (the RDP entry's, for its SSH management sign-in), and the shared login rule is checked
    /// for that id before anything is read from the vault, the user name included.
    fn prepare_resolved(
        &self,
        library: &Library,
        mut conn: Connection,
        username: String,
        login: SshLogin,
        jump_trust: HashMap<String, String>,
        jump_logins: HashMap<String, SshLogin>,
    ) -> FfiResult<Prepared> {
        let target = conn.id;
        if !self.saved_login_allowed(library, &login, &[target])? {
            return Err(FfiError::failed(crate::credtree::NOT_OFFERED.into()));
        }
        let mut username = self.login_username(&login, username)?;
        let jumps = crate::workflow::prepare_connection(&self.data_dir, library, &mut conn, &mut username)?;
        // A jump host with no login of its own reuses the target's, checked above. One chosen
        // for it must be allowed for the target or for the jump host's own library entry.
        for j in &jumps {
            let chosen = jump_logins.get(&hop_key(&j.conn));
            if !chosen.map_or(Ok(true), |l| self.saved_login_allowed(library, l, &[target, j.conn.id]))? {
                return Err(FfiError::failed(format!("the login chosen for jump host {} is not offered for this connection", j.conn.name)));
            }
        }
        self.assemble(conn, username, login, jumps, jump_trust, jump_logins)
    }

    /// False for a saved (vault) login the shared rule does not allow for a connect to the first
    /// of `connections`. Other logins carry what the user typed or chose from another source.
    fn saved_login_allowed(&self, library: &Library, login: &SshLogin, connections: &[Uuid]) -> FfiResult<bool> {
        let SshLogin::Vault { credential_id } = login else { return Ok(true) };
        // `Ok(true)` with no vault open is safe only because nothing can be read then:
        // `PromptProvider::add` fails with "the credential vault is not open" before any
        // secret exists. If the vault handle is ever opened lazily on this path, this must
        // become a refusal or run after the open, or the rule would be skipped.
        let Some(vault) = self.vault.lock().unwrap_or_else(|e| e.into_inner()).clone() else { return Ok(true) };
        vault.may_connect_with(library, connections, parse_id(credential_id)?)
    }

    /// `saved_login_allowed` for one connection (Telnet auto-login, B7).
    pub(crate) fn login_allowed_for(&self, library: &Library, login: &SshLogin, id: Uuid) -> FfiResult<bool> {
        self.saved_login_allowed(library, login, &[id])
    }

    pub(crate) fn login_username_for(&self, login: &SshLogin, username: String) -> FfiResult<String> {
        self.login_username(login, username)
    }

    pub(crate) fn vault_handle(&self) -> Option<Arc<CredentialVault>> {
        self.vault.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub(crate) fn vaultwarden_handle(&self) -> Option<Arc<VaultwardenSession>> {
        self.vaultwarden.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// A vault or Vaultwarden login with no username typed uses the credential's own.
    fn login_username(&self, login: &SshLogin, username: String) -> FfiResult<String> {
        if !username.trim().is_empty() {
            return Ok(username);
        }
        if let (SshLogin::Vault { credential_id }, Some(v)) = (login, self.vault.lock().unwrap_or_else(|e| e.into_inner()).clone()) {
            return Ok(v.secret_for(credential_id)?.1);
        }
        if let (SshLogin::Vaultwarden { item_id }, Some(v)) = (login, self.vaultwarden.lock().unwrap_or_else(|e| e.into_inner()).clone()) {
            return Ok(v.secret_for(item_id)?.1.unwrap_or_default());
        }
        Ok(username)
    }

    /// Register the typed logins for a resolved target and its jump hops.
    fn assemble(
        &self,
        conn: Connection,
        username: String,
        login: SshLogin,
        jumps: Vec<crate::workflow::JumpTarget>,
        jump_trust: HashMap<String, String>,
        mut jump_logins: HashMap<String, SshLogin>,
    ) -> FfiResult<Prepared> {
        if username.trim().is_empty() {
            return Err(FfiError::failed("a username is required".into()));
        }
        let vault = self.vault.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let vw = self.vaultwarden.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let provider = Arc::new(PromptProvider::default());
        let scope = conn.classification.customer.clone();
        let mut hops = Vec::with_capacity(jumps.len());
        for j in jumps {
            let key = hop_key(&j.conn);
            let hop_login = jump_logins.remove(&key).unwrap_or_else(|| login.clone());
            let (item, usage, saved) = provider.add(hop_login, vault.as_deref(), vw.as_deref())?;
            // A saved credential keeps its own scope; a typed secret takes the hop's customer
            // (a jump host imported from the same customer file shares the customer scope).
            let hop_scope = saved.unwrap_or_else(|| j.conn.classification.customer.clone().or(scope.clone()));
            let cred = CredentialRef { provider: "prompt".into(), item, scope: hop_scope, username: j.username, usage };
            hops.push(JumpHop { trust: jump_trust.get(&key).cloned(), conn: j.conn, cred });
        }
        let code = match &login {
            SshLogin::PasswordAndCode { code, .. } => Some(Secret::new(code.trim().to_string())),
            _ => None,
        };
        let (item, usage, saved) = provider.add(login, vault.as_deref(), vw.as_deref())?;
        let cred = CredentialRef { provider: "prompt".into(), item, scope: saved.unwrap_or(scope), username, usage };
        Ok(Prepared { conn, cred, hops, provider, code: Mutex::new(code) })
    }

    /// Dial a gateway itself as the SSH target (the route for an RDP, VNC or web connection):
    /// same policy, broker, host-key check and audit record as any SSH connect.
    pub(crate) fn dial_gateway(&self, gateway: Connection, username: String, login: SshLogin, trust_fingerprint: Option<String>) -> FfiResult<SshSession> {
        let username = self.login_username(&login, username)?;
        let prepared = self.assemble(gateway, username, login, Vec::new(), HashMap::new(), HashMap::new())?;
        Ok(RUNTIME.block_on(self.dialer.dial(&prepared, trust_fingerprint.as_deref()))?)
    }
}

#[derive(uniffi::Enum, Clone, Copy)]
pub enum MouseButtonView {
    Left,
    Middle,
    Right,
    WheelUp,
    WheelDown,
    None,
}

impl From<MouseButtonView> for termmouse::MouseButton {
    fn from(b: MouseButtonView) -> Self {
        match b {
            MouseButtonView::Left => Self::Left,
            MouseButtonView::Middle => Self::Middle,
            MouseButtonView::Right => Self::Right,
            MouseButtonView::WheelUp => Self::WheelUp,
            MouseButtonView::WheelDown => Self::WheelDown,
            MouseButtonView::None => Self::None,
        }
    }
}

#[derive(uniffi::Enum, Clone, Copy)]
pub enum MouseActionView {
    Press,
    Release,
    Motion,
}

impl From<MouseActionView> for termmouse::MouseAction {
    fn from(a: MouseActionView) -> Self {
        match a {
            MouseActionView::Press => Self::Press,
            MouseActionView::Release => Self::Release,
            MouseActionView::Motion => Self::Motion,
        }
    }
}

#[cfg(test)]
#[path = "a1_fu2_tests.rs"]
mod a1_fu2_tests;
