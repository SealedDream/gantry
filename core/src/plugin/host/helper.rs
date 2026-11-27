//! One running helper, seen from the core: its pipe, its reader thread and its ping watchdog.
//!
//! - The first message must be `Hello` (the sandbox report) within `Timing::hello`, with this
//!   build's protocol number and the role the core asked for. Nothing is sent before it.
//! - Every later message is checked with the broker's `check_message` (02a): a view helper never
//!   sends compiled code; a compile helper sends only code, its end and pongs. A violation, a
//!   frame over 16 MiB or one that does not decode kills the helper (a trust-withdrawing stop).
//! - The core pings every `Timing::ping_every`; no pong for `Timing::hang_after` kills the
//!   helper (spec section 5, "Hangs": 10 s).
//! - Nothing that stops a helper ever waits on its pipe. One writer thread owns the pipe; `send`
//!   only queues (at most `OUTBOX_BYTES` unwritten), so a helper that stops reading cannot block
//!   the core, the watchdog or `Drop` (review of #951, HIGH). Such a helper stops answering
//!   pings and is killed as hung.
//! - What the helper sends and the core has not read yet is capped at `INBOX_BYTES`; more is a
//!   violation.
//! - Dropping a `Helper` kills it, without touching the pipe.

use std::fs::File;
use std::io::{self, BufReader, BufWriter};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bastion_plugin_host::proto::{read_frame, write_frame, Role, Sandbox, ToCore, ToHelper, PROTOCOL_VERSION};

use super::spawn::{self, Child};
use crate::plugin::broker::view::{check_message, FromHelper, HelperKind};
use crate::plugin::broker::StopReason;

/// Unwritten bytes queued for one helper. A helper that reads normally never gets near it.
pub const OUTBOX_BYTES: usize = 64 << 20;
/// Bytes from one helper the core has not read yet. Over it, the helper is stopped.
pub const INBOX_BYTES: usize = 64 << 20;
/// Each queued message counts at least this much, so floods of tiny messages are capped too.
const MIN_MESSAGE_COST: usize = 64;

fn cost(len: usize) -> usize {
    len.max(MIN_MESSAGE_COST)
}

/// How long the core waits and how often it pings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// The first message must arrive within this.
    pub hello: Duration,
    pub ping_every: Duration,
    /// No pong for this long kills the helper.
    pub hang_after: Duration,
}

impl Timing {
    /// Spec section 5: a helper that does not answer for 10 s is killed.
    pub const DEFAULT: Timing = Timing { hello: Duration::from_secs(10), ping_every: Duration::from_secs(2), hang_after: Duration::from_secs(10) };
}

/// The helper's exit code when its own memory watchdog stopped it (macOS).
pub const EXIT_MEMORY: i32 = 4;

/// Why a helper is gone, as the core saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stopped {
    /// It exited or closed its pipe: a crash unless the core asked it to stop. `None` when the
    /// exit code could not be read.
    Exited(Option<i32>),
    /// Reading its pipe failed with this error (not a clean end); a crash.
    ReadFailed(String),
    /// No pong in time.
    Hung,
    /// It broke the protocol; it was killed.
    Violation(String),
    /// The core killed it (`Helper::stop`).
    Killed(StopReason),
}

impl Stopped {
    /// The stop reason for the audit record and the abort-bytes decision (02a).
    pub fn reason(&self) -> StopReason {
        match self {
            // The macOS helper's memory watchdog exits with this code (`plugin-host/src/limits.rs`).
            Stopped::Exited(Some(EXIT_MEMORY)) => StopReason::LimitKill,
            Stopped::Exited(_) | Stopped::ReadFailed(_) => StopReason::Crash,
            Stopped::Hung => StopReason::HangKill,
            Stopped::Violation(_) => StopReason::ProtocolViolation,
            Stopped::Killed(reason) => *reason,
        }
    }
}

/// What the core receives from a running helper.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Message(ToCore),
    Stopped(Stopped),
}

#[derive(Debug)]
pub enum StartError {
    Spawn(io::Error),
    NoHello,
    BadHello(String),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::Spawn(e) => write!(f, "the plugin helper could not start: {e}"),
            StartError::NoHello => write!(f, "the plugin helper did not report in time"),
            StartError::BadHello(why) => write!(f, "the plugin helper is not this build's: {why}"),
        }
    }
}

impl std::error::Error for StartError {}

/// The message kind the broker's rules know it as.
fn kind(message: &ToCore) -> FromHelper {
    match message {
        ToCore::Hello { .. } => FromHelper::SandboxReport,
        ToCore::Compiled(_) => FromHelper::CompiledCode,
        ToCore::CompileDone { .. } => FromHelper::CompileDone,
        ToCore::Pong(_) => FromHelper::Pong,
        // View-helper traffic: loading, the plugin's calls and its end.
        ToCore::Loaded { .. } | ToCore::Import { .. } | ToCore::Ended { .. } => FromHelper::Call,
    }
}

fn helper_kind(role: Role) -> HelperKind {
    match role {
        Role::View => HelperKind::View,
        Role::Compile => HelperKind::Compile,
    }
}

/// State shared by the handle, the reader and the watchdog.
struct Shared {
    child: Mutex<Child>,
    /// Encoded frames for the writer thread. Never blocks: see `send`.
    outbox: mpsc::Sender<Vec<u8>>,
    /// Bytes queued in `outbox` and not yet written.
    unwritten: Arc<AtomicUsize>,
    /// Set once: the first `Stopped` event wins, later causes are not reported.
    stopped: AtomicBool,
    last_pong: Mutex<Instant>,
    /// Each event with the bytes it counts against `INBOX_BYTES`.
    events: mpsc::Sender<(usize, Event)>,
    /// Bytes sent to `events` and not yet taken by the core.
    unread: AtomicUsize,
}

impl Shared {
    /// True while the helper has not exited and has not been stopped.
    fn running(&self) -> bool {
        !self.stopped.load(Ordering::SeqCst) && self.child.lock().unwrap_or_else(|e| e.into_inner()).try_wait().is_none()
    }

    /// Kills the helper and reports why, once.
    fn stop(&self, why: Stopped) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut child = self.child.lock().unwrap_or_else(|e| e.into_inner());
        let why = match why {
            // A pipe that closed by itself: wait a moment for the exit code.
            Stopped::Exited(None) => {
                let deadline = Instant::now() + Duration::from_millis(500);
                let mut code = child.try_wait();
                while code.is_none() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                    code = child.try_wait();
                }
                if code.is_none() {
                    child.kill();
                }
                Stopped::Exited(code)
            }
            other => {
                child.kill();
                other
            }
        };
        let _ = self.events.send((0, Event::Stopped(why)));
    }

    /// Queues `message` for the writer thread and returns at once. `WouldBlock` when the helper
    /// has `OUTBOX_BYTES` unwritten already (it is not reading; the watchdog will kill it).
    fn send(&self, message: &ToHelper) -> io::Result<()> {
        if self.stopped.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let frame = message.encode();
        let size = cost(frame.len());
        let queued = self.unwritten.fetch_add(size, Ordering::SeqCst);
        if queued + size > OUTBOX_BYTES {
            self.unwritten.fetch_sub(size, Ordering::SeqCst);
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "the plugin helper is not reading"));
        }
        self.outbox.send(frame).map_err(|_| {
            self.unwritten.fetch_sub(size, Ordering::SeqCst);
            io::Error::from(io::ErrorKind::BrokenPipe)
        })
    }

    /// Takes one event off the channel and returns its bytes to the inbox budget.
    fn took(&self, (size, event): (usize, Event)) -> Event {
        self.unread.fetch_sub(size, Ordering::SeqCst);
        event
    }
}

/// The writer thread: the only code that writes to the helper's pipe. It may block on a full
/// pipe; nothing waits for it. It ends when the pipe breaks (the helper is gone) or when every
/// sender is dropped. It holds no `Shared`, so it never keeps the helper's state alive.
fn write_messages(to_helper: File, frames: mpsc::Receiver<Vec<u8>>, unwritten: Arc<AtomicUsize>) {
    std::thread::spawn(move || {
        let mut out = BufWriter::new(to_helper);
        for frame in frames {
            let size = cost(frame.len());
            let written = write_frame(&mut out, &frame);
            unwritten.fetch_sub(size, Ordering::SeqCst);
            if written.is_err() {
                return;
            }
        }
    });
}

/// macOS: writing to a pipe whose reader is gone returns `EPIPE` instead of raising `SIGPIPE`,
/// which would end the app (the core runs inside the Mac app, where `SIGPIPE` is not ignored).
#[cfg(target_os = "macos")]
fn no_sigpipe(file: &File) {
    use std::os::fd::AsRawFd;
    // SAFETY: a plain fcntl on a descriptor we own.
    unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETNOSIGPIPE, 1) };
}

#[cfg(not(target_os = "macos"))]
fn no_sigpipe(_file: &File) {}

/// A running helper. Messages and the stop arrive through `next_event`.
pub struct Helper {
    pub role: Role,
    pub pid: u32,
    pub sandbox: Sandbox,
    /// The helper's Wasmtime engine key: compiled code from another key is never sent to it.
    pub engine_key: String,
    shared: Arc<Shared>,
    events: mpsc::Receiver<(usize, Event)>,
}

impl Helper {
    /// Starts the helper program at `program` in `role` and waits for its sandbox report.
    /// `require_sandbox` refuses a helper without one (on once PLUG-05 lands).
    pub fn start(program: &Path, role: Role, memory_cap: u64, timing: Timing, require_sandbox: bool) -> Result<Helper, StartError> {
        Helper::start_with_caps(program, role, memory_cap, memory_cap, timing, require_sandbox)
    }

    /// `start` with the helper's own cap and the cap the core checks from outside apart. Only
    /// tests give them different values, to prove the outside check alone.
    pub(crate) fn start_with_caps(program: &Path, role: Role, memory_cap: u64, outside_cap: u64, timing: Timing, require_sandbox: bool) -> Result<Helper, StartError> {
        let mut child = spawn::spawn(program, role, memory_cap).map_err(StartError::Spawn)?;
        let (Some(to_helper), Some(from_helper)) = (child.to_helper.take(), child.from_helper.take()) else {
            child.kill();
            return Err(StartError::Spawn(io::ErrorKind::BrokenPipe.into()));
        };
        let pid = child.pid;
        let (tx, events) = mpsc::channel();
        let (outbox, frames) = mpsc::channel();
        let unwritten = Arc::new(AtomicUsize::new(0));
        no_sigpipe(&to_helper);
        write_messages(to_helper, frames, unwritten.clone());
        let shared = Arc::new(Shared {
            child: Mutex::new(child),
            outbox,
            unwritten,
            stopped: AtomicBool::new(false),
            last_pong: Mutex::new(Instant::now()),
            events: tx,
            unread: AtomicUsize::new(0),
        });
        read_messages(from_helper, role, shared.clone());

        let fail = |error: StartError| {
            shared.stop(Stopped::Killed(StopReason::NoSandbox));
            Err(error)
        };
        let first = events.recv_timeout(timing.hello).map(|event| shared.took(event));
        let (protocol, hello_role, sandbox, engine_key) = match first {
            Ok(Event::Message(ToCore::Hello { protocol, role, sandbox, engine_key, .. })) => (protocol, role, sandbox, engine_key),
            Ok(Event::Stopped(_)) | Err(_) => return fail(StartError::NoHello),
            Ok(Event::Message(_)) => return fail(StartError::BadHello("the first message is not the sandbox report".into())),
        };
        if protocol != PROTOCOL_VERSION {
            return fail(StartError::BadHello(format!("protocol {protocol}, this build speaks {PROTOCOL_VERSION}")));
        }
        if hello_role != role {
            return fail(StartError::BadHello("it started in the wrong role".into()));
        }
        if require_sandbox && sandbox != Sandbox::Applied {
            return fail(StartError::BadHello("it reports no sandbox".into()));
        }
        // PLUG-05: do not take the helper's word. Where the OS can tell from outside, a helper
        // that claims or needs a sandbox must really be in one.
        if (require_sandbox || sandbox == Sandbox::Applied) && os_sandboxed(pid) == Some(false) {
            return fail(StartError::BadHello("the OS reports no sandbox on it".into()));
        }
        watch(shared.clone(), timing, pid, outside_cap);
        Ok(Helper { role, pid, sandbox, engine_key, shared, events })
    }

    pub fn send(&self, message: &ToHelper) -> io::Result<()> {
        self.shared.send(message)
    }

    /// The next event, waiting at most `limit`. `None` on timeout or once nothing more can come.
    pub fn next_event(&self, limit: Duration) -> Option<Event> {
        self.events.recv_timeout(limit).ok().map(|event| self.shared.took(event))
    }

    /// Stops the helper now for `reason`. The `Stopped` event follows.
    pub fn stop(&self, reason: StopReason) {
        self.shared.stop(Stopped::Killed(reason));
    }

    pub fn is_stopped(&self) -> bool {
        self.shared.stopped.load(Ordering::SeqCst)
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        // Kill only: a `Shutdown` before it would change nothing, and nothing here may wait on
        // the pipe (review of #951, HIGH).
        self.shared.stop(Stopped::Killed(StopReason::TabClosed));
    }
}

/// The reader thread: every frame is decoded and checked before it is passed on.
fn read_messages(from_helper: File, role: Role, shared: Arc<Shared>) {
    std::thread::spawn(move || {
        let mut input = BufReader::new(from_helper);
        let mut accepted = false;
        loop {
            let frame = match read_frame(&mut input) {
                Ok(Some(frame)) => frame,
                Ok(None) => return shared.stop(Stopped::Exited(None)),
                // A length over 16 MiB is refused before anything is allocated.
                Err(e) if e.kind() == io::ErrorKind::InvalidData => return shared.stop(Stopped::Violation(e.to_string())),
                Err(e) => return shared.stop(Stopped::ReadFailed(e.to_string())),
            };
            let size = cost(frame.len());
            let message = match ToCore::decode(&frame) {
                Ok(message) => message,
                Err(e) => return shared.stop(Stopped::Violation(e.to_string())),
            };
            if let Err(violation) = check_message(helper_kind(role), accepted, kind(&message)) {
                return shared.stop(Stopped::Violation(violation.0));
            }
            accepted = true;
            if let ToCore::Pong(_) = message {
                *shared.last_pong.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
                continue;
            }
            if shared.unread.fetch_add(size, Ordering::SeqCst) + size > INBOX_BYTES {
                return shared.stop(Stopped::Violation(format!("the helper sent over {} MiB the core has not read", INBOX_BYTES >> 20)));
            }
            if shared.events.send((size, Event::Message(message))).is_err() {
                return;
            }
        }
    });
}

/// The ping watchdog. It ends when the helper has stopped.
fn watch(shared: Arc<Shared>, timing: Timing, pid: u32, memory_cap: u64) {
    std::thread::spawn(move || {
        let mut n = 0u64;
        while !shared.stopped.load(Ordering::SeqCst) {
            std::thread::sleep(timing.ping_every);
            // PLUG-01 part 2: the outside check of the memory cap, in case the helper's own
            // watchdog is gone. Windows needs none: the job object enforces it.
            // Fails closed: a footprint that cannot be read on a helper still running is a kill.
            match footprint(pid) {
                Some(bytes) if bytes > memory_cap => return shared.stop(Stopped::Killed(StopReason::LimitKill)),
                Some(_) => {}
                None if FOOTPRINT_READABLE && shared.running() => return shared.stop(Stopped::Killed(StopReason::LimitKill)),
                None => {}
            }
            let silent = shared.last_pong.lock().unwrap_or_else(|e| e.into_inner()).elapsed();
            if silent > timing.hang_after {
                return shared.stop(Stopped::Hung);
            }
            n += 1;
            // Never waits. A full outbox means the helper is not reading: no pong will come and
            // the check above kills it.
            match shared.send(&ToHelper::Ping(n)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
        }
    });
}

/// Whether `footprint` can read anything on this OS.
const FOOTPRINT_READABLE: bool = cfg!(target_os = "macos");

/// The physical footprint of process `pid` in bytes, read from outside (macOS).
#[cfg(target_os = "macos")]
pub(crate) fn footprint(pid: u32) -> Option<u64> {
    let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a rusage_info_v2, the flavour asked for.
    let rc = unsafe { libc::proc_pid_rusage(pid as libc::c_int, libc::RUSAGE_INFO_V2, (&mut info as *mut libc::rusage_info_v2).cast()) };
    (rc == 0).then_some(info.ri_phys_footprint)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn footprint(_pid: u32) -> Option<u64> {
    None
}

/// Whether the OS holds process `pid` in a sandbox, checked from outside: `Some` where the OS can
/// tell (macOS `sandbox_check`, Windows `TokenIsAppContainer`), `None` where this build cannot check.
#[cfg(target_os = "macos")]
pub(crate) fn os_sandboxed(pid: u32) -> Option<bool> {
    extern "C" {
        // libsystem_sandbox. With no operation it answers "is this process sandboxed": 1 yes, 0 no.
        fn sandbox_check(pid: libc::pid_t, operation: *const std::ffi::c_char, filter_type: std::ffi::c_int, ...) -> std::ffi::c_int;
    }
    // SAFETY: a null operation with filter type 0 (SANDBOX_FILTER_NONE) takes no further arguments.
    Some(unsafe { sandbox_check(pid as libc::pid_t, std::ptr::null(), 0) } == 1)
}

/// Windows: whether process `pid`'s token is an AppContainer token.
#[cfg(windows)]
pub(crate) fn os_sandboxed(pid: u32) -> Option<bool> {
    super::spawn::is_app_container(pid)
}

#[cfg(not(any(target_os = "macos", windows)))]
pub(crate) fn os_sandboxed(_pid: u32) -> Option<bool> {
    None
}
