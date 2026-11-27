//! Activity store: the handle that writes, queries, sweeps and purges (`ActivityLog`).
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use serde::Deserialize;
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::store::create_private_dir;

use super::reader::*;
use super::*;

pub(super) struct OpenSession {
    started_at: u64,
    reconnects: u32,
    events: u32,
    /// False when it began while logging was off: nothing is written for it.
    written: bool,
}

/// The instants of a sweep ([`ActivityLog::close_orphans`]) at which a test starts another run.
/// Test builds only: a release build has neither the steps nor the hook.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SweepStep {
    /// Before anything is done.
    Start,
    /// Before each monthly file is read.
    BeforeRead,
    /// Between reading the log and finding out which runs are alive.
    Between,
    /// After both, before the ends of the orphans are written.
    BeforeWrite,
    /// A run lock was found free and is locked by the sweep; the next thing done is its removal.
    BeforeRemove,
}

#[cfg(test)]
thread_local! {
    /// Called at each [`SweepStep`] of a sweep made on this thread.
    static SWEEP_HOOK: std::cell::RefCell<Option<Box<dyn FnMut(SweepStep)>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Called once, with the path, between creating a run lock and locking it on this thread.
    static RUN_LOCK_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce(&Path)>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Called before each open of a run lock on this thread; an error it returns is what the
    /// open "fails" with.
    static RUN_LOCK_OPEN_HOOK: std::cell::RefCell<Option<Box<dyn FnMut() -> Option<std::io::Error>>>> = const { std::cell::RefCell::new(None) };
}

/// Open (create) a run lock file.
pub(super) fn open_run_lock(opts: &OpenOptions, path: &Path) -> std::io::Result<File> {
    #[cfg(test)]
    if let Some(e) = RUN_LOCK_OPEN_HOOK.with(|hook| hook.borrow_mut().as_mut().and_then(|at| at())) {
        return Err(e);
    }
    opts.open(path)
}

/// Whether a failed open of a run lock may succeed a moment later. A sweep that is removing the
/// file at this instant makes the open fail on Windows when the removal only marks the file
/// (no POSIX delete: FAT, exFAT, some network folders): access denied, or a sharing violation,
/// until the sweep's handle closes. `NotFound` is the name going away under the open.
pub(super) fn run_lock_open_may_recover(e: &std::io::Error) -> bool {
    /// `ERROR_SHARING_VIOLATION`, which std gives no kind of its own.
    #[cfg(windows)]
    const SHARING_VIOLATION: i32 = 32;
    #[cfg(windows)]
    if e.raw_os_error() == Some(SHARING_VIOLATION) {
        return true;
    }
    matches!(e.kind(), std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound)
}

#[cfg(test)]
pub(super) fn sweep_step(step: SweepStep) {
    SWEEP_HOOK.with(|hook| {
        if let Some(at) = hook.borrow_mut().as_mut() {
            at(step);
        }
    });
}

#[derive(Default)]
pub(super) struct State {
    /// Held locked for the life of the handle: proof to other instances that this run is alive.
    run_lock: Option<File>,
    sessions: HashMap<SessionId, OpenSession>,
    /// Files this handle has already made owner-only.
    #[cfg(windows)]
    restricted: HashSet<PathBuf>,
}

/// The one writer (and reader) of the activity store. Share it between threads; several handles
/// and several processes may use the same directory at once.
pub struct ActivityLog {
    dir: PathBuf,
    run_id: Uuid,
    enabled: AtomicBool,
    state: Mutex<State>,
}

impl ActivityLog {
    /// The store in `<data_dir>/activity`. Nothing is created until the first record is written.
    pub fn in_dir(data_dir: impl AsRef<Path>) -> ActivityLog {
        ActivityLog { dir: data_dir.as_ref().join(DIR_NAME), run_id: Uuid::new_v4(), enabled: AtomicBool::new(true), state: Mutex::new(State::default()) }
    }

    /// The `logging.activity-enabled` setting. While off, `begin` still returns an id but
    /// nothing is written for that session. A session begun while on is still completed.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // The table stays usable if a writer thread panicked: it holds no half-made entries.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn run_lock_path(&self, run: Uuid) -> PathBuf {
        self.dir.join(format!("run-{run}.lock"))
    }

    /// Take the gate, waiting up to [`GATE_WAIT`] for it; after that the error is `TimedOut`. While it is held no run lock appears and none is tested or
    /// removed, so a sweep sees every run lock either held (the run is alive) or free (it has
    /// ended), never one that exists and is about to be locked.
    fn lock_gate(&self) -> Result<File> {
        let path = self.dir.join(GATE_NAME);
        let mut opts = OpenOptions::new();
        opts.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let gate = opts.open(&path)?;
        #[cfg(windows)]
        crate::winacl::restrict_path(&path, false)?;
        let deadline = Instant::now() + GATE_WAIT;
        loop {
            match gate.try_lock() {
                Ok(()) => return Ok(gate),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => std::thread::sleep(GATE_POLL),
                Err(TryLockError::WouldBlock) => {
                    return Err(CoreError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "activity gate: still held by another instance")));
                }
                Err(TryLockError::Error(e)) => return Err(e.into()),
            }
        }
    }

    /// Create the directory and take this run's lock, once.
    fn ensure_ready(&self, state: &mut State) -> Result<()> {
        if state.run_lock.is_some() {
            return Ok(());
        }
        create_private_dir(&self.dir)?;
        let path = self.run_lock_path(self.run_id);
        let mut opts = OpenOptions::new();
        opts.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        // Created and locked under the gate: a sweep of another instance waits, so it cannot
        // meet this file between its creation and its locking and take this run for dead.
        // If the gate is not free in time (an instance stopped or hung while holding it), the lock
        // is taken without it: the caller is not held up further and the record is not lost. The
        // gate only matters if the holder is a sweep that resumes in the instant between the two
        // lines below; refusing the write would lose the session every time instead.
        let _gate = match self.lock_gate() {
            Ok(gate) => Some(gate),
            Err(CoreError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                eprintln!("bastion: activity gate not free after {GATE_WAIT:?}, taking the run lock without it");
                None
            }
            Err(e) => return Err(e),
        };
        // Under the gate the first try succeeds. Without it a sweep that had stopped may come
        // back, find the file before it is locked and remove it; the sweep keeps the file locked
        // until it is gone. So a refused lock is tried again, and a lock on a file that is no
        // longer in the directory is made again: this run always ends up holding a lock that
        // every later sweep can see. An open that fails because the file is being removed at
        // this instant is tried again too, within the same bound.
        let mut last_open_error = None;
        for _ in 0..RUN_LOCK_TRIES {
            let lock = match open_run_lock(&opts, &path) {
                Ok(lock) => lock,
                Err(e) if run_lock_open_may_recover(&e) => {
                    last_open_error = Some(e);
                    std::thread::sleep(GATE_POLL);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            // Restricted by name, so a sweep that removes the file between the open above and this line makes it
            // fail as the open can (NotFound, or access denied while the removal is pending): tried again like the
            // open, never a failed write. The next try creates and restricts a new file.
            #[cfg(windows)]
            if let Err(e) = crate::winacl::restrict_path(&path, false) {
                if !run_lock_open_may_recover(&e) {
                    return Err(e.into());
                }
                last_open_error = Some(e);
                drop(lock);
                std::thread::sleep(GATE_POLL);
                continue;
            }
            #[cfg(test)]
            if let Some(at) = RUN_LOCK_HOOK.with(|hook| hook.borrow_mut().take()) {
                at(&path);
            }
            match lock.try_lock() {
                Ok(()) if path.exists() => {
                    state.run_lock = Some(lock);
                    return Ok(());
                }
                // Locked, but the name has gone: made again after the same pause.
                Ok(()) | Err(TryLockError::WouldBlock) => std::thread::sleep(GATE_POLL),
                Err(TryLockError::Error(e)) => return Err(CoreError::Io(std::io::Error::other(format!("activity run lock: {e}")))),
            }
        }
        // A run without its lock would have its sessions closed by the next sweep: the write fails.
        Err(CoreError::Io(match last_open_error {
            Some(e) => std::io::Error::new(e.kind(), format!("activity run lock: could not be opened: {e}")),
            None => std::io::Error::other("activity run lock: could not be taken"),
        }))
    }

    /// Monthly files, oldest first. Names of any other shape are ignored.
    fn files(&self) -> Result<Vec<FileKey>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut keys = Vec::new();
        for entry in entries {
            if let Some(key) = entry?.file_name().to_str().and_then(FileKey::parse) {
                keys.push(key);
            }
        }
        keys.sort();
        Ok(keys)
    }

    /// The file a record of time `at` is appended to: the month's last part, or the next part
    /// when that one is full.
    fn file_for(&self, at: u64) -> Result<FileKey> {
        let (year, month) = month_of(at);
        let part = self.files()?.into_iter().filter(|k| (k.year, k.month) == (year, month)).map(|k| k.part).max().unwrap_or(1);
        let key = FileKey { year, month, part };
        let full = std::fs::metadata(self.dir.join(key.name())).is_ok_and(|m| m.len() >= MAX_FILE_BYTES);
        Ok(if full { FileKey { part: part + 1, ..key } } else { key })
    }

    /// Append lines under the exclusive file lock, as one write.
    fn append(&self, state: &mut State, at: u64, lines: &[Line], sync: bool) -> Result<()> {
        let mut records = Vec::new();
        for line in lines {
            let json = serde_json::to_string(line).map_err(|e| CoreError::Invalid(e.to_string()))?;
            if json.len() >= MAX_LINE_BYTES {
                return Err(CoreError::Invalid("activity record is too long".into()));
            }
            records.extend_from_slice(json.as_bytes());
            records.push(b'\n');
        }
        self.ensure_ready(state)?;
        let path = self.dir.join(self.file_for(at)?.name());
        let mut opts = OpenOptions::new();
        opts.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path)?;
        // Held until `f` closes: lines of different writers never interleave.
        f.lock()?;
        // Owner-only before this handle's first record. Fail closed, as the audit log does.
        #[cfg(windows)]
        if !state.restricted.contains(&path) {
            crate::winacl::restrict_path(&path, false)?;
            state.restricted.insert(path.clone());
        }
        let len = f.metadata()?.len();
        let mut bytes = Vec::with_capacity(records.len() + 1);
        if len > 0 {
            // A writer that died mid-line must not swallow this record.
            let mut last = [0u8; 1];
            f.seek(SeekFrom::Start(len - 1))?;
            f.read_exact(&mut last)?;
            if last[0] != b'\n' {
                bytes.push(b'\n');
            }
        }
        bytes.extend_from_slice(&records);
        f.write_all(&bytes)?;
        if sync {
            f.sync_data()?;
        }
        Ok(())
    }

    /// Record the start of a session and return its id.
    pub fn begin(&self, start: SessionStart) -> Result<SessionId> {
        if start.app == App::Unknown || start.login_source == LoginSource::Unknown {
            return Err(CoreError::Invalid("activity: unknown app or login source".into()));
        }
        let id = Uuid::new_v4();
        let written = self.is_enabled();
        let started_at = bounded(start.started_at);
        let mut state = self.state();
        if written {
            let line = Line::SessionStart(StartLine {
                session_id: id,
                run_id: Some(self.run_id),
                connection_id: start.connection_id,
                connection_name: clean(&start.connection_name, MAX_TEXT_CHARS),
                folder_path: start.folder_path.into_iter().take(MAX_FOLDER_DEPTH).map(|f| FolderRef { id: f.id, name: clean(&f.name, MAX_TEXT_CHARS) }).collect(),
                protocol: clean(&start.protocol, MAX_PROTOCOL_CHARS).to_lowercase(),
                host: clean_host(&start.host),
                port: start.port,
                username: start.username.map(|u| clean(&u, MAX_TEXT_CHARS)),
                route: start.route.iter().take(MAX_ROUTE).map(|r| clean(r, MAX_TEXT_CHARS)).collect(),
                login_source: start.login_source,
                started_at,
                app: start.app,
                app_version: clean(&start.app_version, MAX_TEXT_CHARS),
                device_name: clean(&start.device_name, MAX_TEXT_CHARS),
            });
            self.append(&mut state, started_at, &[line], true)?;
        }
        state.sessions.insert(id, OpenSession { started_at, reconnects: 0, events: 0, written });
        Ok(id)
    }

    /// Record an event of an open session, now.
    pub fn event(&self, session: SessionId, kind: EventKind, details: BTreeMap<String, String>) -> Result<()> {
        self.event_at(session, now_ms(), kind, details)
    }

    /// Record an event of an open session at time `at`. Details are metadata only: a value whose
    /// key looks sensitive is masked, error text is shortened, everything is bounded.
    pub fn event_at(&self, session: SessionId, at: u64, kind: EventKind, details: BTreeMap<String, String>) -> Result<()> {
        if kind == EventKind::Unknown {
            return Err(CoreError::Invalid("activity: unknown event kind".into()));
        }
        let mut state = self.state();
        let open = state.sessions.get(&session).ok_or_else(|| CoreError::NotFound(format!("open session `{session}`")))?;
        if !open.written || open.events >= MAX_EVENTS_PER_SESSION {
            return Ok(());
        }
        let at = bounded(at).max(open.started_at);
        let line = Line::Event(EventLine { session_id: session, at, kind, details: clean_details(kind, details) });
        self.append(&mut state, at, &[line], false)?;
        if let Some(open) = state.sessions.get_mut(&session) {
            open.events += 1;
            open.reconnects += u32::from(kind == EventKind::Reconnect);
        }
        Ok(())
    }

    /// Record the end of a session. A refused end (bad input, write failure) leaves it open.
    pub fn end(&self, session: SessionId, end: SessionEnd) -> Result<()> {
        if end.end_reason == EndReason::Unknown {
            return Err(CoreError::Invalid("activity: unknown end reason".into()));
        }
        let transcript_sha256 = end.transcript_sha256.as_deref().map(clean_sha256).transpose()?;
        let mut state = self.state();
        let open = state.sessions.get(&session).ok_or_else(|| CoreError::NotFound(format!("open session `{session}`")))?;
        if open.written {
            let ended_at = bounded(end.ended_at).max(open.started_at);
            let connected_at = end.connected_at.map(|c| c.clamp(open.started_at, ended_at));
            let line = Line::SessionEnd(EndLine {
                session_id: session,
                connected_at,
                ended_at,
                duration_ms: connected_at.map_or(0, |c| ended_at - c),
                end_reason: end.end_reason,
                reconnects: end.reconnects.unwrap_or(open.reconnects),
                transcript_path: end.transcript_path.map(|p| clean(&p, MAX_PATH_CHARS)),
                transcript_sha256,
            });
            self.append(&mut state, ended_at, &[line], true)?;
        }
        state.sessions.remove(&session);
        Ok(())
    }

    /// Open a monthly file for reading under the shared lock; `None` when it has gone (purged).
    fn open_read(&self, key: FileKey) -> Result<Option<File>> {
        match File::open(self.dir.join(key.name())) {
            Ok(f) => {
                f.lock_shared()?;
                Ok(Some(f))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Sessions matching `filter`, newest first, one page. The cost is that of reaching the
    /// page from the newest record, not of the whole history.
    pub fn query(&self, filter: &Filter, page: Page) -> Result<Vec<SessionSummary>> {
        let limit = page.limit.min(MAX_PAGE);
        let mut out = Vec::new();
        if limit == 0 {
            return Ok(out);
        }
        let (from_month, to_month) = (filter.from.map(month_of), filter.to.map(month_of));
        // Ends met so far whose start has not been reached yet.
        let mut ends: HashMap<SessionId, EndLine> = HashMap::new();
        let mut matched = 0usize;
        for key in self.files()?.into_iter().rev() {
            let month = (key.year, key.month);
            if from_month.is_some_and(|m| month < m) {
                break;
            }
            // A session that started in range may have ended in a later month.
            let ends_only = to_month.is_some_and(|m| month > m);
            let Some(mut file) = self.open_read(key)? else { continue };
            for_each_line_back(&mut file, |line| {
                if line.starts_with(END_PREFIX) {
                    if let Some(Line::SessionEnd(e)) = parse(line) {
                        // Going backwards, the earliest end of a session is the one that stays.
                        ends.insert(e.session_id, e);
                    }
                } else if !ends_only && line.starts_with(START_PREFIX) {
                    if let Some(Line::SessionStart(s)) = parse(line) {
                        let end = ends.remove(&s.session_id);
                        if filter.matches(&s, end.as_ref()) {
                            if matched >= page.offset {
                                out.push(summary(s, end));
                            }
                            matched += 1;
                        }
                    }
                }
                out.len() < limit
            })?;
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// The events of one session, oldest first.
    pub fn events(&self, session: SessionId) -> Result<Vec<Event>> {
        let id = session.to_string();
        let mut out = Vec::new();
        let mut found_start = false;
        for key in self.files()?.into_iter().rev() {
            let Some(mut file) = self.open_read(key)? else { continue };
            for_each_line_back(&mut file, |line| {
                // Only lines that name the session are parsed.
                if contains(line, id.as_bytes()) {
                    match parse(line) {
                        Some(Line::Event(e)) if e.session_id == session && out.len() < MAX_EVENTS_PER_SESSION as usize => out.push(Event { at: e.at, kind: e.kind, details: e.details }),
                        Some(Line::SessionStart(s)) if s.session_id == session => found_start = true,
                        _ => {}
                    }
                }
                !found_start
            })?;
            if found_start {
                break;
            }
        }
        out.reverse();
        Ok(out)
    }

    /// Runs whose lock is still held, so are alive (this one included). Lock files of runs
    /// that have ended are removed on the way.
    fn live_runs(&self) -> Result<HashSet<Uuid>> {
        let mut live = HashSet::from([self.run_id]);
        // Nothing has been written here yet: no runs, and nothing to create.
        if !self.dir.is_dir() {
            return Ok(live);
        }
        // Held to the end: no run creates its lock while the locks are tested and removed.
        let _gate = self.lock_gate()?;
        for entry in std::fs::read_dir(&self.dir)? {
            let name = entry?.file_name();
            let Some(stem) = name.to_str().and_then(|n| n.strip_prefix("run-")) else { continue };
            // `.lock.tmp`: how builds before the gate made a lock. A dead run's is removed like a
            // lock; one that an old build beside this one holds at this instant is left alone.
            let Some(run) = stem.strip_suffix(".lock").or_else(|| stem.strip_suffix(".lock.tmp")).and_then(|n| Uuid::parse_str(n).ok()) else { continue };
            if run == self.run_id {
                continue;
            }
            if self.run_lock_is_held(&self.dir.join(&name)) {
                live.insert(run);
            }
        }
        Ok(live)
    }

    /// Test the lock of another run. Free: that run has ended, the file is removed and the
    /// answer is false. The file stays locked by this test until it is gone, so a run that takes
    /// this very lock without the gate cannot end up holding a file that is about to vanish.
    /// The order matters: unlocked first and removed second, that run could lock the file in
    /// between, keep it, and be taken for dead by every later sweep.
    fn run_lock_is_held(&self, path: &Path) -> bool {
        let file = OpenOptions::new().write(true).open(path);
        match file.as_ref().map(|f| f.try_lock()) {
            // Nobody holds it: that run has ended.
            Ok(Ok(())) => {
                #[cfg(test)]
                sweep_step(SweepStep::BeforeRemove);
                // `file`, and with it the lock, lives to the end of this function.
                let _ = std::fs::remove_file(path);
                false
            }
            // Held: the run is alive. Gone: an old build has just renamed its temporary file.
            Ok(Err(TryLockError::WouldBlock)) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            // In doubt: the run counts as alive, since a live session is never closed. Said
            // aloud, because if this lasts that run's sessions are never closed as crashed.
            Ok(Err(TryLockError::Error(e))) => {
                eprintln!("bastion: activity run lock {} cannot be tested, its run counts as alive: {e}", path.display());
                true
            }
            Err(e) => {
                eprintln!("bastion: activity run lock {} cannot be opened, its run counts as alive: {e}", path.display());
                true
            }
        }
    }

    /// Close sessions left open by a run that has ended without ending them (crash, power
    /// loss): each gets a `session_end` with `app_crashed`. Call once at start-up, off the main
    /// thread. The end time is the last time known for the session, not `now`. Returns how many
    /// were closed. Two instances starting at the same moment may both close the same orphan, and
    /// a run that ends its session and exits while this sweep is between reading the log and
    /// checking the runs gets a second end after its own; readers keep the first end of a
    /// session, so the later one is harmless. A session of a run that is alive is never closed.
    /// If another instance holds the gate for longer than [`GATE_WAIT`] nothing is closed and the
    /// error is `TimedOut`; the next start-up sweeps again.
    pub fn close_orphans(&self, now: u64) -> Result<usize> {
        #[cfg(test)]
        sweep_step(SweepStep::Start);
        /// The three fields of an event line this scan needs.
        #[derive(Deserialize)]
        struct EventHead {
            session_id: SessionId,
            at: u64,
            kind: EventKind,
        }
        let mut ended: HashSet<SessionId> = HashSet::new();
        // Last event time and reconnect count of each session not seen ended, gathered in the
        // same pass: closing costs one scan however many orphans there are.
        let mut seen: HashMap<SessionId, (u64, u32)> = HashMap::new();
        // Every session without an end, with the run that began it.
        let mut open: Vec<(SessionId, Option<Uuid>, u64, (u64, u32))> = Vec::new();
        for key in self.files()?.into_iter().rev() {
            #[cfg(test)]
            sweep_step(SweepStep::BeforeRead);
            let Some(mut file) = self.open_read(key)? else { continue };
            for_each_line_back(&mut file, |line| {
                if line.starts_with(END_PREFIX) {
                    if let Some(Line::SessionEnd(e)) = parse(line) {
                        ended.insert(e.session_id);
                    }
                } else if line.starts_with(START_PREFIX) {
                    if let Some(Line::SessionStart(s)) = parse(line) {
                        let events = seen.remove(&s.session_id).unwrap_or_default();
                        if !ended.remove(&s.session_id) {
                            open.push((s.session_id, s.run_id, s.started_at, events));
                        }
                    }
                } else if line.starts_with(EVENT_PREFIX) {
                    if let Ok(e) = serde_json::from_slice::<EventHead>(line) {
                        if !ended.contains(&e.session_id) {
                            let (last, reconnects) = seen.entry(e.session_id).or_default();
                            *last = (*last).max(e.at);
                            *reconnects += u32::from(e.kind == EventKind::Reconnect);
                        }
                    }
                }
                true
            })?;
        }
        #[cfg(test)]
        sweep_step(SweepStep::Between);
        // Which runs are alive is found out AFTER the log has been read, never before. A run
        // takes its lock before it writes its first start and holds it for as long as it lives,
        // so the run of every start read above either holds its lock now or has ended. Asked the
        // other way round, a run that started between the two steps would have its start read
        // without being among the live runs, and its live session would be closed as crashed.
        let live = self.live_runs()?;
        let orphans: Vec<_> = open.into_iter().filter(|(_, run, ..)| !run.is_some_and(|r| live.contains(&r))).collect();
        let mut ends = Vec::with_capacity(orphans.len());
        let mut latest = 0;
        for (session, _, started_at, (last_event, reconnects)) in &orphans {
            let ended_at = bounded(*last_event).max(*started_at);
            latest = latest.max(ended_at);
            ends.push(Line::SessionEnd(EndLine {
                session_id: *session,
                connected_at: None,
                ended_at,
                duration_ms: ended_at - started_at,
                end_reason: EndReason::AppCrashed,
                reconnects: *reconnects,
                transcript_path: None,
                transcript_sha256: None,
            }));
        }
        #[cfg(test)]
        sweep_step(SweepStep::BeforeWrite);
        if !ends.is_empty() {
            // One write to the current file, after every start, wherever the starts are.
            self.append(&mut self.state(), bounded(now).max(latest), &ends, true)?;
        }
        Ok(orphans.len())
    }

    /// Delete whole monthly files whose month ended more than `retention_days` before `now`
    /// (0 keeps everything). Returns how many files were deleted. Nothing else is touched.
    /// A file that cannot be deleted now is reported on stderr and tried again next time.
    pub fn purge(&self, retention_days: u32, now: u64) -> Result<usize> {
        if retention_days == 0 {
            return Ok(0);
        }
        let cutoff = now.saturating_sub(u64::from(retention_days) * DAY_MS);
        let mut removed = 0;
        for key in self.files()? {
            let (year, month) = next_month(key.year, key.month);
            if month_start_ms(year, month) <= cutoff {
                // A file another process holds open cannot be deleted on Windows: it is left for
                // the next purge, and the others are still deleted.
                match std::fs::remove_file(self.dir.join(key.name())) {
                    Ok(()) => removed += 1,
                    Err(e) => eprintln!("bastion: activity purge left {}: {e}", key.name()),
                }
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests;
