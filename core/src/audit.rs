//! Structured security audit log: append-only JSON Lines, owner-only permissions, secret
//! redaction, and a SHA-256 hash chain so edits, deletions or reordering are *detectable*.
//!
//! This is tamper-evident, not tamper-proof: a local administrator can rewrite the whole file.
//! Tamper-resistant evidence requires forwarding to a protected central collector.
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, LazyLock, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{CoreError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    AppLock,
    Authentication,
    CredentialAccess,
    Connection,
    Tunnel,
    HypervisorAction,
    BulkOperation,
    PolicyChange,
    ImportExport,
    Plugin,
    Update,
    SecurityWarning,
    Task,
    RemoteManagement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    Failure,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub ts_unix_ms: u128,
    pub category: Category,
    pub action: String,
    pub actor: Option<String>,
    pub target: Option<String>,
    pub outcome: Outcome,
    pub correlation_id: Option<Uuid>,
    pub details: BTreeMap<String, String>,
    /// Hash of the previous record (hex); all zeros for the first record.
    pub prev_hash: String,
}

pub(crate) const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const SENSITIVE_KEY_PARTS: &[&str] = &["password", "passphrase", "secret", "token", "private_key", "otp", "ticket", "cookie"];

/// Whether a field name looks like it holds a secret (shared by audit redaction and export).
pub fn is_sensitive_key(k: &str) -> bool {
    let k = k.to_lowercase();
    SENSITIVE_KEY_PARTS.iter().any(|p| k.contains(p))
}

/// Several `AuditLog`s (in this process or others) may append to one file. Each append holds an
/// exclusive OS lock on the log file and takes the predecessor hash from the file's current
/// last record, so writers never fork the chain.
pub struct AuditLog {
    path: PathBuf,
    /// Hash of the last record and the file length it was read at; refreshed under the lock
    /// whenever the file grew because another writer appended.
    last_hash: String,
    known_len: Option<u64>,
    /// Windows: owner-only ACL already applied to the log file by this instance.
    #[cfg(windows)]
    acl_applied: bool,
    /// This open let the full check run behind it: nothing is recorded, and no connect is handed over, until
    /// that check has passed ([`AuditLog::confirm`]).
    pending: bool,
}

impl AuditLog {
    /// Open (or create) a log. The whole chain is checked on every open: synchronously the first time in this
    /// process, after a failed check, or when the cheap guard ([`guard_holds`]) sees the file shrink or the last
    /// verified record change; otherwise on a background thread, so a connect does not pay for the log's length.
    /// Fail closed all the same: a connect waits for that check alongside its handshake ([`AuditLog::confirm`]) and
    /// fails, the first one included, when the chain is broken.
    pub fn open(path: impl Into<PathBuf>) -> Result<AuditLog> {
        let path = path.into();
        let (last_hash, pending) = if path.exists() { open_checked(&path)? } else { (GENESIS.to_string(), false) };
        // No length is taken here: read apart from the verify above, it could already include a record another
        // writer appended in between while `last_hash` does not, and the first `record` would then chain to a stale
        // hash. With no known length the first `record` reads the tail under its own lock.
        Ok(AuditLog {
            path,
            last_hash,
            known_len: None,
            #[cfg(windows)]
            acl_applied: false,
            pending,
        })
    }

    /// The file whose full check this open still waits for, if any: [`await_check`] it off an async runtime.
    pub fn pending_check(&self) -> Option<PathBuf> {
        self.pending.then(|| self.path.clone())
    }

    /// Wait for the full check this open let run behind it; `Corrupt` when it failed. A connect calls it (through
    /// [`await_check`]) before it hands the session over or records its success.
    pub fn confirm(&mut self) -> Result<()> {
        if self.pending {
            await_check(&self.path)?;
            self.pending = false;
        }
        Ok(())
    }

    pub fn record(
        &mut self,
        category: Category,
        action: &str,
        target: Option<&str>,
        outcome: Outcome,
        details: BTreeMap<String, String>,
    ) -> Result<AuditEvent> {
        self.record_correlated(category, action, target, outcome, details, None)
    }

    /// [`AuditLog::record`] with a correlation id that ties related records together: for
    /// connect-related events, the session id of the activity store (`activity`).
    pub fn record_correlated(
        &mut self,
        category: Category,
        action: &str,
        target: Option<&str>,
        outcome: Outcome,
        details: BTreeMap<String, String>,
        correlation_id: Option<Uuid>,
    ) -> Result<AuditEvent> {
        let details = details
            .into_iter()
            .map(|(k, v)| if is_sensitive_key(&k) { (k, "***".to_string()) } else { (k, v) })
            .collect();
        let event = AuditEvent {
            id: Uuid::new_v4(),
            ts_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0),
            category,
            action: action.into(),
            actor: std::env::var("USER").or_else(|_| std::env::var("USERNAME")).ok(),
            target: target.map(str::to_string),
            outcome,
            correlation_id,
            details,
            prev_hash: String::new(),
        };
        let mut opts = OpenOptions::new();
        opts.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&self.path)?;
        // Held until `f` closes: no other writer appends between reading the tail and writing.
        f.lock()?;
        let len = f.metadata()?.len();
        if self.known_len != Some(len) {
            self.last_hash = last_record_hash(&mut f, len)?;
        }
        let event = AuditEvent { prev_hash: self.last_hash.clone(), ..event };
        let line = serde_json::to_string(&event).map_err(|e| CoreError::Invalid(e.to_string()))?;
        // Owner-only before the first record is written; also tightens a log created by an
        // older build. Fail closed: no record is written if the ACL cannot be applied.
        #[cfg(windows)]
        if !self.acl_applied {
            crate::winacl::restrict_path(&self.path, false)?;
            self.acl_applied = true;
        }
        writeln!(f, "{line}")?;
        f.sync_data()?;
        self.last_hash = hash(&line);
        self.known_len = Some(f.metadata()?.len());
        Ok(event)
    }
}

/// Longest record read back from the tail (records are small; this bounds a corrupt file).
const MAX_RECORD_BYTES: u64 = 1024 * 1024;

/// Hash of the last line of a log `len` bytes long (`GENESIS` when empty). Reads backwards from
/// the end only as far as that line, so appending stays cheap however long the log is.
fn last_record_hash(f: &mut std::fs::File, len: u64) -> Result<String> {
    if len == 0 {
        return Ok(GENESIS.to_string());
    }
    let window = len.min(MAX_RECORD_BYTES + 1);
    f.seek(SeekFrom::Start(len - window))?;
    let mut tail = vec![0u8; window as usize];
    f.read_exact(&mut tail)?;
    let body = tail.strip_suffix(b"\n").ok_or_else(|| CoreError::Corrupt("audit log does not end with a complete record".into()))?;
    let start = match body.iter().rposition(|b| *b == b'\n') {
        Some(i) => i + 1,
        None if window == len => 0,
        None => return Err(CoreError::Corrupt("audit record too long".into())),
    };
    let line = std::str::from_utf8(&body[start..]).map_err(|_| CoreError::Corrupt("audit record is not UTF-8".into()))?;
    Ok(hash(line))
}

pub(crate) fn hash(line: &str) -> String {
    hex::encode(Sha256::digest(line.as_bytes()))
}

/// Verify the hash chain; returns the hash of the last record. The length is read under a shared lock, so a
/// writer's half-appended record is never mistaken for corruption; the lock is then released and only the bytes
/// up to that length are read. Writers only append, so those bytes are whole records, and a long check never
/// holds up a writer (each `record` takes the exclusive lock).
pub fn verify(path: &Path) -> Result<String> {
    verify_to(path).map(|c| c.hash)
}

/// [`verify`], also returning the file length the chain was checked at (read under the same lock).
fn verify_to(path: &Path) -> Result<Verified> {
    let f = std::fs::File::open(path)?;
    f.lock_shared()?;
    let len = f.metadata()?.len();
    f.unlock()?;
    let mut expected = GENESIS.to_string();
    for (n, line) in BufReader::new(LockWaitReader(f).take(len)).lines().enumerate() {
        let line = line?;
        let event: AuditEvent = serde_json::from_str(&line)
            .map_err(|e| CoreError::Corrupt(format!("audit record {}: {e}", n + 1)))?;
        if event.prev_hash != expected {
            return Err(CoreError::Corrupt(format!("audit chain broken at record {}", n + 1)));
        }
        expected = hash(&line);
    }
    Ok(Verified { len, hash: expected })
}

/// Windows file locks are mandatory: while a writer holds the exclusive lock of [`AuditLog::record`] (an append and
/// its fsync), a read by another handle fails with `ERROR_LOCK_VIOLATION` (33). The check reads without a lock so
/// that it never holds up a writer; on that error it waits for the writer and reads the same bytes again. The bytes
/// are never skipped: a read that keeps failing past [`LOCK_WAIT`] fails the check (fail closed). On Unix locks are
/// advisory, so reads never fail this way.
struct LockWaitReader(std::fs::File);

/// Longest a check waits on writers holding the log, per read.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(windows)]
const ERROR_LOCK_VIOLATION: i32 = 33;

impl Read for LockWaitReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(windows)]
        {
            let end = std::time::Instant::now() + LOCK_WAIT;
            loop {
                match self.0.read(buf) {
                    Err(e) if e.raw_os_error() == Some(ERROR_LOCK_VIOLATION) && std::time::Instant::now() < end => {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    other => return other,
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = LOCK_WAIT;
            self.0.read(buf)
        }
    }
}

/// A chain verified in full up to `len` bytes, ending in the record whose hash is `hash`.
#[derive(Clone)]
struct Verified {
    len: u64,
    hash: String,
}

/// What this process knows about one log file's chain.
#[derive(Default)]
struct Checkpoint {
    verified: Option<Verified>,
    /// The last full check failed: every open checks synchronously (and fails) until one passes.
    failed: bool,
    /// A background check is running; `rerun` asks it to check once more when it ends (coalescing).
    running: bool,
    rerun: bool,
}

static CHECKPOINTS: LazyLock<Mutex<HashMap<PathBuf, Checkpoint>>> = LazyLock::new(Mutex::default);

fn checkpoints() -> MutexGuard<'static, HashMap<PathBuf, Checkpoint>> {
    CHECKPOINTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The full check on open, moved off the hot path when it is safe to (see [`AuditLog::open`]). Returns the last
/// hash and whether the check still runs behind the open.
fn open_checked(path: &Path) -> Result<(String, bool)> {
    let known = {
        let map = checkpoints();
        map.get(path).filter(|c| !c.failed).and_then(|c| c.verified.clone())
    };
    match known {
        Some(v) if guard_holds(path, &v)? && schedule_background_verify(path) => Ok((v.hash, true)),
        _ => verify_now(path).map(|h| (h, false)),
    }
}

/// The cheap synchronous guard: the file has not shrunk, and the record that ended the verified chain is
/// still there, byte for byte, at the same place. Reads one record, however long the log is.
fn guard_holds(path: &Path, v: &Verified) -> Result<bool> {
    let mut f = std::fs::File::open(path)?;
    f.lock_shared()?;
    let len = f.metadata()?.len();
    if len < v.len {
        return Ok(false);
    }
    // A record the guard cannot read (cut, not UTF-8) means the file changed: check it in full.
    Ok(last_record_hash(&mut f, v.len).is_ok_and(|h| h == v.hash))
}

/// Verify in full now and record the outcome.
fn verify_now(path: &Path) -> Result<String> {
    let outcome = verify_to(path);
    let mut map = checkpoints();
    let cp = map.entry(path.to_path_buf()).or_default();
    match outcome {
        Ok(v) => {
            let hash = v.hash.clone();
            cp.verified = Some(v);
            cp.failed = false;
            Ok(hash)
        }
        Err(e) => {
            cp.verified = None;
            cp.failed = true;
            Err(e)
        }
    }
}

/// Run a full check on a background thread: at most one per file at a time; a request while one runs makes
/// it run once more afterwards, so appends during a check are covered too. False when no thread could be started:
/// the caller then checks synchronously.
fn schedule_background_verify(path: &Path) -> bool {
    {
        let mut map = checkpoints();
        let cp = map.entry(path.to_path_buf()).or_default();
        if cp.running {
            cp.rerun = true;
            return true;
        }
        cp.running = true;
    }
    let path = path.to_path_buf();
    let spawned = std::thread::Builder::new().name("audit-verify".into()).spawn({
        let path = path.clone();
        move || background_verify(&path)
    });
    if spawned.is_err() {
        let mut map = checkpoints();
        if let Some(cp) = map.get_mut(&path) {
            cp.running = false;
        }
        CHECK_DONE.notify_all();
        return false;
    }
    true
}

/// Signalled whenever a background check ends.
static CHECK_DONE: Condvar = Condvar::new();

/// Longest wait for a background check; past it the log counts as unchecked and fails closed.
const CHECK_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Wait until no background check runs for `path`, then fail with `Corrupt` if the last check failed.
pub fn await_check(path: &Path) -> Result<()> {
    let map = checkpoints();
    let (map, timeout) = CHECK_DONE
        .wait_timeout_while(map, CHECK_WAIT, |m| m.get(path).is_some_and(|c| c.running))
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if timeout.timed_out() {
        return Err(CoreError::Corrupt("audit log check did not finish".into()));
    }
    if map.get(path).is_some_and(|c| c.failed) {
        return Err(CoreError::Corrupt("audit log check failed: the hash chain is broken".into()));
    }
    Ok(())
}

/// Clears `running` if a background check panics, and fails closed: the next open checks synchronously and
/// fails until the chain checks out. Without it a stuck `running` would skip every later background check.
struct RunningGuard<'a>(&'a Path);

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let mut map = checkpoints();
        let cp = map.entry(self.0.to_path_buf()).or_default();
        cp.running = false;
        cp.rerun = false;
        cp.verified = None;
        cp.failed = true;
        drop(map);
        CHECK_DONE.notify_all();
    }
}

fn background_verify(path: &Path) {
    let _guard = RunningGuard(path);
    loop {
        let outcome = verify_to(path);
        let mut map = checkpoints();
        let cp = map.entry(path.to_path_buf()).or_default();
        match outcome {
            // A pass never clears a failure: this check may have read the file before a synchronous one found
            // it changed. Only a synchronous check (the next open) clears it, once the chain checks out again.
            Ok(v) if !cp.failed => cp.verified = Some(v),
            Ok(_) => {}
            Err(e) => {
                // The same alert as a synchronous check: reported now, and every later open fails until the
                // chain checks out again.
                eprintln!("bastion: audit log check failed: {e}");
                cp.verified = None;
                cp.failed = true;
            }
        }
        if !std::mem::take(&mut cp.rerun) {
            cp.running = false;
            drop(map);
            CHECK_DONE.notify_all();
            return;
        }
    }
}

/// Tests: wait until no background check runs for `path`.
#[cfg(test)]
pub(crate) fn wait_for_background_verify(path: &Path) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while checkpoints().get(path).is_some_and(|c| c.running) {
        assert!(std::time::Instant::now() < end, "background audit check did not finish");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Win10 run of #971: `open` read the file length apart from its verify, so a record another writer appended in
    /// between could be counted in the length but not in the hash. The first `record` then saw "unchanged", skipped the
    /// tail and chained to a stale hash. The window cannot be hit on demand, so this test shows both halves: the stale
    /// state breaks the chain, and `open` no longer produces it.
    #[test]
    fn a_record_appended_while_a_log_opens_is_chained_to() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut other = AuditLog::open(&path).unwrap();
        other.record(Category::Connection, "one", None, Outcome::Success, BTreeMap::new()).unwrap();

        // The old open: hash from the verify, then the length after another writer appended.
        let mut stale = AuditLog::open(&path).unwrap();
        other.record(Category::Connection, "two", None, Outcome::Success, BTreeMap::new()).unwrap();
        stale.known_len = Some(std::fs::metadata(&path).unwrap().len());
        stale.record(Category::Connection, "three", None, Outcome::Success, BTreeMap::new()).unwrap();
        assert!(matches!(verify(&path), Err(CoreError::Corrupt(_))), "a stale length chains to a stale hash");

        // The fixed open keeps no length, so the same interleaving chains correctly.
        let fresh_dir = tempfile::tempdir().unwrap();
        let path = fresh_dir.path().join("audit.jsonl");
        let mut other = AuditLog::open(&path).unwrap();
        other.record(Category::Connection, "one", None, Outcome::Success, BTreeMap::new()).unwrap();
        let mut opened = AuditLog::open(&path).unwrap();
        assert_eq!(opened.known_len, None, "open keeps no length of its own");
        other.record(Category::Connection, "two", None, Outcome::Success, BTreeMap::new()).unwrap();
        opened.record(Category::Connection, "three", None, Outcome::Success, BTreeMap::new()).unwrap();
        verify(&path).expect("the chain holds");
    }
}

/// The full chain check on open, moved off the connect path (grow-only stores audit, 2026-11-16).
#[cfg(test)]
mod off_path_check_tests {
    use super::*;

    /// Write `n` valid chained records quickly (no fsync per record, as `record` does).
    fn write_chain(path: &Path, n: usize) {
        let mut f = std::io::BufWriter::new(OpenOptions::new().create(true).append(true).open(path).unwrap());
        let mut prev = GENESIS.to_string();
        let details: BTreeMap<String, String> = [("protocol".to_string(), "ssh".to_string())].into();
        for i in 0..n {
            let e = AuditEvent {
                id: Uuid::new_v4(),
                ts_unix_ms: i as u128,
                category: Category::Connection,
                action: "connection.open".into(),
                actor: Some("tester".into()),
                target: Some(format!("host-{i:06}")),
                outcome: Outcome::Success,
                correlation_id: None,
                details: details.clone(),
                prev_hash: prev,
            };
            let line = serde_json::to_string(&e).unwrap();
            prev = hash(&line);
            writeln!(f, "{line}").unwrap();
        }
    }

    fn connect(path: &Path) -> Result<()> {
        AuditLog::open(path)?.record(Category::Connection, "connection.open", Some("web"), Outcome::Success, BTreeMap::new()).map(|_| ())
    }

    /// A connect as the orchestrator makes it: open, wait for the check that ran alongside the handshake, record.
    fn gated_connect(path: &Path) -> Result<()> {
        let mut log = AuditLog::open(path)?;
        log.confirm()?;
        log.record(Category::Connection, "connection.open", Some("web"), Outcome::Success, BTreeMap::new()).map(|_| ())
    }

    /// Replace `from` with `to` (same length) in record `n` (0-based), keeping the file length.
    fn edit_record(path: &Path, n: usize, from: &str, to: &str) {
        assert_eq!(from.len(), to.len());
        let text = std::fs::read_to_string(path).unwrap();
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        assert!(lines[n].contains(from));
        lines[n] = lines[n].replacen(from, to, 1);
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn at_fifty_thousand_records_an_open_and_connect_cost_stays_flat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_chain(&path, 50_000);

        let first = std::time::Instant::now();
        connect(&path).unwrap();
        let full_check = first.elapsed();

        // The median of 50 later connects: a later open that walked the log would make every one of them slow, while
        // a single fsync or antivirus spike on one append (seen on Windows) does not show the open's cost.
        let mut times: Vec<std::time::Duration> = (0..50)
            .map(|_| {
                let t = std::time::Instant::now();
                connect(&path).unwrap();
                t.elapsed()
            })
            .collect();
        times.sort();
        let median = times[times.len() / 2];
        let slowest = times[times.len() - 1];
        wait_for_background_verify(&path);
        eprintln!("audit open+record at 50k records: first (full check) {full_check:?}, median of 50 later {median:?}, slowest {slowest:?}");
        verify(&path).expect("the chain holds after the appends");
        assert!(
            median * 5 < full_check,
            "a later open must not walk the log: median {median:?}, the full check {full_check:?}"
        );
    }

    #[test]
    fn tampering_with_a_middle_record_is_still_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_chain(&path, 200);
        gated_connect(&path).unwrap();
        wait_for_background_verify(&path);

        edit_record(&path, 100, "host-000100", "host-999999");
        // The guard sees the end unchanged, so the open itself goes through, but its record waits for the full
        // check: the first connect after the edit fails, as before the check moved off the hot path.
        assert!(matches!(gated_connect(&path), Err(CoreError::Corrupt(_))), "the first connect after the edit fails");
        for _ in 0..3 {
            assert!(matches!(gated_connect(&path), Err(CoreError::Corrupt(_))), "and every later one");
        }
    }

    #[test]
    fn a_changed_last_checked_record_fails_the_open_itself() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_chain(&path, 50);
        connect(&path).unwrap();
        wait_for_background_verify(&path);
        // This open's background check covers the whole file; the record below then chains to its last record.
        let mut log = AuditLog::open(&path).unwrap();
        wait_for_background_verify(&path);
        log.record(Category::Connection, "connection.open", Some("web"), Outcome::Success, BTreeMap::new()).unwrap();
        // The guard reads the record that ended the last check; a change there is checked in full at once.
        let lines = std::fs::read_to_string(&path).unwrap().lines().count();
        edit_record(&path, lines - 2, "connection.open", "connection.opex");
        assert!(matches!(AuditLog::open(&path), Err(CoreError::Corrupt(_))));
    }

    #[test]
    fn a_shortened_log_fails_the_open_itself() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_chain(&path, 50);
        AuditLog::open(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.remove(10);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert!(matches!(AuditLog::open(&path), Err(CoreError::Corrupt(_))));
    }

    #[test]
    fn a_restored_log_opens_again_after_a_failed_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_chain(&path, 20);
        let good = std::fs::read(&path).unwrap();
        AuditLog::open(&path).unwrap();
        std::fs::write(&path, &good[..good.len() / 2]).unwrap();
        assert!(AuditLog::open(&path).is_err());
        std::fs::write(&path, good).unwrap();
        AuditLog::open(&path).expect("the chain checks out again");
    }
}
