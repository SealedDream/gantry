//! Unit tests of the activity store (they reach its private parts).
use super::*;


#[test]
fn file_names_round_trip_and_reject_other_shapes() {
    for (name, key) in [("2026-11.jsonl", (2026, 11, 1)), ("2026-01.2.jsonl", (2026, 1, 2)), ("1999-12.17.jsonl", (1999, 12, 17))] {
        let parsed = FileKey::parse(name).unwrap();
        assert_eq!((parsed.year, parsed.month, parsed.part), key);
        assert_eq!(parsed.name(), name);
    }
    for bad in ["2026-13.jsonl", "2026-00.jsonl", "2026-1.jsonl", "2026-11.1.jsonl", "2026-11.02.jsonl", "2026-11.jsonl.bak", "x2026-11.jsonl", "2026-11.json", "run-1.lock", "2026-11..jsonl", "2026-11.-2.jsonl", "", "日本語-11.jsonl"] {
        assert_eq!(FileKey::parse(bad), None, "{bad}");
    }
    assert!(FileKey::parse("2026-11.jsonl") < FileKey::parse("2026-11.2.jsonl"));
    assert!(FileKey::parse("2026-11.9.jsonl") < FileKey::parse("2026-12.jsonl"));
}

#[test]
fn months_convert_both_ways() {
    assert_eq!(month_start_ms(1970, 1), 0);
    assert_eq!(month_of(0), (1970, 1));
    for (year, month) in [(1999, 12), (2000, 2), (2000, 3), (2024, 2), (2026, 11), (2027, 1)] {
        let start = month_start_ms(year, month);
        assert_eq!(month_of(start), (year, month));
        assert_eq!(month_of(start - 1), if month == 1 { (year - 1, 12) } else { (year, month - 1) });
    }
    assert_eq!(month_of(u64::MAX), (9999, 12));
}

#[test]
fn hosts_lose_everything_but_the_host_and_port() {
    assert_eq!(clean_host("web-01.example.test"), "web-01.example.test");
    assert_eq!(clean_host("[fe80::1]:22"), "[fe80::1]:22");
    assert_eq!(clean_host("https://user:pw@host.test:8443/a/b?c=d#f"), "host.test:8443");
    assert_eq!(clean_host("user@host.test"), "host.test");
    assert_eq!(clean_host("https://user:p@w:z@host.test/a"), "host.test");
    // An `@` after a `/`, `?` or `#` is not user-info: nothing is kept.
    assert_eq!(clean_host("https://user:p/w?x#y@z@host.test/a"), HIDDEN);
    assert_eq!(clean_host("host.test/path@x"), HIDDEN);
    assert_eq!(clean_host("https://h/?sig=a@ABCDEF123"), HIDDEN);
    assert_eq!(clean_host("https://host.test:8443/a?b=c#d"), "host.test:8443");
    assert_eq!(clean_host("https://host.test/?mail=a@b c"), HIDDEN);
    assert_eq!(clean_host("höst.example"), "höst.example");
}

#[test]
fn a_host_and_port_is_kept_and_a_bare_user_and_password_is_not_stored() {
    // A host and a port: the part after the one colon is a port number.
    for kept in ["web-01:22", "web-01.example.test:65535", "10.0.0.7:3389", "[fe80::1]:22", "[fe80::1%en0]", "fe80::1", "2001:db8::2:1", "::1", "localhost"] {
        assert_eq!(clean_host(kept), kept, "{kept}");
    }
    // `name:word` is not a host and a port: it has the shape `user:password`.
    for hidden in ["deploy:hunter2", "admin:s3cret-pw", "root:", ":pw", "web-01:0", "web-01:65536", "web-01:22x", "user:pa:ss", "a:b:c:d", "[fe80::1]:pw", "[fe80::1]x", "ssh://deploy:hunter2"] {
        assert_eq!(clean_host(hidden), HIDDEN, "{hidden}");
    }
    // What cannot be told apart stays: a password made only of digits in the port range.
    assert_eq!(clean_host("admin:8080"), "admin:8080");
    // A URL is still cut to its host, with a valid port.
    assert_eq!(clean_host("https://user:pw@host.test:8443/a"), "host.test:8443");
    assert_eq!(clean_host("https://user:pw@host.test:pw2/a"), HIDDEN);
}

#[test]
fn a_long_key_that_names_a_secret_is_still_masked() {
    let key = format!("{}password", "k".repeat(60));
    let d = clean_details(EventKind::Resize, BTreeMap::from([(key, "value".to_string())]));
    assert_eq!(d.values().collect::<Vec<_>>(), [MASK]);
}

/// 2025-11-12 10:00:00 UTC.
const NOV_12: u64 = 1_762_941_600_000;

fn start(at: u64) -> SessionStart {
    SessionStart {
        connection_id: Uuid::new_v4(),
        connection_name: "web-01".into(),
        folder_path: vec![],
        protocol: "ssh".into(),
        host: "web-01.example.test".into(),
        port: Some(22),
        username: Some("deploy".into()),
        route: vec![],
        login_source: LoginSource::Own,
        started_at: at,
        app: App::NativeMac,
        app_version: "1.0.0".into(),
        device_name: "test-mac".into(),
    }
}

/// A second instance that starts a session at any instant of a sweep is alive, so its
/// session is never closed as crashed. No timing: the run starts inside the sweep.
#[test]
fn a_run_that_starts_a_session_during_a_sweep_is_never_closed() {
    let dir = tempfile::tempdir().unwrap();
    let sweeper = ActivityLog::in_dir(dir.path());
    // A real orphan, so the sweep has an end to write.
    let orphan = ActivityLog::in_dir(dir.path()).begin(start(NOV_12)).unwrap();
    let started = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let at = {
        let (started, path) = (started.clone(), dir.path().to_path_buf());
        move |step| {
            // The orphan's lock is removed under the gate; a run cannot start there.
            if step == SweepStep::BeforeRemove {
                return;
            }
            let run = ActivityLog::in_dir(&path);
            let id = run.begin(start(NOV_12 + 1_000)).unwrap();
            started.borrow_mut().push((step, run, id));
        }
    };
    SWEEP_HOOK.with(|hook| *hook.borrow_mut() = Some(Box::new(at)));
    let closed = sweeper.close_orphans(NOV_12 + DAY_MS);
    SWEEP_HOOK.with(|hook| *hook.borrow_mut() = None);
    let closed = closed.unwrap();
    let alive = started.borrow();
    // One monthly file, so one `BeforeRead`: a run that starts after the sweep has begun and
    // before the log is read is covered wherever the sweep asks which runs are alive.
    assert_eq!(alive.iter().map(|(step, ..)| *step).collect::<Vec<_>>(), [SweepStep::Start, SweepStep::BeforeRead, SweepStep::Between, SweepStep::BeforeWrite]);

    let all = sweeper.query(&Filter::default(), Page { offset: 0, limit: 50 }).unwrap();
    for (step, _run, id) in alive.iter() {
        let s = all.iter().find(|s| s.session_id == *id).unwrap();
        assert!(s.open, "the session of a run that started at {step:?} was closed as {:?}", s.end_reason);
    }
    assert_eq!(closed, 1, "only the orphan is closed");
    assert_eq!(all.iter().find(|s| s.session_id == orphan).unwrap().end_reason, Some(EndReason::AppCrashed));
    // The runs are still alive: a later sweep leaves them alone too.
    assert_eq!(sweeper.close_orphans(NOV_12 + DAY_MS).unwrap(), 0);
}

fn run_lock_files(log: &ActivityLog) -> usize {
    std::fs::read_dir(&log.dir).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("run-")).count()
}

/// How long a thread that must be waiting is watched before the test believes it.
const WAIT: std::time::Duration = std::time::Duration::from_millis(300);

/// A run's first write and a sweep exclude each other: while one is in progress (the gate
/// is held) the other waits and then succeeds. Neither fails, and no run lock file can be
/// seen before it is locked.
#[test]
fn a_first_write_and_a_sweep_wait_for_each_other_and_neither_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sweeper = ActivityLog::in_dir(dir.path());
    create_private_dir(&sweeper.dir).unwrap();

    // A sweep is in progress: a first write waits for it.
    let gate = sweeper.lock_gate().unwrap();
    std::thread::scope(|scope| {
        let run = ActivityLog::in_dir(dir.path());
        let writer = scope.spawn(move || {
            let id = run.begin(start(NOV_12)).unwrap();
            (run, id)
        });
        std::thread::sleep(WAIT);
        assert!(!writer.is_finished(), "the first write did not wait for the sweep");
        assert_eq!(run_lock_files(&sweeper), 0, "a run lock appeared while a sweep was in progress");
        drop(gate);
        let (run, id) = writer.join().unwrap();
        assert_eq!(run_lock_files(&sweeper), 1);

        // A first write is in progress: a sweep waits for it, then finds the run alive.
        let gate = run.lock_gate().unwrap();
        let sweep = scope.spawn(|| sweeper.close_orphans(NOV_12 + DAY_MS).unwrap());
        std::thread::sleep(WAIT);
        assert!(!sweep.is_finished(), "the sweep did not wait for the first write");
        drop(gate);
        assert_eq!(sweep.join().unwrap(), 0);
        let end = SessionEnd { connected_at: None, ended_at: NOV_12 + 1, end_reason: EndReason::ClosedByUser, reconnects: None, transcript_path: None, transcript_sha256: None };
        run.end(id, end).unwrap();
    });
    // The run has ended: its lock file goes at the next sweep; the gate file stays.
    assert_eq!(sweeper.close_orphans(NOV_12 + DAY_MS).unwrap(), 0);
    assert_eq!(run_lock_files(&sweeper), 0);
    assert!(sweeper.dir.join(GATE_NAME).is_file());
}

/// How long a call that must give up waiting by itself is given before the test fails.
const RETURNS_WITHIN: std::time::Duration = std::time::Duration::from_secs(8);

fn all_sessions(log: &ActivityLog) -> Vec<SessionSummary> {
    log.query(&Filter::default(), Page { offset: 0, limit: 50 }).unwrap()
}

/// Another instance holds the gate and never lets go (stopped, hung, a stalled disk). The
/// first write of this run does not wait for ever, and the session is still recorded.
#[test]
fn a_first_write_gives_up_waiting_for_a_gate_that_is_never_released_and_still_records() {
    let dir = tempfile::tempdir().unwrap();
    let holder = ActivityLog::in_dir(dir.path());
    create_private_dir(&holder.dir).unwrap();
    let gate = holder.lock_gate().unwrap();
    let run = std::sync::Arc::new(ActivityLog::in_dir(dir.path()));
    let (done, result) = std::sync::mpsc::channel();
    let writer = std::thread::spawn({
        let run = run.clone();
        move || done.send(run.begin(start(NOV_12))).unwrap()
    });
    let got = result.recv_timeout(RETURNS_WITHIN);
    drop(gate);
    writer.join().unwrap();
    let id = got.expect("the first write was still waiting for the gate").expect("the session is recorded although the gate was never free");
    assert_eq!(run_lock_files(&holder), 1, "the run holds its lock");
    assert!(all_sessions(&holder).iter().any(|s| s.session_id == id && s.open));
    // The run is alive and is seen alive.
    assert_eq!(holder.close_orphans(NOV_12 + DAY_MS).unwrap(), 0);
}

/// A sweep that cannot get the gate does not wait for ever and does not test run locks
/// without it: it fails, closes nothing, and works the next time.
#[test]
fn a_sweep_gives_up_waiting_for_a_gate_that_is_never_released_and_closes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let holder = ActivityLog::in_dir(dir.path());
    let orphan = ActivityLog::in_dir(dir.path()).begin(start(NOV_12)).unwrap();
    let gate = holder.lock_gate().unwrap();
    let sweeper = std::sync::Arc::new(ActivityLog::in_dir(dir.path()));
    let (done, result) = std::sync::mpsc::channel();
    let sweep = std::thread::spawn({
        let sweeper = sweeper.clone();
        move || done.send(sweeper.close_orphans(NOV_12 + DAY_MS)).unwrap()
    });
    let got = result.recv_timeout(RETURNS_WITHIN);
    drop(gate);
    sweep.join().unwrap();
    got.expect("the sweep was still waiting for the gate").expect_err("a sweep must not go on without the gate");
    assert!(all_sessions(&holder).iter().any(|s| s.session_id == orphan && s.open), "nothing was closed");
    assert_eq!(sweeper.close_orphans(NOV_12 + DAY_MS).unwrap(), 1, "with the gate free the orphan is closed");
}

/// The gate is never released, so a run takes its lock without it; then the sweep that held
/// the gate comes back and meets the run's lock file before it is locked. The sweep removes
/// it. The run notices, makes its lock again, and no later sweep takes it for dead.
#[test]
fn a_sweep_that_comes_back_while_a_run_locks_without_the_gate_cannot_make_it_look_dead() {
    let dir = tempfile::tempdir().unwrap();
    let stopped_sweep = std::rc::Rc::new(ActivityLog::in_dir(dir.path()));
    create_private_dir(&stopped_sweep.dir).unwrap();
    let gate = stopped_sweep.lock_gate().unwrap();
    let removed = std::rc::Rc::new(std::cell::Cell::new(false));
    let at = {
        let (sweep, removed) = (stopped_sweep.clone(), removed.clone());
        move |path: &Path| removed.set(!sweep.run_lock_is_held(path) && !path.exists())
    };
    RUN_LOCK_HOOK.with(|hook| *hook.borrow_mut() = Some(Box::new(at)));

    let run = ActivityLog::in_dir(dir.path());
    let id = run.begin(start(NOV_12)).unwrap();
    assert!(removed.get(), "the sweep met the lock file unlocked and removed it");
    assert_eq!(run_lock_files(&run), 1, "the run made its lock again");
    drop(gate);

    let later = ActivityLog::in_dir(dir.path());
    assert_eq!(later.close_orphans(NOV_12 + DAY_MS).unwrap(), 0, "a run that is alive was closed");
    assert!(all_sessions(&later).iter().any(|s| s.session_id == id && s.open));
    assert_eq!(run_lock_files(&run), 1);
}

/// How long the sweep is kept stopped just before it removes a lock file. Shorter than the
/// time a run keeps trying for its lock (`RUN_LOCK_TRIES` pauses of `GATE_POLL`).
const SWEEP_STOPPED_FOR: std::time::Duration = std::time::Duration::from_millis(200);

/// Whether another descriptor finds the file at `path` locked.
fn is_locked(path: &Path) -> bool {
    let file = OpenOptions::new().write(true).open(path).unwrap();
    matches!(file.try_lock(), Err(TryLockError::WouldBlock))
}

/// The gate is never released, so a run takes its lock without it. The sweep that held the
/// gate comes back, meets the run's lock file before it is locked, and is stopped at the last
/// instant before it removes the file; the run tries for its lock during that stop. The sweep
/// must still hold the lock there, so the run cannot keep a file that is about to vanish.
/// Fails if the sweep unlocks the file before it removes it.
#[test]
fn a_sweep_holds_a_free_lock_until_it_has_removed_it_so_a_run_never_keeps_a_file_that_vanishes() {
    use std::sync::mpsc::channel;
    let dir = tempfile::tempdir().unwrap();
    let stopped_sweep = ActivityLog::in_dir(dir.path());
    create_private_dir(&stopped_sweep.dir).unwrap();
    let gate = stopped_sweep.lock_gate().unwrap();

    let run = std::sync::Arc::new(ActivityLog::in_dir(dir.path()));
    let (created, created_rx) = channel::<PathBuf>();
    let (go, go_rx) = channel::<()>();
    let (done, done_rx) = channel();
    let done_rx = std::rc::Rc::new(done_rx);
    let writer = std::thread::spawn({
        let run = run.clone();
        move || {
            // The run has created its lock file and waits, not yet locking it, until the
            // sweep stands just before the removal.
            let at = move |path: &Path| {
                created.send(path.to_path_buf()).unwrap();
                let _ = go_rx.recv();
            };
            RUN_LOCK_HOOK.with(|hook| *hook.borrow_mut() = Some(Box::new(at)));
            done.send(run.begin(start(NOV_12))).unwrap();
        }
    });
    let path = created_rx.recv_timeout(RETURNS_WITHIN).expect("the run did not give up waiting for the gate");
    assert!(SWEEP_STOPPED_FOR * 2 < GATE_POLL * RUN_LOCK_TRIES, "the stop must stay well inside the run's tries");

    // (locked by the sweep at the stop, what the run achieved during the stop)
    let at_stop = std::rc::Rc::new(std::cell::RefCell::new(None));
    let at = {
        let (at_stop, path, done_rx) = (at_stop.clone(), path.clone(), done_rx.clone());
        move |step| {
            if step != SweepStep::BeforeRemove {
                return;
            }
            let locked = is_locked(&path);
            go.send(()).unwrap();
            let early = done_rx.recv_timeout(SWEEP_STOPPED_FOR).ok();
            *at_stop.borrow_mut() = Some((locked, early));
        }
    };
    SWEEP_HOOK.with(|hook| *hook.borrow_mut() = Some(Box::new(at)));
    let held = stopped_sweep.run_lock_is_held(&path);
    SWEEP_HOOK.with(|hook| *hook.borrow_mut() = None);
    let (locked_at_stop, early) = at_stop.borrow_mut().take().expect("the sweep did not reach the removal");
    let finished_during_stop = early.is_some();
    let id = early.unwrap_or_else(|| done_rx.recv_timeout(RETURNS_WITHIN).expect("the run never got its lock")).unwrap();
    writer.join().unwrap();
    drop(gate);

    assert!(!held, "the sweep met the lock file unlocked, so it removes it");
    // What matters: the run is alive, holds a lock that is in the directory, and is not closed.
    assert!(path.exists(), "the run holds a lock on a file that is no longer in the directory");
    assert!(is_locked(&path), "the file in the directory is not the one the run has locked");
    assert_eq!(run_lock_files(&run), 1);
    let later = ActivityLog::in_dir(dir.path());
    assert_eq!(later.close_orphans(NOV_12 + DAY_MS).unwrap(), 0, "a run that is alive was closed");
    assert!(all_sessions(&later).iter().any(|s| s.session_id == id && s.open));
    assert!(path.exists() && is_locked(&path), "the sweep removed the lock of a run that is alive");
    // Why it holds: the sweep had not let go of the file when it was about to remove it.
    assert!(locked_at_stop, "the sweep had unlocked the file before removing it");
    assert!(!finished_during_stop, "the run took its lock while the sweep was about to remove the file");
}

fn fail_run_lock_opens(mut errors: impl FnMut(u32) -> Option<std::io::Error> + 'static) -> std::rc::Rc<std::cell::Cell<u32>> {
    let opens = std::rc::Rc::new(std::cell::Cell::new(0));
    let at = {
        let opens = opens.clone();
        move || {
            opens.set(opens.get() + 1);
            errors(opens.get())
        }
    };
    RUN_LOCK_OPEN_HOOK.with(|hook| *hook.borrow_mut() = Some(Box::new(at)));
    opens
}

/// The errors an open gives while a sweep is removing that very file (Windows: delete
/// pending). The run tries again and the session is recorded.
#[test]
fn an_open_refused_while_the_lock_file_is_being_removed_is_tried_again() {
    let mut errors = vec![std::io::ErrorKind::PermissionDenied.into(), std::io::ErrorKind::NotFound.into()];
    // ERROR_ACCESS_DENIED and ERROR_SHARING_VIOLATION as Windows reports them.
    #[cfg(windows)]
    errors.extend([std::io::Error::from_raw_os_error(5), std::io::Error::from_raw_os_error(32)]);
    let refused = errors.len() as u32;
    let dir = tempfile::tempdir().unwrap();
    let run = ActivityLog::in_dir(dir.path());
    let opens = fail_run_lock_opens(move |_| errors.pop());
    let id = run.begin(start(NOV_12));
    RUN_LOCK_OPEN_HOOK.with(|hook| *hook.borrow_mut() = None);
    let id = id.expect("the session is recorded once the open succeeds");
    assert_eq!(opens.get(), refused + 1);
    assert_eq!(run_lock_files(&run), 1);
    assert!(all_sessions(&run).iter().any(|s| s.session_id == id && s.open));
    assert_eq!(ActivityLog::in_dir(dir.path()).close_orphans(NOV_12 + DAY_MS).unwrap(), 0, "the run is alive");
}

/// The retry is bounded, and the error says why. An error of another kind is not retried.
#[test]
fn an_open_that_keeps_being_refused_fails_after_the_bound_and_another_error_fails_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let run = ActivityLog::in_dir(dir.path());
    let opens = fail_run_lock_opens(|_| Some(std::io::ErrorKind::PermissionDenied.into()));
    let refused = run.begin(start(NOV_12));
    let tries = opens.get();
    let opens = fail_run_lock_opens(|_| Some(std::io::Error::other("disk on fire")));
    let other = run.begin(start(NOV_12));
    RUN_LOCK_OPEN_HOOK.with(|hook| *hook.borrow_mut() = None);

    assert_eq!(tries, RUN_LOCK_TRIES);
    match refused {
        Err(CoreError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}"),
        other => panic!("expected the open error, got {other:?}"),
    }
    assert_eq!(opens.get(), 1, "an error that cannot pass is not retried");
    assert!(matches!(other, Err(CoreError::Io(_))));
    assert_eq!(all_sessions(&run).len(), 0, "nothing is written without the run lock");
    // With the open working again the same handle records.
    run.begin(start(NOV_12)).unwrap();
}

/// Builds before the gate made locks as `run-<id>.lock.tmp`. One left by a run that died is
/// removed by a sweep; one that an old build still holds is left alone.
/// How long the second handle of the Windows tests is kept: a few of the run's tries
/// (`GATE_POLL` apart), far fewer than `RUN_LOCK_TRIES`.
#[cfg(windows)]
const HANDLE_KEPT: std::time::Duration = std::time::Duration::from_millis(100);

/// Begin a session on its own thread while `gate` is held, so the run takes its lock without
/// the gate; `during` runs once the run has given up on the gate and is trying for its lock.
#[cfg(windows)]
fn begin_without_the_gate(run: &std::sync::Arc<ActivityLog>, gate: File, during: impl FnOnce()) -> SessionId {
    let writer = std::thread::spawn({
        let run = run.clone();
        move || run.begin(start(NOV_12))
    });
    std::thread::sleep(GATE_WAIT + HANDLE_KEPT);
    during();
    let id = writer.join().unwrap().expect("the session is recorded once the second handle is closed");
    drop(gate);
    id
}

/// Windows only, real file system, nothing injected (LOG-CORE-01-FU-GATE-TIMEOUT, M1). A sweep
/// that tested this run's lock file removes it while a second handle on it is still open. On a
/// volume without POSIX delete the file is then only marked: opening its name fails (access
/// denied) until that handle closes. The run must try again and record, on a lock file that is
/// in the directory, and a later sweep must see it alive.
#[cfg(windows)]
#[test]
fn a_run_records_while_a_sweep_holds_a_second_handle_on_its_removed_lock_file() {
    let dir = tempfile::tempdir().unwrap();
    let holder = ActivityLog::in_dir(dir.path());
    create_private_dir(&holder.dir).unwrap();
    let run = std::sync::Arc::new(ActivityLog::in_dir(dir.path()));
    let path = run.run_lock_path(run.run_id);
    // The file as a run leaves it between creating and locking it, and the sweep's handle on it.
    let second = OpenOptions::new().create(true).truncate(false).write(true).open(&path).unwrap();
    std::fs::remove_file(&path).expect("the sweep removes the lock file while its handle is open");
    let pending = path.exists() || OpenOptions::new().write(true).open(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied);
    eprintln!("lock file after removal with a handle open: {}", if pending { "delete pending (no POSIX delete)" } else { "gone at once (POSIX delete)" });

    let gate = holder.lock_gate().unwrap();
    let id = begin_without_the_gate(&run, gate, || drop(second));

    assert!(path.exists(), "the run holds a lock on a file that is not in the directory");
    assert!(is_locked(&path), "the run's lock file is not locked");
    assert_eq!(run_lock_files(&holder), 1);
    assert!(all_sessions(&holder).iter().any(|s| s.session_id == id && s.open));
    assert_eq!(holder.close_orphans(NOV_12 + DAY_MS).unwrap(), 0, "a later sweep closed a live run");
    assert!(all_sessions(&holder).iter().any(|s| s.session_id == id && s.open));
}

/// Windows only, nothing injected: another handle holds the run's lock file open without
/// sharing it, so the run's open fails with the real `ERROR_SHARING_VIOLATION` (32). The open
/// is tried again and the session is recorded once that handle closes.
#[cfg(windows)]
#[test]
fn a_run_records_after_a_real_sharing_violation_on_opening_its_lock_file() {
    use std::os::windows::fs::OpenOptionsExt;
    const SHARING_VIOLATION: i32 = 32;
    let dir = tempfile::tempdir().unwrap();
    let holder = ActivityLog::in_dir(dir.path());
    create_private_dir(&holder.dir).unwrap();
    let run = std::sync::Arc::new(ActivityLog::in_dir(dir.path()));
    let path = run.run_lock_path(run.run_id);
    let exclusive = OpenOptions::new().create(true).truncate(false).write(true).share_mode(0).open(&path).unwrap();
    let refused = OpenOptions::new().write(true).open(&path).expect_err("the lock file is held without sharing");
    assert_eq!(refused.raw_os_error(), Some(SHARING_VIOLATION), "Windows gave another error than a sharing violation: {refused}");
    assert!(run_lock_open_may_recover(&refused), "the real error is not one the run tries again on");

    let gate = holder.lock_gate().unwrap();
    let id = begin_without_the_gate(&run, gate, || drop(exclusive));

    assert!(path.exists() && is_locked(&path));
    assert!(all_sessions(&holder).iter().any(|s| s.session_id == id && s.open));
    assert_eq!(holder.close_orphans(NOV_12 + DAY_MS).unwrap(), 0, "a later sweep closed a live run");
}

/// Windows only: a handle that is never closed. The run gives up after its bounded tries with
/// the cause in the error, and writes nothing without a lock.
#[cfg(windows)]
#[test]
fn a_sharing_violation_that_never_ends_fails_the_first_write_with_its_cause() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = tempfile::tempdir().unwrap();
    let run = ActivityLog::in_dir(dir.path());
    create_private_dir(&run.dir).unwrap();
    let path = run.run_lock_path(run.run_id);
    let _exclusive = OpenOptions::new().create(true).truncate(false).write(true).share_mode(0).open(&path).unwrap();
    let error = run.begin(start(NOV_12)).expect_err("a run without its lock must not write").to_string();
    assert!(error.contains("activity run lock: could not be opened"), "{error}");
    assert!(all_sessions(&run).is_empty(), "a session was written without the run lock");
}

#[test]
fn a_temporary_lock_file_of_an_older_build_is_removed_unless_it_is_held() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    create_private_dir(&log.dir).unwrap();
    let left_behind = log.dir.join(format!("run-{}.lock.tmp", Uuid::new_v4()));
    File::create(&left_behind).unwrap();
    let held_path = log.dir.join(format!("run-{}.lock.tmp", Uuid::new_v4()));
    let held = File::create(&held_path).unwrap();
    held.try_lock().unwrap();

    assert_eq!(log.close_orphans(NOV_12).unwrap(), 0);
    assert!(!left_behind.exists(), "the file a dead run left behind is still there");
    assert!(held_path.exists(), "a file that is held was removed");
}

#[test]
fn lines_are_read_backwards_across_blocks_and_long_lines_are_passed_over() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lines");
    let mut expected = Vec::new();
    let mut text = String::new();
    for i in 0..3000 {
        // Lines of varying length, so block edges fall everywhere.
        let line = format!("{i}:{}", "x".repeat(i % 211));
        text.push_str(&line);
        text.push('\n');
        expected.push(line);
        if i % 1000 == 500 {
            text.push_str(&"y".repeat(MAX_LINE_BYTES * 3 + i));
            text.push_str("\n\n");
        }
    }
    // No newline after the last line.
    text.push_str("last");
    expected.push("last".into());
    std::fs::write(&path, &text).unwrap();
    expected.reverse();

    let mut got = Vec::new();
    for_each_line_back(&mut File::open(&path).unwrap(), |l| {
        got.push(String::from_utf8(l.to_vec()).unwrap());
        true
    })
    .unwrap();
    assert_eq!(got, expected);

    let mut first_two = Vec::new();
    for_each_line_back(&mut File::open(&path).unwrap(), |l| {
        first_two.push(l.len());
        first_two.len() < 2
    })
    .unwrap();
    assert_eq!(first_two.len(), 2, "the scan stops when asked to");
}
