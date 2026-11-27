//! Activity store (`bastion_core::activity`): the acceptance list of LOG-CORE-01.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bastion_core::activity::{
    ActivityLog, App, EndReason, EventKind, Filter, FolderRef, LoginSource, Page, ResultFilter, SessionEnd, SessionStart, MAX_FILE_BYTES, MAX_VALUE_CHARS,
};
use bastion_core::audit::{self, AuditLog};
use bastion_core::broker::{Broker, LeaseLimits, SystemClock};
use bastion_core::connect::{ActivitySink, CredentialRef, Orchestrator, SecretUse};
use bastion_core::model::{Connection, Protocol};
use bastion_core::policy::Policy;
use bastion_core::settings::{self, Settings};
use bastion_core::CoreError;
use uuid::Uuid;

/// 2025-11-12 10:00:00 UTC in Unix milliseconds: in the past, because times after tomorrow are
/// clamped by the store.
const NOV_12: u64 = 1_762_941_600_000;
const DAY: u64 = 86_400_000;
const PAGE: Page = Page { offset: 0, limit: 50 };

fn start(connection: Uuid, at: u64) -> SessionStart {
    SessionStart {
        connection_id: connection,
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

fn end(connected_at: Option<u64>, ended_at: u64, reason: EndReason) -> SessionEnd {
    SessionEnd { connected_at, ended_at, end_reason: reason, reconnects: None, transcript_path: None, transcript_sha256: None }
}

fn for_connection(id: Uuid) -> Filter {
    Filter { connection: Some(id), ..Filter::default() }
}

fn details(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir.join("activity")).unwrap().map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|e| e == "jsonl")).collect();
    v.sort();
    v
}

fn names(dir: &Path) -> Vec<String> {
    files(dir).iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect()
}

fn all_text(dir: &Path) -> String {
    files(dir).iter().map(|p| std::fs::read_to_string(p).unwrap()).collect()
}

#[test]
fn a_start_and_an_end_make_one_summary_with_duration_and_reason() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();

    let id = log.begin(start(c, NOV_12)).unwrap();
    log.end(id, end(Some(NOV_12 + 2_000), NOV_12 + 62_000, EndReason::ClosedByUser)).unwrap();

    let got = log.query(&for_connection(c), PAGE).unwrap();
    assert_eq!(got.len(), 1);
    let s = &got[0];
    assert_eq!(s.session_id, id);
    assert_eq!(s.connection_name, "web-01");
    assert_eq!(s.started_at, NOV_12);
    assert_eq!(s.connected_at, Some(NOV_12 + 2_000));
    assert_eq!(s.ended_at, Some(NOV_12 + 62_000));
    assert_eq!(s.duration_ms, Some(60_000));
    assert_eq!(s.end_reason, Some(EndReason::ClosedByUser));
    assert!(!s.open);
    assert_eq!(names(dir.path()), ["2025-11.jsonl"]);
}

#[test]
fn a_session_that_never_connected_has_no_duration_and_cannot_end_twice() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();
    let id = log.begin(start(c, NOV_12)).unwrap();
    log.end(id, end(None, NOV_12 + 500, EndReason::AuthFailed)).unwrap();
    assert!(matches!(log.end(id, end(None, NOV_12 + 900, EndReason::Failed)), Err(CoreError::NotFound(_))));
    assert!(matches!(log.event_at(id, NOV_12 + 900, EventKind::Resize, details(&[])), Err(CoreError::NotFound(_))));

    let got = log.query(&for_connection(c), PAGE).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].duration_ms, Some(0));
    assert_eq!(got[0].end_reason, Some(EndReason::AuthFailed));
}

#[test]
fn newest_first_and_paged() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();
    let mut ids = vec![];
    for i in 0..7u64 {
        // Spread over three months: the query must walk the monthly files.
        let at = NOV_12 - 60 * DAY + i * 12 * DAY;
        let id = log.begin(start(c, at)).unwrap();
        log.end(id, end(Some(at), at + 1_000, EndReason::RemoteClosed)).unwrap();
        ids.push(id);
    }
    assert_eq!(names(dir.path()), ["2025-09.jsonl", "2025-10.jsonl", "2025-11.jsonl"]);
    ids.reverse();
    let page = |offset| log.query(&for_connection(c), Page { offset, limit: 3 }).unwrap().iter().map(|s| s.session_id).collect::<Vec<_>>();
    assert_eq!(page(0), ids[..3]);
    assert_eq!(page(3), ids[3..6]);
    assert_eq!(page(6), ids[6..]);
    assert!(page(7).is_empty());
}

#[test]
fn an_end_in_a_later_month_is_joined_to_its_start() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();
    let started = NOV_12 - 20 * DAY; // October
    let id = log.begin(start(c, started)).unwrap();
    log.end(id, end(Some(started), NOV_12, EndReason::NetworkLost)).unwrap();
    assert_eq!(names(dir.path()), ["2025-10.jsonl", "2025-11.jsonl"]);

    // A date range that ends before the month holding the end record.
    let f = Filter { connection: Some(c), from: Some(started - DAY), to: Some(started + DAY), ..Filter::default() };
    let got = log.query(&f, PAGE).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].end_reason, Some(EndReason::NetworkLost));
    assert_eq!(got[0].duration_ms, Some(20 * DAY));
}

#[test]
fn filters_by_date_protocol_user_and_result() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();
    let ok = log.begin(start(c, NOV_12)).unwrap();
    log.end(ok, end(Some(NOV_12), NOV_12 + 10, EndReason::ClosedByUser)).unwrap();
    let failed = log.begin(SessionStart { protocol: "rdp".into(), username: Some("Admin".into()), ..start(c, NOV_12 + DAY) }).unwrap();
    log.end(failed, end(None, NOV_12 + DAY + 10, EndReason::Timeout)).unwrap();
    let open = log.begin(SessionStart { protocol: "vnc".into(), username: None, ..start(c, NOV_12 + 2 * DAY) }).unwrap();

    let ids = |f: Filter| log.query(&f, PAGE).unwrap().iter().map(|s| s.session_id).collect::<Vec<_>>();
    assert_eq!(ids(Filter::default()), vec![open, failed, ok]);
    assert_eq!(ids(Filter { protocol: Some("rdp".into()), ..Filter::default() }), vec![failed]);
    assert_eq!(ids(Filter { user: Some("admin".into()), ..Filter::default() }), vec![failed]);
    assert_eq!(ids(Filter { result: Some(ResultFilter::Ok), ..Filter::default() }), vec![ok]);
    assert_eq!(ids(Filter { result: Some(ResultFilter::Failed), ..Filter::default() }), vec![failed]);
    assert_eq!(ids(Filter { result: Some(ResultFilter::Open), ..Filter::default() }), vec![open]);
    assert_eq!(ids(Filter { from: Some(NOV_12 + DAY), ..Filter::default() }), vec![open, failed]);
    assert_eq!(ids(Filter { to: Some(NOV_12 + DAY), ..Filter::default() }), vec![failed, ok]);
    assert_eq!(ids(Filter { connection: Some(Uuid::new_v4()), ..Filter::default() }), Vec::<Uuid>::new());
}

#[test]
fn a_start_without_an_end_is_closed_as_crashed_by_the_next_run() {
    let dir = tempfile::tempdir().unwrap();
    let c = Uuid::new_v4();
    let crashed = {
        let earlier_run = ActivityLog::in_dir(dir.path());
        let id = earlier_run.begin(start(c, NOV_12)).unwrap();
        earlier_run.event_at(id, NOV_12 + 5_000, EventKind::Resize, details(&[("size", "1920x1080")])).unwrap();
        id
        // Dropped without an end: the run is gone, as after a crash.
    };

    let log = ActivityLog::in_dir(dir.path());
    let live = log.begin(start(c, NOV_12 + DAY)).unwrap();
    assert_eq!(log.close_orphans(NOV_12 + 3 * DAY).unwrap(), 1);
    assert_eq!(log.close_orphans(NOV_12 + 3 * DAY).unwrap(), 0, "closing is done once");

    let got = log.query(&for_connection(c), PAGE).unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].session_id, live);
    assert!(got[0].open, "a session of this run is left alone");
    assert_eq!(got[1].session_id, crashed);
    assert_eq!(got[1].end_reason, Some(EndReason::AppCrashed));
    // The end time is the last time known for the session, not the time of the next launch.
    assert_eq!(got[1].ended_at, Some(NOV_12 + 5_000));
    assert_eq!(got[1].duration_ms, Some(5_000));
}

#[test]
fn a_session_of_another_running_instance_is_not_an_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let c = Uuid::new_v4();
    let other_instance = ActivityLog::in_dir(dir.path());
    let theirs = other_instance.begin(start(c, NOV_12)).unwrap();

    let log = ActivityLog::in_dir(dir.path());
    assert_eq!(log.close_orphans(NOV_12 + DAY).unwrap(), 0);
    other_instance.end(theirs, end(Some(NOV_12), NOV_12 + 1_000, EndReason::AppQuit)).unwrap();
    assert_eq!(log.query(&for_connection(c), PAGE).unwrap()[0].end_reason, Some(EndReason::AppQuit));
}

#[test]
fn folder_history_includes_subfolders_and_survives_a_move_or_delete() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let (customers, acme, other) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let path = |ids: &[(Uuid, &str)]| ids.iter().map(|(id, name)| FolderRef { id: *id, name: name.to_string() }).collect::<Vec<_>>();
    let c = Uuid::new_v4();

    // Recorded while the connection was in Customers / Acme.
    let old = log.begin(SessionStart { folder_path: path(&[(customers, "Customers"), (acme, "Acme")]), ..start(c, NOV_12) }).unwrap();
    log.end(old, end(Some(NOV_12), NOV_12 + 10, EndReason::ClosedByUser)).unwrap();
    // The connection is then moved to Other and used again.
    let moved = log.begin(SessionStart { folder_path: path(&[(other, "Other")]), ..start(c, NOV_12 + DAY) }).unwrap();
    log.end(moved, end(Some(NOV_12 + DAY), NOV_12 + DAY + 10, EndReason::ClosedByUser)).unwrap();

    let in_folder = |f: Uuid| log.query(&Filter { folder: Some(f), ..Filter::default() }, PAGE).unwrap().iter().map(|s| s.session_id).collect::<Vec<_>>();
    assert_eq!(in_folder(customers), vec![old], "a parent folder shows sessions of its subfolders");
    assert_eq!(in_folder(acme), vec![old], "the old folder keeps the session after the move");
    assert_eq!(in_folder(other), vec![moved]);
    // Nothing in the store depends on the library: a deleted connection keeps its history.
    let got = log.query(&Filter { folder: Some(acme), ..Filter::default() }, PAGE).unwrap();
    assert_eq!(got[0].folder_path.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), ["Customers", "Acme"]);
}

#[test]
fn sensitive_details_are_masked_and_long_values_are_cut() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();
    let long = "x".repeat(10_000);
    let id = log.begin(SessionStart { connection_name: long.clone(), device_name: "dev\u{7}ice\nname".into(), ..start(c, NOV_12) }).unwrap();
    log.event_at(
        id,
        NOV_12 + 1,
        EventKind::FileTransfer,
        details(&[
            ("password", "hunter2-secret-value"),
            ("access_token", "tok-secret-value"),
            ("name", &long),
            ("error", "login failed: password=hunter2-secret-value rejected\nsecond line"),
            ("direction", "upload"),
        ]),
    )
    .unwrap();

    let events = log.events(id).unwrap();
    assert_eq!(events.len(), 1);
    let d = &events[0].details;
    assert_eq!(d["password"], "***");
    assert_eq!(d["access_token"], "***");
    assert_eq!(d["direction"], "upload");
    assert_eq!(d["error"], "Failed (details hidden)");
    assert_eq!(d["name"].chars().count(), MAX_VALUE_CHARS);
    assert!(d["name"].ends_with('…'));

    let s = &log.query(&for_connection(c), PAGE).unwrap()[0];
    assert_eq!(s.connection_name.chars().count(), 256);
    assert_eq!(s.device_name, "dev ice name");

    let text = all_text(dir.path());
    assert!(!text.contains("hunter2"), "a secret reached the store");
    assert!(!text.contains("tok-secret"), "a secret reached the store");
    assert!(text.lines().all(|l| l.len() < 4_000), "a stored line is not bounded");
}

#[test]
fn a_url_given_as_host_is_reduced_to_the_host_name() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();
    log.begin(SessionStart { host: "https://admin:url-secret-value@portal.example.test:8443/login?token=query-secret-value#frag".into(), ..start(c, NOV_12) }).unwrap();
    assert_eq!(log.query(&for_connection(c), PAGE).unwrap()[0].host, "portal.example.test:8443");
    let text = all_text(dir.path());
    assert!(!text.contains("url-secret") && !text.contains("query-secret"));
}

/// Review H1: a password may hold any character, also the ones that end a URL's authority.
#[test]
fn the_device_name_is_one_short_line() {
    let name = bastion_core::activity::device_name();
    assert!(!name.is_empty(), "this computer has a name");
    assert!(name.chars().count() <= 256 && !name.chars().any(char::is_control), "{name:?}");
}

#[test]
fn a_bare_user_and_password_given_as_host_is_not_stored() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();
    let mut s = start(c, NOV_12);
    s.host = "deploy:n2-bare-secret".into();
    log.begin(s).unwrap();
    let mut s = start(c, NOV_12 + 1);
    s.host = "web-01.example.test:2222".into();
    log.begin(s).unwrap();

    let stored = all_text(dir.path());
    assert!(!stored.contains("n2-bare-secret"), "a password given as the host reached the store");
    let hosts: Vec<String> = log.query(&for_connection(c), PAGE).unwrap().into_iter().map(|s| s.host).collect();
    assert_eq!(hosts, ["web-01.example.test:2222", "(hidden)"], "a host and port is kept; user:password is hidden");
}

#[test]
fn no_part_of_a_url_password_reaches_the_host_whatever_characters_it_holds() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    for (given, host) in [
        ("https://admin:pa/ss-h1secret@web.example/x", "(hidden)"),
        ("https://admin:p#w-h1secret@web.example", "(hidden)"),
        ("https://admin:p?w-h1secret@web.example:8443/a?b=c", "(hidden)"),
        ("https://admin:p@ss-h1secret@web.example", "web.example"),
        ("https://admin:p:w-h1secret@web.example", "web.example"),
        ("admin:bare-h1secret@web.example", "web.example"),
        ("admin:ba/re-h1secret@web.example", "(hidden)"),
        // Note N1: an `@` after a `/`, `?` or `#` is not user-info, and what follows it may be
        // a signature or a token from the query string.
        ("https://h/?sig=a@ABCDEF123", "(hidden)"),
        ("https://h.example/path@n1secret.example", "(hidden)"),
        ("https://h.example:8443/?next=/x", "h.example:8443"),
        ("https://admin:h1secret@[fe80::1]:8443/x", "[fe80::1]:8443"),
        ("[fe80::1]:22", "[fe80::1]:22"),
        ("web-01.example.test", "web-01.example.test"),
    ] {
        let c = Uuid::new_v4();
        log.begin(SessionStart { host: given.into(), ..start(c, NOV_12) }).unwrap();
        assert_eq!(log.query(&for_connection(c), PAGE).unwrap()[0].host, host, "{given}");
    }
    // What is left after the cut must look like a host, or nothing of it is kept.
    let c = Uuid::new_v4();
    log.begin(SessionStart { host: "not a host; h1secret".into(), ..start(c, NOV_12) }).unwrap();
    assert_eq!(log.query(&for_connection(c), PAGE).unwrap()[0].host, "(hidden)");
    let text = all_text(dir.path());
    assert!(!text.contains("h1secret") && !text.contains("admin"), "user-info reached the store");
    assert!(!text.contains("ABCDEF123") && !text.contains("n1secret"), "text after an `@` in the path or query reached the store");
}

/// Review M1: details are an allow-list per event kind, and no value may look like a secret.
#[test]
fn a_detail_under_a_key_the_event_kind_does_not_know_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let id = log.begin(start(Uuid::new_v4(), NOV_12)).unwrap();
    log.event_at(
        id,
        NOV_12,
        EventKind::FileTransfer,
        details(&[
            ("command", "mysql -pm1secret-in-command"),
            ("last_error", "login failed for m1secret-in-error"),
            ("cmd", "export KEY=m1secret-in-cmd"),
            ("name", "token: m1secret-in-name"),
            ("result", "Bearer m1secret-in-result"),
            ("direction", "download"),
            ("bytes", "2048"),
        ]),
    )
    .unwrap();
    // The same key is fine for a kind that lists it, and unknown for one that does not.
    log.event_at(id, NOV_12, EventKind::Resize, details(&[("width", "1920"), ("height", "1080"), ("direction", "upload")])).unwrap();

    let events = log.events(id).unwrap();
    let keys = |i: usize| events[i].details.keys().map(String::as_str).collect::<Vec<_>>();
    assert_eq!(keys(0), ["bytes", "direction", "name", "result"]);
    assert_eq!(events[0].details["name"], "(hidden)");
    assert_eq!(events[0].details["result"], "(hidden)");
    assert_eq!(events[0].details["bytes"], "2048");
    assert_eq!(keys(1), ["height", "width"]);
    assert!(!all_text(dir.path()).contains("m1secret"), "a secret reached the store");
}

/// Note N4: a tunnel's remote host is a host, so it gets the host rule, not the free-text rule.
#[test]
fn a_tunnel_remote_host_is_reduced_like_a_session_host() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let id = log.begin(start(Uuid::new_v4(), NOV_12)).unwrap();
    for remote in ["https://svc:n4secret@db.internal:5432/admin?key=n4secret", "db.internal/?sig=a@n4secret", "db.internal"] {
        log.event_at(id, NOV_12, EventKind::Tunnel, details(&[("state", "opened"), ("remote_host", remote), ("remote_port", "5432")])).unwrap();
    }
    let hosts: Vec<String> = log.events(id).unwrap().iter().map(|e| e.details["remote_host"].clone()).collect();
    assert_eq!(hosts, ["db.internal:5432", "(hidden)", "db.internal"]);
    assert!(!all_text(dir.path()).contains("n4secret") && !all_text(dir.path()).contains("svc"));
}

/// Review M3: a time far in the future must not create a file that is never purged.
#[test]
fn times_in_the_far_future_are_clamped_to_tomorrow() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();
    const YEAR_9000: u64 = 221_845_392_000_000;
    let tomorrow = bastion_core::activity::now_ms() + DAY + 60_000;
    let id = log.begin(start(c, YEAR_9000)).unwrap();
    log.event_at(id, YEAR_9000 + 1, EventKind::Resize, details(&[("width", "10")])).unwrap();
    log.end(id, end(Some(YEAR_9000), u64::MAX, EndReason::ClosedByUser)).unwrap();

    let s = &log.query(&for_connection(c), PAGE).unwrap()[0];
    assert!(s.started_at <= tomorrow, "{}", s.started_at);
    assert!(s.ended_at.unwrap() <= tomorrow && s.connected_at.unwrap() <= tomorrow);
    assert!(log.events(id).unwrap()[0].at <= tomorrow);
    assert!(names(dir.path()).iter().all(|n| n.as_str() < "2100"), "{:?}", names(dir.path()));
    // An orphan is not closed into the far future either.
    drop(log);
    let next = ActivityLog::in_dir(dir.path());
    let other = Uuid::new_v4();
    {
        let crashed = ActivityLog::in_dir(dir.path());
        crashed.begin(start(other, NOV_12)).unwrap();
    }
    assert_eq!(next.close_orphans(u64::MAX).unwrap(), 1);
    assert!(names(dir.path()).iter().all(|n| n.as_str() < "2100"), "{:?}", names(dir.path()));
}

/// Review M2: another instance sweeping dead lock files at the instant a run takes its lock
/// must never leave that run looking dead, and must never make the run's first write fail.
///
/// Each new run is released together with one sweep of each of two other instances, so the
/// sweeps overlap the run's first write, its end and its exit. The test does a fixed amount of
/// work (the sweepers do not spin), so it also ends in bounded time on a loaded machine. The
/// instants themselves are tested without timing in `core/src/activity.rs`
/// (`a_run_that_starts_a_session_during_a_sweep_is_never_closed`,
/// `a_first_write_and_a_sweep_wait_for_each_other_and_neither_fails`).
#[test]
fn a_run_that_is_just_starting_is_never_taken_for_dead() {
    const RUNS: u64 = 400;
    const SWEEPERS: usize = 2;
    let dir = tempfile::tempdir().unwrap();
    let c = Uuid::new_v4();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let go = Arc::new(std::sync::Barrier::new(SWEEPERS + 1));
    let sweepers: Vec<_> = (0..SWEEPERS)
        .map(|_| {
            let (path, stop, go) = (dir.path().to_path_buf(), stop.clone(), go.clone());
            std::thread::spawn(move || {
                let log = ActivityLog::in_dir(&path);
                let mut closed = 0;
                loop {
                    go.wait();
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        return closed;
                    }
                    closed += log.close_orphans(NOV_12 + DAY).unwrap();
                }
            })
        })
        .collect();
    for i in 0..RUNS {
        go.wait();
        // A new run each time: its first write creates and takes its lock.
        let run = ActivityLog::in_dir(dir.path());
        let id = run.begin(start(c, NOV_12 + i)).unwrap();
        std::thread::yield_now();
        run.end(id, end(Some(NOV_12 + i), NOV_12 + i + 1, EndReason::ClosedByUser)).unwrap();
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    go.wait();
    let closed: usize = sweepers.into_iter().map(|s| s.join().unwrap()).sum();
    let got = ActivityLog::in_dir(dir.path()).query(&for_connection(c), Page { offset: 0, limit: 500 }).unwrap();
    assert_eq!(got.len(), RUNS as usize);
    let crashed = got.iter().filter(|s| s.end_reason == Some(EndReason::AppCrashed)).count();
    // `closed` counts second ends written after a run's own end (harmless: readers keep the first).
    assert_eq!(crashed, 0, "live sessions were closed as crashed ({closed} ends written by sweeps)");
    // No lock file of an ended run is left behind after a sweep.
    ActivityLog::in_dir(dir.path()).close_orphans(NOV_12 + DAY).unwrap();
    let left = std::fs::read_dir(dir.path().join("activity")).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("run-")).count();
    assert_eq!(left, 0, "lock files of ended runs were left behind");
}

/// Review M4: every orphan gets its own last event time and reconnect count from the one scan.
#[test]
fn many_orphans_are_closed_with_their_own_last_event_time() {
    let dir = tempfile::tempdir().unwrap();
    let c = Uuid::new_v4();
    let mut ids = vec![];
    {
        let crashed_run = ActivityLog::in_dir(dir.path());
        for i in 0..150u64 {
            let at = NOV_12 + i * 10_000;
            let id = crashed_run.begin(start(c, at)).unwrap();
            for r in 0..(i % 3) {
                crashed_run.event_at(id, at + 100 + r, EventKind::Reconnect, details(&[("attempt", "1")])).unwrap();
            }
            if i % 2 == 0 {
                crashed_run.event_at(id, at + 5_000 + i, EventKind::Resize, details(&[("width", "800")])).unwrap();
            }
            ids.push(id);
        }
    }
    let log = ActivityLog::in_dir(dir.path());
    assert_eq!(log.close_orphans(NOV_12 + 30 * DAY).unwrap(), 150);
    let got = log.query(&for_connection(c), Page { offset: 0, limit: 500 }).unwrap();
    assert_eq!(got.len(), 150);
    for s in &got {
        let i = ids.iter().position(|id| *id == s.session_id).unwrap() as u64;
        let last = if i.is_multiple_of(2) {
            5_000 + i
        } else if !i.is_multiple_of(3) {
            100 + i % 3 - 1
        } else {
            0
        };
        assert_eq!(s.end_reason, Some(EndReason::AppCrashed));
        assert_eq!(s.duration_ms, Some(last), "session {i}");
        assert_eq!(s.ended_at, Some(s.started_at + last), "session {i}");
        assert_eq!(s.reconnects, Some((i % 3) as u32), "session {i}");
    }
}

/// Review M4, timed: `cargo test --release --test activity_tests closing_2000 -- --ignored --nocapture`
#[ignore = "timed: run with --ignored --nocapture"]
#[test]
fn closing_2000_orphans_over_a_large_history_is_one_pass() {
    let dir = tempfile::tempdir().unwrap();
    let activity = dir.path().join("activity");
    std::fs::create_dir_all(&activity).unwrap();
    let c = Uuid::new_v4();
    let mut text = String::new();
    for i in 0..40_000u64 {
        let id = Uuid::new_v4();
        let at = NOV_12 + i * 1_000;
        text.push_str(&format!(
            "{{\"type\":\"session_start\",\"session_id\":\"{id}\",\"run_id\":\"{id}\",\"connection_id\":\"{c}\",\"connection_name\":\"web-01\",\"folder_path\":[],\"protocol\":\"ssh\",\"host\":\"web-01.example.test\",\"port\":22,\"username\":\"deploy\",\"route\":[],\"login_source\":\"own\",\"started_at\":{at},\"app\":\"native-mac\",\"app_version\":\"1.0.0\",\"device_name\":\"test-mac\"}}\n"
        ));
        text.push_str(&format!("{{\"type\":\"event\",\"session_id\":\"{id}\",\"at\":{},\"kind\":\"resize\",\"details\":{{\"width\":\"800\"}}}}\n", at + 200));
        // One session in twenty never got its end.
        if i % 20 != 0 {
            text.push_str(&format!(
                "{{\"type\":\"session_end\",\"session_id\":\"{id}\",\"connected_at\":{at},\"ended_at\":{},\"duration_ms\":500,\"end_reason\":\"closed_by_user\",\"reconnects\":0,\"transcript_path\":null,\"transcript_sha256\":null}}\n",
                at + 500
            ));
        }
    }
    std::fs::write(activity.join("2025-11.jsonl"), &text).unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let t = std::time::Instant::now();
    assert_eq!(log.close_orphans(NOV_12 + 60 * DAY).unwrap(), 2_000);
    let took = t.elapsed();
    eprintln!("close_orphans: 2,000 orphans over {} lines ({} MiB): {took:?}", text.lines().count(), text.len() / (1024 * 1024));
    assert!(took < std::time::Duration::from_secs(5), "closing 2,000 orphans took {took:?}");
}

#[test]
fn too_many_details_and_bad_input_are_bounded_or_refused() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();
    let id = log.begin(start(c, NOV_12)).unwrap();
    let many: BTreeMap<String, String> = (0..100).map(|i| (format!("token-{i:03}"), "v".to_string())).collect();
    log.event_at(id, NOV_12, EventKind::Task, many).unwrap();
    assert_eq!(log.events(id).unwrap()[0].details.len(), 24);

    assert!(matches!(log.event_at(id, NOV_12, EventKind::Unknown, details(&[])), Err(CoreError::Invalid(_))));
    assert!(matches!(log.begin(SessionStart { app: App::Unknown, ..start(c, NOV_12) }), Err(CoreError::Invalid(_))));
    let bad_hash = SessionEnd { transcript_path: Some("/logs/a.log".into()), transcript_sha256: Some("not-a-hash".into()), ..end(None, NOV_12, EndReason::Failed) };
    assert!(matches!(log.end(id, bad_hash), Err(CoreError::Invalid(_))));
    // A refused end leaves the session open, so the caller can end it properly.
    let good = SessionEnd { transcript_path: Some("/logs/a.log".into()), transcript_sha256: Some("ab".repeat(32)), reconnects: Some(3), ..end(Some(NOV_12), NOV_12 + 1, EndReason::RemoteClosed) };
    log.end(id, good).unwrap();
    let s = &log.query(&for_connection(c), PAGE).unwrap()[0];
    assert_eq!(s.transcript_path.as_deref(), Some("/logs/a.log"));
    assert_eq!(s.transcript_sha256.as_deref(), Some("ab".repeat(32).as_str()));
    assert_eq!(s.reconnects, Some(3));
}

#[test]
fn reconnect_events_are_counted_when_the_caller_gives_no_figure() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();
    let id = log.begin(start(c, NOV_12)).unwrap();
    log.event_at(id, NOV_12 + 1, EventKind::Reconnect, details(&[("attempt", "1")])).unwrap();
    log.event_at(id, NOV_12 + 2, EventKind::Reconnect, details(&[("attempt", "2")])).unwrap();
    log.event_at(id, NOV_12 + 3, EventKind::Clipboard, details(&[("direction", "to-remote"), ("bytes", "12")])).unwrap();
    log.end(id, end(Some(NOV_12), NOV_12 + 10, EndReason::ClosedByUser)).unwrap();

    assert_eq!(log.query(&for_connection(c), PAGE).unwrap()[0].reconnects, Some(2));
    let kinds: Vec<EventKind> = log.events(id).unwrap().iter().map(|e| e.kind).collect();
    assert_eq!(kinds, [EventKind::Reconnect, EventKind::Reconnect, EventKind::Clipboard], "events come back oldest first");
    assert!(log.events(Uuid::new_v4()).unwrap().is_empty());
}

#[test]
fn two_writers_at_once_never_interleave_or_lose_a_line() {
    let dir = tempfile::tempdir().unwrap();
    let c = Uuid::new_v4();
    const SESSIONS: usize = 200;
    let writers: Vec<_> = (0..2)
        .map(|w| {
            let path = dir.path().to_path_buf();
            std::thread::spawn(move || {
                // Its own handle, as a second process would have.
                let log = ActivityLog::in_dir(&path);
                for i in 0..SESSIONS {
                    let at = NOV_12 + (i * 2 + w) as u64;
                    let id = log.begin(SessionStart { connection_name: "n".repeat(200), ..start(c, at) }).unwrap();
                    log.event_at(id, at, EventKind::Tunnel, details(&[("state", "opened")])).unwrap();
                    log.end(id, end(Some(at), at + 1, EndReason::ClosedByUser)).unwrap();
                }
            })
        })
        .collect();
    // One shared handle used from two threads as well.
    let shared = Arc::new(ActivityLog::in_dir(dir.path()));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let log = shared.clone();
            std::thread::spawn(move || {
                for i in 0..SESSIONS {
                    let id = log.begin(start(c, NOV_12 + i as u64)).unwrap();
                    log.end(id, end(None, NOV_12 + i as u64, EndReason::Failed)).unwrap();
                }
            })
        })
        .collect();
    for t in writers.into_iter().chain(threads) {
        t.join().unwrap();
    }

    let text = all_text(dir.path());
    assert_eq!(text.lines().count(), 2 * SESSIONS * 3 + 2 * SESSIONS * 2);
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("every line is one whole record");
        assert!(v["type"].is_string());
    }
    let got = shared.query(&for_connection(c), Page { offset: 0, limit: 500 }).unwrap();
    assert_eq!(got.len(), 500);
    assert!(got.iter().all(|s| !s.open), "an end was lost");
    assert_eq!(shared.query(&for_connection(c), Page { offset: 500, limit: 500 }).unwrap().len(), 300);
}

#[test]
fn a_torn_or_foreign_line_is_skipped_and_does_not_swallow_the_next_record() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();
    let a = log.begin(start(c, NOV_12)).unwrap();
    // A line from some other tool, and a writer that died mid-line.
    let file = &files(dir.path())[0];
    let mut text = std::fs::read_to_string(file).unwrap();
    text.push_str("not json\n{\"type\":\"session_start\",\"session_id\":\"trunc");
    std::fs::write(file, text).unwrap();

    let b = log.begin(start(c, NOV_12 + 1)).unwrap();
    let got = log.query(&for_connection(c), PAGE).unwrap();
    assert_eq!(got.iter().map(|s| s.session_id).collect::<Vec<_>>(), vec![b, a]);
}

#[test]
fn purge_removes_only_files_older_than_the_limit() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();
    for days_ago in [400, 100, 45, 0] {
        let at = NOV_12 - days_ago * DAY;
        let id = log.begin(start(c, at)).unwrap();
        log.end(id, end(Some(at), at + 1, EndReason::ClosedByUser)).unwrap();
    }
    let activity = dir.path().join("activity");
    std::fs::write(activity.join("notes.txt"), "not ours").unwrap();
    std::fs::write(activity.join("2020-01.jsonl.bak"), "not ours").unwrap();
    std::fs::write(activity.join("2020-1.jsonl"), "not ours").unwrap();
    assert_eq!(names(dir.path()), ["2020-1.jsonl", "2024-10.jsonl", "2025-08.jsonl", "2025-09.jsonl", "2025-11.jsonl"]);

    assert_eq!(log.purge(0, NOV_12).unwrap(), 0, "0 keeps everything");
    assert_eq!(log.purge(365, NOV_12).unwrap(), 1);
    assert_eq!(names(dir.path()), ["2020-1.jsonl", "2025-08.jsonl", "2025-09.jsonl", "2025-11.jsonl"]);
    // September ended 42 days before 12 November: inside 90 days, outside 30.
    assert_eq!(log.purge(90, NOV_12).unwrap(), 0);
    assert_eq!(log.purge(30, NOV_12).unwrap(), 2);
    assert_eq!(names(dir.path()), ["2020-1.jsonl", "2025-11.jsonl"]);
    assert!(activity.join("notes.txt").exists() && activity.join("2020-01.jsonl.bak").exists(), "purge touched a file that is not a monthly log");
    assert_eq!(log.query(&for_connection(c), PAGE).unwrap().len(), 1);
}

#[test]
fn a_full_file_continues_in_the_next_part_and_is_still_queried() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let c = Uuid::new_v4();
    let first = log.begin(start(c, NOV_12)).unwrap();
    // Grow the month's file past the limit without writing 32 MiB of records.
    let file = files(dir.path())[0].clone();
    std::fs::OpenOptions::new().write(true).open(&file).unwrap().set_len(MAX_FILE_BYTES + 1).unwrap();
    std::fs::OpenOptions::new().append(true).open(&file).and_then(|mut f| std::io::Write::write_all(&mut f, b"\n")).unwrap();

    let second = log.begin(start(c, NOV_12 + 1)).unwrap();
    log.end(first, end(Some(NOV_12), NOV_12 + 5, EndReason::ClosedByUser)).unwrap();
    assert_eq!(names(dir.path()), ["2025-11.2.jsonl", "2025-11.jsonl"]);
    let got = log.query(&for_connection(c), PAGE).unwrap();
    assert_eq!(got.iter().map(|s| s.session_id).collect::<Vec<_>>(), vec![second, first]);
    assert_eq!(got[1].end_reason, Some(EndReason::ClosedByUser));
}

#[cfg(unix)]
#[test]
fn the_directory_and_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let id = log.begin(start(Uuid::new_v4(), NOV_12)).unwrap();
    log.end(id, end(None, NOV_12, EndReason::Failed)).unwrap();
    let activity = dir.path().join("activity");
    assert_eq!(std::fs::metadata(&activity).unwrap().permissions().mode() & 0o777, 0o700);
    let mut seen = 0;
    for entry in std::fs::read_dir(&activity).unwrap() {
        let path = entry.unwrap().path();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600, "{}", path.display());
        seen += 1;
    }
    assert!(seen >= 2, "expected the monthly file and the run lock");
}

#[cfg(windows)]
#[test]
fn the_directory_and_files_are_owner_only() {
    use bastion_core::winacl::{current_user_sid, dacl_report};
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    let id = log.begin(start(Uuid::new_v4(), NOV_12)).unwrap();
    log.end(id, end(None, NOV_12, EndReason::Failed)).unwrap();
    let activity = dir.path().join("activity");
    let me = current_user_sid().unwrap();
    let owner_only = |path: &Path| {
        let r = dacl_report(path).unwrap();
        assert!(r.protected, "{}: {r:?}", path.display());
        assert_eq!(r.aces.len(), 1, "{}: {r:?}", path.display());
        assert_eq!(r.aces[0].sid, me, "{}: {r:?}", path.display());
    };
    owner_only(&activity);
    let mut seen = 0;
    for entry in std::fs::read_dir(&activity).unwrap() {
        owner_only(&entry.unwrap().path());
        seen += 1;
    }
    assert!(seen >= 2, "expected the monthly file and the run lock");
}

#[test]
fn a_disabled_log_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let log = ActivityLog::in_dir(dir.path());
    log.set_enabled(false);
    let c = Uuid::new_v4();
    let id = log.begin(start(c, NOV_12)).unwrap();
    log.event_at(id, NOV_12, EventKind::Resize, details(&[])).unwrap();
    log.end(id, end(None, NOV_12, EndReason::Failed)).unwrap();
    assert!(!dir.path().join("activity").exists());
    assert!(log.query(&Filter::default(), PAGE).unwrap().is_empty());

    // A session begun while logging was on is completed after it is turned off.
    log.set_enabled(true);
    let kept = log.begin(start(c, NOV_12)).unwrap();
    log.set_enabled(false);
    log.end(kept, end(Some(NOV_12), NOV_12 + 1, EndReason::ClosedByUser)).unwrap();
    let got = log.query(&for_connection(c), PAGE).unwrap();
    assert_eq!(got.len(), 1);
    assert!(!got[0].open);
}

#[test]
fn the_logging_settings_have_the_agreed_defaults_and_choices() {
    let mut s = Settings::default();
    assert_eq!(s.get("logging.activity-enabled").unwrap(), "true");
    assert_eq!(s.get("logging.activity-retention-days").unwrap(), "365");
    for days in ["30", "90", "365", "0"] {
        s.set("logging.activity-retention-days", days).unwrap();
        assert_eq!(s.get("logging.activity-retention-days").unwrap(), days);
    }
    assert!(s.set("logging.activity-retention-days", "7").is_err());
    s.set("logging.activity-enabled", "false").unwrap();
    assert_eq!(s.get("logging.activity-enabled").unwrap(), "false");
    // No app shows them before it has a history view.
    assert!(settings::visible(&[]).iter().all(|d| !d.id.starts_with("logging.")));
    assert_eq!(settings::visible(&["activity-log"]).iter().filter(|d| d.id.starts_with("logging.")).count(), 2);
}

#[test]
fn an_audit_record_can_carry_a_correlation_id_and_the_chain_still_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&path).unwrap();
    let session = Uuid::new_v4();
    let plain = log.record(audit::Category::Connection, "ssh.connect", Some("web-01"), audit::Outcome::Success, BTreeMap::new()).unwrap();
    let linked = log.record_correlated(audit::Category::Connection, "ssh.disconnect", Some("web-01"), audit::Outcome::Success, BTreeMap::new(), Some(session)).unwrap();
    assert_eq!(plain.correlation_id, None);
    assert_eq!(linked.correlation_id, Some(session));
    audit::verify(&path).unwrap();
    assert!(std::fs::read_to_string(&path).unwrap().contains(&session.to_string()));
}

fn orchestrator(dir: &Path, log: Arc<ActivityLog>) -> (Orchestrator, CredentialRef) {
    let broker = Arc::new(Broker::new(LeaseLimits::default(), Policy::default(), Arc::new(SystemClock)));
    let mut o = Orchestrator::new(Policy::default(), broker, vec![], AuditLog::open(dir.join("audit.jsonl")).unwrap(), dir.join("known_hosts"));
    o.connect_timeout = std::time::Duration::from_secs(3);
    o.activity = Some(ActivitySink {
        log,
        folder_path: vec![FolderRef { id: Uuid::new_v4(), name: "Lab".into() }],
        login_source: LoginSource::Agent,
        app: App::NativeMac,
        app_version: "1.0.0".into(),
        device_name: "test-mac".into(),
    });
    // An agent login brokers no secret, so no vault is needed.
    let cred = CredentialRef { provider: "vault".into(), item: "none".into(), scope: None, username: "tester".into(), usage: SecretUse::Agent(Some(dir.join("no-agent.sock"))) };
    (o, cred)
}

#[tokio::test]
async fn a_failed_ssh_connect_is_recorded_with_its_reason_and_linked_to_the_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(ActivityLog::in_dir(dir.path()));
    let (o, cred) = orchestrator(dir.path(), log.clone());
    // A port nothing listens on: the connect fails without a server.
    let mut conn = Connection::new("lab-box", Protocol::Ssh, "127.0.0.1");
    conn.settings.port = Some(1);

    assert!(o.connect_ssh(&conn, &cred).await.is_err());
    assert_eq!(o.activity_session(), None, "a failed connect leaves no open session");

    let got = log.query(&for_connection(conn.id), PAGE).unwrap();
    assert_eq!(got.len(), 1);
    let s = &got[0];
    assert_eq!((s.connection_name.as_str(), s.protocol.as_str(), s.host.as_str(), s.port), ("lab-box", "ssh", "127.0.0.1", Some(1)));
    assert_eq!(s.username.as_deref(), Some("tester"));
    assert_eq!(s.login_source, LoginSource::Agent);
    assert_eq!(s.folder_path[0].name, "Lab");
    assert!(!s.open);
    assert!(matches!(s.end_reason, Some(EndReason::Failed | EndReason::Timeout | EndReason::NetworkLost)));

    audit::verify(&dir.path().join("audit.jsonl")).unwrap();
    let audit_text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    let connect = audit_text.lines().find(|l| l.contains("\"ssh.connect\"")).expect("ssh.connect audited");
    assert!(connect.contains(&s.session_id.to_string()), "the audit record does not carry the session id");
}

#[tokio::test]
async fn a_policy_denial_is_recorded_as_a_failed_session() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(ActivityLog::in_dir(dir.path()));
    let (o, cred) = orchestrator(dir.path(), log.clone());
    let conn = Connection::new("old-switch", Protocol::Telnet, "127.0.0.1");
    assert!(matches!(o.connect_ssh(&conn, &cred).await, Err(CoreError::PolicyDenied(_))));
    let got = log.query(&for_connection(conn.id), PAGE).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].end_reason, Some(EndReason::Failed));
}

#[tokio::test]
async fn without_a_sink_the_orchestrator_records_no_activity() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(ActivityLog::in_dir(dir.path()));
    let (mut o, cred) = orchestrator(dir.path(), log.clone());
    o.activity = None;
    let conn = Connection::new("old-switch", Protocol::Telnet, "127.0.0.1");
    assert!(o.connect_ssh(&conn, &cred).await.is_err());
    // Ending with nothing connected is a no-op, not an error.
    o.session_ended(EndReason::ClosedByUser, None, None, None);
    assert!(log.query(&Filter::default(), PAGE).unwrap().is_empty());
    assert!(!std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap().contains("ssh.disconnect"));
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[tokio::test]
async fn a_live_ssh_session_is_recorded_from_connect_to_disconnect() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    use bastion_core::provider::LocalVaultProvider;
    use bastion_core::vault::{Credential, CredentialKind, Secret, Vault};
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(ActivityLog::in_dir(dir.path()));
    // The fixture's test account (docs/TESTING.md), as in connect_integration.rs.
    let mut v = Vault::default();
    let item = v.add(Credential { id: Uuid::new_v4(), name: "tester".into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: "tester".into(), password: Secret::new("test-pass-123") } });
    let broker = Arc::new(Broker::new(LeaseLimits::default(), Policy::default(), Arc::new(SystemClock)));
    let mut o = Orchestrator::new(Policy::default(), broker, vec![Arc::new(LocalVaultProvider::new(Some(v)))], AuditLog::open(dir.path().join("audit.jsonl")).unwrap(), dir.path().join("known_hosts"));
    o.activity = Some(ActivitySink { log: log.clone(), folder_path: vec![], login_source: LoginSource::Own, app: App::NativeMac, app_version: "1.0.0".into(), device_name: "test-mac".into() });
    let cred = CredentialRef { provider: "vault".into(), item: item.to_string(), scope: None, username: "tester".into(), usage: SecretUse::Password };
    let mut conn = Connection::new("fixture", Protocol::Ssh, "127.0.0.1");
    conn.settings.port = Some(2222);

    let Err(CoreError::HostKeyUnknown { fingerprint }) = o.connect_ssh(&conn, &cred).await else { panic!("expected HostKeyUnknown") };
    let session = o.connect_ssh_trusting(&conn, &cred, &fingerprint).await.expect("login to the fixture");
    let id = o.activity_session().expect("an open session");
    drop(session);
    o.session_ended(EndReason::ClosedByUser, None, None, None);
    assert_eq!(o.activity_session(), None);

    let got = log.query(&for_connection(conn.id), PAGE).unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!((got[0].session_id, got[0].end_reason), (id, Some(EndReason::ClosedByUser)));
    assert!(got[0].connected_at.is_some());
    assert_eq!(got[1].end_reason, Some(EndReason::HostKey));
    audit::verify(&dir.path().join("audit.jsonl")).unwrap();
    let audit_text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    let disconnect = audit_text.lines().find(|l| l.contains("\"ssh.disconnect\"")).expect("ssh.disconnect audited");
    assert!(disconnect.contains(&id.to_string()));
    assert!(!all_text(dir.path()).contains("test-pass-123"), "the password reached the activity store");
}

/// Acceptance: the first page of a connection with 100,000 records comes back in under 200 ms.
/// `cargo test --release --test activity_tests first_page -- --ignored --nocapture`
#[ignore = "timed: run on a quiet Mac with --ignored --nocapture"]
#[test]
fn first_page_of_100_000_records_is_fast() {
    let dir = tempfile::tempdir().unwrap();
    let c = Uuid::new_v4();
    // Written directly in the stored format: 50,000 sessions (a start and an end each, so
    // 100,000 records) for one connection in one month, among 5,000 sessions of other connections.
    let activity = dir.path().join("activity");
    std::fs::create_dir_all(&activity).unwrap();
    let mut text = String::new();
    for i in 0..55_000u64 {
        let conn = if i % 11 == 10 { Uuid::new_v4() } else { c };
        let id = Uuid::new_v4();
        let at = NOV_12 + i * 1_000;
        text.push_str(&format!(
            "{{\"type\":\"session_start\",\"session_id\":\"{id}\",\"run_id\":\"{id}\",\"connection_id\":\"{conn}\",\"connection_name\":\"web-01\",\"folder_path\":[{{\"id\":\"{conn}\",\"name\":\"Customers\"}}],\"protocol\":\"ssh\",\"host\":\"web-01.example.test\",\"port\":22,\"username\":\"deploy\",\"route\":[],\"login_source\":\"own\",\"started_at\":{at},\"app\":\"native-mac\",\"app_version\":\"1.0.0\",\"device_name\":\"test-mac\"}}\n"
        ));
        text.push_str(&format!(
            "{{\"type\":\"session_end\",\"session_id\":\"{id}\",\"connected_at\":{at},\"ended_at\":{},\"duration_ms\":500,\"end_reason\":\"closed_by_user\",\"reconnects\":0,\"transcript_path\":null,\"transcript_sha256\":null}}\n",
            at + 500
        ));
    }
    std::fs::write(activity.join("2025-11.jsonl"), &text).unwrap();
    let log = ActivityLog::in_dir(dir.path());

    let mut worst = std::time::Duration::ZERO;
    for _ in 0..5 {
        let t = std::time::Instant::now();
        let got = log.query(&for_connection(c), Page { offset: 0, limit: 50 }).unwrap();
        worst = worst.max(t.elapsed());
        assert_eq!(got.len(), 50);
        assert!(got.iter().all(|s| s.connection_id == c && !s.open));
    }
    let t = std::time::Instant::now();
    let deep = log.query(&for_connection(c), Page { offset: 49_950, limit: 50 }).unwrap();
    let deep_time = t.elapsed();
    assert_eq!(deep.len(), 50);
    let t = std::time::Instant::now();
    assert_eq!(log.close_orphans(NOV_12 + 90 * DAY).unwrap(), 0);
    eprintln!("first page (worst of 5): {worst:?}; last page: {deep_time:?}; close_orphans over 110,000 lines: {:?}; file {} MiB", t.elapsed(), text.len() / (1024 * 1024));
    assert!(worst < std::time::Duration::from_millis(200), "first page took {worst:?}");
}
