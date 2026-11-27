use super::*;
use crate::model::{Connection, Document, Folder, Node, Protocol, Settings as ConnSettings};
use crate::settings::Settings;

fn opts() -> LogOptions {
    LogOptions::default()
}

fn render_plain(line: &str, o: &LogOptions) -> String {
    let pats = compile_patterns(&o.redact_patterns.join("\n")).unwrap();
    render(line, o, &pats, &mut false)
}

#[test]
fn redacts_echoed_answers_after_prompts() {
    assert_eq!(redact_after_prompt("Password: hunter2\r\n").as_deref(), Some("Password: [redacted]\n"));
    assert_eq!(redact_after_prompt("Enter passphrase for key '/k': s3cret\n").as_deref(), Some("Enter passphrase for key '/k': [redacted]\n"));
    assert_eq!(redact_after_prompt("GitHub TOKEN: ghp_x\n").as_deref(), Some("GitHub TOKEN: [redacted]\n"));
}

#[test]
fn leaves_harmless_lines_alone() {
    assert_eq!(redact_after_prompt("[sudo] password for mo: \n"), None, "nothing echoed");
    assert_eq!(redact_after_prompt("ls -la\n"), None);
    assert_eq!(redact_after_prompt("password reset done\n"), None, "no colon");
}

#[test]
fn prompt_hidden_in_colour_is_still_found() {
    assert_eq!(render_plain("\x1b[1mPassword:\x1b[0m hunter2\n", &opts()), "Password: [redacted]\n");
    assert_eq!(render_plain("\x1b[1mok\x1b[0m\n", &opts()), "\x1b[1mok\x1b[0m\n");
}

#[test]
fn rejects_bad_options() {
    assert!(LogOptions { max_bytes: 10, ..Default::default() }.validated().is_err());
    assert!(LogOptions { keep: 1000, ..Default::default() }.validated().is_err());
}

#[test]
fn built_in_extras_redact_keys_and_authorization() {
    let mut in_key = false;
    let o = opts();
    let lines = ["-----BEGIN OPENSSH PRIVATE KEY-----\n", "b3BlbnNzaC1rZXktdjEAAAA\n", "AAAAC3NzaC1lZDI1NTE5\n", "-----END OPENSSH PRIVATE KEY-----\n", "after\n"];
    let out: Vec<String> = lines.iter().map(|l| render(l, &o, &[], &mut in_key)).collect();
    assert_eq!(out[1], "[redacted]\n");
    assert_eq!(out[2], "[redacted]\n");
    assert_eq!(out[3], lines[3]);
    assert_eq!(out[4], "after\n");
    assert_eq!(render_plain("Authorization: Bearer eyJabc.def\r\n", &o), "Authorization: [redacted]\r\n");
    assert_eq!(render_plain("< proxy-authorization: Basic Zm9v\n", &o), "< proxy-authorization: [redacted]\n");
}

#[test]
fn user_pattern_redacts_and_invalid_pattern_is_refused_at_save() {
    let o = LogOptions { redact_patterns: vec![r"API_KEY=\S+".into()], ..opts() };
    assert_eq!(render_plain("export API_KEY=abc123\n", &o), "export [redacted]\n");
    let mut s = Settings::default();
    assert!(s.set(REDACT_SETTING, "(unclosed").is_err());
    assert!(s.set(REDACT_SETTING, &"a".repeat(600)).is_err(), "too long");
    assert!(s.set(REDACT_SETTING, "x{1000}{1000}").is_err(), "compiled size limit");
    s.set(REDACT_SETTING, "API_KEY=\\S+\ntoken=\\w+").unwrap();
    assert_eq!(s.get(REDACT_SETTING).unwrap(), "API_KEY=\\S+\ntoken=\\w+");
}

fn doc_three_deep() -> (Document, Uuid) {
    let mut doc = Document::new("t");
    let mut conn = Connection::new("web/01 . 🚀", Protocol::Ssh, "web01.example");
    conn.settings.username = Some("ops/../me".into());
    let id = conn.id;
    let folder = |name: &str, children: Vec<Node>| Folder { id: Uuid::new_v4(), name: name.into(), color: None, defaults: ConnSettings::default(), children, dynamic_task_id: None, extra: Default::default() };
    let tree = folder("Customers", vec![Node::Folder(folder("Acme/EU", vec![Node::Folder(folder("..Prod", vec![Node::Connection(conn)]))]))]);
    doc.insert(None, Node::Folder(tree)).unwrap();
    (doc, id)
}

fn ctx(root: &Path, now_ms: u64) -> PlanContext {
    PlanContext { default_root: root.to_path_buf(), app: "Bastion test".into(), version: "1.0".into(), now_ms, utc_offset_minutes: 60 }
}

// 2026-11-20 10:11:12.345 UTC
const T0: u64 = 1_795_169_472_345;

#[test]
fn plan_for_a_connection_three_folders_deep() {
    let dir = tempfile::tempdir().unwrap();
    let (doc, id) = doc_three_deep();
    let plan = session_log_plan(&doc, &Settings::default(), id, &ctx(dir.path(), T0)).unwrap();
    let rel: Vec<String> = plan.path.strip_prefix(dir.path()).unwrap().components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    assert_eq!(rel, ["Customers", "Acme-EU", "Prod", "web-01", "2026-11-20_11-11-12_ops-..-me.log"]);
    assert!(rel.iter().all(|p| !p.contains('/') && p != ".." && !p.starts_with('.')), "{rel:?}");
    assert_eq!(plan.root, dir.path());
}

#[test]
fn planned_logs_strip_escape_codes() {
    let dir = tempfile::tempdir().unwrap();
    let (doc, id) = doc_three_deep();
    let plan = session_log_plan(&doc, &Settings::default(), id, &ctx(dir.path(), T0)).unwrap();
    assert!(plan.options.strip_ansi, "a planned log is plain text on every app");
    let mut log = SessionLog::create_planned(&plan).unwrap();
    log.write(b"\x1b[1;32mok\x1b[0m done\r\n").unwrap();
    drop(log);
    let text = std::fs::read_to_string(&plan.path).unwrap();
    assert!(text.contains("ok done") && !text.contains('\x1b'), "{text:?}");
}

#[cfg(unix)]
#[test]
fn planned_log_folders_are_owner_only_up_to_the_root() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("session-logs");
    let (doc, id) = doc_three_deep();
    let plan = session_log_plan(&doc, &Settings::default(), id, &ctx(&root, T0)).unwrap();
    drop(SessionLog::create_planned(&plan).unwrap());
    for d in plan.path.parent().unwrap().ancestors().take_while(|a| a.starts_with(&root)) {
        assert_eq!(std::fs::metadata(d).unwrap().permissions().mode() & 0o777, 0o700, "{}", d.display());
    }
}

#[test]
fn folder_property_and_setting_override_the_root() {
    let dir = tempfile::tempdir().unwrap();
    let (mut doc, id) = doc_three_deep();
    let mut s = Settings::default();
    let other = dir.path().join("elsewhere");
    s.set(FOLDER_SETTING, other.to_str().unwrap()).unwrap();
    assert!(session_log_plan(&doc, &s, id, &ctx(dir.path(), T0)).unwrap().path.starts_with(&other));
    let own = dir.path().join("own");
    if let Node::Folder(f) = &mut doc.root.children[0] {
        f.defaults.session_log_folder = Some(own.to_str().unwrap().into());
    }
    assert!(session_log_plan(&doc, &s, id, &ctx(dir.path(), T0)).unwrap().path.starts_with(&own), "inherited property wins");
    assert!(s.set(FOLDER_SETTING, "relative/path").is_err());
}

#[test]
fn long_paths_lose_middle_folders() {
    let dir = tempfile::tempdir().unwrap();
    let mut doc = Document::new("t");
    let conn = Connection::new("c", Protocol::Ssh, "h");
    let id = conn.id;
    let mut node = Node::Connection(conn);
    for i in (0..8).rev() {
        node = Node::Folder(Folder { id: Uuid::new_v4(), name: format!("{i}{}", "x".repeat(60)), color: None, defaults: ConnSettings::default(), children: vec![node], dynamic_task_id: None, extra: Default::default() });
    }
    doc.insert(None, node).unwrap();
    let plan = session_log_plan(&doc, &Settings::default(), id, &ctx(dir.path(), T0)).unwrap();
    assert!(plan.path.as_os_str().len() <= MAX_PATH_CHARS, "{}", plan.path.display());
    let rel = plan.path.strip_prefix(dir.path()).unwrap().to_string_lossy().into_owned();
    assert!(rel.starts_with('0'), "first folder kept: {rel}");
}

#[test]
fn two_sessions_in_the_same_second_get_different_files() {
    let dir = tempfile::tempdir().unwrap();
    let (doc, id) = doc_three_deep();
    let plan = session_log_plan(&doc, &Settings::default(), id, &ctx(dir.path(), T0)).unwrap();
    let a = SessionLog::create_planned(&plan).unwrap();
    let b = SessionLog::create_planned(&plan).unwrap();
    assert_ne!(a.path(), b.path());
    assert!(b.path().to_string_lossy().ends_with("-2.log"));
}

#[test]
fn header_and_footer_contents_and_duration() {
    let dir = tempfile::tempdir().unwrap();
    let (doc, id) = doc_three_deep();
    let plan = session_log_plan(&doc, &Settings::default(), id, &ctx(dir.path(), T0)).unwrap();
    let mut log = SessionLog::create_planned(&plan).unwrap();
    log.write(b"hello\n").unwrap();
    let hash = log.finish_with(&LogEnd { reason: "server closed\nthe connection".into(), end_ms: T0 + 3_723_000 }).unwrap();
    let text = std::fs::read_to_string(log.path()).unwrap();
    let expect_head = format!(
        "# Gantry session log\n# name: web/01 . 🚀\n# connection: {id}\n# host: web01.example\n# port: 22\n# user: ops/../me\n# route: direct\n# app: Bastion test 1.0\n# started: 2026-11-20 10:11:12 UTC (local 2026-11-20 11:11:12 +01:00)\n# Output only; keystrokes are not recorded.\nhello\n"
    );
    assert!(text.starts_with(&expect_head), "{text}");
    assert!(text.ends_with("# ended: 2026-11-20 11:13:15 UTC (local 2026-11-20 12:13:15 +01:00)\n# duration: 1h 02m 03s (3723 s)\n# end reason: server closed the connection\n"), "{text}");
    assert_eq!(hash, hex::encode(Sha256::digest(text.as_bytes())), "returned hash matches the file");
    let mut log2 = SessionLog::create(&dir.path().join("x.log"), LOG_MAGIC, opts()).unwrap();
    log2.finish_with(&LogEnd { reason: String::new(), end_ms: now_ms() }).unwrap();
    assert!(std::fs::read_to_string(dir.path().join("x.log")).unwrap().ends_with("# end reason: unknown\n"));
}

#[test]
fn timestamps_prefix_every_line_and_partial_lines_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.log");
    let mut log = SessionLog::create(&path, LOG_MAGIC, LogOptions { timestamps: true, ..opts() }).unwrap();
    log.write(b"one\ntw").unwrap();
    log.write(&vec![b'o'; MAX_PENDING_BYTES + 10]).unwrap(); // forces the partial line out
    log.write(b" more\nthree\n").unwrap();
    log.finish().unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    let body: Vec<&str> = text.lines().skip(1).collect();
    assert_eq!(body.len(), 3, "{}", body.len());
    let stamped = |l: &str| l.len() > 13 && l.as_bytes()[2] == b':' && l.as_bytes()[5] == b':' && l.as_bytes()[8] == b'.' && l.as_bytes()[12] == b' ';
    assert!(body.iter().all(|l| stamped(l)), "{:?}", body.iter().map(|l| &l[..20.min(l.len())]).collect::<Vec<_>>());
    assert!(body[1].ends_with("o more"), "the continued line is stamped once");
    assert_eq!(body[1].matches(':').count(), 2);
    assert!(body[2].ends_with("three"));
}

fn write_log(path: &Path, body: &str, age_days: u64) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("{LOG_MAGIC}\n{body}")).unwrap();
    let t = std::time::SystemTime::now() - Duration::from_secs(age_days * 86_400);
    File::options().write(true).open(path).unwrap().set_modified(t).unwrap();
}

#[test]
fn retention_by_age_and_size_keeps_non_logs_and_removes_empty_folders() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("logs");
    let old = root.join("A/B/conn/old.log");
    let rotated = root.join("A/B/conn/old.log.1");
    let fresh = root.join("A/new.log");
    let not_log = root.join("A/B/notes.log");
    let other_dir = root.join("Empty-before");
    write_log(&old, "x", 40);
    write_log(&rotated, "x", 41);
    write_log(&fresh, "x", 1);
    std::fs::write(&not_log, "my notes").unwrap();
    std::fs::create_dir_all(&other_dir).unwrap();
    let outside = dir.path().join("outside.log");
    write_log(&outside, "x", 400);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, root.join("link.log")).unwrap();

    let r = purge_session_logs(&root, &PurgeRules { keep_days: 30, max_bytes: 0 , ..Default::default() }, now_ms()).unwrap();
    assert_eq!(r.deleted_files, 2);
    assert!(!old.exists() && !rotated.exists());
    assert!(fresh.exists() && not_log.exists() && outside.exists());
    assert!(!root.join("A/B/conn").exists(), "emptied folder removed");
    assert!(root.join("A/B").exists(), "still holds a non-log file");
    assert!(other_dir.exists(), "a folder the purge did not empty is left alone");

    // Size: the oldest go first.
    let a = root.join("s/a.log");
    let b = root.join("s/b.log");
    write_log(&a, &"y".repeat(1000), 3);
    write_log(&b, &"y".repeat(1000), 2);
    let r = purge_session_logs(&root, &PurgeRules { keep_days: 0, max_bytes: 1100 , ..Default::default() }, now_ms()).unwrap();
    assert!(!a.exists() && fresh.exists() && b.exists(), "{r:?}");
    assert!(root.exists(), "never removes the root");
    assert_eq!(purge_session_logs(&dir.path().join("missing"), &PurgeRules { keep_days: 1, max_bytes: 1 , ..Default::default() }, now_ms()).unwrap(), PurgeReport::default());
}

#[test]
fn purge_rules_from_settings() {
    let mut s = Settings::default();
    assert_eq!(PurgeRules::from_settings(&s), PurgeRules::default());
    s.set(KEEP_DAYS_SETTING, "14").unwrap();
    s.set(MAX_GB_SETTING, "2").unwrap();
    assert_eq!(PurgeRules::from_settings(&s), PurgeRules { keep_days: 14, max_bytes: 2 << 30 , ..Default::default() });
}

#[test]
fn a_slow_disk_does_not_block_write_and_overflow_stops_logging() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(LogState::Off));
    let log = SessionLog::create(&dir.path().join("slow.log"), LOG_MAGIC, opts()).unwrap();
    let blocked = Arc::new(AtomicBool::new(true));
    let b = blocked.clone();
    let hook: Hook = Arc::new(move || {
        let start = Instant::now();
        while b.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let w = LogWriter::spawn_with_hook(log, state.clone(), Some(hook)).unwrap();
    assert!(matches!(&*state.lock().unwrap(), LogState::Active { .. }));
    let line = vec![b'z'; 1024];
    let mut slowest = Duration::ZERO;
    for _ in 0..100 {
        let t = Instant::now();
        assert!(w.write(&line));
        slowest = slowest.max(t.elapsed());
    }
    assert!(slowest < Duration::from_millis(5), "write blocked for {slowest:?}");
    // Fill the queue while the disk is still blocked.
    let chunk = vec![b'q'; 64 * 1024];
    let mut refused = false;
    for _ in 0..(QUEUE_BYTES / chunk.len() + 2) {
        if !w.write(&chunk) {
            refused = true;
            break;
        }
    }
    assert!(refused, "the queue is bounded");
    assert_eq!(*state.lock().unwrap(), LogState::Stopped { reason: OVERFLOW_REASON.into() });
    assert!(!w.write(b"later\n"));
    blocked.store(false, Ordering::SeqCst);
    drop(w);
}

#[test]
fn writer_finish_returns_the_file_hash_and_turns_off() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w.log");
    let state = Arc::new(Mutex::new(LogState::Off));
    let w = LogWriter::spawn(SessionLog::create(&path, LOG_MAGIC, opts()).unwrap(), state.clone()).unwrap();
    assert!(w.write(b"a line\npartial"));
    let hash = w.finish(LogEnd::now("user closed the tab")).unwrap();
    assert_eq!(*state.lock().unwrap(), LogState::Off);
    let text = std::fs::read(&path).unwrap();
    assert_eq!(hash, hex::encode(Sha256::digest(&text)));
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("a line\npartial\n# ended: "), "{text}");
    assert!(text.ends_with("# end reason: user closed the tab\n"));
}

#[test]
fn a_disk_error_becomes_a_visible_stopped_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("e.log");
    let state = Arc::new(Mutex::new(LogState::Off));
    // Rotation with keep 0 removes the file; removing the folder first makes the reopen fail.
    let log = SessionLog::create(&path, LOG_MAGIC, LogOptions { max_bytes: MIN_MAX_BYTES, keep: 0, ..opts() }).unwrap();
    let w = LogWriter::spawn(log, state.clone()).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(dir.path()).unwrap();
    assert!(w.write(&vec![b'x'; 8192]));
    assert!(w.write(b"\n"));
    let start = Instant::now();
    while !matches!(&*state.lock().unwrap(), LogState::Stopped { .. }) && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    match &*state.lock().unwrap() {
        LogState::Stopped { reason } => assert!(reason.starts_with("writing the session log failed"), "{reason}"),
        s => panic!("{s:?}"),
    }
    assert!(!w.write(b"more"), "write reports the stop");
    assert!(w.finish(LogEnd::now("")).is_err());
}

#[test]
fn rotation_starts_each_file_with_the_magic_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("r.log");
    let mut log = SessionLog::create(&path, LOG_MAGIC, LogOptions { max_bytes: MIN_MAX_BYTES, keep: 2, ..opts() }).unwrap();
    for _ in 0..200 {
        log.write(b"0123456789012345678901234567890123456789\n").unwrap();
    }
    log.finish().unwrap();
    assert!(is_session_log(&path) && is_session_log(&dir.path().join("r.log.1")));
}

#[test]
fn keep_days_property_is_bounded_and_inherited() {
    let (mut doc, id) = doc_three_deep();
    let folder_id = match &doc.root.children[0] {
        Node::Folder(f) => f.id,
        _ => unreachable!(),
    };
    for bad in ["-1", "3651", "ten", "1.5"] {
        assert!(crate::properties::set_value(&mut doc, folder_id, "session_log_keep_days", Some(bad)).is_err(), "{bad}");
    }
    crate::properties::set_value(&mut doc, folder_id, "session_log_keep_days", Some("7")).unwrap();
    assert_eq!(doc.resolve(id).unwrap().effective.session_log_keep_days, Some(7), "inherited by the connection");
    let mut s = Settings::default();
    assert!(s.set(KEEP_DAYS_SETTING, "3651").is_err());
    s.set(KEEP_DAYS_SETTING, "3650").unwrap();
}

#[test]
fn folder_keep_days_overrides_the_setting_in_purge() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("session-logs");
    let (mut doc, id) = doc_three_deep();
    let mut s = Settings::default();
    s.set(KEEP_DAYS_SETTING, "30").unwrap();
    if let Node::Folder(f) = &mut doc.root.children[0] {
        f.defaults.session_log_keep_days = Some(5);
    }
    let plan = session_log_plan(&doc, &s, id, &ctx(&root, T0)).unwrap();
    let conn_dir = plan.path.parent().unwrap().to_path_buf();
    let rules = PurgeRules::for_library(&doc, &s, &root, &root);
    assert_eq!(rules.keep_days, 30);
    assert_eq!(rules.folder_keep_days, vec![(conn_dir.clone(), 5)]);
    let in_folder = conn_dir.join("a.log");
    let elsewhere = root.join("Other/conn/b.log");
    write_log(&in_folder, "x", 10);
    write_log(&elsewhere, "x", 10);
    purge_session_logs(&root, &rules, now_ms()).unwrap();
    assert!(!in_folder.exists(), "10 days is past the folder's 5");
    assert!(elsewhere.exists(), "10 days is within the setting's 30");
    // A folder may also keep its logs longer than the setting, or forever.
    if let Node::Folder(f) = &mut doc.root.children[0] {
        f.defaults.session_log_keep_days = Some(0);
    }
    write_log(&in_folder, "x", 100);
    let rules = PurgeRules::for_library(&doc, &s, &root, &root);
    purge_session_logs(&root, &rules, now_ms()).unwrap();
    assert!(in_folder.exists(), "0 keeps the folder's logs forever");
    // Connections whose logs live under another root add nothing.
    assert!(PurgeRules::for_library(&doc, &s, &dir.path().join("elsewhere"), &root).folder_keep_days.is_empty());
}
