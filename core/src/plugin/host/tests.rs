//! Tests for the helper processes. The pure rules first; then real helpers: the tests build
//! `plugin-host` (and, for the end-to-end run, the plugin template for `wasm32-wasip2`) once
//! per run and start the program from its target folder.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::helper::{Event, Helper, StartError, Stopped, Timing};
use super::proto::{Role, Sandbox, ToCore, ToHelper, Value, CHUNK};
use super::*;
use crate::plugin::broker::cache::max_compiled_bytes;
use crate::plugin::broker::StopReason;

// ---- pure rules ----

#[test]
fn crashes_wait_one_then_five_then_thirty_seconds() {
    let mut b = CrashBackoff::default();
    let t = Instant::now();
    let delays: Vec<u64> = (0..5).map(|i| b.on_crash(t + Duration::from_secs(i)).as_secs()).collect();
    assert_eq!(delays, [1, 5, 30, 30, 30]);
}

#[test]
fn a_helper_healthy_for_two_minutes_starts_over_at_one_second() {
    let mut b = CrashBackoff::default();
    let t = Instant::now();
    b.on_crash(t);
    b.on_crash(t + Duration::from_secs(1));
    assert_eq!(b.on_crash(t + Duration::from_secs(1) + HEALTHY_AFTER - Duration::from_millis(1)), RESTART_DELAYS[2]);
    let later = t + Duration::from_secs(2) + HEALTHY_AFTER * 2;
    assert_eq!(b.on_crash(later), RESTART_DELAYS[0], "healthy for HEALTHY_AFTER: back to the first delay");
}

#[test]
fn restart_by_the_user_clears_the_backoff() {
    let mut b = CrashBackoff::default();
    let t = Instant::now();
    b.on_crash(t);
    b.on_crash(t);
    b.reset();
    assert_eq!(b.on_crash(t), RESTART_DELAYS[0]);
}

fn launch(policy: &Policy) -> Launch<'_> {
    Launch { policy, rollout: Rollout::OFFICIAL_ONLY, plugin_id: "com.example.pg", tier: Tier::Official, allow_unverified: false, safe_mode: false }
}

fn nowhere() -> Pool {
    Pool::with_program(PathBuf::from("/nonexistent/bastion-plugin-host"), Timing::DEFAULT)
}

#[test]
fn the_load_gate_is_asked_before_any_process_starts() {
    let pool = nowhere();
    let off = Policy { plugins_disabled: true, ..Policy::default() };
    assert!(matches!(pool.start_view(&launch(&off), 1 << 20), Err(Failure::Denied(_))));
    let policy = Policy::default();
    let safe = Launch { safe_mode: true, ..launch(&policy) };
    assert!(matches!(pool.start_view(&safe, 1 << 20), Err(Failure::Denied(_))));
    let external = Launch { tier: Tier::External, ..launch(&policy) };
    assert!(matches!(pool.start_compile(&external, "h"), Err(Failure::Denied(_))), "External plugins wait for PLUG-12");
    assert_eq!(pool.running(), 0);
}

#[test]
fn the_eighth_helper_gets_a_place_and_the_ninth_does_not() {
    let pool = nowhere();
    let policy = Policy::default();
    let places: Vec<_> = (0..MAX_HELPERS).map(|_| pool.reserve(&launch(&policy), None).expect("a place")).collect();
    assert_eq!(pool.running(), MAX_HELPERS);
    assert!(matches!(pool.reserve(&launch(&policy), None), Err(Failure::Invalid(_))));
    drop(places);
    assert_eq!(pool.running(), 0, "dropping a slot frees its place");
}

#[test]
fn one_compile_helper_per_plugin_hash_and_it_counts_toward_the_eight() {
    let pool = nowhere();
    let policy = Policy::default();
    let first = pool.reserve(&launch(&policy), Some("abc")).unwrap();
    assert!(matches!(pool.reserve(&launch(&policy), Some("abc")), Err(Failure::Invalid(_))));
    let other = pool.reserve(&launch(&policy), Some("def")).unwrap();
    assert_eq!(pool.running(), 2);
    drop(first);
    assert!(pool.reserve(&launch(&policy), Some("abc")).is_ok(), "free again once the first ends");
    drop(other);
}

#[test]
fn a_failed_start_frees_its_place() {
    let pool = nowhere();
    let policy = Policy::default();
    assert!(matches!(pool.start_view(&launch(&policy), 1 << 20), Err(Failure::Invalid(_))));
    assert_eq!(pool.running(), 0);
}

#[test]
fn stop_reasons_follow_the_cause() {
    assert_eq!(Stopped::Exited(Some(1)).reason(), StopReason::Crash);
    assert_eq!(Stopped::Hung.reason(), StopReason::HangKill);
    assert!(Stopped::Violation("x".into()).reason().withdraws_trust());
    assert_eq!(Stopped::Killed(StopReason::TurnedOff).reason(), StopReason::TurnedOff);
}

// ---- real helpers ----

fn cargo_build(dir: &Path, extra: &[&str]) {
    let out = Command::new(env!("CARGO"))
        .arg("build")
        .args(extra)
        .arg("--quiet")
        .current_dir(dir)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("RUSTFLAGS")
        .output()
        .expect("run cargo");
    if out.status.success() {
        return;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The plugin template builds for wasm32-wasip2, a target rustup does not install by default (docs/TESTING.md).
    let hint = if extra.contains(&"wasm32-wasip2") && stderr.contains("wasm32-wasip2") {
        "\nthis machine lacks the plugin target: run `rustup target add wasm32-wasip2`, then re-run"
    } else {
        ""
    };
    panic!("building {} failed:\n{stderr}{hint}", dir.display());
}

/// The helper program, built from `plugin-host/` once per run. `BASTION_TEST_PLUGIN_HELPER` names
/// a helper that is already built instead, such as the signed one inside `Bastion.app`
/// (`Contents/Helpers/bastion-plugin-host`), so these tests prove the packaged helper (PLUG-14).
fn program() -> &'static PathBuf {
    static P: OnceLock<PathBuf> = OnceLock::new();
    P.get_or_init(|| {
        if let Some(path) = std::env::var_os("BASTION_TEST_PLUGIN_HELPER") {
            let path = PathBuf::from(path);
            assert!(path.is_file(), "BASTION_TEST_PLUGIN_HELPER: no file at {}", path.display());
            return path;
        }
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../plugin-host");
        cargo_build(&dir, &[]);
        dir.join("target/debug").join(HELPER_PROGRAM)
    })
}

/// The plugin template's component, built for `wasm32-wasip2` once per run.
fn template_component() -> &'static Vec<u8> {
    static C: OnceLock<Vec<u8>> = OnceLock::new();
    C.get_or_init(|| {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../plugins/template");
        cargo_build(&dir, &["--release", "--target", "wasm32-wasip2"]);
        std::fs::read(dir.join("target/wasm32-wasip2/release/bastion_plugin_template.wasm")).expect("template component")
    })
}

const FAST: Timing = Timing { hello: Duration::from_secs(20), ping_every: Duration::from_millis(100), hang_after: Duration::from_millis(600) };
const WAIT: Duration = Duration::from_secs(20);

fn start(role: Role) -> Helper {
    Helper::start(program(), role, 1 << 30, FAST, false).expect("helper starts")
}

fn next(helper: &Helper) -> Event {
    helper.next_event(WAIT).expect("an event in time")
}

fn wait_stopped(helper: &Helper) -> Stopped {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if let Some(Event::Stopped(s)) = helper.next_event(Duration::from_millis(200)) {
            return s;
        }
    }
    panic!("the helper did not stop in time");
}

fn send_bytes(helper: &Helper, bytes: &[u8]) {
    for piece in bytes.chunks(CHUNK) {
        helper.send(&ToHelper::Chunk(piece.to_vec())).unwrap();
    }
    helper.send(&ToHelper::End).unwrap();
}

#[cfg(unix)]
fn alive(pid: u32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[test]
fn a_helper_reports_its_role_and_engine_and_is_gone_when_dropped() {
    let helper = start(Role::View);
    assert_eq!(helper.role, Role::View);
    // PLUG-05: the macOS helper sandboxes itself before Hello; on Windows the core starts it in
    // an AppContainer. Both are checked from outside as well.
    let expected = if cfg!(any(target_os = "macos", windows)) { Sandbox::Applied } else { Sandbox::None };
    assert_eq!(helper.sandbox, expected);
    #[cfg(any(target_os = "macos", windows))]
    assert_eq!(super::helper::os_sandboxed(helper.pid), Some(true));
    assert!(helper.engine_key.starts_with("wasmtime-48.0.8-"), "{}", helper.engine_key);
    let pid = helper.pid;
    drop(helper);
    // Killed at once; reaped when the reader and watchdog threads let go (within a ping).
    #[cfg(unix)]
    {
        let deadline = Instant::now() + WAIT;
        while alive(pid) {
            assert!(Instant::now() < deadline, "the helper is still there after drop");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let _ = pid;
}

#[test]
fn view_and_compile_helpers_share_one_engine_key() {
    let view = start(Role::View);
    let compile = start(Role::Compile);
    assert_eq!(view.engine_key, compile.engine_key, "code from the compile helper loads in a view helper");
}

#[test]
fn pings_keep_a_healthy_idle_helper_alive() {
    let helper = start(Role::View);
    // Several hang windows pass with nothing to do: the helper answers every ping.
    assert_eq!(helper.next_event(FAST.hang_after * 4), None);
    assert!(!helper.is_stopped());
}

#[cfg(unix)]
#[test]
fn a_helper_that_stops_answering_pings_is_killed() {
    let helper = start(Role::View);
    // SAFETY: stops our own child; the watchdog kills and reaps it.
    unsafe { libc::kill(helper.pid as libc::pid_t, libc::SIGSTOP) };
    // A healthy helper is left alone (`pings_keep_a_healthy_idle_helper_alive`); a silent one
    // is killed after the hang window.
    assert_eq!(wait_stopped(&helper), Stopped::Hung);
}

/// Review of #951 (HIGH): a helper that is alive but never reads must not block the core. Its
/// pipe and the core's queue fill up; every `send` still returns at once, the watchdog still
/// kills it as hung, and dropping it returns at once.
#[cfg(unix)]
#[test]
fn a_helper_that_never_reads_is_killed_and_never_blocks_the_core() {
    use super::helper::OUTBOX_BYTES;
    use std::io::ErrorKind;
    let helper = start(Role::View);
    // SAFETY: stops our own child; it stays alive and reads nothing.
    unsafe { libc::kill(helper.pid as libc::pid_t, libc::SIGSTOP) };
    let chunk = ToHelper::Chunk(vec![0; 1 << 20]);
    let mut refused = false;
    for _ in 0..(OUTBOX_BYTES >> 20) + 8 {
        let began = Instant::now();
        let sent = helper.send(&chunk);
        assert!(began.elapsed() < Duration::from_millis(500), "send waited on the pipe");
        match sent {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                refused = true;
                break;
            }
            // Already killed as hung: also fine.
            Err(_) => break,
        }
    }
    assert!(refused || helper.is_stopped(), "the queue is capped");
    assert_eq!(wait_stopped(&helper), Stopped::Hung);
    let began = Instant::now();
    drop(helper);
    assert!(began.elapsed() < Duration::from_secs(2), "drop waited on the pipe");
}

#[cfg(unix)]
#[test]
fn a_helper_killed_from_outside_is_reported_as_a_crash() {
    let helper = start(Role::View);
    // SAFETY: kills our own child.
    unsafe { libc::kill(helper.pid as libc::pid_t, libc::SIGKILL) };
    let stopped = wait_stopped(&helper);
    assert_eq!(stopped, Stopped::Exited(Some(-libc::SIGKILL)));
    assert_eq!(stopped.reason(), StopReason::Crash);
}

#[test]
fn a_stop_from_the_core_is_reported_once_with_its_reason() {
    let helper = start(Role::View);
    helper.stop(StopReason::TurnedOff);
    helper.stop(StopReason::Crash);
    assert_eq!(wait_stopped(&helper), Stopped::Killed(StopReason::TurnedOff));
    assert!(helper.next_event(Duration::from_millis(300)).is_none(), "one stop event only");
    assert!(helper.send(&ToHelper::Run).is_err(), "nothing is sent after a stop");
}

#[cfg(unix)]
#[test]
fn a_program_that_never_reports_is_refused() {
    // `/usr/bin/true` exits at once without a sandbox report.
    let err = Helper::start(Path::new("/usr/bin/true"), Role::View, 1 << 30, FAST, false).err().expect("refused");
    assert!(matches!(err, StartError::NoHello), "{err}");
}

#[test]
fn a_helper_without_a_sandbox_is_refused_when_one_is_required() {
    let started = Helper::start(program(), Role::View, 1 << 30, FAST, true);
    if cfg!(any(target_os = "macos", windows)) {
        // PLUG-05: the macOS helper sandboxes itself and the Windows core starts it in an
        // AppContainer, so a required sandbox is met.
        assert_eq!(started.expect("sandboxed helper accepted").sandbox, Sandbox::Applied);
    } else {
        let err = started.err().expect("refused");
        assert!(matches!(err, StartError::BadHello(_)), "{err}");
    }
}

#[cfg(unix)]
#[test]
fn the_cores_pipe_ends_are_close_on_exec() {
    use std::os::fd::AsRawFd;
    let mut child = spawn::spawn(program(), Role::View, 1 << 30).unwrap();
    for file in [child.to_helper.as_ref().unwrap(), child.from_helper.as_ref().unwrap()] {
        // SAFETY: an open descriptor we own.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0, "a later child of the core must not inherit it");
    }
    child.kill();
}

#[test]
fn a_helper_leaves_when_the_core_closes_its_pipe() {
    let mut child = spawn::spawn(program(), Role::View, 1 << 30).unwrap();
    drop(child.to_helper.take());
    let deadline = Instant::now() + WAIT;
    while child.try_wait().is_none() {
        assert!(Instant::now() < deadline, "the helper did not leave");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(child.try_wait(), Some(0));
}

fn compile_template(cap: u64) -> Result<Vec<u8>, String> {
    let component = template_component();
    let helper = start(Role::Compile);
    helper.send(&ToHelper::Compile { total: component.len() as u64, max_output: cap }).unwrap();
    send_bytes(&helper, component);
    let mut code = Vec::new();
    loop {
        match next(&helper) {
            Event::Message(ToCore::Compiled(piece)) => code.extend_from_slice(&piece),
            Event::Message(ToCore::CompileDone { error: None }) => return Ok(code),
            Event::Message(ToCore::CompileDone { error: Some(e) }) => return Err(e),
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn compiled_code_over_its_cap_is_refused_by_the_compile_helper() {
    let err = compile_template(1024).expect_err("over the cap");
    assert!(err.contains("over the cap"), "{err}");
}

#[test]
fn the_template_compiles_loads_runs_and_returns_on_stop() {
    let component = template_component();
    let code = compile_template(max_compiled_bytes(component.len() as u64)).expect("compiles");

    let helper = start(Role::View);
    helper.send(&ToHelper::Load { memory_limit: 256 << 20, compute_ms: 2_000, total: code.len() as u64 }).unwrap();
    send_bytes(&helper, &code);
    assert_eq!(next(&helper), Event::Message(ToCore::Loaded { error: None }));
    helper.send(&ToHelper::Run).unwrap();
    loop {
        match next(&helper) {
            Event::Message(ToCore::Import { seq, name, .. }) if name.starts_with("bastion:plugin/events@1.") && name.ends_with("#next") => {
                helper.send(&ToHelper::Reply { seq, results: vec![Value::Variant("stop".into(), None)] }).unwrap();
            }
            Event::Message(ToCore::Import { name, .. }) => panic!("unexpected import {name}"),
            Event::Message(ToCore::Ended { error }) => {
                assert_eq!(error, None, "run returned normally after stop");
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn a_view_helper_refuses_code_that_is_not_compiled_code() {
    let helper = start(Role::View);
    let junk = b"not compiled code";
    helper.send(&ToHelper::Load { memory_limit: 1 << 20, compute_ms: 100, total: junk.len() as u64 }).unwrap();
    send_bytes(&helper, junk);
    match next(&helper) {
        Event::Message(ToCore::Loaded { error: Some(e) }) => assert!(e.contains("compiled code"), "{e}"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn a_helper_that_is_sent_more_bytes_than_announced_leaves() {
    let helper = start(Role::View);
    helper.send(&ToHelper::Load { memory_limit: 1 << 20, compute_ms: 100, total: 4 }).unwrap();
    helper.send(&ToHelper::Chunk(vec![0; 5])).unwrap();
    assert_eq!(wait_stopped(&helper), Stopped::Exited(Some(2)), "exit code 2: protocol");
}

#[cfg(target_os = "macos")]
#[test]
fn the_outside_check_tells_a_sandboxed_process_from_a_plain_one() {
    use super::helper::os_sandboxed;
    assert_eq!(os_sandboxed(std::process::id()), Some(false));
    let mut plain = std::process::Command::new("/bin/sleep").arg("5").spawn().unwrap();
    let mut boxed = std::process::Command::new("/usr/bin/sandbox-exec")
        .args(["-p", "(version 1)(allow default)", "/bin/sleep", "5"])
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let plain_state = os_sandboxed(plain.id());
    let boxed_state = os_sandboxed(boxed.id());
    let _ = plain.kill();
    let _ = boxed.kill();
    let _ = plain.wait();
    let _ = boxed.wait();
    assert_eq!(plain_state, Some(false));
    assert_eq!(boxed_state, Some(true));
}

#[cfg(target_os = "macos")]
#[test]
fn the_pool_requires_the_sandbox_on_macos_and_the_real_helper_passes_the_outside_check() {
    let helper = Helper::start(program(), Role::View, 1 << 30, FAST, true).expect("sandboxed helper accepted");
    assert_eq!(helper.sandbox, Sandbox::Applied);
    assert_eq!(super::helper::os_sandboxed(helper.pid), Some(true));
}

// ---- PLUG-02b part 2 ----

#[test]
fn plugin_audit_records_go_into_the_hash_chain() {
    use crate::audit::{AuditLog, Outcome};
    use crate::plugin::broker::audit as plugin_audit;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    write_audit(&path, &plugin_audit::cache_mismatch("com.example.pg", "1.0.0", "abc")).unwrap();
    write_audit(&path, &plugin_audit::helper_stopped("com.example.pg", "1.0.0", Some("e1"), StopReason::ProtocolViolation, "bad frame")).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("plugin.cache.mismatch") && text.contains("plugin.helper.stop"));
    // The chain still verifies after the writes.
    let mut log = AuditLog::open(&path).unwrap();
    log.confirm().unwrap();
    let _ = Outcome::Success;
}

#[test]
fn the_helper_program_must_sit_inside_the_apps_own_files() {
    let dir = tempfile::tempdir().unwrap();
    let (exe_dir, helpers) = if cfg!(target_os = "macos") {
        let contents = dir.path().join("Bastion.app/Contents");
        (contents.join("MacOS"), contents.join("Helpers"))
    } else {
        (dir.path().join("app"), dir.path().join("app"))
    };
    std::fs::create_dir_all(&exe_dir).unwrap();
    std::fs::create_dir_all(&helpers).unwrap();
    let exe = exe_dir.join("Bastion");
    std::fs::write(&exe, b"").unwrap();
    let helper = helpers.join(HELPER_PROGRAM);
    std::fs::write(&helper, b"").unwrap();
    assert!(helper_path_allowed(&helper, &exe));
    // Elsewhere, under another name, or missing: refused.
    let elsewhere = dir.path().join(HELPER_PROGRAM);
    std::fs::write(&elsewhere, b"").unwrap();
    assert!(!helper_path_allowed(&elsewhere, &exe));
    let renamed = helpers.join("other-program");
    std::fs::write(&renamed, b"").unwrap();
    assert!(!helper_path_allowed(&renamed, &exe));
    assert!(!helper_path_allowed(&helpers.join("missing").join(HELPER_PROGRAM), &exe));
    #[cfg(unix)]
    {
        // A link inside the app's files that points outside is refused once resolved.
        let link_dir = dir.path().join("linked");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::fs::remove_file(&helper).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &helper).unwrap();
        assert!(!helper_path_allowed(&helper, &exe));
    }
}

#[cfg(unix)]
#[test]
fn other_launchers_wait_for_the_spawn_lock() {
    // While a helper's pipe is being made (SPAWN_LOCK held), a task start must wait.
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let held = spawn::spawn_guard();
    let done = Arc::new(AtomicBool::new(false));
    let flag = done.clone();
    let t = std::thread::spawn(move || {
        let never = AtomicBool::new(false);
        let _ = crate::tasks::run_local("/usr/bin/true", &[], Duration::from_secs(5), &never);
        flag.store(true, Ordering::SeqCst);
    });
    std::thread::sleep(Duration::from_millis(300));
    assert!(!done.load(Ordering::SeqCst), "the task started while the lock was held");
    drop(held);
    t.join().unwrap();
    assert!(done.load(Ordering::SeqCst));
}

#[test]
fn compiled_code_is_stored_checked_and_compiled_again_after_tampering() {
    use super::store::{CodeStore, Stored};
    let component = template_component();
    let dir = tempfile::tempdir().unwrap();
    let store = CodeStore::new(dir.path());
    let pool = Pool::with_program(program().clone(), FAST);
    let policy = Policy::default();
    let engine_key = start(Role::View).engine_key.clone();
    let key = view::cache_key(component, &engine_key);
    let code = view::compile(&pool, &launch(&policy), &store, &key, component).expect("compiles");
    assert_eq!(pool.running(), 0, "the compile helper is gone");
    assert_eq!(store.load(&key).unwrap(), Stored::Valid(code.clone()));

    // A tampered file is a mismatch, deleted; the next compile stores good code again.
    let file = std::fs::read_dir(store.dir()).unwrap().flatten().map(|e| e.path()).find(|p| p.extension().is_some_and(|x| x == "code")).unwrap();
    let mut bad = code.clone();
    bad[100] ^= 0xff;
    std::fs::write(&file, &bad).unwrap();
    assert_eq!(store.load(&key).unwrap(), Stored::Mismatch);
    assert!(!file.exists());
    view::compile(&pool, &launch(&policy), &store, &key, component).expect("compiles again");
    let Stored::Valid(again) = store.load(&key).unwrap() else { panic!("stored") };

    // The checked code loads and runs in a view helper.
    let helper = start(Role::View);
    helper.send(&ToHelper::Load { memory_limit: 256 << 20, compute_ms: 2_000, total: again.len() as u64 }).unwrap();
    send_bytes(&helper, &again);
    assert_eq!(next(&helper), Event::Message(ToCore::Loaded { error: None }));
}

// ---- PLUG-01 part 2: the macOS process limits (memory cap, one process, killed with the core) ----

#[test]
fn a_helper_that_exits_on_its_memory_cap_is_a_limit_kill() {
    assert_eq!(Stopped::Exited(Some(super::helper::EXIT_MEMORY)).reason(), StopReason::LimitKill);
    assert_eq!(Stopped::Exited(Some(1)).reason(), StopReason::Crash);
}

#[cfg(target_os = "macos")]
#[test]
fn the_core_reads_a_helpers_footprint_from_outside() {
    let helper = start(Role::View);
    let bytes = super::helper::footprint(helper.pid).expect("footprint");
    assert!(bytes > 1 << 20 && bytes < 1 << 30, "footprint {bytes}");
}

#[cfg(target_os = "macos")]
#[test]
fn a_helper_with_a_cap_below_its_own_size_never_says_hello() {
    let mut child = spawn::spawn(program(), Role::View, 1 << 20).unwrap();
    let deadline = Instant::now() + WAIT;
    while child.try_wait().is_none() {
        assert!(Instant::now() < deadline, "the helper did not leave");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(child.try_wait(), Some(super::helper::EXIT_MEMORY));
}

/// The helper is given a cap 32 MiB above its idle size, then made to hold a 60 MiB load: it
/// must stop itself, and the core must report a limit kill.
#[cfg(target_os = "macos")]
#[test]
fn a_helper_that_grows_past_its_memory_cap_is_stopped_as_a_limit_kill() {
    let cap = idle_footprint() + (32 << 20);
    let stopped = grow_past(cap, cap);
    assert_eq!(stopped.reason(), StopReason::LimitKill, "{stopped:?} (cap {cap})");
}

/// The helper's own cap is 1 GiB, so its watchdog never fires; only the core's outside check is
/// at idle + 32 MiB. The stop must come from the core: `Killed(LimitKill)`, not an exit.
#[cfg(target_os = "macos")]
#[test]
fn the_cores_outside_check_alone_stops_a_helper_over_its_cap() {
    let cap = idle_footprint() + (32 << 20);
    assert_eq!(grow_past(1 << 30, cap), Stopped::Killed(StopReason::LimitKill));
}

#[cfg(target_os = "macos")]
fn idle_footprint() -> u64 {
    let probe = start(Role::View);
    super::helper::footprint(probe.pid).expect("footprint")
}

/// Starts a helper with `helper_cap` (its watchdog) and `outside_cap` (the core's check), makes
/// it hold a 60 MiB load and returns how it stopped.
#[cfg(target_os = "macos")]
fn grow_past(helper_cap: u64, outside_cap: u64) -> Stopped {
    let helper = Helper::start_with_caps(program(), Role::View, helper_cap, outside_cap, FAST, true).expect("helper starts");
    let total: u64 = 60 << 20;
    helper.send(&ToHelper::Load { memory_limit: 256 << 20, compute_ms: 2_000, total }).unwrap();
    let piece = vec![7u8; CHUNK];
    let mut sent = 0u64;
    while sent < total {
        if helper.send(&ToHelper::Chunk(piece.clone())).is_err() {
            break;
        }
        sent += CHUNK as u64;
    }
    wait_stopped(&helper)
}

/// An orphan of the helper program (parent launchd, same user) is ended at pool creation;
/// the same program run from another path is left alone. A copy of `/bin/sleep` stands in for
/// a helper that ignores its closed pipe.
#[cfg(target_os = "macos")]
#[test]
fn orphaned_helpers_are_ended_when_a_pool_is_made() {
    let dir = std::env::temp_dir().join(format!("plug01-orphan-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fake = dir.join(HELPER_PROGRAM);
    let other = dir.join("not-the-helper");
    std::fs::copy("/bin/sleep", &fake).unwrap();
    std::fs::copy("/bin/sleep", &other).unwrap();
    // A copied platform binary is killed at exec until it is signed again (ad-hoc).
    for path in [&fake, &other] {
        assert!(Command::new("codesign").args(["-s", "-", "-f"]).arg(path).output().unwrap().status.success());
    }
    let orphan = |path: &Path| -> u32 {
        // `sh` starts it in the background and exits, so launchd becomes its parent.
        let out = Command::new("/bin/sh").arg("-c").arg(format!("'{}' 60 >/dev/null 2>&1 & echo $!", path.display())).output().unwrap();
        String::from_utf8(out.stdout).unwrap().trim().parse().unwrap()
    };
    let (target, bystander) = (orphan(&fake), orphan(&other));
    std::thread::sleep(Duration::from_millis(200));
    let _pool = Pool::with_program(fake.clone(), FAST);
    let deadline = Instant::now() + WAIT;
    while alive(target) {
        assert!(Instant::now() < deadline, "the orphan is still there");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(alive(bystander), "another program was ended");
    // SAFETY: ending the process this test started.
    unsafe { libc::kill(bystander as libc::pid_t, libc::SIGKILL) };
    let _ = std::fs::remove_dir_all(dir);
}

/// The "core" is a copy of this test binary that starts a helper, prints its pid and waits.
/// Killing that copy with SIGKILL (no clean-up runs) must end the helper too.
#[cfg(target_os = "macos")]
#[test]
#[ignore]
fn core_stand_in() {
    if std::env::var_os("BASTION_CORE_STAND_IN").is_none() {
        return;
    }
    let child = spawn::spawn(program(), Role::View, 1 << 30).unwrap();
    println!("HELPER_PID={}", child.pid);
    std::thread::sleep(Duration::from_secs(60));
    drop(child);
}

#[cfg(target_os = "macos")]
#[test]
fn a_helper_dies_with_its_core_even_when_the_core_is_killed() {
    use std::io::{BufRead, BufReader};
    let _ = program(); // build it here, not inside the stand-in
    let mut core = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "plugin::host::tests::core_stand_in", "--ignored", "--nocapture", "--test-threads=1"])
        .env("BASTION_CORE_STAND_IN", "1")
        .env("BASTION_TEST_PLUGIN_HELPER", program())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut pid = None;
    for line in BufReader::new(core.stdout.take().unwrap()).lines() {
        // libtest prints "test <name> ... " first, on the same line.
        if let Some((_, p)) = line.unwrap().split_once("HELPER_PID=") {
            pid = Some(p.trim().parse::<u32>().unwrap());
            break;
        }
    }
    let pid = pid.expect("the stand-in reported its helper");
    assert!(alive(pid));
    core.kill().unwrap();
    core.wait().unwrap();
    let deadline = Instant::now() + WAIT;
    while alive(pid) {
        assert!(Instant::now() < deadline, "the helper outlived its core");
        std::thread::sleep(Duration::from_millis(20));
    }
}
