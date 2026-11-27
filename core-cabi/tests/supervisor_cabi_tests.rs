//! Boundary tests for the ABI v8 `bastion_supervisor_*` surface (reconnect, cancel, sleep/wake).
//!
//! No SSH server is needed: the supervised "link" is a local program in a terminal, which is all
//! the supervisor watches (is the shell alive?). Reconnect attempts go to a saved connection on
//! 127.0.0.1:1, where nothing listens, so they fail at once and the give-up path is exercised.
//! A successful reconnect against a real server is covered by
//! `a_dropped_key_session_reconnects_against_a_real_server` (needs `BASTION_SSH_TEST=1`).
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use bastion_cabi::*;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    bastion_string_free(p);
    Some(s)
}

struct Fixture {
    dir: std::path::PathBuf,
    lib: *mut BastionLibrary,
    mgr: *mut BastionSessionManager,
    id: CString,
}

impl Fixture {
    unsafe fn new(tag: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("bastion-cabi-sup-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut err = null_mut();
        let lib = bastion_library_open(c(&dir.join("lib.json").to_string_lossy()).as_ptr(), &mut err);
        assert!(!lib.is_null(), "library open: {:?}", take(err));
        let id = take(bastion_library_add_connection(lib, null(), c("unreachable").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), 1, c("tester").as_ptr(), &mut err))
            .expect("add_connection");
        let mgr = bastion_session_manager_new(c(&dir.to_string_lossy()).as_ptr(), &mut err);
        assert!(!mgr.is_null(), "manager new: {:?}", take(err));
        Fixture { dir, lib, mgr, id: c(&id) }
    }

    /// A terminal running a program that exits after `secs` seconds (0 = at once).
    unsafe fn program(&self, secs: u32) -> *mut BastionTerminal {
        #[cfg(windows)]
        let (prog, args) = ("cmd.exe", format!(r#"["/c","ping -n {} 127.0.0.1 >nul"]"#, secs + 1));
        #[cfg(not(windows))]
        let (prog, args) = ("/bin/sh", format!(r#"["-c","sleep {secs}"]"#));
        let mut err = null_mut();
        let t = bastion_terminal_spawn(c(prog).as_ptr(), c(&args).as_ptr(), 80, 24, &mut err);
        assert!(!t.is_null(), "spawn: {:?}", take(err));
        t
    }

    unsafe fn supervise(&self, t: *const BastionTerminal, kind: i32, cred: Option<&str>, attempts: u32) -> *mut BastionSupervisor {
        let cred = cred.map(c);
        let mut err = null_mut();
        let s = bastion_supervisor_new(self.mgr, self.lib, t, self.id.as_ptr(), null(), kind, cred.as_ref().map_or(null(), |p| p.as_ptr()), attempts, &mut err);
        assert!(!s.is_null(), "supervisor new: {:?}", take(err));
        s
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        unsafe {
            bastion_session_manager_free(self.mgr);
            bastion_library_free(self.lib);
        }
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

unsafe fn state(s: *const BastionSupervisor) -> (i32, u32, Option<String>) {
    let mut attempt = 99;
    let mut reason = null_mut();
    let st = bastion_supervisor_state(s, &mut attempt, &mut reason);
    (st, attempt, take(reason))
}

/// Poll until the state is `want` (recording every state seen) or fail after `secs`.
unsafe fn wait_for(s: *const BastionSupervisor, want: i32, secs: u64, seen: &mut Vec<i32>) -> (u32, Option<String>) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let (st, attempt, reason) = state(s);
        if seen.last() != Some(&st) {
            seen.push(st);
        }
        if st == want {
            return (attempt, reason);
        }
        assert!(Instant::now() < deadline, "state {want} not reached; saw {seen:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_password_session_is_not_reconnected_silently() {
    unsafe {
        let f = Fixture::new("password");
        let t = f.program(0);
        // Even if a host passed something here for a password login, it is ignored, never used.
        let s = f.supervise(t, LOGIN_PASSWORD, Some("not-a-password-but-ignored"), 3);
        let mut seen = vec![];
        let (_, reason) = wait_for(s, STATE_FAILED, 10, &mut seen);
        assert!(!seen.contains(&STATE_RECONNECTING), "a password login must not auto-reconnect: {seen:?}");
        assert!(reason.is_some(), "the UI gets a reason to show");
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(state(s).0, STATE_FAILED, "it stays failed for the user to reconnect by hand");
        assert_eq!(bastion_supervisor_link(s), 1, "no new link");
        bastion_supervisor_free(s);
        bastion_terminal_free(t);
    }
}

/// F06: a shell without its own supervisor is never redialled from the C ABI, whatever the
/// login kind: a drop ends in failed without a reconnect attempt and without a new link.
#[test]
fn an_unsupervised_shell_is_never_redialled() {
    unsafe {
        let f = Fixture::new("retry");
        let t = f.program(0);
        let s = f.supervise(t, LOGIN_KEY_FILE, Some(&f.dir.join("no-such-key").to_string_lossy()), 3);
        let mut seen = vec![];
        let (_, reason) = wait_for(s, STATE_FAILED, 15, &mut seen);
        assert!(reason.is_some());
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!seen.contains(&STATE_RECONNECTING), "{seen:?}");
        assert_eq!(state(s).0, STATE_FAILED);
        assert_eq!(bastion_supervisor_link(s), 1);
        bastion_supervisor_free(s);
        bastion_terminal_free(t);
    }
}

#[test]
fn cancel_closes_the_shell() {
    unsafe {
        let f = Fixture::new("sleep");
        let t = f.program(60);
        let s = f.supervise(t, LOGIN_KEY_FILE, Some("C:/no/such/key"), 1);
        let mut seen = vec![];
        wait_for(s, STATE_CONNECTED, 10, &mut seen);
        assert_eq!(bastion_supervisor_event(s, EVENT_CANCEL, null_mut()), 0);
        wait_for(s, STATE_CLOSED, 10, &mut seen);
        let deadline = Instant::now() + Duration::from_secs(10);
        while bastion_terminal_is_alive(t) == 1 {
            assert!(Instant::now() < deadline, "cancel must close the shell");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!seen.contains(&STATE_RECONNECTING), "{seen:?}");
        bastion_supervisor_free(s);
        bastion_terminal_free(t);
    }
}

#[test]
fn free_cancels_and_closes_the_shell() {
    unsafe {
        let f = Fixture::new("free");
        let t = f.program(60);
        let s = f.supervise(t, LOGIN_PASSWORD, None, 1);
        wait_for(s, STATE_CONNECTED, 10, &mut vec![]);
        // The host's handle and one taken from the supervisor are the same shell.
        let mut err = null_mut();
        let t2 = bastion_supervisor_terminal(s, &mut err);
        assert!(!t2.is_null(), "{:?}", take(err));
        bastion_supervisor_free(s);
        let deadline = Instant::now() + Duration::from_secs(10);
        while bastion_terminal_is_alive(t) == 1 || bastion_terminal_is_alive(t2) == 1 {
            assert!(Instant::now() < deadline, "freeing the supervisor must close the shell");
            std::thread::sleep(Duration::from_millis(20));
        }
        bastion_terminal_free(t2);
        bastion_terminal_free(t);
    }
}

#[test]
fn bad_arguments_are_errors_not_crashes() {
    unsafe {
        let f = Fixture::new("args");
        let t = f.program(30);
        let mut err = null_mut();
        let new = |m, l, t, id: *const c_char, kind, cred: *const c_char, n, err: &mut *mut c_char| bastion_supervisor_new(m, l, t, id, null(), kind, cred, n, err);
        let key = c("C:/k");
        for (m, l, tt, id, kind, cred, n, what) in [
            (null(), f.lib as *const _, t as *const _, f.id.as_ptr(), LOGIN_PASSWORD, null(), 1, "manager"),
            (f.mgr as *const _, null(), t as *const _, f.id.as_ptr(), LOGIN_PASSWORD, null(), 1, "library"),
            (f.mgr as *const _, f.lib as *const _, null(), f.id.as_ptr(), LOGIN_PASSWORD, null(), 1, "terminal"),
            (f.mgr as *const _, f.lib as *const _, t as *const _, null(), LOGIN_PASSWORD, null(), 1, "connection_id"),
            (f.mgr as *const _, f.lib as *const _, t as *const _, f.id.as_ptr(), LOGIN_PASSWORD, null(), 0, "max_attempts"),
            (f.mgr as *const _, f.lib as *const _, t as *const _, f.id.as_ptr(), LOGIN_PASSWORD, null(), MAX_RECONNECT_ATTEMPTS + 1, "max_attempts"),
            (f.mgr as *const _, f.lib as *const _, t as *const _, f.id.as_ptr(), 42, key.as_ptr(), 1, "login_kind"),
            (f.mgr as *const _, f.lib as *const _, t as *const _, f.id.as_ptr(), LOGIN_VAULT, null(), 1, "credential id"),
            (f.mgr as *const _, f.lib as *const _, t as *const _, f.id.as_ptr(), LOGIN_KEY_FILE, null(), 1, "key_path"),
        ] {
            let s = new(m, l, tt, id, kind, cred, n, &mut err);
            assert!(s.is_null(), "{what} must be rejected");
            let msg = take(err).expect("an error message");
            assert!(msg.contains(what), "{what}: {msg}");
        }
        assert_eq!(bastion_supervisor_state(null(), null_mut(), null_mut()), -1);
        assert_eq!(bastion_supervisor_link(null()), 0);
        assert!(bastion_supervisor_terminal(null(), null_mut()).is_null());
        assert_eq!(bastion_supervisor_event(null(), EVENT_WAKE, null_mut()), -1);
        bastion_supervisor_free(null_mut());

        let s = f.supervise(t, LOGIN_PASSWORD, None, 1);
        let mut err = null_mut();
        assert_eq!(bastion_supervisor_event(s, 7, &mut err), -1);
        assert!(take(err).unwrap().contains("unknown event"));
        bastion_supervisor_free(s);
        bastion_terminal_free(t);
    }
}

/// A key-file login reconnects on its own after the shell drops, against a real server. Skipped
/// without one; see `session_cabi_tests.rs` for the environment variables and
/// `apps/windows/tests/ssh-test-setup.sh` for the server.
#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn a_live_session_that_has_not_opted_in_is_not_redialled() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_SSH_TEST").is_err() {
        eprintln!("SKIPPED a_live_session_that_has_not_opted_in_is_not_redialled: set BASTION_SSH_TEST=1");
        return;
    }
    let port: i32 = std::env::var("BASTION_SSH_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(2222);
    let user = std::env::var("BASTION_SSH_USER").expect("BASTION_SSH_USER");
    let key = std::env::var("BASTION_SSH_KEY").expect("BASTION_SSH_KEY");
    unsafe {
        let dir = std::env::temp_dir().join(format!("bastion-cabi-sup-live-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let mut err = null_mut();
        let lib = bastion_library_open(c(&dir.join("lib.json").to_string_lossy()).as_ptr(), &mut err);
        let id = c(&take(bastion_library_add_connection(lib, null(), c("live").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), port, c(&user).as_ptr(), &mut err)).unwrap());
        let mgr = bastion_session_manager_new(c(&dir.to_string_lossy()).as_ptr(), &mut err);
        let connect = |trust: *const c_char| {
            let (mut outcome, mut fp, mut hop, mut err) = (-1, null_mut(), null_mut(), null_mut());
            let t = bastion_session_connect_ssh(mgr, lib, id.as_ptr(), c(&user).as_ptr(), LOGIN_KEY_FILE, null(), c(&key).as_ptr(), trust, null(), 80, 24, &mut outcome, &mut fp, &mut hop, &mut err);
            (t, outcome, take(fp), take(err))
        };
        let (_, outcome, fp, e) = connect(null());
        assert_eq!(outcome, CONNECT_HOST_KEY_UNKNOWN, "{e:?}");
        let (t, outcome, _, e) = connect(c(&fp.unwrap()).as_ptr());
        assert_eq!(outcome, CONNECT_OK, "{e:?}");

        let s = bastion_supervisor_new(mgr, lib, t, id.as_ptr(), c(&user).as_ptr(), LOGIN_KEY_FILE, c(&key).as_ptr(), 3, &mut err);
        assert!(!s.is_null(), "{:?}", take(err));
        let mut seen = vec![];
        wait_for(s, STATE_CONNECTED, 10, &mut seen);
        // F06: a far-side exit ends the session on purpose, so it is not redialled, even with
        // auto-reconnect on by default since owner point W25 (only a lost link is retried).
        let exit = c("exit\r");
        bastion_terminal_write(t, exit.as_ptr() as *const u8, 5, null_mut());
        std::thread::sleep(Duration::from_secs(5));
        assert_eq!(bastion_supervisor_link(s), 1, "no new link without the opt-in");
        assert_ne!(state(s).0, STATE_RECONNECTING);
        let t2 = bastion_supervisor_terminal(s, null_mut());
        bastion_supervisor_free(s);
        bastion_terminal_free(t2);
        bastion_terminal_free(t);
        bastion_session_manager_free(mgr);
        bastion_library_free(lib);
        std::fs::remove_dir_all(&dir).ok();
    }
}
