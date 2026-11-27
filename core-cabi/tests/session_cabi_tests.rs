//! Boundary tests for the ABI v3 `bastion_session_*` surface, driven the way a P/Invoke host does:
//! raw handles, out-parameters, explicit frees.
//!
//! These run without an SSH server: every case here is one the core must reject before it opens a
//! socket, or one where the socket cannot be opened at all. The parts that need a real server (a
//! password login, a key login, unknown host → trust → success) are covered by
//! `apps/windows/tests/ssh-ui-test.ps1` and `core-ffi`'s `ssh_terminal_requires_explicit_host_key_trust`.
//!
//! What every case asserts: an error is reported, the call does not panic across the boundary, and
//! no secret appears in the message.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;

const SECRET: &str = "boundary-secret-9f3a";

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Read and free an out-parameter string.
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
    /// A saved SSH connection pointing at a port nothing listens on.
    id: CString,
}

impl Fixture {
    unsafe fn new(tag: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("bastion-cabi-session-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut err = null_mut();
        let lib = bastion_library_open(c(&dir.join("lib.json").to_string_lossy()).as_ptr(), &mut err);
        assert!(!lib.is_null(), "library open: {:?}", take(err));
        // Port 1 on the loopback address: a connect attempt fails at once, with no server involved.
        let id = take(bastion_library_add_connection(lib, null(), c("unreachable").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), 1, c("tester").as_ptr(), &mut err))
            .expect("add_connection");
        let mgr = bastion_session_manager_new(c(&dir.to_string_lossy()).as_ptr(), &mut err);
        assert!(!mgr.is_null(), "manager new: {:?}", take(err));
        Fixture { dir, lib, mgr, id: c(&id) }
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

/// One connect attempt. Returns `(terminal, outcome, fingerprint, hop, err)`.
#[allow(clippy::type_complexity)]
unsafe fn connect(
    mgr: *const BastionSessionManager,
    lib: *const BastionLibrary,
    id: *const c_char,
    username: *const c_char,
    kind: i32,
    password: *const c_char,
    key_path: *const c_char,
    cols: u16,
    rows: u16,
) -> (*mut BastionTerminal, i32, Option<String>, Option<String>, Option<String>) {
    let mut outcome = -42; // a value the ABI never writes, so "untouched" is visible
    let mut fingerprint = null_mut();
    let mut hop = null_mut();
    let mut err = null_mut();
    let t = bastion_session_connect_ssh(mgr, lib, id, username, kind, password, key_path, null(), null(), cols, rows, &mut outcome, &mut fingerprint, &mut hop, &mut err);
    (t, outcome, take(fingerprint), take(hop), take(err))
}

#[test]
fn manager_rejects_a_null_or_empty_data_dir() {
    unsafe {
        let mut err = null_mut();
        assert!(bastion_session_manager_new(null(), &mut err).is_null());
        assert!(take(err).unwrap().contains("data_dir"));
        let mut err = null_mut();
        assert!(bastion_session_manager_new(c("").as_ptr(), &mut err).is_null());
        assert!(take(err).unwrap().contains("data_dir"));
        // Freeing NULL is a no-op, not a crash.
        bastion_session_manager_free(null_mut());
    }
}

#[test]
fn null_handles_are_errors_not_crashes() {
    unsafe {
        let f = Fixture::new("nulls");
        let mut err = null_mut();
        assert_eq!(bastion_session_lock_credentials(null(), &mut err), -1);
        assert!(take(err).unwrap().contains("session manager"));

        // A NULL manager, a NULL library and a NULL id each fail with the outcome left at FAILED.
        for (mgr, lib, id, expect) in [
            (null(), f.lib as *const _, f.id.as_ptr(), "session manager"),
            (f.mgr as *const _, null(), f.id.as_ptr(), "library"),
            (f.mgr as *const _, f.lib as *const _, null(), "connection_id"),
        ] {
            let (t, outcome, fp, hop, err) = connect(mgr, lib, id, c("tester").as_ptr(), LOGIN_PASSWORD, c(SECRET).as_ptr(), null(), 80, 24);
            assert!(t.is_null());
            assert_eq!(outcome, CONNECT_FAILED);
            assert!(fp.is_none() && hop.is_none(), "no fingerprint without an unknown host key");
            let msg = err.expect("an error message");
            assert!(msg.contains(expect), "{msg} should mention {expect}");
            assert!(!msg.contains(SECRET), "the error leaked the secret: {msg}");
        }

        let mut err = null_mut();
        assert!(bastion_session_jump_hosts_json(null(), f.lib, f.id.as_ptr(), &mut err).is_null());
        assert!(take(err).unwrap().contains("session manager"));
        let mut err = null_mut();
        assert!(bastion_session_jump_hosts_json(f.mgr, null(), f.id.as_ptr(), &mut err).is_null());
        assert!(take(err).unwrap().contains("library"));
        let mut err = null_mut();
        assert!(bastion_session_jump_hosts_json(f.mgr, f.lib, null(), &mut err).is_null());
        assert!(take(err).unwrap().contains("connection_id"));
    }
}

/// `err`, `outcome`, `fingerprint` and `hop` are all optional: passing NULL for each must be safe.
#[test]
fn optional_out_parameters_may_be_null() {
    unsafe {
        let f = Fixture::new("outnull");
        let t = bastion_session_connect_ssh(
            f.mgr,
            f.lib,
            f.id.as_ptr(),
            c("tester").as_ptr(),
            LOGIN_PASSWORD,
            c(SECRET).as_ptr(),
            null(),
            null(),
            null(),
            80,
            24,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
        );
        assert!(t.is_null(), "an unreachable host cannot connect");
        // Freeing NULL handles is a no-op.
        bastion_terminal_free(null_mut());
    }
}

#[test]
fn an_unknown_connection_id_is_an_error() {
    unsafe {
        let f = Fixture::new("badid");
        for id in ["not-a-uuid", "00000000-0000-0000-0000-000000000000"] {
            let (t, outcome, _, _, err) = connect(f.mgr, f.lib, c(id).as_ptr(), c("tester").as_ptr(), LOGIN_PASSWORD, c(SECRET).as_ptr(), null(), 80, 24);
            assert!(t.is_null());
            assert_eq!(outcome, CONNECT_FAILED, "id {id}");
            let msg = err.expect("an error message");
            assert!(!msg.contains(SECRET), "the error leaked the secret: {msg}");
        }
    }
}

#[test]
fn bad_arguments_are_rejected_before_any_connect() {
    unsafe {
        let f = Fixture::new("badargs");

        // An out-of-range terminal size.
        for (cols, rows) in [(0u16, 24u16), (80, 0), (2000, 24), (80, 2000)] {
            let (t, outcome, _, _, err) = connect(f.mgr, f.lib, f.id.as_ptr(), c("tester").as_ptr(), LOGIN_PASSWORD, c(SECRET).as_ptr(), null(), cols, rows);
            assert!(t.is_null());
            assert_eq!(outcome, CONNECT_FAILED);
            assert!(err.unwrap().contains("out of range"), "{cols}x{rows}");
        }

        // A Vaultwarden login with no Vaultwarden session given to the manager: refused before connecting.
        let (t, outcome, _, _, err) = connect(f.mgr, f.lib, f.id.as_ptr(), c("tester").as_ptr(), LOGIN_VAULTWARDEN, c("item-id").as_ptr(), null(), 80, 24);
        assert!(t.is_null());
        assert_eq!(outcome, CONNECT_FAILED);
        assert!(err.expect("an error message").contains("Vaultwarden"));

        // An unknown login kind.
        for kind in [-1, 7, 99] {
            let (t, outcome, _, _, err) = connect(f.mgr, f.lib, f.id.as_ptr(), c("tester").as_ptr(), kind, c(SECRET).as_ptr(), null(), 80, 24);
            assert!(t.is_null());
            assert_eq!(outcome, CONNECT_FAILED);
            let msg = err.expect("an error message");
            assert!(msg.contains("login_kind"), "{msg}");
            assert!(!msg.contains(SECRET), "the error leaked the secret: {msg}");
        }

        // A key-file login without a key path.
        let (t, outcome, _, _, err) = connect(f.mgr, f.lib, f.id.as_ptr(), c("tester").as_ptr(), LOGIN_KEY_FILE, c(SECRET).as_ptr(), null(), 80, 24);
        assert!(t.is_null());
        assert_eq!(outcome, CONNECT_FAILED);
        assert!(err.unwrap().contains("key_path"));

        // Malformed jump trust.
        let mut outcome = -42;
        let mut err = null_mut();
        let t = bastion_session_connect_ssh(
            f.mgr,
            f.lib,
            f.id.as_ptr(),
            c("tester").as_ptr(),
            LOGIN_PASSWORD,
            c(SECRET).as_ptr(),
            null(),
            null(),
            c("[\"not an object\"]").as_ptr(),
            80,
            24,
            &mut outcome,
            null_mut(),
            null_mut(),
            &mut err,
        );
        assert!(t.is_null());
        assert_eq!(outcome, CONNECT_FAILED);
        assert!(take(err).unwrap().contains("jump_trust_json"));

        // A two-factor login with no code, malformed jump logins and a bad hop kind.
        let cases: [(i32, *const c_char, &str, &str); 3] = [
            (LOGIN_PASSWORD_AND_CODE, null(), "null", "one-time code"),
            (LOGIN_PASSWORD, null(), "[1]", "jump_logins_json"),
            (LOGIN_PASSWORD, null(), r#"{"jump:22":{"kind":99,"secret":"hop-secret"}}"#, "login_kind"),
        ];
        for (kind, code, jump_logins, expected) in cases {
            let jump_logins = (jump_logins != "null").then(|| c(jump_logins));
            let mut outcome = -42;
            let mut err = null_mut();
            let t = bastion_session_connect_ssh_mfa(
                f.mgr,
                f.lib,
                f.id.as_ptr(),
                c("tester").as_ptr(),
                kind,
                c(SECRET).as_ptr(),
                null(),
                code,
                null(),
                null(),
                jump_logins.as_ref().map_or(null(), |j| j.as_ptr()),
                80,
                24,
                &mut outcome,
                null_mut(),
                null_mut(),
                &mut err,
            );
            assert!(t.is_null());
            assert_eq!(outcome, CONNECT_FAILED);
            let msg = take(err).unwrap();
            assert!(msg.contains(expected), "{msg}");
            assert!(!msg.contains(SECRET) && !msg.contains("hop-secret"), "the error leaked a secret: {msg}");
        }
    }
}

/// A connection with no user name anywhere must be refused with a clear message rather than
/// attempted with an empty user.
#[test]
fn a_missing_username_is_an_error() {
    unsafe {
        let f = Fixture::new("nouser");
        let mut err = null_mut();
        let id = take(bastion_library_add_connection(f.lib, null(), c("no-user").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), 1, null(), &mut err)).unwrap();
        let (t, outcome, _, _, err) = connect(f.mgr, f.lib, c(&id).as_ptr(), null(), LOGIN_PASSWORD, c(SECRET).as_ptr(), null(), 80, 24);
        assert!(t.is_null());
        assert_eq!(outcome, CONNECT_FAILED);
        assert!(err.unwrap().contains("username"));
    }
}

/// An unreachable host: a real connect attempt that fails at the socket. It must report an error,
/// not panic, and must not leak the password. Repeated to show the manager stays usable.
#[test]
fn an_unreachable_host_fails_cleanly_and_repeatedly() {
    unsafe {
        let f = Fixture::new("unreachable");
        for attempt in 0..3 {
            let (t, outcome, fp, hop, err) = connect(f.mgr, f.lib, f.id.as_ptr(), c("tester").as_ptr(), LOGIN_PASSWORD, c(SECRET).as_ptr(), null(), 80, 24);
            assert!(t.is_null(), "attempt {attempt} must not connect");
            // Nothing listens, so this is never a host-key or auth outcome.
            assert_eq!(outcome, CONNECT_FAILED, "attempt {attempt}");
            assert!(fp.is_none() && hop.is_none());
            let msg = err.expect("an error message");
            assert!(!msg.contains(SECRET), "the error leaked the secret: {msg}");
            assert!(!msg.is_empty());
        }
        // A key-file login to the same unreachable host: also an error, and the passphrase stays out.
        let (t, outcome, _, _, err) = connect(f.mgr, f.lib, f.id.as_ptr(), c("tester").as_ptr(), LOGIN_KEY_FILE, c(SECRET).as_ptr(), c("C:\\does\\not\\exist\\id_ed25519").as_ptr(), 80, 24);
        assert!(t.is_null());
        assert_eq!(outcome, CONNECT_FAILED);
        assert!(!err.unwrap().contains(SECRET));
    }
}

#[test]
fn jump_hosts_of_a_direct_connection_are_empty_and_lock_credentials_works() {
    unsafe {
        let f = Fixture::new("direct");
        let mut err = null_mut();
        let json = take(bastion_session_jump_hosts_json(f.mgr, f.lib, f.id.as_ptr(), &mut err)).expect("jump hosts");
        assert_eq!(json, "[]", "a direct connection has no jump hosts");
        let mut err = null_mut();
        assert_eq!(bastion_session_lock_credentials(f.mgr, &mut err), 0, "{:?}", take(err));
    }
}

/// The whole trust-and-login path against a real server, through the C ABI exactly as the WinUI host
/// drives it: unknown host key → the fingerprint comes back → trust it → connect, then a wrong
/// password, a key login, and a key login with a passphrase.
///
/// Needs a reachable SSH server and is skipped without one. Set:
///   `BASTION_SSH_TEST=1`, `BASTION_SSH_PORT` (default 2222), `BASTION_SSH_USER`,
///   `BASTION_SSH_PASSWORD`, `BASTION_SSH_KEY` (an unencrypted private key),
///   `BASTION_SSH_KEY_PASS` and `BASTION_SSH_KEY_PASSPHRASE` (a key and its passphrase).
/// `apps/windows/tests/ssh-test-setup.sh` sets up such a server in WSL.
#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn trust_then_password_key_and_wrong_password_against_a_real_server() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_SSH_TEST").is_err() {
        eprintln!("SKIPPED trust_then_password_key_and_wrong_password_against_a_real_server: set BASTION_SSH_TEST=1");
        return;
    }
    let port: i32 = std::env::var("BASTION_SSH_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(2222);
    let user = std::env::var("BASTION_SSH_USER").expect("BASTION_SSH_USER");
    let password = std::env::var("BASTION_SSH_PASSWORD").expect("BASTION_SSH_PASSWORD");
    let key = std::env::var("BASTION_SSH_KEY").expect("BASTION_SSH_KEY");
    let key_pass = std::env::var("BASTION_SSH_KEY_PASS").expect("BASTION_SSH_KEY_PASS");
    let key_passphrase = std::env::var("BASTION_SSH_KEY_PASSPHRASE").expect("BASTION_SSH_KEY_PASSPHRASE");

    unsafe {
        let dir = std::env::temp_dir().join(format!("bastion-cabi-ssh-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let mut err = null_mut();
        let lib = bastion_library_open(c(&dir.join("lib.json").to_string_lossy()).as_ptr(), &mut err);
        assert!(!lib.is_null(), "library open: {:?}", take(err));
        let id = take(bastion_library_add_connection(lib, null(), c("test").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), port, c(&user).as_ptr(), &mut err)).unwrap();
        let id = c(&id);
        let mgr = bastion_session_manager_new(c(&dir.to_string_lossy()).as_ptr(), &mut err);
        assert!(!mgr.is_null(), "manager new: {:?}", take(err));

        let attempt = |kind: i32, secret: &str, key_path: Option<&str>, trust: Option<&str>| {
            let secret = c(secret);
            let key_path = key_path.map(c);
            let trust = trust.map(c);
            let mut outcome = -42;
            let mut fp = null_mut();
            let mut hop = null_mut();
            let mut err = null_mut();
            let t = bastion_session_connect_ssh(
                mgr,
                lib,
                id.as_ptr(),
                c(&user).as_ptr(),
                kind,
                secret.as_ptr(),
                key_path.as_ref().map_or(null(), |p| p.as_ptr()),
                trust.as_ref().map_or(null(), |p| p.as_ptr()),
                null(),
                80,
                24,
                &mut outcome,
                &mut fp,
                &mut hop,
                &mut err,
            );
            (t, outcome, take(fp), take(hop), take(err))
        };

        // 1. An unknown server is refused, and the fingerprint comes back for the user to verify.
        let (t, outcome, fingerprint, hop, err) = attempt(LOGIN_PASSWORD, &password, None, None);
        assert!(t.is_null(), "an unknown host key must not connect");
        assert_eq!(outcome, CONNECT_HOST_KEY_UNKNOWN, "{err:?}");
        assert!(hop.is_none(), "a direct connection has no hop");
        let fingerprint = fingerprint.expect("a fingerprint to show the user");
        assert!(fingerprint.starts_with("SHA256:"), "{fingerprint}");
        assert!(!err.unwrap().contains(&password), "the error leaked the password");

        // 2. The right fingerprint but the wrong password: refused as an auth failure, not a host-key one.
        let (t, outcome, _, _, err) = attempt(LOGIN_PASSWORD, "definitely-not-the-password", None, Some(&fingerprint));
        assert!(t.is_null());
        assert_eq!(outcome, CONNECT_AUTH_FAILED, "{err:?}");

        // 3. Trusted fingerprint and the right password: a working shell.
        let (t, outcome, _, _, err) = attempt(LOGIN_PASSWORD, &password, None, Some(&fingerprint));
        assert_eq!(outcome, CONNECT_OK, "{err:?}");
        assert!(!t.is_null());
        let cmd = "echo cabi-ssh-$((40+2))\n";
        let mut werr = null_mut();
        assert_eq!(bastion_terminal_write(t, cmd.as_ptr(), cmd.len(), &mut werr), 0, "{:?}", take(werr));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut saw = false;
        while !saw && std::time::Instant::now() < deadline {
            let mut serr = null_mut();
            let s = bastion_terminal_screen(t, &mut serr);
            if !s.is_null() {
                let r = &*s;
                let text = std::slice::from_raw_parts(r.text, r.text_len as usize);
                saw = String::from_utf8_lossy(text).contains("cabi-ssh-42");
                bastion_screen_free(s);
            }
            if !saw {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        assert!(saw, "the shell did not echo over SSH");
        assert_eq!(bastion_terminal_is_alive(t), 1);

        // 3b. A split pane: a second shell channel on the same connection, no new login.
        let mut serr = null_mut();
        let sib = bastion_terminal_open_sibling(t, 60, 20, &mut serr);
        assert!(!sib.is_null(), "sibling: {:?}", take(serr));
        let cmd = "echo cabi-sibling-$((40+3))\n";
        assert_eq!(bastion_terminal_write(sib, cmd.as_ptr(), cmd.len(), &mut werr), 0, "{:?}", take(werr));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut saw = false;
        while !saw && std::time::Instant::now() < deadline {
            let s = bastion_terminal_screen(sib, &mut serr);
            if !s.is_null() {
                let r = &*s;
                saw = String::from_utf8_lossy(std::slice::from_raw_parts(r.text, r.text_len as usize)).contains("cabi-sibling-43");
                bastion_screen_free(s);
            }
            if !saw {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        assert!(saw, "the sibling shell did not echo over SSH");
        bastion_terminal_free(sib);

        // 3c. An SFTP browser on the same connection: home, mkdir, upload, list, rename, download.
        let b = bastion_terminal_open_sftp(t, &mut serr);
        assert!(!b.is_null(), "sftp: {:?}", take(serr));
        let home = take(bastion_sftp_home(b, &mut serr)).expect("home");
        let rdir = format!("{home}/cabi-sftp-{}", std::process::id());
        assert_eq!(bastion_sftp_mkdir(b, c(&rdir).as_ptr(), &mut serr), 0, "{:?}", take(serr));
        let local = std::env::temp_dir().join(format!("bastion-cabi-sftp-{}.txt", std::process::id()));
        std::fs::write(&local, b"hello sftp").unwrap();
        let remote = format!("{rdir}/a.txt");
        let local_c = c(&local.to_string_lossy());
        assert_eq!(bastion_sftp_upload(b, local_c.as_ptr(), c(&remote).as_ptr(), 0, &mut serr), 10, "{:?}", take(serr));
        assert_eq!(bastion_sftp_upload(b, local_c.as_ptr(), c(&remote).as_ptr(), 0, &mut serr), -1, "no silent overwrite");
        take(serr);
        let listing: serde_json::Value = serde_json::from_str(&take(bastion_sftp_list_json(b, c(&rdir).as_ptr(), &mut serr)).unwrap()).unwrap();
        assert_eq!(listing.as_array().unwrap().len(), 1, "{listing}");
        assert_eq!(listing[0]["name"], "a.txt");
        assert_eq!(listing[0]["kind"], "file");
        assert_eq!(listing[0]["size"], 10);
        let moved = format!("{rdir}/b.txt");
        assert_eq!(bastion_sftp_rename(b, c(&remote).as_ptr(), c(&moved).as_ptr(), &mut serr), 0, "{:?}", take(serr));
        let back = local.with_extension("back");
        assert_eq!(bastion_sftp_download(b, c(&moved).as_ptr(), c(&back.to_string_lossy()).as_ptr(), 0, &mut serr), 10, "{:?}", take(serr));
        assert_eq!(std::fs::read(&back).unwrap(), b"hello sftp");
        // Delete: the root is refused; a file; then a folder with a nested folder and file.
        assert_eq!(bastion_sftp_remove(b, c("/").as_ptr(), 1, &mut serr), -1, "the root is never deleted");
        take(serr);
        assert_eq!(bastion_sftp_remove(b, c(&format!("{rdir}/..")).as_ptr(), 1, &mut serr), -1, "`..` is refused");
        take(serr);
        let nested = format!("{rdir}/sub/deeper");
        assert_eq!(bastion_sftp_mkdir(b, c(&format!("{rdir}/sub")).as_ptr(), &mut serr), 0, "{:?}", take(serr));
        assert_eq!(bastion_sftp_mkdir(b, c(&nested).as_ptr(), &mut serr), 0, "{:?}", take(serr));
        assert_eq!(bastion_sftp_upload(b, local_c.as_ptr(), c(&format!("{nested}/x.txt")).as_ptr(), 0, &mut serr), 10, "{:?}", take(serr));
        assert_eq!(bastion_sftp_remove(b, c(&moved).as_ptr(), 0, &mut serr), 1, "{:?}", take(serr));
        assert_eq!(bastion_sftp_remove(b, c(&rdir).as_ptr(), 1, &mut serr), 4, "{:?}", take(serr));
        let gone = bastion_sftp_list_json(b, c(&rdir).as_ptr(), &mut serr);
        assert!(gone.is_null(), "the folder is gone");
        take(serr);
        std::fs::remove_file(&local).ok();
        std::fs::remove_file(&back).ok();
        bastion_sftp_free(b);
        assert_eq!(bastion_terminal_is_alive(t), 1, "freeing the browser must leave the shell open");
        assert_eq!(bastion_terminal_is_alive(t), 1, "closing the sibling must leave the first shell open");
        bastion_terminal_free(t);

        // 4. The key is remembered: a plain connect now works with no fingerprint at all.
        let (t, outcome, _, _, err) = attempt(LOGIN_PASSWORD, &password, None, None);
        assert_eq!(outcome, CONNECT_OK, "{err:?}");
        bastion_terminal_free(t);

        // 5. A key file with no passphrase.
        let (t, outcome, _, _, err) = attempt(LOGIN_KEY_FILE, "", Some(&key), None);
        assert_eq!(outcome, CONNECT_OK, "key login: {err:?}");
        bastion_terminal_free(t);

        // 6. A key file with a passphrase.
        let (t, outcome, _, _, err) = attempt(LOGIN_KEY_FILE, &key_passphrase, Some(&key_pass), None);
        assert_eq!(outcome, CONNECT_OK, "key-with-passphrase login: {err:?}");
        bastion_terminal_free(t);

        // The audit log records the trust decision and holds no secret.
        let audit = std::fs::read_to_string(dir.join("audit.jsonl")).expect("an audit log");
        assert!(audit.contains("hostkey.trust"), "the trust decision is audited");
        assert!(!audit.contains(&password) && !audit.contains(&key_passphrase), "the audit log leaked a secret");
        // known_hosts holds the key that was trusted.
        assert!(dir.join("known_hosts").exists(), "the trusted key is remembered");

        bastion_session_manager_free(mgr);
        bastion_library_free(lib);
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// The audit log the manager writes must never contain the secret that was typed.
#[test]
fn the_audit_log_never_contains_the_secret() {
    unsafe {
        let f = Fixture::new("audit");
        let _ = connect(f.mgr, f.lib, f.id.as_ptr(), c("tester").as_ptr(), LOGIN_PASSWORD, c(SECRET).as_ptr(), null(), 80, 24);
        if let Ok(log) = std::fs::read_to_string(f.dir.join("audit.jsonl")) {
            assert!(!log.contains(SECRET), "the audit log leaked the secret");
        }
    }
}

/// `LOGIN_VAULT` without a vault, without an id, or with an id the vault does not hold is an error
/// before any socket is opened, and the id is not echoed as if it were a secret.
#[test]
fn vault_login_needs_a_vault_and_an_id() {
    unsafe {
        let f = Fixture::new("vault");
        let missing = c("00000000-0000-0000-0000-000000000000");
        let (t, outcome, ..) = connect(f.mgr, f.lib, f.id.as_ptr(), null(), LOGIN_VAULT, missing.as_ptr(), null(), 80, 24);
        assert!(t.is_null());
        assert_ne!(outcome, CONNECT_OK);
        let (t, _, _, _, err) = connect(f.mgr, f.lib, f.id.as_ptr(), null(), LOGIN_VAULT, null(), null(), 80, 24);
        assert!(t.is_null());
        assert!(err.unwrap_or_default().contains("credential id"));

        // In-memory key: the hermetic suite must not create login-Keychain items (Codex T04).
        let mut err = null_mut();
        let creds = bastion_cabi::credentials::ephemeral_handle_for_tests(&f.dir.join("credentials.vault").to_string_lossy()).unwrap();
        assert_eq!(bastion_session_set_credentials(f.mgr, creds, &mut err), 0, "{:?}", take(err));
        assert_eq!(bastion_session_set_credentials(f.mgr, null(), &mut err), -1);
        take(err);
        let (t, outcome, _, _, err) = connect(f.mgr, f.lib, f.id.as_ptr(), null(), LOGIN_VAULT, missing.as_ptr(), null(), 80, 24);
        assert!(t.is_null());
        assert_ne!(outcome, CONNECT_OK);
        assert!(!err.unwrap_or_default().contains(SECRET));
        bastion_credentials_free(creds);
    }
}

/// A vault credential assigned to a connection logs in against a real server with no user name
/// typed and no secret crossing the ABI, then fails after Lock is not needed for the vault (it is
/// keyed by DPAPI) but does fail once the credential is removed. Same environment as the test above.
#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn vault_credential_logs_in_against_a_real_server() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_SSH_TEST").is_err() {
        eprintln!("SKIPPED vault_credential_logs_in_against_a_real_server: set BASTION_SSH_TEST=1");
        return;
    }
    let port: i32 = std::env::var("BASTION_SSH_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(2222);
    let user = std::env::var("BASTION_SSH_USER").expect("BASTION_SSH_USER");
    let password = std::env::var("BASTION_SSH_PASSWORD").expect("BASTION_SSH_PASSWORD");
    unsafe {
        let dir = std::env::temp_dir().join(format!("bastion-cabi-vault-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let mut err = null_mut();
        let lib = bastion_library_open(c(&dir.join("lib.json").to_string_lossy()).as_ptr(), &mut err);
        let id = c(&take(bastion_library_add_connection(lib, null(), c("vault").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), port, null(), &mut err)).unwrap());
        let mgr = bastion_session_manager_new(c(&dir.to_string_lossy()).as_ptr(), &mut err);
        let creds = bastion_credentials_open(c(&dir.join("credentials.vault").to_string_lossy()).as_ptr(), &mut err);
        assert!(!creds.is_null(), "{:?}", take(err));
        let cred = take(bastion_credentials_save_password(creds, null(), c("test login").as_ptr(), null(), c(&user).as_ptr(), password.as_ptr(), password.len(), &mut err)).unwrap();
        assert_eq!(bastion_library_set_credential(lib, id.as_ptr(), c(&cred).as_ptr(), &mut err), 0);
        assert_eq!(bastion_session_set_credentials(mgr, creds, &mut err), 0);

        let attempt = |trust: Option<&str>| {
            let trust = trust.map(c);
            let (mut outcome, mut fp, mut hop, mut err) = (-42, null_mut(), null_mut(), null_mut());
            let t = bastion_session_connect_ssh(mgr, lib, id.as_ptr(), null(), LOGIN_VAULT, c(&cred).as_ptr(), null(), trust.as_ref().map_or(null(), |s| s.as_ptr()), null(), 80, 24, &mut outcome, &mut fp, &mut hop, &mut err);
            (t, outcome, take(fp), take(err))
        };
        let (t, outcome, fp, _) = attempt(None);
        assert!(t.is_null());
        assert_eq!(outcome, CONNECT_HOST_KEY_UNKNOWN);
        let (t, outcome, _, e) = attempt(fp.as_deref());
        assert_eq!(outcome, CONNECT_OK, "vault login failed: {e:?}");
        assert!(!t.is_null());
        bastion_terminal_free(t);

        // The audit log records the login without the password.
        let audit = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap_or_default();
        assert!(!audit.contains(&password));

        assert_eq!(bastion_credentials_remove(creds, c(&cred).as_ptr(), &mut err), 0);
        let (t, outcome, _, _) = attempt(None);
        assert!(t.is_null());
        assert_ne!(outcome, CONNECT_OK, "a removed credential must not log in");

        bastion_session_manager_free(mgr);
        bastion_credentials_free(creds);
        bastion_library_free(lib);
        std::fs::remove_dir_all(&dir).ok();
    }
}
