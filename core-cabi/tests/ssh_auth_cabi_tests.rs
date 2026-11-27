//! SSH agent, keyboard-interactive second factor and per-hop jump logins through the C ABI, against
//! the throwaway PAM server and the jump topology in docs/TESTING.md:
//!
//! - `BASTION_KBD_TEST=1`: the PAM server (`docs/testservers/ssh-pam`) on `BASTION_KBD_PORT`
//!   (default 2231) of 127.0.0.1. Users `kbd` (password over keyboard-interactive) and `mfa`
//!   (password plus TOTP).
//! - `BASTION_AGENT_TEST=1` as well: the user's agent (`SSH_AUTH_SOCK`, or on Windows the OpenSSH
//!   agent pipe) holds the key authorised for `agent`.
//! - `BASTION_SSH_TEST=1`: bastion-jump on 127.0.0.1:`BASTION_JUMP_PORT` (default 2223) and
//!   bastion-target behind it.
use std::ffi::{c_char, CString};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bastion_cabi::*;
use hmac::{Hmac, Mac};

/// RFC 6238 test secret, as in the server's users.oath.
const TOTP_SECRET: &[u8] = b"12345678901234567890";

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned();
    bastion_string_free(p);
    Some(s)
}

/// The code an authenticator shows now (SHA-1, 6 digits, 30 s).
fn totp() -> String {
    let unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut m = Hmac::<sha1::Sha1>::new_from_slice(TOTP_SECRET).unwrap();
    m.update(&(unix / 30).to_be_bytes());
    let h = m.finalize().into_bytes();
    let o = (h[19] & 0x0f) as usize;
    format!("{:06}", u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]) % 1_000_000)
}

struct Env {
    dir: std::path::PathBuf,
    lib: *mut BastionLibrary,
    mgr: *mut BastionSessionManager,
}

impl Env {
    unsafe fn new(tag: &str) -> Env {
        let dir = std::env::temp_dir().join(format!("bastion-cabi-auth-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let mut err = null_mut();
        let lib = bastion_library_open(c(&dir.join("lib.json").to_string_lossy()).as_ptr(), &mut err);
        assert!(!lib.is_null(), "{:?}", take(err));
        let mgr = bastion_session_manager_new(c(&dir.to_string_lossy()).as_ptr(), &mut err);
        assert!(!mgr.is_null(), "{:?}", take(err));
        Env { dir, lib, mgr }
    }

    unsafe fn add(&self, name: &str, port: i32, user: &str) -> CString {
        let mut err = null_mut();
        let id = take(bastion_library_add_connection(self.lib, null(), c(name).as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), port, c(user).as_ptr(), &mut err));
        c(&id.unwrap_or_else(|| panic!("{:?}", take(err))))
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        unsafe {
            bastion_session_manager_free(self.mgr);
            bastion_library_free(self.lib);
        }
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

struct Attempt<'a> {
    user: Option<&'a str>,
    kind: i32,
    secret: Option<&'a str>,
    code: Option<&'a str>,
    trust: Option<&'a str>,
    jump_trust: Option<&'a str>,
    jump_logins: Option<&'a str>,
}

impl Default for Attempt<'_> {
    fn default() -> Self {
        Attempt { user: None, kind: LOGIN_PASSWORD, secret: None, code: None, trust: None, jump_trust: None, jump_logins: None }
    }
}

/// Returns `(terminal, outcome, fingerprint, hop, err)`.
unsafe fn connect(env: &Env, id: &CString, a: Attempt) -> (*mut BastionTerminal, i32, Option<String>, Option<String>, Option<String>) {
    let owned = |s: Option<&str>| s.map(c);
    let ptr = |s: &Option<CString>| s.as_ref().map_or(null(), |s| s.as_ptr());
    let (user, secret, code, trust, jt, jl) = (owned(a.user), owned(a.secret), owned(a.code), owned(a.trust), owned(a.jump_trust), owned(a.jump_logins));
    let (mut outcome, mut fp, mut hop, mut err) = (-42, null_mut(), null_mut(), null_mut());
    let t = bastion_session_connect_ssh_mfa(
        env.mgr, env.lib, id.as_ptr(), ptr(&user), a.kind, ptr(&secret), null(), ptr(&code), ptr(&trust), ptr(&jt), ptr(&jl), 80, 24,
        &mut outcome, &mut fp, &mut hop, &mut err,
    );
    (t, outcome, take(fp), take(hop), take(err))
}

/// Trust the target's key on first contact, the way the app does after the user compared it.
unsafe fn connect_trusting(env: &Env, id: &CString, user: &str, kind: i32, secret: Option<&str>) -> (*mut BastionTerminal, i32, Option<String>) {
    let (t, outcome, fp, _, err) = connect(env, id, Attempt { user: Some(user), kind, secret, ..Default::default() });
    if outcome != CONNECT_HOST_KEY_UNKNOWN {
        return (t, outcome, err);
    }
    let (t, outcome, _, _, err) = connect(env, id, Attempt { user: Some(user), kind, secret, trust: fp.as_deref(), ..Default::default() });
    (t, outcome, err)
}

/// Run `echo` in the shell and wait for its output.
unsafe fn assert_shell(t: *mut BastionTerminal, marker: &str) {
    let cmd = format!("echo {marker}-$((40+2))\n");
    let mut err = null_mut();
    assert_eq!(bastion_terminal_write(t, cmd.as_ptr(), cmd.len(), &mut err), 0, "{:?}", take(err));
    let want = format!("{marker}-42");
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let s = bastion_terminal_screen(t, &mut err);
        if !s.is_null() {
            let r = &*s;
            let seen = String::from_utf8_lossy(std::slice::from_raw_parts(r.text, r.text_len as usize)).contains(&want);
            bastion_screen_free(s);
            if seen {
                bastion_terminal_free(t);
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bastion_terminal_free(t);
    panic!("the shell did not print {want}");
}

fn kbd_port() -> Option<i32> {
    std::env::var("BASTION_KBD_TEST").ok()?;
    Some(std::env::var("BASTION_KBD_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(2231))
}

#[ignore = "live: needs BASTION_KBD_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn keyboard_interactive_password_and_second_factor() {
    assert!(std::env::var_os("BASTION_KBD_TEST").is_some(), "live test run without BASTION_KBD_TEST: start the fixture (docs/TESTING.md)");
    let Some(port) = kbd_port() else { return eprintln!("SKIPPED keyboard_interactive_password_and_second_factor: set BASTION_KBD_TEST=1") };
    unsafe {
        let env = Env::new("kbd");
        // A password-only PAM account: the password is answered over keyboard-interactive.
        let kbd = env.add("kbd", port, "kbd");
        let (t, outcome, err) = connect_trusting(&env, &kbd, "kbd", LOGIN_PASSWORD, Some("kbd-pass-321"));
        assert_eq!(outcome, CONNECT_OK, "{err:?}");
        assert_shell(t, "cabi-kbd");

        // Password plus TOTP: the first attempt asks for the code, the retry with it gets in.
        let mfa = env.add("mfa", port, "mfa");
        let (t, outcome, err) = connect_trusting(&env, &mfa, "mfa", LOGIN_PASSWORD, Some("mfa-pass-789"));
        assert!(t.is_null());
        assert_eq!(outcome, CONNECT_TWO_FACTOR_REQUIRED, "{err:?}");
        assert!(!err.unwrap_or_default().contains("mfa-pass-789"));

        // A wrong code is refused, never accepted.
        let (t, outcome, _, _, _) = connect(&env, &mfa, Attempt { user: Some("mfa"), kind: LOGIN_PASSWORD_AND_CODE, secret: Some("mfa-pass-789"), code: Some("000000"), ..Default::default() });
        assert!(t.is_null());
        assert!(outcome == CONNECT_TWO_FACTOR_REQUIRED || outcome == CONNECT_AUTH_FAILED, "wrong code gave {outcome}");

        let code = totp();
        let (t, outcome, _, _, err) = connect(&env, &mfa, Attempt { user: Some("mfa"), kind: LOGIN_PASSWORD_AND_CODE, secret: Some("mfa-pass-789"), code: Some(&code), ..Default::default() });
        assert_eq!(outcome, CONNECT_OK, "{err:?}");
        assert_shell(t, "cabi-mfa");

        let audit = std::fs::read_to_string(env.dir.join("audit.jsonl")).unwrap_or_default();
        for secret in ["kbd-pass-321", "mfa-pass-789", code.as_str()] {
            assert!(!audit.contains(secret), "the audit log holds a secret");
        }
    }
}

#[ignore = "live: needs BASTION_AGENT_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn agent_login() {
    assert!(std::env::var_os("BASTION_AGENT_TEST").is_some(), "live test run without BASTION_AGENT_TEST: start the fixture (docs/TESTING.md)");
    let Some(port) = kbd_port() else { return eprintln!("SKIPPED agent_login: set BASTION_KBD_TEST=1") };
    if std::env::var("BASTION_AGENT_TEST").is_err() {
        return eprintln!("SKIPPED agent_login: set BASTION_AGENT_TEST=1 with the agent holding the test key");
    }
    unsafe {
        let env = Env::new("agent");
        let agent = env.add("agent", port, "agent");
        let (t, outcome, err) = connect_trusting(&env, &agent, "agent", LOGIN_AGENT, None);
        assert_eq!(outcome, CONNECT_OK, "{err:?}");
        assert_shell(t, "cabi-agent");
        // The agent's key is not authorised for kbd: refused, not a crash or a prompt.
        let kbd = env.add("kbd", port, "kbd");
        let (t, outcome, err) = connect_trusting(&env, &kbd, "kbd", LOGIN_AGENT, None);
        assert!(t.is_null());
        assert_ne!(outcome, CONNECT_OK, "{err:?}");
    }
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn each_jump_host_logs_in_with_its_own_login() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_SSH_TEST").is_err() {
        return eprintln!("SKIPPED each_jump_host_logs_in_with_its_own_login: set BASTION_SSH_TEST=1");
    }
    let port: u16 = std::env::var("BASTION_JUMP_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(2223);
    let hop_key = format!("127.0.0.1:{port}");
    unsafe {
        let env = Env::new("hops");
        let ssh = env.dir.join("ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("config"), format!("Host gw\n  HostName 127.0.0.1\n  Port {port}\n  User tester\n\nHost inner\n  HostName target\n  Port 2222\n  User tester\n  ProxyJump gw\n")).unwrap();
        let root = c(&ssh.to_string_lossy());
        let mut err = null_mut();
        let scan: serde_json::Value = serde_json::from_str(&take(bastion_ssh_scan_json(root.as_ptr(), null(), &mut err)).unwrap()).unwrap();
        let ids: Vec<&str> = scan["hosts"].as_array().unwrap().iter().map(|h| h["identity"].as_str().unwrap()).collect();
        assert_eq!(bastion_library_import_ssh_hosts(env.lib, root.as_ptr(), null(), c(&serde_json::to_string(&ids).unwrap()).as_ptr(), &mut err), 2, "{:?}", take(err));
        let tree: serde_json::Value = serde_json::from_str(&take(bastion_library_tree_json(env.lib, &mut err)).unwrap()).unwrap();
        let inner = find_id(&tree, "inner").expect("inner id");
        let inner = c(&inner);

        let hops = take(bastion_session_jump_hosts_json(env.mgr, env.lib, inner.as_ptr(), &mut err)).unwrap();
        assert!(hops.contains(&hop_key), "{hops}");

        // The hop's password differs from the target's: only a per-hop login gets through.
        let jump_logins = serde_json::to_string(&std::collections::HashMap::from([(&hop_key, serde_json::json!({ "kind": LOGIN_PASSWORD, "secret": "test-pass-123" }))])).unwrap();
        let target = Some("target-pass-456");
        let (t, outcome, fp, hop, err) = connect(&env, &inner, Attempt { secret: target, jump_logins: Some(&jump_logins), ..Default::default() });
        assert!(t.is_null());
        assert_eq!((outcome, hop.as_deref()), (CONNECT_HOST_KEY_UNKNOWN, Some(hop_key.as_str())), "{err:?}");
        let jt = serde_json::to_string(&std::collections::HashMap::from([(&hop_key, fp.unwrap())])).unwrap();
        let (_, outcome, fp, hop, err) = connect(&env, &inner, Attempt { secret: target, jump_trust: Some(&jt), jump_logins: Some(&jump_logins), ..Default::default() });
        assert_eq!((outcome, hop), (CONNECT_HOST_KEY_UNKNOWN, None), "{err:?}");
        let (t, outcome, _, _, err) =
            connect(&env, &inner, Attempt { secret: target, trust: fp.as_deref(), jump_trust: Some(&jt), jump_logins: Some(&jump_logins), ..Default::default() });
        assert_eq!(outcome, CONNECT_OK, "{err:?}");
        assert_shell(t, "cabi-hop");

        // Without the hop's own login the target's password is tried on the jump host and refused.
        let (t, outcome, _, _, _) = connect(&env, &inner, Attempt { secret: target, ..Default::default() });
        assert!(t.is_null());
        assert_eq!(outcome, CONNECT_AUTH_FAILED);
    }
}

/// The id of the connection named `name` anywhere in the tree JSON.
fn find_id(v: &serde_json::Value, name: &str) -> Option<String> {
    match v {
        serde_json::Value::Object(o) => {
            if o.get("name").and_then(|n| n.as_str()) == Some(name) && o.contains_key("protocol") {
                return o.get("id").and_then(|i| i.as_str()).map(str::to_owned);
            }
            o.values().find_map(|x| find_id(x, name))
        }
        serde_json::Value::Array(a) => a.iter().find_map(|x| find_id(x, name)),
        _ => None,
    }
}

/// `BASTION_HOSTCERT_TEST=<port>`: a server whose host key is signed by the CA in
/// `BASTION_HOSTCERT_CA` (a `ca.pub`), user `tester` with `BASTION_HOSTCERT_PASSWORD`
/// (docs/TESTING.md, "SSH host certificates"). With only the CA in known_hosts the first connect
/// goes through with no fingerprint prompt; without it the host key is unknown.
#[ignore = "live: needs BASTION_HOSTCERT_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn a_host_certificate_from_a_trusted_ca_needs_no_prompt() {
    assert!(std::env::var_os("BASTION_HOSTCERT_TEST").is_some(), "live test run without BASTION_HOSTCERT_TEST: start the fixture (docs/TESTING.md)");
    let Ok(port) = std::env::var("BASTION_HOSTCERT_TEST") else {
        return eprintln!("SKIPPED a_host_certificate_from_a_trusted_ca_needs_no_prompt: set BASTION_HOSTCERT_TEST=<port>");
    };
    let port: i32 = port.parse().unwrap();
    let ca = std::fs::read_to_string(std::env::var("BASTION_HOSTCERT_CA").expect("BASTION_HOSTCERT_CA")).unwrap();
    let password = std::env::var("BASTION_HOSTCERT_PASSWORD").expect("BASTION_HOSTCERT_PASSWORD");
    unsafe {
        let env = Env::new("hostcert");
        let id = env.add("certified", port, "tester");
        let login = || Attempt { user: Some("tester"), secret: Some(&password), ..Default::default() };

        let (t, outcome, fp, _, _) = connect(&env, &id, login());
        assert!(t.is_null());
        assert_eq!(outcome, CONNECT_HOST_KEY_UNKNOWN, "no CA yet: the key must be unknown");
        assert!(fp.is_some());

        std::fs::write(env.dir.join("known_hosts"), format!("@cert-authority [127.0.0.1]:{port} {}\n", ca.trim())).unwrap();
        let (t, outcome, fp, _, err) = connect(&env, &id, login());
        assert_eq!(outcome, CONNECT_OK, "{err:?}");
        assert!(fp.is_none(), "a certified host must not prompt");
        assert_shell(t, "cabi-cert");
    }
}
