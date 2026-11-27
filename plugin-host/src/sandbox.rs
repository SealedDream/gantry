//! The helper's OS sandbox (PLUG-05; spec `docs/specs/plugins.md`, "OS sandbox"; THREAT_MODEL
//! T18).
//!
//! macOS: the helper applies a sandbox profile to itself with `sandbox_init` straight after it
//! has taken its two pipe ends and before it builds the engine or reads any byte from the core.
//! The profile denies everything, then allows reading the helper's own folder and kernel
//! settings (`sysctl`). There is no network rule, no write rule and no process rule, so a
//! connect, a file write, a file read anywhere else, and starting a program all fail with
//! "Operation not permitted". Reading and writing the two pipe ends it already holds still works:
//! the sandbox checks opening, not descriptors that are already open.
//!
//! The helper then confirms with `sandbox_check` that the kernel holds it in a sandbox, and only
//! then reports `Sandbox::Applied`. If either step fails it exits before the core sends anything.
//!
//! Windows: the core starts the helper inside an AppContainer with no capabilities and a job
//! object (PLUG-05, Windows part). The helper cannot put itself in one, so it only checks: it
//! reads `TokenIsAppContainer` from its own token and reports `Sandbox::Applied`. A helper whose
//! token is not an AppContainer exits before the core sends anything.

use bastion_plugin_host::proto::Sandbox;

/// The macOS profile for a helper in `helper_dir` (an absolute, canonical path).
#[cfg(target_os = "macos")]
pub fn mac_profile(helper_dir: &str) -> String {
    let escaped = helper_dir.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"(version 1)
(deny default)
(allow file-read* (subpath "{escaped}"))
(allow sysctl-read)
"#
    )
}

#[cfg(target_os = "macos")]
mod ffi {
    use std::ffi::{c_char, c_int};
    extern "C" {
        // <sandbox.h>. Deprecated by Apple since 10.8 but still the call Chromium relies on.
        // With flags 0 the string is profile source.
        pub fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
        pub fn sandbox_free_error(errorbuf: *mut c_char);
        // <sandbox/private.h>, exported by libsystem_sandbox. With no operation it answers
        // "is this process sandboxed": 1 yes, 0 no.
        pub fn sandbox_check(pid: libc::pid_t, operation: *const c_char, filter_type: c_int, ...) -> c_int;
    }
}

/// True when the kernel holds process `pid` in a sandbox.
#[cfg(target_os = "macos")]
pub fn is_sandboxed(pid: u32) -> bool {
    // SAFETY: a null operation with filter type 0 (SANDBOX_FILTER_NONE) takes no further arguments.
    unsafe { ffi::sandbox_check(pid as libc::pid_t, std::ptr::null(), 0) == 1 }
}

/// Applies the sandbox to this process. Called once, before any plugin byte is read.
#[cfg(target_os = "macos")]
pub fn enter() -> Result<Sandbox, String> {
    use std::ffi::{c_char, CStr, CString};
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let exe = exe.canonicalize().map_err(|e| format!("canonicalize: {e}"))?;
    let dir = exe.parent().ok_or("helper has no parent folder")?;
    let profile = CString::new(mac_profile(&dir.to_string_lossy())).map_err(|e| e.to_string())?;
    let mut error: *mut c_char = std::ptr::null_mut();
    // SAFETY: `profile` is a valid NUL-terminated string and `error` a valid out-pointer.
    let rc = unsafe { ffi::sandbox_init(profile.as_ptr(), 0, &mut error) };
    if rc != 0 {
        let text = if error.is_null() {
            "unknown error".to_string()
        } else {
            // SAFETY: on failure the call stores a NUL-terminated string that we free here.
            let text = unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned();
            unsafe { ffi::sandbox_free_error(error) };
            text
        };
        return Err(format!("sandbox_init failed: {text}"));
    }
    if !is_sandboxed(std::process::id()) {
        return Err("sandbox_init returned success but sandbox_check reports no sandbox".into());
    }
    Ok(Sandbox::Applied)
}

/// Windows: confirms the core started this process inside an AppContainer.
#[cfg(windows)]
pub fn enter() -> Result<Sandbox, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenIsAppContainer, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: valid out-pointer; the pseudo-handle for the current process needs no close.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err("OpenProcessToken failed".into());
    }
    let mut is_app_container: u32 = 0;
    let mut len: u32 = 0;
    // SAFETY: the buffer is a u32, the size the TokenIsAppContainer class returns.
    let ok = unsafe { GetTokenInformation(token, TokenIsAppContainer, (&mut is_app_container as *mut u32).cast(), 4, &mut len) };
    // SAFETY: a token handle we own.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err("GetTokenInformation failed".into());
    }
    if is_app_container == 0 {
        return Err("not started inside an AppContainer".into());
    }
    Ok(Sandbox::Applied)
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn enter() -> Result<Sandbox, String> {
    Ok(Sandbox::None)
}

/// Each case runs in a fresh copy of this test binary (`child`), because a sandbox cannot be
/// removed once applied and would otherwise cover the whole test runner. The parent prepares
/// the target (a listening socket, a file outside the helper's folder), starts the child with the
/// case in its environment, and reads the child's verdict from its exit code.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Command;

    const CASE: &str = "BASTION_SANDBOX_CASE";
    const ARG: &str = "BASTION_SANDBOX_ARG";
    /// Child exit codes.
    const DENIED: i32 = 10;
    const ALLOWED: i32 = 11;
    const NO_SANDBOX: i32 = 12;

    fn denied(r: std::io::Result<()>) -> i32 {
        match r {
            Err(e) if e.raw_os_error() == Some(libc::EPERM) || e.raw_os_error() == Some(libc::EACCES) => DENIED,
            Err(_) => 13, // failed, but not because of the sandbox: the test is not proving anything
            Ok(()) => ALLOWED,
        }
    }

    /// The child side. Ignored so a normal `cargo test` run does not apply a sandbox to itself.
    #[test]
    #[ignore]
    fn child() {
        let Ok(case) = std::env::var(CASE) else { return };
        let arg = std::env::var(ARG).unwrap_or_default();
        // Resolved before the sandbox: resolving a path walks parent folders, which it denies.
        let own = std::env::current_exe().unwrap().canonicalize().unwrap();
        if enter().is_err() || !is_sandboxed(std::process::id()) {
            std::process::exit(NO_SANDBOX);
        }
        let code = match case.as_str() {
            "connect" => denied(std::net::TcpStream::connect(arg.as_str()).map(|_| ())),
            "read-outside" => denied(std::fs::read(&arg).map(|_| ())),
            "write-outside" => denied(std::fs::write(&arg, b"x")),
            "write-own" => denied(std::fs::write(own.with_file_name("plug05-sandbox-probe"), b"x")),
            "exec" => denied(Command::new("/bin/echo").output().map(|_| ())),
            "read-own" => denied(std::fs::read(&own).map(|_| ())),
            // SAFETY: the child calls only `_exit`, which is async-signal-safe.
            "fork" => denied(match unsafe { libc::fork() } {
                0 => unsafe { libc::_exit(0) },
                -1 => Err(std::io::Error::last_os_error()),
                pid => {
                    // SAFETY: reaping the child just started.
                    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                    Ok(())
                }
            }),
            "rlimits" => rlimits_hold(),
            _ => 14,
        };
        std::process::exit(code);
    }

    /// After `lower_rlimits`: no core dumps, few descriptors, and neither can be raised again.
    fn rlimits_hold() -> i32 {
        if crate::limits::lower_rlimits().is_err() {
            return 15;
        }
        let read = |resource| {
            let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            // SAFETY: a valid out-pointer.
            unsafe { libc::getrlimit(resource, &mut limit) };
            limit
        };
        let core = read(libc::RLIMIT_CORE);
        let files = read(libc::RLIMIT_NOFILE);
        if core.rlim_max != 0 || files.rlim_max != crate::limits::MAX_FILES as libc::rlim_t {
            return 16;
        }
        let raise = libc::rlimit { rlim_cur: 1 << 20, rlim_max: 1 << 20 };
        // SAFETY: a valid rlimit struct.
        let raised = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raise) } == 0;
        if raised { ALLOWED } else { DENIED }
    }

    fn run(case: &str, arg: &str) -> i32 {
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "sandbox::tests::child", "--ignored", "--nocapture", "--test-threads=1"])
            .env(CASE, case)
            .env(ARG, arg)
            .output()
            .unwrap();
        out.status.code().unwrap_or(-1)
    }

    fn outside_file() -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("plug05-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("secret.txt");
        std::fs::File::create(&file).unwrap().write_all(b"secret").unwrap();
        (dir, file)
    }

    fn rand_suffix() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    }

    #[test]
    fn profile_has_no_network_write_or_exec_rule() {
        let p = mac_profile("/Applications/Bastion.app/Contents/Helpers");
        assert!(p.contains("(deny default)"));
        assert!(p.contains(r#"(allow file-read* (subpath "/Applications/Bastion.app/Contents/Helpers"))"#));
        for word in ["network", "file-write", "process", "mach", "ipc", "iokit"] {
            assert!(!p.contains(word), "profile allows {word}");
        }
    }

    #[test]
    fn profile_escapes_quotes_in_the_folder() {
        let p = mac_profile(r#"/tmp/a"b\c"#);
        assert!(p.contains(r#"(subpath "/tmp/a\"b\\c")"#));
    }

    #[test]
    fn the_test_runner_itself_is_not_sandboxed() {
        assert!(!is_sandboxed(std::process::id()));
    }

    #[test]
    fn connect_is_denied_inside_the_sandbox() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        // Control: the same connect works from outside.
        assert!(std::net::TcpStream::connect(&addr).is_ok());
        assert_eq!(run("connect", &addr), DENIED);
    }

    #[test]
    fn reading_a_file_outside_its_folder_is_denied() {
        let (dir, file) = outside_file();
        assert_eq!(run("read-outside", file.to_str().unwrap()), DENIED);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn writing_a_file_outside_its_folder_is_denied() {
        let (dir, _) = outside_file();
        let target = dir.join("written.txt");
        assert_eq!(run("write-outside", target.to_str().unwrap()), DENIED);
        assert!(!target.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn writing_into_its_own_folder_is_denied() {
        assert_eq!(run("write-own", ""), DENIED);
        let probe = std::env::current_exe().unwrap().canonicalize().unwrap().with_file_name("plug05-sandbox-probe");
        assert!(!probe.exists());
    }

    #[test]
    fn starting_a_program_is_denied() {
        assert_eq!(run("exec", ""), DENIED);
    }

    #[test]
    fn forking_is_denied() {
        assert_eq!(run("fork", ""), DENIED);
    }

    #[test]
    fn the_lowered_rlimits_cannot_be_raised_again() {
        assert_eq!(run("rlimits", ""), DENIED);
    }

    #[test]
    fn reading_its_own_folder_still_works() {
        assert_eq!(run("read-own", ""), ALLOWED);
    }
}
