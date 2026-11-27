//! 1Password as a read-only credential provider, through the official `op` CLI.
//!
//! Every `fetch` runs `op read --no-newline -- <op://vault/item/field>` directly (no shell; the
//! reference is one argument) and returns its stdout; nothing is cached. Sign-in is `op`'s own
//! business (desktop-app integration or `op signin`); a service-account token, if given, lives
//! only in memory and is passed to the child as `OP_SERVICE_ACCOUNT_TOKEN`. `store` and
//! `delete` are refused.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::provider::{CredentialProvider, ProviderStatus};
use crate::vault::Secret;

/// `op` may wait for the desktop app's approval prompt, so allow time for a human.
const OP_TIMEOUT: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(20);
/// Refuse absurd output instead of buffering it.
const MAX_OUTPUT: u64 = 64 * 1024;
/// Where `op` is usually installed when it is not on the GUI app's PATH.
const KNOWN_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"];

pub struct OnePasswordProvider {
    op: Option<PathBuf>,
    account: Option<String>,
    service_token: Mutex<Option<Secret>>,
    timeout: Duration,
}

impl OnePasswordProvider {
    /// `op_path`: an explicit `op` binary, else it is looked up on PATH and the usual dirs.
    /// `account`: optional `--account` (shorthand, sign-in address or id).
    pub fn new(op_path: Option<PathBuf>, account: Option<String>) -> Result<Self> {
        let account = account.map(|a| a.trim().to_string()).filter(|a| !a.is_empty());
        if let Some(a) = &account {
            check_arg(a, "account")?;
        }
        let op = match op_path {
            Some(p) if p.is_file() => Some(p),
            Some(p) => return Err(CoreError::NotFound(format!("1Password CLI at {}", p.display()))),
            None => find_op(),
        };
        Ok(OnePasswordProvider { op, account, service_token: Mutex::new(None), timeout: OP_TIMEOUT })
    }

    /// Use a service-account token instead of the desktop-app sign-in. Memory only.
    pub fn set_service_token(&self, token: Option<Secret>) {
        *self.service_token.lock().unwrap_or_else(|e| e.into_inner()) = token;
    }

    pub fn lock(&self) {
        self.set_service_token(None);
    }

    fn command(&self, op: &Path, reference: &str) -> Command {
        let mut cmd = Command::new(op);
        cmd.arg("read").arg("--no-newline");
        if let Some(a) = &self.account {
            cmd.arg("--account").arg(a);
        }
        // `--` so a reference can never be read as a flag (it is also validated).
        cmd.arg("--").arg(reference);
        if let Some(t) = &*self.service_token.lock().unwrap_or_else(|e| e.into_inner()) {
            cmd.env("OP_SERVICE_ACCOUNT_TOKEN", t.expose());
        }
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd
    }

    fn run(&self, op: &Path, reference: &str) -> Result<(std::process::ExitStatus, Zeroizing<Vec<u8>>, String)> {
        let mut child = {
            let _spawning = crate::plugin::host::spawn::spawn_guard();
            self.command(op, reference).spawn().map_err(CoreError::Io)?
        };
        let out = read_capped(child.stdout.take());
        let err = read_capped(child.stderr.take());
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            if let Some(s) = child.try_wait().map_err(CoreError::Io)? {
                break s;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CoreError::Timeout);
            }
            std::thread::sleep(POLL);
        };
        let stdout = Zeroizing::new(out.join().unwrap_or_default());
        let stderr = String::from_utf8_lossy(&err.join().unwrap_or_default()).into_owned();
        Ok((status, stdout, stderr))
    }
}

fn find_op() -> Option<PathBuf> {
    let name = if cfg!(windows) { "op.exe" } else { "op" };
    let path_dirs = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect::<Vec<_>>()).unwrap_or_default();
    path_dirs.into_iter().chain(KNOWN_DIRS.iter().map(PathBuf::from)).map(|d| d.join(name)).find(|p| p.is_file())
}

fn check_arg(s: &str, what: &str) -> Result<()> {
    if s.starts_with('-') || s.chars().any(char::is_control) {
        return Err(CoreError::Invalid(format!("1Password {what} must not start with '-' or hold control characters")));
    }
    Ok(())
}

/// Accepts `op://vault/item/field`, `op://vault/item/section/field`, or the same without the
/// scheme. Returns the full `op://` reference.
pub fn secret_reference(item: &str) -> Result<String> {
    let item = item.trim();
    check_arg(item, "item")?;
    let body = item.strip_prefix("op://").unwrap_or(item);
    let parts: Vec<&str> = body.split('/').collect();
    if !(3..=4).contains(&parts.len()) || parts.iter().any(|p| p.trim().is_empty()) {
        return Err(CoreError::Invalid("1Password item must be op://vault/item/field".into()));
    }
    Ok(format!("op://{body}"))
}

/// Reads up to `MAX_OUTPUT + 1` bytes, then drains the rest so the child never blocks.
fn read_capped<R: Read + Send + 'static>(r: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = r {
            let _ = (&mut r).take(MAX_OUTPUT + 1).read_to_end(&mut buf);
            let _ = std::io::copy(&mut r, &mut std::io::sink());
        }
        buf
    })
}

fn map_failure(stderr: &str, item: &str) -> CoreError {
    let s = stderr.to_lowercase();
    if s.contains("not currently signed in") || s.contains("sign in") || s.contains("unauthorized") || s.contains("authorization") {
        CoreError::AuthFailed
    } else if ["isn't an item", "isn't a vault", "not found", "no item", "does not have a field"].iter().any(|m| s.contains(m)) {
        CoreError::NotFound(item.into())
    } else {
        // op's stderr never holds the secret; keep its first line for the user.
        CoreError::Invalid(format!("1Password CLI: {}", stderr.lines().next().unwrap_or("failed").trim()))
    }
}

impl CredentialProvider for OnePasswordProvider {
    fn id(&self) -> &'static str {
        "onepassword"
    }

    fn status(&self) -> ProviderStatus {
        match self.op {
            Some(_) => ProviderStatus::Available,
            None => ProviderStatus::Unavailable("1Password CLI (op) is not installed".into()),
        }
    }

    fn fetch(&self, item: &str) -> Result<Secret> {
        let reference = secret_reference(item)?;
        let op = self.op.as_ref().ok_or_else(|| CoreError::NotFound("1Password CLI (op); install it or set its path".into()))?;
        let (status, stdout, stderr) = self.run(op, &reference)?;
        if !status.success() {
            return Err(map_failure(&stderr, item));
        }
        if stdout.len() as u64 > MAX_OUTPUT {
            return Err(CoreError::Invalid("1Password field is too large".into()));
        }
        let text = std::str::from_utf8(&stdout).map_err(|_| CoreError::Corrupt("1Password field is not text".into()))?;
        Ok(Secret::new(text))
    }

    fn store(&self, _: &str, _: &Secret) -> Result<()> {
        Err(read_only())
    }

    fn delete(&self, _: &str) -> Result<()> {
        Err(read_only())
    }
}

fn read_only() -> CoreError {
    CoreError::PolicyDenied("1Password is read-only in Gantry".into())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A fake `op` shell script standing in for the real CLI.
    fn fake_op(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn references_are_validated() {
        assert_eq!(secret_reference("Prod/db/password").unwrap(), "op://Prod/db/password");
        assert_eq!(secret_reference("op://Prod/db/sec/password").unwrap(), "op://Prod/db/sec/password");
        for bad in ["-v", "op://a/b", "a//c", "op://a/b/c/d/e", "a/b/c\n--x"] {
            assert!(secret_reference(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn runs_op_read_without_a_shell_and_passes_the_token() {
        let d = tempfile::tempdir().unwrap();
        let op = fake_op(d.path(), "op", r#"for a in "$@"; do printf '%s|' "$a"; done; printf 'T=%s' "$OP_SERVICE_ACCOUNT_TOKEN""#);
        let p = OnePasswordProvider::new(Some(op), Some("my.1password.com".into())).unwrap();
        assert_eq!(p.status(), ProviderStatus::Available);
        p.set_service_token(Some(Secret::new("ops_tok")));
        let item = "Prod/$(touch bastion-op-pwned);id/pw";
        let got = p.fetch(item).unwrap();
        assert_eq!(got.expose(), format!("read|--no-newline|--account|my.1password.com|--|op://{item}|T=ops_tok"));
        assert!(!Path::new("bastion-op-pwned").exists(), "the reference reached a shell");
        p.lock();
        assert_eq!(p.fetch("a/b/c").unwrap().expose(), "read|--no-newline|--account|my.1password.com|--|op://a/b/c|T=");
    }

    #[test]
    fn failures_map_to_errors_and_writes_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = OnePasswordProvider::new(Some(fake_op(d.path(), "op1", r#"echo '[ERROR] "x" isn'"'"'t an item in the "Prod" vault' >&2; exit 1"#)), None).unwrap();
        assert!(matches!(p.fetch("Prod/x/pw"), Err(CoreError::NotFound(_))));
        let p = OnePasswordProvider::new(Some(fake_op(d.path(), "op2", "echo '[ERROR] You are not currently signed in.' >&2; exit 1")), None).unwrap();
        assert!(matches!(p.fetch("Prod/x/pw"), Err(CoreError::AuthFailed)));
        assert!(matches!(p.store("a/b/c", &Secret::new("x")), Err(CoreError::PolicyDenied(_))));
        assert!(matches!(p.delete("a/b/c"), Err(CoreError::PolicyDenied(_))));
        assert!(OnePasswordProvider::new(Some(d.path().join("missing")), None).is_err());
        assert!(OnePasswordProvider::new(None, Some("--evil".into())).is_err());
    }

    #[test]
    fn a_hung_op_times_out() {
        let d = tempfile::tempdir().unwrap();
        let mut p = OnePasswordProvider::new(Some(fake_op(d.path(), "op", "exec sleep 30")), None).unwrap();
        p.timeout = Duration::from_millis(200);
        let t = Instant::now();
        assert!(matches!(p.fetch("a/b/c"), Err(CoreError::Timeout)));
        assert!(t.elapsed() < Duration::from_secs(5));
    }
}
