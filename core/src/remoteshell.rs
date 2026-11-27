//! What an SSH terminal runs on the host, and how: tmux attach and Mosh.
//!
//! - `ssh.tmux` = `attach`: the terminal runs `tmux new-session -A -s <name>` instead of a plain
//!   login shell, so a reconnect (auto-reconnect redials, `core-ffi` supervisor) lands back in the
//!   same tmux session with its windows and running programs. `ssh.tmux_session` names it
//!   (default [`DEFAULT_TMUX_SESSION`]). Split panes on the same connection stay plain shells.
//! - `ssh.transport` = `mosh`: the frontend starts the local `mosh` client in a local PTY with the
//!   arguments from [`mosh_launch`] (it roams and survives sleep on its own). Mosh logs in with the
//!   system `ssh`, so key or agent auth works and a password is typed in the terminal; Bastion's
//!   vault, jump hosts and gateways are not used for it, which [`mosh_launch`] refuses up front.
use std::path::Path;

use crate::error::{CoreError, Result};
use crate::localshell::LocalShellSpec;
use crate::model::{Connection, Protocol, Settings};
use crate::tasks::posix_quote;

pub const TMUX: &str = "ssh.tmux";
pub const TMUX_SESSION: &str = "ssh.tmux_session";
pub const TRANSPORT: &str = "ssh.transport";
pub const DEFAULT_TMUX_SESSION: &str = "bastion";
pub const TMUX_MODES: &[(&str, &str)] = &[("off", "Off"), ("attach", "Attach or create")];
pub const TRANSPORTS: &[(&str, &str)] = &[("ssh", "SSH"), ("mosh", "Mosh")];
const MAX_TMUX_SESSION: usize = 64;

/// Where the `mosh` client is usually installed (Homebrew, MacPorts, distro packages).
const MOSH_CANDIDATES: &[&str] = &["/opt/homebrew/bin/mosh", "/usr/local/bin/mosh", "/opt/local/bin/mosh", "/usr/bin/mosh"];

fn meta<'a>(c: &'a Connection, key: &str) -> Option<&'a str> {
    c.metadata.get(key).map(String::as_str).map(str::trim).filter(|v| !v.is_empty())
}

/// Validate a value for one of this module's metadata keys (property editor).
pub fn check(key: &str, value: &str) -> Result<()> {
    let v = value.trim();
    let ok = match key {
        TMUX => TMUX_MODES.iter().any(|(id, _)| *id == v),
        TRANSPORT => TRANSPORTS.iter().any(|(id, _)| *id == v),
        TMUX_SESSION => return check_session_name(v),
        _ => return Err(CoreError::Invalid(format!("`{key}` is not a remote shell setting"))),
    };
    if ok {
        Ok(())
    } else {
        Err(CoreError::Invalid(format!("`{v}` is not a value for {key}")))
    }
}

/// tmux session names: no `:` or `.` (tmux target separators), printable, at most 64 chars.
fn check_session_name(v: &str) -> Result<()> {
    if v.is_empty() || v.len() > MAX_TMUX_SESSION || v.chars().any(|c| c == ':' || c == '.' || c.is_control()) {
        return Err(CoreError::Invalid("tmux session: 1–64 characters, without `:` or `.`.".into()));
    }
    Ok(())
}

/// The tmux session a connection attaches to, or `None` when tmux attach is off.
pub fn tmux_session(c: &Connection) -> Option<String> {
    if c.protocol != Protocol::Ssh || meta(c, TMUX) != Some("attach") {
        return None;
    }
    let name = meta(c, TMUX_SESSION).filter(|n| check_session_name(n).is_ok()).unwrap_or(DEFAULT_TMUX_SESSION);
    Some(name.to_string())
}

/// The remote command for a connection's terminal: attach-or-create its tmux session, or `None`
/// for a plain login shell. If tmux is missing on the host the shell's error shows and the
/// channel ends, which the terminal reports like any closed session.
pub fn tmux_command(c: &Connection) -> Option<String> {
    tmux_session(c).map(|s| format!("tmux new-session -A -s {}", posix_quote(&s)))
}

/// True when the connection asks for Mosh.
pub fn uses_mosh(c: &Connection) -> bool {
    c.protocol == Protocol::Ssh && meta(c, TRANSPORT) == Some("mosh")
}

/// Find the `mosh` client: a known install path, else `mosh` on `PATH` (`exists` is injectable
/// for tests).
pub fn find_mosh(exists: impl Fn(&Path) -> bool, path_var: Option<&str>) -> Option<String> {
    if let Some(p) = MOSH_CANDIDATES.iter().find(|p| exists(Path::new(p))) {
        return Some((*p).to_string());
    }
    let sep = if cfg!(windows) { ';' } else { ':' };
    // Windows programs carry an extension: look for mosh.exe there (a bare "mosh" could not be started anyway).
    let name = if cfg!(windows) { "mosh.exe" } else { "mosh" };
    path_var?.split(sep).filter(|d| !d.is_empty()).map(|d| Path::new(d).join(name)).find(|p| exists(p)).map(|p| p.to_string_lossy().into_owned())
}

/// The local program and arguments that open `c` over Mosh. `effective` is the connection's
/// resolved settings (port, username). Refused when the connection needs what only Bastion's own
/// SSH client provides (gateway or jump host) or `mosh` is not installed.
/// What to do when `mosh` is not on PATH, for this platform.
#[cfg(target_os = "macos")]
const MOSH_MISSING: &str = "Mosh is not installed on this computer (`brew install mosh`).";
#[cfg(windows)]
const MOSH_MISSING: &str = "Mosh is not installed on this computer (put mosh.exe on PATH, or switch the transport to SSH).";
#[cfg(not(any(target_os = "macos", windows)))]
const MOSH_MISSING: &str = "Mosh is not installed on this computer (install the `mosh` package).";

pub fn mosh_launch(c: &Connection, effective: &Settings, mosh: Option<String>) -> Result<LocalShellSpec> {
    if !uses_mosh(c) {
        return Err(CoreError::Invalid("This connection does not use Mosh.".into()));
    }
    if effective.gateway_id.is_some() || c.metadata.contains_key("ProxyJump") {
        return Err(CoreError::Invalid("Mosh cannot go through a gateway or jump host; switch the transport to SSH.".into()));
    }
    let program = mosh.ok_or_else(|| CoreError::Invalid(MOSH_MISSING.into()))?;
    let host = c.host.trim();
    if host.is_empty() || host.starts_with('-') || host.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(CoreError::Invalid("Mosh: the host name is not valid.".into()));
    }
    let mut args = Vec::new();
    if let Some(port) = effective.port.filter(|p| *p != 22) {
        args.push(format!("--ssh=ssh -p {port}"));
    }
    let target = match effective.username.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(u) if u.starts_with('-') || u.contains(['@', ' ']) => return Err(CoreError::Invalid("Mosh: the user name is not valid.".into())),
        Some(u) => format!("{u}@{host}"),
        None => host.to_string(),
    };
    args.push(target);
    if let Some(s) = tmux_session(c) {
        args.extend(["--", "tmux", "new-session", "-A", "-s"].map(String::from));
        args.push(s);
    }
    Ok(LocalShellSpec { program, args, cwd: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh(pairs: &[(&str, &str)]) -> Connection {
        let mut c = Connection::new("web", Protocol::Ssh, "web.example");
        for (k, v) in pairs {
            c.metadata.insert(k.to_string(), v.to_string());
        }
        c
    }

    fn settings(port: Option<u16>, user: Option<&str>) -> Settings {
        Settings { port, username: user.map(String::from), ..Settings::default() }
    }

    #[test]
    fn tmux_off_by_default_and_attaches_when_on() {
        assert_eq!(tmux_command(&ssh(&[])), None);
        assert_eq!(tmux_command(&ssh(&[(TMUX, "attach")])).as_deref(), Some("tmux new-session -A -s bastion"));
        assert_eq!(tmux_command(&ssh(&[(TMUX, "attach"), (TMUX_SESSION, "ops main")])).as_deref(), Some("tmux new-session -A -s 'ops main'"));
    }

    #[test]
    fn hostile_session_names_fall_back_or_are_quoted() {
        assert_eq!(tmux_command(&ssh(&[(TMUX, "attach"), (TMUX_SESSION, "a:b")])).as_deref(), Some("tmux new-session -A -s bastion"));
        assert_eq!(tmux_command(&ssh(&[(TMUX, "attach"), (TMUX_SESSION, "x';rm -rf ~;'")])).as_deref(), Some(r"tmux new-session -A -s 'x'\'';rm -rf ~;'\'''"));
    }

    #[test]
    fn tmux_only_for_ssh() {
        let mut c = ssh(&[(TMUX, "attach")]);
        c.protocol = Protocol::Sftp;
        assert_eq!(tmux_command(&c), None);
    }

    #[test]
    fn check_validates_each_key() {
        assert!(check(TMUX, "attach").is_ok() && check(TMUX, "always").is_err());
        assert!(check(TRANSPORT, "mosh").is_ok() && check(TRANSPORT, "telnet").is_err());
        assert!(check(TMUX_SESSION, "main").is_ok() && check(TMUX_SESSION, "a.b").is_err() && check(TMUX_SESSION, &"x".repeat(65)).is_err());
    }

    #[test]
    fn mosh_args_carry_port_user_and_tmux() {
        let c = ssh(&[(TRANSPORT, "mosh"), (TMUX, "attach")]);
        let spec = mosh_launch(&c, &settings(Some(2222), Some("ops")), Some("/opt/homebrew/bin/mosh".into())).unwrap();
        assert_eq!(spec.program, "/opt/homebrew/bin/mosh");
        assert_eq!(spec.args, ["--ssh=ssh -p 2222", "ops@web.example", "--", "tmux", "new-session", "-A", "-s", "bastion"]);
        let plain = mosh_launch(&ssh(&[(TRANSPORT, "mosh")]), &settings(Some(22), None), Some("mosh".into())).unwrap();
        assert_eq!(plain.args, ["web.example"]);
    }

    #[test]
    fn mosh_refuses_what_it_cannot_do() {
        let c = ssh(&[(TRANSPORT, "mosh")]);
        assert!(mosh_launch(&ssh(&[]), &settings(None, None), Some("mosh".into())).is_err(), "transport is ssh");
        assert!(mosh_launch(&c, &settings(None, None), None).unwrap_err().to_string().contains("not installed"));
        let gw = Settings { gateway_id: Some(uuid::Uuid::new_v4()), ..Settings::default() };
        assert!(mosh_launch(&c, &gw, Some("mosh".into())).unwrap_err().to_string().contains("gateway"));
        assert!(mosh_launch(&c, &settings(None, Some("-oProxyCommand=x")), Some("mosh".into())).is_err());
        let mut evil = c.clone();
        evil.host = "-oProxyCommand=x".into();
        assert!(mosh_launch(&evil, &settings(None, None), Some("mosh".into())).is_err());
    }

    #[test]
    fn finds_mosh_on_known_paths_then_path() {
        assert_eq!(find_mosh(|p| p == Path::new("/usr/local/bin/mosh"), None).as_deref(), Some("/usr/local/bin/mosh"));
        let sep = if cfg!(windows) { ";" } else { ":" };
        let exe = if cfg!(windows) { "mosh.exe" } else { "mosh" };
        let found = find_mosh(|p| p.ends_with(format!("custom/{exe}")), Some(&format!("/nope{sep}/custom"))).unwrap();
        assert!(found.ends_with(exe) && found.contains("custom"));
        assert_eq!(find_mosh(|_| false, Some("/a")), None);
    }
}
