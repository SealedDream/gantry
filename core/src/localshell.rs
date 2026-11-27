//! Local terminal connections (`Protocol::Local`): a shell on this computer saved in the tree like
//! any host. The connection's `host` is unused; the shell is chosen by per-connection metadata:
//! `local.shell` (a `SHELLS` id, `wsl:<distro>`, or `custom`), `local.path` and `local.args` for
//! `custom`, and `local.cwd` for the start folder. Programs are started directly, never through
//! another shell, so arguments are passed exactly as split here.
use std::path::Path;

use crate::error::{CoreError, Result};
use crate::model::Connection;

pub const SHELL: &str = "local.shell";
pub const PATH: &str = "local.path";
pub const ARGS: &str = "local.args";
pub const CWD: &str = "local.cwd";

/// What to start: `program` with `args`, in `cwd` (`None`: the user's home).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalShellSpec {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
}

/// `(id, label)` of the built-in shells for this platform, the default first. `custom` is always
/// offered; Windows frontends add `wsl:<distro>` entries from `wsl::parse_distro_list`.
pub fn shells() -> &'static [(&'static str, &'static str)] {
    if cfg!(windows) {
        &[("powershell", "Windows PowerShell"), ("pwsh", "PowerShell 7"), ("cmd", "Command Prompt"), ("custom", "Custom program")]
    } else {
        &[("login", "Login shell"), ("zsh", "zsh"), ("bash", "bash"), ("fish", "fish"), ("custom", "Custom program")]
    }
}

/// Every id `local.shell` may hold on any platform (libraries move between Mac and Windows).
pub const SHELL_OPTIONS: &[(&str, &str)] = &[
    ("login", "Login shell"),
    ("zsh", "zsh"),
    ("bash", "bash"),
    ("fish", "fish"),
    ("powershell", "Windows PowerShell"),
    ("pwsh", "PowerShell 7"),
    ("cmd", "Command Prompt"),
    ("custom", "Custom program"),
];

const MAX_ARGS: usize = 64;
const MAX_VALUE: usize = 1024;

/// Split `local.args` like a shell would for plain words and double or single quotes; no
/// expansion of any kind happens.
pub fn split_args(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for ch in s.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '"' | '\'') => {
                quote = Some(ch);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            (None, c) => {
                cur.push(c);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return Err(CoreError::Invalid("Arguments: a quote is not closed.".into()));
    }
    if started {
        out.push(cur);
    }
    if out.len() > MAX_ARGS {
        return Err(CoreError::Invalid(format!("Arguments: at most {MAX_ARGS}.")));
    }
    Ok(out)
}

fn check_text(label: &str, v: &str) -> Result<()> {
    if v.len() > MAX_VALUE || v.chars().any(char::is_control) {
        return Err(CoreError::Invalid(format!("{label}: not a usable value.")));
    }
    Ok(())
}

/// Validate one `local.*` value before it is stored.
pub fn check(key: &str, v: &str) -> Result<()> {
    match key {
        SHELL => {
            let ok = SHELL_OPTIONS.iter().any(|(id, _)| *id == v) || v.strip_prefix("wsl:").is_some_and(|d| crate::wsl::launch_args(d).is_ok());
            if ok { Ok(()) } else { Err(CoreError::Invalid(format!("Shell: `{v}` is not one of the options."))) }
        }
        PATH => {
            check_text("Program", v)?;
            if !Path::new(v).is_absolute() {
                return Err(CoreError::Invalid("Program: use the program's full path.".into()));
            }
            Ok(())
        }
        CWD => {
            check_text("Start folder", v)?;
            if !(v.starts_with('~') || Path::new(v).is_absolute()) {
                return Err(CoreError::Invalid("Start folder: use a full path or one starting with ~.".into()));
            }
            Ok(())
        }
        ARGS => check_text("Arguments", v).and_then(|_| split_args(v).map(|_| ())),
        _ => Err(CoreError::Invalid(format!("`{key}` is not a local shell setting"))),
    }
}

fn home() -> Option<String> {
    let vars: [&str; 2] = if cfg!(windows) { ["USERPROFILE", "HOME"] } else { ["HOME", "USERPROFILE"] };
    vars.iter().find_map(|v| std::env::var(v).ok().filter(|h| !h.is_empty()))
}

/// `~` and `~/…` become the user's home; anything else is used as written.
fn expand_home(p: &str) -> String {
    match (p.strip_prefix('~'), home()) {
        (Some(rest), Some(h)) if rest.is_empty() || rest.starts_with('/') || rest.starts_with('\\') => format!("{h}{rest}"),
        _ => p.to_string(),
    }
}

/// First existing path among `candidates`, else the bare name (found on `PATH` when started).
fn find(candidates: &[&str], name: &str) -> String {
    candidates.iter().find(|c| Path::new(c).exists()).map_or_else(|| name.to_string(), |c| c.to_string())
}

/// Resolve a local connection to the program to start. Shells start as login shells where that
/// is the convention (`-l`), so they read the same profile as a new Terminal window.
pub fn resolve(c: &Connection) -> Result<LocalShellSpec> {
    let meta = |k: &str| c.metadata.get(k).map(String::as_str).filter(|v| !v.trim().is_empty());
    let shell = meta(SHELL).unwrap_or(shells()[0].0);
    check(SHELL, shell)?;
    let extra = meta(ARGS).map(split_args).transpose()?.unwrap_or_default();
    let (program, mut args): (String, Vec<String>) = match shell {
        "login" => (std::env::var("SHELL").ok().filter(|s| Path::new(s).is_absolute()).unwrap_or_else(|| "/bin/zsh".into()), vec!["-l".into()]),
        "zsh" => (find(&["/bin/zsh", "/usr/bin/zsh"], "zsh"), vec!["-l".into()]),
        "bash" => (find(&["/opt/homebrew/bin/bash", "/usr/local/bin/bash", "/bin/bash", "/usr/bin/bash"], "bash"), vec!["-l".into()]),
        "fish" => (find(&["/opt/homebrew/bin/fish", "/usr/local/bin/fish", "/usr/bin/fish"], "fish"), vec!["-l".into()]),
        "powershell" => ("powershell.exe".into(), vec!["-NoLogo".into()]),
        "pwsh" => ("pwsh.exe".into(), vec!["-NoLogo".into()]),
        "cmd" => ("cmd.exe".into(), vec![]),
        "custom" => {
            let p = meta(PATH).ok_or_else(|| CoreError::Invalid("Choose the program to start.".into()))?;
            check(PATH, p)?;
            (p.to_string(), vec![])
        }
        wsl => ("wsl.exe".into(), crate::wsl::launch_args(wsl.trim_start_matches("wsl:"))?),
    };
    args.extend(extra);
    let cwd = meta(CWD).map(|d| check(CWD, d).map(|_| expand_home(d))).transpose()?;
    Ok(LocalShellSpec { program, args, cwd })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;

    fn local(pairs: &[(&str, &str)]) -> Connection {
        let mut c = Connection::new("shell", Protocol::Local, "");
        for (k, v) in pairs {
            c.metadata.insert(k.to_string(), v.to_string());
        }
        c
    }

    #[test]
    fn args_split_on_spaces_and_respect_quotes() {
        assert_eq!(split_args(r#"-c "echo hi" 'a b' x"#).unwrap(), vec!["-c", "echo hi", "a b", "x"]);
        assert_eq!(split_args(r#""" x"#).unwrap(), vec!["", "x"]);
        assert!(split_args("\"open").is_err());
    }

    #[test]
    fn custom_program_needs_an_absolute_path() {
        assert!(resolve(&local(&[(SHELL, "custom")])).is_err());
        assert!(resolve(&local(&[(SHELL, "custom"), (PATH, "zsh")])).is_err());
        // An absolute path is spelled differently per platform: `/usr/bin/env` is not absolute on Windows.
        #[cfg(windows)]
        let (prog, dir) = (r"C:\Windows\System32\cmd.exe", r"C:\Temp");
        #[cfg(not(windows))]
        let (prog, dir) = ("/usr/bin/env", "/tmp");
        assert!(resolve(&local(&[(SHELL, "custom"), (PATH, "bin/env")])).is_err());
        let s = resolve(&local(&[(SHELL, "custom"), (PATH, prog), (ARGS, "FOO=1 /bin/sh"), (CWD, dir)])).unwrap();
        assert_eq!((s.program.as_str(), s.args, s.cwd.as_deref()), (prog, vec!["FOO=1".to_string(), "/bin/sh".to_string()], Some(dir)));
    }

    #[test]
    fn named_shells_and_wsl_resolve() {
        assert_eq!(resolve(&local(&[(SHELL, "zsh")])).unwrap().args, vec!["-l"]);
        assert_eq!(resolve(&local(&[(SHELL, "cmd")])).unwrap().program, "cmd.exe");
        let w = resolve(&local(&[(SHELL, "wsl:Ubuntu-22.04")])).unwrap();
        assert_eq!((w.program.as_str(), w.args[1].as_str()), ("wsl.exe", "Ubuntu-22.04"));
        assert!(check(SHELL, "wsl:-x").is_err() && check(SHELL, "sh; rm").is_err());
    }

    #[test]
    fn start_folder_expands_home_and_rejects_relative_paths() {
        assert!(check(CWD, "projects").is_err());
        let s = resolve(&local(&[(SHELL, "zsh"), (CWD, "~/src")])).unwrap();
        assert!(s.cwd.unwrap().ends_with("/src"));
    }
}
