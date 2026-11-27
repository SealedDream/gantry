//! Running Ansible from Bastion: the argument vector for an ad-hoc command (`ansible`) or a
//! playbook (`ansible-playbook`) against an inventory (usually one exported by
//! `ansible_inventory`). The host starts `argv[0]` with `argv[1..]` directly in a terminal (no
//! shell), so nothing here is ever re-parsed by a shell.
//!
//! Every field is checked so it cannot turn into another option: host patterns and limits may not
//! start with `-`, module names are dotted identifiers, files must be absolute and exist. No
//! password ever goes on the command line: `become` adds `--become` only, so a sudo that needs a
//! password fails instead of prompting into a log.
use std::path::{Path, PathBuf};

use crate::error::{CoreError, Result};

/// Longest host pattern or `--limit` accepted.
const MAX_PATTERN: usize = 256;
/// Longest module name accepted.
const MAX_MODULE: usize = 128;
/// Longest module argument string accepted (`-a`).
const MAX_ARGS: usize = 8 * 1024;
/// Largest `--forks` accepted.
pub const MAX_FORKS: u32 = 100;
/// Most `-v` flags (`-vvvv`).
pub const MAX_VERBOSITY: u8 = 4;

/// What to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `ansible <pattern> -m <module> [-a <args>]`.
    AdHoc { pattern: String, module: String, args: String },
    /// `ansible-playbook <playbook>`.
    Playbook { path: PathBuf },
}

/// One run, as the run sheet fills it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest {
    pub action: Action,
    pub inventory: PathBuf,
    /// `--limit`, narrowing the hosts further (optional for both kinds).
    pub limit: Option<String>,
    /// `--check`: report what would change without changing it.
    pub check: bool,
    /// `--diff`: show file changes.
    pub diff: bool,
    /// `--become` (sudo without a password prompt).
    pub become_root: bool,
    pub forks: Option<u32>,
    /// Number of `-v` flags, 0 to 4.
    pub verbosity: u8,
    /// `--tags`, comma-separated tag names (playbooks only).
    pub tags: Option<String>,
    /// `-e`, one line of `key=value` pairs or JSON. Visible in the process list: never secrets.
    pub extra_vars: Option<String>,
}

/// The argument vector (`argv[0]` is `ansible` or `ansible-playbook`, found on PATH by the host).
pub fn argv(req: &RunRequest) -> Result<Vec<String>> {
    let inventory = existing_file(&req.inventory, "inventory")?;
    let mut out = match &req.action {
        Action::AdHoc { pattern, module, args } => {
            let mut v = vec!["ansible".to_string(), check_pattern(pattern, "host pattern")?.to_string()];
            v.extend(["-i".into(), inventory, "-m".into(), check_module(module)?.to_string()]);
            if !args.is_empty() {
                v.extend(["-a".into(), check_args(args)?.to_string()]);
            }
            v
        }
        Action::Playbook { path } => {
            let playbook = existing_file(path, "playbook")?;
            if !matches!(path.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")) {
                return Err(invalid("The playbook must be a .yml or .yaml file."));
            }
            vec!["ansible-playbook".into(), "-i".into(), inventory, playbook]
        }
    };
    if let Some(limit) = &req.limit {
        out.extend(["--limit".into(), check_pattern(limit, "limit")?.to_string()]);
    }
    if req.check {
        out.push("--check".into());
    }
    if req.diff {
        out.push("--diff".into());
    }
    if req.become_root {
        out.push("--become".into());
    }
    if let Some(forks) = req.forks {
        if forks == 0 || forks > MAX_FORKS {
            return Err(invalid(&format!("Forks must be 1 to {MAX_FORKS}.")));
        }
        out.extend(["--forks".into(), forks.to_string()]);
    }
    if let Some(tags) = req.tags.as_deref().filter(|t| !t.is_empty()) {
        if !matches!(req.action, Action::Playbook { .. }) {
            return Err(invalid("Tags apply to playbooks only."));
        }
        out.extend(["--tags".into(), check_tags(tags)?.to_string()]);
    }
    if let Some(vars) = req.extra_vars.as_deref().filter(|v| !v.is_empty()) {
        out.extend(["-e".into(), check_extra_vars(vars)?.to_string()]);
    }
    if req.verbosity > MAX_VERBOSITY {
        return Err(invalid(&format!("Verbosity is 0 to {MAX_VERBOSITY}.")));
    }
    if req.verbosity > 0 {
        out.push(format!("-{}", "v".repeat(req.verbosity.into())));
    }
    Ok(out)
}

/// Things the run sheet should point out before starting (empty when nothing stands out).
pub fn warnings(req: &RunRequest) -> Vec<String> {
    let mut w = Vec::new();
    if let Action::AdHoc { module, .. } = &req.action {
        if matches!(module.as_str(), "shell" | "command" | "raw" | "ansible.builtin.shell" | "ansible.builtin.command" | "ansible.builtin.raw") {
            w.push(format!("`{module}` runs the text as a command on every matched host."));
        }
    }
    if req.become_root && !req.check {
        w.push("Runs as root (--become) and changes hosts; use Check first to preview.".into());
    }
    w
}

fn invalid(msg: &str) -> CoreError {
    CoreError::Invalid(msg.into())
}

fn existing_file(path: &Path, what: &str) -> Result<String> {
    if !path.is_absolute() || !path.is_file() {
        return Err(invalid(&format!("The {what} {} is not an existing file.", path.display())));
    }
    let s = path.to_str().ok_or_else(|| invalid(&format!("The {what} path is not valid UTF-8.")))?;
    if s.starts_with('-') || s.chars().any(char::is_control) {
        return Err(invalid(&format!("The {what} path is not allowed.")));
    }
    Ok(s.to_string())
}

/// Host patterns: names, groups, wildcards and the `:`, `,`, `&`, `!` operators; never an option.
fn check_pattern<'a>(p: &'a str, what: &str) -> Result<&'a str> {
    let ok = !p.is_empty()
        && p.len() <= MAX_PATTERN
        && !p.starts_with('-')
        && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '*' | '?' | ':' | ',' | '&' | '!' | '[' | ']' | '@' | '~'));
    ok.then_some(p).ok_or_else(|| invalid(&format!("The {what} `{p}` is not a valid Ansible host pattern.")))
}

fn check_module(m: &str) -> Result<&str> {
    let ok = !m.is_empty()
        && m.len() <= MAX_MODULE
        && m.split('.').all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !part.starts_with(|c: char| c.is_ascii_digit()));
    ok.then_some(m).ok_or_else(|| invalid(&format!("`{m}` is not a module name.")))
}

fn check_tags(t: &str) -> Result<&str> {
    let ok = t.len() <= MAX_PATTERN
        && t.split(',').all(|p| !p.is_empty() && !p.starts_with('-') && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')));
    ok.then_some(t).ok_or_else(|| invalid(&format!("Tags `{t}` must be names separated by commas.")))
}

fn check_extra_vars(v: &str) -> Result<&str> {
    if v.starts_with(['-', '@']) || v.len() > MAX_ARGS || v.chars().any(|c| c.is_control() && c != '\t') {
        return Err(invalid("Extra vars must be one line of key=value pairs or JSON (no @file, no leading -)."));
    }
    Ok(v)
}

/// Quote one word for a POSIX shell (`'…'`, with `'` written as `'\''`).
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn check_args(a: &str) -> Result<&str> {
    if a.len() > MAX_ARGS || a.chars().any(|c| c.is_control() && c != '\t') {
        return Err(invalid("Module arguments must be one line of at most 8 KiB."));
    }
    Ok(a)
}
