//! Save an Ansible run (ad hoc or playbook) as a custom task (owner, 2026-11-23). The task records
//! where it runs by its shape:
//!
//! - [`Mode::Local`]: `/bin/sh -c <check> gantry argv…` on this Mac. The check adds the
//!   usual install folders to PATH and prints the run sheet's "not found" message when Ansible is
//!   missing.
//! - [`Mode::Wsl`]: `wsl.exe -e sh -c <check> gantry argv…` on Windows, paths turned into WSL
//!   mount paths. The app checks WSL itself before the run (its message needs Windows calls).
//! - [`Mode::ControlHost`]: an SSH task run on the control host connection, with the connection's
//!   own credentials at run time. The inventory and playbook travel base64-encoded in the
//!   arguments, are written to a private temporary folder there and removed when the run ends.
//!   No password is stored in the task or written on the host (the inventory has none).
//!
//! Every `$` is doubled so the task's variable substitution leaves the command as planned.
use crate::ansible_remote::DIR_PREFIX;
use crate::ansible_run::{self, shell_quote, Action, RunRequest};
use crate::error::{CoreError, Result};
use crate::tasks::{RunOn, MAX_ARGS, MAX_ARG_LEN};

/// Where a saved Ansible task runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Local,
    Wsl,
    ControlHost,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Mode> {
        match s {
            "local" => Ok(Mode::Local),
            "wsl" => Ok(Mode::Wsl),
            "host" => Ok(Mode::ControlHost),
            other => Err(CoreError::Invalid(format!("unknown Ansible task mode `{other}`"))),
        }
    }
}

/// The custom task to save.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSpec {
    pub name: String,
    pub program: String,
    pub args: Vec<String>,
    pub run_on: RunOn,
}

/// The `$0` of the `sh -c` scripts.
const ARG0: &str = "gantry";
/// Base64 characters per argument (task arguments are at most [`MAX_ARG_LEN`]).
const CHUNK: usize = 4000;
/// Longest saved task name.
const MAX_NAME: usize = 60;
/// Where pip, pipx and Homebrew put Ansible (a GUI app's PATH is short), as the run sheet searches.
const LOCAL_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin";

fn invalid(msg: &str) -> CoreError {
    CoreError::Invalid(msg.into())
}

/// Build the task for `req`. `host_name` (control host only) goes in the task name.
pub fn task(req: &RunRequest, mode: Mode, host_name: Option<&str>) -> Result<TaskSpec> {
    let argv = ansible_run::argv(req)?;
    let (program, args, run_on) = match mode {
        Mode::Local => ("/bin/sh".to_string(), local_args(&argv, "on this Mac. Install: brew install ansible", true), RunOn::Local),
        Mode::Wsl => {
            let mut args = vec!["-e".to_string(), "sh".to_string()];
            let wsl: Vec<String> = argv.iter().map(|a| windows_to_wsl_path(a).unwrap_or_else(|| a.clone())).collect();
            args.extend(local_args(&wsl, "in WSL. Install there: sudo apt install ansible", false));
            ("wsl.exe".to_string(), args, RunOn::Local)
        }
        Mode::ControlHost => ("sh".to_string(), host_args(req, &argv)?, RunOn::Ssh),
    };
    let escape = |s: &str| s.replace('$', "$$");
    let args: Vec<String> = args.iter().map(|a| escape(a)).collect();
    if args.len() > MAX_ARGS || args.iter().any(|a| a.len() > MAX_ARG_LEN) {
        return Err(invalid("This run is too large to save as a task (inventory and playbook together at most about 200 KB)."));
    }
    Ok(TaskSpec { name: name(req, mode, host_name), program: escape(&program), args, run_on })
}

/// `-c <check> gantry argv…`: report a missing program the way the run sheet does, else exec it.
fn local_args(argv: &[String], missing: &str, extend_path: bool) -> Vec<String> {
    let path = if extend_path { format!("PATH=\"$PATH:{LOCAL_PATH}\"; export PATH; ") } else { String::new() };
    let script = format!(
        "{path}if ! command -v \"$1\" >/dev/null 2>&1; then printf '%s not found {missing}\\n' \"$1\" >&2; exit 127; fi; exec \"$@\""
    );
    let mut out = vec!["-c".to_string(), script, ARG0.to_string()];
    out.extend(argv.iter().cloned());
    out
}

/// `-c <script> gantry <n> <inventory chunks…> <playbook chunks…>`: write the files to a private
/// temporary folder in the control host's home, check the program, run it there, remove the folder.
fn host_args(req: &RunRequest, argv: &[String]) -> Result<Vec<String>> {
    let read = |p: &std::path::Path, what: &str| std::fs::read(p).map_err(|e| invalid(&format!("Could not read the {what} {}: {e}", p.display())));
    let ext = req.inventory.extension().and_then(|e| e.to_str()).filter(|e| matches!(*e, "ini" | "yml" | "yaml")).unwrap_or("ini");
    let inventory_name = format!("inventory.{ext}");
    let inventory = chunks(&read(&req.inventory, "inventory")?);
    let (playbook_name, playbook) = match &req.action {
        Action::Playbook { path } => {
            let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| invalid("The playbook has no file name."))?;
            if name.chars().any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))) {
                return Err(invalid("The playbook file name may hold only letters, digits, dot, dash and underscore."));
            }
            (Some(name.to_string()), chunks(&read(path, "playbook")?))
        }
        Action::AdHoc { .. } => (None, Vec::new()),
    };
    let local_inventory = req.inventory.to_str().unwrap_or_default();
    let local_playbook = match &req.action {
        Action::Playbook { path } => path.to_str(),
        Action::AdHoc { .. } => None,
    };
    let run = argv
        .iter()
        .map(|a| {
            if a == local_inventory {
                format!("\"$d\"/{inventory_name}")
            } else if Some(a.as_str()) == local_playbook {
                format!("\"$d\"/{}", playbook_name.as_deref().unwrap_or_default())
            } else {
                shell_quote(a)
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let program = shell_quote(&argv[0]);
    let missing = shell_quote(&format!("{} is not installed on this control host. Install Ansible there, or run on this computer.", argv[0]));
    let playbook_write = match &playbook_name {
        Some(name) => format!("printf %s \"$@\" | base64 -d > \"$d\"/{name} || exit 1; "),
        None => String::new(),
    };
    let script = format!(
        "n=$1; shift; inv=; i=0; while [ \"$i\" -lt \"$n\" ]; do inv=$inv$1; shift; i=$((i+1)); done; \
         d=$(mktemp -d \"${{HOME:-/tmp}}/{DIR_PREFIX}XXXXXXXX\") || exit 1; trap 'rm -rf -- \"$d\"' EXIT; \
         printf %s \"$inv\" | base64 -d > \"$d\"/{inventory_name} || exit 1; {playbook_write}\
         cd \"$d\" || exit 1; if ! command -v {program} >/dev/null 2>&1; then printf '%s\\n' {missing} >&2; exit 127; fi; {run}"
    );
    let mut out = vec!["-c".to_string(), script, ARG0.to_string(), inventory.len().to_string()];
    out.extend(inventory);
    out.extend(playbook);
    Ok(out)
}

fn chunks(bytes: &[u8]) -> Vec<String> {
    use base64::Engine;
    let text = base64::engine::general_purpose::STANDARD.encode(bytes);
    if text.is_empty() {
        return vec![String::new()];
    }
    text.as_bytes().chunks(CHUNK).map(|c| String::from_utf8_lossy(c).into_owned()).collect()
}

fn name(req: &RunRequest, mode: Mode, host_name: Option<&str>) -> String {
    let what = match &req.action {
        Action::AdHoc { pattern, module, .. } => format!("Ansible {module} {pattern}"),
        Action::Playbook { path } => format!("Ansible {}", path.file_name().and_then(|n| n.to_str()).unwrap_or("playbook")),
    };
    let full = match (mode, host_name) {
        (Mode::ControlHost, Some(h)) if !h.trim().is_empty() => format!("{what} on {}", h.trim()),
        _ => what,
    };
    full.chars().filter(|c| !c.is_control()).take(MAX_NAME).collect()
}

/// `C:\a\b.ini` → `/mnt/c/a/b.ini`; None for anything that is not a drive-rooted path.
pub fn windows_to_wsl_path(arg: &str) -> Option<String> {
    let b = arg.as_bytes();
    if b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' || (b[2] != b'\\' && b[2] != b'/') {
        return None;
    }
    Some(format!("/mnt/{}{}", (b[0] as char).to_ascii_lowercase(), arg[2..].replace('\\', "/")))
}

#[cfg(test)]
#[path = "ansible_task_tests.rs"]
mod tests;
