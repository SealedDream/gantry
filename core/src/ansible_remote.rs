//! Running Ansible on a control host: a saved SSH connection whose machine has Ansible installed.
//! The host app connects to it as usual (vault credentials, host-key rules), opens SFTP on that
//! session, creates [`RemotePlan::dirs`], uploads [`RemotePlan::uploads`] and types
//! [`RemotePlan::command`] into the terminal. The command checks that the Ansible program exists,
//! runs it from the run directory and removes that directory whatever the result.
//!
//! Nothing secret is uploaded or put on the command line: the inventory carries no passwords
//! (`ansible_inventory`), hosts keep their own SSH users, and the only files are the inventory
//! and the playbook (or its folder when the user asks).
use std::path::{Path, PathBuf};

use crate::ansible_run::{self, shell_quote, Action, RunRequest};
use crate::error::{CoreError, Result};

/// Most files uploaded with a playbook folder.
pub const MAX_FILES: usize = 2000;
/// Largest playbook folder uploaded, in bytes.
pub const MAX_BYTES: u64 = 100 * 1024 * 1024;
/// Deepest folder nesting followed.
const MAX_DEPTH: usize = 16;
/// Prefix of the per-run directory in the control host's home.
pub const DIR_PREFIX: &str = ".gantry-ansible-";

/// One file to copy to the control host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upload {
    pub local: PathBuf,
    pub remote: String,
}

/// What the host app does on the control host, in order: make `dirs`, upload `uploads`, type
/// `command` (one line; it removes `dir` when the run ends).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePlan {
    pub dir: String,
    pub dirs: Vec<String>,
    pub uploads: Vec<Upload>,
    /// The argv run on the control host (remote paths).
    pub argv: Vec<String>,
    pub command: String,
    pub warnings: Vec<String>,
}

fn invalid(msg: &str) -> CoreError {
    CoreError::Invalid(msg.into())
}

/// Plan a run on the control host. `home` is the SFTP home directory there, `run_id` 8 to 32
/// lowercase hex characters (unique per run), `upload_folder` copies the playbook's whole folder
/// (roles, group_vars, templates) instead of the playbook file only.
pub fn plan(req: &RunRequest, home: &str, run_id: &str, upload_folder: bool) -> Result<RemotePlan> {
    let local = ansible_run::argv(req)?;
    if !home.starts_with('/') || home.contains("/../") || home.ends_with("/..") || home.chars().any(char::is_control) {
        return Err(invalid("The control host's home folder is not an absolute path."));
    }
    if !(8..=32).contains(&run_id.len()) || !run_id.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return Err(invalid("The run id must be 8 to 32 lowercase hex characters."));
    }
    let dir = format!("{}/{DIR_PREFIX}{run_id}", home.trim_end_matches('/'));
    let mut dirs = vec![dir.clone()];
    let ext = req.inventory.extension().and_then(|e| e.to_str()).filter(|e| matches!(*e, "ini" | "yml" | "yaml")).unwrap_or("ini");
    let inventory = format!("{dir}/inventory.{ext}");
    let mut uploads = vec![Upload { local: req.inventory.clone(), remote: inventory.clone() }];
    let mut playbook_remote = None;
    if let Action::Playbook { path } = &req.action {
        let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| invalid("The playbook has no file name."))?;
        if upload_folder {
            let root = path.parent().ok_or_else(|| invalid("The playbook has no folder."))?;
            let play = format!("{dir}/play");
            dirs.push(play.clone());
            collect(root, root, &play, 0, &mut dirs, &mut uploads, &mut 0)?;
            playbook_remote = Some(format!("{play}/{name}"));
        } else {
            let remote = format!("{dir}/{name}");
            uploads.push(Upload { local: path.clone(), remote: remote.clone() });
            playbook_remote = Some(remote);
        }
    }
    let local_inventory = req.inventory.to_str().unwrap_or_default();
    let local_playbook = match &req.action {
        Action::Playbook { path } => path.to_str(),
        Action::AdHoc { .. } => None,
    };
    let argv: Vec<String> = local
        .into_iter()
        .map(|a| {
            if a == local_inventory {
                inventory.clone()
            } else if Some(a.as_str()) == local_playbook {
                playbook_remote.clone().unwrap_or(a)
            } else {
                a
            }
        })
        .collect();
    let command = command_line(&dir, &argv);
    Ok(RemotePlan { dir, dirs, uploads, argv, command, warnings: ansible_run::warnings(req) })
}

/// One shell line: check the program, run it in `dir`, remove `dir`, report the exit code. A
/// leading space keeps it out of shell history where `HISTCONTROL` ignores such lines.
pub fn command_line(dir: &str, argv: &[String]) -> String {
    let program = shell_quote(&argv[0]);
    let missing = shell_quote(&format!("{} is not installed on this control host. Install Ansible there, or run on this computer.", argv[0]));
    let run = argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ");
    let dir = shell_quote(dir);
    format!(
        " cd {dir} && if command -v {program} >/dev/null 2>&1; then {run}; rc=$?; else printf '%s\\n' {missing}; rc=127; fi; cd; rm -rf -- {dir}; printf '[ansible exited %s]\\n' \"$rc\""
    )
}

/// Walk the playbook folder: regular files only (symlinks and `.git` skipped), bounded in count,
/// size and depth so a wrong pick (a home folder) fails fast instead of uploading everything.
fn collect(root: &Path, at: &Path, remote: &str, depth: usize, dirs: &mut Vec<String>, uploads: &mut Vec<Upload>, bytes: &mut u64) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(invalid(&format!("The playbook folder is nested deeper than {MAX_DEPTH} levels.")));
    }
    let mut entries: Vec<_> = std::fs::read_dir(at).map_err(|e| invalid(&format!("Could not read {}: {e}", at.display())))?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if name == ".git" || name.chars().any(char::is_control) {
            continue;
        }
        let ty = e.file_type().map_err(|err| invalid(&format!("Could not read {}: {err}", e.path().display())))?;
        let target = format!("{remote}/{name}");
        if ty.is_dir() {
            dirs.push(target.clone());
            collect(root, &e.path(), &target, depth + 1, dirs, uploads, bytes)?;
        } else if ty.is_file() {
            *bytes += e.metadata().map(|m| m.len()).unwrap_or(0);
            if uploads.len() > MAX_FILES || *bytes > MAX_BYTES {
                return Err(invalid(&format!(
                    "The folder {} is too large to upload (over {MAX_FILES} files or {} MB). Pick the playbook only.",
                    root.display(),
                    MAX_BYTES / 1024 / 1024
                )));
            }
            uploads.push(Upload { local: e.path(), remote: target });
        }
    }
    Ok(())
}
