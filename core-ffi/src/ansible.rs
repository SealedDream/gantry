//! Ansible run sheet bridge (`bastion_core::ansible_run`): the validated argv for an ad-hoc command
//! or a playbook, plus what the sheet should warn about. The host spawns `argv[0]` with the rest
//! in a terminal, never through a shell.
use std::path::PathBuf;

use bastion_core::{ansible_remote, ansible_task};
use bastion_core::ansible_run::{self, Action, RunRequest};

use crate::FfiResult;

#[derive(uniffi::Record, Clone)]
pub struct AnsibleRunInput {
    /// "adhoc" or "playbook".
    pub kind: String,
    /// Absolute path of the inventory file.
    pub inventory: String,
    /// Ad-hoc: the host pattern (e.g. "bastion", "web*:!db1").
    pub pattern: String,
    /// Ad-hoc: module name ("ping", "ansible.builtin.setup").
    pub module: String,
    /// Ad-hoc: module arguments (`-a`), empty for none.
    pub module_args: String,
    /// Playbook: absolute path of the .yml/.yaml file.
    pub playbook: String,
    pub limit: Option<String>,
    pub check: bool,
    pub diff: bool,
    pub become_root: bool,
    pub forks: Option<u32>,
    pub verbosity: u8,
    /// Playbook: `--tags`, comma-separated.
    pub tags: Option<String>,
    /// `-e`, one line (never secrets: visible in the process list).
    pub extra_vars: Option<String>,
}

#[derive(uniffi::Record)]
pub struct AnsibleRunPlan {
    /// `argv[0]` is "ansible" or "ansible-playbook".
    pub argv: Vec<String>,
    pub warnings: Vec<String>,
}

fn request(input: AnsibleRunInput) -> FfiResult<RunRequest> {
    let action = match input.kind.as_str() {
        "adhoc" => Action::AdHoc { pattern: input.pattern, module: input.module, args: input.module_args },
        "playbook" => Action::Playbook { path: PathBuf::from(input.playbook) },
        other => return Err(crate::FfiError::failed(format!("unknown Ansible run kind `{other}`"))),
    };
    Ok(RunRequest {
        action,
        inventory: PathBuf::from(input.inventory),
        limit: input.limit.filter(|l| !l.is_empty()),
        check: input.check,
        diff: input.diff,
        become_root: input.become_root,
        forks: input.forks,
        verbosity: input.verbosity,
        tags: input.tags.filter(|t| !t.is_empty()),
        extra_vars: input.extra_vars.filter(|v| !v.is_empty()),
    })
}

/// Check the run sheet and return the command to start, or the first problem with it.
#[uniffi::export]
pub fn ansible_run_plan(input: AnsibleRunInput) -> FfiResult<AnsibleRunPlan> {
    let req = request(input)?;
    Ok(AnsibleRunPlan { argv: ansible_run::argv(&req)?, warnings: ansible_run::warnings(&req) })
}

#[derive(uniffi::Record)]
pub struct AnsibleUpload {
    pub local: String,
    pub remote: String,
}

/// A run on a control host: make `dirs` and upload `uploads` over SFTP on the host's SSH session,
/// then type `command` into its terminal (it removes `dir` when the run ends).
#[derive(uniffi::Record)]
pub struct AnsibleRemotePlan {
    pub dir: String,
    pub dirs: Vec<String>,
    pub uploads: Vec<AnsibleUpload>,
    pub argv: Vec<String>,
    pub command: String,
    pub warnings: Vec<String>,
}

/// Plan a control-host run. `home` is the SFTP home there, `run_id` 8 to 32 lowercase hex
/// characters, `upload_folder` copies the playbook's whole folder.
#[uniffi::export]
pub fn ansible_remote_plan(input: AnsibleRunInput, home: String, run_id: String, upload_folder: bool) -> FfiResult<AnsibleRemotePlan> {
    let p = ansible_remote::plan(&request(input)?, &home, &run_id, upload_folder)?;
    Ok(AnsibleRemotePlan {
        dir: p.dir,
        dirs: p.dirs,
        uploads: p.uploads.into_iter().map(|u| AnsibleUpload { local: u.local.to_string_lossy().into_owned(), remote: u.remote }).collect(),
        argv: p.argv,
        command: p.command,
        warnings: p.warnings,
    })
}

/// A saved Ansible task (owner, 2026-11-23): `program`, `args` and `run_on` ("local" or "ssh") for
/// a custom task. Save it with `save_task`; a "host" task runs on the control host connection.
#[derive(uniffi::Record)]
pub struct AnsibleTaskSpec {
    pub name: String,
    pub program: String,
    pub args: Vec<String>,
    pub run_on: String,
}

/// Build the task for a run. `mode` is "local" (this Mac), "wsl" (Windows) or "host" (the control
/// host, `host_name` for the task's name).
#[uniffi::export]
pub fn ansible_task(input: AnsibleRunInput, mode: String, host_name: Option<String>) -> FfiResult<AnsibleTaskSpec> {
    let mode = ansible_task::Mode::parse(&mode)?;
    let t = ansible_task::task(&request(input)?, mode, host_name.as_deref())?;
    let run_on = match t.run_on {
        bastion_core::tasks::RunOn::Local => "local",
        bastion_core::tasks::RunOn::Ssh => "ssh",
    };
    Ok(AnsibleTaskSpec { name: t.name, program: t.program, args: t.args, run_on: run_on.into() })
}
