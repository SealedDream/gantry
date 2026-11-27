use std::path::{Path, PathBuf};
use std::process::Command;

use super::*;
use crate::model::{Connection, Protocol};
use crate::policy::Policy;
use crate::tasks::{prepare, Invocation, TaskDef, TaskKind};

fn request(dir: &Path, playbook: bool) -> RunRequest {
    let inventory = dir.join("inv.ini");
    std::fs::write(&inventory, "[web]\nweb1 ansible_host=10.0.0.1\n").unwrap();
    let action = if playbook {
        let p = dir.join("site.yml");
        std::fs::write(&p, "- hosts: all\n  tasks:\n    - ping:\n").unwrap();
        Action::Playbook { path: p }
    } else {
        Action::AdHoc { pattern: "web".into(), module: "shell".into(), args: "echo $HOME".into() }
    };
    RunRequest { action, inventory, limit: None, check: false, diff: false, become_root: false, forks: None, verbosity: 0, tags: None, extra_vars: None }
}

fn as_task(spec: &TaskSpec) -> TaskDef {
    TaskDef {
        id: uuid::Uuid::new_v4(),
        name: spec.name.clone(),
        favorite: false,
        kind: TaskKind::Custom { program: spec.program.clone(), args: spec.args.clone(), run_on: spec.run_on },
        timeout_secs: 600,
    }
}

/// A fake `ansible`/`ansible-playbook` that prints its arguments and the files they name.
fn fake_bin(dir: &Path) -> PathBuf {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for name in ["ansible", "ansible-playbook"] {
        let p = bin.join(name);
        std::fs::write(&p, "#!/bin/sh\nfor a in \"$@\"; do echo \"ARG $a\"; [ -f \"$a\" ] && cat \"$a\"; done\necho \"PWD $PWD\"\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    bin
}

fn conn() -> Connection {
    Connection::new("ctl", Protocol::Ssh, "127.0.0.1")
}

#[test]
fn modes_parse() {
    assert_eq!(Mode::parse("local").unwrap(), Mode::Local);
    assert_eq!(Mode::parse("wsl").unwrap(), Mode::Wsl);
    assert_eq!(Mode::parse("host").unwrap(), Mode::ControlHost);
    assert!(Mode::parse("x").is_err());
}

#[test]
fn local_task_keeps_dollar_signs_through_substitution() {
    let dir = tempfile::tempdir().unwrap();
    let spec = task(&request(dir.path(), false), Mode::Local, None).unwrap();
    assert_eq!((spec.program.as_str(), spec.run_on), ("/bin/sh", RunOn::Local));
    assert_eq!(spec.name, "Ansible shell web");
    let p = prepare(&as_task(&spec), &conn(), &Policy::default()).unwrap();
    let Invocation::Local { args, .. } = p.invocation else { panic!("local") };
    assert!(args.iter().any(|a| a == "echo $HOME"), "{args:?}");
    assert!(args[1].contains("brew install ansible"));
}

#[test]
fn wsl_task_uses_mount_paths() {
    let dir = tempfile::tempdir().unwrap();
    let mut req = request(dir.path(), true);
    let spec = task(&req, Mode::Wsl, None).unwrap();
    assert_eq!(spec.program, "wsl.exe");
    assert_eq!(&spec.args[..3], &["-e".to_string(), "sh".into(), "-c".into()]);
    assert!(spec.args[3].contains("sudo apt install ansible"));
    assert_eq!(windows_to_wsl_path(r"C:\Users\a\inv.ini").as_deref(), Some("/mnt/c/Users/a/inv.ini"));
    assert_eq!(windows_to_wsl_path("relative"), None);
    req.extra_vars = Some("a=1".into());
    assert!(task(&req, Mode::Wsl, None).unwrap().args.contains(&"a=1".to_string()));
}

#[cfg(unix)]
#[test]
fn local_task_runs_and_reports_missing_ansible() {
    let dir = tempfile::tempdir().unwrap();
    let spec = task(&request(dir.path(), false), Mode::Local, None).unwrap();
    let Invocation::Local { program, args } = prepare(&as_task(&spec), &conn(), &Policy::default()).unwrap().invocation else { panic!() };
    let bin = fake_bin(dir.path());
    let ok = Command::new(&program).args(&args).env("PATH", format!("{}:/usr/bin:/bin", bin.display())).output().unwrap();
    assert!(ok.status.success());
    assert!(String::from_utf8_lossy(&ok.stdout).contains("ARG echo $HOME"));
    // Ansible may be installed in the Homebrew folders the check adds, so name a program that is not.
    let mut gone = args.clone();
    gone[3] = "ansible-gantry-missing".into();
    let missing = Command::new(&program).args(&gone).env("PATH", "/usr/bin:/bin").output().unwrap();
    assert_eq!(missing.status.code(), Some(127));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("ansible-gantry-missing not found on this Mac. Install: brew install ansible"));
}

/// The control-host command, as the SSH task engine would send it, run here with `sh`.
#[cfg(unix)]
fn run_host(req: &RunRequest, path: &str, home: &Path) -> std::process::Output {
    let spec = task(req, Mode::ControlHost, Some("ctl")).unwrap();
    assert_eq!((spec.program.as_str(), spec.run_on), ("sh", RunOn::Ssh));
    let Invocation::Remote { command } = prepare(&as_task(&spec), &conn(), &Policy::default()).unwrap().invocation else { panic!() };
    Command::new("/bin/sh").arg("-c").arg(&command).env("PATH", path).env("HOME", home).output().unwrap()
}

#[cfg(unix)]
#[test]
fn control_host_task_writes_files_runs_and_cleans_up() {
    let local = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let bin = fake_bin(local.path());
    let req = request(local.path(), true);
    let out = run_host(&req, &format!("{}:/usr/bin:/bin", bin.display()), home.path());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text} {}", String::from_utf8_lossy(&out.stderr));
    assert!(text.contains("web1 ansible_host=10.0.0.1"), "{text}");
    assert!(text.contains("- hosts: all"), "{text}");
    assert!(text.contains(DIR_PREFIX), "{text}");
    assert!(!text.contains(local.path().to_str().unwrap()), "local paths must not reach the host: {text}");
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0, "run folder removed");
    assert_eq!(task(&req, Mode::ControlHost, Some("ctl")).unwrap().name, "Ansible site.yml on ctl");
}

#[cfg(unix)]
#[test]
fn control_host_task_reports_missing_ansible_and_cleans_up() {
    let local = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let out = run_host(&request(local.path(), false), "/usr/bin:/bin", home.path());
    assert_eq!(out.status.code(), Some(127));
    assert!(String::from_utf8_lossy(&out.stderr).contains("ansible is not installed on this control host"));
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn control_host_task_carries_a_large_playbook_in_chunks() {
    let local = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let bin = fake_bin(local.path());
    let req = request(local.path(), true);
    let Action::Playbook { path } = &req.action else { panic!() };
    let big = format!("- hosts: all\n{}#END\n", "# filler line\n".repeat(1500));
    std::fs::write(path, &big).unwrap();
    assert!(task(&req, Mode::ControlHost, None).unwrap().args.len() > 6);
    let out = run_host(&req, &format!("{}:/usr/bin:/bin", bin.display()), home.path());
    assert!(String::from_utf8_lossy(&out.stdout).contains("# filler line\n#END"));
}

#[test]
fn too_large_a_run_is_refused() {
    let local = tempfile::tempdir().unwrap();
    let req = request(local.path(), true);
    let Action::Playbook { path } = &req.action else { panic!() };
    std::fs::write(path, "x".repeat(300 * 1024)).unwrap();
    assert!(task(&req, Mode::ControlHost, None).unwrap_err().to_string().contains("too large"));
}

#[test]
fn odd_playbook_names_are_refused_for_control_host() {
    let local = tempfile::tempdir().unwrap();
    let mut req = request(local.path(), true);
    let p = local.path().join("my play.yml");
    std::fs::write(&p, "- hosts: all\n").unwrap();
    req.action = Action::Playbook { path: p };
    assert!(task(&req, Mode::ControlHost, None).is_err());
    assert!(task(&req, Mode::Local, None).is_ok());
}
