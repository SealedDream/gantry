//! Control-host runs: what is uploaded where, the one-line command, and the guards.
use std::path::PathBuf;
use std::process::Command;

use bastion_core::ansible_remote::{command_line, plan, MAX_FILES};
use bastion_core::ansible_run::{Action, RunRequest};

fn files() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let inv = d.path().join("inventory.ini");
    let pb = d.path().join("site.yml");
    std::fs::write(&inv, "[bastion]\nweb1 ansible_host=10.0.0.1 ansible_user=ops\n").unwrap();
    std::fs::write(&pb, "- hosts: all\n  tasks: []\n").unwrap();
    (d, inv, pb)
}

fn req(inv: &PathBuf, action: Action) -> RunRequest {
    RunRequest { action, inventory: inv.clone(), limit: None, check: false, diff: false, become_root: false, forks: None, verbosity: 0, tags: None, extra_vars: None }
}

const ID: &str = "0123abcd";

#[test]
fn playbook_file_is_uploaded_and_paths_are_swapped() {
    let (_d, inv, pb) = files();
    let mut r = req(&inv, Action::Playbook { path: pb.clone() });
    r.check = true;
    r.limit = Some("web1".into());
    r.tags = Some("setup,users".into());
    r.extra_vars = Some("env=lab".into());
    let p = plan(&r, "/home/ops", ID, false).unwrap();
    assert_eq!(p.dir, "/home/ops/.gantry-ansible-0123abcd");
    assert_eq!(p.dirs, [p.dir.clone()]);
    assert_eq!(p.uploads.len(), 2);
    assert_eq!(p.uploads[0].local, inv);
    assert_eq!(p.uploads[0].remote, format!("{}/inventory.ini", p.dir));
    assert_eq!(p.uploads[1].remote, format!("{}/site.yml", p.dir));
    assert_eq!(
        p.argv,
        ["ansible-playbook", "-i", &format!("{}/inventory.ini", p.dir), &format!("{}/site.yml", p.dir), "--limit", "web1", "--check", "--tags", "setup,users", "-e", "env=lab"]
    );
    assert!(p.command.starts_with(" cd '/home/ops/.gantry-ansible-0123abcd' && "), "leading space keeps it out of history");
    assert!(p.command.contains("rm -rf -- '/home/ops/.gantry-ansible-0123abcd'"), "the run dir is always removed");
}

#[test]
fn adhoc_uploads_only_the_inventory() {
    let (_d, inv, _pb) = files();
    let p = plan(&req(&inv, Action::AdHoc { pattern: "all".into(), module: "ping".into(), args: String::new() }), "/root/", ID, false).unwrap();
    assert_eq!(p.dir, "/root/.gantry-ansible-0123abcd");
    assert_eq!(p.uploads.len(), 1);
    assert_eq!(p.argv[..2], ["ansible".to_string(), "all".to_string()]);
}

#[test]
fn folder_upload_keeps_layout_and_skips_git_and_symlinks() {
    let (d, inv, pb) = files();
    std::fs::create_dir_all(d.path().join("roles/web/tasks")).unwrap();
    std::fs::write(d.path().join("roles/web/tasks/main.yml"), "[]").unwrap();
    std::fs::create_dir_all(d.path().join(".git")).unwrap();
    std::fs::write(d.path().join(".git/config"), "x").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", d.path().join("leak")).unwrap();
    let p = plan(&req(&inv, Action::Playbook { path: pb }), "/home/ops", ID, true).unwrap();
    let remotes: Vec<_> = p.uploads.iter().map(|u| u.remote.trim_start_matches(&p.dir).to_string()).collect();
    assert!(remotes.contains(&"/play/roles/web/tasks/main.yml".to_string()));
    assert!(remotes.contains(&"/play/site.yml".to_string()));
    assert!(!remotes.iter().any(|r| r.contains(".git") || r.ends_with("/leak")), "{remotes:?}");
    assert!(p.dirs.contains(&format!("{}/play/roles/web/tasks", p.dir)));
    assert_eq!(p.argv[3], format!("{}/play/site.yml", p.dir));
}

#[test]
fn too_many_files_is_refused() {
    let (d, inv, pb) = files();
    for i in 0..=MAX_FILES {
        std::fs::write(d.path().join(format!("f{i}")), "").unwrap();
    }
    let e = plan(&req(&inv, Action::Playbook { path: pb }), "/home/ops", ID, true).unwrap_err().to_string();
    assert!(e.contains("too large"), "{e}");
}

#[test]
fn bad_home_or_run_id_is_refused() {
    let (_d, inv, pb) = files();
    let r = req(&inv, Action::Playbook { path: pb });
    for home in ["relative", "/a/../b", "/a\nb", ""] {
        assert!(plan(&r, home, ID, false).is_err(), "{home:?}");
    }
    for id in ["short", "0123ABCD", "0123abcd;rm", &"a".repeat(33)] {
        assert!(plan(&r, "/home/ops", id, false).is_err(), "{id:?}");
    }
}

#[test]
fn missing_playbook_says_so() {
    let (d, inv, _pb) = files();
    let e = plan(&req(&inv, Action::Playbook { path: d.path().join("gone.yml") }), "/home/ops", ID, false).unwrap_err().to_string();
    assert!(e.contains("gone.yml") && e.contains("not an existing file"), "{e}");
}

#[test]
fn tags_and_extra_vars_are_checked() {
    let (_d, inv, pb) = files();
    let mut r = req(&inv, Action::Playbook { path: pb });
    r.tags = Some("--force".into());
    assert!(plan(&r, "/h", ID, false).is_err());
    r.tags = None;
    r.extra_vars = Some("@/etc/shadow".into());
    assert!(plan(&r, "/h", ID, false).is_err());
    let mut a = req(&inv, Action::AdHoc { pattern: "all".into(), module: "ping".into(), args: String::new() });
    a.tags = Some("x".into());
    assert!(plan(&a, "/h", ID, false).is_err(), "tags are for playbooks");
}

/// The command really runs in sh: quoting survives hostile text, a missing program prints the
/// clear message, and the run dir is removed either way.
#[cfg(unix)]
#[test]
fn command_line_runs_in_sh_and_cleans_up() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("run dir 'x'");
    std::fs::create_dir(&dir).unwrap();
    let dir_s = dir.to_str().unwrap();
    let ok = command_line(dir_s, &["echo".into(), "a b".into(), "$(touch /tmp/pwned-gantry)".into()]);
    let out = Command::new("sh").arg("-c").arg(&ok).env("HOME", d.path()).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("a b $(touch /tmp/pwned-gantry)") && text.contains("[ansible exited 0]"), "{text}");
    assert!(!dir.exists(), "run dir removed");
    std::fs::create_dir(&dir).unwrap();
    let missing = command_line(dir_s, &["ansible-playbook-not-here".into()]);
    let out = Command::new("sh").arg("-c").arg(&missing).env("HOME", d.path()).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("ansible-playbook-not-here is not installed on this control host") && text.contains("[ansible exited 127]"), "{text}");
    assert!(!dir.exists(), "run dir removed after a missing program too");
}

/// Live: plans run on a real control host over the system ssh/sftp (the apps use the same SFTP
/// calls and type the same line). `BASTION_LAB_CH="user@host port keyfile"`.
struct Lab {
    target: String,
    port: String,
    key: String,
}

impl Lab {
    fn from_env() -> Option<Lab> {
        let spec = std::env::var("BASTION_LAB_CH").ok()?;
        let p: Vec<&str> = spec.split_whitespace().collect();
        Some(Lab { target: p[0].into(), port: p[1].into(), key: p[2].into() })
    }

    fn ssh(&self, cmd: &str) -> String {
        let o = Command::new("ssh")
            .args(["-i", &self.key, "-p", &self.port, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", &self.target, cmd])
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr)
    }

    /// Upload, run, and return (output, run folder removed).
    fn run(&self, r: &RunRequest, folder: bool) -> (String, bool) {
        let home = self.ssh("pwd").trim().to_string();
        let id = format!("{:016x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64);
        let p = plan(r, &home, &id, folder).unwrap();
        let mut batch: Vec<String> = p.dirs.iter().map(|d| format!("mkdir \"{d}\"")).collect();
        batch.extend(p.uploads.iter().map(|u| format!("put \"{}\" \"{}\"", u.local.display(), u.remote)));
        let d = tempfile::tempdir().unwrap();
        let bf = d.path().join("batch");
        std::fs::write(&bf, batch.join("\n")).unwrap();
        let up = Command::new("sftp").args(["-i", &self.key, "-P", &self.port, "-o", "BatchMode=yes", "-b", bf.to_str().unwrap(), &self.target]).output().unwrap();
        assert!(up.status.success(), "{}", String::from_utf8_lossy(&up.stderr));
        let text = self.ssh(&p.command);
        println!("---- {}\n{text}", p.argv.join(" "));
        let gone = self.ssh(&format!("test -e {} && echo LEFT || echo GONE", p.dir)).trim() == "GONE";
        (text, gone)
    }
}

/// A control host without Ansible (`BASTION_LAB_CH_EXPECT=missing`).
#[test]
#[ignore]
fn live_control_host_without_ansible() {
    let Some(lab) = Lab::from_env() else { return };
    if std::env::var("BASTION_LAB_CH_EXPECT").as_deref() != Ok("missing") {
        return;
    }
    let (_d, inv, pb) = files();
    let (text, gone) = lab.run(&req(&inv, Action::Playbook { path: pb }), false);
    assert!(text.contains("ansible-playbook is not installed on this control host") && text.contains("[ansible exited 127]"), "{text}");
    assert!(gone, "run folder removed");
}

/// A control host with Ansible, against a lab sshd target reachable from it
/// (`BASTION_LAB_CH_TARGET="host port user"`; the control host has its own key for it). The
/// targets have no Python, so the tasks use `raw`. Each case reads a marker back over ssh.
#[test]
#[ignore]
fn live_control_host_runs() {
    let Some(lab) = Lab::from_env() else { return };
    let Ok(t) = std::env::var("BASTION_LAB_CH_TARGET") else { return };
    let t: Vec<&str> = t.split_whitespace().collect();
    let d = tempfile::tempdir().unwrap();
    let inv = d.path().join("inventory.ini");
    std::fs::write(&inv, format!("[lab]\nlab1 ansible_host={} ansible_port={} ansible_user={}\ndead1 ansible_host={} ansible_port=1 ansible_user={}\n", t[0], t[1], t[2], t[0], t[2])).unwrap();
    std::fs::create_dir(d.path().join("files")).unwrap();
    std::fs::write(d.path().join("files/extra.txt"), "x").unwrap();
    let tag = format!("{:08x}", std::process::id());
    let pb = d.path().join("site.yml");
    std::fs::write(
        &pb,
        format!(
            "- hosts: lab1\n  gather_facts: false\n  tasks:\n    - ansible.builtin.raw: echo book > ch-book-{tag}.txt\n      tags: [book]\n    - ansible.builtin.raw: echo other > ch-other-{tag}.txt\n      tags: [other]\n    - ansible.builtin.raw: echo {{{{ env | default('none') }}}} > ch-vars-{tag}.txt\n      tags: [book]\n"
        ),
    )
    .unwrap();
    let target = |cmd: &str| lab.ssh(&format!("ssh -o BatchMode=yes -p {} {}@{} {}", t[1], t[2], t[0], shell_q(cmd)));
    let book = || Action::Playbook { path: pb.clone() };

    // Playbook with tags, extra vars and the whole folder uploaded.
    let mut r = req(&inv, book());
    r.tags = Some("book".into());
    r.extra_vars = Some("env=labvar".into());
    r.limit = Some("lab1".into());
    let (text, gone) = lab.run(&r, true);
    assert!(text.contains("[ansible exited 0]") && gone, "{text}");
    let seen = target(&format!("cat ch-book-{tag}.txt ch-vars-{tag}.txt; test -e ch-other-{tag}.txt && echo OTHER-RAN || echo OTHER-SKIPPED"));
    assert!(seen.contains("book") && seen.contains("labvar") && seen.contains("OTHER-SKIPPED"), "tags and extra vars: {seen}");

    // Check mode: raw does not run in check mode, so no marker appears.
    target(&format!("rm -f ch-*-{tag}.txt"));
    let mut r = req(&inv, book());
    r.check = true;
    r.limit = Some("lab1".into());
    let (text, gone) = lab.run(&r, false);
    assert!(text.contains("[ansible exited 0]") && gone, "{text}");
    assert!(target(&format!("ls ch-book-{tag}.txt 2>&1")).contains("No such file"), "check mode changed nothing");

    // Limit to a host the play does not target: nothing runs.
    let mut r = req(&inv, book());
    r.limit = Some("dead1".into());
    let (text, gone) = lab.run(&r, false);
    assert!(gone && !target(&format!("ls ch-book-{tag}.txt 2>&1")).contains(&format!("ch-book-{tag}.txt\n")), "{text}");

    // Ad-hoc raw on lab1.
    let r = req(&inv, Action::AdHoc { pattern: "lab1".into(), module: "raw".into(), args: format!("echo adhoc > ch-adhoc-{tag}.txt") });
    let (text, gone) = lab.run(&r, false);
    assert!(text.contains("[ansible exited 0]") && gone, "{text}");
    assert!(target(&format!("cat ch-adhoc-{tag}.txt")).contains("adhoc"));

    // An unreachable target: Ansible says UNREACHABLE, exit 4, and the folder still goes.
    let r = req(&inv, Action::AdHoc { pattern: "dead1".into(), module: "raw".into(), args: "true".into() });
    let (text, gone) = lab.run(&r, false);
    assert!(text.contains("UNREACHABLE") && text.contains("[ansible exited 4]") && gone, "{text}");

    target(&format!("rm -f ch-*-{tag}.txt"));
}

fn shell_q(s: &str) -> String {
    bastion_core::ansible_run::shell_quote(s)
}
