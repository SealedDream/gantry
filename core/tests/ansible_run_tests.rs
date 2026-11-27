//! Ansible run argv: every accepted field lands as one argv element, nothing can become an option.
use std::path::PathBuf;

use bastion_core::ansible_run::{argv, warnings, Action, RunRequest};

fn files() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let inv = d.path().join("inventory.ini");
    let pb = d.path().join("site.yml");
    std::fs::write(&inv, "[bastion]\nweb1 ansible_host=10.0.0.1\n").unwrap();
    std::fs::write(&pb, "- hosts: all\n  tasks: []\n").unwrap();
    (d, inv, pb)
}

fn adhoc(inv: &PathBuf, pattern: &str, module: &str, args: &str) -> RunRequest {
    RunRequest {
        action: Action::AdHoc { pattern: pattern.into(), module: module.into(), args: args.into() },
        inventory: inv.clone(),
        limit: None,
        check: false,
        diff: false,
        become_root: false,
        forks: None,
        verbosity: 0, tags: None, extra_vars: None,
    }
}

#[test]
fn ad_hoc_and_playbook_argv() {
    let (_d, inv, pb) = files();
    let inv_s = inv.to_str().unwrap().to_string();
    assert_eq!(argv(&adhoc(&inv, "bastion", "ping", "")).unwrap(), ["ansible", "bastion", "-i", &inv_s, "-m", "ping"]);
    let with_args = argv(&adhoc(&inv, "web*:!db1", "ansible.builtin.shell", "uptime; echo $HOME")).unwrap();
    assert_eq!(with_args[6..], ["-a".to_string(), "uptime; echo $HOME".to_string()], "args stay one element, unparsed");

    let req = RunRequest {
        action: Action::Playbook { path: pb.clone() },
        limit: Some("web1".into()),
        check: true,
        diff: true,
        become_root: true,
        forks: Some(10),
        verbosity: 2, tags: None, extra_vars: None,
        ..adhoc(&inv, "x", "ping", "")
    };
    assert_eq!(
        argv(&req).unwrap(),
        ["ansible-playbook", "-i", &inv_s, pb.to_str().unwrap(), "--limit", "web1", "--check", "--diff", "--become", "--forks", "10", "-vv"]
    );
    assert!(warnings(&req).is_empty(), "become under --check is only a preview");
}

#[test]
fn nothing_becomes_an_option_or_reaches_a_missing_file() {
    let (d, inv, pb) = files();
    for pattern in ["", "-i", "--become", "web 1", "web;rm", "a\nb", &"x".repeat(257)] {
        assert!(argv(&adhoc(&inv, pattern, "ping", "")).is_err(), "pattern {pattern:?}");
    }
    for module in ["", "-a", "ping x", "1ping", "a..b", "a/b"] {
        assert!(argv(&adhoc(&inv, "all", module, "")).is_err(), "module {module:?}");
    }
    assert!(argv(&adhoc(&inv, "all", "ping", "a\nb")).is_err(), "multi-line args");
    assert!(argv(&adhoc(&inv, "all", "ping", &"x".repeat(8 * 1024 + 1))).is_err());
    assert!(argv(&adhoc(&d.path().join("missing.ini"), "all", "ping", "")).is_err());
    assert!(argv(&adhoc(&PathBuf::from("inventory.ini"), "all", "ping", "")).is_err(), "relative inventory");
    let mut r = adhoc(&inv, "all", "ping", "");
    r.limit = Some("-e".into());
    assert!(argv(&r).is_err());
    r.limit = None;
    r.forks = Some(0);
    assert!(argv(&r).is_err());
    r.forks = Some(101);
    assert!(argv(&r).is_err());
    r.forks = None;
    r.verbosity = 5;
    assert!(argv(&r).is_err());
    let txt = d.path().join("site.txt");
    std::fs::write(&txt, "x").unwrap();
    for path in [txt, d.path().join("gone.yml"), d.path().to_path_buf()] {
        let req = RunRequest { action: Action::Playbook { path: path.clone() }, ..adhoc(&inv, "all", "ping", "") };
        assert!(argv(&req).is_err(), "playbook {path:?}");
    }
    let _ = pb;
}

#[test]
fn risky_runs_are_pointed_out() {
    let (_d, inv, _pb) = files();
    assert_eq!(warnings(&adhoc(&inv, "all", "shell", "id")).len(), 1);
    assert!(warnings(&adhoc(&inv, "all", "ping", "")).is_empty());
    let mut r = adhoc(&inv, "all", "ansible.builtin.raw", "id");
    r.become_root = true;
    assert_eq!(warnings(&r).len(), 2);
}

/// Live: `BASTION_ANSIBLE_LIVE=1 cargo test --test ansible_run_tests live` with Ansible on PATH.
/// Runs the generated argv directly (no shell) against a local-connection inventory.
#[test]
fn live_ad_hoc_and_playbook_run() {
    if std::env::var("BASTION_ANSIBLE_LIVE").is_err() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let inv = d.path().join("inventory.ini");
    std::fs::write(&inv, "[bastion]\nlocal1 ansible_connection=local\n").unwrap();
    let pb = d.path().join("site.yml");
    std::fs::write(&pb, "- hosts: bastion\n  gather_facts: false\n  tasks:\n    - ansible.builtin.debug:\n        msg: bastion-playbook-ok\n").unwrap();
    let run = |args: Vec<String>| {
        let out = std::process::Command::new(&args[0]).args(&args[1..]).env("ANSIBLE_NOCOLOR", "1").output().expect("start ansible");
        (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let (ok, out) = run(argv(&adhoc(&inv, "bastion", "ping", "")).unwrap());
    assert!(ok && out.contains("\"ping\": \"pong\""), "{out}");
    let (ok, out) = run(argv(&adhoc(&inv, "local1", "ansible.builtin.command", "echo hello-$HOME")).unwrap());
    assert!(ok && out.contains("hello-"), "{out}");
    let req = RunRequest { action: Action::Playbook { path: pb }, check: true, ..adhoc(&inv, "x", "ping", "") };
    let (ok, out) = run(argv(&req).unwrap());
    assert!(ok && out.contains("bastion-playbook-ok"), "{out}");
}
