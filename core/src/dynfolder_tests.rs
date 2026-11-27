//! B15 acceptance tests (core part). Numbers refer to the review's acceptance list.
use std::sync::atomic::AtomicBool;

use uuid::Uuid;

use super::*;
use crate::model::{Document, Folder, Node};
use crate::policy::Policy;
use crate::tasks::{RunOn, TaskDef, TaskKind};

fn on() -> Policy {
    Policy { dynamic_folders_enabled: true, ..Policy::default() }
}

/// A full path to a program that exists here: `/bin/cat` on Unix (the Unix-only tests run it), the test binary
/// itself elsewhere (Windows has no `/bin/cat`, and `/bin/cat` is not a full path there).
fn prog() -> String {
    if cfg!(unix) {
        "/bin/cat".into()
    } else {
        std::env::current_exe().unwrap().to_string_lossy().into_owned()
    }
}

fn task(program: &str, args: &[&str]) -> TaskDef {
    TaskDef {
        id: Uuid::new_v4(),
        name: "Inventory".into(),
        favorite: false,
        kind: TaskKind::Custom { program: program.into(), args: args.iter().map(|s| s.to_string()).collect(), run_on: RunOn::Local },
        timeout_secs: 30,
    }
}

/// A document with one dynamic folder fed by `t`.
fn doc_with(t: TaskDef) -> (Document, Uuid) {
    let mut doc = Document::new("Lib");
    let folder = Folder { id: Uuid::new_v4(), name: "Cloud".into(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() };
    let fid = folder.id;
    doc.root.children.push(Node::Folder(folder));
    doc.tasks.push(t.clone());
    set_task(&mut doc, fid, Some(t.id), &on()).unwrap();
    (doc, fid)
}

#[cfg(unix)]
fn script(dir: &std::path::Path, body: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(format!("s{}.sh", Uuid::new_v4().simple()));
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    p.to_string_lossy().into_owned()
}

const THREE: &str = r#"{"Objects":[
 {"Type":"TerminalConnection","Name":"web1","ComputerName":"10.0.0.1","Username":"ops","CredentialName":"ops-key"},
 {"Type":"RemoteDesktopConnection","Name":"dc1","ComputerName":"dc1.lan"},
 {"Type":"Folder","Name":"Sub","Objects":[{"Type":"VNCConnection","Name":"kvm","ComputerName":"kvm.lan","Port":5901}]}]}"#;

#[cfg(unix)]
#[test]
fn acc1_three_items_and_refresh_replaces() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.json");
    std::fs::write(&out, THREE).unwrap();
    let t = task(&prog(), &[out.to_str().unwrap()]);
    let (doc, fid) = doc_with(t.clone());
    crate::tasktrust::trust(dir.path(), doc.id, &t).unwrap();
    let r = refresh(&doc, fid, &on(), dir.path(), &AtomicBool::new(false)).unwrap();
    assert_eq!(r.error, None);
    assert_eq!(r.items.len(), 3);
    assert_eq!(r.items[0].connection.settings.credential_name, None, "the script cannot pick a vault credential");
    assert!(r.skipped.iter().any(|s| s.contains("web1: credential name ignored")));
    assert_eq!(r.items[2].path, vec!["Sub".to_string()]);
    let again = refresh(&doc, fid, &on(), dir.path(), &AtomicBool::new(false)).unwrap();
    assert_eq!(again.items.len(), 3);
    assert_ne!(again.items[0].connection.id, r.items[0].connection.id, "each refresh is a fresh set");
    assert!(doc.folder(fid).unwrap().children.is_empty(), "nothing is written into the document");
}

#[cfg(unix)]
#[test]
fn acc2_untrusted_runs_nothing_and_any_change_drops_trust() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let prog = script(dir.path(), &format!("touch '{}'; echo '{{\"Objects\":[]}}'", marker.display()));
    let t = task(&prog, &["a"]);
    let (mut doc, fid) = doc_with(t.clone());
    let err = refresh(&doc, fid, &on(), dir.path(), &AtomicBool::new(false)).unwrap_err();
    assert!(err.to_string().contains("not trusted"));
    assert!(!marker.exists(), "nothing ran");
    crate::tasktrust::trust(dir.path(), doc.id, &t).unwrap();
    refresh(&doc, fid, &on(), dir.path(), &AtomicBool::new(false)).unwrap();
    assert!(marker.exists());
    std::fs::remove_file(&marker).unwrap();
    if let TaskKind::Custom { args, .. } = &mut doc.tasks[0].kind {
        args[0] = "b".into();
    }
    assert!(refresh(&doc, fid, &on(), dir.path(), &AtomicBool::new(false)).is_err());
    assert!(!marker.exists(), "a changed argument runs nothing");
    assert!(!review(&doc, fid, &crate::tasktrust::load(dir.path())).unwrap().trusted);
}

#[test]
fn acc3_policy_off_or_forbidden_refuses() {
    let t = task(&prog(), &[]);
    let (mut doc, fid) = doc_with(t.clone());
    let dir = tempfile::tempdir().unwrap();
    assert!(!enabled(&Policy::default()), "off by default");
    assert!(refresh(&doc, fid, &Policy::default(), dir.path(), &AtomicBool::new(false)).is_err());
    let managed = Policy { forbid_dynamic_folders: true, ..Policy::default() };
    let eff = on().with_managed(&managed);
    assert!(!enabled(&eff), "a managed ban wins over the user's switch");
    assert!(matches!(refresh(&doc, fid, &eff, dir.path(), &AtomicBool::new(false)), Err(CoreError::PolicyDenied(_))));
    assert!(set_task(&mut doc, fid, Some(t.id), &eff).is_err());
    set_task(&mut doc, fid, None, &eff).expect("clearing is always allowed");
}

#[cfg(unix)]
#[test]
fn acc4_runaway_output_and_endless_run_are_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let big = script(dir.path(), "head -c 104857600 /dev/zero");
    let t = task(&big, &[]);
    let (doc, fid) = doc_with(t.clone());
    crate::tasktrust::trust(dir.path(), doc.id, &t).unwrap();
    let r = refresh(&doc, fid, &on(), dir.path(), &AtomicBool::new(false)).unwrap();
    assert!(r.stdout_bytes <= crate::tasks::MAX_OUTPUT + 64);
    assert!(r.items.is_empty() && r.error.is_some());

    let mut forever = task(&script(dir.path(), "sleep 600"), &[]);
    forever.timeout_secs = 1;
    let (doc, fid) = doc_with(forever.clone());
    crate::tasktrust::trust(dir.path(), doc.id, &forever).unwrap();
    let t0 = std::time::Instant::now();
    let r = refresh(&doc, fid, &on(), dir.path(), &AtomicBool::new(false)).unwrap();
    assert!(r.timed_out && t0.elapsed().as_secs() < 10);
    let cancel = AtomicBool::new(true);
    let r = refresh(&doc, fid, &on(), dir.path(), &cancel).unwrap();
    assert!(r.cancelled);
}

#[test]
fn timeout_is_capped_at_300s() {
    let mut t = task(&prog(), &[]);
    t.timeout_secs = 3600;
    let (doc, fid) = doc_with(t.clone());
    let dir = tempfile::tempdir().unwrap();
    crate::tasktrust::trust(dir.path(), doc.id, &t).unwrap();
    let p = plan(&doc, fid, &on(), &crate::tasktrust::load(dir.path())).unwrap();
    assert_eq!(p.timeout.as_secs(), u64::from(MAX_REFRESH_SECS));
}

#[test]
fn acc5_ineligible_tasks_are_refused() {
    assert!(eligible(&task("cat", &[])).is_err(), "relative path");
    assert!(eligible(&task(&prog(), &["$Host$"])).is_err(), "token");
    assert!(eligible(&task(&format!("{}.missing", prog()), &[])).is_err(), "missing");
    assert!(eligible(&crate::tasks::builtins().remove(0)).is_err(), "built-in");
    let mut ssh = task(&prog(), &[]);
    ssh.kind = TaskKind::Custom { program: prog(), args: vec![], run_on: RunOn::Ssh };
    assert!(eligible(&ssh).is_err(), "ssh");
    assert!(eligible(&task(&prog(), &["one $ sign is fine"])).is_ok());
    let mut doc = Document::new("x");
    let root = doc.root.id;
    assert!(set_task(&mut doc, root, None, &on()).is_err(), "root is never dynamic");
}

#[test]
fn acc6_hostile_output_is_cleaned() {
    let json = r#"{"Objects":[{"Type":"TerminalConnection","Name":"a\u0007b","ComputerName":"h\u001b[31m","Password":"p","PrivateKey":"k","ApiToken":"t","Notes":"line1\nline2\u0000"}]}"#;
    let (items, skipped) = parse(json).unwrap();
    assert_eq!(items[0].connection.name, "ab");
    assert_eq!(items[0].connection.host, "h[31m");
    assert_eq!(items[0].connection.notes, "line1\nline2");
    let all = skipped.join("|");
    assert!(all.contains("PrivateKey") && all.contains("ApiToken") && all.contains("password"));
    assert!(!all.contains("\"p\"") && !all.contains(": k") && !all.contains(": t"), "values never listed");

    let mut deep = String::from(r#"{"Type":"TerminalConnection","Name":"x","ComputerName":"h"}"#);
    for _ in 0..40 {
        deep = format!(r#"{{"Type":"Folder","Name":"f","Objects":[{deep}]}}"#);
    }
    assert!(parse(&format!(r#"{{"Objects":[{deep}]}}"#)).is_err(), "depth 40 refused");

    let many: Vec<String> = (0..10_000).map(|i| format!(r#"{{"Type":"TerminalConnection","Name":"n{i}","ComputerName":"h"}}"#)).collect();
    let (items, skipped) = parse(&format!(r#"{{"Objects":[{}]}}"#, many.join(","))).unwrap();
    assert_eq!(items.len(), MAX_ITEMS);
    assert!(skipped.iter().any(|s| s.contains("5000 items over")));

    let long = "x".repeat(10_000);
    let (items, _) = parse(&format!(r#"{{"Objects":[{{"Type":"TerminalConnection","Name":"{long}","ComputerName":"h","Notes":"{long}"}},{{"Type":"TerminalConnection","Name":"far","ComputerName":"{long}"}}]}}"#)).unwrap();
    assert_eq!(items.len(), 1, "a host over 253 characters is refused, not cut");
    let c = &items[0].connection;
    assert_eq!(c.name.chars().count(), MAX_NAME_CHARS);
    assert!(c.notes.len() <= MAX_NOTES_BYTES);
    assert!(c.metadata.is_empty());
}

#[test]
fn acc7_export_strips_binding_and_make_permanent_adds() {
    let t = task(&prog(), &[]);
    let (mut doc, fid) = doc_with(t);
    let (exported, _) = crate::export::prepare(&doc, &crate::export::Selection::All);
    assert!(exported.folder(fid).is_none_or(|f| f.dynamic_task_id.is_none()));
    let saved = serde_json::to_string(&doc).unwrap();
    assert!(saved.contains("dynamic_task_id"), "the library itself keeps the binding");
    let (items, _) = parse(THREE).unwrap();
    assert_eq!(make_permanent(&mut doc, fid, &items).unwrap(), 3);
    let f = doc.folder(fid).unwrap();
    assert_eq!(f.children.len(), 3, "two connections and the Sub folder");
    let back: Document = serde_json::from_str(&serde_json::to_string(&doc).unwrap()).unwrap();
    assert_eq!(back.folder(fid).unwrap().dynamic_task_id, doc.folder(fid).unwrap().dynamic_task_id);
}

#[test]
fn acc8_audit_details_hold_no_output_or_args() {
    let t = task(&prog(), &["secret-arg"]);
    let p = Plan { task: t.clone(), program: prog(), args: vec!["secret-arg".into()], timeout: std::time::Duration::from_secs(1) };
    let (items, skipped) = parse(THREE).unwrap();
    let r = DynResult { items, skipped, exit: Some(0), stdout_bytes: THREE.len(), ..Default::default() };
    let d = audit_details(&p, &r);
    let all = format!("{d:?}");
    assert!(!all.contains("secret-arg") && !all.contains("web1"));
    assert_eq!(d["items"], "3");
    assert_eq!(d["exit"], "0");
    assert!(trust_audit_details(Uuid::nil(), &t).contains_key("program"));
}

#[test]
fn acc9_imports_never_set_a_binding() {
    let t = task(&prog(), &[]);
    let (src, _) = doc_with(t);
    let mut target = Document::new("Mine");
    let mut incoming = src.root.clone();
    incoming.name = "Imported".into();
    crate::import::merge_import(&mut target, incoming);
    fn any_bound(f: &Folder) -> bool {
        f.dynamic_task_id.is_some() || f.children.iter().any(|n| matches!(n, Node::Folder(s) if any_bound(s)))
    }
    assert!(!any_bound(&target.root));
    assert!(!any_bound(&crate::import::into_folder("x", crate::import::royal_json(THREE).unwrap().found)));
}

#[cfg(unix)]
#[test]
fn acc10_network_failure_shows_an_error_line() {
    let dir = tempfile::tempdir().unwrap();
    let prog = script(dir.path(), "echo 'cannot reach api.example: network is unreachable' >&2; exit 7");
    let t = task(&prog, &[]);
    let (doc, fid) = doc_with(t.clone());
    crate::tasktrust::trust(dir.path(), doc.id, &t).unwrap();
    let r = refresh(&doc, fid, &on(), dir.path(), &AtomicBool::new(false)).unwrap();
    assert_eq!(r.exit, Some(7));
    assert!(r.error.unwrap().contains("network is unreachable"));
    assert!(r.items.is_empty());
}

#[test]
fn review_fixes_hosts_free_text_and_unc() {
    let json = r#"{"Objects":[
      {"Type":"TerminalConnection","Name":"opt","ComputerName":"-oProxyCommand=x"},
      {"Type":"TerminalConnection","Name":"sp","ComputerName":"a b"},
      {"Type":"TerminalConnection","Name":"file","ComputerName":"file:///etc/passwd"},
      {"Type":"TerminalConnection","Name":"ok","ComputerName":"ok.lan","Username":"token=abc","Tags":"prod,secret=1","Notes":"rack 4\npassword: hunter2\nowner ops"}]}"#;
    let (items, skipped) = parse(json).unwrap();
    assert_eq!(items.len(), 1);
    let c = &items[0].connection;
    assert_eq!(c.host, "ok.lan");
    assert_eq!(c.settings.username, None);
    assert_eq!(c.tags, vec!["prod".to_string()]);
    assert_eq!(c.notes, "rack 4\nowner ops");
    let all = skipped.join("|");
    assert!(all.contains("opt: computer name refused") && all.contains("sp: computer name refused") && all.contains("file: computer name refused"));
    assert!(!all.contains("hunter2") && !all.contains("abc"));
    assert!(eligible(&task("\\\\server\\share\\x.exe", &[])).is_err());
    assert!(eligible(&task("//server/share/x", &[])).is_err());
}

#[test]
fn trust_needs_policy_and_the_reviewed_hash() {
    let t = task(&prog(), &["a"]);
    let (mut doc, fid) = doc_with(t);
    let dir = tempfile::tempdir().unwrap();
    let r = review(&doc, fid, &[]).unwrap();
    assert_eq!(r.sha256.len(), 64);
    assert!(trust(&doc, fid, &Policy::default(), dir.path(), &r.sha256).is_err(), "feature off");
    if let TaskKind::Custom { args, .. } = &mut doc.tasks[0].kind {
        args[0] = "changed".into();
    }
    assert!(trust(&doc, fid, &on(), dir.path(), &r.sha256).is_err(), "changed after review");
    let r2 = review(&doc, fid, &[]).unwrap();
    trust(&doc, fid, &on(), dir.path(), &r2.sha256).unwrap();
    assert!(review(&doc, fid, &crate::tasktrust::load(dir.path())).unwrap().trusted);
}

#[cfg(unix)]
#[test]
fn world_writable_folder_is_warned() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let prog = script(dir.path(), "true");
    let (doc, fid) = doc_with(task(&prog, &[]));
    assert!(review(&doc, fid, &[]).unwrap().warnings.iter().any(|w| w.contains("other users")));
}
