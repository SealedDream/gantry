//! SSH-CONFIG-SYNC: import an OpenSSH config (with config.d), then sync again. Cases (a)-(h)
//! of the owner's question, using the same call sequence the apps use (scan, changes,
//! apply_refresh, record_snapshot). Test hosts only (*.example.test); no real ~/.ssh is read.
use std::path::Path;

use bastion_core::model::{Connection, Document, Folder, Node};
use bastion_core::sshconfig::SshConfig;
use bastion_core::sshworkflow::*;

fn write(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

const MAIN: &str = "Include config.d/*.conf\n\nHost jump\n  HostName jump.example.test\n  User ops\n";
const ACME: &str = "Host acme-web\n  HostName web.acme.example.test\n  User <user>\n  Port 22\n\nHost acme-db\n  HostName db.acme.example.test\n  User dba\n";
const GLOBEX: &str = "Host globex-app\n  HostName app.globex.example.test\n  User deploy\n";

struct Rig {
    ssh: tempfile::TempDir,
    data: tempfile::TempDir,
    store: WorkflowStore,
    doc: Document,
}

impl Rig {
    fn new() -> Rig {
        let ssh = tempfile::tempdir().unwrap();
        write(ssh.path(), "config", MAIN);
        write(ssh.path(), "config.d/acme.conf", ACME);
        write(ssh.path(), "config.d/globex.conf", GLOBEX);
        let data = tempfile::tempdir().unwrap();
        let store = WorkflowStore::open(data.path().join("ssh-workflow.json")).unwrap();
        Rig { ssh, data, store, doc: Document::new("Library") }
    }

    fn cfg(&self) -> SshConfig {
        self.store.scan(self.ssh.path())
    }

    /// First import of every scanned host (the Import sheet), then take the baseline.
    fn import_all(&mut self) -> u32 {
        let cfg = self.cfg();
        let n = import_hosts(&mut self.doc, &cfg.hosts()).unwrap();
        self.store.record_snapshot(self.ssh.path(), &cfg);
        n
    }

    /// "Sync now": scan, compare, apply, take the new baseline. Returns the preview and summary.
    fn sync(&mut self, import_added: bool) -> (ChangeSet, RefreshSummary) {
        let cfg = self.cfg();
        let ch = self.store.changes(self.ssh.path(), &cfg);
        let sum = apply_refresh(&mut self.doc, &cfg, &ch, import_added).unwrap();
        self.store.record_snapshot(self.ssh.path(), &cfg);
        (ch, sum)
    }

    /// A file edit the mtime check will see, even on a coarse clock.
    fn edit(&self, rel: &str, text: &str) {
        std::thread::sleep(std::time::Duration::from_millis(1100));
        write(self.ssh.path(), rel, text);
    }

    fn conn(&self, name: &str) -> Connection {
        let all: Vec<_> = self.doc.connections().into_iter().filter(|r| r.connection.name == name).collect();
        assert_eq!(all.len(), 1, "exactly one connection named {name}");
        all[0].connection.clone()
    }

    fn set(&mut self, name: &str, f: impl FnOnce(&mut Connection)) {
        fn walk<'a>(folder: &'a mut Folder, name: &str) -> Option<&'a mut Connection> {
            for n in &mut folder.children {
                match n {
                    Node::Folder(sub) => {
                        if let Some(c) = walk(sub, name) {
                            return Some(c);
                        }
                    }
                    Node::Connection(c) if c.name == name => return Some(c),
                    Node::Connection(_) => {}
                }
            }
            None
        }
        f(walk(&mut self.doc.root, name).unwrap());
    }

    /// Names of the folders (any depth) that directly hold `name`.
    fn folder_of(&self, name: &str) -> String {
        fn find(f: &Folder, name: &str) -> Option<String> {
            for n in &f.children {
                match n {
                    Node::Connection(c) if c.name == name => return Some(f.name.clone()),
                    Node::Folder(s) => {
                        if let Some(x) = find(s, name) {
                            return Some(x);
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        find(&self.doc.root, name).unwrap()
    }

    fn identity(&self, alias: &str) -> String {
        self.cfg().hosts().into_iter().find(|h| h.alias == alias).unwrap().identity
    }

    fn snapshot_of_library(&self) -> String {
        serde_json::to_string(&self.doc).unwrap()
    }
}

fn aliases(r: &Rig) -> Vec<String> {
    let mut v: Vec<String> = r.doc.connections().into_iter().map(|c| c.connection.name).collect();
    v.sort();
    v
}

#[test]
fn a_first_import_creates_hosts_in_folders() {
    let mut r = Rig::new();
    assert_eq!(r.import_all(), 4);
    assert_eq!(aliases(&r), ["acme-db", "acme-web", "globex-app", "jump"]);
    assert_eq!(r.conn("acme-web").host, "web.acme.example.test");
    assert_eq!(r.conn("globex-app").settings.username.as_deref(), Some("deploy"));
    assert_ne!(r.folder_of("acme-web"), r.folder_of("globex-app"), "one folder per config.d file");
    assert_eq!(r.folder_of("acme-web"), r.folder_of("acme-db"));
}

#[test]
fn b_reimport_without_change_changes_nothing() {
    let mut r = Rig::new();
    r.import_all();
    let before = r.snapshot_of_library();
    assert!(!r.store.sources_changed(r.ssh.path(), &r.cfg()), "cheap check says unchanged");
    let (ch, sum) = r.sync(true);
    assert!(ch.is_empty(), "no change reported: {ch:?}");
    assert_eq!((sum.added, sum.updated, sum.marked_removed), (0, 0, 0));
    assert_eq!(r.snapshot_of_library(), before, "library is byte-identical");
    // The all-hosts import path (Import sheet used again) also adds nothing.
    let cfg = r.cfg();
    assert_eq!(import_hosts(&mut r.doc, &cfg.hosts()).unwrap(), 0);
    assert_eq!(r.snapshot_of_library(), before);
}

#[test]
fn c_changed_hostname_port_user_updates_only_that_host() {
    let mut r = Rig::new();
    r.import_all();
    let web_id = r.conn("acme-web").id;
    r.edit("config.d/acme.conf", &ACME.replace("web.acme.example.test", "web2.acme.example.test").replace("Port 22", "Port 2222").replace("User <user>", "User alice"));
    let (ch, sum) = r.sync(true);
    assert_eq!(ch.hosts.len(), 1, "only acme-web is reported: {ch:?}");
    assert_eq!((sum.added, sum.updated, sum.marked_removed), (0, 1, 0));
    let w = r.conn("acme-web");
    assert_eq!((w.host.as_str(), w.settings.port, w.settings.username.as_deref()), ("web2.acme.example.test", Some(2222), Some("alice")));
    assert_eq!(w.id, web_id, "same connection, not a new one");
    assert_eq!(r.conn("acme-db").host, "db.acme.example.test");
    assert_eq!(aliases(&r).len(), 4);
}

#[test]
fn d_new_host_in_config_d_is_added() {
    let mut r = Rig::new();
    r.import_all();
    r.edit("config.d/initech.conf", "Host initech-vpn\n  HostName vpn.initech.example.test\n");
    let (ch, sum) = r.sync(true);
    assert_eq!(ch.hosts.len(), 1);
    assert_eq!(sum.added, 1);
    assert_eq!(aliases(&r).len(), 5);
    assert_eq!(r.conn("initech-vpn").host, "vpn.initech.example.test");
    assert_eq!(r.conn("acme-web").host, "web.acme.example.test");
}

#[test]
fn e_removed_host_is_kept_and_flagged_not_deleted() {
    let mut r = Rig::new();
    r.import_all();
    r.edit("config.d/acme.conf", "Host acme-web\n  HostName web.acme.example.test\n  User <user>\n  Port 22\n");
    let (_, sum) = r.sync(true);
    assert_eq!((sum.added, sum.updated, sum.marked_removed), (0, 0, 1));
    assert_eq!(aliases(&r).len(), 4, "nothing deleted");
    assert_eq!(r.conn("acme-db").metadata.get(STATUS_KEY).map(String::as_str), Some(STATUS_REMOVED));
    // A second sync does not keep re-reporting it.
    let (ch, _) = r.sync(true);
    assert!(ch.is_empty());
    assert_eq!(r.conn("acme-db").metadata.get(STATUS_KEY).map(String::as_str), Some(STATUS_REMOVED), "flag stays");
}

#[test]
fn e2_host_that_comes_back_loses_the_removed_flag() {
    let mut r = Rig::new();
    r.import_all();
    r.edit("config.d/acme.conf", "Host acme-web\n  HostName web.acme.example.test\n  User <user>\n  Port 22\n");
    r.sync(true);
    r.edit("config.d/acme.conf", ACME.replace("db.acme.example.test", "db2.acme.example.test").as_str());
    let (_, _) = r.sync(true);
    let d = r.conn("acme-db");
    assert_eq!(aliases(&r).len(), 4, "no duplicate");
    assert_eq!(d.metadata.get(STATUS_KEY), None, "flag cleared when the host is back");
    assert_eq!(d.host, "db2.acme.example.test", "and its values follow the file");
}

#[test]
fn f_user_edits_and_overrides_survive() {
    let mut r = Rig::new();
    r.import_all();
    let id = r.identity("acme-web");
    r.store.set_override(&id, HostOverride { user: Some("alice".into()), port: Some(2200), ..Default::default() }).unwrap();
    r.set("acme-web", |c| {
        c.favorite = true;
        c.tags.push("critical".into());
        c.notes = "on-call".into();
    });
    r.set("globex-app", |c| c.notes = "my note".into());
    r.edit("config.d/acme.conf", &ACME.replace("web.acme", "web3.acme"));
    r.edit("config.d/globex.conf", &GLOBEX.replace("deploy", "deploy2"));
    r.sync(true);
    let w = r.conn("acme-web");
    assert!(w.favorite && w.tags == ["critical"] && w.notes == "on-call");
    assert_eq!(w.host, "web3.acme.example.test");
    assert_eq!(r.conn("globex-app").notes, "my note");
    let e = r.store.effective_for_connection(&w).unwrap();
    assert_eq!((e.user.as_deref(), e.port), (Some("alice"), Some(2200)), "override still wins");
    assert_eq!(r.store.data.hosts[&id].user.as_deref(), Some("alice"));
}

#[test]
fn f2_user_edit_of_a_source_field_on_an_unchanged_host_is_kept() {
    let mut r = Rig::new();
    r.import_all();
    r.set("jump", |c| c.host = "my-own-edit.example.test".into());
    r.edit("config.d/acme.conf", &ACME.replace("web.acme", "web4.acme"));
    r.sync(true);
    assert_eq!(r.conn("jump").host, "my-own-edit.example.test", "host not touched by the file is not rewritten");
}

#[test]
fn g_host_moved_by_the_user_stays_put() {
    let mut r = Rig::new();
    r.import_all();
    let id = r.conn("acme-web").id;
    r.doc.insert(None, Node::Folder(Folder { id: uuid::Uuid::new_v4(), name: "Mine".into(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() })).unwrap();
    let mine = r.doc.root.children.iter().find_map(|n| match n {
        Node::Folder(f) if f.name == "Mine" => Some(f.id),
        _ => None,
    });
    r.doc.move_node(id, mine).unwrap();
    assert_eq!(r.folder_of("acme-web"), "Mine");
    r.edit("config.d/acme.conf", &ACME.replace("web.acme", "web5.acme"));
    r.edit("config.d/initech.conf", "Host initech-vpn\n  HostName vpn.initech.example.test\n");
    r.sync(true);
    assert_eq!(r.folder_of("acme-web"), "Mine", "still in the user's folder");
    assert_eq!(r.conn("acme-web").host, "web5.acme.example.test", "and still updated");
    assert_eq!(aliases(&r).len(), 5, "no duplicate left behind in the old folder");
}

#[test]
fn h_placeholders_and_answers_survive() {
    let mut r = Rig::new();
    r.import_all();
    r.store.set_placeholder("user", "alice").unwrap();
    let id = r.identity("acme-web");
    r.store.set_override(&id, HostOverride { placeholders: [("user".to_string(), "bob".to_string())].into(), ..Default::default() }).unwrap();
    r.edit("config.d/acme.conf", &ACME.replace("web.acme", "web6.acme"));
    r.sync(true);
    r.edit("config.d/globex.conf", &GLOBEX.replace("deploy", "deploy3"));
    r.sync(true);
    assert_eq!(r.store.data.placeholder_values["user"], "alice");
    let w = r.conn("acme-web");
    assert_eq!(w.settings.username.as_deref(), Some("<user>"), "the source keeps the literal placeholder");
    let e = r.store.effective_for_connection(&w).unwrap();
    assert_eq!(e.user.as_deref(), Some("bob"), "per-host answer wins");
    assert!(e.unresolved.is_empty());
    // Saved answers also survive a restart of the store.
    r.store.save().unwrap();
    let again = WorkflowStore::open(r.data.path().join("ssh-workflow.json")).unwrap();
    assert_eq!(again.data.placeholder_values["user"], "alice");
    assert_eq!(again.data.hosts[&id].placeholders["user"], "bob");
}
