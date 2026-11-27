//! Optional shared-config workflow, tested with fixture trees (no real ~/.ssh is read).
use std::collections::BTreeMap;
use std::path::Path;

use bastion_core::model::{Connection, Document, Node, Protocol};
use bastion_core::sshconfig::{Discovery, Limits, SshConfig};
use bastion_core::sshworkflow::*;

fn write(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// A team layout: a main config including one customer file, plus a config.d file that is not
/// included (only found by the optional scan).
fn team_tree() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "config", "Include config.d/acme\n\nHost personal\n  HostName pc.home\n");
    write(d.path(), "config.d/acme", "Host acme-web\n  HostName web.acme.example\n  User <user>\n  IdentityFile ~/.ssh/<key>\n\nHost acme-db\n  HostName db.acme.example\n  User <user>\n  ProxyJump acme-web\n");
    write(d.path(), "config.d/globex", "Host globex-app\n  HostName app.globex.example\n  User deploy\n");
    d
}

fn store(dir: &tempfile::TempDir) -> WorkflowStore {
    WorkflowStore::open(dir.path().join("ssh-workflow.json")).unwrap()
}

fn host<'a>(cfg: &'a [bastion_core::sshconfig::ResolvedHost], alias: &str) -> &'a bastion_core::sshconfig::ResolvedHost {
    cfg.iter().find(|h| h.alias == alias).unwrap()
}

/// Every file under `root` with its bytes and mtime.
fn fingerprint_tree(root: &Path) -> BTreeMap<String, (Vec<u8>, std::time::SystemTime)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let m = std::fs::metadata(&p).unwrap();
                out.insert(p.strip_prefix(root).unwrap().display().to_string(), (std::fs::read(&p).unwrap(), m.modified().unwrap()));
            }
        }
    }
    out
}

#[test]
fn config_d_scan_is_optional_but_includes_are_always_followed() {
    let t = team_tree();
    let off = SshConfig::discover_opts(t.path(), &Discovery { scan_config_d: false, ..Default::default() }, &Limits::default());
    let aliases: Vec<String> = off.hosts().into_iter().map(|h| h.alias).collect();
    assert!(aliases.contains(&"acme-web".to_string()), "included file is read: {aliases:?}");
    assert!(!aliases.contains(&"globex-app".to_string()), "unincluded config.d file is not scanned: {aliases:?}");

    let on = SshConfig::discover_opts(t.path(), &Discovery { scan_config_d: true, ..Default::default() }, &Limits::default());
    let g = on.hosts().into_iter().find(|h| h.alias == "globex-app").unwrap();
    assert_eq!(g.group, "globex", "customer group comes from the file name");
}

#[test]
fn no_ssh_dir_at_all_is_fine() {
    let empty = tempfile::tempdir().unwrap();
    let missing = empty.path().join("no-such-dir");
    let cfg = SshConfig::discover_opts(&missing, &Discovery { scan_config_d: true, ..Default::default() }, &Limits::default());
    assert!(cfg.hosts().is_empty());
}

#[test]
fn placeholders_are_detected_and_resolved_without_touching_files() {
    let t = team_tree();
    let data = tempfile::tempdir().unwrap();
    let before = fingerprint_tree(t.path());
    let mut s = store(&data);
    let hosts = s.scan(t.path()).hosts();
    let web = host(&hosts, "acme-web");
    assert_eq!(host_placeholders(web).into_iter().collect::<Vec<_>>(), vec!["key", "user"]);
    assert_eq!(find_placeholders("%h ${HOME} <not a name> plain"), Vec::<String>::new(), "OpenSSH tokens are not placeholders");

    let e = s.effective(web);
    assert!(!e.ready());
    assert_eq!(e.unresolved, vec!["key", "user"]);

    s.set_placeholder("user", "alice").unwrap();
    let mut o = HostOverride::default();
    o.placeholders.insert("key".into(), "id_acme".into());
    s.set_override(&web.identity, o).unwrap();
    let e = s.effective(web);
    assert!(e.ready(), "{e:?}");
    assert_eq!(e.user.as_deref(), Some("alice"));
    assert_eq!(e.identity_file.as_deref(), Some("~/.ssh/id_acme"));
    // Per-host answers win over global ones.
    let db = host(&hosts, "acme-db");
    let mut o = HostOverride::default();
    o.placeholders.insert("user".into(), "dba".into());
    s.set_override(&db.identity, o).unwrap();
    assert_eq!(s.effective(db).user.as_deref(), Some("dba"));

    s.save().unwrap();
    assert_eq!(fingerprint_tree(t.path()), before, "source files must be byte- and mtime-identical");
    let reopened = store(&data);
    assert_eq!(reopened.data.placeholder_values.get("user").map(String::as_str), Some("alice"));
}

#[test]
fn unsafe_values_are_rejected() {
    let data = tempfile::tempdir().unwrap();
    let mut s = store(&data);
    for bad in ["", "-oProxyCommand=x", "a b", "a\nb", "<user>", &"x".repeat(300)] {
        assert!(s.set_placeholder("user", bad).is_err(), "accepted {bad:?}");
    }
    assert!(s.set_placeholder("bad name", "x").is_err());
    let o = HostOverride { port: Some(0), ..Default::default() };
    assert!(s.set_override("id", o).is_err());
    let o = HostOverride { user: Some("ok\u{7}".into()), ..Default::default() };
    assert!(s.set_override("id", o).is_err());
}

#[test]
fn each_switch_works_independently() {
    let t = team_tree();
    let data = tempfile::tempdir().unwrap();
    let mut s = store(&data);
    let hosts = s.scan(t.path()).hosts();
    let web = host(&hosts, "acme-web");
    s.set_placeholder("user", "alice").unwrap();
    s.set_override(&web.identity, HostOverride { port: Some(2200), hostname: Some("10.0.0.5".into()), credential_ref: Some("keychain:acme".into()), ..Default::default() }).unwrap();

    s.data.settings.overrides = false;
    let e = s.effective(web);
    assert_eq!((e.port, e.hostname.as_str(), e.user.as_deref()), (None, "web.acme.example", Some("alice")), "placeholders still apply");
    assert_eq!(e.credential_ref, None);

    s.data.settings.overrides = true;
    s.data.settings.placeholders = false;
    let e = s.effective(web);
    assert_eq!((e.port, e.hostname.as_str()), (Some(2200), "10.0.0.5"));
    assert_eq!(e.user.as_deref(), Some("<user>"));
    assert!(e.unresolved.contains(&"user".to_string()), "a literal placeholder never reaches a connect");
    assert_eq!(e.credential_ref.as_deref(), Some("keychain:acme"));
}

#[test]
fn change_detection_after_a_manual_pull_preserves_personal_data() {
    let t = team_tree();
    let data = tempfile::tempdir().unwrap();
    let mut s = store(&data);
    let cfg = s.scan(t.path());

    // First import: everything is new.
    let first = s.changes(t.path(), &cfg);
    assert!(first.hosts.iter().all(|c| c.kind == ChangeKind::Added));
    let mut doc = Document::new("Library");
    doc.insert(None, Node::Connection(Connection::new("manual-box", Protocol::Ssh, "10.1.1.1"))).unwrap();
    let sum = apply_refresh(&mut doc, &cfg, &first, true).unwrap();
    assert_eq!(sum.added, 4);
    s.record_snapshot(t.path(), &cfg);
    assert!(!s.sources_changed(t.path(), &cfg));

    // Personal state the refresh must keep.
    let web_id = host(&cfg.hosts(), "acme-web").identity.clone();
    s.set_override(&web_id, HostOverride { user: Some("alice".into()), ..Default::default() }).unwrap();
    set_conn(&mut doc, "acme-web", |c| {
        c.favorite = true;
        c.tags.push("critical".into());
        c.notes = "on-call".into();
    });

    // Simulated `git pull`: one host changed, one removed, one new file.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    write(t.path(), "config.d/acme", "Host acme-web\n  HostName web2.acme.example\n  User <user>\n  Port 2222\n  IdentityFile ~/.ssh/<key>\n");
    write(t.path(), "config.d/initech", "Host initech-vpn\n  HostName vpn.initech.example\n");
    let cfg2 = s.scan(t.path());
    assert!(s.sources_changed(t.path(), &cfg2));
    let ch = s.changes(t.path(), &cfg2);
    let kind = |a: &str| ch.hosts.iter().find(|c| c.alias == a).map(|c| c.kind);
    assert_eq!(kind("acme-web"), Some(ChangeKind::Changed));
    assert_eq!(kind("acme-db"), Some(ChangeKind::Removed));
    assert_eq!(kind("initech-vpn"), Some(ChangeKind::Added));
    assert_eq!(kind("globex-app"), None, "unchanged hosts are not reported");
    let web = ch.hosts.iter().find(|c| c.alias == "acme-web").unwrap();
    let f: BTreeMap<&str, (Option<&str>, Option<&str>)> = web.fields.iter().map(|f| (f.field.as_str(), (f.old.as_deref(), f.new.as_deref()))).collect();
    assert_eq!(f["HostName"], (Some("web.acme.example"), Some("web2.acme.example")));
    assert_eq!(f["Port"], (None, Some("2222")));
    assert!(ch.files.contains(&"config.d/acme".to_string()) && ch.files.contains(&"config.d/initech".to_string()));

    // Preview first: applying without new hosts.
    let sum = apply_refresh(&mut doc, &cfg2, &ch, false).unwrap();
    assert_eq!((sum.added, sum.updated, sum.marked_removed), (0, 1, 1));
    let web_conn = conn(&doc, "acme-web");
    assert_eq!((web_conn.host.as_str(), web_conn.settings.port), ("web2.acme.example", Some(2222)));
    assert!(web_conn.favorite && web_conn.tags == ["critical"] && web_conn.notes == "on-call");
    assert_eq!(conn(&doc, "acme-db").metadata.get(STATUS_KEY).map(String::as_str), Some(STATUS_REMOVED), "removed hosts are kept and marked");
    assert_eq!(conn(&doc, "manual-box").host, "10.1.1.1", "manual connections are untouched");
    assert_eq!(s.data.hosts[&web_id].user.as_deref(), Some("alice"), "overrides survive (same identity)");
    s.record_snapshot(t.path(), &cfg2);
    assert!(s.changes(t.path(), &cfg2).is_empty());
}

#[test]
fn without_change_detection_there_is_no_baseline() {
    let t = team_tree();
    let data = tempfile::tempdir().unwrap();
    let mut s = store(&data);
    s.data.settings.change_detection = false;
    let cfg = s.scan(t.path());
    s.record_snapshot(t.path(), &cfg);
    assert!(s.data.snapshot.is_none());
    assert!(s.changes(t.path(), &cfg).hosts.iter().all(|c| c.kind == ChangeKind::Added));
}

#[test]
fn corrupt_or_future_store_is_an_error_not_a_reset() {
    let data = tempfile::tempdir().unwrap();
    let p = data.path().join("ssh-workflow.json");
    std::fs::write(&p, "{not json").unwrap();
    assert!(WorkflowStore::open(&p).is_err());
    std::fs::write(&p, r#"{"version": 99}"#).unwrap();
    assert!(WorkflowStore::open(&p).is_err());
}

fn conn(doc: &Document, name: &str) -> Connection {
    doc.connections().into_iter().find(|r| r.connection.name == name).unwrap().connection
}

fn set_conn(doc: &mut Document, name: &str, f: impl FnOnce(&mut Connection)) {
    fn walk<'a>(folder: &'a mut bastion_core::model::Folder, name: &str) -> Option<&'a mut Connection> {
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
    f(walk(&mut doc.root, name).unwrap());
}

#[test]
fn imported_connection_resolves_like_the_source_host() {
    let t = team_tree();
    let data = tempfile::tempdir().unwrap();
    let mut s = store(&data);
    let hosts = s.scan(t.path()).hosts();
    let web = host(&hosts, "acme-web");
    s.set_placeholder("user", "alice").unwrap();
    s.set_placeholder("key", "id_acme").unwrap();
    s.set_override(&web.identity, HostOverride { port: Some(2200), ..Default::default() }).unwrap();
    let from_conn = s.effective_for_connection(&web.to_connection()).unwrap();
    assert_eq!(from_conn, s.effective(web));
    assert_eq!(from_conn.port, Some(2200));
    assert!(s.effective_for_connection(&Connection::new("manual", Protocol::Ssh, "h")).is_none(), "manual connections are not managed");
}

#[test]
fn jump_specs_parse() {
    assert_eq!(bastion_core::sshworkflow::parse_jump("bastion").unwrap(), (None, "bastion".into(), None));
    assert_eq!(bastion_core::sshworkflow::parse_jump("ops@10.0.0.1:2200").unwrap(), (Some("ops".into()), "10.0.0.1".into(), Some(2200)));
    assert_eq!(bastion_core::sshworkflow::parse_jump("ssh://a@[::1]:22").unwrap(), (Some("a".into()), "::1".into(), Some(22)));
    for bad in ["", "h:0", "h:x", "-oProxyCommand=x", "[::1", "a b"] {
        assert!(bastion_core::sshworkflow::parse_jump(bad).is_err(), "{bad}");
    }
}

/// THREAT_MODEL T16: a ProxyCommand is kept for display and never run; the host is refused
/// instead of reached directly, until a ProxyJump override replaces the command.
#[test]
fn proxy_command_hosts_are_refused_until_a_proxy_jump_replaces_them() {
    let t = tempfile::tempdir().unwrap();
    write(t.path(), "config", "Host gw\n  HostName gw.example\n\nHost inner\n  HostName 10.9.9.9\n  User ops\n  ProxyCommand ssh -W %h:%p gw ; touch /tmp/pwned\n");
    let data = tempfile::tempdir().unwrap();
    let mut s = store(&data);
    let hosts = s.scan(t.path()).hosts();
    let mut doc = Document::new("Library");
    import_hosts(&mut doc, &hosts).unwrap();
    let imported = imported_by_alias(&doc);
    let mut conn = imported["inner"].clone();
    assert_eq!(conn.metadata.get("ProxyCommand").map(String::as_str), Some("ssh -W %h:%p gw ; touch /tmp/pwned"), "kept byte for byte");
    let mut user = String::new();
    let Err(err) = prepare_connection(&s, &imported, &mut conn.clone(), &mut user) else { panic!("a ProxyCommand host was let through") };
    let err = err.to_string();
    assert!(err.contains("ssh -W %h:%p gw ; touch /tmp/pwned") && err.contains("does not run"), "{err}");

    let inner = host(&hosts, "inner");
    s.set_override(&inner.identity, HostOverride { proxy_jump: Some("gw".into()), ..Default::default() }).unwrap();
    let jumps = prepare_connection(&s, &imported, &mut conn, &mut user).unwrap();
    assert_eq!(jumps.len(), 1, "the ProxyJump override is used instead");
    assert_eq!(conn.host, "10.9.9.9");
}

#[test]
fn algorithm_and_session_directives_are_imported() {
    let cfg = SshConfig::parse_str(
        "Host old\n  HostName old.example\n  KexAlgorithms +diffie-hellman-group14-sha1\n  Ciphers ^aes128-ctr\n  MACs -hmac-sha2-512*\n  HostKeyAlgorithms +ssh-rsa\n  PubkeyAcceptedAlgorithms +ssh-rsa\n  Compression yes\n  SendEnv LANG LC_*\n  SetEnv FOO=\"a b\" BAR=1\n  RequestTTY force\n  RemoteCommand tmux new -A -s main\n  AddKeysToAgent confirm\n  ExitOnForwardFailure yes\n  MACs +umac-64@openssh.com\n",
        "config",
    );
    let h = cfg.resolve("old");
    assert_eq!(h.kex_algorithms.as_deref(), Some("+diffie-hellman-group14-sha1"));
    assert_eq!(h.macs.as_deref(), Some("-hmac-sha2-512*"), "first MACs wins");
    assert_eq!(h.send_env, ["LANG", "LC_*"]);
    assert_eq!(h.set_env, ["FOO=a b", "BAR=1"]);
    assert_eq!(h.remote_command.as_deref(), Some("tmux new -A -s main"));
    assert_eq!(h.exit_on_forward_failure, Some(true));
    assert!(h.flags.contains(&bastion_core::sshconfig::HostFlag::WeakAlgorithmsRequested));
    let c = h.to_connection();
    let a = c.settings.ssh_algorithms.clone().unwrap();
    assert!(!a.allow_weak, "an import never opts into weak algorithms");
    let r = a.resolve(false).unwrap();
    assert_eq!(r.ciphers[0], "aes128-ctr");
    assert!(!r.macs.iter().any(|m| m.starts_with("hmac-sha2-512")));
    assert!(!r.kex.contains(&"diffie-hellman-group14-sha1".to_string()));
    assert_eq!(c.metadata.get("RequestTTY").map(String::as_str), Some("force"));
    assert_eq!(c.metadata.get("SendEnv").map(String::as_str), Some("LANG LC_*"));
}

#[test]
fn reimport_updates_in_place_without_duplicates() {
    let d = team_tree();
    let opts = Discovery { scan_config_d: true, ..Default::default() };
    let hosts = SshConfig::discover_opts(d.path(), &opts, &Limits::default()).hosts();
    let mut doc = Document::new("Library");
    let first = reimport_hosts(&mut doc, &hosts).unwrap();
    let total = doc.connections().len();
    assert_eq!(first.added as usize, total);
    write(d.path(), "config.d/globex", "Host globex-app\n  HostName app2.globex.example\n  User deploy\n  Ciphers aes256-ctr\n");
    let hosts = SshConfig::discover_opts(d.path(), &opts, &Limits::default()).hosts();
    let again = reimport_hosts(&mut doc, &hosts).unwrap();
    assert_eq!((again.added, again.updated as usize), (0, total));
    assert_eq!(doc.connections().len(), total);
    let g = doc.connections().into_iter().find(|r| r.connection.name == "globex-app").unwrap().connection;
    assert_eq!(g.host, "app2.globex.example");
    assert_eq!(g.settings.ssh_algorithms.unwrap().ciphers.as_deref(), Some("aes256-ctr"));

    // The same customer folder imported from another checkout (different identity) is adopted.
    let other = tempfile::tempdir().unwrap();
    write(other.path(), "acme", "Host acme-web\n  HostName web2.acme.example\n");
    let moved = SshConfig::discover_with(other.path(), &[other.path().join("acme")], &[], &Limits::default()).hosts();
    let m = host(&moved, "acme-web");
    assert_eq!(m.group, "acme");
    let r = reimport_hosts(&mut doc, &moved).unwrap();
    assert_eq!((r.added, r.updated), (0, 1));
    assert_eq!(doc.connections().len(), total);
}
