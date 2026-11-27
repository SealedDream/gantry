//! Behaviour kept by the single-pass rewrites of H02, H03, H04 and H06
//! (timings: `cargo run --release --example health_bench`).
use bastion_core::model::{Connection, Document, Folder, Node, Protocol, Settings};
use bastion_core::sshconfig::ResolvedHost;
use bastion_core::{properties, search, sshworkflow};
use uuid::Uuid;

fn folder(name: &str, keepalive: Option<u32>, children: Vec<Node>) -> Folder {
    Folder { id: Uuid::new_v4(), name: name.into(), color: None, defaults: Settings { keepalive_secs: keepalive, ..Default::default() }, children, dynamic_task_id: None, extra: Default::default() }
}

fn ssh(name: &str) -> Connection {
    Connection::new(name, Protocol::Ssh, format!("{name}.example"))
}

/// root ─ top ─ inner(sets keepalive) ─ shadowed
///          └ open
///      └ own (sets its own keepalive), rdp (no keepalive in its schema)
fn tree() -> (Document, Uuid, Uuid) {
    let mut doc = Document::new("t");
    let mut own = ssh("own");
    own.settings.keepalive_secs = Some(5);
    let inner = folder("inner", Some(30), vec![Node::Connection(ssh("shadowed"))]);
    let inner_id = inner.id;
    let top = folder("top", None, vec![Node::Folder(inner), Node::Connection(ssh("open"))]);
    let top_id = top.id;
    doc.root.children = vec![Node::Folder(top), Node::Connection(own), Node::Connection(Connection::new("rdp", Protocol::Rdp, "w"))];
    (doc, top_id, inner_id)
}

#[test]
fn affected_by_stops_at_nearer_folder_defaults_and_own_settings() {
    let (doc, top, inner) = tree();
    assert_eq!(properties::affected_by(&doc, None, None, "keepalive_secs"), vec!["open"]);
    assert_eq!(properties::affected_by(&doc, Some(top), None, "keepalive_secs"), vec!["open"]);
    // The edited folder's own value does not shadow itself.
    assert_eq!(properties::affected_by(&doc, Some(inner), None, "keepalive_secs"), vec!["shadowed"]);
    assert!(properties::affected_by(&doc, None, Some(Protocol::Rdp), "keepalive_secs").is_empty());
    assert!(properties::affected_by(&doc, Some(Uuid::new_v4()), None, "keepalive_secs").is_empty());
}

#[test]
fn resolve_and_resolve_many_match_full_resolution() {
    let (doc, _, _) = tree();
    let all = doc.connections();
    for r in &all {
        let one = doc.resolve(r.connection.id).unwrap();
        assert_eq!((one.connection.name.as_str(), &one.effective, &one.path), (r.connection.name.as_str(), &r.effective, &r.path));
    }
    let ids: Vec<Uuid> = all.iter().rev().map(|r| r.connection.id).chain([all[0].connection.id]).collect();
    let many = doc.resolve_many(&ids).unwrap();
    assert_eq!(many.iter().map(|r| r.connection.id).collect::<Vec<_>>(), ids, "order given, duplicates kept");
    assert_eq!(many[0].effective, all.last().unwrap().effective);
    assert!(doc.resolve_many(&[all[0].connection.id, Uuid::new_v4()]).is_err());
    assert!(doc.resolve(Uuid::new_v4()).is_err());
    assert_eq!(doc.resolve(all[0].connection.id).unwrap().effective.keepalive_secs, Some(30), "folder default inherited");
}

#[test]
fn search_still_matches_paths_tags_and_protocol_with_and_terms() {
    let (mut doc, _, _) = tree();
    if let Node::Connection(c) = &mut doc.root.children[1] {
        c.tags = vec!["Prod".into()];
        c.notes = "Backup Box".into();
    }
    let names = |q: &str| search::search(&doc, q).into_iter().map(|r| r.connection.name).collect::<Vec<_>>();
    assert_eq!(names("top/inner"), vec!["shadowed"]);
    assert_eq!(names("prod backup"), vec!["own"]);
    assert_eq!(names("rdp"), vec!["rdp"]);
    assert_eq!(names("OPEN top"), vec!["open"]);
    assert!(names("open inner").is_empty());
    assert_eq!(names("").len(), 4);
    assert_eq!(search::search(&doc, "shadowed")[0].effective.keepalive_secs, Some(30));
}

fn host(alias: &str, group: &str, hostname: &str) -> ResolvedHost {
    ResolvedHost { alias: alias.into(), identity: format!("{group}/{alias}"), source_file: format!("config.d/{group}"), group: group.into(), hostname: hostname.into(), ..Default::default() }
}

#[test]
fn reimport_updates_in_place_adds_new_and_reuses_group_folders() {
    let mut doc = Document::new("t");
    assert_eq!(sshworkflow::import_hosts(&mut doc, &[host("a", "g1", "1"), host("b", "g2", "2"), host("c", "g1", "3")]).unwrap(), 3);
    assert_eq!(doc.root.children.len(), 2, "one folder per group");
    let id_a = doc.connections().iter().find(|r| r.connection.name == "a").unwrap().connection.id;
    let s = sshworkflow::reimport_hosts(&mut doc, &[host("a", "g1", "10"), host("d", "g2", "4"), host("c", "g1", "3")]).unwrap();
    assert_eq!((s.updated, s.added), (2, 1));
    let a = doc.resolve(id_a).unwrap();
    assert_eq!((a.connection.host.as_str(), a.path.clone()), ("10", vec!["g1".to_string()]), "id and folder kept");
    assert_eq!(doc.connections().len(), 4);
    assert_eq!(sshworkflow::import_hosts(&mut doc, &[host("a", "g1", "x")]).unwrap(), 0, "known identity is skipped");
}
