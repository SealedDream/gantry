//! B10: Recently Deleted — trash, restore, purge with an injected clock, export stripping and
//! the live set for pruning inline secrets.

use bastion_core::export::{self, Selection};
use bastion_core::model::{Connection, Document, Folder, Node, Protocol, Settings};
use bastion_core::vault::{CredentialKind, Secret, Vault};
use uuid::Uuid;

const DAY: i64 = 86_400;
const T0: i64 = 1_800_000_000;

fn folder(name: &str) -> Folder {
    Folder { id: Uuid::new_v4(), name: name.into(), color: None, defaults: Settings::default(), children: vec![], dynamic_task_id: None, extra: Default::default() }
}

/// Root: [Other conn] + Customers/[Web, A, B, C]; C has an inline secret, B a shared credential.
struct Lib {
    doc: Document,
    customers: Uuid,
    web: Uuid,
    conns: [Uuid; 3],
    shared_cred: Uuid,
}

fn lib() -> Lib {
    let mut doc = Document::new("B10");
    doc.insert(None, Node::Connection(Connection::new("Other", Protocol::Ssh, "other.lab"))).unwrap();
    let customers = folder("Customers");
    let cid = customers.id;
    doc.insert(None, Node::Folder(customers)).unwrap();
    let web = folder("Web");
    let web_id = web.id;
    doc.insert(Some(cid), Node::Folder(web)).unwrap();
    let mut ids = [Uuid::nil(); 3];
    for (i, name) in ["A", "B", "C"].iter().enumerate() {
        let c = Connection::new(*name, Protocol::Ssh, format!("{name}.lab"));
        ids[i] = c.id;
        doc.insert(Some(web_id), Node::Connection(c)).unwrap();
    }
    let shared_cred = Uuid::new_v4();
    doc.set_credential(ids[1], Some(shared_cred)).unwrap();
    Lib { doc, customers: cid, web: web_id, conns: ids, shared_cred }
}

fn vault_with_inline(conn: Uuid) -> Vault {
    let mut v = Vault::default();
    v.set_inline(conn, CredentialKind::Password { username: "root".into(), password: Secret::new("inline-pw") });
    v
}

#[test]
fn delete_folder_with_three_connections_and_restore_brings_everything_back() {
    let Lib { mut doc, customers, web, conns, shared_cred } = lib();
    let before = doc.clone();
    let mut vault = vault_with_inline(conns[2]);

    assert!(doc.trash(web, T0, 30).unwrap().is_empty(), "nothing is dropped for good with a keep time");
    assert!(doc.folder(web).is_none());
    assert_eq!(doc.connections().len(), 1, "only the untouched connection is visible");
    assert_eq!(doc.deleted_items().len(), 1);
    assert_eq!(doc.deleted_items()[0].parent, Some(customers));

    // A prune in between (Mac prunes on credential edits) must keep the trashed secret.
    assert_eq!(vault.prune_inline(&doc.all_connection_ids()), 0);
    assert!(vault.inline(conns[2]).is_some());

    let r = doc.restore(web).unwrap();
    assert_eq!(r.landed_in, Some(customers));
    assert!(!r.at_root_because_parent_missing);
    assert!(doc.deleted_items().is_empty());
    assert_eq!(doc.root, before.root, "tree, order, settings and credential references identical");
    assert_eq!(doc.resolve(conns[1]).unwrap().effective.credential_id, Some(shared_cred));
    assert!(vault.inline(conns[2]).is_some(), "inline secret still there after restore");
}

#[test]
fn tree_only_live_set_would_lose_the_secret_which_is_why_apps_use_all_connection_ids() {
    let Lib { mut doc, web, conns, .. } = lib();
    doc.trash(web, T0, 30).unwrap();
    let tree_only: std::collections::BTreeSet<Uuid> = doc.connections().iter().map(|r| r.connection.id).collect();
    assert!(!tree_only.contains(&conns[2]));
    assert!(doc.all_connection_ids().contains(&conns[2]));
    assert_eq!(doc.all_connection_ids().len(), 4);
}

#[test]
fn retention_purges_at_the_end_of_the_keep_time_and_the_secret_goes_with_it() {
    let Lib { mut doc, web, conns, .. } = lib();
    let mut vault = vault_with_inline(conns[2]);
    doc.trash(web, T0, 30).unwrap();

    assert!(doc.purge_deleted(T0 + 29 * DAY, 30).is_empty());
    assert_eq!(doc.deleted_items().len(), 1, "still listed at day 29");

    let mut gone = doc.purge_deleted(T0 + 30 * DAY, 30);
    gone.sort();
    let mut want = conns.to_vec();
    want.sort();
    assert_eq!(gone, want);
    assert!(doc.deleted_items().is_empty());
    assert_eq!(vault.prune_inline(&doc.all_connection_ids()), 1);
    assert!(vault.inline(conns[2]).is_none());
}

#[test]
fn a_clock_moved_backwards_never_purges_early() {
    let Lib { mut doc, web, .. } = lib();
    doc.trash(web, T0, 7).unwrap();
    assert!(doc.purge_deleted(T0 - 400 * DAY, 7).is_empty());
    assert!(doc.purge_deleted(T0 + 6 * DAY, 7).is_empty());
    assert_eq!(doc.deleted_items().len(), 1);
}

#[test]
fn retention_off_drops_at_once_and_returns_the_connection_ids() {
    let Lib { mut doc, web, conns, .. } = lib();
    let mut gone = doc.trash(web, T0, 0).unwrap();
    gone.sort();
    let mut want = conns.to_vec();
    want.sort();
    assert_eq!(gone, want);
    assert!(doc.deleted_items().is_empty());
    assert!(doc.restore(web).is_err());
}

#[test]
fn switching_to_off_purges_everything() {
    let Lib { mut doc, web, .. } = lib();
    doc.trash(web, T0, 30).unwrap();
    assert_eq!(doc.purge_deleted(T0, 0).len(), 3);
    assert!(doc.deleted_items().is_empty());
}

#[test]
fn restore_lands_at_the_root_when_the_parent_was_also_deleted_or_is_gone() {
    let Lib { mut doc, customers, conns, .. } = lib();
    doc.trash(conns[0], T0, 30).unwrap();
    doc.trash(customers, T0 + 1, 30).unwrap();
    let r = doc.restore(conns[0]).unwrap();
    assert_eq!(r.landed_in, None);
    assert!(r.at_root_because_parent_missing);
    assert!(doc.root.children.iter().any(|n| n.id() == conns[0]));

    // Parent purged for good: the restored folder still lands at the root.
    let Lib { mut doc, customers, web, .. } = lib();
    doc.trash(web, T0, 30).unwrap();
    doc.trash(customers, T0, 30).unwrap();
    doc.delete_permanently(customers).unwrap();
    let r = doc.restore(web).unwrap();
    assert!(r.at_root_because_parent_missing);
    assert!(doc.folder(web).is_some());
}

#[test]
fn restore_keeps_the_original_position_among_siblings() {
    let Lib { mut doc, web, conns, .. } = lib();
    doc.trash(conns[1], T0, 30).unwrap();
    doc.restore(conns[1]).unwrap();
    let order: Vec<Uuid> = doc.folder(web).unwrap().children.iter().map(|n| n.id()).collect();
    assert_eq!(order, conns.to_vec());
}

#[test]
fn deleted_items_are_invisible_to_lookups() {
    let Lib { mut doc, web, conns, .. } = lib();
    doc.trash(web, T0, 30).unwrap();
    assert!(doc.resolve(conns[0]).is_err(), "cannot connect to a trashed connection");
    assert!(bastion_core::search::search(&doc, "A.lab").is_empty());
    assert!(doc.rename(conns[0], "x").is_err());
}

#[test]
fn delete_permanently_and_empty_return_ids_for_pruning() {
    let Lib { mut doc, web, conns, .. } = lib();
    let other = doc.root.children[0].id();
    doc.trash(web, T0, 30).unwrap();
    doc.trash(other, T0, 30).unwrap();
    assert_eq!(doc.delete_permanently(other).unwrap(), vec![other]);
    assert!(doc.delete_permanently(other).is_err());
    let mut vault = vault_with_inline(conns[2]);
    assert_eq!(doc.empty_deleted().len(), 3);
    assert_eq!(vault.prune_inline(&doc.all_connection_ids()), 1);
}

#[test]
fn the_root_cannot_be_trashed() {
    let mut doc = Document::new("x");
    let root = doc.root.id;
    assert!(doc.trash(root, T0, 30).is_err());
}

#[test]
fn restore_refuses_an_id_already_back_in_the_library() {
    let Lib { mut doc, web, .. } = lib();
    let copy = doc.folder(web).unwrap().clone();
    doc.trash(web, T0, 30).unwrap();
    doc.insert(None, Node::Folder(copy)).unwrap();
    assert!(doc.restore(web).is_err());
    assert_eq!(doc.deleted_items().len(), 1, "a refused restore keeps the item");
}

#[test]
fn export_never_contains_deleted_items() {
    let Lib { mut doc, web, conns, .. } = lib();
    doc.trash(web, T0, 30).unwrap();
    for sel in [Selection::All, Selection::Nodes([doc.root.children[0].id()].into_iter().collect())] {
        let bytes = export::export(&doc, &sel).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        for id in conns.iter().chain([&web]) {
            assert!(!text.contains(&id.to_string()), "deleted id in export");
        }
        assert!(!text.contains("B.lab") && !text.contains("\"deleted\""));
        assert!(export::import(&bytes).unwrap().deleted.is_empty());
    }
}

#[test]
fn import_of_a_file_carrying_deleted_items_drops_them() {
    let Lib { mut doc, web, .. } = lib();
    doc.trash(web, T0, 30).unwrap();
    let file = export::ExportFile { format: export::FORMAT.into(), version: 1, exported_at_unix: 0, document: doc };
    let d = export::import(&serde_json::to_vec(&file).unwrap()).unwrap();
    assert!(d.deleted.is_empty());
    assert!(d.folder(web).is_none());
}

#[test]
fn recently_deleted_round_trips_through_the_saved_document() {
    let Lib { mut doc, web, .. } = lib();
    doc.trash(web, T0, 30).unwrap();
    let json = serde_json::to_string(&doc).unwrap();
    let back: Document = serde_json::from_str(&json).unwrap();
    assert_eq!(back.deleted, doc.deleted);
    let mut back = back;
    assert!(back.restore(web).is_ok());

    // A document without the field reads as empty.
    let plain: Document = serde_json::from_str(&serde_json::to_string(&Document::new("p")).unwrap()).unwrap();
    assert!(plain.deleted.is_empty());
}

#[test]
fn retention_setting_defaults_to_30_with_off_7_30_90() {
    use bastion_core::settings::{self, Settings as AppSettings, DELETED_RETENTION_SETTING};
    let mut s = AppSettings::default();
    assert_eq!(s.deleted_retention_days(), 30);
    for v in ["0", "7", "90"] {
        s.set(DELETED_RETENTION_SETTING, v).unwrap();
        assert_eq!(s.deleted_retention_days().to_string(), v);
    }
    assert!(s.set(DELETED_RETENTION_SETTING, "14").is_err());
    assert!(settings::visible(&[]).iter().all(|d| d.id != DELETED_RETENTION_SETTING), "hidden until an app has the UI");
    assert!(settings::visible(&["restore-deleted"]).iter().any(|d| d.id == DELETED_RETENTION_SETTING));
}

#[test]
fn trash_and_purge_stay_fast_with_a_thousand_deleted_connections() {
    let mut doc = Document::new("big");
    let mut ids = Vec::new();
    for i in 0..1000 {
        let c = Connection::new(format!("c{i}"), Protocol::Ssh, "h");
        ids.push(c.id);
        doc.insert(None, Node::Connection(c)).unwrap();
    }
    let t = std::time::Instant::now();
    for id in &ids {
        doc.trash(*id, T0, 30).unwrap();
    }
    assert_eq!(doc.all_connection_ids().len(), 1000);
    assert_eq!(doc.purge_deleted(T0 + 31 * DAY, 30).len(), 1000);
    assert!(t.elapsed() < std::time::Duration::from_secs(2), "{:?}", t.elapsed());
}
