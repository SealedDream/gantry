use std::collections::BTreeSet;

use bastion_core::export::{self, Selection};
use bastion_core::model::{Connection, Document, Folder, Node, Protocol, Settings};
use uuid::Uuid;

fn doc() -> (Document, Uuid, Uuid, Uuid) {
    let mut d = Document::new("Work");
    let cred = Uuid::new_v4();
    let folder = Folder { id: Uuid::new_v4(), name: "Acme".into(), color: None, defaults: Settings { credential_id: Some(cred), ..Default::default() }, children: vec![], dynamic_task_id: None, extra: Default::default() };
    let fid = folder.id;
    d.insert(None, Node::Folder(folder)).unwrap();
    let mut web = Connection::new("acme-web", Protocol::Ssh, "web.acme");
    web.metadata.insert("api_token".into(), "SHOULD-NOT-LEAK".into());
    web.metadata.insert("Group".into(), "acme".into());
    let wid = web.id;
    d.insert(Some(fid), Node::Connection(web)).unwrap();
    let other = Connection::new("home", Protocol::Rdp, "pc.home");
    let oid = other.id;
    d.insert(None, Node::Connection(other)).unwrap();
    (d, fid, wid, oid)
}

#[test]
fn full_export_round_trips_without_secrets() {
    let (d, _, wid, _) = doc();
    let p = export::preview(&d, &Selection::All);
    assert_eq!((p.folders, p.connections, p.credential_refs.len()), (1, 2, 1));
    assert_eq!(p.stripped_fields, ["acme-web: api_token"]);
    let bytes = export::export(&d, &Selection::All).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(!text.contains("SHOULD-NOT-LEAK"));
    assert!(text.contains("\"format\": \"bastion-export\""));
    let back = export::import(&bytes).unwrap();
    assert_eq!(back.connections().len(), 2);
    let web = back.resolve(wid).unwrap();
    assert_eq!(web.path, ["Acme"]);
    assert!(web.effective.credential_id.is_some(), "credential reference survives");
}

#[test]
fn selective_export_keeps_ancestors() {
    let (d, _, wid, oid) = doc();
    let sel = Selection::Nodes(BTreeSet::from([wid]));
    let (out, p) = export::prepare(&d, &sel);
    assert_eq!(p.connections, 1);
    assert!(out.resolve(oid).is_err());
    assert_eq!(out.resolve(wid).unwrap().path, ["Acme"]);
}

#[test]
fn rejects_foreign_newer_and_oversize_files() {
    assert!(export::import(b"{\"schema\":1}").is_err());
    assert!(export::import(b"not json").is_err());
    let (d, ..) = doc();
    let mut v: serde_json::Value = serde_json::from_slice(&export::export(&d, &Selection::All).unwrap()).unwrap();
    v["version"] = 99.into();
    let err = export::import(&serde_json::to_vec(&v).unwrap()).unwrap_err().to_string();
    assert!(err.contains("newer"), "{err}");
    assert!(export::import(&vec![b' '; export::MAX_IMPORT_BYTES + 1]).is_err());
}

#[test]
fn import_scrubs_secret_metadata_from_hand_edited_files() {
    let (d, ..) = doc();
    let mut v: serde_json::Value = serde_json::from_slice(&export::export(&d, &Selection::All).unwrap()).unwrap();
    let text = serde_json::to_string(&v).unwrap().replace("\"Group\":\"acme\"", "\"Group\":\"acme\",\"Password\":\"hunter2\"");
    v = serde_json::from_str(&text).unwrap();
    let back = export::import(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert!(!serde_json::to_string(&back).unwrap().contains("hunter2"));
}
