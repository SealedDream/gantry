//! Audit SP-01: a secret-free export must not carry the Wake-on-LAN SecureOn password, at any
//! inheritance level, in either the portable JSON or the `.bastion` export.
use bastion_core::docfile::{self, DocumentFile};
use bastion_core::export::{self, Selection};
use bastion_core::model::{Connection, Document, Folder, Node, Protocol, Settings};
use uuid::Uuid;

const CONN: &str = "aa:aa:aa:00:00:01";
const FOLDER: &str = "bb:bb:bb:00:00:02";
const TYPE: &str = "cc:cc:cc:00:00:03";

fn doc() -> Document {
    let mut d = Document::new("SecureOn");
    d.type_defaults.insert(Protocol::Ssh, Settings { wol_secureon: Some(TYPE.into()), ..Default::default() });
    let folder = Folder { id: Uuid::new_v4(), name: "Lab".into(), color: None, defaults: Settings { wol_secureon: Some(FOLDER.into()), ..Default::default() }, children: vec![], dynamic_task_id: None, extra: Default::default() };
    let fid = folder.id;
    d.insert(None, Node::Folder(folder)).unwrap();
    let mut c = Connection::new("box", Protocol::Ssh, "127.0.0.1");
    c.settings.wol_secureon = Some(CONN.into());
    d.insert(Some(fid), Node::Connection(c)).unwrap();
    d
}

fn assert_no_sentinel(text: &str) {
    for s in [CONN, FOLDER, TYPE] {
        assert!(!text.contains(s), "SecureOn password {s} survived a secret-free export");
    }
}

#[test]
fn portable_export_strips_secureon_at_every_level_and_reports_it() {
    let d = doc();
    let p = export::preview(&d, &Selection::All);
    assert_eq!(p.stripped_fields, ["Lab: wol_secureon", "box: wol_secureon", "Ssh defaults: wol_secureon"]);
    let text = String::from_utf8(export::export(&d, &Selection::All).unwrap()).unwrap();
    assert_no_sentinel(&text);
    assert!(d.connections()[0].effective.wol_secureon.is_some(), "the source document is untouched");
}

#[test]
fn secret_free_bastion_export_strips_secureon_and_preview_agrees() {
    let source = DocumentFile::from_document(doc());
    let (out, summary) = docfile::export(&source, &Selection::All, "Out", false, None).unwrap();
    assert_eq!(summary.stripped_fields, export::preview(&source.document().unwrap().clone(), &Selection::All).stripped_fields);
    assert_eq!(summary.stripped_fields.len(), 3);
    assert_no_sentinel(&String::from_utf8_lossy(&out.to_bytes().unwrap()));
    // A password without secrets protects the tree but is still secret-free.
    let (out, _) = docfile::export(&source, &Selection::All, "Out", false, Some("generated-pw")).unwrap();
    assert_no_sentinel(&serde_json::to_string(out.document().unwrap()).unwrap());
}

#[test]
fn protected_export_with_secrets_keeps_secureon() {
    let source = DocumentFile::from_document(doc());
    let (out, summary) = docfile::export(&source, &Selection::All, "Out", true, Some("generated-pw")).unwrap();
    assert!(summary.stripped_fields.is_empty());
    let r = &out.document().unwrap().connections()[0];
    assert_eq!(r.effective.wol_secureon.as_deref(), Some(CONN));
    assert!(docfile::export(&source, &Selection::All, "Out", true, None).is_err(), "secrets need a password");
}
