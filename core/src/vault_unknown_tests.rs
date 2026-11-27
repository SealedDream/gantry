//! A vault written by a newer app with a credential kind this app does not know.
use serde_json::{json, Value};
use uuid::Uuid;

use crate::error::CoreError;
use crate::vault::{Credential, CredentialKind, Secret, Vault};
use crate::vault_unknown::UNSUPPORTED_CREDENTIAL;

fn cert(id: Uuid) -> Value {
    json!({"id": id, "name": "cluster cert", "folder": null, "kind": {"ClientCertificate": {"certificate": "PEM-CERT", "private_key": "PEM-KEY", "future": [1, {"x": true}]}}})
}

fn password(id: Uuid) -> Value {
    json!({"id": id, "name": "root", "folder": null, "scope": null, "kind": {"Password": {"username": "root", "password": "pw"}}})
}

fn plain(list: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&list).unwrap()
}

fn written(v: &Vault) -> Vec<Value> {
    let out: Value = serde_json::from_slice(&v.to_plain().unwrap()).unwrap();
    match out {
        Value::Array(a) => a,
        Value::Object(o) => o["credentials"].as_array().unwrap().clone(),
        _ => panic!("unexpected layout"),
    }
}

#[test]
fn reads_a_vault_with_an_unknown_kind_without_error() {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let v = Vault::from_plain(&plain(vec![password(a), cert(b)])).unwrap();
    assert!(v.get(a).is_some());
    assert!(v.get(b).is_none(), "an unknown kind is never handed out as a credential");
    assert!(v.is_unsupported(b));
    assert_eq!(v.len(), 2);
    assert_eq!(v.list().len(), 1);
    let u = v.list_unsupported();
    assert_eq!(u.len(), 1);
    assert_eq!((u[0].id, u[0].name.as_str(), u[0].username.as_str()), (b, "cluster cert", UNSUPPORTED_CREDENTIAL));
}

#[test]
fn round_trips_the_unknown_credential_unchanged() {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let v = Vault::from_plain(&plain(vec![password(a), cert(b)])).unwrap();
    let out = written(&v);
    assert!(out.contains(&cert(b)), "the unknown credential is written back byte for byte");
    let again = Vault::from_plain(&v.to_plain().unwrap()).unwrap();
    assert!(again.is_unsupported(b) && again.get(a).is_some());
}

#[test]
fn saving_after_an_edit_keeps_the_unknown_credential() {
    let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let mut v = Vault::from_plain(&plain(vec![password(a), cert(b)])).unwrap();
    v.add(Credential { id: c, name: "new".into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: "u".into(), password: Secret::new("p") } });
    v.remove(a);
    let sealed = v.seal("master").unwrap();
    let opened = Vault::open(&sealed, "master").unwrap();
    assert!(opened.is_unsupported(b) && opened.get(c).is_some() && opened.get(a).is_none());
    assert!(written(&opened).contains(&cert(b)));
}

#[test]
fn keeps_the_folder_placement_of_an_unknown_credential() {
    let (a, b, f) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let doc = json!({
        "credentials": [password(a), cert(b)],
        "folders": [{"id": f, "name": "Clusters", "parent": null}],
        "placement": {b.to_string(): f}
    });
    let v = Vault::from_plain(&serde_json::to_vec(&doc).unwrap()).unwrap();
    assert_eq!(v.list_unsupported()[0].folder.as_deref(), Some("Clusters"));
    let out: Value = serde_json::from_slice(&v.to_plain().unwrap()).unwrap();
    assert_eq!(out["placement"][b.to_string()], json!(f));
}

#[test]
fn deleting_removes_an_unknown_credential() {
    let b = Uuid::new_v4();
    let mut v = Vault::from_plain(&plain(vec![cert(b)])).unwrap();
    v.remove(b);
    assert!(v.is_empty() && written(&v).is_empty());
}

#[test]
fn a_known_kind_that_does_not_parse_is_still_corrupt() {
    let bad = json!({"id": Uuid::new_v4(), "name": "x", "folder": null, "kind": {"Password": {"username": 5}}});
    assert!(matches!(Vault::from_plain(&plain(vec![bad])), Err(CoreError::Corrupt(_))));
}

#[test]
fn a_malformed_kind_tag_is_corrupt() {
    for kind in [json!({"a": 1, "b": 2}), json!({"Bad tag!": {}}), json!(7), json!({"": {}})] {
        let bad = json!({"id": Uuid::new_v4(), "name": "x", "kind": kind});
        assert!(matches!(Vault::from_plain(&plain(vec![bad])), Err(CoreError::Corrupt(_))));
    }
}

#[test]
fn an_oversized_unknown_credential_is_corrupt() {
    let mut c = cert(Uuid::new_v4());
    c["kind"]["ClientCertificate"]["certificate"] = json!("x".repeat(crate::unknown::MAX_UNKNOWN_ENTRY_BYTES));
    assert!(matches!(Vault::from_plain(&plain(vec![c])), Err(CoreError::Corrupt(_))));
}

#[test]
fn an_unknown_inline_secret_is_kept_when_inline_secrets_are_pruned() {
    let conn = Uuid::new_v4();
    let mut c = cert(conn);
    c["owner"] = json!(conn);
    let mut v = Vault::from_plain(&plain(vec![c])).unwrap();
    assert!(v.list_unsupported().is_empty(), "inline secrets are not listed");
    assert!(!v.is_unsupported(conn) && v.is_unsupported_inline(conn));
    assert_eq!(v.prune_inline(&Default::default()), 0);
    assert_eq!(v.len(), 1);
}

#[test]
fn adding_with_the_id_of_an_unknown_credential_never_overwrites_it() {
    let b = Uuid::new_v4();
    let mut v = Vault::from_plain(&plain(vec![cert(b)])).unwrap();
    let got = v.add(Credential { id: b, name: "n".into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: "u".into(), password: Secret::new("p") } });
    assert_ne!(got, b);
    assert!(v.is_unsupported(b) && v.get(got).is_some());
    assert!(written(&v).contains(&cert(b)));
}

#[test]
fn two_credentials_with_one_id_are_corrupt() {
    let a = Uuid::new_v4();
    for list in [vec![cert(a), cert(a)], vec![password(a), cert(a)], vec![password(a), password(a)]] {
        assert!(matches!(Vault::from_plain(&plain(list)), Err(CoreError::Corrupt(_))));
    }
}

#[test]
fn a_document_refuses_to_replace_an_unknown_credential() {
    let b = Uuid::new_v4();
    let mut doc = crate::docfile::DocumentFile::new("Newer").unwrap();
    doc.set_password(Some("pw-for-test")).unwrap();
    doc.set_credentials_for_tests(serde_json::from_value(json!([cert(b)])).unwrap());
    let c = Credential { id: b, name: "n".into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: "u".into(), password: Secret::new("p") } };
    assert!(doc.put_credential(c).is_err());
    assert_eq!(doc.unsupported_credentials().unwrap()[0].id, b);
}

#[test]
fn a_protected_document_with_an_unknown_credential_opens_and_saves_unchanged() {
    // Downgrade: a document a newer app saved, opened and saved again by this app.
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let newer = Vault::from_plain(&plain(vec![password(a), cert(b)])).unwrap();
    let mut doc = crate::docfile::DocumentFile::new_device(crate::model::Document::new("t"));
    doc.set_vault(&newer).unwrap();
    let v = doc.vault().unwrap();
    assert!(v.is_unsupported(b) && v.get(a).is_some());
    doc.set_vault(&v).unwrap();
    assert!(written(&doc.vault().unwrap()).contains(&cert(b)));
}

#[test]
fn the_credentials_tree_shows_an_unknown_credential_as_unsupported() {
    let b = Uuid::new_v4();
    let v = Vault::from_plain(&plain(vec![cert(b)])).unwrap();
    let tree = v.credential_tree();
    let leaf = tree.credentials.iter().find(|l| l.id == b).expect("listed");
    assert_eq!((leaf.kind, leaf.username.as_str()), ("unsupported", UNSUPPORTED_CREDENTIAL));
}

/// Writes the Mac UI fixture `apps/macos/uitests/fixtures/unsupported-credential.bastion`
/// (test password `test-doc-pw-1`): a library a newer app saved, with one credential of an
/// unknown kind next to a password. Run: `BASTION_FIXTURE_OUT=<path> cargo test --lib
/// write_unsupported_credential_fixture -- --ignored`.
#[test]
#[ignore]
fn write_unsupported_credential_fixture() {
    let out = std::env::var("BASTION_FIXTURE_OUT").expect("BASTION_FIXTURE_OUT");
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let mut c = cert(b);
    c["kind"]["ClientCertificate"] = json!({"certificate": "fixture", "private_key": "fixture"});
    let newer = Vault::from_plain(&plain(vec![password(a), c])).unwrap();
    let mut doc = crate::docfile::DocumentFile::new("Newer").unwrap();
    doc.set_password(Some("test-doc-pw-1")).unwrap();
    doc.set_vault(&newer).unwrap();
    // A shared library keeps its credentials in the document's own list.
    let a2 = Uuid::new_v4();
    let mut c2 = cert(Uuid::new_v4());
    c2["kind"]["ClientCertificate"] = json!({"certificate": "fixture", "private_key": "fixture"});
    doc.set_credentials_for_tests(serde_json::from_value(json!([password(a2), c2])).unwrap());
    doc.save_as(std::path::Path::new(&out)).unwrap();
}

#[test]
fn a_document_credential_list_keeps_an_unknown_kind_through_save_and_open() {
    let dir = std::env::temp_dir().join(format!("bastion-vu-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("Newer.bastion");
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let mut doc = crate::docfile::DocumentFile::new("Newer").unwrap();
    doc.set_password(Some("pw-for-test")).unwrap();
    doc.set_credentials_for_tests(serde_json::from_value(json!([password(a), cert(b)])).unwrap());
    doc.save_as(&path).unwrap();

    let mut opened = crate::docfile::DocumentFile::open(&path).unwrap();
    opened.unlock("pw-for-test").unwrap();
    assert_eq!(opened.credentials().unwrap().len(), 1);
    assert_eq!(opened.unsupported_credentials().unwrap()[0].id, b);
    // Removing the password would write the unknown secret in the clear: refused.
    assert!(opened.set_password(None).is_err());
    opened.remove_credential(a).unwrap();
    assert!(opened.set_password(None).is_err(), "the unknown credential still counts");
    opened.save().unwrap();

    let mut again = crate::docfile::DocumentFile::open(&path).unwrap();
    again.unlock("pw-for-test").unwrap();
    assert_eq!(again.unsupported_credentials().unwrap()[0].id, b);
    assert!(again.remove_credential(b).unwrap());
    assert!(again.unsupported_credentials().unwrap().is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

/// Writes the Mac UI fixture folder `apps/macos/uitests/fixtures/unsupported-personal/`: a
/// Personal library a newer app saved (its vault holds a password and a credential of an unknown
/// kind), its wrapped key under `keys/`, and the fixed test device key in `device-key.txt`.
/// Run: `BASTION_FIXTURE_DIR=<dir> cargo test --lib write_unsupported_personal_fixture -- --ignored`.
#[test]
#[ignore]
fn write_unsupported_personal_fixture() {
    let dir = std::path::PathBuf::from(std::env::var("BASTION_FIXTURE_DIR").expect("BASTION_FIXTURE_DIR"));
    std::fs::create_dir_all(&dir).unwrap();
    let hex = "7e57".repeat(16);
    let device = crate::docfile::key_from_hex(&hex).unwrap();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let mut c = cert(b);
    c["kind"]["ClientCertificate"] = json!({"certificate": "fixture", "private_key": "fixture"});
    let newer = Vault::from_plain(&plain(vec![password(a), c])).unwrap();
    let mut doc = crate::docfile::DocumentFile::new_device(crate::model::Document::new("Personal"));
    doc.set_vault(&newer).unwrap();
    doc.save_as(&dir.join("Personal.bastion")).unwrap();
    crate::personal::store_document_key(&dir, &doc, &device).unwrap();
    std::fs::write(dir.join("device-key.txt"), &hex).unwrap();
}
