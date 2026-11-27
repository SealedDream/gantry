//! PLUG-03a, protected documents: unknown data survives sealing, a `VERSION + 1` document
//! stays `VERSION + 1` and stays authenticated, and the key bindings are unchanged.
use super::*;
use crate::model::{Protocol, NEEDS_NEWER};
use crate::unknown::MAX_UNKNOWN_ENTRY_BYTES;
use serde_json::{json, Value};

const PW: &str = "correct horse battery";
const LIBRARY: &str = include_str!("../tests/fixtures/plug03a/library-unknown.json");
const UNKNOWN_ID: &str = "0a000000-0000-4000-8000-000000000004";
const SSH_ID: &str = "0a000000-0000-4000-8000-000000000005";

fn library() -> Document {
    serde_json::from_str(LIBRARY).unwrap()
}

/// A password-protected document holding the unknown-data fixture, saved in format `version`.
fn protected(dir: &Path, version: u32) -> PathBuf {
    let path = dir.join(format!("Team-v{version}.bastion"));
    let mut d = DocumentFile::from_document(library());
    d.loaded_version = version;
    d.set_password(Some(PW)).unwrap();
    d.contents.as_mut().unwrap().extra.insert("future_contents".into(), json!({ "k": [1, "two"] }));
    d.save_as(&path).unwrap();
    path
}

/// A password-protected document with no unknown data, saved in format `VERSION`.
fn protected_plain(dir: &Path) -> PathBuf {
    let path = dir.join("Plain.bastion");
    let mut d = DocumentFile::from_document(Document::new("Plain"));
    d.set_password(Some(PW)).unwrap();
    d.save_as(&path).unwrap();
    assert_eq!(file_json(&path)["version"], json!(VERSION));
    path
}

fn file_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn edit_file(path: &Path, edit: impl FnOnce(&mut Value)) {
    let mut v = file_json(path);
    edit(&mut v);
    fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

fn connection(doc: &Document, id: &str) -> Connection {
    fn walk(f: &Folder, id: Uuid) -> Option<Connection> {
        f.children.iter().find_map(|n| match n {
            Node::Connection(c) if c.id == id => Some(c.clone()),
            Node::Folder(sub) => walk(sub, id),
            _ => None,
        })
    }
    walk(&doc.root, Uuid::parse_str(id).unwrap()).unwrap()
}

/// The revision counter advances on save and is not what these tests compare.
fn at_revision_zero(doc: &Document) -> Document {
    Document { revision: 0, ..doc.clone() }
}

/// The document equals the fixture, unknown data included, apart from the revision.
fn assert_same_as_fixture(d: &DocumentFile) {
    assert!(at_revision_zero(d.document().unwrap()) == at_revision_zero(&library()), "the document differs from the fixture");
    assert_eq!(d.contents().unwrap().extra.get("future_contents"), Some(&json!({ "k": [1, "two"] })));
    assert_unknown_entry_kept(d, "web01");
}

/// The unknown entry is marked and still carries its unknown data; `ssh_name` is the known one.
fn assert_unknown_entry_kept(d: &DocumentFile, ssh_name: &str) {
    let doc = d.document().unwrap();
    assert_eq!(connection(doc, SSH_ID).name, ssh_name);
    let unknown = connection(doc, UNKNOWN_ID);
    assert_eq!((unknown.unavailable(), unknown.protocol, unknown.protocol_name()), (Some(NEEDS_NEWER), Protocol::Unsupported, "postgresql"));
    assert_eq!(unknown.extra, connection(&library(), UNKNOWN_ID).extra);
    assert_eq!(doc.type_defaults.unknown(), library().type_defaults.unknown());
}

#[test]
fn key_bindings_are_what_they_were() {
    let id = Uuid::from_u128(7);
    assert_eq!(key_aad(id), format!("bastion-document/1/key/{id}").into_bytes());
    assert_eq!(wrap_aad(id), format!("bastion-document/1/keywrap/{id}").into_bytes());
    assert_eq!(payload_aad(VERSION, id, "Team", 4), format!("bastion-document/1/contents/{id}/4/Team").into_bytes());
    assert_eq!(payload_aad(VERSION + 1, id, "Team", 4), format!("bastion-document/2/contents/{id}/4/Team").into_bytes());
    assert_eq!((VERSION, MAX_READ_VERSION, crate::model::SCHEMA_VERSION), (1, 2, 1));
}

#[test]
fn protected_document_keeps_unknown_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = protected(dir.path(), VERSION);
    let raw = fs::read_to_string(&path).unwrap();
    // PLUG-03b: a document holding unknown data is raised to `VERSION + 1` on save.
    assert_eq!(file_json(&path)["version"], json!(VERSION + 1));
    for clear in ["postgresql", "orders-db", "future_", "sslmode"] {
        assert!(!raw.contains(clear), "{clear} must be inside the sealed contents");
    }

    let mut d = DocumentFile::open(&path).unwrap();
    assert!(d.is_locked() && d.loaded_version() == VERSION + 1);
    d.unlock(PW).unwrap();
    assert_same_as_fixture(&d);

    // Edit a known entry, save, lock and unlock: everything unknown is still there.
    d.document_mut().unwrap().set_notes(Uuid::parse_str(SSH_ID).unwrap(), "edited").unwrap();
    d.save().unwrap();
    assert!(d.lock());
    d.unlock(PW).unwrap();
    let mut back = DocumentFile::open(&path).unwrap();
    back.unlock(PW).unwrap();
    assert!(at_revision_zero(back.document().unwrap()) == at_revision_zero(d.document().unwrap()), "the reopened document differs");
    assert_eq!(connection(back.document().unwrap(), SSH_ID).notes, "edited");
    let v = serde_json::to_value(back.document().unwrap()).unwrap();
    let fixture: Value = serde_json::from_str(LIBRARY).unwrap();
    for p in ["/root/children/0/children/0/plugin", "/root/children/0/children/0/protocol", "/type_defaults/postgresql", "/plugins", "/root/children/0/folder_badge"] {
        assert_eq!(v.pointer(p), fixture.pointer(p), "{p}");
    }
    assert_eq!(file_json(&path)["version"], json!(VERSION + 1));
}

#[test]
fn protected_version_plus_one_stays_version_plus_one_and_authenticated() {
    let dir = tempfile::tempdir().unwrap();
    let path = protected(dir.path(), VERSION + 1);
    assert_eq!(file_json(&path)["version"], json!(VERSION + 1));

    let mut d = DocumentFile::open(&path).unwrap();
    assert!(d.is_locked());
    assert_eq!((d.loaded_version(), d.format_version()), (VERSION + 1, VERSION + 1));
    assert!(matches!(d.unlock("not the password"), Err(CoreError::VaultAuth)));
    d.unlock(PW).unwrap();
    assert_same_as_fixture(&d);

    // Every way back in works on the newer format: the key itself, a wrapped key, a re-seal.
    let key = d.key().unwrap();
    let wrapping = new_wrapping_key();
    let blob = d.export_wrapped_key(&wrapping).unwrap();
    d.document_mut().unwrap().rename(Uuid::parse_str(SSH_ID).unwrap(), "web01-renamed").unwrap();
    assert!(d.lock_keeping_changes().unwrap());
    d.unlock_with_key(key.clone()).unwrap();
    assert_unknown_entry_kept(&d, "web01-renamed");
    d.save().unwrap();
    assert_eq!(file_json(&path)["version"], json!(VERSION + 1), "never silently downgraded");

    let mut by_key = DocumentFile::open(&path).unwrap();
    by_key.unlock_with_key(key).unwrap();
    let mut by_blob = DocumentFile::open(&path).unwrap();
    by_blob.unlock_with_wrapped_key(&blob, &wrapping).unwrap();
    let mut by_password = DocumentFile::open(&path).unwrap();
    by_password.unlock(PW).unwrap();
    assert!(by_key.document().unwrap() == by_password.document().unwrap() && by_blob.document().unwrap() == by_password.document().unwrap());
    assert_unknown_entry_kept(&by_password, "web01-renamed");

    // Changing the password rewraps the same key and keeps the format.
    by_password.set_password(Some("another long password")).unwrap();
    by_password.save().unwrap();
    assert_eq!(file_json(&path)["version"], json!(VERSION + 1));
    let mut again = DocumentFile::open(&path).unwrap();
    again.unlock("another long password").unwrap();
    assert_unknown_entry_kept(&again, "web01-renamed");
}

#[test]
fn device_keyed_version_plus_one_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Device.bastion");
    let mut d = DocumentFile::new_device(library());
    d.loaded_version = VERSION + 1;
    let key = d.key().unwrap();
    d.save_as(&path).unwrap();
    assert_eq!(file_json(&path)["version"], json!(VERSION + 1));
    let mut back = DocumentFile::open(&path).unwrap();
    back.unlock_with_key(key).unwrap();
    assert_unknown_entry_kept(&back, "web01");
    back.document_mut().unwrap();
    back.save().unwrap();
    assert_eq!(file_json(&path)["version"], json!(VERSION + 1));
}

#[test]
fn editing_the_format_version_of_a_protected_document_fails_authentication() {
    let dir = tempfile::tempdir().unwrap();
    for (written, edited) in [(VERSION + 1, VERSION), (VERSION, VERSION + 1)] {
        // A document written as `VERSION` holds no unknown data since PLUG-03b raises those.
        let path = if written == VERSION { protected_plain(dir.path()) } else { protected(dir.path(), written) };
        edit_file(&path, |v| v["version"] = json!(edited));
        let mut d = DocumentFile::open(&path).unwrap();
        assert!(matches!(d.unlock(PW), Err(CoreError::VaultAuth)), "format {written} relabelled as {edited} must not open");
        assert!(d.is_locked());
    }
}

#[test]
fn damaged_protected_documents_still_fail_authentication() {
    let dir = tempfile::tempdir().unwrap();
    for version in [VERSION, VERSION + 1] {
        let sealed = protected(dir.path(), version);
        let damaged = |name: &str, edit: &dyn Fn(&mut Value)| {
            let path = dir.path().join(format!("{name}-v{version}.bastion"));
            fs::copy(&sealed, &path).unwrap();
            edit_file(&path, |v| edit(v));
            path
        };
        for (i, field) in ["/sealed/ciphertext", "/sealed/nonce", "/protection/wrapped_key", "/name", "/revision"].into_iter().enumerate() {
            let path = damaged(&format!("edit{i}"), &|v| {
                let target = v.pointer_mut(field).unwrap();
                *target = match target.clone() {
                    Value::String(s) if field == "/name" => json!(format!("{s}x")),
                    // Change the first base64 character, keeping it valid base64.
                    Value::String(s) => json!(format!("{}{}", if s.starts_with('A') { "B" } else { "A" }, &s[1..])),
                    Value::Number(n) => json!(n.as_u64().unwrap() + 1),
                    other => other,
                };
            });
            let mut d = DocumentFile::open(&path).unwrap();
            assert!(matches!(d.unlock(PW), Err(CoreError::VaultAuth)), "format {version}: an edited {field} must fail authentication");
        }
        // A seal or key-derivation header that cannot be read is corrupt, as before.
        let path = damaged("seal", &|v| v["sealed"]["ciphertext"] = json!("not base64 !!"));
        assert!(matches!(DocumentFile::open(&path), Err(CoreError::Corrupt(_))));
        let path = damaged("kdf", &|v| v["protection"]["m_cost"] = json!(1));
        assert!(matches!(DocumentFile::open(&path), Err(CoreError::Corrupt(_))));
    }
}

#[test]
fn sealed_unknown_data_over_the_cap_is_refused_and_the_document_stays_locked() {
    // This app neither reads nor writes such contents, so they are sealed here by hand, as a
    // newer writer holding the document key could.
    let dir = tempfile::tempdir().unwrap();
    let path = protected(dir.path(), VERSION);
    let mut d = DocumentFile::open(&path).unwrap();
    d.unlock(PW).unwrap();
    let mut v: Value = serde_json::from_str(LIBRARY).unwrap();
    *v.pointer_mut("/root/children/0/children/0/plugin").unwrap() = json!("x".repeat(MAX_UNKNOWN_ENTRY_BYTES + 1));
    let plain = serde_json::to_vec(&json!({ "document": v })).unwrap();
    let file = file_json(&path);
    let written = file_json(&path)["version"].as_u64().unwrap() as u32;
    let aad = payload_aad(written, d.id, file["name"].as_str().unwrap(), file["revision"].as_u64().unwrap());
    let (nonce, ciphertext) = seal(d.key.as_ref().unwrap(), &aad, &plain).unwrap();
    edit_file(&path, |f| f["sealed"] = serde_json::to_value(Sealed { nonce, ciphertext }).unwrap());

    let mut back = DocumentFile::open(&path).unwrap();
    let e = back.unlock(PW).unwrap_err();
    assert!(matches!(&e, CoreError::Invalid(m) if m.contains("more than this app can keep")), "{e}");
    assert!(back.is_locked());
}
