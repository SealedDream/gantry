use super::*;
use crate::docfile::new_wrapping_key;
use crate::model::{Connection, Protocol};
use crate::vault::{Credential, CredentialKind};

const OLD_KEY: &str = "0123456789abcdef0123456789abcdef";

fn legacy(dir: &Path) -> (Document, Vault, Uuid) {
    let mut doc = Document::new("Personal");
    let folder = Folder { id: Uuid::new_v4(), name: "Prod".into(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() };
    let fid = folder.id;
    doc.insert(None, Node::Folder(folder)).unwrap();
    let conn = Connection::new("web01", Protocol::Ssh, "web01.example");
    let cid = conn.id;
    doc.insert(Some(fid), Node::Connection(conn)).unwrap();
    doc.insert(None, Node::Connection(Connection::new("db", Protocol::Rdp, "db.example"))).unwrap();
    let saved = Store::new(dir.join(LEGACY_LIBRARY)).save(&doc).unwrap();
    let mut v = Vault::default();
    v.add(Credential { id: Uuid::new_v4(), name: "ops".into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: "ops".into(), password: Secret::new("hunter2") } });
    v.set_inline(cid, CredentialKind::Password { username: "root".into(), password: Secret::new("inline-pw") });
    fs::write(dir.join(LEGACY_VAULT), v.seal(OLD_KEY).unwrap()).unwrap();
    (saved, v, cid)
}

fn old_key() -> Result<Secret> {
    Ok(Secret::new(OLD_KEY))
}

#[test]
fn first_launch_creates_encrypted_personal() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("Documents/Bastion/Personal.bastion");
    let device = new_wrapping_key();
    let (doc, how) = open_or_migrate(t.path(), &path, &device, &|| panic!("no legacy vault")).unwrap();
    assert_eq!(how, Opened::Created);
    assert!(doc.is_device_keyed() && !doc.is_locked());
    let raw = fs::read_to_string(&path).unwrap();
    assert!(raw.contains("\"sealed\"") && !raw.contains("\"contents\""));
    let (again, how) = open_or_migrate(t.path(), &path, &device, &|| panic!("no legacy vault")).unwrap();
    assert_eq!(how, Opened::Existing);
    assert_eq!(again.id(), doc.id());
}

#[test]
fn migration_moves_everything_and_keeps_backup() {
    let t = tempfile::tempdir().unwrap();
    let (tree, vault, cid) = legacy(t.path());
    let path = t.path().join("Personal.bastion");
    let device = new_wrapping_key();
    let (doc, how) = open_or_migrate(t.path(), &path, &device, &old_key).unwrap();
    let Opened::Migrated(r) = how else { panic!("expected migration") };
    assert_eq!((r.folders, r.connections, r.credentials), (1, 2, 2));
    assert!(same_tree(doc.document().unwrap(), &tree));
    let moved = doc.vault().unwrap();
    assert_eq!(moved.ids(), vault.ids());
    assert_eq!(moved.inline(cid).map(|c| c.id), vault.inline(cid).map(|c| c.id));
    // Secrets never appear in the clear on disk.
    let raw = fs::read_to_string(&path).unwrap();
    assert!(!raw.contains("hunter2") && !raw.contains("inline-pw") && !raw.contains("web01"));
    // Old files moved to a kept backup, byte-identical vault.
    let b = r.backup.unwrap();
    assert!(b.join(LEGACY_LIBRARY).is_file() && b.join(LEGACY_VAULT).is_file());
    assert!(!t.path().join(LEGACY_LIBRARY).exists() && !t.path().join(LEGACY_VAULT).exists());
    let restored = Vault::open(&fs::read(b.join(LEGACY_VAULT)).unwrap(), OLD_KEY).unwrap();
    assert_eq!(restored.ids(), vault.ids());
    assert!(t.path().join(MARKER).is_file());
    // Reopen from disk with only the device key: same secrets.
    let (back, how) = open_or_migrate(t.path(), &path, &device, &|| panic!("migrates once")).unwrap();
    assert_eq!(how, Opened::Existing);
    assert_eq!(back.vault().unwrap().to_plain().unwrap().as_slice(), vault.to_plain().unwrap().as_slice());
}

#[test]
fn cancelled_keychain_read_migrates_nothing() {
    let t = tempfile::tempdir().unwrap();
    legacy(t.path());
    let path = t.path().join("Personal.bastion");
    let r = open_or_migrate(t.path(), &path, &new_wrapping_key(), &|| Err(CoreError::Invalid("cancelled".into())));
    assert!(r.is_err());
    assert!(!path.exists());
    assert!(t.path().join(LEGACY_LIBRARY).is_file() && t.path().join(LEGACY_VAULT).is_file());
}

#[test]
fn wrong_device_key_cannot_open() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("Personal.bastion");
    open_or_migrate(t.path(), &path, &new_wrapping_key(), &old_key).unwrap();
    assert!(matches!(open_or_migrate(t.path(), &path, &new_wrapping_key(), &old_key), Err(CoreError::VaultAuth)));
}

#[test]
fn master_password_optional_and_removable() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("Personal.bastion");
    let device = new_wrapping_key();
    let (mut doc, _) = open_or_migrate(t.path(), &path, &device, &old_key).unwrap();
    let mut v = Vault::default();
    v.add(Credential { id: Uuid::new_v4(), name: "x".into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: "u".into(), password: Secret::new("p") } });
    doc.set_vault(&v).unwrap();
    doc.set_password(Some("a long master pw")).unwrap();
    forget_document_key(t.path(), doc.id()).unwrap();
    doc.save().unwrap();
    let mut back = DocumentFile::open(&path).unwrap();
    assert!(back.is_locked() && back.has_password());
    back.unlock("a long master pw").unwrap();
    assert_eq!(back.vault().unwrap().ids(), v.ids());
    back.remove_master_password().unwrap();
    store_document_key(t.path(), &back, &device).unwrap();
    back.save().unwrap();
    let (again, _) = open_or_migrate(t.path(), &path, &device, &old_key).unwrap();
    assert!(again.is_device_keyed() && !again.is_locked());
    assert!(DocumentFile::open(&path).unwrap().unlock("a long master pw").is_err());
}

#[test]
fn device_document_rejects_tampered_wrap_fields() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("Personal.bastion");
    open_or_migrate(t.path(), &path, &new_wrapping_key(), &old_key).unwrap();
    let raw = fs::read_to_string(&path).unwrap().replacen("\"salt\": \"\"", "\"salt\": \"AAAAAAAAAAAAAAAAAAAAAA==\"", 1);
    assert!(DocumentFile::parse(raw.as_bytes()).is_err());
}
