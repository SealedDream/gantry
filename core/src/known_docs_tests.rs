use std::path::PathBuf;

use super::*;
use crate::docfile::DocumentFile;
use crate::model::{Connection, Document, Node, Protocol};

const PW: &str = "document password";

fn saved(dir: &Path, file: &str) -> (PathBuf, Uuid) {
    let mut d = DocumentFile::new(file).unwrap();
    let path = dir.join(format!("{file}.bastion"));
    d.save_as(&path).unwrap();
    (path, d.id())
}

fn record_text(dir: &Path) -> String {
    std::fs::read_to_string(dir.join(KNOWN_FILE)).unwrap()
}

#[test]
fn a_library_is_unknown_until_added_and_known_afterwards_on_this_device() {
    let dir = tempfile::tempdir().unwrap();
    let (id, other) = (Uuid::new_v4(), Uuid::new_v4());
    let known = KnownDocuments::in_dir(dir.path());
    assert!(!known.is_known(id), "first open asks");
    known.add(id).unwrap();
    assert!(known.is_known(id), "second open does not");
    assert!(KnownDocuments::in_dir(dir.path()).is_known(id), "kept across launches");
    assert!(!known.is_known(other), "another document id is asked about");
}

#[test]
fn adding_twice_keeps_one_entry() {
    let dir = tempfile::tempdir().unwrap();
    let id = Uuid::new_v4();
    let known = KnownDocuments::in_dir(dir.path());
    known.add(id).unwrap();
    known.add(id).unwrap();
    assert_eq!(serde_json::from_str::<Vec<String>>(&record_text(dir.path())).unwrap(), vec![id.to_string()]);
}

/// Threat case 11: ids only, as lower-case strings. No name, path, time or secret.
#[test]
fn the_record_is_a_list_of_ids_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let (path, id) = saved(dir.path(), "Secret Customer Name");
    let personal = Uuid::new_v4();
    let known = KnownDocuments::in_dir(dir.path());
    assert!(known.migrate(Some(personal), &[path.clone()]).unwrap());
    let extra = Uuid::new_v4();
    known.add(extra).unwrap();
    let text = record_text(dir.path());
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let list = value.as_array().expect("a JSON list");
    assert_eq!(list.len(), 3);
    for entry in list {
        let s = entry.as_str().expect("each entry is a string");
        assert_eq!(s, s.to_lowercase());
        assert_eq!(Uuid::parse_str(s).unwrap().to_string(), s, "a hyphenated UUID and nothing more");
    }
    assert!(!text.contains("Secret Customer Name") && !text.contains(&*path.to_string_lossy()));
    assert_eq!(list.iter().map(|v| v.as_str().unwrap().to_string()).collect::<Vec<_>>(), vec![personal.to_string(), id.to_string(), extra.to_string()]);
}

#[cfg(unix)]
#[test]
fn the_record_is_readable_by_the_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    KnownDocuments::in_dir(dir.path()).add(Uuid::new_v4()).unwrap();
    let mode = std::fs::metadata(dir.path().join(KNOWN_FILE)).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// Threat case 9: a damaged record means "ask", never "everything is known", and the migration
/// does not replace it.
#[test]
fn a_damaged_record_knows_nothing_and_the_migration_leaves_it_alone() {
    for damaged in ["", "{", "null", "{\"all\":true}", "[\"not-an-id\"]", "[1,2]", "true"] {
        let dir = tempfile::tempdir().unwrap();
        let (path, id) = saved(dir.path(), "Mine");
        std::fs::write(dir.path().join(KNOWN_FILE), damaged).unwrap();
        let known = KnownDocuments::in_dir(dir.path());
        assert!(!known.is_known(id), "{damaged:?}");
        assert!(!known.migrate(Some(id), &[path]).unwrap(), "{damaged:?}: the migration must not run");
        assert_eq!(record_text(dir.path()), damaged, "{damaged:?}: not overwritten");
        assert!(!known.is_known(id), "{damaged:?}");
    }
}

/// One valid id beside a broken entry does not make the record half-trusted.
#[test]
fn a_record_with_one_bad_entry_is_damaged_as_a_whole() {
    let dir = tempfile::tempdir().unwrap();
    let id = Uuid::new_v4();
    std::fs::write(dir.path().join(KNOWN_FILE), format!("[\"{id}\", 7]")).unwrap();
    assert!(!KnownDocuments::in_dir(dir.path()).is_known(id));
}

#[test]
fn a_missing_record_knows_nothing() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!KnownDocuments::in_dir(dir.path()).is_known(Uuid::new_v4()));
    assert!(!KnownDocuments::in_dir(&dir.path().join("no-such-folder")).is_known(Uuid::new_v4()));
}

/// An answer after a damaged record starts a fresh one: the answered library is known, every
/// other one is asked about again.
#[test]
fn adding_after_damage_starts_a_fresh_record() {
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = (Uuid::new_v4(), Uuid::new_v4());
    std::fs::write(dir.path().join(KNOWN_FILE), format!("[\"{old}\", oops")).unwrap();
    let known = KnownDocuments::in_dir(dir.path());
    known.add(new).unwrap();
    assert!(known.is_known(new) && !known.is_known(old));
}

/// Threat case 9: the migration records the Personal library and what was opened before, once.
#[test]
fn the_migration_records_personal_and_earlier_documents_once() {
    let dir = tempfile::tempdir().unwrap();
    let (recent, recent_id) = saved(dir.path(), "Recent");
    let (later, later_id) = saved(dir.path(), "Dropped in later");
    let (_, never_opened) = saved(dir.path(), "Never opened");
    let personal = Uuid::new_v4();
    let gone = dir.path().join("gone.bastion");
    let junk = dir.path().join("junk.bastion");
    std::fs::write(&junk, "not a document").unwrap();
    let known = KnownDocuments::in_dir(dir.path());

    assert!(known.migrate(Some(personal), &[recent.clone(), gone, junk, recent]).unwrap(), "ran");
    assert!(known.is_known(personal) && known.is_known(recent_id));
    assert!(!known.is_known(never_opened), "a file that was never opened is asked about");
    assert_eq!(serde_json::from_str::<Vec<String>>(&record_text(dir.path())).unwrap().len(), 2, "unreadable files skipped, no duplicates");

    assert!(!known.migrate(None, &[later]).unwrap(), "runs once");
    assert!(!known.is_known(later_id));
}

#[test]
fn the_migration_writes_an_empty_record_so_it_never_runs_again() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data"); // not created yet: a first launch
    let (path, id) = saved(dir.path(), "Later");
    let known = KnownDocuments::in_dir(&data);
    assert!(known.migrate(None, &[]).unwrap());
    assert_eq!(serde_json::from_str::<Vec<String>>(&record_text(&data)).unwrap(), Vec::<String>::new());
    assert!(!known.migrate(None, &[path]).unwrap());
    assert!(!known.is_known(id));
}

/// A locked protected document is recorded by the migration from its envelope: no password.
#[test]
fn the_migration_reads_the_id_of_a_locked_document() {
    let dir = tempfile::tempdir().unwrap();
    let mut d = DocumentFile::new("Team").unwrap();
    d.set_password(Some(PW)).unwrap();
    let path = dir.path().join("Team.bastion");
    d.save_as(&path).unwrap();
    let known = KnownDocuments::in_dir(dir.path());
    assert!(known.migrate(None, &[path]).unwrap());
    assert!(known.is_known(d.id()));
    assert!(!record_text(dir.path()).contains(PW));
}

/// When the record cannot be written the migration reports it and nothing is waved through;
/// it runs again at the next start.
#[cfg(unix)]
#[test]
fn a_migration_that_cannot_write_fails_and_knows_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o500)).unwrap();
    let id = Uuid::new_v4();
    let known = KnownDocuments::in_dir(&data);
    assert!(known.migrate(Some(id), &[]).is_err());
    assert!(!known.is_known(id));
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(known.migrate(Some(id), &[]).unwrap(), "retried at the next start");
    assert!(known.is_known(id));
}

#[test]
fn the_record_keeps_the_newest_ids_when_full() {
    let dir = tempfile::tempdir().unwrap();
    let ids: Vec<Uuid> = (0..MAX_KNOWN).map(|_| Uuid::new_v4()).collect();
    std::fs::write(dir.path().join(KNOWN_FILE), serde_json::to_vec(&ids).unwrap()).unwrap();
    let known = KnownDocuments::in_dir(dir.path());
    assert!(known.is_known(ids[0]));
    let newest = Uuid::new_v4();
    known.add(newest).unwrap();
    assert!(known.is_known(newest) && known.is_known(ids[1]) && known.is_known(ids[MAX_KNOWN - 1]));
    assert!(!known.is_known(ids[0]), "the oldest is dropped and asked about once more");
    assert_eq!(serde_json::from_str::<Vec<String>>(&record_text(dir.path())).unwrap().len(), MAX_KNOWN);
}

/// A record longer than the bound (written by hand or by a later build) is read as its newest part.
#[test]
fn an_overlong_record_is_read_as_its_newest_ids() {
    let dir = tempfile::tempdir().unwrap();
    let ids: Vec<Uuid> = (0..MAX_KNOWN + 5).map(|_| Uuid::new_v4()).collect();
    std::fs::write(dir.path().join(KNOWN_FILE), serde_json::to_vec(&ids).unwrap()).unwrap();
    let known = KnownDocuments::in_dir(dir.path());
    assert!(!known.is_known(ids[4]) && known.is_known(ids[5]) && known.is_known(ids[MAX_KNOWN + 4]));
}

// ---------------------------------------------------------------------------------------------
// `DocumentFile::mark_as_received`

/// A document as a sender would write it: references to the reader's credentials that claim to
/// be confirmed already.
fn senders_document() -> (Document, Uuid, Uuid) {
    let (cred, other) = (Uuid::new_v4(), Uuid::new_v4());
    let mut doc = Document::new("Sent");
    let mut c = Connection::new("web", Protocol::Ssh, "web.sender.example");
    c.settings.credential_id = Some(cred);
    c.settings.logins = vec![other];
    c.settings.credential_unconfirmed = Some(false);
    c.settings.credential_confirmed = vec![cred, other];
    let id = c.id;
    doc.insert(None, Node::Connection(c)).unwrap();
    doc.insert(None, Node::Connection(Connection::new("plain", Protocol::Ssh, "plain.sender.example"))).unwrap();
    doc.root.defaults.credential_name = Some("Admin".into());
    let rdp = doc.type_defaults.entry(Protocol::Rdp).or_default();
    rdp.credential_id = Some(cred);
    rdp.credential_confirmed = vec![cred];
    (doc, id, cred)
}

fn connection(doc: &Document, name: &str) -> Connection {
    doc.connections().into_iter().find(|r| r.connection.name == name).unwrap().connection
}

#[test]
fn mark_as_received_marks_every_reference_and_drops_what_the_file_says() {
    let (doc, _, _) = senders_document();
    let mut file = DocumentFile::from_document(doc);
    file.mark_as_received(true).unwrap();
    let d = file.document().unwrap();
    let web = connection(d, "web").settings;
    assert_eq!(web.credential_unconfirmed, Some(true));
    assert!(web.credential_confirmed.is_empty(), "a pre-filled confirmed list does not count");
    assert_eq!(d.root.defaults.credential_unconfirmed, Some(true), "a folder's named login");
    let rdp = &d.type_defaults[&Protocol::Rdp];
    assert_eq!((rdp.credential_unconfirmed, rdp.credential_confirmed.len()), (Some(true), 0), "type defaults");
    assert_eq!(connection(d, "plain").settings.credential_unconfirmed, None, "no reference, no mark");
}

#[test]
fn mark_as_received_sets_the_changed_flag_only_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let (doc, _, _) = senders_document();
    let path = dir.path().join("Sent.bastion");
    DocumentFile::from_document(doc).save_as(&path).unwrap();

    let mut in_memory = DocumentFile::open(&path).unwrap();
    in_memory.mark_as_received(false).unwrap();
    assert!(!in_memory.is_dirty(), "an in-memory mark is not a change to save");
    assert_eq!(connection(in_memory.document().unwrap(), "web").settings.credential_unconfirmed, Some(true));

    let mut kept = DocumentFile::open(&path).unwrap();
    kept.mark_as_received(true).unwrap();
    assert!(kept.is_dirty());
    kept.save().unwrap();
    let reread = DocumentFile::open(&path).unwrap();
    assert_eq!(connection(reread.document().unwrap(), "web").settings.credential_unconfirmed, Some(true), "saved with the marks");

    // An in-memory mark never clears a change that was already pending.
    let mut pending = DocumentFile::open(&path).unwrap();
    pending.rename("Renamed").unwrap();
    pending.mark_as_received(false).unwrap();
    assert!(pending.is_dirty());
}

#[test]
fn mark_as_received_fails_on_a_locked_document() {
    let dir = tempfile::tempdir().unwrap();
    let (doc, _, _) = senders_document();
    let mut d = DocumentFile::from_document(doc);
    d.set_password(Some(PW)).unwrap();
    let path = dir.path().join("Sent.bastion");
    d.save_as(&path).unwrap();
    let mut locked = DocumentFile::open(&path).unwrap();
    assert!(locked.is_locked());
    assert!(locked.mark_as_received(false).is_err());
    locked.unlock(PW).unwrap();
    locked.mark_as_received(false).unwrap();
    assert_eq!(connection(locked.document().unwrap(), "web").settings.credential_unconfirmed, Some(true));
}

/// Threat cases 1 and 2 at the core: after the mark, the sender's reference is offered, not used.
#[test]
fn a_marked_reference_is_offered_not_used() {
    use crate::logins::{login_candidates, LoginPurpose};
    use crate::vault::{Credential, CredentialKind, Secret, Vault};
    let (doc, id, cred) = senders_document();
    let mut vault = Vault::default();
    vault.entries.insert(cred, Credential { id: cred, name: "Admin".into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: "admin".into(), password: Secret::new("generated-test-value") } });
    let mut file = DocumentFile::from_document(doc);
    let auto = |f: &DocumentFile| login_candidates(f.document().unwrap(), &vault, id, LoginPurpose::Any).unwrap().iter().map(|c| c.auto_use).collect::<Vec<_>>();
    assert_eq!(auto(&file), vec![true], "what the file claims, before the mark");
    file.mark_as_received(false).unwrap();
    assert_eq!(auto(&file), vec![false]);
}
