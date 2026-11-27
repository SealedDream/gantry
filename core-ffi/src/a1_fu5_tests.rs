//! A1-CORE-01-FU5 through the Mac bridge: a library opened by path is asked about once per
//! device and remembered by document id. Until the user answers, and after "Someone sent it",
//! a login the file names is offered, not used, whatever the file says about confirmation.
//! The threat-case numbers are the packet's. Generated data only.
use std::path::Path;

use bastion_core::known_docs::{KnownDocuments, KNOWN_FILE};
use bastion_core::model::{Connection, Node, Protocol, Settings};

use super::*;
use crate::CredentialVault;

const PW: &str = "document password";

/// One device: its data folder and its vault with a saved login called "Admin".
struct Device {
    dir: tempfile::TempDir,
    data: String,
    vault: CredentialVault,
    admin: Uuid,
}

fn device() -> Device {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data").display().to_string();
    let vault = CredentialVault::open_ephemeral(dir.path().join("c.vault").display().to_string()).unwrap();
    let admin = vault.save_password(None, "Admin".into(), None, "admin".into(), "generated-admin-value".into()).unwrap();
    Device { dir, data, vault, admin: admin.parse().unwrap() }
}

/// A file written somewhere else: one connection that names the reader's "Admin" login, with
/// whatever the writer chose to say about confirmation (`claim`).
struct Sent {
    path: String,
    id: Uuid,
    connection: String,
}

fn sent(dev: &Device, name: &str, password: Option<&str>, claim: impl FnOnce(&mut Settings, Uuid)) -> Sent {
    let mut doc = Document::new(name);
    let mut c = Connection::new("web", Protocol::Ssh, "web.sender.example");
    c.settings.credential_id = Some(dev.admin);
    claim(&mut c.settings, dev.admin);
    let connection = c.id.to_string();
    doc.insert(None, Node::Connection(c)).unwrap();
    let mut file = DocumentFile::from_document(doc);
    if let Some(pw) = password {
        file.set_password(Some(pw)).unwrap();
    }
    let path = dev.dir.path().join(format!("{name}.bastion"));
    file.save_as(&path).unwrap();
    Sent { path: path.display().to_string(), id: file.id(), connection }
}

fn says_confirmed(s: &mut Settings, _: Uuid) {
    s.credential_unconfirmed = Some(false);
}

fn says_nothing(_: &mut Settings, _: Uuid) {}

fn open(dev: &Device, file: &Sent) -> Arc<BastionDocument> {
    BastionDocument::open(file.path.clone(), dev.data.clone()).unwrap()
}

/// Whether each login offered for the file's connection would be used without asking.
fn auto_use(dev: &Device, d: &BastionDocument, file: &Sent) -> Vec<bool> {
    dev.vault.login_candidates(d.library().unwrap(), file.connection.clone(), false).unwrap().into_iter().map(|l| l.auto_use).collect()
}

fn record(dev: &Device) -> Vec<String> {
    serde_json::from_slice(&std::fs::read(Path::new(&dev.data).join(KNOWN_FILE)).unwrap()).unwrap()
}

fn audit_log(dev: &Device) -> String {
    std::fs::read_to_string(Path::new(&dev.data).join("audit.jsonl")).unwrap()
}

/// Threat case 1: the file says its reference is confirmed. It is not used before any answer.
#[test]
fn case_01_an_unknown_file_is_asked_about_and_its_login_is_not_used_before_the_answer() {
    let dev = device();
    let file = sent(&dev, "Sent", None, says_confirmed);
    let d = open(&dev, &file);
    assert_eq!(d.origin(), DocumentOrigin::Unknown);
    assert_eq!(auto_use(&dev, &d, &file), vec![false]);
    assert!(!d.info().dirty, "the mark is in memory only");
    assert!(!KnownDocuments::in_dir(Path::new(&dev.data)).is_known(file.id), "opening records nothing");
}

/// Threat case 2: a pre-filled confirmed list does not count either.
#[test]
fn case_02_a_prefilled_confirmed_list_does_not_count() {
    let dev = device();
    let file = sent(&dev, "Sent", None, |s, admin| {
        s.credential_unconfirmed = Some(true);
        s.credential_confirmed = vec![admin];
    });
    let d = open(&dev, &file);
    assert_eq!(d.origin(), DocumentOrigin::Unknown);
    assert_eq!(auto_use(&dev, &d, &file), vec![false]);
}

/// Threat case 3: "Someone sent it" keeps the marks with the next save and is not asked again.
#[test]
fn case_03_someone_sent_it_saves_the_marks_and_is_known_afterwards() {
    let dev = device();
    let file = sent(&dev, "Sent", None, says_confirmed);
    let d = open(&dev, &file);
    d.answer_origin(false).unwrap();
    assert_eq!(d.origin(), DocumentOrigin::Known);
    assert!(d.info().dirty, "the marks are a change to save");
    assert_eq!(auto_use(&dev, &d, &file), vec![false]);
    d.save().unwrap();
    drop(d);

    let again = open(&dev, &file);
    assert_eq!(again.origin(), DocumentOrigin::Known, "asked once per device");
    assert_eq!(auto_use(&dev, &again, &file), vec![false], "the marks were saved");
    // The user's own choice still confirms it, as after an import.
    dev.vault.add_login(again.library().unwrap(), file.connection.clone(), dev.admin.to_string()).unwrap();
    assert_eq!(auto_use(&dev, &again, &file), vec![true]);
}

/// Threat case 4: "I made it" opens the library as it is and is not asked again.
#[test]
fn case_04_i_made_it_uses_the_logins_as_before_and_is_known_afterwards() {
    let dev = device();
    let file = sent(&dev, "Mine", None, says_nothing);
    let before = std::fs::read(&file.path).unwrap();
    let d = open(&dev, &file);
    let handed_out = d.library().unwrap(); // a view taken while the question is up
    assert_eq!(auto_use(&dev, &d, &file), vec![false]);
    d.answer_origin(true).unwrap();
    assert_eq!(d.origin(), DocumentOrigin::Known);
    assert_eq!(auto_use(&dev, &d, &file), vec![true]);
    assert!(Arc::ptr_eq(&handed_out, &d.library().unwrap()), "the same view, without the marks");
    assert!(!d.info().dirty);
    assert_eq!(std::fs::read(&file.path).unwrap(), before, "nothing was written to the library");
    drop(d);

    let again = open(&dev, &file);
    assert_eq!(again.origin(), DocumentOrigin::Known);
    assert_eq!(auto_use(&dev, &again, &file), vec![true]);
}

/// "I made it" keeps what the user's own library says about parts imported into it earlier
/// (FU1): the file is read again, the in-memory marks are not undone by guessing.
#[test]
fn i_made_it_keeps_the_librarys_own_import_confirmations() {
    let dev = device();
    let confirmed = sent(&dev, "Confirmed", None, |s, admin| {
        s.credential_unconfirmed = Some(true);
        s.credential_confirmed = vec![admin];
    });
    let d = open(&dev, &confirmed);
    d.answer_origin(true).unwrap();
    assert_eq!(auto_use(&dev, &d, &confirmed), vec![true], "confirmed after an import, before this rule");

    let pending = sent(&dev, "Pending", None, |s, _| s.credential_unconfirmed = Some(true));
    let d = open(&dev, &pending);
    d.answer_origin(true).unwrap();
    assert_eq!(auto_use(&dev, &d, &pending), vec![false], "an imported part still waiting stays waiting");
}

/// Threat case 5: closing the question records nothing, writes nothing, and asks again.
#[test]
fn case_05_closing_the_question_asks_again_and_leaves_the_file_unchanged() {
    let dev = device();
    let file = sent(&dev, "Sent", None, says_confirmed);
    let before = std::fs::read(&file.path).unwrap();
    let d = open(&dev, &file);
    assert_eq!(auto_use(&dev, &d, &file), vec![false], "treated as sent for this session");
    drop(d);
    assert_eq!(std::fs::read(&file.path).unwrap(), before, "byte for byte");
    assert!(record(&dev).is_empty());

    let again = open(&dev, &file);
    assert_eq!(again.origin(), DocumentOrigin::Unknown);
    assert_eq!(auto_use(&dev, &again, &file), vec![false]);
}

/// Threat case 6: a known library that is copied or moved keeps its id and is not asked about.
#[test]
fn case_06_a_copied_or_moved_known_library_is_known() {
    let dev = device();
    let file = sent(&dev, "Mine", None, says_nothing);
    open(&dev, &file).answer_origin(true).unwrap();

    let copy = Sent { path: dev.dir.path().join("Copy of Mine.bastion").display().to_string(), id: file.id, connection: file.connection.clone() };
    std::fs::copy(&file.path, &copy.path).unwrap();
    let d = open(&dev, &copy);
    assert_eq!(d.origin(), DocumentOrigin::Known);
    assert_eq!(auto_use(&dev, &d, &copy), vec![true]);

    let moved = Sent { path: dev.dir.path().join("elsewhere.bastion").display().to_string(), id: file.id, connection: file.connection.clone() };
    std::fs::rename(&file.path, &moved.path).unwrap();
    assert_eq!(open(&dev, &moved).origin(), DocumentOrigin::Known);
}

/// Threat case 7: another document put at the path of a known library is asked about.
#[test]
fn case_07_a_different_file_at_a_known_path_is_asked_about() {
    let dev = device();
    let mine = sent(&dev, "Mine", None, says_nothing);
    open(&dev, &mine).answer_origin(true).unwrap();

    let theirs = sent(&dev, "Theirs", None, says_confirmed);
    std::fs::rename(&theirs.path, &mine.path).unwrap();
    let swapped = Sent { path: mine.path.clone(), ..theirs };
    let d = open(&dev, &swapped);
    assert_eq!(d.origin(), DocumentOrigin::Unknown, "the path is in Recents, the id is not known");
    assert_eq!(auto_use(&dev, &d, &swapped), vec![false]);
    // The same through the restore at launch, which does not touch Recents.
    let restored = BastionDocument::reopen(swapped.path.clone(), dev.data.clone()).unwrap();
    assert_eq!(restored.origin(), DocumentOrigin::Unknown);
    assert_eq!(auto_use(&dev, &restored, &swapped), vec![false]);
}

/// Threat case 8: a device-keyed document is always known and needs no record entry.
#[test]
fn case_08_a_device_keyed_document_is_known_without_a_record_entry() {
    let dev = device();
    let mut file = DocumentFile::new_device(Document::new("Made here"));
    let path = dev.dir.path().join("Made here.bastion");
    file.save_as(&path).unwrap();
    let d = BastionDocument::open(path.display().to_string(), dev.data.clone()).unwrap();
    assert!(d.info().locked);
    assert_eq!(d.origin(), DocumentOrigin::Known);
    assert!(!KnownDocuments::in_dir(Path::new(&dev.data)).is_known(file.id()), "no record entry");
}

/// Threat case 9: the migration records the Personal library, Recents and the documents
/// restored at launch, once; a document that was never opened is asked about.
#[test]
fn case_09_the_migration_records_what_was_opened_before_and_runs_once() {
    let dev = device();
    let recent = sent(&dev, "Recent", None, says_nothing);
    let restored = sent(&dev, "Restored", None, says_nothing);
    let never = sent(&dev, "Never opened", None, says_confirmed);
    let later = sent(&dev, "Later", None, says_nothing);
    RecentDocuments::new(Path::new(&dev.data).join(RECENT_FILE)).add(Path::new(&recent.path)).unwrap();
    let personal = Uuid::new_v4();

    assert!(migrate_known_documents(dev.data.clone(), Some(personal.to_string()), vec![restored.path.clone()]).unwrap());
    assert_eq!(record(&dev), vec![personal.to_string(), recent.id.to_string(), restored.id.to_string()]);
    assert!(!migrate_known_documents(dev.data.clone(), None, vec![later.path.clone()]).unwrap(), "runs once");

    let d = open(&dev, &recent);
    assert_eq!(d.origin(), DocumentOrigin::Known);
    assert_eq!(auto_use(&dev, &d, &recent), vec![true], "nothing changes for a library opened before the update");
    assert_eq!(BastionDocument::reopen(restored.path.clone(), dev.data.clone()).unwrap().origin(), DocumentOrigin::Known);
    assert_eq!(open(&dev, &never).origin(), DocumentOrigin::Unknown);
    assert_eq!(open(&dev, &later).origin(), DocumentOrigin::Unknown);
    assert!(migrate_known_documents(dev.data.clone(), Some("not an id".into()), vec![]).is_err());
}

/// Threat case 9: a damaged record is not overwritten by the migration and knows nothing.
#[test]
fn case_09_a_damaged_record_is_left_alone_and_every_library_is_asked_about() {
    let dev = device();
    let file = sent(&dev, "Mine", None, says_confirmed);
    RecentDocuments::new(Path::new(&dev.data).join(RECENT_FILE)).add(Path::new(&file.path)).unwrap();
    let damaged = format!("[\"{}\", ", file.id);
    let record_path = Path::new(&dev.data).join(KNOWN_FILE);
    std::fs::write(&record_path, &damaged).unwrap();

    assert!(!migrate_known_documents(dev.data.clone(), Some(file.id.to_string()), vec![file.path.clone()]).unwrap());
    let d = open(&dev, &file);
    assert_eq!(d.origin(), DocumentOrigin::Unknown);
    assert_eq!(auto_use(&dev, &d, &file), vec![false]);
    assert_eq!(std::fs::read_to_string(&record_path).unwrap(), damaged, "not overwritten");
    // The answer starts a fresh record.
    d.answer_origin(false).unwrap();
    assert_eq!(record(&dev), vec![file.id.to_string()]);
}

/// An app that has not called the migration yet: the first open writes the record from
/// Recents before the opened document is added there, so a library opened before the update
/// is not asked about and a file opened for the first time is.
#[test]
fn without_the_launch_migration_the_first_open_records_recents_only() {
    let dev = device();
    let before = sent(&dev, "Opened before", None, says_nothing);
    let new = sent(&dev, "New", None, says_confirmed);
    RecentDocuments::new(Path::new(&dev.data).join(RECENT_FILE)).add(Path::new(&before.path)).unwrap();

    let d = open(&dev, &new);
    assert_eq!(d.origin(), DocumentOrigin::Unknown, "the file being opened is not waved through");
    assert_eq!(record(&dev), vec![before.id.to_string()]);
    let known = open(&dev, &before);
    assert_eq!(known.origin(), DocumentOrigin::Known);
    assert_eq!(auto_use(&dev, &known, &before), vec![true]);
    drop(d);
    assert_eq!(open(&dev, &new).origin(), DocumentOrigin::Unknown, "being in Recents now does not make it known");
}

/// Threat case 10: a document made here is recorded when it first gets a file.
#[test]
fn case_10_a_new_documents_id_is_recorded_on_its_first_save() {
    let dev = device();
    let d = BastionDocument::create("New".into(), dev.data.clone()).unwrap();
    assert_eq!(d.origin(), DocumentOrigin::Known);
    let path = dev.dir.path().join("New.bastion").display().to_string();
    d.save_as(path.clone()).unwrap();
    assert_eq!(record(&dev), vec![d.info().id]);
    assert_eq!(BastionDocument::open(path, dev.data.clone()).unwrap().origin(), DocumentOrigin::Known);

    // Save As of an unanswered library does not answer for it.
    let file = sent(&dev, "Sent", None, says_confirmed);
    let unknown = open(&dev, &file);
    unknown.save_as(dev.dir.path().join("Sent copy.bastion").display().to_string()).unwrap();
    assert_eq!(unknown.origin(), DocumentOrigin::Unknown);
    assert!(!record(&dev).contains(&file.id.to_string()));
}

/// Threat case 11: the record holds ids only; the audit entries hold no id.
#[test]
fn case_11_the_record_holds_only_ids_and_the_audit_log_holds_none() {
    let dev = device();
    let sent_file = sent(&dev, "Customer Alpha", Some(PW), says_confirmed);
    let made_file = sent(&dev, "Mine", None, says_nothing);
    let closed_file = sent(&dev, "Closed", None, says_confirmed);
    let d = open(&dev, &sent_file);
    d.unlock(PW.into()).unwrap();
    d.answer_origin(false).unwrap();
    d.save().unwrap();
    open(&dev, &made_file).answer_origin(true).unwrap();
    drop(open(&dev, &closed_file));
    drop(open(&dev, &made_file));

    let text = std::fs::read_to_string(Path::new(&dev.data).join(KNOWN_FILE)).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let list = value.as_array().expect("a JSON list");
    assert_eq!(list.len(), 2);
    for entry in list {
        let s = entry.as_str().expect("a string");
        assert_eq!(s.parse::<Uuid>().unwrap().to_string(), s, "a lower-case id and nothing more");
    }
    for secret_or_detail in [PW, "generated-admin-value", "Customer Alpha", "Admin", "bastion", "web.sender.example"] {
        assert!(!text.contains(secret_or_detail), "{secret_or_detail}");
    }

    let log = audit_log(&dev);
    for answer in ["known", "asked-made", "asked-sent", "asked-closed"] {
        let line = log.lines().find(|l| l.contains("document.origin") && l.contains(&format!("\"{answer}\""))).unwrap_or_else(|| panic!("no document.origin entry for {answer}"));
        for id in [sent_file.id, made_file.id, closed_file.id] {
            assert!(!line.contains(&id.to_string()), "{answer}: no document id");
        }
    }
    assert!(!log.contains(PW) && !log.contains("generated-admin-value"));
}

/// Threat case 12: a locked protected library is marked on unlock, before the tree is returned,
/// and again after a lock that discarded the marked contents.
#[test]
fn case_12_a_protected_library_is_marked_on_unlock_before_the_tree_is_returned() {
    let dev = device();
    let file = sent(&dev, "Sent", Some(PW), says_confirmed);
    let before = std::fs::read(&file.path).unwrap();
    let d = open(&dev, &file);
    assert!(d.info().locked);
    assert_eq!(d.origin(), DocumentOrigin::Unknown);
    assert!(d.answer_origin(true).is_err() && d.answer_origin(false).is_err(), "answered after it is unlocked");
    assert_eq!(d.origin(), DocumentOrigin::Unknown);

    d.unlock(PW.into()).unwrap();
    assert_eq!(auto_use(&dev, &d, &file), vec![false]);
    assert!(d.lock().unwrap());
    d.unlock(PW.into()).unwrap();
    assert_eq!(auto_use(&dev, &d, &file), vec![false], "marked again after a lock");
    assert_eq!(std::fs::read(&file.path).unwrap(), before, "locking an unanswered library writes nothing");

    d.answer_origin(false).unwrap();
    d.save().unwrap();
    drop(d);
    let again = open(&dev, &file);
    assert_eq!(again.origin(), DocumentOrigin::Known);
    again.unlock(PW.into()).unwrap();
    assert_eq!(auto_use(&dev, &again, &file), vec![false], "the marks were saved in the sealed contents");
}

#[test]
fn i_made_it_on_a_protected_library_reads_the_sealed_contents_again() {
    let dev = device();
    let file = sent(&dev, "Mine", Some(PW), says_nothing);
    let d = open(&dev, &file);
    d.unlock(PW.into()).unwrap();
    assert_eq!(auto_use(&dev, &d, &file), vec![false]);
    d.answer_origin(true).unwrap();
    assert!(!d.info().locked && !d.info().dirty);
    assert_eq!(auto_use(&dev, &d, &file), vec![true]);
    assert_eq!(d.credentials().unwrap().len(), 0);
    assert!(d.lock().unwrap());
    d.unlock(PW.into()).unwrap();
    assert_eq!(auto_use(&dev, &d, &file), vec![true], "known now: not marked on unlock");
}

/// A login the user confirmed while the question was closed survives a lock and unlock: the
/// confirmation was saved, so the contents are not marked a second time.
#[test]
fn a_login_confirmed_while_unanswered_survives_a_lock() {
    let dev = device();
    let file = sent(&dev, "Sent", Some(PW), says_confirmed);
    let d = open(&dev, &file);
    d.unlock(PW.into()).unwrap();
    let lib = d.library().unwrap();
    dev.vault.add_login(lib.clone(), file.connection.clone(), dev.admin.to_string()).unwrap();
    lib.save().unwrap();
    assert_eq!(auto_use(&dev, &d, &file), vec![true]);
    assert!(d.lock().unwrap());
    d.unlock(PW.into()).unwrap();
    assert_eq!(d.origin(), DocumentOrigin::Unknown, "still asked about next time");
    assert_eq!(auto_use(&dev, &d, &file), vec![true]);
}

/// "I made it" after the library was edited or saved with the marks is refused: reading the
/// file again would lose the edit or bring the marks back. Nothing is recorded.
#[test]
fn i_made_it_is_refused_once_the_library_was_changed() {
    let dev = device();
    let file = sent(&dev, "Sent", None, says_confirmed);

    let d = open(&dev, &file);
    let lib = d.library().unwrap();
    lib.add_connection(None, "db".into(), "ssh".into(), "db.example".into(), None, None).unwrap();
    assert!(d.answer_origin(true).is_err(), "an unsaved edit in the working copy");
    lib.save().unwrap();
    assert!(d.answer_origin(true).is_err(), "saved with the marks");
    assert_eq!(d.origin(), DocumentOrigin::Unknown);
    assert!(record(&dev).is_empty());
    assert_eq!(auto_use(&dev, &d, &file), vec![false]);

    d.answer_origin(false).unwrap();
    assert_eq!(d.origin(), DocumentOrigin::Known);
    assert_eq!(d.library().unwrap().tree().connections.len(), 2, "the edit is kept");
}

/// An answer for a known library changes nothing.
#[test]
fn a_known_library_takes_no_answer() {
    let dev = device();
    let d = BastionDocument::create("New".into(), dev.data.clone()).unwrap();
    d.answer_origin(false).unwrap();
    d.answer_origin(true).unwrap();
    assert!(!Path::new(&dev.data).join(KNOWN_FILE).exists());
}
