//! A1-CORE-01-FU5 over the C ABI (ABI 108): `bastion_document_origin`,
//! `bastion_document_answer_origin` and `bastion_known_documents_migrate`, as the Windows app
//! calls them. The threat-case numbers are the packet's. Generated data only.
use std::ffi::{CStr, CString};
use std::path::Path;
use std::ptr::null;
use std::sync::Arc;

use bastion_core::docfile::{DocumentFile, RecentDocuments};
use bastion_core::known_docs::KNOWN_FILE;
use bastion_core::model::{Connection, Document, Node, Protocol};
use bastion_ffi::CredentialVault;
use uuid::Uuid;

use super::*;
use crate::credentials::BastionCredentials;
use crate::credtree::bastion_credentials_logins_json;
use crate::{bastion_library_free, bastion_string_free};

const PW: &[u8] = b"document password";

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// One device: its data folder and a vault with a saved login called "Admin".
struct Device {
    dir: tempfile::TempDir,
    data: CString,
    vault: BastionCredentials,
    admin: Uuid,
}

fn device() -> Device {
    let dir = tempfile::tempdir().unwrap();
    let data = c(dir.path().join("data").to_str().unwrap());
    let vault = CredentialVault::open_ephemeral(dir.path().join("c.vault").to_string_lossy().into_owned()).unwrap();
    let admin = vault.save_password(None, "Admin".into(), None, "admin".into(), "generated-admin-value".into()).unwrap().parse().unwrap();
    Device { dir, data, vault: BastionCredentials(Arc::new(vault)), admin }
}

impl Device {
    fn data_dir(&self) -> &Path {
        Path::new(self.data.to_str().unwrap())
    }

    fn record(&self) -> Vec<String> {
        serde_json::from_slice(&std::fs::read(self.data_dir().join(KNOWN_FILE)).unwrap()).unwrap()
    }
}

/// A file written somewhere else: one connection naming the reader's "Admin" login, which
/// the file claims is confirmed (`claims_confirmed`) or says nothing about.
struct Sent {
    path: CString,
    id: Uuid,
    connection: CString,
}

fn sent(dev: &Device, name: &str, protected: bool, claims_confirmed: bool) -> Sent {
    let mut doc = Document::new(name);
    let mut conn = Connection::new("web", Protocol::Ssh, "web.sender.example");
    conn.settings.credential_id = Some(dev.admin);
    if claims_confirmed {
        conn.settings.credential_unconfirmed = Some(false);
        conn.settings.credential_confirmed = vec![dev.admin];
    }
    let connection = c(&conn.id.to_string());
    doc.insert(None, Node::Connection(conn)).unwrap();
    let mut file = DocumentFile::from_document(doc);
    if protected {
        file.set_password(Some(std::str::from_utf8(PW).unwrap())).unwrap();
    }
    let path = dev.dir.path().join(format!("{name}.bastion"));
    file.save_as(&path).unwrap();
    Sent { path: c(path.to_str().unwrap()), id: file.id(), connection }
}

unsafe fn open(dev: &Device, file: &Sent) -> *mut BastionDocumentHandle {
    let mut err = null_mut();
    let d = bastion_document_open(file.path.as_ptr(), dev.data.as_ptr(), &mut err);
    assert!(!d.is_null() && err.is_null());
    d
}

unsafe fn origin(d: *const BastionDocumentHandle) -> i32 {
    let mut err = null_mut();
    let o = bastion_document_origin(d, &mut err);
    assert!(err.is_null());
    o
}

unsafe fn answer(d: *const BastionDocumentHandle, made_by_me: i32) -> i32 {
    let mut err = null_mut();
    let r = bastion_document_answer_origin(d, made_by_me, &mut err);
    assert_eq!(r == 0, err.is_null(), "an error message exactly when it fails");
    if !err.is_null() {
        bastion_string_free(err);
    }
    r
}

/// `autoUse` of each login offered for the file's connection.
unsafe fn auto_use(dev: &Device, d: *const BastionDocumentHandle, file: &Sent) -> Vec<bool> {
    let mut err = null_mut();
    let lib = bastion_document_library(d, &mut err);
    assert!(!lib.is_null());
    let json = bastion_credentials_logins_json(&dev.vault, lib, file.connection.as_ptr(), 0, &mut err);
    assert!(!json.is_null());
    let list: Value = serde_json::from_str(CStr::from_ptr(json).to_str().unwrap()).unwrap();
    bastion_string_free(json);
    bastion_library_free(lib);
    list.as_array().unwrap().iter().map(|l| l["autoUse"].as_bool().unwrap()).collect()
}

unsafe fn dirty(d: *const BastionDocumentHandle) -> bool {
    let mut err = null_mut();
    let info = bastion_document_info_json(d, &mut err);
    let v: Value = serde_json::from_str(CStr::from_ptr(info).to_str().unwrap()).unwrap();
    bastion_string_free(info);
    v["dirty"].as_bool().unwrap()
}

unsafe fn migrate(dev: &Device, personal: Option<&str>, restore_json: Option<&str>) -> i32 {
    let (personal, restore) = (personal.map(c), restore_json.map(c));
    let mut err = null_mut();
    let r = bastion_known_documents_migrate(dev.data.as_ptr(), personal.as_ref().map_or(null(), |p| p.as_ptr()), restore.as_ref().map_or(null(), |p| p.as_ptr()), &mut err);
    assert_eq!(r >= 0, err.is_null());
    if !err.is_null() {
        bastion_string_free(err);
    }
    r
}

/// Threat cases 1, 2 and 3.
#[test]
fn an_unknown_library_is_asked_about_and_someone_sent_it_keeps_the_marks() {
    let dev = device();
    let file = sent(&dev, "Sent", false, true);
    unsafe {
        let d = open(&dev, &file);
        assert_eq!(origin(d), 1);
        assert_eq!(auto_use(&dev, d, &file), vec![false], "not used before any answer, whatever the file claims");
        assert!(!dirty(d));
        assert_eq!(answer(d, 2), -1, "only 0 and 1 are answers");
        assert_eq!(origin(d), 1);
        assert_eq!(answer(d, 0), 0);
        assert_eq!(origin(d), 0);
        assert!(dirty(d), "the marks are a change to save");
        let mut err = null_mut();
        assert_eq!(bastion_document_save(d, null(), &mut err), 0);
        bastion_document_free(d);

        let again = open(&dev, &file);
        assert_eq!(origin(again), 0, "asked once per device");
        assert_eq!(auto_use(&dev, again, &file), vec![false], "the marks were saved");
        bastion_document_free(again);
    }
    assert_eq!(dev.record(), vec![file.id.to_string()]);
}

/// Threat cases 4, 6 and 7.
#[test]
fn i_made_it_is_known_afterwards_by_id_not_by_path() {
    let dev = device();
    let mine = sent(&dev, "Mine", false, false);
    let before = std::fs::read(mine.path.to_str().unwrap()).unwrap();
    unsafe {
        let d = open(&dev, &mine);
        assert_eq!((origin(d), auto_use(&dev, d, &mine)), (1, vec![false]));
        assert_eq!(answer(d, 1), 0);
        assert_eq!((origin(d), auto_use(&dev, d, &mine)), (0, vec![true]));
        assert!(!dirty(d));
        bastion_document_free(d);
        assert_eq!(std::fs::read(mine.path.to_str().unwrap()).unwrap(), before, "nothing written to the library");

        // A copy at another path keeps the id.
        let copy_path = dev.dir.path().join("Copy.bastion");
        std::fs::copy(mine.path.to_str().unwrap(), &copy_path).unwrap();
        let copy = Sent { path: c(copy_path.to_str().unwrap()), id: mine.id, connection: mine.connection.clone() };
        let d = open(&dev, &copy);
        assert_eq!((origin(d), auto_use(&dev, d, &copy)), (0, vec![true]));
        bastion_document_free(d);

        // Another document at the known path does not.
        let theirs = sent(&dev, "Theirs", false, true);
        std::fs::rename(theirs.path.to_str().unwrap(), mine.path.to_str().unwrap()).unwrap();
        let swapped = Sent { path: mine.path.clone(), ..theirs };
        let d = open(&dev, &swapped);
        assert_eq!((origin(d), auto_use(&dev, d, &swapped)), (1, vec![false]));
        bastion_document_free(d);
    }
}

/// Threat case 5.
#[test]
fn closing_the_question_records_nothing_and_asks_again() {
    let dev = device();
    let file = sent(&dev, "Sent", false, true);
    let before = std::fs::read(file.path.to_str().unwrap()).unwrap();
    unsafe {
        let d = open(&dev, &file);
        assert_eq!(auto_use(&dev, d, &file), vec![false]);
        bastion_document_free(d);
        assert_eq!(std::fs::read(file.path.to_str().unwrap()).unwrap(), before, "byte for byte");
        assert!(dev.record().is_empty());
        let again = open(&dev, &file);
        assert_eq!(origin(again), 1);
        bastion_document_free(again);
    }
}

/// Threat case 9.
#[test]
fn the_migration_records_personal_recents_and_restored_documents_once() {
    let dev = device();
    let recent = sent(&dev, "Recent", false, false);
    let restored = sent(&dev, "Restored", false, false);
    let never = sent(&dev, "Never opened", false, true);
    RecentDocuments::new(dev.data_dir().join("recent-documents.json")).add(Path::new(recent.path.to_str().unwrap())).unwrap();
    let personal = Uuid::new_v4().to_string();
    let restore = serde_json::json!([restored.path.to_str().unwrap()]).to_string();
    unsafe {
        assert_eq!(migrate(&dev, Some("not an id"), None), -1);
        assert_eq!(migrate(&dev, None, Some("{\"not\":\"a list\"}")), -1);
        assert_eq!(bastion_known_documents_migrate(null(), null(), null(), null_mut()), -1, "data_dir is required");
        assert!(!dev.data_dir().join(KNOWN_FILE).exists(), "a refused call writes nothing");

        assert_eq!(migrate(&dev, Some(&personal), Some(&restore)), 1);
        assert_eq!(dev.record(), vec![personal, recent.id.to_string(), restored.id.to_string()]);
        assert_eq!(migrate(&dev, None, None), 0, "runs once");

        let d = open(&dev, &recent);
        assert_eq!((origin(d), auto_use(&dev, d, &recent)), (0, vec![true]), "nothing changes for a library opened before the update");
        bastion_document_free(d);
        let d = open(&dev, &never);
        assert_eq!(origin(d), 1);
        bastion_document_free(d);
    }
}

/// Threat case 9: a damaged record is left alone and knows nothing.
#[test]
fn a_damaged_record_is_not_overwritten_and_asks() {
    let dev = device();
    let file = sent(&dev, "Mine", false, false);
    std::fs::create_dir_all(dev.data_dir()).unwrap();
    let damaged = format!("[\"{}\"", file.id);
    std::fs::write(dev.data_dir().join(KNOWN_FILE), &damaged).unwrap();
    unsafe {
        assert_eq!(migrate(&dev, Some(&file.id.to_string()), None), 0);
        let d = open(&dev, &file);
        assert_eq!((origin(d), auto_use(&dev, d, &file)), (1, vec![false]));
        bastion_document_free(d);
    }
    assert_eq!(std::fs::read_to_string(dev.data_dir().join(KNOWN_FILE)).unwrap(), damaged);
}

/// Threat cases 8 and 10.
#[test]
fn documents_made_here_are_never_asked_about() {
    let dev = device();
    let path = c(dev.dir.path().join("New.bastion").to_str().unwrap());
    let mut device_keyed = DocumentFile::new_device(Document::new("Made here"));
    let keyed_path = dev.dir.path().join("Made here.bastion");
    device_keyed.save_as(&keyed_path).unwrap();
    unsafe {
        let mut err = null_mut();
        let d = bastion_document_create(c("New").as_ptr(), dev.data.as_ptr(), &mut err);
        assert_eq!(origin(d), 0);
        assert_eq!(answer(d, 1), 0, "a known library takes no answer");
        assert_eq!(bastion_document_save(d, path.as_ptr(), &mut err), 0);
        bastion_document_free(d);
        assert_eq!(dev.record().len(), 1, "recorded on its first save");
        let d = bastion_document_open(path.as_ptr(), dev.data.as_ptr(), &mut err);
        assert_eq!(origin(d), 0);
        bastion_document_free(d);

        let d = bastion_document_open(c(keyed_path.to_str().unwrap()).as_ptr(), dev.data.as_ptr(), &mut err);
        assert_eq!(origin(d), 0, "device-keyed: always known");
        bastion_document_free(d);
    }
    assert!(!dev.record().contains(&device_keyed.id().to_string()), "and needs no record entry");
}

/// Threat case 12.
#[test]
fn a_protected_library_is_marked_on_unlock_and_answered_after_it() {
    let dev = device();
    let file = sent(&dev, "Sent", true, true);
    unsafe {
        let d = open(&dev, &file);
        assert_eq!(origin(d), 1);
        assert_eq!(answer(d, 1), -1, "locked: answered after the unlock");
        assert_eq!(answer(d, 0), -1);
        let mut err = null_mut();
        assert_eq!(bastion_document_unlock(d, PW.as_ptr(), PW.len(), &mut err), 0);
        assert_eq!(auto_use(&dev, d, &file), vec![false], "marked before the tree is returned");
        assert_eq!(bastion_document_lock(d, &mut err), 1);
        assert_eq!(bastion_document_unlock(d, PW.as_ptr(), PW.len(), &mut err), 0);
        assert_eq!(auto_use(&dev, d, &file), vec![false], "and again after a lock");
        assert_eq!(answer(d, 1), 0);
        assert_eq!((origin(d), auto_use(&dev, d, &file)), (0, vec![true]));
        bastion_document_free(d);
    }
}

#[test]
fn null_handles_fail_cleanly() {
    unsafe {
        let mut err = null_mut();
        assert_eq!(bastion_document_origin(null(), &mut err), -1);
        assert!(!err.is_null());
        bastion_string_free(err);
        assert_eq!(bastion_document_answer_origin(null(), 1, null_mut()), -1);
    }
}

/// Threat case 11: only ids in the record.
#[test]
fn the_record_holds_only_ids() {
    let dev = device();
    let file = sent(&dev, "Customer Alpha", true, true);
    unsafe {
        let d = open(&dev, &file);
        let mut err = null_mut();
        assert_eq!(bastion_document_unlock(d, PW.as_ptr(), PW.len(), &mut err), 0);
        assert_eq!(answer(d, 0), 0);
        bastion_document_free(d);
    }
    let text = std::fs::read_to_string(dev.data_dir().join(KNOWN_FILE)).unwrap();
    assert_eq!(text, format!("[\"{}\"]", file.id));
}
