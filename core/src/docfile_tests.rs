use super::*;
use crate::model::Protocol;
use crate::vault::{CredentialKind, Secret};

const PW: &str = "correct horse battery";

fn sample(name: &str) -> DocumentFile {
    let mut d = DocumentFile::new(name).unwrap();
    let mut c = Connection::new("web01", Protocol::Ssh, "web01.example");
    c.settings.username = Some("ops".into());
    d.document_mut().unwrap().insert(None, Node::Connection(c)).unwrap();
    d
}

fn credential(id: Uuid) -> Credential {
    Credential { id, name: "ops".into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: "ops".into(), password: Secret::new("hunter2-secret") } }
}

fn protected_with_credential(dir: &Path) -> (PathBuf, Uuid) {
    let path = dir.join("Team.bastion");
    let mut d = sample("Team");
    d.set_password(Some(PW)).unwrap();
    let cid = Uuid::new_v4();
    d.put_credential(credential(cid)).unwrap();
    d.save_as(&path).unwrap();
    (path, cid)
}

#[test]
fn unprotected_round_trip_and_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Personal.bastion");
    let mut d = sample("Personal");
    d.save_as(&path).unwrap();
    let back = DocumentFile::open(&path).unwrap();
    assert!(!back.is_locked() && !back.is_protected());
    assert_eq!(back.name(), "Personal");
    assert_eq!(back.document().unwrap().root.children.len(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn unprotected_document_refuses_credentials() {
    let mut d = sample("Plain");
    assert!(d.put_credential(credential(Uuid::new_v4())).is_err());
    // A hand-made unprotected file that carries credentials is refused on read.
    let mut p = sample("Plain");
    p.set_password(Some(PW)).unwrap();
    p.put_credential(credential(Uuid::new_v4())).unwrap();
    let mut env = p.to_envelope(1).unwrap();
    env.protection = None;
    env.sealed = None;
    env.contents = Some(p.contents().unwrap().clone());
    let bytes = serde_json::to_vec(&env).unwrap();
    assert!(DocumentFile::parse(&bytes).is_err());
}

#[test]
fn protected_document_is_encrypted_and_starts_locked() {
    let dir = tempfile::tempdir().unwrap();
    let (path, cid) = protected_with_credential(dir.path());
    let text = fs::read_to_string(&path).unwrap();
    assert!(!text.contains("hunter2-secret") && !text.contains("web01"), "nothing readable in the file");
    let mut d = DocumentFile::open(&path).unwrap();
    assert!(d.is_locked() && d.is_protected());
    assert!(d.document().is_err());
    d.unlock(PW).unwrap();
    assert_eq!(d.credentials().unwrap()[0].id, cid);
    assert!(d.lock());
    assert!(d.is_locked() && d.credentials().is_err());
    d.unlock(PW).unwrap();
}

#[test]
fn wrong_password_is_refused_without_detail() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = protected_with_credential(dir.path());
    let mut d = DocumentFile::open(&path).unwrap();
    let err = d.unlock("wrong password!").unwrap_err();
    assert!(matches!(err, CoreError::VaultAuth));
    assert!(!err.to_string().contains("web01"));
    assert!(d.is_locked());
}

#[test]
fn tampered_files_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = protected_with_credential(dir.path());
    let original: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

    let try_open = |v: &serde_json::Value| -> Result<()> {
        let mut d = DocumentFile::parse(&serde_json::to_vec(v).unwrap())?;
        d.unlock(PW)
    };
    // Renamed in the clear, replayed under another revision, or another id: all bound as AAD.
    for (field, value) in [("name", serde_json::json!("Evil")), ("revision", serde_json::json!(99)), ("id", serde_json::json!(Uuid::new_v4()))] {
        let mut v = original.clone();
        v[field] = value;
        assert!(matches!(try_open(&v), Err(CoreError::VaultAuth)), "{field} edit must fail authentication");
    }
    // One flipped ciphertext byte.
    let mut v = original.clone();
    let ct = v["sealed"]["ciphertext"].as_str().unwrap().to_string();
    let mut raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ct).unwrap();
    raw[10] ^= 1;
    v["sealed"]["ciphertext"] = serde_json::json!(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw));
    assert!(matches!(try_open(&v), Err(CoreError::VaultAuth)));
    // Weakened key derivation is refused before any work is done.
    let mut v = original.clone();
    v["protection"]["m_cost"] = serde_json::json!(8);
    assert!(matches!(try_open(&v), Err(CoreError::Corrupt(_))));
    // Garbage and truncation.
    assert!(DocumentFile::parse(b"{not json").is_err());
    let bytes = fs::read(&path).unwrap();
    assert!(DocumentFile::parse(&bytes[..bytes.len() / 2]).is_err());
}

#[test]
fn old_library_json_opens_as_version_zero_and_upgrades() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("library.json");
    let mut old = Document::new("Library");
    old.insert(None, Node::Connection(Connection::new("db", Protocol::Ssh, "db.example"))).unwrap();
    old.revision = 7;
    fs::write(&path, serde_json::to_vec_pretty(&old).unwrap()).unwrap();

    let mut d = DocumentFile::open(&path).unwrap();
    assert_eq!(d.loaded_version(), 0);
    assert_eq!(d.document().unwrap().root.children.len(), 1);
    let new_path = dir.path().join("Personal.bastion");
    d.save_as(&new_path).unwrap();
    let back = DocumentFile::open(&new_path).unwrap();
    assert_eq!(back.loaded_version(), VERSION);
    assert_eq!(back.revision(), 8);
}

#[test]
fn newer_format_and_foreign_files_are_refused() {
    // VERSION + 1 is read since PLUG-03a (`docfile_tolerant_tests`); above that is "newer".
    let v = serde_json::json!({"format": FORMAT, "version": VERSION + 2, "id": Uuid::new_v4(), "name": "x", "revision": 1});
    let err = DocumentFile::parse(&serde_json::to_vec(&v).unwrap()).unwrap_err();
    assert!(err.to_string().contains("newer"));
    assert!(DocumentFile::parse(br#"{"format":"something-else","version":1}"#).is_err());
}

#[test]
fn concurrent_save_is_a_conflict_and_backups_are_kept() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Shared.bastion");
    sample("Shared").save_as(&path).unwrap();
    let mut a = DocumentFile::open(&path).unwrap();
    let mut b = DocumentFile::open(&path).unwrap();
    a.rename("Shared A").unwrap();
    a.save().unwrap();
    b.rename("Shared B").unwrap();
    assert!(matches!(b.save(), Err(CoreError::Conflict { .. })));
    assert_eq!(fs::read_dir(backups_dir(&path)).unwrap().count(), 1);
}

#[test]
fn password_change_keeps_the_key_and_removal_needs_no_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let (path, cid) = protected_with_credential(dir.path());
    let mut d = DocumentFile::open(&path).unwrap();
    d.unlock(PW).unwrap();
    let key = d.key().unwrap();
    d.set_password(Some("another long password")).unwrap();
    assert_eq!(*d.key().unwrap(), *key, "biometric key store stays valid");
    assert!(d.set_password(Some("short")).is_err());
    assert!(d.set_password(None).is_err(), "credentials would be written in the clear");
    d.save().unwrap();

    let mut by_key = DocumentFile::open(&path).unwrap();
    by_key.unlock_with_key(key_from_hex(&key_to_hex(&key)).unwrap()).unwrap();
    let mut old_pw = DocumentFile::open(&path).unwrap();
    assert!(old_pw.unlock(PW).is_err());
    old_pw.unlock("another long password").unwrap();

    old_pw.remove_credential(cid).unwrap();
    old_pw.set_password(None).unwrap();
    old_pw.save().unwrap();
    assert!(!DocumentFile::open(&path).unwrap().is_protected());
}

#[test]
fn export_strips_secrets_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let (path, cid) = protected_with_credential(dir.path());
    let mut src = DocumentFile::open(&path).unwrap();
    src.unlock(PW).unwrap();
    if let Node::Connection(c) = &mut src.document_mut().unwrap().root.children[0] {
        c.settings.credential_id = Some(cid);
    }
    let (plain, s) = export(&src, &Selection::All, "Share", false, None).unwrap();
    assert_eq!((s.connections, s.credentials, s.credential_refs), (1, 0, 1));
    assert!(!plain.is_protected());
    assert!(!String::from_utf8(plain.to_bytes().unwrap()).unwrap().contains("hunter2"));
    assert!(export(&src, &Selection::All, "Share", true, None).is_err(), "secrets need a password");

    let (mut with, s) = export(&src, &Selection::All, "Share", true, Some("share password 1")).unwrap();
    assert_eq!(s.credentials, 1);
    let out = dir.path().join("Share.bastion");
    with.save_as(&out).unwrap();
    let mut back = DocumentFile::open(&out).unwrap();
    back.unlock("share password 1").unwrap();
    assert_eq!(back.credentials().unwrap().len(), 1);
    assert_ne!(back.id(), src.id(), "an export is a new document");
}

#[test]
fn import_dedupes_and_drops_credentials_into_unprotected_targets() {
    let dir = tempfile::tempdir().unwrap();
    let (path, cid) = protected_with_credential(dir.path());
    let mut src = DocumentFile::open(&path).unwrap();
    src.unlock(PW).unwrap();
    let mut extra = Connection::new("db", Protocol::Rdp, "db.example");
    extra.settings.credential_id = Some(cid);
    src.document_mut().unwrap().insert(None, Node::Connection(extra)).unwrap();

    let mut target = sample("Personal"); // already has web01 (same protocol/host/user)
    let (plan, none) = import_into(&mut target, &src, false).unwrap();
    assert!(none.is_none());
    assert_eq!((plan.connections, plan.duplicates.len(), plan.credentials, plan.credentials_dropped), (1, 1, 0, 1));
    let (_, folder) = import_into(&mut target, &src, true).unwrap();
    let doc = target.document().unwrap();
    let imported = doc
        .root
        .children
        .iter()
        .find_map(|n| match n {
            Node::Folder(f) if Some(f.id) == folder => Some(f),
            _ => None,
        })
        .unwrap();
    assert_eq!(imported.name, "Imported Team");
    match &imported.children[0] {
        Node::Connection(c) => assert_eq!(c.settings.credential_id, None, "reference to a dropped credential is cleared"),
        _ => panic!("expected a connection"),
    }

    let mut protected = sample("Vaulted");
    protected.set_password(Some(PW)).unwrap();
    let (plan, _) = import_into(&mut protected, &src, true).unwrap();
    assert_eq!((plan.credentials, plan.credentials_dropped), (1, 0));
    assert_eq!(protected.credentials().unwrap().len(), 1);
}

#[test]
fn recent_documents_are_newest_first_and_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let r = RecentDocuments::new(dir.path().join("recent.json"));
    for i in 0..12 {
        r.add(Path::new(&format!("/d/{i}.bastion"))).unwrap();
    }
    r.add(Path::new("/d/3.bastion")).unwrap();
    let l = r.list();
    assert_eq!(l.len(), MAX_RECENT);
    assert_eq!(l[0], PathBuf::from("/d/3.bastion"));
    r.remove(Path::new("/d/3.bastion")).unwrap();
    assert!(!r.list().contains(&PathBuf::from("/d/3.bastion")));
}

/// Open/save timing with 5,000 connections (`cargo test --release -- --ignored large_document --nocapture`).
/// Protected unlock includes one Argon2id derivation (64 MiB, t=3) by design.
#[test]
#[ignore]
fn large_document_timings() {
    use std::time::Instant;
    let dir = tempfile::tempdir().unwrap();
    let mut d = DocumentFile::new("Large").unwrap();
    for f in 0..50 {
        let folder = Folder { id: Uuid::new_v4(), name: format!("Customer {f}"), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() };
        let fid = folder.id;
        d.document_mut().unwrap().insert(None, Node::Folder(folder)).unwrap();
        for i in 0..100 {
            let mut c = Connection::new(format!("host-{f}-{i}"), Protocol::Ssh, format!("h{f}-{i}.example.internal"));
            c.settings.username = Some("ops".into());
            d.document_mut().unwrap().insert(Some(fid), Node::Connection(c)).unwrap();
        }
    }
    let ms = |t: Instant| t.elapsed().as_secs_f64() * 1000.0;
    for protected in [false, true] {
        let path = dir.path().join(format!("large-{protected}.bastion"));
        if protected {
            d.set_password(Some(PW)).unwrap();
        }
        let t = Instant::now();
        d.save_as(&path).unwrap();
        let first = ms(t);
        let t = Instant::now();
        d.save().unwrap();
        let resave = ms(t);
        let size = fs::metadata(&path).unwrap().len();
        let t = Instant::now();
        let mut o = DocumentFile::open(&path).unwrap();
        let open = ms(t);
        let t = Instant::now();
        if protected {
            o.unlock(PW).unwrap();
        }
        let unlock = ms(t);
        let t = Instant::now();
        if protected {
            o.lock();
            o.unlock_with_key(d.key().unwrap()).unwrap();
        }
        let key_unlock = ms(t);
        assert_eq!(o.document().unwrap().root.children.len(), 50);
        println!("TIMING protected={protected} size={}KB save-as={first:.1}ms save={resave:.1}ms open={open:.1}ms unlock(password)={unlock:.1}ms unlock(key)={key_unlock:.1}ms", size / 1024);
    }
}

/// Codex C07: eight writers loading the same revision and saving at once; before the save lock
/// all eight reported success and the last rename silently dropped the others' edits.
#[test]
fn simultaneous_saves_from_one_revision_admit_exactly_one() {
    const WRITERS: usize = 8;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Shared.bastion");
    sample("Shared").save_as(&path).unwrap();
    let store_path = dir.path().join("library.json");
    crate::store::Store::new(&store_path).save(&Document::new("Lib")).unwrap();

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS * 2));
    let handles: Vec<_> = (0..WRITERS)
        .flat_map(|i| {
            let (b1, b2, p, sp) = (barrier.clone(), barrier.clone(), path.clone(), store_path.clone());
            let doc_writer = std::thread::spawn(move || {
                let mut d = DocumentFile::open(&p).unwrap();
                d.document_mut().unwrap().root.children.push(Node::Connection(Connection::new(&format!("edit-{i}"), Protocol::Ssh, "h")));
                b1.wait();
                d.save().is_ok()
            });
            let store_writer = std::thread::spawn(move || {
                let store = crate::store::Store::new(&sp);
                let mut doc = store.load().unwrap();
                doc.name = format!("edit-{i}");
                b2.wait();
                store.save(&doc).is_ok()
            });
            [doc_writer, store_writer]
        })
        .collect();
    let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let doc_ok = results.iter().step_by(2).filter(|ok| **ok).count();
    let store_ok = results.iter().skip(1).step_by(2).filter(|ok| **ok).count();
    assert_eq!((doc_ok, store_ok), (1, 1), "exactly one save per file may win; the rest are conflicts");
    let saved = DocumentFile::open(&path).unwrap();
    assert_eq!(saved.revision(), 2);
    assert_eq!(saved.contents().unwrap().document.root.children.len(), 2, "the winner's edit is on disk");
}

/// Codex C13: credentials a connection inherits through its type's Default Settings (by id or
/// by name) travel with a protected export.
#[test]
fn export_includes_credentials_inherited_from_type_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let (path, cid) = protected_with_credential(dir.path());
    let mut src = DocumentFile::open(&path).unwrap();
    src.unlock(PW).unwrap();
    let named = Uuid::new_v4();
    src.put_credential(Credential { name: "rdp-admin".into(), ..credential(named) }).unwrap();
    let unrelated = Uuid::new_v4();
    src.put_credential(Credential { name: "unused".into(), ..credential(unrelated) }).unwrap();
    {
        let doc = src.document_mut().unwrap();
        doc.type_defaults.insert(Protocol::Ssh, crate::model::Settings { credential_id: Some(cid), ..Default::default() });
        doc.type_defaults.insert(Protocol::Rdp, crate::model::Settings { credential_name: Some("rdp-admin".into()), ..Default::default() });
        doc.insert(None, Node::Connection(Connection::new("desk", Protocol::Rdp, "desk.example"))).unwrap();
    }
    let (out, s) = export(&src, &Selection::All, "Share", true, Some("share password 1")).unwrap();
    assert_eq!(s.credentials, 2, "the SSH type default (id) and the RDP type default (name)");
    let file = dir.path().join("Share.bastion");
    let mut out = out;
    out.save_as(&file).unwrap();
    let mut back = DocumentFile::open(&file).unwrap();
    back.unlock("share password 1").unwrap();
    let ids: BTreeSet<Uuid> = back.credentials().unwrap().iter().map(|c| c.id).collect();
    assert_eq!(ids, BTreeSet::from([cid, named]), "only what the exported connections use");
}

#[cfg(unix)]
#[test]
fn read_only_document_is_not_replaced_on_save() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Shared.bastion");
    let mut d = sample("Shared");
    d.save_as(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let before = fs::read(&path).unwrap();
    let err = d.save().unwrap_err().to_string();
    assert!(err.contains("read-only"), "{err}");
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o400);
}

/// A1-CORE-01-FU1: logins that arrive with an imported document are offered, not used
/// automatically. The target already holds the credential the sender refers to by id and by name.
#[test]
fn logins_that_arrive_with_an_imported_document_are_not_used_automatically() {
    use crate::logins::{login_candidates, LoginPurpose, LoginSource};
    let dir = tempfile::tempdir().unwrap();
    let (path, cid) = protected_with_credential(dir.path());
    let mut src = DocumentFile::open(&path).unwrap();
    src.unlock(PW).unwrap();
    let mut by_id = Connection::new("by id", Protocol::Rdp, "id.sender.example");
    by_id.settings.credential_id = Some(cid);
    let mut by_name = Connection::new("by name", Protocol::Ssh, "name.sender.example");
    by_name.settings.credential_name = Some("OPS".into());
    let plain = Connection::new("plain", Protocol::Ssh, "plain.sender.example");
    let folder = Folder { id: Uuid::new_v4(), name: "Named".into(), color: None, defaults: crate::model::Settings { credential_name: Some("ops".into()), ..Default::default() }, children: vec![Node::Connection(plain)], dynamic_task_id: None, extra: Default::default() };
    let doc = src.document_mut().unwrap();
    doc.insert(None, Node::Connection(by_id)).unwrap();
    doc.insert(None, Node::Connection(by_name)).unwrap();
    doc.insert(None, Node::Folder(folder)).unwrap();
    let mut target = DocumentFile::new("Mine").unwrap();
    target.set_password(Some(PW)).unwrap();
    target.put_credential(credential(cid)).unwrap();

    import_into(&mut target, &src, true).unwrap();

    // The user's vault as the resolver sees it holds the same credential.
    let mut vault = crate::vault::Vault::default();
    vault.add(credential(cid));
    let doc = target.document().unwrap();
    let rows = |name: &str| {
        let c = doc.connections().into_iter().find(|r| r.connection.name == name).unwrap().connection.id;
        login_candidates(doc, &vault, c, LoginPurpose::Any).unwrap().into_iter().map(|l| (l.credential, l.source, l.auto_use)).collect::<Vec<_>>()
    };
    assert_eq!(rows("by id"), vec![(cid, LoginSource::Default, false)]);
    assert_eq!(rows("by name"), vec![(cid, LoginSource::Named, false)]);
    assert!(matches!(rows("plain").as_slice(), [(c, LoginSource::Inherited { folder: Some(_), .. }, false)] if *c == cid));
}

/// Review of #813, H1: a document that arrives with `credential_confirmed` filled in by its
/// sender is imported without it, so its logins are still only offered.
#[test]
fn a_confirmed_list_in_an_imported_document_is_dropped() {
    use crate::logins::{login_candidates, LoginPurpose, LoginSource};
    let dir = tempfile::tempdir().unwrap();
    let (path, cid) = protected_with_credential(dir.path());
    let mut src = DocumentFile::open(&path).unwrap();
    src.unlock(PW).unwrap();
    let claimed = || crate::model::Settings { credential_unconfirmed: Some(false), credential_confirmed: vec![cid], ..Default::default() };
    let mut by_id = Connection::new("by id", Protocol::Rdp, "id.sender.example");
    by_id.settings = crate::model::Settings { credential_id: Some(cid), ..claimed() };
    let mut plain = Connection::new("plain", Protocol::Ssh, "plain.sender.example");
    plain.settings = claimed();
    let folder = Folder { id: Uuid::new_v4(), name: "Named".into(), color: None, defaults: crate::model::Settings { credential_name: Some("ops".into()), ..claimed() }, children: vec![Node::Connection(plain)], dynamic_task_id: None, extra: Default::default() };
    let doc = src.document_mut().unwrap();
    doc.insert(None, Node::Connection(by_id)).unwrap();
    doc.insert(None, Node::Folder(folder)).unwrap();
    let mut target = DocumentFile::new("Mine").unwrap();
    target.set_password(Some(PW)).unwrap();
    target.put_credential(credential(cid)).unwrap();

    import_into(&mut target, &src, true).unwrap();

    let mut vault = crate::vault::Vault::default();
    vault.add(credential(cid));
    let doc = target.document().unwrap();
    let node = |name: &str| doc.connections().into_iter().find(|r| r.connection.name == name).unwrap().connection;
    let rows = |name: &str| login_candidates(doc, &vault, node(name).id, LoginPurpose::Any).unwrap().into_iter().map(|l| (l.credential, l.source, l.auto_use)).collect::<Vec<_>>();
    assert_eq!(rows("by id"), vec![(cid, LoginSource::Default, false)]);
    assert!(matches!(rows("plain").as_slice(), [(c, LoginSource::Inherited { folder: Some(_), .. }, false)] if *c == cid));
    assert!(node("by id").settings.credential_confirmed.is_empty() && node("plain").settings.credential_confirmed.is_empty());
    assert_eq!(node("plain").settings.credential_unconfirmed, None, "no reference, no mark, whatever the file said");
}

#[test]
fn parse_skips_a_leading_utf8_bom() {
    // A pre-document library.json saved by Notepad or Windows PowerShell 5.1 starts with a BOM.
    let mut bytes = b"\xEF\xBB\xBF".to_vec();
    bytes.extend(serde_json::to_vec(&Document::new("Lib")).unwrap());
    assert!(DocumentFile::parse(&bytes).is_ok());
    // A BOM is not a way past the object check.
    assert!(DocumentFile::parse(b"\xEF\xBB\xBF[1]").is_err());
}
