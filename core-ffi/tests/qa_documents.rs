//! Journey 5: app-facing document lifecycle and lock failure regressions.
use bastion_ffi::BastionDocument;

fn document(dir: &tempfile::TempDir) -> std::sync::Arc<BastionDocument> {
    let doc =
        BastionDocument::create("QA 日本".into(), dir.path().to_str().unwrap().into()).unwrap();
    doc.set_password(Some("generated-document-password".into()))
        .unwrap();
    doc.save_as(dir.path().join("qa.bastion").to_str().unwrap().into())
        .unwrap();
    doc
}

#[test]
fn protected_document_reopens_locked_and_keeps_secrets_out_of_disk_and_audit() {
    let dir = tempfile::tempdir().unwrap();
    let doc = document(&dir);
    let lib = doc.library().unwrap();
    lib.add_connection(
        None,
        "lab".into(),
        "ssh".into(),
        "127.0.0.1".into(),
        None,
        None,
    )
    .unwrap();
    doc.save_password_credential(
        None,
        "QA credential".into(),
        "tester".into(),
        "generated-secret-canary".into(),
    )
    .unwrap();
    doc.save().unwrap();
    assert!(doc.lock().unwrap());
    assert!(doc.info().locked);
    assert!(doc.library().is_err());
    assert!(doc.credentials().is_err());
    drop(lib);
    drop(doc);
    let path = dir.path().join("qa.bastion");
    let doc = BastionDocument::open(
        path.to_str().unwrap().into(),
        dir.path().to_str().unwrap().into(),
    )
    .unwrap();
    assert!(doc.info().locked);
    doc.unlock("generated-document-password".into()).unwrap();
    assert_eq!(doc.library().unwrap().tree().connections.len(), 1);
    assert_eq!(doc.credentials().unwrap().len(), 1);
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(path).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("generated-secret-canary"));
        }
    }
    bastion_core::audit::verify(&dir.path().join("audit.jsonl")).unwrap();
}

#[test]
fn old_library_cannot_save_after_lock_and_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let doc = document(&dir);
    let stale = doc.library().unwrap();
    stale.add_folder(None, "Original".into()).unwrap();
    doc.save().unwrap();
    doc.lock().unwrap();
    doc.unlock("generated-document-password".into()).unwrap();
    let current = doc.library().unwrap();
    current.add_folder(None, "Current".into()).unwrap();
    current.save().unwrap();
    assert!(
        stale.save().is_err(),
        "revoked pre-lock handle must not replace the current tree"
    );
}

#[test]
fn document_lock_revokes_secrets_even_when_persistence_fails() {
    let dir = tempfile::tempdir().unwrap();
    let doc = document(&dir);
    doc.library()
        .unwrap()
        .add_folder(None, "Unsaved edit".into())
        .unwrap();
    let path = dir.path().join("qa.bastion");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(
        doc.lock().is_err(),
        "the persistence failure must remain visible"
    );
    assert!(
        doc.info().locked,
        "persistence failure must not cancel the security transition"
    );
    assert!(doc.library().is_err());
}
