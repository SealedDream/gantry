//! Journey 16: public audit API with independently opened writers and generated canaries.
use bastion_core::audit::{self, AuditLog, Category, Outcome};
use std::collections::BTreeMap;

#[test]
fn sensitive_detail_fields_are_redacted_and_chain_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    for key in [
        "password",
        "passphrase",
        "access_token",
        "private_key",
        "cookie",
        "otp",
    ] {
        let mut log = AuditLog::open(&path).unwrap();
        log.record(
            Category::CredentialAccess,
            "qa.test",
            None,
            Outcome::Success,
            BTreeMap::from([(key.into(), "generated-audit-canary".into())]),
        )
        .unwrap();
    }
    audit::verify(&path).unwrap();
    let text = std::fs::read_to_string(path).unwrap();
    assert!(!text.contains("generated-audit-canary"));
    assert_eq!(text.lines().count(), 6);
}

#[test]
fn two_independent_writers_preserve_a_valid_audit_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut a = AuditLog::open(&path).unwrap();
    let mut b = AuditLog::open(&path).unwrap();
    a.record(
        Category::AppLock,
        "qa.lock",
        None,
        Outcome::Success,
        BTreeMap::new(),
    )
    .unwrap();
    b.record(
        Category::ImportExport,
        "qa.save",
        None,
        Outcome::Success,
        BTreeMap::new(),
    )
    .unwrap();
    audit::verify(&path).unwrap();
}
