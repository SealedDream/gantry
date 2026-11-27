use std::fs::File;
use std::path::{Path, PathBuf};

use keepass::db::fields;
use keepass::{Database, DatabaseKey};

use super::*;

/// Generated test file: "Servers/Lab" holds two entries, one without a password; one entry at
/// the root. Values are synthetic.
fn fixture(dir: &Path) -> PathBuf {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "router");
        e.set_unprotected(fields::USERNAME, "admin");
        e.set_protected(fields::PASSWORD, "rt-pass-1");
        let mut servers = root.add_group();
        servers.name = "Servers".into();
        let mut lab = servers.add_group();
        lab.name = "Lab".into();
        let mut e = lab.add_entry();
        e.set_unprotected(fields::TITLE, "lab sshd");
        e.set_unprotected(fields::USERNAME, "root");
        e.set_protected(fields::PASSWORD, "kp-s3cret");
        let mut e = lab.add_entry();
        e.set_unprotected(fields::TITLE, "notes only");
    }
    let path = dir.join("Team.kdbx");
    db.save(&mut File::create(&path).unwrap(), DatabaseKey::new().with_password("master")).unwrap();
    path
}

fn pw() -> Option<Secret> {
    Some(Secret::new("master"))
}

fn password_of(v: &Vault, id: Uuid) -> String {
    match &v.get(id).unwrap().kind {
        CredentialKind::Password { password, .. } => password.expose().to_string(),
        _ => panic!("not a password"),
    }
}

#[test]
fn preview_has_no_secrets_and_marks_rows() {
    let d = tempfile::tempdir().unwrap();
    let path = fixture(d.path());
    let rows = preview(&Vault::default(), &path, pw(), None).unwrap();
    assert_eq!(rows.len(), 3);
    let dump = format!("{rows:?}");
    assert!(!dump.contains("kp-s3cret") && !dump.contains("rt-pass-1"));
    let lab = rows.iter().find(|r| r.title == "lab sshd").unwrap();
    assert_eq!(lab.folder, "KeePass Team/Servers/Lab");
    assert_eq!(lab.status, RowStatus::New);
    assert_eq!(rows.iter().find(|r| r.title == "notes only").unwrap().status, RowStatus::NoPassword);
}

#[test]
fn wrong_password_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let path = fixture(d.path());
    assert!(matches!(preview(&Vault::default(), &path, Some(Secret::new("nope")), None), Err(CoreError::AuthFailed)));
    let mut v = Vault::default();
    assert!(import(&mut v, &path, Some(Secret::new("nope")), None, DuplicateRule::Skip).is_err());
    assert!(v.is_empty());
}

#[test]
fn import_builds_folders_and_applies_duplicate_rules() {
    let d = tempfile::tempdir().unwrap();
    let path = fixture(d.path());
    let mut v = Vault::default();
    let r = import(&mut v, &path, pw(), None, DuplicateRule::Skip).unwrap();
    assert_eq!((r.added, r.replaced, r.skipped_duplicates, r.skipped_no_password), (2, 0, 0, 1));
    assert!(r.folder.is_some());
    let lab = v.list().into_iter().find(|c| c.name == "lab sshd").unwrap();
    assert_eq!(lab.folder.as_deref(), Some("KeePass Team/Servers/Lab"));
    assert_eq!(lab.username, "root");
    assert_eq!(password_of(&v, lab.id), "kp-s3cret");

    // Second run: everything is a duplicate.
    let rows = preview(&v, &path, pw(), None).unwrap();
    assert_eq!(rows.iter().filter(|r| r.status == RowStatus::Duplicate).count(), 2);
    let r = import(&mut v, &path, pw(), None, DuplicateRule::Skip).unwrap();
    assert_eq!((r.added, r.skipped_duplicates), (0, 2));
    assert_eq!(v.len(), 2);

    // Replace keeps the id; keep-both adds beside it.
    if let Some(c) = v.entries.get_mut(&lab.id) {
        c.kind = CredentialKind::Password { username: "root".into(), password: Secret::new("old") };
    }
    let r = import(&mut v, &path, pw(), None, DuplicateRule::Replace).unwrap();
    assert_eq!((r.added, r.replaced), (0, 2));
    assert_eq!(password_of(&v, lab.id), "kp-s3cret");
    let r = import(&mut v, &path, pw(), None, DuplicateRule::KeepBoth).unwrap();
    assert_eq!(r.added, 2);
    assert_eq!(v.len(), 4);
    assert_eq!(v.folders().len(), 3);
}

#[test]
fn rule_names_parse() {
    assert_eq!(DuplicateRule::parse("skip").unwrap(), DuplicateRule::Skip);
    assert_eq!(DuplicateRule::parse("replace").unwrap(), DuplicateRule::Replace);
    assert_eq!(DuplicateRule::parse("keep-both").unwrap(), DuplicateRule::KeepBoth);
    assert!(DuplicateRule::parse("merge").is_err());
}

#[test]
fn unsafe_names_are_cleaned() {
    assert_eq!(top_folder_name(Path::new("/x/a\u{7}b.kdbx")), "KeePass a b");
    assert_eq!(safe_name("a/b", "x"), "a b");
    assert_eq!(safe_name("  ", "x"), "x");
}

/// Regenerates the synthetic fixture the Mac UI suite `b8-keepass-import-fit` uses:
/// `BASTION_KDBX_FIXTURE=<path> cargo test --lib write_ui_fixture -- --ignored`.
#[test]
#[ignore]
fn write_ui_fixture() {
    let out = std::env::var("BASTION_KDBX_FIXTURE").expect("BASTION_KDBX_FIXTURE");
    let d = tempfile::tempdir().unwrap();
    std::fs::copy(fixture(d.path()), out).unwrap();
}
