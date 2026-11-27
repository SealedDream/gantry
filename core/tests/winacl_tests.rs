//! Windows owner-only ACL tests (SECURITY.md O1). Each test reads the DACL back from disk and
//! asserts the only principal with access is the current user, with no inheritance.
#![cfg(windows)]
use std::collections::BTreeMap;
use std::path::Path;

use bastion_core::audit::{AuditLog, Category, Outcome};
use bastion_core::model::Document;
use bastion_core::store::{write_atomic, Store};
use bastion_core::winacl::{current_user_sid, dacl_report, restrict_path};

/// Well-known principals that must never appear.
const FORBIDDEN: &[(&str, &str)] = &[
    ("S-1-1-0", "Everyone"),
    ("S-1-5-32-545", "BUILTIN\\Users"),
    ("S-1-5-11", "Authenticated Users"),
    ("S-1-5-18", "SYSTEM"),
    ("S-1-5-32-544", "BUILTIN\\Administrators"),
    ("S-1-5-4", "INTERACTIVE"),
    ("S-1-2-1", "CONSOLE LOGON"),
];

fn assert_owner_only(path: &Path, inheritable: bool) {
    let me = current_user_sid().unwrap();
    let r = dacl_report(path).unwrap();
    assert!(r.protected, "{}: DACL must be protected (no inheritance from the profile): {r:?}", path.display());
    assert_eq!(r.aces.len(), 1, "{}: exactly one entry expected: {r:?}", path.display());
    let ace = &r.aces[0];
    assert_eq!(ace.sid, me, "{}: the only principal must be the current user", path.display());
    assert_eq!(ace.ace_type, 0, "{}: must be an allow entry", path.display());
    assert_eq!(ace.mask & 0x001F_01FF, 0x001F_01FF, "{}: full control expected, mask {:#x}", path.display(), ace.mask);
    for (sid, name) in FORBIDDEN {
        assert!(r.aces.iter().all(|a| a.sid != *sid), "{}: {name} must not have access: {r:?}", path.display());
    }
    // OBJECT_INHERIT_ACE (0x1) | CONTAINER_INHERIT_ACE (0x2) on directories only.
    let inherit = ace.flags & 0x3;
    assert_eq!(inherit, if inheritable { 0x3 } else { 0 }, "{}: inheritance flags {:#x}", path.display(), ace.flags);
}

#[test]
fn the_check_can_fail_default_acls_are_not_owner_only() {
    // Guards the assertions above: an ordinary file in %TEMP% inherits the profile's ACL.
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("plain.txt");
    std::fs::write(&f, b"x").unwrap();
    let r = dacl_report(&f).unwrap();
    assert!(!r.protected, "default file ACL should inherit: {r:?}");
    assert!(r.aces.len() > 1, "default file ACL should list several principals: {r:?}");
}

#[test]
fn restrict_path_makes_files_and_directories_owner_only() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("secret.bin");
    std::fs::write(&f, b"x").unwrap();
    restrict_path(&f, false).unwrap();
    assert_owner_only(&f, false);
    // Still usable by us afterwards.
    assert_eq!(std::fs::read(&f).unwrap(), b"x");
    std::fs::write(&f, b"y").unwrap();

    let sub = d.path().join("private");
    std::fs::create_dir(&sub).unwrap();
    restrict_path(&sub, true).unwrap();
    assert_owner_only(&sub, true);
    // A file created inside is born owner-only through inheritance.
    let child = sub.join("child.txt");
    std::fs::write(&child, b"z").unwrap();
    let r = dacl_report(&child).unwrap();
    assert_eq!(r.aces.len(), 1, "{r:?}");
    assert_eq!(r.aces[0].sid, current_user_sid().unwrap());
}

#[test]
fn restrict_path_is_idempotent_and_reports_missing_paths() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("a");
    std::fs::write(&f, b"").unwrap();
    restrict_path(&f, false).unwrap();
    restrict_path(&f, false).unwrap();
    assert_owner_only(&f, false);
    assert!(restrict_path(&d.path().join("missing"), false).is_err());
}

#[test]
fn write_atomic_produces_an_owner_only_file_and_no_temp_leftovers() {
    let d = tempfile::tempdir().unwrap();
    let target = d.path().join("library.json");
    write_atomic(&target, b"{}").unwrap();
    assert_owner_only(&target, false);
    write_atomic(&target, b"{\"v\":2}").unwrap();
    assert_owner_only(&target, false);
    assert_eq!(std::fs::read(&target).unwrap(), b"{\"v\":2}");
    let names: Vec<_> = std::fs::read_dir(d.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names.len(), 1, "temp files must be renamed away: {names:?}");
}

#[test]
fn store_library_backups_dir_and_backup_files_are_owner_only() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("lib.json");
    let store = Store::new(&path);
    let v1 = store.save(&Document::new("one")).unwrap();
    store.save(&v1).unwrap(); // second save snapshots the first into the backups dir
    assert_owner_only(&path, false);
    let dir = store.backups_dir();
    assert_owner_only(&dir, true);
    let backups = store.list_backups().unwrap();
    assert!(!backups.is_empty());
    for b in backups {
        assert_owner_only(&b, false);
    }
}

#[test]
fn audit_log_is_owner_only_from_the_first_record_and_stays_appendable() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("audit.log");
    let mut log = AuditLog::open(&path).unwrap();
    log.record(Category::AppLock, "unlock", None, Outcome::Success, BTreeMap::new()).unwrap();
    assert_owner_only(&path, false);
    log.record(Category::AppLock, "lock", None, Outcome::Success, BTreeMap::new()).unwrap();
    assert_owner_only(&path, false);
    bastion_core::audit::verify(&path).unwrap();
}

#[test]
fn audit_log_created_by_an_older_build_is_tightened_on_next_write() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("audit.log");
    let mut first = AuditLog::open(&path).unwrap();
    first.record(Category::AppLock, "unlock", None, Outcome::Success, BTreeMap::new()).unwrap();
    // Simulate a log left with the profile's default ACL by a build without this fix.
    let mut loose = std::process::Command::new("icacls");
    loose.arg(&path).args(["/reset"]);
    assert!(loose.output().unwrap().status.success(), "icacls /reset failed");
    assert!(!dacl_report(&path).unwrap().protected, "precondition: log is back to inheriting");
    let mut reopened = AuditLog::open(&path).unwrap();
    reopened.record(Category::AppLock, "lock", None, Outcome::Success, BTreeMap::new()).unwrap();
    assert_owner_only(&path, false);
    bastion_core::audit::verify(&path).unwrap();
}
