//! An interrupted document write leaves a temp file; the next write of that file removes it,
//! but never another live writer's file (audit DS-03).
use std::io::Write;
use std::time::{Duration, SystemTime};

fn age(f: &std::path::Path) {
    let old = SystemTime::now() - Duration::from_secs(120);
    std::fs::File::options().write(true).open(f).unwrap().set_modified(old).unwrap();
}

#[test]
fn a_later_write_removes_stale_temps_of_an_interrupted_one() {
    let dir = tempfile::tempdir().unwrap();
    let doc = dir.path().join("lab.bastion");
    let stale = dir.path().join(format!("lab.bastion.{}.tmp", "a".repeat(32)));
    let legacy = dir.path().join(format!("lab.{}.tmp", "d".repeat(32)));
    let fresh = dir.path().join(format!("lab.bastion.{}.tmp", "b".repeat(32)));
    let other = dir.path().join(format!("other.bastion.{}.tmp", "c".repeat(32)));
    for f in [&stale, &legacy, &fresh, &other] {
        std::fs::write(f, b"half").unwrap();
    }
    for f in [&stale, &legacy, &other] {
        age(f);
    }
    bastion_core::store::write_atomic(&doc, b"{}").unwrap();
    assert!(!stale.exists(), "stale temp of this file removed");
    assert!(!legacy.exists(), "stale temp in the pre-DS-03 naming removed");
    assert!(fresh.exists(), "a recent temp may be another writer's: kept");
    assert!(other.exists(), "another file's temp: kept");
}

#[test]
fn same_stem_destinations_use_separate_temp_namespaces() {
    let dir = tempfile::tempdir().unwrap();
    let json = dir.path().join("shared.json");
    bastion_core::store::write_atomic(&json, b"{}").unwrap();
    let foreign = dir.path().join(format!("shared.bastion.{}.tmp", "e".repeat(32)));
    std::fs::write(&foreign, b"unrelated").unwrap();
    age(&foreign);
    bastion_core::store::write_atomic(&json, b"{\"v\":2}").unwrap();
    assert_eq!(std::fs::read(&foreign).unwrap(), b"unrelated", "shared.bastion's temp is not shared.json's to clean");
}

/// The Codex probe: a paused writer holds a temp file older than the cutoff while another save
/// of a same-stem file completes. The paused writer must still be able to commit.
#[test]
fn a_paused_live_writer_survives_cleanup_and_commits() {
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join(format!("shared.{}.tmp", "f".repeat(32)));
    let mut f = std::fs::File::options().write(true).create_new(true).open(&live).unwrap();
    f.lock().unwrap();
    f.write_all(b"{\"live\":").unwrap();
    age(&live);
    bastion_core::store::write_atomic(&dir.path().join("shared.json"), b"{}").unwrap();
    bastion_core::store::write_atomic(&dir.path().join("shared.bastion"), b"{}").unwrap();
    assert!(live.exists(), "a locked (live) writer's temp file is never unlinked");
    f.write_all(b"true}").unwrap();
    f.sync_all().unwrap();
    let target = dir.path().join("shared.bastion");
    std::fs::rename(&live, &target).unwrap();
    drop(f);
    assert_eq!(std::fs::read(&target).unwrap(), b"{\"live\":true}");
}

/// Release/normal builds (no `test-hooks` feature) ignore the crash-hook variable entirely.
#[cfg(not(feature = "test-hooks"))]
#[test]
fn without_test_hooks_the_kill_variable_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let doc = dir.path().join("hooked.bastion");
    std::env::set_var("BASTION_TEST_KILL_DURING_WRITE", "hooked.bastion");
    let r = bastion_core::store::write_atomic(&doc, b"{\"ok\":true}");
    std::env::remove_var("BASTION_TEST_KILL_DURING_WRITE");
    r.unwrap();
    assert_eq!(std::fs::read(&doc).unwrap(), b"{\"ok\":true}", "the write completed: the process was not ended");
}
