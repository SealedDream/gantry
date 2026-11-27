use super::*;
use crate::docfile::{new_wrapping_key, DocumentFile};

const PW: &str = "document password";

#[test]
fn back_off_starts_at_the_fifth_wrong_password_and_doubles() {
    assert_eq!((1..=4).map(wait_after).collect::<Vec<_>>(), vec![0, 0, 0, 0]);
    assert_eq!(wait_after(5), 30);
    assert_eq!(wait_after(6), 60);
    assert_eq!(wait_after(7), 120);
    assert_eq!(wait_after(40), MAX_WAIT_SECS);
}

#[test]
fn back_off_survives_a_relaunch_and_clears_on_success() {
    let dir = tempfile::tempdir().unwrap();
    let doc = Uuid::new_v4();
    let b = UnlockBackoff::in_dir(dir.path());
    for _ in 0..4 {
        assert_eq!(b.record_failure(doc, 1000).unwrap().retry_at, 0);
    }
    b.check(doc, 1000).unwrap();
    let a = b.record_failure(doc, 1000).unwrap();
    assert_eq!((a.failures, a.retry_at), (5, 1030));
    let again = UnlockBackoff::in_dir(dir.path());
    let e = again.check(doc, 1010).unwrap_err().to_string();
    assert!(e.contains("20 s"), "{e}");
    again.check(doc, 1030).unwrap();
    assert_eq!(again.record_failure(doc, 1030).unwrap().retry_at, 1090);
    again.record_success(doc).unwrap();
    assert_eq!(again.get(doc), Attempts::default());
    let text = std::fs::read_to_string(dir.path().join(BACKOFF_FILE)).unwrap();
    assert!(!text.contains("password"));
}

#[test]
fn auto_lock_rules() {
    assert_eq!(auto_lock_due(15, 899, false, false, false), None);
    assert_eq!(auto_lock_due(15, 900, false, false, false), Some(LockReason::Idle));
    assert_eq!(auto_lock_due(0, 1_000_000, false, false, false), None, "0 = never on idle");
    assert_eq!(auto_lock_due(15, 5000, false, false, true), None, "remember until quit skips idle");
    assert_eq!(auto_lock_due(0, 0, true, false, true), Some(LockReason::ScreenLocked));
    assert_eq!(auto_lock_due(0, 0, false, true, true), Some(LockReason::Sleep));
    assert_eq!(effective_auto_lock_minutes(0, Some(10)), 10, "policy forbids never");
    assert_eq!(effective_auto_lock_minutes(30, Some(10)), 10);
    assert_eq!(effective_auto_lock_minutes(5, Some(10)), 5);
    assert_eq!(effective_auto_lock_minutes(0, None), 0);
}

#[test]
fn wrapped_key_unlocks_only_with_the_same_wrapping_key_and_document() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.bastion");
    let mut d = DocumentFile::new("A").unwrap();
    d.set_password(Some(PW)).unwrap();
    d.save_as(&path).unwrap();
    let wk = new_wrapping_key();
    let blob = d.export_wrapped_key(&wk).unwrap();
    assert!(!blob.contains(PW));

    let mut locked = DocumentFile::open(&path).unwrap();
    assert!(locked.is_locked());
    assert!(locked.unlock_with_wrapped_key(&blob, &new_wrapping_key()).is_err(), "other device key");
    assert!(locked.unlock_with_wrapped_key("00ff", &wk).is_err(), "garbage");
    locked.unlock_with_wrapped_key(&blob, &wk).unwrap();
    assert!(!locked.is_locked());

    let mut other = DocumentFile::new("B").unwrap();
    other.set_password(Some(PW)).unwrap();
    let other_path = dir.path().join("b.bastion");
    other.save_as(&other_path).unwrap();
    let mut other = DocumentFile::open(&other_path).unwrap();
    assert!(other.unlock_with_wrapped_key(&blob, &wk).is_err(), "bound to the document id");
}

#[test]
fn state_dirs_are_per_document_and_recents_show_missing_files() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let da = document_state_dir(dir.path(), a).unwrap();
    assert_ne!(da, document_state_dir(dir.path(), b).unwrap());
    assert!(da.is_dir());

    let path = dir.path().join("work.bastion");
    let mut d = DocumentFile::new("Work").unwrap();
    d.set_password(Some(PW)).unwrap();
    d.save_as(&path).unwrap();
    let gone = dir.path().join("gone.bastion");
    let recent = vec![path.clone(), gone.clone()];
    record_opened(dir.path(), &path, &recent, 1234).unwrap();
    let rows = recent_details(dir.path(), &recent);
    assert_eq!(rows[0].name.as_deref(), Some("Work"));
    assert!(rows[0].present && rows[0].protected && !rows[0].biometric);
    assert_eq!(rows[0].last_opened_at, Some(1234));
    assert_eq!(rows[0].id, Some(d.id()));
    assert!(!rows[1].present && rows[1].name.is_none());
}

#[test]
fn recents_carry_the_recorded_connection_count_and_nothing_when_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lab.bastion");
    let mut d = DocumentFile::new("Lab").unwrap();
    d.set_password(Some(PW)).unwrap();
    d.save_as(&path).unwrap();
    let other = dir.path().join("other.bastion");
    DocumentFile::new("Other").unwrap().save_as(&other).unwrap();
    let recent = vec![path.clone(), other.clone()];
    assert_eq!(recent_details(dir.path(), &recent)[0].connection_count, None);
    record_connection_count(dir.path(), &path, &recent, 12).unwrap();
    let rows = recent_details(dir.path(), &recent);
    assert_eq!(rows[0].connection_count, Some(12));
    assert_eq!(rows[1].connection_count, None);
    // Dropped from Recents: its count goes with it on the next write.
    record_connection_count(dir.path(), &other, &[other.clone()], 3).unwrap();
    assert_eq!(recent_details(dir.path(), &recent)[0].connection_count, None);
    // A file that is gone shows no count.
    std::fs::remove_file(&other).unwrap();
    assert_eq!(recent_details(dir.path(), &[other.clone()])[0].connection_count, None);
    let json = serde_json::to_string(&rows[0]).unwrap();
    assert!(json.contains("\"connectionCount\":12"), "{json}");
}

#[test]
fn managed_policy_caps_auto_lock_and_can_forbid_biometrics() {
    use crate::policy::Policy;
    let user = Policy::default();
    assert_eq!(policy_auto_lock_minutes(0, &user), 0);
    check_biometric_allowed(&user).unwrap();
    let managed: Policy = Policy::parse_managed(br#"{"document_auto_lock_max_minutes": 10, "password_only_document_unlock": true}"#).unwrap();
    let p = user.with_managed(&managed);
    assert_eq!(policy_auto_lock_minutes(0, &p), 10);
    assert_eq!(policy_auto_lock_minutes(30, &p), 10);
    assert_eq!(policy_auto_lock_minutes(5, &p), 5);
    assert!(check_biometric_allowed(&p).is_err());
}
