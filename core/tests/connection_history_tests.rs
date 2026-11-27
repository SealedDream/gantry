//! Connection history for the two-line inspector footer: what is recorded, that it stays
//! secret-free and bounded, and that the file is owner-only and survives damage.
use bastion_core::connection_history::{self, ConnectionHistory, History, MAX_ERROR_CHARS};
use bastion_core::CoreError;
use uuid::Uuid;

#[test]
fn success_then_failure_keeps_last_connected_and_shows_the_error() {
    let d = tempfile::tempdir().unwrap();
    let h = ConnectionHistory::in_dir(d.path());
    let id = Uuid::new_v4();
    assert_eq!(h.get(id), History::default());
    assert_eq!(h.get(id).last_result(), None, "nothing before the first attempt");

    h.record_success(id, Some("alice"), 1000).unwrap();
    let a = h.get(id);
    assert_eq!((a.last_connected_at, a.last_user.as_deref(), a.last_result()), (Some(1000), Some("alice"), Some("OK")));

    h.record_failure(id, "Connection refused\nat line 2", 2000).unwrap();
    let b = h.get(id);
    assert_eq!((b.last_connected_at, b.last_user.as_deref()), (Some(1000), Some("alice")), "last success kept");
    assert_eq!(b.last_result(), Some("Connection refused"));

    h.record_success(id, None, 3000).unwrap();
    let c = h.get(id);
    assert_eq!((c.last_connected_at, c.last_user.clone(), c.last_result()), (Some(3000), None, Some("OK")));
}

#[test]
fn errors_are_one_short_line_and_never_carry_secrets() {
    assert_eq!(connection_history::short_error("  \n\tTimed out\t after 3 s \n more"), "Timed out after 3 s");
    let long = connection_history::short_error(&"x".repeat(500));
    assert_eq!(long.chars().count(), MAX_ERROR_CHARS);
    assert!(long.ends_with('…'));
    assert_eq!(connection_history::short_error("login failed: password=hunter2"), "Failed (details hidden)");
    assert_eq!(connection_history::short_error("Token: abc123"), "Failed (details hidden)");
    assert_eq!(connection_history::short_error("\u{1b}[31mred\u{7}"), "[31mred");
    assert_eq!(connection_history::short_error(""), "Failed");
    assert_eq!(connection_history::short_core_error(&CoreError::AuthFailed), "Authentication failed");
    assert_eq!(connection_history::short_core_error(&CoreError::SecretLeak("hunter2".into())), "Failed (details hidden)");
    assert_eq!(connection_history::short_core_error(&CoreError::Offline("x".into())), "Offline");

    let d = tempfile::tempdir().unwrap();
    let h = ConnectionHistory::in_dir(d.path());
    let id = Uuid::new_v4();
    h.record_failure(id, "auth: passphrase = s3cret", 1).unwrap();
    let raw = std::fs::read_to_string(d.path().join(connection_history::FILE_NAME)).unwrap();
    assert!(!raw.contains("s3cret"));
    assert!(h.record_success(id, Some("bad user\n"), 2).is_err(), "usernames are validated");
}

#[test]
fn file_is_owner_only_and_damage_means_empty_history() {
    let d = tempfile::tempdir().unwrap();
    let h = ConnectionHistory::in_dir(d.path());
    let id = Uuid::new_v4();
    h.record_success(id, Some("ops"), 5).unwrap();
    let path = d.path().join(connection_history::FILE_NAME);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    std::fs::write(&path, b"\xff{not json").unwrap();
    assert_eq!(h.get(id), History::default());
    h.record_failure(id, "Timed out", 6).unwrap();
    assert_eq!(h.get(id).last_result(), Some("Timed out"), "recovers by rewriting");
}

#[test]
fn forget_prune_and_the_size_cap() {
    let d = tempfile::tempdir().unwrap();
    let h = ConnectionHistory::in_dir(d.path());
    let ids: Vec<Uuid> = (0..4).map(|_| Uuid::new_v4()).collect();
    for (i, id) in ids.iter().enumerate() {
        h.record_success(*id, Some("u"), i as u64).unwrap();
    }
    h.forget(ids[0]).unwrap();
    assert_eq!(h.prune(&ids[1..3]).unwrap(), 1);
    assert_eq!(h.all().len(), 2);

    // Over the cap the oldest attempts go, never the one just recorded.
    let cap = connection_history::MAX_CONNECTIONS;
    let start = std::time::Instant::now();
    let many: Vec<Uuid> = (0..cap + 3).map(|_| Uuid::new_v4()).collect();
    let d2 = tempfile::tempdir().unwrap();
    let h2 = ConnectionHistory::in_dir(d2.path());
    let seeded: std::collections::BTreeMap<Uuid, History> =
        many.iter().enumerate().map(|(i, id)| (*id, History { last_attempt_at: Some(100 + i as u64), ..Default::default() })).collect();
    std::fs::write(d2.path().join(connection_history::FILE_NAME), serde_json::to_vec(&serde_json::json!({ "connections": seeded })).unwrap()).unwrap();
    let newest = Uuid::new_v4();
    h2.record_failure(newest, "Timed out", 1).unwrap();
    let all = h2.all();
    assert_eq!(all.len(), cap);
    assert!(all.contains_key(&newest), "the entry just recorded stays even with an old clock");
    assert!(!all.contains_key(&many[0]) && all.contains_key(&many[cap + 2]));
    assert!(start.elapsed().as_secs() < 5, "took {:?}", start.elapsed());
}

/// Grow-only stores audit (2026-11-16): a year of connects to ever-new connections keeps the file at the cap,
/// and forgetting deleted connections shrinks it.
#[test]
fn many_connects_keep_the_history_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let h = ConnectionHistory::in_dir(dir.path());
    let cap = connection_history::MAX_CONNECTIONS;
    let ids: Vec<Uuid> = (0..cap + 1_000).map(|_| Uuid::new_v4()).collect();
    for (at, id) in ids.iter().enumerate() {
        h.record_success(*id, Some("ops"), at as u64).unwrap();
    }
    assert_eq!(h.all().len(), cap);
    let size_at_cap = std::fs::metadata(dir.path().join(connection_history::FILE_NAME)).unwrap().len();

    let t = std::time::Instant::now();
    for (at, id) in ids.iter().cycle().skip(17).take(500).enumerate() {
        h.record_failure(*id, "connection refused", (cap + 1_000 + at) as u64).unwrap();
    }
    eprintln!("connection history at {cap} entries: {:?} per connect, {size_at_cap} bytes", t.elapsed() / 500);
    assert_eq!(h.all().len(), cap);
    let size_after = std::fs::metadata(dir.path().join(connection_history::FILE_NAME)).unwrap().len();
    assert!(size_after < size_at_cap * 11 / 10, "the file stays near its size at the cap: {size_at_cap} -> {size_after}");

    for id in h.all().keys().take(2_000) {
        h.forget(*id).unwrap();
    }
    assert_eq!(h.all().len(), cap - 2_000, "deleted connections leave the file");
}
