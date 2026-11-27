//! Recent usernames per host ("Connect as…" suggestions): newest first, capped, no secrets.
use bastion_core::recent_users::{host_key, RecentUsers, FILE_NAME, MAX_PER_HOST};

fn store() -> (tempfile::TempDir, RecentUsers) {
    let dir = tempfile::tempdir().unwrap();
    let s = RecentUsers::in_dir(dir.path());
    (dir, s)
}

#[test]
fn newest_first_without_duplicates() {
    let (_d, s) = store();
    s.record("Host.Example", Some(22), "alice").unwrap();
    s.record("host.example", Some(22), "bob").unwrap();
    s.record("HOST.example", Some(22), "alice").unwrap();
    assert_eq!(s.list("host.example", Some(22)).unwrap(), ["alice", "bob"]);
    assert!(s.list("host.example", Some(2222)).unwrap().is_empty(), "the port is part of the host");
}

#[test]
fn caps_per_host() {
    let (_d, s) = store();
    for i in 0..MAX_PER_HOST + 3 {
        s.record("h", None, &format!("u{i}")).unwrap();
    }
    let l = s.list("h", None).unwrap();
    assert_eq!(l.len(), MAX_PER_HOST);
    assert_eq!(l[0], format!("u{}", MAX_PER_HOST + 2));
}

#[test]
fn refuses_bad_usernames_and_hosts() {
    let (_d, s) = store();
    for bad in ["", "  ", "a b", "x\ny", &"u".repeat(300)] {
        assert!(s.record("h", None, bad).is_err(), "{bad:?}");
    }
    assert!(host_key("", None).is_err());
    assert!(host_key("a b", None).is_err());
    assert!(s.list("h", None).unwrap().is_empty());
}

#[test]
fn forget_one_or_all() {
    let (_d, s) = store();
    s.record("h", None, "a").unwrap();
    s.record("h", None, "b").unwrap();
    s.forget("h", None, Some("b")).unwrap();
    assert_eq!(s.list("h", None).unwrap(), ["a"]);
    s.forget("h", None, None).unwrap();
    assert!(s.list("h", None).unwrap().is_empty());
}

#[test]
fn file_holds_usernames_only_and_damage_means_empty() {
    let (d, s) = store();
    s.record("h", None, "alice").unwrap();
    let text = std::fs::read_to_string(d.path().join(FILE_NAME)).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["hosts"]["h"], serde_json::json!(["alice"]));
    assert_eq!(v.as_object().unwrap().len(), 2, "hosts and order only");
    std::fs::write(d.path().join(FILE_NAME), b"{not json").unwrap();
    assert!(s.list("h", None).unwrap().is_empty());
    s.record("h", None, "bob").unwrap();
    assert_eq!(s.list("h", None).unwrap(), ["bob"]);
}
