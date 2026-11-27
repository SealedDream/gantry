//! Snippet store: validation, secret refusal, persistence, search.
use bastion_core::snippets::{Snippet, SnippetStore};

#[test]
fn snippets_round_trip_search_and_refuse_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let path = SnippetStore::file(dir.path());
    let mut store = SnippetStore::open(path.clone()).unwrap();
    let id = store.put("Disk usage", "df -h /", None).unwrap();
    store.put("Restart nginx", "sudo systemctl restart nginx\nsudo systemctl status nginx --no-pager", None).unwrap();
    assert!(store.put("disk usage", "du -sh", None).is_err(), "unique names");
    assert!(store.put("Login", "sshpass -p hunter2 ssh x", None).is_err(), "inline passwords refused");
    assert!(store.put("Key", "-----BEGIN OPENSSH PRIVATE KEY-----", None).is_err());
    assert!(store.put("", "x", None).is_err());
    assert!(store.put("Empty", "   ", None).is_err());
    store.put("Disk usage (all)", "df -h", Some(&id)).unwrap();
    let back = SnippetStore::open(path.clone()).unwrap();
    assert_eq!(back.list().iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["Disk usage (all)", "Restart nginx"]);
    assert_eq!(back.search("nginx status").len(), 1);
    assert!(back.list()[1].is_multiline());
    assert!(!Snippet { id: "x".into(), name: "n".into(), text: "ls\n".into() }.is_multiline(), "one trailing newline is one command");
    store.remove(&id).unwrap();
    assert!(store.remove(&id).is_err());
    std::fs::write(&path, b"{").unwrap();
    assert!(SnippetStore::open(path).is_err(), "damaged file is an error");
}
