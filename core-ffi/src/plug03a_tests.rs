//! PLUG-03a through the Mac bridge: the tree marks an entry of an unknown type with the core's
//! fixed text, every way to use it is refused with that text, and saving keeps its data.
use std::sync::Arc;

use bastion_core::model::NEEDS_NEWER;

use crate::*;

const LIBRARY: &str = include_str!("../../core/tests/fixtures/plug03a/library-unknown.json");
const UNKNOWN_ID: &str = "0a000000-0000-4000-8000-000000000004";
const SSH_ID: &str = "0a000000-0000-4000-8000-000000000005";

fn library(dir: &std::path::Path) -> (Library, std::path::PathBuf) {
    let path = dir.join("library.json");
    std::fs::write(&path, LIBRARY).unwrap();
    (Library::open(path.display().to_string()).expect("an unknown connection type is not corruption"), path)
}

fn refused<T>(r: FfiResult<T>) {
    match r {
        Err(FfiError::Failed { message, code }) => assert!(message.contains(NEEDS_NEWER) && code != "corrupt", "{code}: {message}"),
        Err(e) => panic!("expected the fixed text, got {e}"),
        Ok(_) => panic!("an entry of an unknown type must be refused"),
    }
}

#[test]
fn tree_marks_an_unknown_entry_with_the_fixed_text() {
    let dir = tempfile::tempdir().unwrap();
    let (lib, _) = library(dir.path());
    let tree = lib.tree();
    let rows = &tree.folders[0].connections;
    let unknown = rows.iter().find(|c| c.id == UNKNOWN_ID).expect("the entry is listed");
    assert_eq!(unknown.unavailable.as_deref(), Some("Needs a newer Gantry or a plugin"));
    assert_eq!((unknown.name.as_str(), unknown.protocol.as_str(), unknown.has_tools), ("orders-db", "postgresql", false));
    let known = rows.iter().find(|c| c.id == SSH_ID).unwrap();
    assert_eq!((known.unavailable.as_deref(), known.protocol.as_str()), (None, "ssh"));
}

#[test]
fn an_unknown_entry_is_refused_everywhere_and_saved_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let (lib, path) = library(dir.path());
    let lib = Arc::new(lib);
    let unknown = uuid::Uuid::parse_str(UNKNOWN_ID).unwrap();

    // Every session, transfer and tool call resolves the connection first.
    refused(lib.resolve(unknown));
    refused(lib.resolve_many(&[uuid::Uuid::parse_str(SSH_ID).unwrap(), unknown]));
    refused(lib.set_property(UNKNOWN_ID.into(), "host".into(), Some("other.example".into())));
    refused(lib.set_property(UNKNOWN_ID.into(), "port".into(), Some("22".into())));
    // Multi-host exec with the entry among its hosts.
    let mgr = SessionManager::new(dir.path().display().to_string()).unwrap();
    let login = SshLogin::Password { password: "typed-for-test".into() };
    refused(MultiExec::new(mgr, lib.clone(), vec![SSH_ID.into(), UNKNOWN_ID.into()], "true".into(), 1, "tester".into(), login, false).map(|_| ()));

    // Its menu still opens, with Rename, Move and Delete and nothing that connects.
    let handled: Vec<String> = bastion_core::actions::all_ids().into_iter().map(|a| a.as_str()).collect();
    let sessions = SessionSnapshot { connected: vec![], connecting: vec![], failed: vec![] };
    let menu: Vec<String> = lib.menu(Some(UNKNOWN_ID.into()), sessions, handled).unwrap().into_iter().map(|m| m.id).collect();
    assert!(["rename", "move", "delete"].iter().all(|a| menu.iter().any(|m| m == a)), "{menu:?}");
    assert!(!menu.iter().any(|m| m.starts_with("connect") || m == "duplicate" || m == "open_sftp"), "{menu:?}");

    // Rename and move work like for any entry, and a save keeps what this app does not know.
    lib.set_property(UNKNOWN_ID.into(), "name".into(), Some("orders-db-2".into())).unwrap();
    lib.move_node(UNKNOWN_ID.into(), None).unwrap();
    lib.save().unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let original: serde_json::Value = serde_json::from_str(LIBRARY).unwrap();
    let moved = saved["root"]["children"].as_array().unwrap().iter().find(|n| n["id"] == UNKNOWN_ID).unwrap();
    assert_eq!((moved["name"].as_str(), moved["protocol"].as_str()), (Some("orders-db-2"), Some("postgresql")));
    assert_eq!(moved.get("plugin"), original.pointer("/root/children/0/children/0/plugin"));
    assert_eq!(saved.pointer("/type_defaults/postgresql"), original.pointer("/type_defaults/postgresql"));
    assert_eq!(saved.pointer("/plugins"), original.pointer("/plugins"));
}

/// The fixture library with `credential` as the unknown entry's own login, opened from `dir`.
fn library_with_login(dir: &std::path::Path, credential: &str) -> Arc<Library> {
    let mut v: serde_json::Value = serde_json::from_str(LIBRARY).unwrap();
    v.pointer_mut("/root/children/0/children/0/settings").unwrap()["credential_id"] = serde_json::json!(credential);
    let path = dir.join("library.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    Arc::new(Library::open(path.display().to_string()).unwrap())
}

#[test]
fn no_login_is_released_for_an_unknown_entry_or_offered_by_it() {
    let dir = tempfile::tempdir().unwrap();
    let vault = CredentialVault::open_ephemeral(dir.path().join("c.vault").display().to_string()).unwrap();
    let cred = vault.save_password(None, "App".into(), None, "app".into(), "typed-for-test".into()).unwrap();
    let lib = library_with_login(dir.path(), &cred);
    // A known entry on the same host as the unknown one.
    let rdp = lib.add_connection(None, "orders-rdp".into(), "rdp".into(), "db.lab.example".into(), None, None).unwrap();

    refused(vault.release_login(lib.clone(), UNKNOWN_ID.into(), cred.clone()).map(|_| ()));
    let e = vault.release_login(lib.clone(), rdp, cred).map(|_| ()).expect_err("an unknown entry offers no same-host login");
    assert!(e.to_string().contains("not offered"), "{e}");
}

#[test]
fn test_connection_on_an_unknown_type_gets_the_fixed_text() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = SessionManager::new(dir.path().display().to_string()).unwrap();
    let input = |protocol: &str| ProbeInput { protocol: protocol.into(), host: "db.lab.example".into(), port: 5432, username: "app".into(), login: None, jumps: vec![], pasted_key: None, pasted_key_passphrase: None, trusted_fingerprint: None, connection_id: None };
    refused(mgr.test_connection(None, input("postgresql")).map(|_| ()));
    refused(mgr.test_connection(None, input("org.bastion.postgresql/table")).map(|_| ()));
}
