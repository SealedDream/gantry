//! A1-CORE-01-FU1 through the Mac bridge: a Bastion export that names one of the user's saved
//! credentials and routes through a jump host is imported with `Library::import_file`. Its login
//! is offered, not used automatically, so no app that follows `auto_use` connects (and hands the
//! login to the first hop) without the user's yes. Generated data only.
use std::sync::Arc;

use bastion_core::model::{Connection, Node, Protocol};

use crate::{CredentialVault, Library};

fn library(dir: &std::path::Path, file: &str) -> Arc<Library> {
    Arc::new(Library::open(dir.join(file).display().to_string()).unwrap())
}

#[test]
fn an_imported_connection_with_a_jump_host_does_not_use_the_login_it_names() {
    let dir = tempfile::tempdir().unwrap();
    // The sender's library: a host of theirs behind a jump host of theirs, naming "Admin".
    let sender = library(dir.path(), "sender.json");
    let mut c = Connection::new("app", Protocol::Ssh, "app.sender.example");
    c.settings.credential_name = Some("Admin".into());
    c.metadata.insert("ProxyJump".into(), "jump.sender.example".into());
    sender.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();
    let export = dir.path().join("sent.json");
    sender.export_to(export.display().to_string(), None).unwrap();

    // The user's library and vault, with a credential of that name.
    let mine = library(dir.path(), "mine.json");
    let vault = CredentialVault::open_ephemeral(dir.path().join("c.vault").display().to_string()).unwrap();
    let admin = vault.save_password(None, "Admin".into(), None, "admin".into(), "pw-admin".into()).unwrap();
    mine.import_file(export.display().to_string()).unwrap();
    let received = mine.lock().connections().into_iter().find(|r| r.connection.name == "app").expect("imported").connection;
    assert_eq!(received.metadata.get("ProxyJump").map(String::as_str), Some("jump.sender.example"), "the route came along");
    let id = received.id.to_string();
    let rows = || vault.login_candidates(mine.clone(), id.clone(), false).unwrap().into_iter().map(|l| (l.source, l.auto_use, l.credential_id)).collect::<Vec<_>>();

    assert_eq!(rows(), vec![("named".to_string(), false, admin.clone())]);

    // "Use this login from now on" is the user's yes.
    vault.add_login(mine.clone(), id.clone(), admin.clone()).unwrap();
    assert_eq!(rows(), vec![("default".to_string(), true, admin)]);
}
