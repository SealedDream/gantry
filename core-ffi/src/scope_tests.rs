//! F01: a saved credential keeps its own customer scope through the SSH bridge. The policy
//! check runs before any dial, so no server is needed: a port nobody listens on is enough.
use std::collections::HashMap;
use std::sync::Arc;

use bastion_core::model::{Connection, Node, Protocol};
use bastion_core::vault::{Credential, CredentialKind, Secret};
use uuid::Uuid;

use crate::{CredentialVault, Library, SessionManager, SshLogin};

fn connect_with_scoped_credential(cred_scope: Option<&str>, conn_customer: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let lib = Arc::new(Library::open(dir.path().join("lib.json").display().to_string()).unwrap());
    let mut c = Connection::new("b-host", Protocol::Ssh, "127.0.0.1");
    c.settings.port = Some(1);
    c.classification.customer = Some(conn_customer.into());
    // The credential is the connection's own login, so the shared login rule allows it
    // (A1-CORE-01-FU2) and the customer scope is the only thing that can refuse it.
    let id = Uuid::new_v4();
    c.settings.credential_id = Some(id);
    let conn_id = c.id.to_string();
    lib.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();

    let vault = Arc::new(CredentialVault::open_with_key(dir.path().join("c.vault").display().to_string(), Secret::new("k".repeat(64))).unwrap());
    vault.lock().add(Credential {
        id,
        name: "a-admin".into(),
        folder: None,
        scope: cred_scope.map(String::from),
        owner: None,
        kind: CredentialKind::Password { username: "root".into(), password: Secret::new("a-secret".to_string()) },
    });
    let mgr = SessionManager::new(dir.path().display().to_string()).unwrap();
    mgr.set_vault(vault);
    match mgr.connect_ssh(lib, conn_id, String::new(), SshLogin::Vault { credential_id: id.to_string() }, None, HashMap::new(), HashMap::new(), 80, 24) {
        Ok(_) => "connected".into(),
        Err(e) => e.to_string(),
    }
}

#[test]
fn credential_of_customer_a_is_refused_for_customer_b() {
    let err = connect_with_scoped_credential(Some("A"), "B");
    assert!(err.contains("belongs to customer `A`"), "expected a scope denial, got: {err}");
}

#[test]
fn credential_of_the_same_customer_reaches_the_dial() {
    let err = connect_with_scoped_credential(Some("B"), "B");
    assert!(!err.contains("belongs to customer"), "same-customer credential was refused: {err}");
}
