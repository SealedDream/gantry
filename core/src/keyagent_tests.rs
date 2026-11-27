use super::*;
use russh::keys::agent::client::AgentClient;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicUsize;

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn new_key(comment: &str) -> PrivateKey {
    let k = crate::keymanager::generate_ed25519(comment, None).unwrap();
    russh::keys::decode_secret_key(&k.private_openssh, None).unwrap()
}

#[tokio::test]
async fn serves_loaded_keys_and_signs() {
    let dir = private_dir();
    let sock = dir.path().join("agent.sock");
    let key = new_key("work");
    let agent = start(&sock, std::slice::from_ref(&key), None).await.unwrap();
    assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);
    let mut c = AgentClient::connect_uds(agent.socket()).await.unwrap();
    let ids = c.request_identities().await.unwrap();
    assert_eq!(ids.len(), 1);
    let sig = c.sign_request_signature(key.public_key(), None, b"data").await;
    assert!(sig.is_ok());
}

#[tokio::test]
async fn clients_cannot_add_or_remove_keys() {
    let dir = private_dir();
    let agent = start(&dir.path().join("a.sock"), &[new_key("mine")], None).await.unwrap();
    let mut c = AgentClient::connect_uds(agent.socket()).await.unwrap();
    assert!(c.add_identity(&new_key("intruder"), &[]).await.is_err());
    let mut c = AgentClient::connect_uds(agent.socket()).await.unwrap();
    assert!(c.remove_all_identities().await.is_err());
    let mut c = AgentClient::connect_uds(agent.socket()).await.unwrap();
    assert_eq!(c.request_identities().await.unwrap().len(), 1);
}

#[tokio::test]
async fn confirm_callback_gates_every_signature() {
    let dir = private_dir();
    let key = new_key("prod");
    let asked = Arc::new(AtomicUsize::new(0));
    let allow = Arc::new(AtomicBool::new(false));
    let (a, b) = (asked.clone(), allow.clone());
    let want = key.fingerprint(russh::keys::HashAlg::Sha256).to_string();
    let confirm: ConfirmFn = Arc::new(move |_comment, fp| {
        assert_eq!(fp, want);
        a.fetch_add(1, Ordering::SeqCst);
        b.load(Ordering::SeqCst)
    });
    let agent = start(&dir.path().join("c.sock"), std::slice::from_ref(&key), Some(confirm)).await.unwrap();
    let mut c = AgentClient::connect_uds(agent.socket()).await.unwrap();
    assert!(c.sign_request_signature(key.public_key(), None, b"x").await.is_err());
    let mut c = AgentClient::connect_uds(agent.socket()).await.unwrap();
    allow.store(true, Ordering::SeqCst);
    assert!(c.sign_request_signature(key.public_key(), None, b"x").await.is_ok());
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn shared_folder_and_existing_socket_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(start(&dir.path().join("s.sock"), &[], None).await.is_err());
    let dir = private_dir();
    let sock = dir.path().join("s.sock");
    std::fs::write(&sock, b"").unwrap();
    assert!(start(&sock, &[], None).await.is_err());
}

#[tokio::test]
async fn drop_removes_the_socket() {
    let dir = private_dir();
    let sock = dir.path().join("d.sock");
    let agent = start(&sock, &[new_key("k")], None).await.unwrap();
    assert!(sock.exists());
    drop(agent);
    assert!(!sock.exists());
}

/// C02: a client that connected before the agent stopped must not be able to sign afterwards,
/// and its connection must be closed.
#[tokio::test]
async fn stopping_the_agent_revokes_connected_clients() {
    let dir = private_dir();
    let sock = dir.path().join("stop.sock");
    let key = new_key("held");
    let agent = start(&sock, std::slice::from_ref(&key), None).await.unwrap();
    let mut c = AgentClient::connect_uds(agent.socket()).await.unwrap();
    assert!(c.sign_request_signature(key.public_key(), None, b"before").await.is_ok());
    drop(agent);
    assert!(!sock.exists());
    let after = tokio::time::timeout(std::time::Duration::from_secs(5), c.sign_request_signature(key.public_key(), None, b"after")).await;
    assert!(matches!(after, Ok(Err(_))), "existing client still signed after stop");
}
