//! C08: RSA user authentication must not fall back to SHA-1 (`ssh-rsa`) without explicit
//! weak-algorithm consent. An in-process russh server whose `server-sig-algs` names only
//! `ssh-rsa` records which signature algorithm each verified publickey login used.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bastion_core::algorithms::{AlgoKind, AlgorithmSettings};
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::{Algorithm, HashAlg};
use russh::keys::PrivateKey;
use russh::server::{Auth, VerifiedPublicKey};
use russh::{server, Preferred};

type Seen = Arc<Mutex<Vec<Algorithm>>>;

struct Recorder(Seen);
impl server::Handler for Recorder {
    type Error = russh::Error;
    async fn auth_publickey(&mut self, _user: &str, key: VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        self.0.lock().unwrap().push(key.algorithm.clone());
        Ok(Auth::Accept)
    }
}

/// A server whose `server-sig-algs` offers only `ssh-rsa` (SHA-1) for RSA keys.
async fn server(seen: Seen) -> (u16, String) {
    let key = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&[9; 32])), "").unwrap();
    let host = key.public_key().to_openssh().unwrap();
    // `server-sig-algs` follows `preferred.key`: list ssh-rsa as the only RSA signature.
    let preferred = Preferred { key: std::borrow::Cow::Owned(vec![Algorithm::Ed25519, SHA1]), ..Preferred::DEFAULT };
    let config = Arc::new(server::Config { keys: vec![key], preferred, ..Default::default() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let (config, seen) = (config.clone(), seen.clone());
            tokio::spawn(async move {
                if let Ok(s) = server::run_stream(config, sock, Recorder(seen)).await {
                    let _ = s.await;
                }
            });
        }
    });
    (port, host)
}

fn rsa_key(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("id_rsa");
    let ok = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f"])
        .arg(&path)
        .status()
        .expect("ssh-keygen runs")
        .success();
    assert!(ok);
    path
}

async fn login(algorithms: AlgorithmSettings, forbid_weak: bool) -> (bool, Vec<Algorithm>) {
    let seen: Seen = Arc::default();
    let (port, host) = server(seen.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    std::fs::write(&kh, format!("[127.0.0.1]:{port} {host}\n")).unwrap();
    let p = SshParams {
        host: "127.0.0.1".into(),
        port,
        username: "alice".into(),
        auth: SshAuth::KeyFile { path: rsa_key(dir.path()), passphrase: None },
        known_hosts: kh,
        policy: HostKeyPolicy::Strict,
        connect_timeout: Duration::from_secs(10),
        keepalive: None,
        prompter: None,
        algorithms: algorithms.resolve(forbid_weak).unwrap(),
    };
    let ok = SshSession::connect(p).await.is_ok();
    let seen = seen.lock().unwrap().clone();
    (ok, seen)
}

const SHA1: Algorithm = Algorithm::Rsa { hash: None };

#[tokio::test]
async fn rsa_login_never_uses_sha1_by_default() {
    let (_, seen) = login(AlgorithmSettings::default(), false).await;
    assert!(!seen.contains(&SHA1), "signed with SHA-1 without consent: {seen:?}");
    assert!(seen.iter().all(|a| matches!(a, Algorithm::Rsa { hash: Some(HashAlg::Sha256 | HashAlg::Sha512) })), "{seen:?}");
}

#[tokio::test]
async fn rsa_sha1_is_never_used_under_the_policy_veto() {
    let allowed = AlgorithmSettings::default().allowing(AlgoKind::HostKey, &["ssh-rsa".to_string()]);
    let (_, seen) = login(allowed, true).await;
    assert!(!seen.contains(&SHA1), "SHA-1 used despite forbid_weak_ssh_algorithms: {seen:?}");
}

#[tokio::test]
async fn rsa_sha1_needs_explicit_consent() {
    let allowed = AlgorithmSettings::default().allowing(AlgoKind::HostKey, &["ssh-rsa".to_string()]);
    let (ok, seen) = login(allowed, false).await;
    assert!(ok);
    assert_eq!(seen, vec![SHA1]);
}
