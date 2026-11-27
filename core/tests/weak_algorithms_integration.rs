//! A real SSH handshake against an in-process russh server on loopback that offers only a weak
//! key exchange: the client must refuse with a precise error, and connect once the weak
//! algorithm is allowed for that host. Hermetic; no external server needed.
use std::sync::Arc;
use std::time::Duration;

use bastion_core::algorithms::{AlgoKind, AlgorithmSettings};
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::CoreError;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::PrivateKey;
use russh::{kex, server, Preferred};

struct Accept;
impl server::Handler for Accept {
    type Error = russh::Error;
}

/// Serve SSH on an ephemeral loopback port offering only `diffie-hellman-group14-sha1`.
async fn weak_server() -> u16 {
    let key = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&[7; 32])), "test").unwrap();
    let preferred = Preferred { kex: std::borrow::Cow::Owned(vec![kex::DH_G14_SHA1, kex::EXTENSION_SUPPORT_AS_SERVER]), ..Preferred::DEFAULT };
    let config = Arc::new(server::Config { keys: vec![key], preferred, ..Default::default() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(s) = server::run_stream(config, sock, Accept).await {
                    let _ = s.await;
                }
            });
        }
    });
    port
}

fn params(port: u16, known_hosts: std::path::PathBuf, a: &AlgorithmSettings) -> SshParams {
    SshParams {
        host: "127.0.0.1".into(),
        port,
        username: "nobody".into(),
        auth: SshAuth::Password(bastion_core::vault::Secret::new("x")),
        known_hosts,
        policy: HostKeyPolicy::Strict,
        connect_timeout: Duration::from_secs(5),
        keepalive: None,
        prompter: None,
        algorithms: a.resolve(false).unwrap(),
    }
}

#[tokio::test]
async fn weak_only_server_gets_a_precise_error_then_allow_for_host_works() {
    let port = weak_server().await;
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");

    let err = SshSession::connect(params(port, kh.clone(), &AlgorithmSettings::default())).await.err().expect("must refuse");
    let CoreError::NoCommonAlgorithm { kind, server_offers, weak_allowable } = &err else { panic!("{err:?}") };
    assert_eq!(*kind, AlgoKind::Kex);
    assert_eq!(server_offers, &["diffie-hellman-group14-sha1"]);
    assert_eq!(weak_allowable, server_offers);
    assert!(err.to_string().contains("can be allowed for this host"), "{err}");

    // "Allow for this host": key exchange now completes and strict host-key checking takes over.
    let allowed = AlgorithmSettings::default().allowing(*kind, weak_allowable);
    let err = SshSession::connect(params(port, kh.clone(), &allowed)).await.err().expect("unknown host key");
    assert!(matches!(err, CoreError::HostKeyUnknown { .. }), "{err:?}");

    // Policy veto: the opt-in is ignored and the server is refused again.
    let mut p = params(port, kh, &AlgorithmSettings::default());
    p.algorithms = allowed.resolve(true).unwrap();
    assert!(matches!(SshSession::connect(p).await, Err(CoreError::NoCommonAlgorithm { .. })));
}
