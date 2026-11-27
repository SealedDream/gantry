use super::*;

fn verifier(known_hosts: PathBuf, policy: HostKeyPolicy) -> Verifier {
    Verifier {
        host: "10.0.0.5".into(),
        port: 22,
        known_hosts,
        policy,
        issue: Arc::new(Mutex::new(None)),
        forwards: Arc::new(Mutex::new(HashMap::new())),
    }
}

fn host_key() -> PublicKey {
    let k = crate::keymanager::generate_ed25519("host", None).unwrap();
    PublicKey::new(russh::keys::decode_secret_key(&k.private_openssh, None).unwrap().public_key().key_data().clone(), "")
}

/// C03: `@revoked` must win over an ordinary known_hosts entry for the same plain key.
#[test]
fn revoked_plain_key_is_refused_even_when_known() {
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    let key = host_key();
    let line = key.to_openssh().unwrap();
    std::fs::write(&kh, format!("10.0.0.5 {line}\n@revoked * {line}\n")).unwrap();
    let v = verifier(kh, HostKeyPolicy::Strict);
    assert!(!v.verify(&key).unwrap(), "revoked host key was accepted");
}

/// C03: neither trust-on-first-use nor an explicitly trusted fingerprint may learn a revoked key.
#[test]
fn revoked_plain_key_is_never_learned() {
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    let key = host_key();
    std::fs::write(&kh, format!("@revoked 10.0.0.* {}\n", key.to_openssh().unwrap())).unwrap();
    for policy in [HostKeyPolicy::AcceptNew, HostKeyPolicy::TrustFingerprint(fingerprint(&key))] {
        let v = verifier(kh.clone(), policy);
        assert!(!v.verify(&key).unwrap(), "revoked host key was learned");
    }
    assert!(!std::fs::read_to_string(&kh).unwrap().lines().any(|l| l.starts_with("10.0.0.5 ")));
}

#[test]
fn unrevoked_known_key_still_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    let key = host_key();
    std::fs::write(&kh, format!("10.0.0.5 {}\n@revoked * {}\n", key.to_openssh().unwrap(), host_key().to_openssh().unwrap())).unwrap();
    assert!(verifier(kh, HostKeyPolicy::Strict).verify(&key).unwrap());
}
