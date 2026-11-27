use bastion_core::provider::{vault_key, CredentialProvider, LocalVaultProvider, ProviderStatus};
use bastion_core::vault::{Credential, CredentialKind, Secret, Vault};
use bastion_core::CoreError;
use uuid::Uuid;

#[test]
fn local_vault_provider_serves_secrets_and_locks() {
    let mut v = Vault::default();
    let id = v.add(Credential {
        id: Uuid::new_v4(),
        name: "k".into(),
        folder: None,
        scope: Some("acme".into()),
        owner: None,
        kind: CredentialKind::SshKey { username: "u".into(), private_key: Secret::new("PEM"), passphrase: Some(Secret::new("pp")) },
    });
    let p = LocalVaultProvider::new(Some(v));
    assert_eq!(p.status(), ProviderStatus::Available);
    assert_eq!(p.fetch(&id.to_string()).unwrap().expose(), "PEM");
    assert_eq!(p.fetch(&format!("{id}#passphrase")).unwrap().expose(), "pp");
    assert!(matches!(p.fetch(&Uuid::new_v4().to_string()), Err(CoreError::NotFound(_))));
    p.lock();
    assert_eq!(p.status(), ProviderStatus::Locked);
    assert!(matches!(p.fetch(&id.to_string()), Err(CoreError::VaultAuth)));
}

/// Real macOS login-Keychain round trip: wraps a vault key, reopens the vault with it.
#[cfg(target_os = "macos")]
#[ignore = "live: needs BASTION_KEYCHAIN_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn keychain_wraps_vault_key() {
    assert!(std::env::var_os("BASTION_KEYCHAIN_TEST").is_some(), "live test run without BASTION_KEYCHAIN_TEST: start the fixture (docs/TESTING.md)");
    use bastion_core::provider::KeychainProvider;
    if std::env::var("BASTION_KEYCHAIN_TEST").is_err() {
        eprintln!("SKIPPED: set BASTION_KEYCHAIN_TEST=1 to touch the login Keychain");
        return;
    }
    let kc = KeychainProvider::new(format!("app.bastion.test.{}", Uuid::new_v4()));
    let vault_id = "test-vault";
    let k1 = vault_key(&kc, vault_id).unwrap();
    assert_eq!(k1.expose().len(), 64);
    let k2 = vault_key(&kc, vault_id).unwrap();
    assert_eq!(k1.expose(), k2.expose(), "second call reads the stored key");

    let mut v = Vault::default();
    v.add(Credential { id: Uuid::new_v4(), name: "n".into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: "u".into(), password: Secret::new("pw") } });
    let sealed = v.seal(k1.expose()).unwrap();
    assert_eq!(Vault::open(&sealed, vault_key(&kc, vault_id).unwrap().expose()).unwrap().list().len(), 1);

    kc.delete(&format!("vault-key:{vault_id}")).unwrap();
    assert!(matches!(kc.fetch(&format!("vault-key:{vault_id}")), Err(CoreError::NotFound(_))));
}
