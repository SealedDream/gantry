//! Live HashiCorp Vault lab (dev-mode `hashicorp/vault` container; see docs/TESTING.md).
//! `BASTION_HCVAULT_TEST=<url>,<root token>`; the test seeds its own generated secrets on
//! KV v2 (`secret/`) and a KV v1 mount (`kv1/`), and a read-only policy token for denial.
use bastion_core::hcvault::{HcVaultProvider, KvVersion};
use bastion_core::provider::CredentialProvider;
use bastion_core::vault::Secret;
use bastion_core::CoreError;
use serde_json::json;

fn lab() -> Option<(String, String)> {
    let spec = std::env::var("BASTION_HCVAULT_TEST").ok()?;
    let (url, token) = spec.split_once(',')?;
    Some((url.to_string(), token.to_string()))
}

fn api(url: &str, token: &str, method: &str, path: &str, body: serde_json::Value) -> serde_json::Value {
    let req = ureq::request(method, &format!("{url}/v1/{path}")).set("X-Vault-Token", token);
    match req.send_json(body) {
        Ok(r) => r.into_json().unwrap_or(json!({})),
        Err(ureq::Error::Status(400, _)) if path.starts_with("sys/mounts") => json!({}), // already mounted
        Err(e) => panic!("vault {method} {path}: {e}"),
    }
}

#[ignore = "live: needs BASTION_HCVAULT_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn live_vault_kv1_kv2_denial_and_lock() {
    assert!(std::env::var_os("BASTION_HCVAULT_TEST").is_some(), "live test run without BASTION_HCVAULT_TEST: start the fixture (docs/TESTING.md)");
    let Some((url, root)) = lab() else {
        eprintln!("SKIPPED live_vault_kv1_kv2_denial_and_lock: set BASTION_HCVAULT_TEST=url,token");
        return;
    };
    let pw = format!("gen-{}", uuid::Uuid::new_v4());
    api(&url, &root, "POST", "secret/data/bastion/lab", json!({"data": {"username": "tester", "password": pw}}));
    api(&url, &root, "POST", "sys/mounts/kv1", json!({"type": "kv", "options": {"version": "1"}}));
    api(&url, &root, "POST", "kv1/bastion/lab", json!({"username": "v1-tester"}));
    api(&url, &root, "PUT", "sys/policies/acl/bastion-none", json!({"policy": "path \"kv1/*\" { capabilities = [\"read\"] }"}));
    let limited = api(&url, &root, "POST", "auth/token/create", json!({"policies": ["bastion-none"], "ttl": "5m"}));
    let limited = limited["auth"]["client_token"].as_str().expect("limited token").to_string();

    let v2 = HcVaultProvider::new(&url, KvVersion::V2, None).unwrap();
    assert!(v2.fetch("secret/bastion/lab#password").is_err(), "locked provider must not fetch");
    v2.unlock(Secret::new(root.clone()));
    assert_eq!(v2.fetch("secret/bastion/lab#password").unwrap().expose(), pw);
    assert_eq!(v2.fetch("secret/bastion/lab#username").unwrap().expose(), "tester");
    assert!(matches!(v2.fetch("secret/bastion/lab#missing"), Err(CoreError::NotFound(_))));
    assert!(v2.fetch("secret/bastion/absent#password").is_err());
    assert!(v2.store("secret/bastion/lab#password", &Secret::new("x")).is_err(), "provider is read-only");

    let v1 = HcVaultProvider::new(&url, KvVersion::V1, None).unwrap();
    v1.unlock(Secret::new(limited.clone()));
    assert_eq!(v1.fetch("kv1/bastion/lab#username").unwrap().expose(), "v1-tester");

    let denied = HcVaultProvider::new(&url, KvVersion::V2, None).unwrap();
    denied.unlock(Secret::new(limited));
    assert!(matches!(denied.fetch("secret/bastion/lab#password"), Err(CoreError::AuthFailed)));

    let bad = HcVaultProvider::new(&url, KvVersion::V2, None).unwrap();
    bad.unlock(Secret::new("not-a-real-token"));
    assert!(matches!(bad.fetch("secret/bastion/lab#password"), Err(CoreError::AuthFailed)));

    v2.lock();
    assert!(v2.fetch("secret/bastion/lab#password").is_err(), "lock clears the token");
}
