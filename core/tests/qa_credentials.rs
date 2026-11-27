//! Journey 4: URL checks only; these tests never issue a network request.
use bastion_core::vaultwarden::check_url;

#[test]
fn credential_provider_requires_tls_except_for_loopback() {
    assert!(check_url("https://vault.example.invalid").is_ok());
    assert!(check_url("http://127.0.0.1:8080").is_ok());
    assert!(check_url("http://vault.example.invalid").is_err());
}

#[test]
fn apparent_loopback_userinfo_cannot_authorize_remote_plaintext_http() {
    assert!(check_url("http://localhost:80@vault.example.invalid").is_err());
}
