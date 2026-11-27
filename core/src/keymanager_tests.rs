use super::*;
use russh::keys::ssh_key::private::SkEd25519;
use russh::keys::ssh_key::public;

// Fixtures from the ssh-key crate's test vectors; the encrypted ones use the passphrase "123".
const PPK_ED25519: &str = include_str!("../tests/fixtures/keys/id_ed25519.ppk");
const PPK_ED25519_ENC: &str = include_str!("../tests/fixtures/keys/id_ed25519_enc.ppk");
const PPK2_RSA_ENC: &str = include_str!("../tests/fixtures/keys/id_rsa_3072_enc.ppk2");
const PPK_ECDSA: &str = include_str!("../tests/fixtures/keys/id_ecdsa_p256.ppk");

#[test]
fn generated_key_is_ed25519_and_round_trips() {
    let key = generate_ed25519("me@laptop", None).unwrap();
    assert_eq!(key.info.algorithm, "ssh-ed25519");
    assert!(key.info.fingerprint.starts_with("SHA256:"));
    assert!(key.info.public_openssh.ends_with(" me@laptop"));
    assert!(!key.info.hardware);
    assert_eq!(inspect(&key.private_openssh, None).unwrap().fingerprint, key.info.fingerprint);
}

#[test]
fn two_generated_keys_differ() {
    let a = generate_ed25519("", None).unwrap();
    let b = generate_ed25519("", None).unwrap();
    assert_ne!(a.info.fingerprint, b.info.fingerprint);
}

#[test]
fn passphrase_encrypts_the_output() {
    let key = generate_ed25519("x", Some("correct horse")).unwrap();
    let err = inspect(&key.private_openssh, None).unwrap_err();
    assert!(err.to_string().contains("passphrase"), "{err}");
    assert!(inspect(&key.private_openssh, Some("wrong")).is_err());
    assert_eq!(inspect(&key.private_openssh, Some("correct horse")).unwrap().fingerprint, key.info.fingerprint);
}

#[test]
fn empty_passphrase_means_plain() {
    let key = generate_ed25519("x", Some("")).unwrap();
    assert!(inspect(&key.private_openssh, None).is_ok());
}

#[test]
fn comment_with_newline_is_refused() {
    assert!(generate_ed25519("a\nb", None).is_err());
    assert!(generate_ed25519(&"c".repeat(MAX_COMMENT + 1), None).is_err());
}

#[test]
fn ppk_v3_imports_and_converts_to_openssh() {
    let info = inspect(PPK_ED25519, None).unwrap();
    assert_eq!(info.format, KeyFormat::Ppk);
    assert_eq!(info.algorithm, "ssh-ed25519");
    let out = convert(PPK_ED25519, None, Some("new pass"), "").unwrap();
    assert!(out.private_openssh.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert_eq!(out.info.comment, info.comment, "empty comment keeps the key's own");
    assert_eq!(inspect(&out.private_openssh, Some("new pass")).unwrap().fingerprint, info.fingerprint);
}

#[test]
fn encrypted_ppk_needs_its_passphrase() {
    assert!(inspect(PPK_ED25519_ENC, None).is_err());
    assert!(inspect(PPK_ED25519_ENC, Some("nope")).is_err());
    let out = convert(PPK_ED25519_ENC, Some("123"), None, "renamed").unwrap();
    assert_eq!(out.info.comment, "renamed");
    assert_eq!(inspect(&out.private_openssh, None).unwrap().comment, "renamed");
}

#[test]
fn ppk_v2_rsa_and_ecdsa_import() {
    assert_eq!(inspect(PPK2_RSA_ENC, Some("123")).unwrap().algorithm, "ssh-rsa");
    assert_eq!(inspect(PPK_ECDSA, None).unwrap().algorithm, "ecdsa-sha2-nistp256");
}

#[test]
fn openssh_re_encodes_under_a_new_passphrase() {
    let key = generate_ed25519("k", Some("a")).unwrap();
    let out = convert(&key.private_openssh, Some("a"), Some("b"), "").unwrap();
    assert_eq!(out.info.fingerprint, key.info.fingerprint);
    assert!(inspect(&out.private_openssh, Some("a")).is_err());
}

#[test]
fn garbage_and_oversized_input_are_refused() {
    assert!(inspect("hello", None).is_err());
    assert!(inspect("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----", None).is_err());
    assert!(inspect(&"a".repeat(MAX_KEY_TEXT + 1), None).is_err());
}

#[test]
fn fido2_sk_key_is_flagged_hardware() {
    let base = generate_ed25519("", None).unwrap();
    let pk = russh::keys::parse_public_key_base64(base.info.public_openssh.split(' ').nth(1).unwrap()).unwrap();
    let ed = *pk.key_data().ed25519().unwrap();
    let sk = SkEd25519::new(public::SkEd25519::new(ed, "ssh:"), 0x01, vec![7u8; 64]).unwrap();
    let key = PrivateKey::new(KeypairData::SkEd25519(sk), "yubikey").unwrap();
    let text = key.to_openssh(LineEnding::LF).unwrap();
    let info = inspect(&text, None).unwrap();
    assert!(info.hardware);
    assert_eq!(info.algorithm, "sk-ssh-ed25519@openssh.com");
    let out = convert(&text, None, None, "").unwrap();
    assert!(out.info.hardware, "conversion keeps the key handle");
}
