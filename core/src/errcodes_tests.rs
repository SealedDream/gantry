use super::*;
use crate::error::CoreError;

#[test]
fn known_core_errors_map_to_stable_codes() {
    assert_eq!(for_error("SSH", &CoreError::AuthFailed), "GT-SSH-001");
    assert_eq!(for_error("RDP", &CoreError::AuthFailed), "GT-RDP-001");
    assert_eq!(for_error("SSH", &CoreError::HostKeyChanged { line: 3 }), "GT-SSH-003");
    assert_eq!(for_error("SSH", &CoreError::HostKeyUnknown { fingerprint: "x".into() }), "GT-SSH-002");
    assert_eq!(for_error("VAULT", &CoreError::VaultAuth), "GT-VAULT-001");
    assert_eq!(for_error("NET", &CoreError::Timeout), "GT-NET-003");
    assert_eq!(for_error("NET", &CoreError::Offline("x".into())), "GT-NET-004");
    assert_eq!(for_error("SSH", &CoreError::Ssh("Connection refused".into())), "GT-NET-001");
    assert_eq!(for_error("SSH", &CoreError::Ssh("weird".into())), "GT-SSH-000");
}

#[test]
fn messages_map_to_codes() {
    assert_eq!(classify("ssh", "failed to lookup address information: nodename nor servname provided"), "GT-NET-002");
    assert_eq!(classify("SSH", "connection timed out"), "GT-NET-003");
    assert_eq!(classify("SSH", "No route to host"), "GT-NET-001");
    assert_eq!(classify("PLUG", "signature does not match the publisher key"), "GT-PLUG-002");
    assert_eq!(classify("UPD", "signature check failed"), "GT-UPD-002");
    assert_eq!(classify("UPD", "SHA-256 hash mismatch"), "GT-UPD-002");
    assert_eq!(classify("PLUG", "plugin host failed to start"), "GT-PLUG-001");
    assert_eq!(classify("RDP", "certificate is not trusted"), "GT-RDP-002");
    assert_eq!(classify("RDP", "Logon failure"), "GT-RDP-001");
    assert_eq!(classify("VAULT", "vault is locked or the password is wrong"), "GT-VAULT-001");
}

#[test]
fn unknown_errors_get_the_area_generic_code() {
    assert_eq!(classify("SSH", "something new"), "GT-SSH-000");
    assert_eq!(classify("VNC", "?"), "GT-VNC-000");
    assert_eq!(classify("nonsense", "?"), "GT-APP-000");
}

#[test]
fn every_returned_code_is_in_the_catalogue_and_the_doc() {
    let doc = include_str!("../../docs/ERROR-CODES.md");
    for (code, _) in CATALOGUE {
        assert!(doc.contains(code), "{code} missing from docs/ERROR-CODES.md");
    }
    for a in AREAS {
        assert!(meaning(classify(a, "zzz")).is_some());
    }
    assert!(meaning("GT-SSH-999").is_none());
}

#[test]
fn redaction_removes_secrets_and_hosts() {
    let line = "connect admin@srv1.lab.local 192.168.1.20 password=hunter2 token: abc123 key fe80::1:2";
    let out = redact(line);
    for bad in ["admin", "srv1", "192.168", "hunter2", "abc123", "fe80"] {
        assert!(!out.contains(bad), "{bad} survived: {out}");
    }
    let pem = "x -----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY----- y";
    assert_eq!(redact(pem), "x (key) y");
    assert!(!redact("ssh://bob:pw@h/").contains("pw"));
    assert!(!redact("Bearer eyJhbGciOiJIUzI1NiJ9eyJzdWIiOiIxMjM0NTY3ODkwIn0").contains("eyJ"));
}

#[test]
fn redaction_keeps_codes_and_plain_words() {
    assert_eq!(redact("GT-SSH-001 authentication failed"), "GT-SSH-001 authentication failed");
    assert_eq!(redact("line1\nline2"), "line1 line2");
}

#[test]
fn detailed_log_turns_off_after_24_hours() {
    use crate::settings::{detailed_log_expired, DETAILED_LOG, DETAILED_LOG_MAX_SECS};
    assert!(!detailed_log_expired(1000, 1000 + DETAILED_LOG_MAX_SECS - 1));
    assert!(detailed_log_expired(1000, 1000 + DETAILED_LOG_MAX_SECS));
    assert!(detailed_log_expired(1000, 999));
    let def = crate::settings::definition(DETAILED_LOG).expect("defined");
    assert_eq!(def.default, "false");
}

#[test]
fn redacts_auth_header_with_scheme() {
    let out = redact("Authorization: Bearer abc123short");
    assert!(!out.contains("abc123short"), "{out}");
    let out = redact("auth header Basic dXNlcjpw");
    assert!(!out.contains("dXNlcjpw"), "{out}");
}

#[test]
fn redacts_password_is_value() {
    let out = redact("password is hunter2");
    assert!(!out.contains("hunter2"), "{out}");
}
