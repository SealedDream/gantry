use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::mpsc;

use bastion_core::error::CoreError;
use bastion_core::hcvault::{HcVaultProvider, KvVersion};
use bastion_core::provider::{CredentialProvider, ProviderStatus};
use bastion_core::vault::Secret;

/// One-shot HTTP server: answers `status` + `body`, reports the request head it saw.
fn serve(status: &str, body: &str) -> (String, mpsc::Receiver<String>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let (tx, rx) = mpsc::channel();
    let (status, body) = (status.to_string(), body.to_string());
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut head = String::new();
        let mut r = BufReader::new(s.try_clone().unwrap());
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
            head.push_str(&line);
        }
        let _ = write!(s, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let _ = tx.send(head);
    });
    (base, rx)
}

#[test]
fn kv2_fetches_field_with_token_and_namespace() {
    let (base, rx) = serve("200 OK", r#"{"data":{"data":{"password":"hunter2"},"metadata":{}}}"#);
    let p = HcVaultProvider::new(&base, KvVersion::V2, Some("team".into())).unwrap();
    p.unlock(Secret::new("s.tok"));
    assert_eq!(p.fetch("secret/prod/db#password").unwrap().expose(), "hunter2");
    let head = rx.recv().unwrap().to_ascii_lowercase();
    assert!(head.starts_with("get /v1/secret/data/prod/db "), "{head}");
    assert!(head.contains("x-vault-token: s.tok"));
    assert!(head.contains("x-vault-namespace: team"));
}

#[test]
fn kv1_reads_flat_data() {
    let (base, rx) = serve("200 OK", r#"{"data":{"user":"root"}}"#);
    let p = HcVaultProvider::new(&base, KvVersion::V1, None).unwrap();
    p.unlock(Secret::new("t"));
    assert_eq!(p.fetch("kv/app#user").unwrap().expose(), "root");
    assert!(rx.recv().unwrap().starts_with("GET /v1/kv/app "));
}

#[test]
fn missing_field_and_denied_token_map_to_errors() {
    let (base, _rx) = serve("200 OK", r#"{"data":{"data":{}}}"#);
    let p = HcVaultProvider::new(&base, KvVersion::V2, None).unwrap();
    p.unlock(Secret::new("t"));
    assert!(matches!(p.fetch("secret/a#x"), Err(CoreError::NotFound(_))));

    let (base, _rx) = serve("403 Forbidden", r#"{"errors":["permission denied"]}"#);
    let p = HcVaultProvider::new(&base, KvVersion::V2, None).unwrap();
    p.unlock(Secret::new("t"));
    assert!(matches!(p.fetch("secret/a#x"), Err(CoreError::AuthFailed)));
}

#[test]
fn locked_read_only_and_bad_input_are_refused() {
    let p = HcVaultProvider::new("https://vault.example", KvVersion::V2, None).unwrap();
    assert_eq!(p.status(), ProviderStatus::Locked);
    assert!(p.fetch("secret/a#x").is_err());
    p.unlock(Secret::new("t"));
    assert_eq!(p.status(), ProviderStatus::Available);
    for bad in ["secret/a", "secret#x", "secret/../sys#x", "secret/a?x=1#y", "secret//a#x", "secret/a#"] {
        assert!(matches!(p.fetch(bad), Err(CoreError::Invalid(_))), "{bad}");
    }
    assert!(matches!(p.store("secret/a#x", &Secret::new("v")), Err(CoreError::PolicyDenied(_))));
    assert!(matches!(p.delete("secret/a#x"), Err(CoreError::PolicyDenied(_))));
    p.lock();
    assert_eq!(p.status(), ProviderStatus::Locked);
    assert!(HcVaultProvider::new("http://vault.example", KvVersion::V2, None).is_err());
}
