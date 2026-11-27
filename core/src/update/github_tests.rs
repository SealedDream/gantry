//! The fetcher against a local HTTPS server with a self-signed certificate for `localhost` and
//! `127.0.0.1` (the test agent trusts only that certificate).
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use super::*;
use crate::update::key_id;

const NOW: u64 = 1_800_000_000;
const REPO: &str = "SealedDream/gantry";
const APP: &[u8] = b"signed app archive";

/// `(status, location or body)` per path.
type Routes = HashMap<String, (u16, Vec<u8>)>;

struct Server {
    port: u16,
    roots: rustls::RootCertStore,
}

/// Serves `routes(port)` over TLS on a background thread, one request per connection.
fn serve(routes: impl FnOnce(u16) -> Routes) -> Server {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![der.clone()], key).unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let routes = routes(port);
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let conn = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let mut line = String::new();
            if BufReader::new(&mut tls).read_line(&mut line).is_err() {
                continue; // the client refused the handshake
            }
            let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
            let response = match routes.get(&path) {
                Some((s, loc)) if (300..400).contains(s) => format!("HTTP/1.1 {s} Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", String::from_utf8_lossy(loc)).into_bytes(),
                Some((s, body)) => [format!("HTTP/1.1 {s} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes(), body.clone()].concat(),
                None => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            };
            let _ = tls.write_all(&response);
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    Server { port, roots }
}

impl Server {
    fn fetcher(&self, hosts: &[&str]) -> ReleaseFetcher {
        ReleaseFetcher::new(agent(Some(self.roots.clone())), &format!("https://localhost:{}", self.port), hosts)
    }
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn manifest(version: &str, file_url: &str) -> Vec<u8> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": 1, "channel": "stable", "version": version, "expires": NOW + 3600, "notes": "",
        "files": [{ "name": "Bastion.zip", "url": file_url, "sha256": hex::encode(Sha256::digest(APP)), "size": APP.len() }],
    }))
    .unwrap();
    let k = key();
    serde_json::to_vec(&serde_json::json!({
        "payload": B64.encode(&payload),
        "signatures": [{ "keyid": key_id(&k.verifying_key().to_bytes()), "sig": B64.encode(k.sign(&payload).to_bytes()) }],
    }))
    .unwrap()
}

const LATEST: &str = "/SealedDream/gantry/releases/latest/download/update-manifest.json";

/// GitHub's shape: latest → tagged download on github.com → the CDN host (here 127.0.0.1).
fn release(port: u16, version: &str) -> Routes {
    let cdn = format!("https://127.0.0.1:{port}");
    HashMap::from([
        (LATEST.into(), (302, format!("https://localhost:{port}/SealedDream/gantry/releases/download/v{version}/update-manifest.json").into_bytes())),
        (format!("/SealedDream/gantry/releases/download/v{version}/update-manifest.json"), (302, format!("{cdn}/asset/manifest").into_bytes())),
        ("/asset/manifest".into(), (200, manifest(version, &format!("https://localhost:{port}/dl/Bastion.zip")))),
        ("/dl/Bastion.zip".into(), (302, format!("{cdn}/asset/app").into_bytes())),
        ("/asset/app".into(), (200, APP.to_vec())),
    ])
}

fn trusted() -> [[u8; 32]; 1] {
    [key().verifying_key().to_bytes()]
}

#[test]
fn latest_release_is_followed_through_redirects_verified_and_downloaded() {
    let server = serve(|port| release(port, "0.3.0"));
    let fetcher = server.fetcher(&["localhost", "127.0.0.1"]);
    let UpdateCheck::Available(m) = fetcher.check_latest(REPO, &trusted(), "stable", "0.2.0", NOW).unwrap() else { panic!("expected an update") };
    assert_eq!(m.version, "0.3.0");
    let dir = tempfile::tempdir().unwrap();
    let path = fetcher.download(&m.files[0], dir.path()).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), APP);
    assert_eq!(fetcher.check_latest(REPO, &trusted(), "stable", "0.3.0", NOW).unwrap(), UpdateCheck::UpToDate { latest: "0.3.0".into() });
    // Every existing manifest check still applies: rollback, channel, untrusted key, expiry.
    assert!(fetcher.check_latest(REPO, &trusted(), "stable", "0.4.0", NOW).unwrap_err().to_string().contains("rollback"));
    assert!(fetcher.check_latest(REPO, &trusted(), "beta", "0.2.0", NOW).is_err());
    assert!(fetcher.check_latest(REPO, &[[9; 32]], "stable", "0.2.0", NOW).is_err());
    assert!(fetcher.check_latest(REPO, &trusted(), "stable", "0.2.0", NOW + 7200).is_err());
}

#[test]
fn redirect_off_the_allow_list_or_to_http_is_refused_before_fetching() {
    let server = serve(|port| release(port, "0.3.0"));
    // 127.0.0.1 plays the CDN; without it on the list the first CDN hop is refused.
    let err = server.fetcher(&["localhost"]).check_latest(REPO, &trusted(), "stable", "0.2.0", NOW).unwrap_err();
    assert!(matches!(err, CoreError::PolicyDenied(_)), "{err}");
    let none = serve(|_| HashMap::new());
    assert!(none.fetcher(&["localhost"]).check_latest(REPO, &trusted(), "stable", "0.2.0", NOW).unwrap_err().to_string().contains("no published release"));
    let server = serve(|port| HashMap::from([(LATEST.into(), (302, format!("http://localhost:{port}/x").into_bytes()))]));
    assert!(matches!(server.fetcher(&["localhost"]).check_latest(REPO, &trusted(), "stable", "0.2.0", NOW), Err(CoreError::PolicyDenied(_))));
}

#[test]
fn oversized_tampered_and_looping_responses_are_refused() {
    let server = serve(|port| {
        let mut r = release(port, "0.3.0");
        r.insert("/asset/manifest".into(), (200, vec![b' '; MAX_MANIFEST_BYTES + 1]));
        r.insert("/asset/app".into(), (200, b"tampered app archive".to_vec()));
        r.insert("/loop".into(), (302, format!("https://localhost:{port}/loop").into_bytes()));
        r
    });
    let fetcher = server.fetcher(&["localhost", "127.0.0.1"]);
    assert!(fetcher.check_latest(REPO, &trusted(), "stable", "0.2.0", NOW).unwrap_err().to_string().contains("larger"));
    let file = UpdateFile { name: "Bastion.zip".into(), url: format!("https://localhost:{}/dl/Bastion.zip", server.port), sha256: hex::encode(Sha256::digest(APP)), size: APP.len() as u64 };
    let dir = tempfile::tempdir().unwrap();
    assert!(fetcher.download(&file, dir.path()).is_err(), "longer body than signed size");
    let same_len = UpdateFile { size: b"tampered app archive".len() as u64, ..file.clone() };
    assert!(fetcher.download(&same_len, dir.path()).unwrap_err().to_string().contains("SHA-256"));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "nothing left behind");
    assert!(fetcher.get(&format!("https://localhost:{}/loop", server.port), 10).unwrap_err().to_string().contains("redirects"));
}

#[test]
fn urls_names_and_repositories_are_validated() {
    let f = ReleaseFetcher::github();
    assert_eq!(f.latest_manifest_url(REPO).unwrap(), "https://github.com/SealedDream/gantry/releases/latest/download/update-manifest.json");
    for bad in ["", "a", "a/b/c", "../x", "a/..", "a b/c"] {
        assert!(f.latest_manifest_url(bad).is_err(), "{bad}");
    }
    for ok in ["https://github.com/x", "https://objects.githubusercontent.com/x", "https://GITHUB.com:443/x"] {
        assert!(f.allowed(ok).is_ok(), "{ok}");
    }
    for bad in ["http://github.com/x", "https://github.com.evil.test/x", "https://evil.test/github.com", "https://github.com@evil.test/x", "https://api.github.com/x", "file:///etc/passwd"] {
        assert!(f.allowed(bad).is_err(), "{bad}");
    }
    let dir = tempfile::tempdir().unwrap();
    for name in ["", "../x", "a/b", ".hidden", "C:x"] {
        let file = UpdateFile { name: name.into(), url: "https://github.com/x".into(), sha256: "0".repeat(64), size: 1 };
        assert!(f.download(&file, dir.path()).unwrap_err().to_string().contains("unsafe"), "{name}");
    }
    let huge = UpdateFile { name: "x.zip".into(), url: "https://github.com/x".into(), sha256: "0".repeat(64), size: MAX_DOWNLOAD_BYTES + 1 };
    assert!(f.download(&huge, dir.path()).is_err());
}

/// Real GitHub: a release asset download redirects only through allowed hosts. Network; run with
/// `cargo test -- --ignored live_github`.
#[test]
#[ignore]
fn live_github_asset_redirects_stay_on_allowed_hosts() {
    let bytes = ReleaseFetcher::github().get("https://github.com/cli/cli/releases/download/v2.62.0/gh_2.62.0_checksums.txt", 64 * 1024).unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("gh_2.62.0_macOS_arm64.zip"));
}
