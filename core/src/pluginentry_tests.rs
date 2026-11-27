use std::net::TcpListener;
use std::sync::Arc;

use super::*;
use crate::model::{Connection, Document, Folder, Node, Protocol};
use crate::plugin::host::relay::{certificate_pin, check_entry_certificate, probe_certificate_pin};
use crate::policy::Policy;
use crate::properties;

const PVE: &str = "dev.bastion.proxmox/pve";
const PIN: &str = "AB0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";

fn plugin_entry(host: &str) -> Connection {
    let mut c = Connection::new("pve", Protocol::Unsupported, host);
    c.unknown_protocol = Some(PVE.into());
    c
}

fn unknown_entry() -> Connection {
    let mut c = Connection::new("future", Protocol::Unsupported, "h");
    c.unknown_protocol = Some("quantum-link".into());
    c
}

#[test]
fn tls_defaults_to_verify_full_and_reads_back_a_pin() {
    let mut c = plugin_entry("pve.lab");
    assert_eq!(entry_tls(&c), (TlsMode::VerifyFull, None));
    set_entry_tls(&mut c, "pinned", Some(PIN)).unwrap();
    assert_eq!(entry_tls(&c), (TlsMode::Pinned, Some(PIN.to_ascii_lowercase())));
    set_entry_tls(&mut c, "verify-full", Some(PIN)).unwrap();
    assert_eq!(entry_tls(&c), (TlsMode::VerifyFull, None), "verify-full drops the pin");
}

#[test]
fn bad_pins_modes_and_built_in_entries_are_refused() {
    let mut c = plugin_entry("pve.lab");
    assert!(set_entry_tls(&mut c, "pinned", None).is_err());
    assert!(set_entry_tls(&mut c, "pinned", Some("abc")).is_err());
    assert!(set_entry_tls(&mut c, "pinned", Some(&"g".repeat(64))).is_err());
    assert!(set_entry_tls(&mut c, "off", None).is_err(), "TLS off is not offered");
    let mut ssh = Connection::new("s", Protocol::Ssh, "h");
    assert!(set_entry_tls(&mut ssh, "verify-full", None).is_err());
    let mut other = unknown_entry();
    assert!(set_entry_tls(&mut other, "verify-full", None).is_err());
}

#[test]
fn a_tampered_store_falls_back_to_the_safe_default() {
    let mut c = plugin_entry("pve.lab");
    assert!(!entry_tls_damaged(&c));
    c.extra.insert(TLS_KEY.into(), serde_json::json!({ "mode": "pinned", "pin_sha256": "x" }));
    assert_eq!(entry_tls(&c), (TlsMode::VerifyFull, None));
    assert!(entry_tls_damaged(&c), "a pinned choice with a bad pin is reported");
    c.extra.insert(TLS_KEY.into(), serde_json::json!({ "mode": "pinned" }));
    assert!(entry_tls_damaged(&c), "a pinned choice with no pin is reported");
    c.extra.insert(TLS_KEY.into(), serde_json::json!({ "mode": "off" }));
    assert_eq!(entry_tls(&c), (TlsMode::VerifyFull, None));
    c.extra.insert(TLS_KEY.into(), serde_json::json!("pinned"));
    assert_eq!(entry_tls(&c), (TlsMode::VerifyFull, None));
    assert!(entry_tls_damaged(&c));
    set_entry_tls(&mut c, "verify-full", None).unwrap();
    assert!(!entry_tls_damaged(&c));
    set_entry_tls(&mut c, "pinned", Some(PIN)).unwrap();
    assert!(!entry_tls_damaged(&c));
}

#[test]
fn the_route_is_direct_only_without_a_gateway_here_or_above() {
    let mut doc = Document::new("lib");
    let mut folder = Folder { id: Uuid::new_v4(), name: "lab".into(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() };
    let c = plugin_entry("pve.lab");
    let id = c.id;
    folder.children.push(Node::Connection(c));
    let fid = folder.id;
    doc.root.children.push(Node::Folder(folder));
    let (c, s) = plugin_entry_settings(&doc, id).unwrap();
    assert_eq!(binding_tls(c, &s).route, EntryRoute::Direct);
    assert!(!binding_tls(c, &s).allow_unencrypted);
    // A gateway on the folder applies to the entry.
    if let Node::Folder(f) = &mut doc.root.children[0] {
        assert_eq!(f.id, fid);
        f.defaults.gateway_id = Some(Uuid::new_v4());
    }
    let (c, s) = plugin_entry_settings(&doc, id).unwrap();
    assert_eq!(binding_tls(c, &s).route, EntryRoute::NotDirect);
}

#[test]
fn only_plugin_entries_are_found() {
    let mut doc = Document::new("lib");
    let ssh = Connection::new("s", Protocol::Ssh, "h");
    let other = unknown_entry();
    let (a, b) = (ssh.id, other.id);
    doc.root.children.push(Node::Connection(ssh));
    doc.root.children.push(Node::Connection(other));
    assert!(plugin_entry_settings(&doc, a).is_none());
    assert!(plugin_entry_settings(&doc, b).is_none());
}

#[test]
fn a_plugin_entry_takes_host_port_and_login_but_an_unknown_one_does_not() {
    let mut doc = Document::new("lib");
    let pve = plugin_entry("old");
    let other = unknown_entry();
    let (p, u) = (pve.id, other.id);
    doc.root.children.push(Node::Connection(pve));
    doc.root.children.push(Node::Connection(other));
    properties::set_value(&mut doc, p, "host", Some("pve.lab")).unwrap();
    properties::set_value(&mut doc, p, "port", Some("8006")).unwrap();
    let cred = Uuid::new_v4().to_string();
    properties::set_value(&mut doc, p, "credential_id", Some(&cred)).unwrap();
    let (c, s) = plugin_entry_settings(&doc, p).unwrap();
    assert_eq!((c.host.as_str(), s.port, s.credential_id.map(|i| i.to_string())), ("pve.lab", Some(8006), Some(cred)));
    // Still never resolvable as a built-in connection.
    assert!(doc.resolve(p).is_err());
    // Settings a plugin entry does not have stay refused.
    assert!(properties::set_value(&mut doc, p, "keepalive_secs", Some("30")).is_err());
    // A gateway is allowed since PLUG-08 (the relay streams through its forward); an id that
    // is not a gateway is still refused.
    assert!(properties::set_value(&mut doc, p, "gateway_id", Some("not-a-gateway")).is_err());
    // An entry of a type nobody knows keeps the PLUG-03a rule.
    assert!(properties::set_value(&mut doc, u, "host", Some("x")).is_err());
    assert!(properties::set_value(&mut doc, u, "port", Some("1")).is_err());
    let keys: Vec<_> = properties::connection_values(&doc, p).unwrap().into_iter().map(|v| v.key).collect();
    assert!(keys.contains(&"host".to_string()) && keys.contains(&"credential_id".to_string()));
}

/// A self-signed TLS server that completes handshakes and closes; returns its port and pin.
fn tls_server() -> (u16, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let pin = certificate_pin(der.as_ref());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = Arc::new(rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![der], key).unwrap());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Some(mut s) = l.incoming().flatten().next() {
            let mut tls = rustls::ServerConnection::new(config).unwrap();
            let _ = tls.complete_io(&mut s);
        }
    });
    (port, pin)
}

#[test]
fn the_probe_reads_the_certificate_pin_and_sends_nothing_else() {
    let (port, pin) = tls_server();
    assert_eq!(probe_certificate_pin("localhost", port, &Policy::default()).unwrap(), pin);
}

#[test]
fn the_probe_refuses_an_empty_host_and_a_closed_port() {
    assert!(probe_certificate_pin("", 8006, &Policy::default()).is_err());
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    assert!(probe_certificate_pin("127.0.0.1", port, &Policy::default()).is_err());
}

#[test]
fn the_check_refuses_a_self_signed_certificate_under_system_trust() {
    let (port, _) = tls_server();
    let err = check_entry_certificate("localhost", port, None, &Policy::default()).unwrap_err();
    assert!(err.to_string().contains("did not pass the TLS mode"), "{err}");
}

#[test]
fn the_check_passes_the_pinned_certificate_and_refuses_another() {
    let (port, pin) = tls_server();
    check_entry_certificate("localhost", port, Some(&pin.to_ascii_uppercase()), &Policy::default()).unwrap();
    let (port, _) = tls_server();
    let err = check_entry_certificate("localhost", port, Some(&"0".repeat(64)), &Policy::default()).unwrap_err();
    assert!(err.to_string().contains("did not pass the TLS mode"), "{err}");
    assert!(check_entry_certificate("", 443, None, &Policy::default()).is_err());
}

/// A self-signed server that speaks TLS only after PostgreSQL's SSLRequest, as PostgreSQL does: a bare
/// ClientHello gets an error message. Serves `n` connections; returns its port and pin.
fn pg_tls_server(n: usize) -> (u16, String) {
    use std::io::{Read, Write};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let pin = certificate_pin(der.as_ref());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = Arc::new(rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![der], key).unwrap());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten().take(n) {
            let mut first = [0u8; 8];
            if s.read_exact(&mut first).is_err() {
                continue;
            }
            if first == [0, 0, 0, 8, 4, 210, 22, 47] {
                let _ = s.write_all(b"S");
                let mut tls = rustls::ServerConnection::new(config.clone()).unwrap();
                let _ = tls.complete_io(&mut s);
            } else {
                // As PostgreSQL: an error message, then the connection closes.
                let _ = s.write_all(b"E\0\0\0\x20SFATAL\0Munsupported frontend protocol\0\0");
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        }
    });
    (port, pin)
}

#[test]
fn the_probe_and_the_check_speak_postgresql_ssl_request() {
    let (port, pin) = pg_tls_server(2);
    assert_eq!(probe_certificate_pin("localhost", port, &Policy::default()).unwrap(), pin);
    let (port, _) = pg_tls_server(2);
    let err = check_entry_certificate("localhost", port, None, &Policy::default()).unwrap_err();
    assert!(err.to_string().contains("did not pass the TLS mode"), "{err}");
    let (port, pin) = pg_tls_server(2);
    check_entry_certificate("localhost", port, Some(&pin), &Policy::default()).unwrap();
}

/// Against a real PostgreSQL with TLS (`BASTION_PG_TLS=host:port`, e.g. the lab's): the probe reads its pin,
/// the check refuses it under system trust when self-signed and passes it pinned. Skipped without the variable.
#[test]
fn a_real_postgresql_is_probed_and_checked_when_given() {
    let Ok(target) = std::env::var("BASTION_PG_TLS") else { return };
    let (host, port) = target.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let pin = probe_certificate_pin(host, port, &Policy::default()).unwrap();
    check_entry_certificate(host, port, Some(&pin), &Policy::default()).unwrap();
}
