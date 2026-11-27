//! `http.send` through the relay against real sockets on loopback (PLUG-HTTP-01).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use super::*;
use crate::plugin::broker::http::{encode_request, host_header, Method, PluginRequest};

fn tls(mode: TlsMode, pin: Option<String>, allow_unencrypted: bool) -> EntryTls {
    EntryTls { mode, pin_sha256: pin, allow_unencrypted, route: EntryRoute::Direct }
}

fn wait(relay: &mut Relay, request: u32) -> Result<Outcome, Failure> {
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        for d in relay.poll() {
            if d.request == request {
                return d.outcome;
            }
        }
        assert!(Instant::now() < end, "no reply to request {request}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn job(target: &str, with_login: bool, timeout: Duration) -> HttpJob {
    let req = PluginRequest { method: Method::Get, port: None, target: target.into(), headers: vec![], body: vec![], with_login, timeout_ms: None };
    let auth = with_login.then_some(("Authorization", "PVEAPIToken=u=s"));
    HttpJob { wire: encode_request(&req, &host_header("127.0.0.1", 1, false), "test.plugin", auth), head: false, timeout, with_login, session: None }
}

fn response(outcome: Result<Outcome, Failure>) -> HttpResponse {
    match outcome {
        Ok(Outcome::Http(r)) => r,
        other => panic!("not an http answer: {other:?}"),
    }
}

/// Reads one request head (and a Content-Length body) from `r`. `None` when the client closed.
fn read_request(r: &mut impl Read) -> Option<String> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match r.read(&mut b) {
            Ok(1) => head.push(b[0]),
            _ => return None,
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let len = text.lines().find_map(|l| l.strip_prefix("Content-Length: ")).and_then(|n| n.trim().parse::<usize>().ok()).unwrap_or(0);
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).ok()?;
    Some(text)
}

/// A keep-alive HTTP server: answers each request with `answer(n)` (n counts requests on the
/// connection) and reports each request head with its connection number.
fn http_server(answer: fn(usize) -> Vec<u8>) -> (u16, mpsc::Receiver<(usize, String)>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for (conn, s) in l.incoming().flatten().enumerate() {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut s = s;
                let mut n = 0;
                while let Some(head) = read_request(&mut s) {
                    let _ = tx.send((conn, head));
                    if s.write_all(&answer(n)).is_err() {
                        break;
                    }
                    n += 1;
                }
            });
        }
    });
    (port, rx)
}

fn ok_json(_: usize) -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"data\":[]}".to_vec()
}

/// An HTTPS server with a fresh self-signed certificate; returns its port, the pin and the
/// request heads it saw.
fn https_server() -> (u16, String, mpsc::Receiver<String>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let der = cert.cert.der().clone();
    let pin = certificate_pin(der.as_ref());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let config = Arc::new(rustls::ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![der], key).unwrap());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let config = config.clone();
            let tx = tx.clone();
            std::thread::spawn(move || {
                let conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, s);
                while let Some(head) = read_request(&mut tls) {
                    let _ = tx.send(head);
                    if tls.write_all(&ok_json(0)).is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, pin, rx)
}

/// A server that accepts and never answers.
fn silent_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut keep: Vec<TcpStream> = Vec::new();
        for s in l.incoming().flatten() {
            keep.push(s);
        }
    });
    port
}

#[test]
fn a_local_plain_request_is_answered_and_the_connection_reused() {
    let (port, seen) = http_server(ok_json);
    let mut relay = Relay::new("127.0.0.1", port, vec![], tls(TlsMode::Off, None, false), Policy::default());
    assert!(relay.http(1, None, job("/api2/json/nodes", false, Duration::from_secs(5))).unwrap(), "first request opens");
    let r = response(wait(&mut relay, 1));
    assert_eq!((r.status, r.body.as_slice()), (200, &b"{\"data\":[]}"[..]));
    assert!(!relay.http(2, None, job("/api2/json/version", false, Duration::from_secs(5))).unwrap(), "second reuses");
    assert_eq!(response(wait(&mut relay, 2)).status, 200);
    assert_eq!(relay.http_connections(), 1);
    let (c1, h1) = seen.recv().unwrap();
    let (c2, h2) = seen.recv().unwrap();
    assert_eq!(c1, c2, "one connection");
    assert!(h1.starts_with("GET /api2/json/nodes HTTP/1.1\r\nHost: 127.0.0.1:1\r\n"));
    assert!(h2.starts_with("GET /api2/json/version HTTP/1.1\r\n"));
    // An http connection is not a net stream.
    let id = *relay.streams.keys().next().unwrap();
    assert!(relay.read(3, id, 10).is_err());
    assert!(relay.write(4, id, b"x".to_vec(), &SecretCheck::new()).is_err());
    assert!(relay.register_abort(id, b"x", &SecretCheck::new()).is_err());
    relay.close(id);
    assert_eq!(relay.http_connections(), 1, "net.close cannot close an http connection");
}

#[test]
fn connection_close_is_not_reused() {
    fn closing(_: usize) -> Vec<u8> {
        b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_vec()
    }
    let (port, seen) = http_server(closing);
    let mut relay = Relay::new("127.0.0.1", port, vec![], tls(TlsMode::Off, None, false), Policy::default());
    relay.http(1, None, job("/a/", false, Duration::from_secs(5))).unwrap();
    let r = response(wait(&mut relay, 1));
    assert_eq!(r.status, 302, "the redirect comes back as it is");
    assert!(relay.http(2, None, job("/a/", false, Duration::from_secs(5))).unwrap(), "a new connection");
    response(wait(&mut relay, 2));
    assert_ne!(seen.recv().unwrap().0, seen.recv().unwrap().0);
}

#[test]
fn an_idle_connection_the_server_closed_is_not_reused() {
    // pveproxy closes an idle keep-alive connection before the relay's 30 s; the next request
    // must go on a new connection, not read the close ("closed inside the headers").
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, seen) = mpsc::channel();
    std::thread::spawn(move || {
        for (conn, s) in l.incoming().flatten().enumerate() {
            let mut s = s;
            if let Some(head) = read_request(&mut s) {
                let _ = tx.send((conn, head));
                let _ = s.write_all(&ok_json(0));
            }
            // Keep-alive was promised; close while idle.
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    });
    let mut relay = Relay::new("127.0.0.1", port, vec![], tls(TlsMode::Off, None, false), Policy::default());
    relay.http(1, None, job("/a", false, Duration::from_secs(5))).unwrap();
    assert_eq!(response(wait(&mut relay, 1)).status, 200);
    std::thread::sleep(Duration::from_millis(200));
    assert!(relay.http(2, None, job("/b", false, Duration::from_secs(5))).unwrap(), "a new connection, not the closed one");
    assert_eq!(response(wait(&mut relay, 2)).status, 200);
    assert_ne!(seen.recv().unwrap().0, seen.recv().unwrap().0);
}

#[test]
fn https_with_the_pin_and_not_without() {
    let (port, pin, seen) = https_server();
    let mut relay = Relay::new("127.0.0.1", port, vec![], tls(TlsMode::Pinned, Some(pin), false), Policy::default());
    relay.test_remote = true;
    relay.http(1, None, job("/api2/json/version", true, Duration::from_secs(10))).unwrap();
    assert_eq!(response(wait(&mut relay, 1)).status, 200);
    let head = seen.recv().unwrap();
    assert!(head.contains("Authorization: PVEAPIToken=u=s\r\n"), "the login went over TLS");
    // Another pin: the certificate fails the mode and nothing is sent.
    let mut wrong = Relay::new("127.0.0.1", port, vec![], tls(TlsMode::Pinned, Some("00".repeat(32)), false), Policy::default());
    wrong.test_remote = true;
    wrong.http(1, None, job("/api2/json/version", true, Duration::from_secs(10))).unwrap();
    assert!(matches!(wait(&mut wrong, 1), Err(Failure::Denied(_))));
    assert!(seen.recv_timeout(Duration::from_millis(300)).is_err());
    // Pinned with no pin stored: refused before connecting.
    let mut none = Relay::new("127.0.0.1", port, vec![], tls(TlsMode::Pinned, None, false), Policy::default());
    assert!(matches!(none.http(1, None, job("/", false, Duration::from_secs(1))), Err(Failure::Denied(_))));
}

#[test]
fn the_login_never_goes_in_cleartext_to_a_remote_destination() {
    let (port, seen) = http_server(ok_json);
    let mut relay = Relay::new("127.0.0.1", port, vec![], tls(TlsMode::Off, None, true), Policy::default());
    relay.test_remote = true;
    relay.http(1, None, job("/a/", true, Duration::from_secs(5))).unwrap();
    assert!(matches!(wait(&mut relay, 1), Err(Failure::Denied(_))));
    assert!(seen.recv_timeout(Duration::from_millis(300)).is_err(), "nothing was written");
    // Without the login, "Allow unencrypted" lets a remote plain request through.
    relay.http(2, None, job("/a/", false, Duration::from_secs(5))).unwrap();
    assert_eq!(response(wait(&mut relay, 2)).status, 200);
    // And without "Allow unencrypted", not at all.
    let mut strict = Relay::new("127.0.0.1", port, vec![], tls(TlsMode::Off, None, false), Policy::default());
    strict.test_remote = true;
    strict.http(1, None, job("/a/", false, Duration::from_secs(5))).unwrap();
    assert!(matches!(wait(&mut strict, 1), Err(Failure::Denied(_))));
}

#[test]
fn ports_and_routes() {
    let (port, _) = http_server(ok_json);
    let mut relay = Relay::new("127.0.0.1", port, vec![9999], tls(TlsMode::Off, None, false), Policy::default());
    assert!(matches!(relay.http(1, Some(9999), job("/", false, Duration::from_secs(1))), Err(Failure::Denied(_))), "a net port is not an http port");
    relay.set_http_ports(vec![9999]);
    assert!(relay.http(2, Some(9999), job("/", false, Duration::from_secs(1))).is_ok());
    let mut routed = Relay::new("127.0.0.1", port, vec![], EntryTls { route: EntryRoute::NotDirect, ..tls(TlsMode::Off, None, false) }, Policy::default());
    assert!(matches!(routed.http(1, None, job("/", false, Duration::from_secs(1))), Err(Failure::Denied(_))));
}

#[test]
fn a_silent_server_times_out_and_cancel_ends_a_request() {
    let port = silent_server();
    let mut relay = Relay::new("127.0.0.1", port, vec![], tls(TlsMode::Off, None, false), Policy::default());
    let t = Instant::now();
    relay.http(1, None, job("/", false, Duration::from_millis(300))).unwrap();
    assert_eq!(wait(&mut relay, 1), Err(Failure::TimedOut));
    assert!(t.elapsed() < Duration::from_secs(5));
    relay.http(2, None, job("/", false, Duration::from_secs(60))).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let t = Instant::now();
    // The worker may still be connecting; cancel once it is busy on the socket.
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        relay.poll();
        if relay.streams.values().any(|h| h.open.is_some() && h.http.is_some()) {
            break;
        }
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(relay.http_cancel(2));
    assert!(wait(&mut relay, 2).is_err());
    assert!(t.elapsed() < Duration::from_secs(5), "cancel did not wait for the 60 s limit");
    assert!(!relay.http_cancel(99));
}

#[test]
fn http_requests_count_against_the_connection_rate() {
    let (port, _) = http_server(|_| b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_vec());
    let mut relay = Relay::new("127.0.0.1", port, vec![], tls(TlsMode::Off, None, false), Policy::default());
    let mut refused = None;
    for i in 1..=40u32 {
        match relay.http(i, None, job("/", false, Duration::from_secs(5))) {
            Ok(_) => {
                let _ = wait(&mut relay, i);
                relay.consumed(i);
            }
            Err(f) => {
                refused = Some((i, f));
                break;
            }
        }
    }
    let (i, f) = refused.expect("the rate cap applies");
    assert_eq!(i, 31, "{f:?}");
}

#[test]
fn an_answer_reserves_its_room_until_taken() {
    let port = silent_server();
    let mut relay = Relay::new("127.0.0.1", port, vec![], tls(TlsMode::Off, None, false), Policy::default());
    relay.http(1, None, job("/", false, Duration::from_secs(60))).unwrap();
    relay.http(2, None, job("/", false, Duration::from_secs(60))).unwrap();
    // 2 x 16 MiB is the whole 32 MiB room: a third waits for the plugin to take a reply.
    assert!(matches!(relay.http(3, None, job("/", false, Duration::from_secs(60))), Err(Failure::Invalid(_))));
    relay.stop(StopReason::TabClosed);
}
