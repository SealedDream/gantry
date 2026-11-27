//! The stream relay against real sockets on loopback (PLUG-02b part 3).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::plugin::broker::stream::{MAX_PREAMBLE_BYTES, MAX_STREAMS_PER_HELPER};

fn direct(mode: TlsMode) -> EntryTls {
    EntryTls { mode, pin_sha256: None, allow_unencrypted: false, route: EntryRoute::Direct }
}

fn relay_to(port: u16, tls: EntryTls) -> Relay {
    Relay::new("127.0.0.1", port, vec![], tls, Policy::default())
}

/// Waits for the reply to `request`.
fn wait(relay: &mut Relay, request: u32) -> Result<Outcome, Failure> {
    let end = Instant::now() + Duration::from_secs(10);
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

fn open(relay: &mut Relay, request: u32) -> u32 {
    relay.connect(request, None).unwrap();
    match wait(relay, request) {
        Ok(Outcome::Opened(s)) => s,
        other => panic!("not opened: {other:?}"),
    }
}

/// An echo server: every connection echoes until closed.
fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// A server that records everything each connection sends, one message per connection.
fn recording_server() -> (u16, mpsc::Receiver<Vec<u8>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut s = s;
                let mut all = Vec::new();
                let _ = s.read_to_end(&mut all);
                let _ = tx.send(all);
            });
        }
    });
    (port, rx)
}

/// A TLS echo server with a fresh self-signed certificate; returns its port and the pin.
fn tls_server() -> (u16, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let der = cert.cert.der().clone();
    let pin = certificate_pin(der.as_ref());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let config = Arc::new(rustls::ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![der], key).unwrap());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let config = config.clone();
            std::thread::spawn(move || {
                // A plaintext hello line first (the "preamble"), echoed back, then TLS.
                let mut sock = s;
                let mut hello = [0u8; 6];
                if sock.read_exact(&mut hello).is_err() {
                    return;
                }
                let _ = sock.write_all(&hello);
                let conn = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, sock);
                let mut buf = [0u8; 4096];
                while let Ok(n) = tls.read(&mut buf) {
                    if n == 0 || tls.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, pin)
}

fn read_all(relay: &mut Relay, req: &mut u32, stream: u32, want: usize) -> Vec<u8> {
    let mut got = Vec::new();
    while got.len() < want {
        *req += 1;
        relay.read(*req, stream, 65536).unwrap();
        match wait(relay, *req).unwrap() {
            Outcome::Data(d) if !d.is_empty() => got.extend(d),
            other => panic!("stream ended early: {other:?}"),
        }
    }
    got
}

#[test]
fn a_local_stream_connects_writes_and_reads() {
    let port = echo_server();
    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    let s = open(&mut relay, 1);
    // Local: the preamble limit does not apply, so a long write goes.
    let data = vec![7u8; 4 * MAX_PREAMBLE_BYTES];
    relay.write(2, s, data.clone(), &SecretCheck::new()).unwrap();
    assert_eq!(wait(&mut relay, 2), Ok(Outcome::None));
    let mut req = 2;
    assert_eq!(read_all(&mut relay, &mut req, s, data.len()), data);
    relay.close(s);
}

#[test]
fn only_the_entrys_port_and_listed_ports() {
    let port = echo_server();
    let other = echo_server();
    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    assert!(matches!(relay.connect(1, Some(other)), Err(Failure::Denied(_))));
    assert!(matches!(relay.connect(2, Some(0)), Err(Failure::Denied(_))));
    let mut relay = Relay::new("127.0.0.1", port, vec![other], direct(TlsMode::VerifyFull), Policy::default());
    relay.connect(3, Some(other)).unwrap();
    assert!(matches!(wait(&mut relay, 3), Ok(Outcome::Opened(_))));
}

#[test]
fn a_route_that_is_not_direct_is_refused() {
    let port = echo_server();
    let mut tls = direct(TlsMode::VerifyFull);
    tls.route = EntryRoute::NotDirect;
    let mut relay = relay_to(port, tls);
    assert!(matches!(relay.connect(1, None), Err(Failure::Denied(_))));
    assert_eq!(relay.open_streams(), 0);
    // The default is not direct: an app that does not say so gets no stream.
    assert_eq!(EntryTls::default().route, EntryRoute::NotDirect);
}

#[test]
fn the_seventeenth_stream_is_refused_and_a_close_frees_one() {
    let port = echo_server();
    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    let mut streams = Vec::new();
    for i in 0..MAX_STREAMS_PER_HELPER as u32 {
        streams.push(open(&mut relay, i + 1));
    }
    assert!(matches!(relay.connect(100, None), Err(Failure::Invalid(_))));
    relay.close(streams[0]);
    // The worker leaves, and its Closed frees the slot.
    let end = Instant::now() + Duration::from_secs(5);
    while relay.open_streams() >= MAX_STREAMS_PER_HELPER {
        relay.poll();
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    open(&mut relay, 101);
}

#[test]
fn a_refused_connect_frees_its_slot() {
    // Bind and drop: nothing listens there.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    relay.connect(1, None).unwrap();
    assert!(matches!(wait(&mut relay, 1), Err(Failure::Io(_)) | Err(Failure::TimedOut)));
    assert_eq!(relay.open_streams(), 0);
}

#[test]
fn close_ends_a_waiting_read() {
    let port = echo_server();
    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    let s = open(&mut relay, 1);
    relay.read(2, s, 100).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    relay.close(s);
    // The read ends (empty data or an I/O error), it does not hang.
    let r = wait(&mut relay, 2);
    assert!(matches!(r, Ok(Outcome::Data(ref d)) if d.is_empty()) || matches!(r, Err(Failure::Io(_))), "{r:?}");
    assert!(matches!(relay.read(3, s, 100), Err(Failure::Invalid(_))));
}

#[test]
fn sizes_and_unknown_streams_are_refused() {
    let port = echo_server();
    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    let s = open(&mut relay, 1);
    assert!(matches!(relay.read(2, s, 0), Err(Failure::Invalid(_))));
    assert!(matches!(relay.read(3, s, MAX_IO_BYTES as u32 + 1), Err(Failure::Invalid(_))));
    assert!(matches!(relay.write(4, s, vec![0; MAX_IO_BYTES + 1], &SecretCheck::new()), Err(Failure::Invalid(_))));
    assert!(matches!(relay.read(5, 999, 10), Err(Failure::Invalid(_))));
    assert!(matches!(relay.write(6, 999, vec![1], &SecretCheck::new()), Err(Failure::Invalid(_))));
    assert!(matches!(relay.start_tls(7, 999), Err(Failure::Invalid(_))));
}

#[test]
fn a_remote_stream_holds_writes_to_the_preamble_until_tls() {
    let (port, pin) = tls_server();
    let mut tls = direct(TlsMode::Pinned);
    tls.pin_sha256 = Some(pin);
    let mut relay = relay_to(port, tls);
    relay.test_remote = true;
    let s = open(&mut relay, 1);
    let mut released = SecretCheck::new();
    released.add(b"hunter2-secret");
    // The secret in the preamble is refused; so is a preamble over 512 bytes.
    assert!(matches!(relay.write(2, s, b"hunter2-secret".to_vec(), &released), Err(Failure::Denied(_))));
    assert!(matches!(relay.write(3, s, vec![b'x'; MAX_PREAMBLE_BYTES + 1], &released), Err(Failure::Denied(_))));
    assert!(matches!(relay.check_login(s), Err(Failure::Denied(_))));
    // A short preamble goes.
    relay.write(4, s, b"HELLO\n".to_vec(), &released).unwrap();
    assert_eq!(wait(&mut relay, 4), Ok(Outcome::None));
    let mut req = 4;
    assert_eq!(read_all(&mut relay, &mut req, s, 6), b"HELLO\n");
    // TLS with the pinned certificate, then any size and the login gate opens.
    relay.start_tls(10, s).unwrap();
    assert_eq!(wait(&mut relay, 10), Ok(Outcome::None));
    assert_eq!(relay.check_login(s), Ok(()));
    let big = vec![9u8; 2 * MAX_PREAMBLE_BYTES];
    relay.write(11, s, big.clone(), &released).unwrap();
    assert_eq!(wait(&mut relay, 11), Ok(Outcome::None));
    let mut req = 11;
    assert_eq!(read_all(&mut relay, &mut req, s, big.len()), big);
}

#[test]
fn a_certificate_that_fails_the_tls_mode_fails_start_tls() {
    let (port, _pin) = tls_server();
    for (mode, pin) in [(TlsMode::Pinned, Some("00".repeat(32))), (TlsMode::VerifyFull, None)] {
        let mut tls = direct(mode);
        tls.pin_sha256 = pin;
        let mut relay = relay_to(port, tls);
        relay.test_remote = true;
        let s = open(&mut relay, 1);
        relay.write(2, s, b"HELLO\n".to_vec(), &SecretCheck::new()).unwrap();
        assert_eq!(wait(&mut relay, 2), Ok(Outcome::None));
        let mut req = 2;
        read_all(&mut relay, &mut req, s, 6);
        relay.start_tls(10, s).unwrap();
        match wait(&mut relay, 10) {
            Err(Failure::Denied(why)) => assert!(why.contains(TLS_MODE_HINT), "{why}"),
            other => panic!("{mode:?}: {other:?}"),
        }
        // No TLS, so the login stays shut and the stream is dead.
        assert!(relay.check_login(s).is_err());
        relay.write(11, s, b"x".to_vec(), &SecretCheck::new()).unwrap();
        assert!(wait(&mut relay, 11).is_err());
    }
}

#[test]
fn tls_off_refuses_start_tls_and_a_remote_stream_without_allow_unencrypted() {
    let port = echo_server();
    let mut relay = relay_to(port, direct(TlsMode::Off));
    // Local and off: allowed, but start-tls is refused.
    let s = open(&mut relay, 1);
    assert!(matches!(relay.start_tls(2, s), Err(Failure::Denied(_))));
    // Remote, off and "Allow unencrypted" off: the connect is refused.
    let mut relay = relay_to(port, direct(TlsMode::Off));
    relay.test_remote = true;
    relay.connect(3, None).unwrap();
    assert!(matches!(wait(&mut relay, 3), Err(Failure::Denied(_))));
    assert_eq!(relay.open_streams(), 0);
    // Pinned with no pin: start-tls refused.
    let mut relay = relay_to(port, direct(TlsMode::Pinned));
    let s = open(&mut relay, 4);
    assert!(matches!(relay.start_tls(5, s), Err(Failure::Denied(_))));
}

#[test]
fn abort_bytes_go_once_on_an_ordinary_stop() {
    let (port, rx) = recording_server();
    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    let s = open(&mut relay, 1);
    relay.register_abort(s, b"CANCEL-1", &SecretCheck::new()).unwrap();
    relay.register_abort(s, b"CANCEL-2", &SecretCheck::new()).unwrap();
    let sender = relay.stop(StopReason::TabClosed).expect("abort sender");
    sender.join().unwrap();
    // Two connections: the stream itself (nothing written) and one abort with the latest bytes.
    let mut seen = vec![rx.recv_timeout(Duration::from_secs(5)).unwrap(), rx.recv_timeout(Duration::from_secs(5)).unwrap()];
    seen.sort();
    assert_eq!(seen, vec![Vec::new(), b"CANCEL-2".to_vec()]);
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    // After stop: no new registrations, and closing changes nothing.
    assert!(relay.register_abort(s, b"again", &SecretCheck::new()).is_err());
    assert!(relay.stop(StopReason::TabClosed).is_none());
}

#[test]
fn abort_bytes_are_not_sent_on_a_trust_withdrawing_stop_or_after_close() {
    let (port, rx) = recording_server();
    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    let s = open(&mut relay, 1);
    relay.register_abort(s, b"CANCEL", &SecretCheck::new()).unwrap();
    assert!(relay.stop(StopReason::ProtocolViolation).is_none());
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Vec::<u8>::new());
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());

    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    let s = open(&mut relay, 1);
    relay.register_abort(s, b"CANCEL", &SecretCheck::new()).unwrap();
    relay.close(s);
    assert!(relay.stop(StopReason::TabClosed).is_none());
    // Dropping a relay never sends (no stated reason).
    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    let s = open(&mut relay, 1);
    relay.register_abort(s, b"CANCEL", &SecretCheck::new()).unwrap();
    drop(relay);
    let mut got = Vec::new();
    while let Ok(m) = rx.recv_timeout(Duration::from_millis(500)) {
        got.push(m);
    }
    assert!(got.iter().all(|m| m.is_empty()), "{got:?}");
}

#[test]
fn abort_bytes_pass_the_secret_check_and_the_size_limit() {
    let port = echo_server();
    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    let s = open(&mut relay, 1);
    let mut released = SecretCheck::new();
    released.add(b"hunter2-secret");
    assert!(matches!(relay.register_abort(s, b"x hunter2-secret", &released), Err(Failure::Denied(_))));
    assert!(relay.register_abort(s, &[1u8; 513], &released).is_err());
    assert!(relay.register_abort(s, &[1u8; 512], &released).is_ok());
    assert!(matches!(relay.register_abort(999, b"x", &released), Err(Failure::Invalid(_))));
}

#[test]
fn the_unspecified_address_is_not_a_destination() {
    let mut relay = Relay::new("0.0.0.0", 9, vec![], direct(TlsMode::VerifyFull), Policy::default());
    relay.connect(1, None).unwrap();
    assert!(matches!(wait(&mut relay, 1), Err(Failure::Denied(_))));
    assert_eq!(relay.open_streams(), 0);
}

#[test]
fn the_pin_is_the_certificate_sha256() {
    assert_eq!(certificate_pin(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn waiting_stream_requests_and_bytes_are_bounded_until_the_plugin_takes_the_replies() {
    // Review of #1331, MEDIUM: a plugin that keeps reading and never takes its replies must not
    // make the core hold data without limit.
    let port = echo_server();
    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    let s = open(&mut relay, 1);
    relay.consumed(1);
    assert_eq!(relay.waiting(), (0, 0));
    // 1 MiB reads: the 33rd would pass 32 MiB, so it is refused, without being queued.
    let mib = MAX_IO_BYTES as u32;
    let fit = MAX_WAITING_BYTES / MAX_IO_BYTES;
    for r in 0..fit as u32 {
        relay.read(100 + r, s, mib).unwrap();
    }
    assert_eq!(relay.waiting(), (fit, MAX_WAITING_BYTES));
    assert!(matches!(relay.read(999, s, mib), Err(Failure::Invalid(_))));
    // A write is data the core holds too.
    assert!(matches!(relay.write(998, s, vec![0; 1], &SecretCheck::new()), Err(Failure::Invalid(_))));
    assert_eq!(relay.waiting(), (fit, MAX_WAITING_BYTES));
    // Polling moves finished requests to the dispatch, but their room stays reserved until the
    // plugin takes them: the bound covers replies waiting in the core, not only in flight.
    relay.write(997, s, vec![], &SecretCheck::new()).ok();
    let end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < end {
        relay.poll();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(relay.waiting().1, MAX_WAITING_BYTES);
    assert!(relay.read(996, s, mib).is_err());
    // Taking one reply frees one MiB.
    relay.consumed(100);
    relay.read(995, s, mib).unwrap();
    // Small requests: at most 256 waiting. Reads on a quiet server wait, so each stream holds
    // one running and 64 queued; five streams could hold 325, and the bound stops it at 256.
    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    let streams: Vec<u32> = (1..=5).map(|r| open(&mut relay, r)).collect();
    (1..=5).for_each(|r| relay.consumed(r));
    let mut request = 1000;
    for s in streams {
        while relay.read(request, s, 1).is_ok() {
            request += 1;
        }
    }
    assert_eq!(relay.waiting().0, MAX_WAITING_REQUESTS);
    assert!(matches!(relay.connect(9999, None), Err(Failure::Invalid(_))));
}

#[test]
fn a_refused_request_gives_its_room_back() {
    let port = echo_server();
    let mut relay = relay_to(port, direct(TlsMode::Off));
    let s = open(&mut relay, 1);
    relay.consumed(1);
    // start-tls is refused before admission; an unknown stream too.
    assert!(relay.start_tls(2, s).is_err());
    assert!(relay.read(3, 999, 10).is_err());
    assert_eq!(relay.waiting(), (0, 0));
    // A remote write over the preamble is refused after admission and gives it back.
    let mut relay = relay_to(port, direct(TlsMode::VerifyFull));
    relay.test_remote = true;
    let s = open(&mut relay, 1);
    relay.consumed(1);
    assert!(relay.write(2, s, vec![b'x'; MAX_PREAMBLE_BYTES + 1], &SecretCheck::new()).is_err());
    assert_eq!(relay.waiting(), (0, 0));
}

// ---- PLUG-08: routes through the app's tunnels -------------------------------------------

fn routed(route: EntryRoute) -> EntryTls {
    EntryTls { mode: TlsMode::VerifyFull, pin_sha256: None, allow_unencrypted: false, route }
}

/// A SOCKS5 proxy that answers one CONNECT (no auth), records the asked host and port, then echoes.
fn socks_server() -> (u16, mpsc::Receiver<(String, u16)>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut s = s;
                let mut hello = [0u8; 3];
                s.read_exact(&mut hello).unwrap();
                s.write_all(&[5, 0]).unwrap();
                let mut head = [0u8; 5];
                s.read_exact(&mut head).unwrap();
                let mut name = vec![0u8; usize::from(head[4])];
                s.read_exact(&mut name).unwrap();
                let mut p = [0u8; 2];
                s.read_exact(&mut p).unwrap();
                tx.send((String::from_utf8(name).unwrap(), u16::from_be_bytes(p))).unwrap();
                s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, rx)
}

#[test]
fn no_login_is_released_before_a_stream_is_open() {
    let relay = relay_to(5432, direct(TlsMode::VerifyFull));
    assert!(matches!(relay.check_login_all(), Err(Failure::Denied(t)) if t.contains("opens a stream")));
}

#[test]
fn a_forward_to_a_loopback_target_is_local_and_reaches_the_listener() {
    let fwd = echo_server();
    let mut relay = Relay::new("db.internal", 5432, vec![], routed(EntryRoute::Forward { port: fwd, target: "127.0.0.1".into() }), Policy::default());
    let s = open(&mut relay, 1);
    // Loopback target behind the SSH server: no TLS needed before the login.
    assert!(relay.check_login_all().is_ok());
    relay.write(2, s, b"ping".to_vec(), &SecretCheck::new()).unwrap();
    assert!(wait(&mut relay, 2).is_ok());
}

#[test]
fn a_forward_to_a_named_host_waits_for_tls_and_serves_only_the_entry_port() {
    let fwd = echo_server();
    let mut relay = Relay::new("db.internal", 5432, vec![6432], routed(EntryRoute::Forward { port: fwd, target: "db.internal".into() }), Policy::default());
    open(&mut relay, 1);
    assert!(matches!(relay.check_login_all(), Err(Failure::Denied(t)) if t.contains("TLS")), "a name is never local");
    assert!(matches!(relay.connect(2, Some(6432)), Err(Failure::Denied(t)) if t.contains("only the entry's own port")));
}

#[test]
fn a_socks_route_asks_the_proxy_for_the_entry_and_is_never_local() {
    let (proxy, asked) = socks_server();
    let mut relay = Relay::new("db.internal", 5432, vec![], routed(EntryRoute::Socks { port: proxy }), Policy::default());
    let s = open(&mut relay, 1);
    assert_eq!(asked.recv_timeout(Duration::from_secs(5)).unwrap(), ("db.internal".to_string(), 5432));
    assert!(relay.check_login_all().is_err(), "SOCKS is never local");
    relay.write(2, s, b"ping".to_vec(), &SecretCheck::new()).unwrap();
    assert!(wait(&mut relay, 2).is_ok());
}

#[test]
fn a_gateway_without_a_running_tunnel_is_refused_in_core_words() {
    let mut relay = relay_to(5432, routed(EntryRoute::NotDirect));
    assert!(matches!(relay.connect(1, None), Err(Failure::Denied(t)) if t.contains("no running tunnel")));
    assert_eq!(EntryRoute::Forward { port: 1, target: "h".into() }.audit_name(), "tunnel");
    assert_eq!(EntryRoute::Socks { port: 1 }.audit_name(), "socks");
}
