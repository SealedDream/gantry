//! Session logins through the relay against a mock ESXi over HTTPS on loopback (design D,
//! `docs/design/VMW-ESXI.md` section 8). There is no real ESXi in the lab: this mock answers
//! the SOAP `Login`/`Logout` calls and checks the session cookie like a host does.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::plugin::broker::http::{encode_request, host_header, Method, PluginRequest};
use crate::plugin::broker::http_session::{self as hs, HttpSession};

const PASSWORD: &str = "s3cret<pw>&'";
const LOGIN: &str = "<Envelope><Body><Login><_this>ha-sessionmgr</_this><userName>{user}</userName><password>{secret}</password></Login></Body></Envelope>";
const LOGOUT: &str = "<Envelope><Body><Logout><_this>ha-sessionmgr</_this></Logout></Body></Envelope>";

/// What the mock host saw, and how it behaves.
#[derive(Default)]
struct Esxi {
    logins: AtomicUsize,
    logouts: Mutex<Vec<String>>,
    requests: Mutex<Vec<String>>,
    /// The cookie the host accepts now; `None` once expired.
    valid: Mutex<Option<String>>,
    /// Every request answers 401, even with a fresh cookie.
    always_401: AtomicBool,
    connections: AtomicUsize,
}

fn read_message(r: &mut impl Read) -> Option<(String, Vec<u8>)> {
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
    Some((text, body))
}

fn answer(status: &str, headers: &str, body: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status}\r\n{headers}Content-Type: text/xml\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
}

fn cookie_of(head: &str) -> Option<String> {
    head.lines().find_map(|l| l.strip_prefix("Cookie: vmware_soap_session=")).map(|c| c.trim().to_string())
}

impl Esxi {
    fn serve(&self, head: &str, body: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(body);
        if text.contains("<Login>") {
            let n = self.logins.fetch_add(1, Ordering::SeqCst) + 1;
            // The host gets the password XML-escaped.
            if !text.contains("<password>s3cret&lt;pw&gt;&amp;&apos;</password>") {
                return answer("500 Internal Server Error", "", "<faultstring>Cannot complete login due to an incorrect user name or password: s3cret</faultstring>");
            }
            let c = format!("sess-{n}-abcdef");
            *self.valid.lock().unwrap() = Some(c.clone());
            return answer("200 OK", &format!("Set-Cookie: vmware_soap_session=\"{c}\"; Path=/; HttpOnly; Secure\r\n"), "<LoginResponse/>");
        }
        if text.contains("<Logout>") {
            self.logouts.lock().unwrap().push(cookie_of(head).unwrap_or_default());
            return answer("200 OK", "", "<LogoutResponse/>");
        }
        self.requests.lock().unwrap().push(head.to_string());
        let ok = cookie_of(head).is_some_and(|c| self.valid.lock().unwrap().as_deref() == Some(c.as_str()));
        if self.always_401.load(Ordering::SeqCst) || !ok {
            return answer("500 Internal Server Error", "", r#"<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>The session is not authenticated.</faultstring><detail><NotAuthenticatedFault xmlns="urn:vim25"/></detail></soapenv:Fault></soapenv:Body></soapenv:Envelope>"#);
        }
        if head.starts_with("GET /sdk/redirect") {
            return answer("302 Found", "Location: https://evil.example/sdk\r\nSet-Cookie: vmware_soap_session=leak\r\n", "");
        }
        answer("200 OK", "Set-Cookie: vmware_soap_session=renewed\r\n", "<RetrievePropertiesExResponse/>")
    }
}

/// A mock ESXi over HTTPS with a fresh self-signed certificate: its port and pin.
fn esxi(host: Arc<Esxi>) -> (u16, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let der = cert.cert.der().clone();
    let pin = certificate_pin(der.as_ref());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let config = Arc::new(rustls::ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![der], key).unwrap());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            host.connections.fetch_add(1, Ordering::SeqCst);
            let (config, host) = (config.clone(), host.clone());
            std::thread::spawn(move || {
                let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), s);
                while let Some((head, body)) = read_message(&mut tls) {
                    if tls.write_all(&host.serve(&head, &body)).is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, pin)
}

fn spec() -> HttpSession {
    HttpSession { login_path: "/sdk".into(), login_body: LOGIN.into(), content_type: "text/xml".into(), cookie: "vmware_soap_session".into(), logout_body: Some(LOGOUT.into()), ticket: None }
}

fn state(password: &str) -> Arc<SessionState> {
    SessionState::new(spec(), "root".into(), zeroize::Zeroizing::new(password.as_bytes().to_vec()), "dev.bastion.vmware", "entry-esxi")
}

fn relay(port: u16, pin: &str, state: &Arc<SessionState>) -> Relay {
    let mut r = Relay::new("127.0.0.1", port, vec![], EntryTls { mode: TlsMode::Pinned, pin_sha256: Some(pin.into()), allow_unencrypted: false, route: EntryRoute::Direct }, Policy::default());
    r.test_remote = true;
    r.set_session(state.clone());
    r
}

fn job(target: &str, state: &Arc<SessionState>) -> HttpJob {
    let req = PluginRequest { method: Method::Get, port: None, target: target.into(), headers: vec![], body: vec![], with_login: true, timeout_ms: None };
    HttpJob { wire: encode_request(&req, &host_header("127.0.0.1", 1, true), "dev.bastion.vmware", None), head: false, timeout: Duration::from_secs(10), with_login: true, session: Some(state.clone()) }
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

fn send(relay: &mut Relay, request: u32, target: &str, state: &Arc<SessionState>) -> Result<HttpResponse, Failure> {
    relay.http(request, None, job(target, state))?;
    let outcome = wait(relay, request);
    relay.consumed(request);
    outcome.map(|o| match o {
        Outcome::Http(r) => r,
        other => panic!("not an http answer: {other:?}"),
    })
}

#[test]
fn the_core_logs_in_once_and_sends_the_cookie_only_to_the_entry_host() {
    let host = Arc::new(Esxi::default());
    let (port, pin) = esxi(host.clone());
    let s = state(PASSWORD);
    let mut r = relay(port, &pin, &s);
    for i in 1..=3 {
        let resp = send(&mut r, i, "/sdk/", &s).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.headers.iter().all(|(n, _)| !n.eq_ignore_ascii_case("set-cookie")), "Set-Cookie never reaches the plugin");
    }
    assert_eq!(host.logins.load(Ordering::SeqCst), 1, "one login for many requests: the ESXi single-session limit holds");
    assert!(host.requests.lock().unwrap().iter().all(|h| h.contains("\r\nCookie: vmware_soap_session=sess-1-abcdef\r\n")));
    assert_eq!(s.cookies(), 1);
    assert!(s.matches(b"x sess-1-abcdef y"), "the cookie joined the secret check");
    assert!(s.matches("s3cret&lt;pw&gt;&amp;&apos;".as_bytes()), "and the XML-escaped password");
    // A redirect is the plugin's answer, not followed: nothing else is contacted, and the
    // cookie the answer sets is stripped.
    let before = host.connections.load(Ordering::SeqCst);
    let redirect = send(&mut r, 9, "/sdk/redirect", &s).unwrap();
    assert_eq!(redirect.status, 302);
    assert!(redirect.headers.iter().all(|(n, _)| !n.eq_ignore_ascii_case("set-cookie")));
    assert_eq!(host.connections.load(Ordering::SeqCst), before, "no new connection");
}

#[test]
fn an_ended_session_logs_in_again_once_and_never_loops() {
    let host = Arc::new(Esxi::default());
    let (port, pin) = esxi(host.clone());
    let s = state(PASSWORD);
    let mut r = relay(port, &pin, &s);
    assert_eq!(send(&mut r, 1, "/sdk/", &s).unwrap().status, 200);
    *host.valid.lock().unwrap() = None; // the host ends the session
    assert_eq!(send(&mut r, 2, "/sdk/", &s).unwrap().status, 200, "re-login, then the request again");
    assert_eq!(host.logins.load(Ordering::SeqCst), 2);
    // A host that refuses every request: one re-login per request, then the refusal.
    host.always_401.store(true, Ordering::SeqCst);
    let before = (host.logins.load(Ordering::SeqCst), host.requests.lock().unwrap().len());
    assert_eq!(send(&mut r, 3, "/sdk/", &s).unwrap().status, 500);
    assert_eq!(host.logins.load(Ordering::SeqCst) - before.0, 1, "one re-login");
    assert_eq!(host.requests.lock().unwrap().len() - before.1, 2, "the request and one retry");
}

#[test]
fn a_wrong_password_fails_in_fixed_words_and_backs_off() {
    let host = Arc::new(Esxi::default());
    let (port, pin) = esxi(host.clone());
    let s = state("wrong");
    let mut r = relay(port, &pin, &s);
    for i in 1..=hs::MAX_FAILED_LOGINS {
        match send(&mut r, i, "/sdk/", &s) {
            Err(Failure::Denied(t)) => assert_eq!(t, hs::LOGIN_FAILED, "never the server's fault text"),
            other => panic!("{other:?}"),
        }
    }
    match send(&mut r, 99, "/sdk/", &s) {
        Err(Failure::Denied(t)) => assert_eq!(t, hs::LOGIN_BACKING_OFF),
        other => panic!("{other:?}"),
    }
    assert_eq!(host.logins.load(Ordering::SeqCst), hs::MAX_FAILED_LOGINS as usize, "no login while backing off");
    assert!(host.requests.lock().unwrap().is_empty(), "no request went without a session");
    assert_eq!(s.cookies(), 0);
}

#[test]
fn sessions_per_host_are_capped_and_stop_logs_out() {
    let host = Arc::new(Esxi::default());
    let (port, pin) = esxi(host.clone());
    let states: Vec<_> = (0..=hs::MAX_SESSIONS_PER_HOST).map(|_| state(PASSWORD)).collect();
    let mut relays: Vec<_> = states.iter().map(|s| relay(port, &pin, s)).collect();
    for (i, (r, s)) in relays.iter_mut().zip(&states).enumerate().take(hs::MAX_SESSIONS_PER_HOST) {
        assert_eq!(send(r, i as u32 + 1, "/sdk/", s).unwrap().status, 200, "session {i}");
    }
    let last = hs::MAX_SESSIONS_PER_HOST;
    match send(&mut relays[last], 50, "/sdk/", &states[last]) {
        Err(Failure::Denied(t)) => assert_eq!(t, hs::TOO_MANY_SESSIONS),
        other => panic!("{other:?}"),
    }
    // Stopping a helper logs out (with its cookie) and frees the place.
    let cookie = host.valid.lock().unwrap().clone().unwrap();
    relays[last - 1].stop(StopReason::TabClosed);
    assert_eq!(states[last - 1].cookies(), 0, "the cookie is dropped at once");
    let end = Instant::now() + Duration::from_secs(5);
    while host.logouts.lock().unwrap().is_empty() {
        assert!(Instant::now() < end, "no logout");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(host.logouts.lock().unwrap()[0], cookie);
    assert_eq!(send(&mut relays[last], 51, "/sdk/", &states[last]).unwrap().status, 200);
}

#[test]
fn the_login_goes_only_over_the_pinned_tls_connection() {
    let host = Arc::new(Esxi::default());
    let (port, _pin) = esxi(host.clone());
    let s = state(PASSWORD);
    // A wrong pin: the handshake fails and no byte of the login is sent.
    let mut wrong = relay(port, &"00".repeat(32), &s);
    assert!(matches!(send(&mut wrong, 1, "/sdk/", &s), Err(Failure::Denied(_))));
    assert_eq!(host.logins.load(Ordering::SeqCst), 0);
    // Plain HTTP to 127.0.0.1, direct: refused even though the host is local.
    let (plain_port, seen) = plain_server();
    let mut plain = Relay::new("127.0.0.1", plain_port, vec![], EntryTls { mode: TlsMode::Off, pin_sha256: None, allow_unencrypted: true, route: EntryRoute::Direct }, Policy::default());
    plain.set_session(s.clone());
    match send(&mut plain, 1, "/sdk/", &s) {
        Err(Failure::Denied(t)) => assert_eq!(t, hs::SESSION_UNENCRYPTED),
        other => panic!("{other:?}"),
    }
    assert!(seen.recv_timeout(Duration::from_millis(300)).is_err(), "nothing was written");
}

/// A plain server that reports any bytes it receives.
fn plain_server() -> (u16, mpsc::Receiver<Vec<u8>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut b = [0u8; 64];
            if let Ok(n) = s.read(&mut b) {
                if n > 0 {
                    let _ = tx.send(b[..n].to_vec());
                }
            }
        }
    });
    (port, rx)
}

fn wait_for(what: &str, ok: impl Fn() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !ok() {
        assert!(Instant::now() < end, "{what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_plugin_cannot_force_repeated_logins() {
    let host = Arc::new(Esxi::default());
    host.always_401.store(true, Ordering::SeqCst);
    let (port, pin) = esxi(host.clone());
    let s = state(PASSWORD);
    let mut r = relay(port, &pin, &s);
    for i in 1..=8 {
        let _ = send(&mut r, i, "/sdk/", &s);
    }
    assert_eq!(host.logins.load(Ordering::SeqCst), hs::MAX_FAILED_LOGINS as usize, "a fresh session refused at once counts as a failed login");
    match send(&mut r, 99, "/sdk/", &s) {
        Err(Failure::Denied(t)) => assert_eq!(t, hs::LOGIN_BACKING_OFF),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_refused_session_is_logged_out_and_concurrent_requests_share_one_login() {
    let host = Arc::new(Esxi::default());
    let (port, pin) = esxi(host.clone());
    let s = state(PASSWORD);
    let mut r = relay(port, &pin, &s);
    // Two requests at once (the most the relay admits), each on its own connection: one login, under the port's lock.
    for i in 1..=2 {
        r.http(i, None, job("/sdk/", &s)).unwrap();
    }
    let mut done = Vec::new();
    let end = Instant::now() + Duration::from_secs(15);
    while done.len() < 2 {
        assert!(Instant::now() < end, "no replies: {done:?}");
        for d in r.poll() {
            assert!(matches!(d.outcome, Ok(Outcome::Http(ref resp)) if resp.status == 200), "{:?}", d.outcome);
            done.push(d.request);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    for i in done {
        r.consumed(i);
    }
    assert_eq!(host.logins.load(Ordering::SeqCst), 1, "one login for concurrent requests");
    // The host ends the session: the old cookie is logged out, best effort, and a new one made.
    *host.valid.lock().unwrap() = None;
    assert_eq!(send(&mut r, 3, "/sdk/", &s).unwrap().status, 200);
    wait_for("the refused cookie is logged out", || host.logouts.lock().unwrap().iter().any(|c| c == "sess-1-abcdef"));
    assert_eq!(s.cookies(), 1);
}

#[test]
fn every_kind_of_stop_logs_out_and_drops_the_cookie() {
    for reason in [Some(StopReason::TabClosed), Some(StopReason::DocumentLocked), Some(StopReason::CredentialsLockedByPolicy), Some(StopReason::UserCancel), None] {
        let host = Arc::new(Esxi::default());
        let (port, pin) = esxi(host.clone());
        let s = state(PASSWORD);
        let mut r = relay(port, &pin, &s);
        assert_eq!(send(&mut r, 1, "/sdk/", &s).unwrap().status, 200);
        match reason {
            Some(why) => drop(r.stop(why)),
            None => drop(r), // entry closed: the view drops its relay
        }
        assert_eq!(s.cookies(), 0, "{reason:?}: the cookie is dropped at once");
        wait_for(&format!("{reason:?}: logout"), || host.logouts.lock().unwrap().len() == 1);
    }
}
