//! The core's plugin HTTP path (PLUG-HTTP-01) against a real Proxmox VE host, read-only.
//! Ignored by default; run by hand against a test Proxmox VE host:
//!
//!   set -a; . ~/.config/bastion/pve-test.env; set +a
//!   BASTION_PVE_CERT_SHA256=<hex> cargo test --test plugin_http_live -- --ignored --nocapture
//!
//! - `BASTION_PVE_URL`, `BASTION_PVE_TOKEN_ID`, `BASTION_PVE_TOKEN_SECRET`: a read-only
//!   PVEAuditor token kept outside the repository. `BASTION_PVE_CERT_SHA256`: the lowercase hex
//!   SHA-256 of the server's certificate, the entry's "pinned" TLS mode.
//! - This is the path a plugin's `http.send` takes: the request checks, the login header built
//!   by the core (`auth_value`), the relay's worker with the pinned TLS, the strict response
//!   reader, and the echo check. Nothing is printed but the release and counts.
//! - GET `version` and `nodes` only: no guest is read, so the owner's VMs are never touched.

use std::time::{Duration, Instant};

use bastion_core::plugin::broker::http::{auth_value, check_echo, check_request, encode_request, host_header, parse_auth_format, HttpAuth, HttpSpec, Method, PluginRequest};
use bastion_core::plugin::broker::secret::SecretCheck;
use bastion_core::plugin::broker::stream::TlsMode;
use bastion_core::plugin::host::relay::{EntryRoute, EntryTls, HttpJob, Outcome, Relay};
use bastion_core::policy::Policy;

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"))
}

fn wait(relay: &mut Relay, request: u32) -> Outcome {
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        for d in relay.poll() {
            if d.request == request {
                match d.outcome {
                    Ok(o) => return o,
                    // The core's words only; they never hold the token.
                    Err(f) => panic!("request {request}: {f}"),
                }
            }
        }
        assert!(Instant::now() < end, "no answer");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "needs a real Proxmox host and a read-only token"]
fn the_core_reads_a_real_proxmox_host_with_the_token_it_holds() {
    let url = env("BASTION_PVE_URL");
    let rest = url.strip_prefix("https://").expect("an https URL");
    let authority = rest.split('/').next().unwrap();
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().expect("a port")),
        None => (authority.to_string(), 443),
    };
    let pin = env("BASTION_PVE_CERT_SHA256").trim().to_ascii_lowercase();
    assert!(pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit()), "BASTION_PVE_CERT_SHA256 is 64 hex digits");
    let user = env("BASTION_PVE_TOKEN_ID");
    let secret = zeroize::Zeroizing::new(env("BASTION_PVE_TOKEN_SECRET"));

    let spec = HttpSpec {
        paths: vec!["/api2/json/".into()],
        ports: vec![],
        methods: vec![Method::Get],
        auth: Some(HttpAuth { header: "Authorization".into(), format: parse_auth_format("PVEAPIToken={user}={secret}").unwrap() }),
        session: None,
    };
    let mut login = SecretCheck::new();
    login.add(secret.as_bytes());
    let tls = EntryTls { mode: TlsMode::Pinned, pin_sha256: Some(pin), allow_unencrypted: false, route: EntryRoute::Direct };
    let mut relay = Relay::new(&host, port, vec![], tls, Policy::default());

    let get = |relay: &mut Relay, request: u32, target: &str| -> serde_json::Value {
        let req = PluginRequest { method: Method::Get, port: None, target: target.into(), headers: vec![("Accept".into(), "application/json".into())], body: vec![], with_login: true, timeout_ms: Some(20_000) };
        check_request(&spec, &req, &login).expect("the request passes the core's checks");
        let value = auth_value(&spec.auth.as_ref().unwrap().format, &user, secret.as_bytes()).expect("a printable token");
        let wire = encode_request(&req, &host_header(&host, port, true), "dev.bastion.proxmox", Some(("Authorization", value.as_str())));
        relay.http(request, None, HttpJob { wire, head: false, timeout: Duration::from_millis(20_000), with_login: true, session: None }).expect("accepted");
        let Outcome::Http(resp) = wait(relay, request) else { panic!("not an http answer") };
        check_echo(&resp, &login).expect("the answer does not repeat the token");
        assert_eq!(resp.status, 200, "status");
        relay.consumed(request);
        serde_json::from_slice::<serde_json::Value>(&resp.body).expect("JSON")["data"].clone()
    };

    let version = get(&mut relay, 1, "/api2/json/version");
    let nodes = get(&mut relay, 2, "/api2/json/nodes");
    let nodes = nodes.as_array().expect("a node list");
    assert!(!nodes.is_empty());
    assert_eq!(relay.http_connections(), 1, "the second request reused the connection");
    println!(
        "live: release {}, {} node(s), {} online, one kept-alive connection",
        version["release"].as_str().unwrap_or("?"),
        nodes.len(),
        nodes.iter().filter(|n| n["status"] == "online").count()
    );
}
