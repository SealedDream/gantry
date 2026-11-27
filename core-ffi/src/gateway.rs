//! Bridge for the Gateway Manager (`bastion_core::gateway`). Gateways hold no secrets.
use std::net::SocketAddr;
use std::sync::Arc;

use bastion_core::gateway::{self, Gateway, GatewayInput, GatewayUse, RouteKind};
use bastion_core::model::{Connection, Protocol};
use bastion_core::ssh::SshSession;
use bastion_core::tunnel::{self, Tunnel};

use crate::terminal::{SessionManager, RUNTIME};
use crate::{parse_id, FfiError, FfiResult, Library, SshLogin};

/// The refusal for a saved (vault) login sent to a gateway. Fixed text: no credential name.
pub(crate) const SAVED_LOGIN_REFUSED: &str = "a gateway does not take a saved login: type its password, or use a key file or the SSH agent";

#[derive(uniffi::Record)]
pub struct GatewayView {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub notes: String,
    /// Display names of what uses it: connections ("web", "db (inherited)"), folders and type defaults.
    pub used_by: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct GatewayInputView {
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub notes: String,
}

fn input(v: GatewayInputView) -> GatewayInput {
    GatewayInput { name: v.name, host: v.host, port: v.port, username: v.username, notes: v.notes }
}

fn view(g: &Gateway, uses: Vec<GatewayUse>) -> GatewayView {
    let used_by = uses
        .into_iter()
        .map(|u| match u {
            GatewayUse::Connection { name, inherited: true, .. } => format!("{name} (inherited)"),
            GatewayUse::Connection { name, .. } => name,
            GatewayUse::Folder { name, .. } => format!("{name} folder defaults"),
            GatewayUse::TypeDefault(p) => format!("{} Default Settings", p.to_uppercase()),
        })
        .collect();
    GatewayView { id: g.id.to_string(), name: g.name.clone(), host: g.host.clone(), port: g.port, username: g.username.clone(), notes: g.notes.clone(), used_by }
}

#[uniffi::export]
impl Library {
    /// The library's gateways by name, each with what uses it.
    pub fn gateways(&self) -> FfiResult<Vec<GatewayView>> {
        self.with_doc(|d| {
            let mut list: Vec<GatewayView> = d.gateways.iter().map(|g| view(g, gateway::uses(d, g.id))).collect();
            list.sort_by_key(|g| g.name.to_lowercase());
            Ok(list)
        })
    }

    pub fn add_gateway(&self, gateway: GatewayInputView) -> FfiResult<String> {
        self.with_doc(|d| gateway::add(d, &input(gateway)).map(|id| id.to_string()))
    }

    pub fn update_gateway(&self, id: String, gateway: GatewayInputView) -> FfiResult<()> {
        let id = parse_id(&id)?;
        self.with_doc(|d| gateway::update(d, id, &input(gateway)))
    }

    /// Refused while anything uses the gateway; the error names those places.
    pub fn remove_gateway(&self, id: String) -> FfiResult<()> {
        let id = parse_id(&id)?;
        self.with_doc(|d| gateway::remove(d, id).map(|_| ()))
    }
}

/// The gateway an RDP, VNC or web connection goes through, for its connect sheet.
#[derive(uniffi::Record)]
pub struct GatewayHopView {
    pub name: String,
    /// `host:port`, as in host-key prompts.
    pub key: String,
    /// The gateway's own user name; nil means "type one".
    pub username: Option<String>,
}

#[uniffi::export]
impl Library {
    /// The gateway an RDP, VNC or web connection is reached through, or nil for a direct one.
    /// A dangling gateway reference or an unsupported protocol is an error, never a direct connect.
    pub fn gateway_route(&self, connection_id: String) -> FfiResult<Option<GatewayHopView>> {
        let id = parse_id(&connection_id)?;
        self.with_doc(|d| {
            Ok(gateway::route_for(d, id)?.map(|r| GatewayHopView {
                key: format!("{}:{}", r.gateway.host, r.gateway.port.unwrap_or(22)),
                name: r.gateway.name,
                username: r.gateway.username,
            }))
        })
    }
}

/// A connection's way through its gateway: a loopback port forward (RDP, VNC) or a loopback
/// SOCKS proxy (web), over one SSH session to the gateway. Closing it (or dropping the last
/// reference) closes the listener and, with it, the SSH session.
#[derive(uniffi::Object)]
pub struct GatewayRoute {
    _session: Arc<SshSession>,
    tunnel: Tunnel,
    summary: String,
}

#[uniffi::export]
impl GatewayRoute {
    /// Loopback port to connect to (RDP/VNC) or to use as SOCKS5 proxy (web).
    pub fn local_port(&self) -> u16 {
        self.tunnel.local_addr.port()
    }

    pub fn is_socks(&self) -> bool {
        matches!(self.tunnel.kind, tunnel::TunnelKind::DynamicSocks)
    }

    pub fn is_running(&self) -> bool {
        self.tunnel.is_running()
    }

    /// e.g. `via Jump (127.0.0.1:2223) → 10.0.0.5:3389`.
    pub fn summary(&self) -> String {
        self.summary.clone()
    }

    pub fn last_error(&self) -> Option<String> {
        self.tunnel.stats().last_error
    }

    pub fn close(&self) {
        self.tunnel.stop();
    }
}

#[uniffi::export]
impl SessionManager {
    /// Sign in to the connection's gateway (`username`/`login` are the gateway's) and open its
    /// route on a free loopback port. An unknown gateway key fails with `HostKeyUnknown`; retry
    /// with `trust_fingerprint` once the user verified it.
    ///
    /// A gateway is not a library entry, so the shared login rule has nothing to say about it:
    /// a saved (vault) login is refused before the gateway is looked up or dialled, and nothing
    /// is read from the vault (A1-CORE-01-FU3, ruling: option A). The gateway takes
    /// a typed password, a key file or the agent.
    pub fn open_gateway_route(
        &self,
        library: Arc<Library>,
        connection_id: String,
        username: String,
        login: SshLogin,
        trust_fingerprint: Option<String>,
    ) -> FfiResult<Arc<GatewayRoute>> {
        if matches!(login, SshLogin::Vault { .. }) {
            return Err(FfiError::failed(SAVED_LOGIN_REFUSED.into()));
        }
        let id = parse_id(&connection_id)?;
        let (route, classification) = library.with_doc(|d| {
            let route = gateway::route_for(d, id)?.ok_or_else(|| bastion_core::CoreError::Invalid("this connection has no gateway".into()))?;
            Ok((route, gateway::classification_of(d, id)?))
        })?;
        let gw = &route.gateway;
        let mut hop = Connection::new(gw.name.clone(), Protocol::Ssh, gw.host.clone());
        hop.settings.port = gw.port;
        hop.classification = classification;
        let username = if username.trim().is_empty() { gw.username.clone().unwrap_or_default() } else { username };
        let session = Arc::new(self.dial_gateway(hop, username, login, trust_fingerprint)?);
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let via = format!("via {} ({}:{})", gw.name, gw.host, gw.port.unwrap_or(22));
        let (tunnel, summary) = match &route.kind {
            RouteKind::Forward { dest_host, dest_port } => (
                RUNTIME.block_on(tunnel::local_forward(session.clone(), loopback, dest_host, *dest_port))?,
                format!("{via} → {dest_host}:{dest_port}"),
            ),
            RouteKind::Socks => (RUNTIME.block_on(tunnel::dynamic_socks(session.clone(), loopback))?, format!("{via} (SOCKS)")),
        };
        Ok(Arc::new(GatewayRoute { _session: session, tunnel, summary }))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    use bastion_core::model::{Connection, Node, Protocol};
    use uuid::Uuid;

    use super::*;
    use crate::{FfiError, GatewayInputView};

    fn library_with(dir: &std::path::Path, conns: Vec<Connection>) -> (Arc<Library>, String) {
        let lib = Arc::new(Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap());
        let gw = lib
            .add_gateway(GatewayInputView { name: "Jump".into(), host: "127.0.0.1".into(), port: Some(2223), username: Some("tester".into()), notes: String::new() })
            .unwrap();
        for c in conns {
            let id = c.id.to_string();
            lib.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();
            lib.set_property(id, "gateway_id".into(), Some(gw.clone())).unwrap();
        }
        (lib, gw)
    }

    /// Open a route, accepting the gateway's key the way the connect sheet does after the prompt.
    fn open(mgr: &SessionManager, lib: &Arc<Library>, id: &str) -> Arc<GatewayRoute> {
        let login = || SshLogin::Password { password: "test-pass-123".into() };
        match mgr.open_gateway_route(lib.clone(), id.into(), String::new(), login(), None) {
            Err(FfiError::HostKeyUnknown { fingerprint }) => mgr.open_gateway_route(lib.clone(), id.into(), String::new(), login(), Some(fingerprint)).unwrap(),
            Ok(r) => r,
            Err(e) => panic!("expected the gateway's key prompt, got {e}"),
        }
    }

    #[test]
    fn gateway_route_view_names_the_hop() {
        let dir = std::env::temp_dir().join(format!("bastion-ffi-gwr-{}", Uuid::new_v4()));
        let rdp = Connection::new("win", Protocol::Rdp, "10.0.0.5");
        let direct = Connection::new("direct", Protocol::Vnc, "10.0.0.6");
        let (rid, did) = (rdp.id.to_string(), direct.id.to_string());
        let (lib, _) = library_with(&dir, vec![rdp]);
        lib.with_doc(|d| d.insert(None, Node::Connection(direct))).unwrap();
        let hop = lib.gateway_route(rid).unwrap().unwrap();
        assert_eq!((hop.name.as_str(), hop.key.as_str(), hop.username.as_deref()), ("Jump", "127.0.0.1:2223", Some("tester")));
        assert!(lib.gateway_route(did).unwrap().is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    /// A plugin entry (PLUG-08) with a gateway gets a forward to its own host and port.
    fn plugin_entry(host: &str, port: u16) -> Connection {
        let mut c = Connection::new("pg", Protocol::Unsupported, host);
        c.unknown_protocol = Some("dev.bastion.postgres/postgres".into());
        c.settings.port = Some(port);
        c
    }

    #[test]
    fn a_plugin_entry_names_its_gateway_hop() {
        let dir = std::env::temp_dir().join(format!("bastion-ffi-gwp-{}", Uuid::new_v4()));
        let pg = plugin_entry("db.internal", 5432);
        let id = pg.id.to_string();
        let (lib, _) = library_with(&dir, vec![pg]);
        let hop = lib.gateway_route(id).unwrap().unwrap();
        assert_eq!(hop.key, "127.0.0.1:2223");
        std::fs::remove_dir_all(dir).ok();
    }

    /// Live (PLUG-08): a plugin entry for the private `target` container, which only bastion-jump
    /// reaches, opens a loopback forward through its gateway; the target's SSH banner comes back.
    #[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
    #[test]
    fn a_plugin_entry_reaches_its_private_host_through_the_gateway() {
        assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
        let dir = std::env::temp_dir().join(format!("bastion-ffi-gwpl-{}", Uuid::new_v4()));
        let pg = plugin_entry("target", 2222);
        let id = pg.id.to_string();
        let (lib, _) = library_with(&dir, vec![pg]);
        let mgr = SessionManager::new(dir.to_string_lossy().into_owned()).unwrap();
        let route = open(&mgr, &lib, &id);
        assert!(!route.is_socks());
        assert!(route.summary().contains("via Jump (127.0.0.1:2223) → target:2222"), "{}", route.summary());
        let mut s = TcpStream::connect(("127.0.0.1", route.local_port())).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        let mut banner = [0u8; 4];
        s.read_exact(&mut banner).unwrap();
        assert_eq!(&banner, b"SSH-");
        drop(s);
        route.close();
        std::fs::remove_dir_all(dir).ok();
    }

    /// Live: VNC desktop of a container that only bastion-jump can reach (set `BASTION_GW_VNC`
    /// to `host:port` as seen from the jump host, `BASTION_VNC_PASSWORD`), and a web route's
    /// SOCKS proxy reaching the private `target` container's SSH banner.
    #[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
    #[test]
    fn routes_reach_private_hosts_through_the_gateway() {
        assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
        if std::env::var("BASTION_SSH_TEST").is_err() {
            return eprintln!("SKIPPED routes_reach_private_hosts_through_the_gateway: set BASTION_SSH_TEST=1");
        }
        let dir = std::env::temp_dir().join(format!("bastion-ffi-gwl-{}", Uuid::new_v4()));
        let web = Connection::new("intranet", Protocol::Web, "http://target:2222");
        let wid = web.id.to_string();
        let mut conns = vec![web];
        let vnc_target = std::env::var("BASTION_GW_VNC").ok();
        let mut vid = None;
        if let Some((host, port)) = vnc_target.as_deref().and_then(|t| t.rsplit_once(':')) {
            let mut v = Connection::new("desk", Protocol::Vnc, host);
            v.settings.port = port.parse().ok();
            vid = Some(v.id.to_string());
            conns.push(v);
        }
        let (lib, _) = library_with(&dir, conns);
        let mgr = SessionManager::new(dir.to_string_lossy().into_owned()).unwrap();

        let socks = open(&mgr, &lib, &wid);
        assert!(socks.is_socks());
        let mut s = TcpStream::connect(("127.0.0.1", socks.local_port())).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        s.write_all(&[5, 1, 0]).unwrap();
        let mut reply = [0u8; 2];
        s.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [5, 0]);
        let mut req = vec![5, 1, 0, 3, 6];
        req.extend_from_slice(b"target");
        req.extend_from_slice(&2222u16.to_be_bytes());
        s.write_all(&req).unwrap();
        let mut head = [0u8; 10];
        s.read_exact(&mut head).unwrap();
        assert_eq!(head[1], 0, "SOCKS CONNECT through the gateway succeeded");
        let mut banner = [0u8; 4];
        s.read_exact(&mut banner).unwrap();
        assert_eq!(&banner, b"SSH-");
        socks.close();

        if let Some(vid) = vid {
            let route = open(&mgr, &lib, &vid);
            assert!(!route.is_socks());
            assert!(route.summary().contains("via Jump (127.0.0.1:2223) →"), "{}", route.summary());
            let viewer = crate::vnc::vnc_connect("127.0.0.1".into(), route.local_port(), std::env::var("BASTION_VNC_PASSWORD").ok()).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            while viewer.frame(0).is_none() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            let f = viewer.frame(0).expect("a desktop frame through the gateway");
            assert!(f.width > 0 && f.height > 0);
            viewer.close();
            route.close();
        } else {
            eprintln!("SKIPPED VNC part: set BASTION_GW_VNC");
        }
        std::fs::remove_dir_all(dir).ok();
    }
}
