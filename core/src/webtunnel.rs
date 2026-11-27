//! Web tabs through a saved SSH tunnel (part of the port-forward manager).
//!
//! A web connection can be set to "use tunnel X". Through a dynamic (SOCKS5, `-D`) tunnel the
//! built-in web tab sends every request, DNS included, over `socks5://127.0.0.1:PORT`; through a
//! local (`-L`) tunnel the tab opens `127.0.0.1:PORT` instead of the real address. Each tunnel
//! gets its own data folder so cookies never mix between tunnels or with the app. Nothing here
//! touches the system proxy or the user's own browser profile; the external-browser helpers
//! build arguments for a separate, throw-away profile and never a shell string.
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::{Document, Protocol};
use crate::tunneldefs::{TunnelDef, TunnelSpec};

/// Connection metadata key holding the id of the tunnel a web connection uses.
pub const WEB_TUNNEL_KEY: &str = "WebTunnel";
/// Folder under the app data directory holding one data folder per tunnel.
const DATA_FOLDER: &str = "web-tunnels";
/// How far [`next_free_port`] looks past the wanted port.
const PORT_SEARCH: u16 = 100;

/// How a web tab reaches its site through a tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum WebRoute {
    /// Give the web view this proxy (`socks5://127.0.0.1:PORT`): WKWebView
    /// `proxyConfigurations`, WebView2 `--proxy-server`, wry `proxy_url`. DNS goes through it.
    Proxy { proxy_url: String },
    /// Open the tab at this address instead of the connection's own host and port (`-L`).
    Forward { address: String },
}

/// Everything an app needs to open a web tab through a tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebTunnelPlan {
    pub tunnel_id: Uuid,
    pub tunnel_name: String,
    /// The SSH connection the tunnel must be running over before the tab loads.
    pub via: Uuid,
    pub route: WebRoute,
    /// Per-tunnel web data folder (cookies, cache), owner-only. Windows passes it to WebView2 as
    /// the user-data folder; macOS keeps a non-persistent store per tunnel and may ignore it.
    pub data_dir: PathBuf,
}

/// Copyable settings for other programs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxySettings {
    /// `socks5h://127.0.0.1:PORT`: the `h` makes clients resolve names through the proxy.
    pub url: String,
    pub pac: String,
    pub host: String,
    pub port: u16,
}

/// A saved tunnel as this module sees it, from either store: the library's `tunneldefs` (native
/// apps) or the per-user `tunnel_registry` (Tauri).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: Uuid,
    pub name: String,
    pub via: Uuid,
    /// `None` for a remote (`-R`) tunnel, which can't carry a web tab.
    pub route: Option<WebRoute>,
    /// The SOCKS port, for a dynamic tunnel.
    pub socks_port: Option<u16>,
}

impl From<&TunnelDef> for Candidate {
    fn from(d: &TunnelDef) -> Self {
        let socks_port = match d.spec {
            TunnelSpec::Dynamic { local_port } => Some(local_port),
            _ => None,
        };
        Candidate { id: d.id, name: d.name.clone(), via: d.via, route: route(d), socks_port }
    }
}

impl From<&crate::tunnel_registry::TunnelDef> for Candidate {
    fn from(d: &crate::tunnel_registry::TunnelDef) -> Self {
        use crate::tunnel_registry::TunnelSpec as R;
        let (route, socks_port) = match d.spec {
            R::Socks { bind_port } => (Some(proxy(bind_port)), Some(bind_port)),
            R::Local { bind_port, .. } => (Some(forward(bind_port)), None),
            R::Remote { .. } => (None, None),
        };
        Candidate { id: d.id, name: d.name.clone(), via: d.connection, route, socks_port }
    }
}

fn library_tunnels(doc: &Document) -> Vec<Candidate> {
    doc.tunnels.iter().map(Candidate::from).collect()
}

/// Set (or clear with `None`) the tunnel a web connection's tab goes through, from the library's
/// own tunnels.
pub fn set_web_tunnel(doc: &mut Document, connection: Uuid, tunnel: Option<Uuid>) -> Result<()> {
    let tunnels = library_tunnels(doc);
    set_web_tunnel_from(doc, connection, tunnel, &tunnels)
}

/// [`set_web_tunnel`] choosing from `tunnels` (another store's).
pub fn set_web_tunnel_from(doc: &mut Document, connection: Uuid, tunnel: Option<Uuid>, tunnels: &[Candidate]) -> Result<()> {
    let c = doc.resolve(connection)?;
    if c.connection.protocol != Protocol::Web {
        return Err(CoreError::Invalid(format!("{} is not a web connection.", c.connection.name)));
    }
    if let Some(t) = tunnel {
        let def = tunnels.iter().find(|d| d.id == t).ok_or_else(|| CoreError::NotFound(format!("tunnel {t}")))?;
        if def.route.is_none() {
            return Err(CoreError::Invalid(format!("{} is a remote (-R) tunnel; a web tab needs a SOCKS (-D) or local (-L) tunnel.", def.name)));
        }
    }
    doc.set_metadata(connection, WEB_TUNNEL_KEY, tunnel.map(|t| t.to_string()))
}

/// The tunnel plan for a web connection, or `None` when it goes direct. A tunnel that was deleted
/// is an error, never a silent direct connection.
pub fn plan_for(doc: &Document, connection: Uuid, data_root: &Path) -> Result<Option<WebTunnelPlan>> {
    plan_from(doc, connection, data_root, &library_tunnels(doc))
}

/// [`plan_for`] resolving the tunnel in `tunnels` (another store's).
pub fn plan_from(doc: &Document, connection: Uuid, data_root: &Path, tunnels: &[Candidate]) -> Result<Option<WebTunnelPlan>> {
    let c = doc.resolve(connection)?;
    let Some(raw) = c.connection.metadata.get(WEB_TUNNEL_KEY) else { return Ok(None) };
    let id = Uuid::parse_str(raw).map_err(|_| CoreError::Invalid("The web tunnel setting is damaged; choose the tunnel again.".into()))?;
    let def = tunnels.iter().find(|d| d.id == id).ok_or_else(|| CoreError::NotFound("The tunnel this web connection uses was deleted.".into()))?;
    let route = def.route.clone().ok_or_else(|| CoreError::Invalid(format!("{} is a remote (-R) tunnel; a web tab can't use it.", def.name)))?;
    Ok(Some(WebTunnelPlan { tunnel_id: def.id, tunnel_name: def.name.clone(), via: def.via, route, data_dir: data_dir(data_root, def.id) }))
}

fn proxy(port: u16) -> WebRoute {
    WebRoute::Proxy { proxy_url: format!("socks5://127.0.0.1:{port}") }
}

fn forward(port: u16) -> WebRoute {
    WebRoute::Forward { address: format!("127.0.0.1:{port}") }
}

/// The web route a tunnel offers; `None` for a remote (`-R`) tunnel.
pub fn route(def: &TunnelDef) -> Option<WebRoute> {
    match def.spec {
        TunnelSpec::Dynamic { local_port } => Some(proxy(local_port)),
        TunnelSpec::Local { local_port, .. } => Some(forward(local_port)),
        TunnelSpec::Remote { .. } => None,
    }
}

/// Copyable proxy settings for a SOCKS tunnel; `None` for other kinds.
pub fn proxy_settings(def: &TunnelDef) -> Option<ProxySettings> {
    Candidate::from(def).socks_port.map(socks_settings)
}

/// Copyable settings for the SOCKS proxy on `127.0.0.1:port`.
pub fn socks_settings(port: u16) -> ProxySettings {
    ProxySettings {
        url: format!("socks5h://127.0.0.1:{port}"),
        pac: format!("function FindProxyForURL(url, host) {{ return \"SOCKS5 127.0.0.1:{port}\"; }}"),
        host: "127.0.0.1".into(),
        port,
    }
}

/// Delete data folders of tunnels that aren't in `live` (any store). Only folders named exactly
/// like a tunnel id are touched; returns how many were removed.
pub fn prune_data_except(data_root: &Path, live: &[Uuid]) -> Result<usize> {
    let Ok(rd) = std::fs::read_dir(data_root.join(DATA_FOLDER)) else { return Ok(0) };
    let mut removed = 0;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Ok(id) = Uuid::parse_str(&name) else { continue };
        if name == id.simple().to_string() && !live.contains(&id) {
            remove_dir(&e.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// The tunnel's own web data folder. Derived from the id only, so it can't point anywhere else.
pub fn data_dir(data_root: &Path, tunnel: Uuid) -> PathBuf {
    data_root.join(DATA_FOLDER).join(tunnel.simple().to_string())
}

/// Create the tunnel's data folder owner-only and return it.
pub fn ensure_data_dir(data_root: &Path, tunnel: Uuid) -> Result<PathBuf> {
    let dir = data_dir(data_root, tunnel);
    crate::store::create_private_dir(&dir)?;
    Ok(dir)
}

/// Delete one tunnel's web data (cookies, cache). Missing is fine.
pub fn clear_data(data_root: &Path, tunnel: Uuid) -> Result<()> {
    remove_dir(&data_dir(data_root, tunnel))
}

/// Delete data folders of the library's tunnels that no longer exist.
pub fn prune_data(data_root: &Path, doc: &Document) -> Result<usize> {
    prune_data_except(data_root, &doc.tunnels.iter().map(|t| t.id).collect::<Vec<_>>())
}

fn remove_dir(dir: &Path) -> Result<()> {
    // Never follow a planted link out of the data folder.
    match std::fs::symlink_metadata(dir) {
        Err(_) => Ok(()),
        Ok(m) if m.file_type().is_symlink() => Ok(std::fs::remove_file(dir)?),
        Ok(_) => Ok(std::fs::remove_dir_all(dir)?),
    }
}

/// Whether `127.0.0.1:port` can be listened on right now.
pub fn port_free(port: u16) -> bool {
    port != 0 && TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).is_ok()
}

/// `wanted` when free, else the next free port within a short range above it.
pub fn next_free_port(wanted: u16) -> Option<u16> {
    (0..PORT_SEARCH).filter_map(|i| wanted.checked_add(i)).find(|&p| port_free(p))
}

/// External browsers the fallback can start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserFamily {
    /// Chrome, Edge, Brave, Chromium.
    Chromium,
    Firefox,
}

/// Arguments for a separate browser profile in `profile_dir` that sends everything, DNS
/// included, through the SOCKS tunnel. Passed as an argument vector, never through a shell.
/// Firefox also needs [`firefox_user_js`] written into the profile first.
pub fn browser_args(family: BrowserFamily, port: u16, profile_dir: &Path) -> Vec<String> {
    let dir = profile_dir.to_string_lossy();
    match family {
        BrowserFamily::Chromium => vec![
            format!("--user-data-dir={dir}"),
            format!("--proxy-server=socks5://127.0.0.1:{port}"),
            // Chromium resolves names through a SOCKS5 proxy only when local lookups fail.
            "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".into(),
            // WebRTC would otherwise send UDP around the proxy and reveal the local address.
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".into(),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
        ],
        BrowserFamily::Firefox => vec!["-profile".into(), dir.into_owned(), "-no-remote".into(), "-new-instance".into()],
    }
}

/// `user.js` for a Firefox fallback profile: SOCKS5 with remote DNS, DNS-over-HTTPS off (it would
/// bypass the proxy), WebRTC kept on the proxy.
pub fn firefox_user_js(port: u16) -> String {
    [
        "user_pref(\"network.proxy.type\", 1);".to_string(),
        "user_pref(\"network.proxy.socks\", \"127.0.0.1\");".into(),
        format!("user_pref(\"network.proxy.socks_port\", {port});"),
        "user_pref(\"network.proxy.socks_version\", 5);".into(),
        "user_pref(\"network.proxy.socks_remote_dns\", true);".into(),
        "user_pref(\"network.trr.mode\", 5);".into(),
        "user_pref(\"media.peerconnection.ice.proxy_only\", true);".into(),
        "user_pref(\"browser.shell.checkDefaultBrowser\", false);".into(),
    ]
    .join("\n")
        + "\n"
}
