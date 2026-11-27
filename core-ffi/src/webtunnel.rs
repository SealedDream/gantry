//! Web tabs through a saved tunnel (`bastion_core::webtunnel`): the per-tunnel proxy URL or
//! forward address, the per-tunnel data folder, port checks, copyable proxy settings and the
//! external-browser fallback arguments.
use std::path::Path;

use bastion_core::webtunnel::{self, BrowserFamily, WebRoute};

use crate::{parse_id, FfiError, FfiResult, Library};

#[derive(uniffi::Record)]
pub struct WebTunnelPlanView {
    pub tunnel_id: String,
    pub tunnel_name: String,
    /// SSH connection the tunnel runs over; start it first.
    pub via_id: String,
    /// `socks5://127.0.0.1:PORT` for a SOCKS tunnel (give it to the web view), else `None`.
    pub proxy_url: Option<String>,
    /// `127.0.0.1:PORT` for a local (-L) tunnel (open the tab there), else `None`.
    pub forward_address: Option<String>,
    /// Per-tunnel web data folder, created owner-only.
    pub data_dir: String,
}

#[derive(uniffi::Record)]
pub struct ProxySettingsView {
    pub url: String,
    pub pac: String,
    pub host: String,
    pub port: u16,
}

#[uniffi::export]
impl Library {
    /// Set (or clear with `None`) the tunnel a web connection's tab goes through.
    pub fn set_web_tunnel(&self, connection_id: String, tunnel_id: Option<String>) -> FfiResult<()> {
        let c = parse_id(&connection_id)?;
        let t = tunnel_id.as_deref().map(parse_id).transpose()?;
        self.with_doc(|d| webtunnel::set_web_tunnel(d, c, t))
    }

    /// How to open a web connection: `None` = direct. A deleted tunnel is an error, never direct.
    pub fn web_tunnel_plan(&self, connection_id: String, data_dir: String) -> FfiResult<Option<WebTunnelPlanView>> {
        let c = parse_id(&connection_id)?;
        let root = Path::new(&data_dir);
        let Some(p) = self.with_doc(|d| webtunnel::plan_for(d, c, root))? else { return Ok(None) };
        webtunnel::ensure_data_dir(root, p.tunnel_id)?;
        let (proxy_url, forward_address) = match p.route {
            WebRoute::Proxy { proxy_url } => (Some(proxy_url), None),
            WebRoute::Forward { address } => (None, Some(address)),
        };
        Ok(Some(WebTunnelPlanView {
            tunnel_id: p.tunnel_id.to_string(),
            tunnel_name: p.tunnel_name,
            via_id: p.via.to_string(),
            proxy_url,
            forward_address,
            data_dir: p.data_dir.to_string_lossy().into_owned(),
        }))
    }

    /// "Copy proxy settings" for a SOCKS tunnel; `None` for other kinds.
    pub fn tunnel_proxy_settings(&self, tunnel_id: String) -> FfiResult<Option<ProxySettingsView>> {
        let id = parse_id(&tunnel_id)?;
        self.with_doc(|d| {
            let def = d.tunnels.iter().find(|t| t.id == id).ok_or_else(|| bastion_core::CoreError::NotFound(format!("tunnel {id}")))?;
            Ok(webtunnel::proxy_settings(def).map(|s| ProxySettingsView { url: s.url, pac: s.pac, host: s.host, port: s.port }))
        })
    }

    /// Remove data folders of deleted tunnels; returns how many.
    pub fn prune_web_tunnel_data(&self, data_dir: String) -> FfiResult<u32> {
        let n = self.with_doc(|d| webtunnel::prune_data(Path::new(&data_dir), d))?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }
}

/// Delete one tunnel's web data (cookies, cache).
#[uniffi::export]
pub fn clear_web_tunnel_data(data_dir: String, tunnel_id: String) -> FfiResult<()> {
    Ok(webtunnel::clear_data(Path::new(&data_dir), parse_id(&tunnel_id)?)?)
}

/// Whether `127.0.0.1:port` is free right now.
#[uniffi::export]
pub fn local_port_free(port: u16) -> bool {
    webtunnel::port_free(port)
}

/// `port` when free, else the next free one shortly above it.
#[uniffi::export]
pub fn next_free_local_port(port: u16) -> Option<u16> {
    webtunnel::next_free_port(port)
}

/// Arguments for an external browser (`chromium` or `firefox`) in a separate profile at
/// `profile_dir`, through the SOCKS port. Pass them as an argument list, never via a shell.
/// For Firefox, write `firefox_user_js` to `<profile_dir>/user.js` first.
#[uniffi::export]
pub fn tunnel_browser_args(family: String, port: u16, profile_dir: String) -> FfiResult<Vec<String>> {
    let f = match family.as_str() {
        "chromium" => BrowserFamily::Chromium,
        "firefox" => BrowserFamily::Firefox,
        other => return Err(FfiError::failed(format!("unknown browser family {other}"))),
    };
    Ok(webtunnel::browser_args(f, port, Path::new(&profile_dir)))
}

#[uniffi::export]
pub fn firefox_user_js(port: u16) -> String {
    webtunnel::firefox_user_js(port)
}
