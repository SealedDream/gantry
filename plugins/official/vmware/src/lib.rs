//! VMware plugin, pure part (PLUG-VMW-01): vCenter over REST, a standalone ESXi host over SOAP
//! ([`soap`], design D, `docs/design/VMW-ESXI.md`).
//!
//! - [`model`]: the vSphere Automation REST records the plugin reads (hosts, VMs, power state,
//!   guest identity and interfaces), parsed tolerantly.
//! - [`api`]: the requests, built as method + origin-form target under `/api/vcenter/`, ready for
//!   the core's `http` interface (API 1.1). Every id that comes from the server or the user is
//!   checked, so a hostile id cannot change the path.
//! - [`Transport`]: what sends a request. The plugin implements it with `http.send`; tests use a
//!   mock.
//!
//! Version 1 is read-only by default: a [`api::Client`] refuses every request that changes the
//! server unless it was made with [`api::Access::MayChange`]. The login is HTTP Basic, added by
//! the core on every request (manifest `[http] auth`); the plugin holds no session token.

pub mod api;
pub mod model;
pub mod soap;
pub mod xml;

/// The mock ESXi host, for the component tests (`plugin.rs`).
#[cfg(all(test, feature = "plugin"))]
#[path = "../tests/support/esxi.rs"]
mod test_esxi;
#[cfg(feature = "plugin")]
pub mod plugin;

pub use api::{Access, Client, Error};

/// HTTP method, the subset the plugin uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Post,
    Delete,
}

impl Method {
    /// True when the request can change the server.
    pub fn changes(self) -> bool {
        !matches!(self, Method::Get)
    }
}

/// One request: method and origin-form target (`/api/vcenter/...?...`). vCenter power actions
/// take their verb in the query; only taking a snapshot sends a JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub target: String,
    pub body: Vec<u8>,
    /// Whether it changes the server. REST: the method says; SOAP: every call is a POST, so the
    /// call says (reads are not changes).
    pub changes: bool,
}

/// A response: status and body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Sends one request. The core adds the host, TLS and the login header.
pub trait Transport {
    fn send(&mut self, req: &Request) -> Result<Response, String>;
}
