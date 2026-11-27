//! Proxmox VE plugin, pure part (PLUG-PVE-01).
//!
//! - [`model`]: the API records the plugin reads (nodes, guests, status, snapshots, guest-agent
//!   addresses), parsed tolerantly from the `{"data": …}` envelope.
//! - [`api`]: the requests, built as method + origin-form target + form body, ready for the
//!   core's `http` interface (API 1.1). Every path segment that comes from the server or the
//!   user is checked, so a hostile node name cannot change the path.
//! - [`Transport`]: what sends a request. The plugin will implement it with `http.send`; tests
//!   use a mock.
//!
//! Version 1 is read-only by default: a [`api::Client`] refuses every request that changes the
//! server unless it was made with [`api::Access::MayChange`].

pub mod api;
pub mod model;
#[cfg(feature = "plugin")]
pub mod plugin;
#[cfg(feature = "plugin")]
pub mod snapshots;

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

/// One request: method, origin-form target (`/api2/json/...?...`) and a form body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub target: String,
    /// `application/x-www-form-urlencoded` pairs; empty for GET and DELETE.
    pub form: Vec<(String, String)>,
}

impl Request {
    /// The form body, URL-encoded.
    pub fn body(&self) -> String {
        self.form
            .iter()
            .map(|(k, v)| format!("{}={}", api::encode(k), api::encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }
}

/// A response: status and body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Sends one request. The core adds the host, TLS and the API token header.
pub trait Transport {
    fn send(&mut self, req: &Request) -> Result<Response, String>;
}
