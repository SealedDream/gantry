//! Kubernetes plugin, pure part.
//!
//! - [`model`]: the Kubernetes API records the plugin reads (pods, deployments, services,
//!   nodes, namespaces, pod metrics), parsed tolerantly, and their display helpers.
//! - [`api`]: the requests, as method + origin-form target, ready for the core's `http`
//!   interface. Every name from the server or the user is checked against the Kubernetes name
//!   rules first, so a hostile name cannot change the path.
//!
//! Read-only by default: a request that changes the cluster is refused unless the caller passes
//! [`api::Access::MayChange`], which the plugin does only when the entry's "Allow changes" field
//! is on and the user confirmed the action. The login is a bearer token the core adds.

pub mod api;
pub mod model;

#[cfg(feature = "plugin")]
pub mod plugin;

pub use api::{Access, Error};

/// HTTP method, the subset the plugin uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Delete,
    Patch,
}

impl Method {
    pub fn changes(self) -> bool {
        !matches!(self, Method::Get)
    }
}

/// One request: method, origin-form target and an optional JSON merge-patch body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub target: String,
    pub body: Vec<u8>,
}

impl Request {
    pub fn content_type(&self) -> Option<&'static str> {
        match self.method {
            Method::Patch => Some("application/merge-patch+json"),
            _ => None,
        }
    }
}

/// A response: status and body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}
