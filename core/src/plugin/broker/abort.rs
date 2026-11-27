//! Abort bytes (spec section 5, "Abort bytes" and "Stops"; T18.23).
//!
//! A plugin registers a few bytes per stream, so that a running statement is cancelled on the
//! server when its helper stops. The core alone decides whether, where and when they are sent.

use std::collections::BTreeMap;

use super::secret::SecretCheck;
use super::{Failure, StopReason};

/// At most this many abort bytes per registration. A longer registration is refused whole, not
/// cut: a cancel request cut short is a different message.
pub const MAX_ABORT_BYTES: usize = 512;
/// The connect limit for an abort stream, in milliseconds.
pub const ABORT_CONNECT_TIMEOUT_MS: u64 = 5_000;
/// How long the core waits for the server after half-closing an abort stream, in milliseconds.
pub const ABORT_CLOSE_WAIT_MS: u64 = 2_000;

/// One registration: the stream it belongs to, and the destination it will be sent to (the
/// same host, port and route as that stream, which the caller resolves).
#[derive(Clone, PartialEq, Eq)]
pub struct AbortSend {
    pub stream_id: u32,
    pub port: u16,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for AbortSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AbortSend(stream {}, port {}, {} bytes)", self.stream_id, self.port, self.bytes.len())
    }
}

/// The registrations of one helper: at most one per stream, so at most 16.
#[derive(Debug, Default)]
pub struct AbortRegistry {
    by_stream: BTreeMap<u32, AbortSend>,
    spent: bool,
}

impl AbortRegistry {
    pub fn new() -> AbortRegistry {
        AbortRegistry::default()
    }

    /// Register the abort bytes for `stream_id`; before a stop, a new registration replaces
    /// the old one (PostgreSQL needs a new cancel key per query). After a stop it is refused. The stream is open to `port`.
    /// `port_granted` is the grant check for that port; `released` the helper's released secrets.
    pub fn register(&mut self, stream_id: u32, port: u16, port_granted: bool, bytes: &[u8], released: &SecretCheck) -> Result<(), Failure> {
        if self.spent {
            return Err(Failure::Invalid("the helper is stopping".into()));
        }
        if bytes.is_empty() {
            return Err(Failure::Invalid("abort bytes are empty".into()));
        }
        if bytes.len() > MAX_ABORT_BYTES {
            return Err(Failure::Invalid(format!("abort bytes are limited to {MAX_ABORT_BYTES}")));
        }
        if !port_granted {
            return Err(Failure::Denied("that port is not in the plugin's grant".into()));
        }
        released.refuse(bytes)?;
        self.by_stream.insert(stream_id, AbortSend { stream_id, port, bytes: bytes.to_vec() });
        Ok(())
    }

    /// The plugin clears a registration. Refused after a stop: nothing may change then.
    pub fn clear(&mut self, stream_id: u32) -> Result<(), Failure> {
        if self.spent {
            return Err(Failure::Invalid("the helper is stopping".into()));
        }
        self.by_stream.remove(&stream_id);
        Ok(())
    }

    /// The stream closed: its registration is dropped.
    pub fn stream_closed(&mut self, stream_id: u32) {
        self.by_stream.remove(&stream_id);
    }

    pub fn len(&self) -> usize {
        self.by_stream.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_stream.is_empty()
    }

    /// The helper stops for `reason`. Returns what to send: everything registered on an
    /// ordinary stop, nothing on a trust-withdrawing one. Either way the registry is emptied
    /// and nothing more can be registered, so each registration is sent at most once.
    pub fn on_stop(&mut self, reason: StopReason) -> Vec<AbortSend> {
        self.spent = true;
        let all = std::mem::take(&mut self.by_stream);
        if reason.withdraws_trust() {
            Vec::new()
        } else {
            all.into_values().collect()
        }
    }
}
