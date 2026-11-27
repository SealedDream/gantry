//! Plugin streams: "local" per route, the TLS gate, the pre-TLS preamble, and the stream and
//! connection caps (spec section 5, `network` row and "Caps"; T18.2, T18.24).

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::policy::Policy;

use super::secret::SecretCheck;
use super::Failure;

/// At most this many bytes may be written on a stream before TLS is up, when TLS is required.
pub const MAX_PREAMBLE_BYTES: usize = 512;
/// Concurrent streams per helper.
pub const MAX_STREAMS_PER_HELPER: usize = 16;
/// New connection attempts per helper per minute (attempts count, not only successes).
pub const MAX_CONNECTS_PER_MINUTE: usize = 30;

/// An entry's TLS mode, a core-owned entry property (verify-full by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMode {
    #[default]
    VerifyFull,
    Pinned,
    Off,
}

/// The target the core asks an SSH server to connect to on a routed stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutedTarget {
    Ip(IpAddr),
    /// A host name. The SSH server resolves it, so the core cannot know where it goes.
    Name(String),
}

/// How a stream reaches its server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// A direct socket; `peer` is the connected socket's peer address.
    Direct { peer: IpAddr },
    /// Through a gateway or an SSH tunnel; `target` is what the SSH server is asked to reach.
    Routed { target: RoutedTarget },
    /// Through a SOCKS proxy: never local.
    Socks,
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6 == Ipv6Addr::LOCALHOST || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
    }
}

fn is_unspecified(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4 == Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(v6) => v6 == Ipv6Addr::UNSPECIFIED || v6.to_ipv4_mapped().is_some_and(|v4| v4 == Ipv4Addr::UNSPECIFIED),
    }
}

impl Route {
    /// Whether the destination is local (spec section 5): a loopback peer on a direct stream;
    /// a loopback IP literal as the routed target (the name `localhost` does not count); never
    /// on SOCKS. Private ranges, link-local and the host's own LAN address are not local.
    pub fn is_local(&self) -> bool {
        match self {
            Route::Direct { peer } => is_loopback(*peer),
            Route::Routed { target: RoutedTarget::Ip(ip) } => is_loopback(*ip),
            Route::Routed { target: RoutedTarget::Name(_) } | Route::Socks => false,
        }
    }

    /// `0.0.0.0` and `::` are refused as destinations.
    pub fn check_destination(&self) -> Result<(), Failure> {
        let ip = match self {
            Route::Direct { peer } => Some(*peer),
            Route::Routed { target: RoutedTarget::Ip(ip) } => Some(*ip),
            _ => None,
        };
        if ip.is_some_and(is_unspecified) {
            return Err(Failure::Denied("the unspecified address is not a destination".into()));
        }
        Ok(())
    }

    fn is_direct(&self) -> bool {
        matches!(self, Route::Direct { .. })
    }
}

/// The TLS state of one plugin stream, and every write and `entry-login` checked against it.
#[derive(Debug)]
pub struct StreamGate {
    tls_required: bool,
    tls_up: bool,
    /// Everything written before TLS (at most 512 bytes), so the secret check sees the whole
    /// preamble, not each write alone. Wiped on drop.
    preamble: zeroize::Zeroizing<Vec<u8>>,
}

/// The message the plugin's error shows when the TLS mode stops a stream (A1-C5.6).
pub const TLS_MODE_HINT: &str = "change \"TLS mode\" in the entry's properties";

impl StreamGate {
    /// Open a stream on `route` for an entry with `mode` and its "Allow unencrypted" setting.
    pub fn open(route: &Route, mode: TlsMode, allow_unencrypted: bool, policy: &Policy) -> Result<StreamGate, Failure> {
        route.check_destination()?;
        let local = route.is_local();
        if mode == TlsMode::Off {
            if policy.forbid_plugin_tls_off {
                return Err(Failure::Denied(format!("policy requires TLS on every route; {TLS_MODE_HINT}")));
            }
            if route.is_direct() && !local {
                if policy.forbid_plugin_unencrypted {
                    return Err(Failure::Denied(format!("policy forbids unencrypted plugin connections; {TLS_MODE_HINT}")));
                }
                if !allow_unencrypted {
                    return Err(Failure::Denied(format!("TLS is off and \"Allow unencrypted\" is off; {TLS_MODE_HINT}")));
                }
            }
            // Through a gateway or tunnel with TLS off, the last leg is cleartext (residual).
            return Ok(StreamGate { tls_required: false, tls_up: false, preamble: Default::default() });
        }
        Ok(StreamGate { tls_required: !local, tls_up: false, preamble: Default::default() })
    }

    /// Whether `entry-login` and long writes wait for TLS on this stream.
    pub fn tls_required(&self) -> bool {
        self.tls_required
    }

    /// Record a successful `start-tls` (the core ran it, and the certificate passed the mode).
    pub fn tls_started(&mut self) {
        self.tls_up = true;
    }

    /// A certificate that fails verify-full or the pin fails `start-tls`; there is no
    /// "accept anyway".
    pub fn tls_failed() -> Failure {
        Failure::Denied(format!("the server's certificate did not pass the TLS mode; {TLS_MODE_HINT}"))
    }

    /// Check a write before it is sent. Before TLS, where TLS is required, writes may total
    /// at most 512 bytes, and the whole preamble so far, this write included, may not pass the
    /// secret check: a password split over two writes is caught.
    pub fn check_write(&mut self, data: &[u8], released: &SecretCheck) -> Result<(), Failure> {
        if !self.tls_required || self.tls_up {
            return Ok(());
        }
        let total = self.preamble.len().saturating_add(data.len());
        if total > MAX_PREAMBLE_BYTES {
            return Err(Failure::Denied(format!("more than {MAX_PREAMBLE_BYTES} bytes before TLS; {TLS_MODE_HINT}")));
        }
        let mut whole = zeroize::Zeroizing::new(Vec::with_capacity(total));
        whole.extend_from_slice(&self.preamble);
        whole.extend_from_slice(data);
        released.refuse(&whole)?;
        self.preamble = whole;
        Ok(())
    }

    /// Check `entry-login` against this stream: it waits for TLS where TLS is required.
    /// [`super::grants::HelperGrants::begin_release`] takes this result, so a release cannot
    /// happen without a passed check.
    pub fn check_login(&self) -> Result<(), Failure> {
        if self.tls_required && !self.tls_up {
            return Err(Failure::Denied(format!("the login waits until TLS is up; {TLS_MODE_HINT}")));
        }
        Ok(())
    }
}

/// Per-helper stream and connection caps. Times are in milliseconds on a monotonic clock the
/// caller passes in.
#[derive(Debug, Default)]
pub struct StreamCaps {
    open: usize,
    attempts: VecDeque<u64>,
}

impl StreamCaps {
    pub fn new() -> StreamCaps {
        StreamCaps::default()
    }

    /// Count a connect attempt at `now_ms`, and refuse it over either cap. Refused attempts
    /// count too, but the record never holds more than [`MAX_CONNECTS_PER_MINUTE`] entries, so
    /// a plugin looping on a refused connect cannot grow the core's memory.
    pub fn try_connect(&mut self, now_ms: u64) -> Result<(), Failure> {
        while self.attempts.front().is_some_and(|t| now_ms.saturating_sub(*t) >= 60_000) {
            self.attempts.pop_front();
        }
        if self.attempts.len() >= MAX_CONNECTS_PER_MINUTE {
            // Full: refused, and not recorded, so the record stays bounded.
            return Err(Failure::Invalid(format!("at most {MAX_CONNECTS_PER_MINUTE} new connections a minute")));
        }
        if self.open >= MAX_STREAMS_PER_HELPER {
            // Recorded (the record is not full here), so this counts toward the rate.
            self.attempts.push_back(now_ms);
            return Err(Failure::Invalid(format!("at most {MAX_STREAMS_PER_HELPER} streams at once")));
        }
        self.attempts.push_back(now_ms);
        self.open += 1;
        Ok(())
    }

    /// A connect that failed after it was counted: the attempt stays counted, the stream does not.
    pub fn connect_failed(&mut self) {
        self.open = self.open.saturating_sub(1);
    }

    pub fn closed(&mut self) {
        self.open = self.open.saturating_sub(1);
    }

    pub fn open_streams(&self) -> usize {
        self.open
    }

    /// How many attempts are on record (at most [`MAX_CONNECTS_PER_MINUTE`]).
    pub fn recorded_attempts(&self) -> usize {
        self.attempts.len()
    }
}
