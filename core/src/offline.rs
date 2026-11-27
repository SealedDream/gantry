//! Offline guarantee. Bastion must work with no internet: optional online features (update
//! check, codec download) fail fast and quietly, and nothing they do blocks a connect.
//!
//! Offline mode (`BASTION_OFFLINE=1`, or [`set_offline`]) refuses every destination that is not
//! on this machine or the LAN before any packet is sent, with [`CoreError::Offline`]. The test
//! run with internet blocked (`scripts/offline-test.sh`) uses it so that only LAN test servers
//! can be reached; frontends show `Offline` errors from optional features as nothing at all.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::error::{CoreError, Result};

pub const ENV: &str = "BASTION_OFFLINE";

/// TCP connect budget for optional online features: an unreachable network fails in this
/// time instead of the OS default (often over a minute).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Name-lookup budget for optional online features. The OS resolver has no timeout of its own;
/// with no network and an unreachable DNS server it can block for 10-20 s or more, which the
/// connect timeout does not cover.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Run `work` on its own thread and give up after `timeout` with `TimedOut`. The thread is left to
/// finish on its own (a blocked system lookup cannot be cancelled); its result is dropped.
pub fn bounded<T: Send + 'static>(timeout: Duration, work: impl FnOnce() -> std::io::Result<T> + Send + 'static) -> std::io::Result<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new().name("bounded-lookup".into()).spawn(move || {
        let _ = tx.send(work());
    })?;
    rx.recv_timeout(timeout).unwrap_or_else(|_| Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "name lookup timed out")))
}

/// Resolve `host:port` within [`RESOLVE_TIMEOUT`].
pub fn resolve(netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
    let netloc = netloc.to_owned();
    bounded(RESOLVE_TIMEOUT, move || netloc.to_socket_addrs().map(Iterator::collect))
}

static FORCED: AtomicBool = AtomicBool::new(false);

pub fn set_offline(on: bool) {
    FORCED.store(on, Ordering::Relaxed);
}

pub fn is_offline() -> bool {
    FORCED.load(Ordering::Relaxed) || std::env::var(ENV).is_ok_and(|v| v == "1")
}

/// Loopback, private, link-local and shared (CGNAT) addresses.
pub fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback() || v.is_private() || v.is_link_local() || (v.octets()[0] == 100 && (v.octets()[1] & 0xC0) == 64),
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return is_lan(IpAddr::V4(v4));
            }
            let s = v.segments()[0];
            v.is_loopback() || (s & 0xFE00) == 0xFC00 || (s & 0xFFC0) == 0xFE80
        }
    }
}

/// In offline mode, refuse `host` unless every address it resolves to is on the LAN. Names go
/// to the system resolver only (a LAN DNS server or the hosts file); a failure is `Offline`.
pub fn check_host(host: &str, port: u16) -> Result<()> {
    if !is_offline() {
        return Ok(());
    }
    let refuse = || CoreError::Offline(format!("{host} is not on this network"));
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if is_lan(ip) { Ok(()) } else { Err(refuse()) };
    }
    let netloc = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let addrs: Vec<IpAddr> = resolve(&netloc).map_err(|_| refuse())?.into_iter().map(|a| a.ip()).collect();
    if !addrs.is_empty() && addrs.iter().all(|ip| is_lan(*ip)) {
        Ok(())
    } else {
        Err(refuse())
    }
}

/// [`check_host`] for an `http(s)://host[:port]/…` URL.
pub fn check_url(url: &str) -> Result<()> {
    if !is_offline() {
        return Ok(());
    }
    let (scheme, rest) = url.split_once("://").ok_or_else(|| CoreError::Invalid(format!("not a URL: {url}")))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let default = if scheme.eq_ignore_ascii_case("http") { 80 } else { 443 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || authority.starts_with('[') => match p.parse() {
            Ok(p) => (h, p),
            Err(_) => (authority, default),
        },
        _ => (authority, default),
    };
    check_host(host, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_gives_up_on_a_slow_lookup() {
        let start = std::time::Instant::now();
        let r = bounded(Duration::from_millis(200), || {
            std::thread::sleep(Duration::from_secs(5));
            Ok(())
        });
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn resolve_returns_ip_literals() {
        assert_eq!(resolve("127.0.0.1:443").unwrap(), vec!["127.0.0.1:443".parse::<SocketAddr>().unwrap()]);
    }

    /// An unroutable host fails within the connect + lookup budgets, never the OS default.
    #[test]
    fn unroutable_update_host_fails_fast() {
        let agent = ureq::AgentBuilder::new().timeout_connect(CONNECT_TIMEOUT).resolver(resolve).build();
        let start = std::time::Instant::now();
        assert!(agent.get("http://10.255.255.1:9/").call().is_err());
        assert!(start.elapsed() < CONNECT_TIMEOUT + RESOLVE_TIMEOUT + Duration::from_secs(2), "{:?}", start.elapsed());
    }

    #[test]
    fn lan_ranges() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.20", "169.254.1.1", "100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:192.168.0.1"] {
            assert!(is_lan(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "100.128.0.1", "2001:4860::8888", "::ffff:8.8.8.8"] {
            assert!(!is_lan(ip.parse().unwrap()), "{ip}");
        }
    }
}
