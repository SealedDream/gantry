//! Wake-on-LAN: build and send a magic packet, then optionally wait for the host to answer.
//!
//! A magic packet is 6 bytes of `FF` followed by the target MAC 16 times (102 bytes), plus an
//! optional 6-byte SecureOn password (108 bytes). It goes out as one UDP broadcast datagram.
//!
//! Rules: nothing is ever sent unless a user action calls [`send`] or [`wake_and_wait`]; there is
//! no background work and no state, so the feature costs nothing when unused. Packets only go to
//! the limited broadcast (`255.255.255.255`) or a directed broadcast on a private/link-local
//! IPv4 network: a public destination is refused before any socket is opened. Every input is
//! validated when parsed.
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::error::{CoreError, Result};

/// Discard port, the usual Wake-on-LAN port (7 is the other common one).
pub const DEFAULT_PORT: u16 = 9;
/// How long "wake before connect" waits for the host by default.
pub const DEFAULT_WAIT_SECS: u32 = 60;
/// Upper bound for the wait, so a host that never wakes cannot hold a connect forever.
pub const MAX_WAIT_SECS: u32 = 300;
/// Copies of the packet sent per wake (UDP may drop one); sent back to back.
const COPIES: usize = 3;
/// Pause between two TCP checks while waiting.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Budget of one TCP check.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const SYNC_LEN: usize = 6;
const MAC_REPEATS: usize = 16;

/// A 6-byte hardware address.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// Parses `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff` or `aabbccddeeff`.
    /// Refuses all-zero, broadcast and multicast addresses, which no network card has.
    pub fn parse(text: &str) -> Result<Mac> {
        let bytes = parse_six_bytes(text)
            .ok_or_else(|| CoreError::Invalid(format!("MAC address: `{}` is not six hex bytes such as 00:11:22:33:44:55.", text.trim())))?;
        if bytes == [0; 6] || bytes == [0xFF; 6] || bytes[0] & 1 == 1 {
            return Err(CoreError::Invalid("MAC address: use the network card's own address (not zero, broadcast or multicast).".into()));
        }
        Ok(Mac(bytes))
    }
}

impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

impl std::fmt::Debug for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mac({self})")
    }
}

/// SecureOn password: 6 bytes, written like a MAC. Never printed by `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecureOn(pub [u8; 6]);

impl SecureOn {
    pub fn parse(text: &str) -> Result<SecureOn> {
        parse_six_bytes(text).map(SecureOn).ok_or_else(|| CoreError::Invalid("SecureOn password: six hex bytes such as 01:23:45:67:89:ab.".into()))
    }
}

impl std::fmt::Debug for SecureOn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecureOn(<redacted>)")
    }
}

fn is_sep(c: char) -> bool {
    matches!(c, ':' | '-' | '.')
}

fn parse_six_bytes(text: &str) -> Option<[u8; 6]> {
    let text = text.trim();
    let hex: String = text.chars().filter(|c| !is_sep(*c)).collect();
    let groups: Vec<usize> = text.split(is_sep).map(str::len).collect();
    let layout_ok = matches!(groups.as_slice(), [12] | [4, 4, 4] | [2, 2, 2, 2, 2, 2]);
    if !layout_ok || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Where the packet goes: `255.255.255.255`, a LAN broadcast address such as `192.168.1.255`,
/// or a LAN subnet in CIDR form (`192.168.1.0/24`), which becomes its directed broadcast.
pub fn parse_broadcast(text: &str) -> Result<Ipv4Addr> {
    let text = text.trim();
    let bad = || CoreError::Invalid(format!("Broadcast address: `{text}` is not an IPv4 address or subnet such as 192.168.1.255 or 192.168.1.0/24."));
    let addr = match text.split_once('/') {
        Some((ip, bits)) => {
            let ip: Ipv4Addr = ip.parse().map_err(|_| bad())?;
            let bits: u32 = bits.parse().ok().filter(|b| (8..=30).contains(b)).ok_or_else(bad)?;
            Ipv4Addr::from(u32::from(ip) | (u32::MAX >> bits))
        }
        None => text.parse().map_err(|_| bad())?,
    };
    check_lan_broadcast(addr)?;
    Ok(addr)
}

/// LAN-only rule: the limited broadcast, or a private / link-local address.
fn check_lan_broadcast(addr: Ipv4Addr) -> Result<()> {
    if addr.is_broadcast() || addr.is_private() || addr.is_link_local() {
        Ok(())
    } else {
        Err(CoreError::Invalid(format!("Broadcast address: {addr} is not on a local network; Wake-on-LAN only sends on the LAN.")))
    }
}

/// UDP port, 1 to 65535.
pub fn parse_port(text: &str) -> Result<u16> {
    text.trim().parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| CoreError::Invalid("Wake-on-LAN port must be a number from 1 to 65535.".into()))
}

/// Seconds to wait for the host after waking it, 1 to [`MAX_WAIT_SECS`].
pub fn parse_wait_secs(text: &str) -> Result<u32> {
    text.trim()
        .parse::<u32>()
        .ok()
        .filter(|s| (1..=MAX_WAIT_SECS).contains(s))
        .ok_or_else(|| CoreError::Invalid(format!("Wake wait must be 1 to {MAX_WAIT_SECS} seconds.")))
}

/// Everything needed to wake one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WolTarget {
    pub mac: Mac,
    pub broadcast: Ipv4Addr,
    pub port: u16,
    pub secureon: Option<SecureOn>,
}

impl WolTarget {
    /// Limited broadcast on the default port, no password.
    pub fn new(mac: Mac) -> WolTarget {
        WolTarget { mac, broadcast: Ipv4Addr::BROADCAST, port: DEFAULT_PORT, secureon: None }
    }
}

/// The magic packet for `target` (102 bytes, or 108 with a SecureOn password).
pub fn magic_packet(target: &WolTarget) -> Vec<u8> {
    let mut p = Vec::with_capacity(SYNC_LEN + 6 * MAC_REPEATS + 6);
    p.extend_from_slice(&[0xFF; SYNC_LEN]);
    for _ in 0..MAC_REPEATS {
        p.extend_from_slice(&target.mac.0);
    }
    if let Some(pw) = target.secureon {
        p.extend_from_slice(&pw.0);
    }
    p
}

/// Sends the magic packet. Called only from an explicit user action.
pub fn send(target: &WolTarget) -> Result<()> {
    check_lan_broadcast(target.broadcast)?;
    if target.port == 0 {
        return Err(CoreError::Invalid("Wake-on-LAN port must be a number from 1 to 65535.".into()));
    }
    let io = |e: std::io::Error| CoreError::Invalid(format!("Wake-on-LAN: could not send the packet ({e})."));
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).map_err(io)?;
    socket.set_broadcast(true).map_err(io)?;
    let packet = magic_packet(target);
    let dest = SocketAddrV4::new(target.broadcast, target.port);
    for _ in 0..COPIES {
        socket.send_to(&packet, dest).map_err(io)?;
    }
    Ok(())
}

/// Result of [`wake_and_wait`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeOutcome {
    /// The host accepted a TCP connection on the port after this long.
    Up(Duration),
    /// The wait ran out; the caller may still try to connect.
    TimedOut,
    /// `cancel` was set.
    Cancelled,
}

/// Sends the packet, then checks `host:port` over TCP every 2 s until it answers, `wait` passes
/// (clamped to [`MAX_WAIT_SECS`]) or `cancel` is set. Blocking: run it off the UI thread.
/// The host must be on the LAN (offline-mode rules apply too).
pub fn wake_and_wait(target: &WolTarget, host: &str, port: u16, wait: Duration, cancel: &AtomicBool) -> Result<WakeOutcome> {
    let addrs = lan_addrs(host, port)?;
    send(target)?;
    poll_until_up(&addrs, wait, cancel)
}

fn poll_until_up(addrs: &[SocketAddr], wait: Duration, cancel: &AtomicBool) -> Result<WakeOutcome> {
    let wait = wait.min(Duration::from_secs(u64::from(MAX_WAIT_SECS)));
    let start = Instant::now();
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(WakeOutcome::Cancelled);
        }
        let budget = PROBE_TIMEOUT.min(wait).max(Duration::from_millis(1));
        if addrs.iter().any(|a| TcpStream::connect_timeout(a, budget).is_ok()) {
            return Ok(WakeOutcome::Up(start.elapsed()));
        }
        let left = wait.saturating_sub(start.elapsed());
        if left.is_zero() {
            return Ok(WakeOutcome::TimedOut);
        }
        sleep_cancellable(POLL_INTERVAL.min(left), cancel);
    }
}

fn sleep_cancellable(d: Duration, cancel: &AtomicBool) {
    let end = Instant::now() + d;
    while !cancel.load(Ordering::Relaxed) {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        std::thread::sleep(left.min(Duration::from_millis(100)));
    }
}

/// Resolves `host` and keeps only LAN addresses; none is an error (a host on the internet
/// cannot be woken, and polling it would only send traffic off the LAN).
fn lan_addrs(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    crate::offline::check_host(host, port)?;
    let bare = host.trim().trim_start_matches('[').trim_end_matches(']');
    let all: Vec<SocketAddr> = match bare.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => (bare, port).to_socket_addrs().map_err(|_| CoreError::Invalid(format!("Wake-on-LAN: cannot find {bare} on this network.")))?.collect(),
    };
    let lan: Vec<SocketAddr> = all.into_iter().filter(|a| crate::offline::is_lan(a.ip())).collect();
    if lan.is_empty() {
        return Err(CoreError::Invalid(format!("Wake-on-LAN: {bare} is not on a local network.")));
    }
    Ok(lan)
}

/// What waking one connection needs, from its effective (own or inherited) settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakePlan {
    pub target: WolTarget,
    /// The connection's host and port, checked over TCP after the packet goes out.
    pub host: String,
    pub port: u16,
    pub wait: Duration,
    /// "Wake before connect" is on.
    pub before_connect: bool,
}

/// The wake plan for connection `id`, or `None` when no MAC is set (no Wake action then).
/// A stored broadcast, port, password or wait that no longer parses (hand-edited file) is an
/// error rather than a silent fallback, so a packet never goes somewhere the user did not set.
pub fn plan_for(doc: &crate::model::Document, id: uuid::Uuid) -> Result<Option<WakePlan>> {
    let r = doc.resolve(id)?;
    let s = &r.effective;
    let Some(mac) = s.wol_mac.as_deref() else { return Ok(None) };
    let mac = Mac::parse(mac)?;
    let broadcast = s.wol_broadcast.as_deref().map(parse_broadcast).transpose()?.unwrap_or(Ipv4Addr::BROADCAST);
    let secureon = s.wol_secureon.as_deref().map(SecureOn::parse).transpose()?;
    let port = s.wol_port.unwrap_or(DEFAULT_PORT);
    let wait = s.wol_wait_secs.unwrap_or(DEFAULT_WAIT_SECS).clamp(1, MAX_WAIT_SECS);
    let check_port = s.port.or(r.connection.protocol.default_port()).unwrap_or(22);
    Ok(Some(WakePlan {
        target: WolTarget { mac, broadcast, port, secureon },
        host: r.connection.host.clone(),
        port: check_port,
        wait: Duration::from_secs(u64::from(wait)),
        before_connect: s.wol_before_connect.unwrap_or(false),
    }))
}

/// Wake action: send the packet for connection `id` now. Errors when it has no MAC.
pub fn wake_connection(doc: &crate::model::Document, id: uuid::Uuid) -> Result<()> {
    let plan = plan_for(doc, id)?.ok_or_else(|| CoreError::Invalid("Wake-on-LAN: set the host's MAC address first.".into()))?;
    send(&plan.target)
}

/// Before a connect: when "Wake before connect" is on, wake the host and wait for it.
/// Returns `None` when there is nothing to do (no MAC or the option off), so the connect
/// path costs one settings lookup when the feature is unused.
pub fn wake_before_connect(doc: &crate::model::Document, id: uuid::Uuid, cancel: &AtomicBool) -> Result<Option<WakeOutcome>> {
    match plan_for(doc, id)? {
        Some(p) if p.before_connect => wake_and_wait(&p.target, &p.host, p.port, p.wait, cancel).map(Some),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn mac() -> Mac {
        Mac::parse("00:11:22:33:44:55").unwrap()
    }

    #[test]
    fn parses_mac_forms() {
        for t in ["00:11:22:33:44:55", "00-11-22-33-44-55", "0011.2233.4455", "001122334455", " 00:11:22:33:44:55 ", "00:11:22:33:44:5F"] {
            assert!(Mac::parse(t).is_ok(), "{t}");
        }
        assert_eq!(Mac::parse("00-11-22-33-44-55").unwrap(), mac());
        assert_eq!(mac().to_string(), "00:11:22:33:44:55");
    }

    #[test]
    fn refuses_bad_macs() {
        for t in ["", "00:11:22:33:44", "00:11:22:33:44:55:66", "zz:11:22:33:44:55", "00:11:22:33:4455", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "0:11:22:33:44:555"] {
            assert!(Mac::parse(t).is_err(), "{t}");
        }
    }

    #[test]
    fn packet_layout_is_6_ff_then_16_macs() {
        let p = magic_packet(&WolTarget::new(mac()));
        assert_eq!(p.len(), 102);
        assert_eq!(&p[..6], &[0xFF; 6]);
        for chunk in p[6..].chunks(6) {
            assert_eq!(chunk, &mac().0);
        }
    }

    #[test]
    fn secureon_is_appended_and_redacted() {
        let pw = SecureOn::parse("01:23:45:67:89:ab").unwrap();
        let p = magic_packet(&WolTarget { secureon: Some(pw), ..WolTarget::new(mac()) });
        assert_eq!(p.len(), 108);
        assert_eq!(&p[102..], &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);
        assert!(!format!("{pw:?}").contains("89"));
        assert!(SecureOn::parse("0123").is_err());
    }

    #[test]
    fn broadcast_is_lan_only() {
        assert_eq!(parse_broadcast("255.255.255.255").unwrap(), Ipv4Addr::BROADCAST);
        assert_eq!(parse_broadcast("192.168.1.255").unwrap(), Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(parse_broadcast("192.168.1.7/24").unwrap(), Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(parse_broadcast("10.0.0.0/8").unwrap(), Ipv4Addr::new(10, 255, 255, 255));
        assert_eq!(parse_broadcast("172.16.4.0/22").unwrap(), Ipv4Addr::new(172, 16, 7, 255));
        for t in ["8.8.8.255", "1.2.3.0/24", "192.168.1.0/31", "192.168.1.0/4", "fe80::1", "nope", ""] {
            assert!(parse_broadcast(t).is_err(), "{t}");
        }
    }

    #[test]
    fn ports_and_waits_are_bounded() {
        assert_eq!(parse_port("9").unwrap(), 9);
        assert!(parse_port("0").is_err() && parse_port("70000").is_err() && parse_port("x").is_err());
        assert_eq!(parse_wait_secs("60").unwrap(), 60);
        assert!(parse_wait_secs("0").is_err() && parse_wait_secs("301").is_err());
    }

    #[test]
    fn send_refuses_public_broadcast_before_opening_a_socket() {
        let t = WolTarget { broadcast: Ipv4Addr::new(8, 8, 8, 8), ..WolTarget::new(mac()) };
        assert!(send(&t).unwrap_err().to_string().contains("local network"));
    }

    #[test]
    fn packet_bytes_arrive_intact_over_udp() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = rx.local_addr().unwrap().port();
        let t = WolTarget { port, ..WolTarget::new(mac()) };
        UdpSocket::bind("127.0.0.1:0").unwrap().send_to(&magic_packet(&t), ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 200];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], magic_packet(&t).as_slice());
    }

    #[test]
    fn poll_sees_a_listening_host() {
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = up.local_addr().unwrap();
        let o = poll_until_up(&[addr], Duration::from_secs(5), &AtomicBool::new(false)).unwrap();
        assert!(matches!(o, WakeOutcome::Up(_)));
    }

    #[test]
    fn poll_times_out_and_cancels() {
        let addr = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap(); // closed on drop
        let start = Instant::now();
        assert_eq!(poll_until_up(&[addr], Duration::from_millis(300), &AtomicBool::new(false)).unwrap(), WakeOutcome::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(3));
        assert_eq!(poll_until_up(&[addr], Duration::from_secs(60), &AtomicBool::new(true)).unwrap(), WakeOutcome::Cancelled);
    }

    fn doc_with(settings: crate::model::Settings, folder: crate::model::Settings) -> (crate::model::Document, uuid::Uuid) {
        use crate::model::{Connection, Document, Folder, Node, Protocol};
        let mut c = Connection::new("pc", Protocol::Rdp, "192.168.1.20");
        c.settings = settings;
        let id = c.id;
        let fid = uuid::Uuid::new_v4();
        let f = Folder { id: fid, name: "Office".into(), color: None, defaults: folder, children: vec![], dynamic_task_id: None, extra: Default::default() };
        let mut doc = Document::new("t");
        doc.insert(None, Node::Folder(f)).unwrap();
        doc.insert(Some(fid), Node::Connection(c)).unwrap();
        (doc, id)
    }

    #[test]
    fn plan_inherits_from_folder_and_uses_defaults() {
        use crate::model::Settings;
        let own = Settings { wol_mac: Some("00:11:22:33:44:55".into()), ..Settings::default() };
        let folder = Settings { wol_broadcast: Some("192.168.1.0/24".into()), wol_before_connect: Some(true), ..Settings::default() };
        let (doc, id) = doc_with(own, folder);
        let p = plan_for(&doc, id).unwrap().unwrap();
        assert_eq!(p.target.broadcast, Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(p.target.port, DEFAULT_PORT);
        assert_eq!((p.host.as_str(), p.port, p.before_connect), ("192.168.1.20", 3389, true));
        assert_eq!(p.wait, Duration::from_secs(u64::from(DEFAULT_WAIT_SECS)));
    }

    #[test]
    fn no_mac_means_no_plan_and_no_send() {
        let (doc, id) = doc_with(Default::default(), Default::default());
        assert!(plan_for(&doc, id).unwrap().is_none());
        assert!(wake_before_connect(&doc, id, &AtomicBool::new(false)).unwrap().is_none());
        assert!(wake_connection(&doc, id).unwrap_err().to_string().contains("MAC"));
    }

    #[test]
    fn hand_edited_public_broadcast_is_refused() {
        use crate::model::Settings;
        let own = Settings { wol_mac: Some("00:11:22:33:44:55".into()), wol_broadcast: Some("8.8.8.255".into()), ..Settings::default() };
        let (doc, id) = doc_with(own, Default::default());
        assert!(plan_for(&doc, id).is_err());
    }

    #[test]
    fn wait_refuses_hosts_off_the_lan() {
        let e = wake_and_wait(&WolTarget::new(mac()), "8.8.8.8", 22, Duration::from_secs(1), &AtomicBool::new(false)).unwrap_err();
        // The refusal is the contract, not its wording: the LAN check says `Invalid`, and under
        // `BASTION_OFFLINE=1` the earlier offline gate says `Offline` (Codex T05).
        assert!(matches!(e, crate::CoreError::Invalid(_) | crate::CoreError::Offline(_)), "{e:?}");
    }
}
