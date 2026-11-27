//! A plugin asks the app to open a built-in connection (plugin API 1.2;
//! `docs/specs/plugins-amendment-3.md`, PLUG-OPEN-00 / PLUG-OPEN-01).
//!
//! Pure decisions only: the host syntax (note section 5, step 2), the address classes (step 3),
//! the loopback exception, the set of addresses the entry's server reported (step 4), the
//! user-action stamp and the rate limit (section 4), and the audit escaping (section 8). The
//! dispatch in `host/view.rs` wires them to the plugin and the app.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use serde_json::Value as Json;

use super::Failure;

/// A request is allowed only this soon after a user action (section 4).
pub const STAMP_WINDOW: Duration = Duration::from_secs(10);
/// Requests per helper per minute, refused ones included (section 4).
pub const MAX_PER_MINUTE: usize = 10;
/// How long a reported address counts (section 5, step 4).
pub const REPORTED_TTL: Duration = Duration::from_secs(30 * 60);
/// Reported addresses kept per helper; the oldest go first.
pub const MAX_REPORTED: usize = 4_096;
/// `[open] address_fields` entries, and fields per entry.
pub const MAX_ADDRESS_FIELDS: usize = 16;
pub const MAX_FIELDS_PER_PATH: usize = 8;
/// The label: characters, and audit bytes for any plugin value.
pub const MAX_LABEL_CHARS: usize = 128;
pub const MAX_AUDIT_VALUE_BYTES: usize = 256;
const MAX_NAME_BYTES: usize = 253;
const MAX_PATTERN_BYTES: usize = 256;
const MAX_FIELD_SEGMENTS: usize = 16;

/// The protocols a plugin may ask for. Fixed by the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Ssh,
    Rdp,
    Vnc,
}

impl Protocol {
    pub fn parse(s: &str) -> Option<Protocol> {
        match s {
            "ssh" => Some(Protocol::Ssh),
            "rdp" => Some(Protocol::Rdp),
            "vnc" => Some(Protocol::Vnc),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Ssh => "ssh",
            Protocol::Rdp => "rdp",
            Protocol::Vnc => "vnc",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Protocol::Ssh => 22,
            Protocol::Rdp => 3389,
            Protocol::Vnc => 5900,
        }
    }
}

/// One `[open] address_fields` entry: responses from paths matching `path` (a `*` is one
/// segment) carry addresses at the JSON paths in `fields` (`a.b[].c`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressField {
    pub path: String,
    pub fields: Vec<String>,
}

/// The manifest's `[open]` table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpenSpec {
    pub address_fields: Vec<AddressField>,
}

/// A path pattern: absolute, printable ASCII, no query, no percent-encoding, no dot segments,
/// no empty segment; `*` only as a whole segment.
pub fn valid_path_pattern(p: &str) -> bool {
    if p.len() > MAX_PATTERN_BYTES || !p.starts_with('/') || p.len() < 2 {
        return false;
    }
    p[1..].split('/').all(|seg| {
        !seg.is_empty()
            && seg != "."
            && seg != ".."
            && (seg == "*" || seg.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.~:@!$&'()+,;=".contains(&b)))
    })
}

/// Whether a request path (without its query) matches a pattern, segment by segment.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    let (Some(p), Some(q)) = (pattern.strip_prefix('/'), path.strip_prefix('/')) else { return false };
    let (p, q): (Vec<&str>, Vec<&str>) = (p.split('/').collect(), q.split('/').collect());
    p.len() == q.len() && p.iter().zip(&q).all(|(a, b)| (*a == "*" && !b.is_empty()) || a == b)
}

/// A JSON field path: `key` segments joined by `.`, each optionally ending in `[]`.
pub fn valid_field_path(f: &str) -> bool {
    let segs: Vec<&str> = f.split('.').collect();
    !f.is_empty()
        && f.len() <= MAX_PATTERN_BYTES
        && segs.len() <= MAX_FIELD_SEGMENTS
        && segs.iter().all(|s| {
            let key = s.strip_suffix("[]").unwrap_or(s);
            !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// The string values at a field path in a parsed JSON document.
fn values_at<'a>(doc: &'a Json, path: &str, out: &mut Vec<&'a str>) {
    let mut current = vec![doc];
    for seg in path.split('.') {
        let (key, many) = match seg.strip_suffix("[]") {
            Some(k) => (k, true),
            None => (seg, false),
        };
        let mut next = Vec::new();
        for v in current {
            let Some(child) = v.get(key) else { continue };
            if many {
                if let Json::Array(items) = child {
                    next.extend(items.iter());
                }
            } else {
                next.push(child);
            }
        }
        current = next;
    }
    out.extend(current.into_iter().filter_map(Json::as_str));
}

/// A host that passed the syntax check, in canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    /// Lower case, without a trailing dot.
    Name(String),
}

impl Host {
    /// The form shown to the user, stored in the reported set and audited.
    pub fn canonical(&self) -> String {
        match self {
            Host::V4(ip) => ip.to_string(),
            Host::V6(ip) => ip.to_string(),
            Host::Name(n) => n.clone(),
        }
    }
}

fn denied(why: &str) -> Failure {
    Failure::Denied(why.into())
}

/// A canonical dotted-decimal IPv4 literal: four parts 0-255, no leading zeros.
fn canonical_v4(s: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        octets[i] = p.parse().ok()?;
    }
    Some(Ipv4Addr::from(octets))
}

/// Looks like a number the IPv4 parsers of some libraries accept (`127`, `017`, `0x7f`).
fn numeric_label(l: &str) -> bool {
    l.bytes().all(|b| b.is_ascii_digit()) || (l.len() > 2 && l.starts_with("0x") && l[2..].bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Section 5, step 2: the host syntax. Non-canonical IPv4 forms are refused, not normalised.
pub fn parse_host(s: &str) -> Result<Host, Failure> {
    if s.is_empty() || s.len() > MAX_NAME_BYTES + 1 {
        return Err(denied("the host is empty or too long"));
    }
    if !s.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(denied("the host holds a character that is not allowed"));
    }
    if s.contains(':') {
        if s.contains(['[', ']', '%', '/', '@']) {
            return Err(denied("the host holds a character that is not allowed"));
        }
        return s.parse::<Ipv6Addr>().map(Host::V6).map_err(|_| denied("the host is not a valid IPv6 address"));
    }
    if s.bytes().all(|b| b.is_ascii_digit() || b == b'.') && s.contains('.') && s.split('.').count() == 4 && !s.ends_with('.') {
        return canonical_v4(s).map(Host::V4).ok_or_else(|| denied("the host is not a canonical IPv4 address"));
    }
    let name = s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(denied("the host is empty or too long"));
    }
    let labels: Vec<&str> = name.split('.').collect();
    let ldh = |l: &&str| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if !labels.iter().all(ldh) {
        return Err(denied("the host is not a valid name"));
    }
    if labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit())) || labels.iter().all(|l| numeric_label(l)) {
        return Err(denied("the host is not a canonical IPv4 address"));
    }
    Ok(Host::Name(name))
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// The label: one line of printable text, at most 128 characters, no bidi controls; the same
/// rules a library entry name meets.
pub fn check_label(s: &str) -> Result<(), Failure> {
    let n = s.chars().count();
    if n == 0 || n > MAX_LABEL_CHARS || s.trim() != s {
        return Err(denied("the label is empty, too long or has spaces at its ends"));
    }
    if s.chars().any(|c| c.is_control() || is_bidi_control(c) || c == '\u{2028}' || c == '\u{2029}') {
        return Err(denied("the label holds a character that is not allowed"));
    }
    Ok(())
}

/// What an address is, for step 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Ok,
    Loopback,
    Refused(&'static str),
}

/// Fixed names that reach cloud metadata services.
const METADATA_NAMES: [&str; 6] = ["metadata.google.internal", "metadata.goog", "metadata.azure.com", "instance-data", "metadata", "instance-data.ec2.internal"];

pub fn class_v4(ip: Ipv4Addr) -> Class {
    let o = ip.octets();
    if o[0] == 0 {
        Class::Refused("an unspecified address")
    } else if ip.is_broadcast() {
        Class::Refused("a broadcast address")
    } else if ip.is_multicast() {
        Class::Refused("a multicast address")
    } else if ip.is_link_local() {
        Class::Refused("a link-local address")
    } else if o == [100, 100, 100, 200] {
        Class::Refused("a cloud metadata address")
    } else if ip.is_loopback() {
        Class::Loopback
    } else {
        Class::Ok
    }
}

fn v4_at(seg: &[u16; 8], i: usize) -> Ipv4Addr {
    Ipv4Addr::from((u32::from(seg[i]) << 16) | u32::from(seg[i + 1]))
}

/// An embedded IPv4 address is refused outright when it is anything but an ordinary address:
/// loopback included (the loopback exception is for plain loopback only).
fn embedded(ip: Ipv4Addr) -> Class {
    match class_v4(ip) {
        Class::Ok => Class::Ok,
        Class::Loopback => Class::Refused("an IPv6 form of a loopback address"),
        Class::Refused(r) => Class::Refused(r),
    }
}

pub fn class_v6(ip: Ipv6Addr) -> Class {
    let s = ip.segments();
    if ip.is_unspecified() {
        return Class::Refused("an unspecified address");
    }
    if ip.is_loopback() {
        return Class::Loopback;
    }
    if s[0] & 0xff00 == 0xff00 {
        return Class::Refused("a multicast address");
    }
    if s[0] & 0xffc0 == 0xfe80 {
        return Class::Refused("a link-local address");
    }
    if ip == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254) {
        return Class::Refused("a cloud metadata address");
    }
    // IPv4-mapped ::ffff:a.b.c.d and IPv4-compatible ::a.b.c.d.
    if s[..5] == [0; 5] && (s[5] == 0xffff || s[5] == 0) {
        return embedded(v4_at(&s, 6));
    }
    // NAT64 well-known prefix 64:ff9b::/96.
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return embedded(v4_at(&s, 6));
    }
    // NAT64 local-use 64:ff9b:1::/48: where the IPv4 sits depends on the operator's prefix.
    if s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1 {
        return Class::Refused("a NAT64 local-use address");
    }
    // 6to4 2002:AABB:CCDD::/48.
    if s[0] == 0x2002 {
        return embedded(v4_at(&s, 1));
    }
    // Teredo 2001:0::/32: the server at bits 32-63, the client inverted in the last 32.
    if s[0] == 0x2001 && s[1] == 0 {
        let client = Ipv4Addr::from(!((u32::from(s[6]) << 16) | u32::from(s[7])));
        for c in [embedded(v4_at(&s, 2)), embedded(client)] {
            if c != Class::Ok {
                return c;
            }
        }
    }
    Class::Ok
}

pub fn class_ip(ip: IpAddr) -> Class {
    match ip {
        IpAddr::V4(v4) => class_v4(v4),
        IpAddr::V6(v6) => class_v6(v6),
    }
}

pub fn class_of(host: &Host) -> Class {
    match host {
        Host::V4(ip) => class_v4(*ip),
        Host::V6(ip) => class_v6(*ip),
        Host::Name(n) if n == "localhost" || n.ends_with(".localhost") => Class::Loopback,
        Host::Name(n) if METADATA_NAMES.contains(&n.as_str()) => Class::Refused("a cloud metadata name"),
        Host::Name(_) => Class::Ok,
    }
}

/// The route a request takes, compared with the plugin entry's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteChoice {
    /// The plugin entry's route (gateway, tunnel, or direct when the entry is direct).
    Entry,
    Direct,
}

/// The loopback exception (section 5, step 3): only when the plugin entry's own target is a
/// loopback literal on the same route, and never after a route change in the sheet.
pub struct LoopbackRule {
    /// The entry's own target (the forward's target when tunnelled) is a loopback IP literal.
    pub entry_target_loopback: bool,
    /// The entry itself connects directly.
    pub entry_direct: bool,
}

impl LoopbackRule {
    fn allows(&self, route: RouteChoice, route_changed: bool) -> bool {
        let same_route = match route {
            RouteChoice::Entry => true,
            RouteChoice::Direct => self.entry_direct,
        };
        self.entry_target_loopback && same_route && !route_changed
    }
}

/// Whether a target string is a loopback IP literal (names do not count).
pub fn is_loopback_literal(s: &str) -> bool {
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => false,
    }
}

/// Section 5, step 3 for a host before the sheet, and again after a route change.
pub fn check_class(host: &Host, route: RouteChoice, route_changed: bool, rule: &LoopbackRule) -> Result<(), Failure> {
    match class_of(host) {
        Class::Ok => Ok(()),
        Class::Refused(why) => Err(Failure::Denied(format!("the host is {why}"))),
        Class::Loopback if rule.allows(route, route_changed) => Ok(()),
        Class::Loopback => Err(denied("the host is a loopback address, which is allowed only when the entry itself is loopback on the same route")),
    }
}

/// The re-check when connecting on a direct route: every address the name returned must pass.
/// An empty answer fails. `loopback_ok` is what [`check_class`] allowed for the request.
pub fn check_resolved(addrs: &[IpAddr], loopback_ok: bool) -> Result<(), Failure> {
    if addrs.is_empty() {
        return Err(denied("the name has no address"));
    }
    for ip in addrs {
        match class_ip(*ip) {
            Class::Ok => {}
            Class::Loopback if loopback_ok => {}
            Class::Loopback => return Err(denied("the name resolves to a loopback address")),
            Class::Refused(why) => return Err(Failure::Denied(format!("the name resolves to {why}"))),
        }
    }
    Ok(())
}

/// Section 5, step 3 when connecting on a direct route: resolves `host` once and checks every
/// address it returns. The app connects to one of the returned addresses (no second lookup),
/// keeping the name for host-key and certificate checks. A literal is checked as it is.
pub fn resolve_checked(host: &str, port: u16, loopback_ok: bool) -> Result<Vec<std::net::SocketAddr>, Failure> {
    use std::net::{SocketAddr, ToSocketAddrs};
    let parsed = parse_host(host)?;
    let addrs: Vec<SocketAddr> = match parsed {
        Host::V4(ip) => vec![SocketAddr::new(IpAddr::V4(ip), port)],
        Host::V6(ip) => vec![SocketAddr::new(IpAddr::V6(ip), port)],
        Host::Name(ref n) => {
            if !matches!(class_of(&parsed), Class::Ok) && !(loopback_ok && class_of(&parsed) == Class::Loopback) {
                return Err(denied("the name is not allowed"));
            }
            (n.as_str(), port).to_socket_addrs().map_err(|e| Failure::Io(format!("the name could not be resolved: {e}")))?.collect()
        }
    };
    let ips: Vec<IpAddr> = addrs.iter().map(SocketAddr::ip).collect();
    check_resolved(&ips, loopback_ok)?;
    Ok(addrs)
}

/// Percent-decodes a request target for the echo comparison (`+` as a space too).
fn percent_decoded(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = |c: u8| (c as char).to_digit(16);
                if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_ascii_lowercase()
}

/// Every IPv6 literal in `s`: runs of hex digits, `:` and `.` that parse as one.
fn ipv6_tokens(s: &str) -> Vec<Ipv6Addr> {
    s.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.')).filter(|t| t.contains(':')).filter_map(|t| t.parse().ok()).collect()
}

/// What the core saw of one `http.send`, for the reported set.
pub struct SeenRequest<'a> {
    pub is_get: bool,
    /// The path, without the query.
    pub path: &'a str,
    /// The whole target, path and query.
    pub target: &'a str,
    pub headers: &'a [(String, String)],
}

/// What the core saw of the response.
pub struct SeenResponse<'a> {
    pub status: u16,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

fn is_json(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(n, v)| {
        if !n.eq_ignore_ascii_case("content-type") {
            return false;
        }
        let mime = v.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        mime == "application/json" || (mime.starts_with("application/") && mime.ends_with("+json"))
    })
}

/// The addresses the entry's server reported to one helper (section 5, step 4).
#[derive(Debug, Default)]
pub struct ReportedSet {
    items: VecDeque<(String, Instant)>,
}

impl ReportedSet {
    pub fn new() -> ReportedSet {
        ReportedSet::default()
    }

    fn expire(&mut self, now: Instant) {
        while self.items.front().is_some_and(|(_, at)| now.duration_since(*at) > REPORTED_TTL) {
            self.items.pop_front();
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Collects from one response, under every rule of step 4. Returns how many it added.
    pub fn collect(&mut self, spec: &OpenSpec, req: &SeenRequest<'_>, resp: &SeenResponse<'_>, now: Instant) -> usize {
        if !req.is_get || !(200..300).contains(&resp.status) || !is_json(resp.headers) {
            return 0;
        }
        let fields: Vec<&String> = spec.address_fields.iter().filter(|a| path_matches(&a.path, req.path)).flat_map(|a| a.fields.iter()).collect();
        if fields.is_empty() {
            return 0;
        }
        let Ok(doc) = serde_json::from_slice::<Json>(resp.body) else { return 0 };
        let mut values = Vec::new();
        for f in fields {
            values_at(&doc, f, &mut values);
        }
        // What the plugin sent: the target as written and decoded, and every header.
        let once = percent_decoded(req.target);
        let mut sent = vec![req.target.to_ascii_lowercase(), percent_decoded(&once), once];
        sent.extend(req.headers.iter().map(|(n, v)| format!("{n}:{v}").to_ascii_lowercase()));
        // IPv6 literals the plugin sent, in canonical form: a server that re-spells one
        // (`0:0::a` → `::a`) must not make it count as reported (review of #1368, LOW).
        let sent_v6: Vec<Ipv6Addr> = sent.iter().take(3).map(String::as_str).chain(req.headers.iter().map(|(_, v)| v.as_str())).flat_map(ipv6_tokens).collect();
        self.expire(now);
        let mut added = 0;
        for raw in values {
            let Ok(host) = parse_host(raw) else { continue };
            let canonical = host.canonical();
            let lower = raw.to_ascii_lowercase();
            let respelled_v6 = matches!(host, Host::V6(ip) if sent_v6.contains(&ip));
            if respelled_v6 || sent.iter().any(|s| s.contains(&lower) || s.contains(&canonical)) {
                continue;
            }
            self.items.retain(|(h, _)| *h != canonical);
            if self.items.len() >= MAX_REPORTED {
                self.items.pop_front();
            }
            self.items.push_back((canonical, now));
            added += 1;
        }
        added
    }

    pub fn contains(&mut self, host: &Host, now: Instant) -> bool {
        self.expire(now);
        let c = host.canonical();
        self.items.iter().any(|(h, _)| *h == c)
    }
}

/// The user-action stamp (section 4): one request within 10 s of a user action.
#[derive(Debug, Default)]
pub struct Stamp {
    at: Option<Instant>,
}

impl Stamp {
    pub fn stamp(&mut self, now: Instant) {
        self.at = Some(now);
    }

    /// Uses the stamp: true once per user action, within the window.
    pub fn take(&mut self, now: Instant) -> bool {
        match self.at.take() {
            Some(at) => now.duration_since(at) <= STAMP_WINDOW,
            None => false,
        }
    }
}

/// At most [`MAX_PER_MINUTE`] requests a minute, refused ones included.
#[derive(Debug, Default)]
pub struct Rate {
    times: VecDeque<Instant>,
}

impl Rate {
    pub fn admit(&mut self, now: Instant) -> bool {
        while self.times.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60)) {
            self.times.pop_front();
        }
        if self.times.len() >= MAX_PER_MINUTE {
            return false;
        }
        self.times.push_back(now);
        true
    }
}

/// Policy for plugin opens (section 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenPolicy {
    Off,
    ReportedOnly,
    Confirm,
}

impl OpenPolicy {
    pub fn from_policy(p: &crate::policy::Policy) -> OpenPolicy {
        if p.plugin_open_disabled {
            OpenPolicy::Off
        } else if p.plugin_open_reported_only {
            OpenPolicy::ReportedOnly
        } else {
            OpenPolicy::Confirm
        }
    }
}

/// A plugin value for an audit record: non-printable and non-ASCII bytes as `\xNN`, cut at
/// 256 bytes (section 8).
pub fn audit_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        let piece = if (0x20..0x7f).contains(&b) && b != b'\\' { (b as char).to_string() } else { format!("\\x{b:02x}") };
        if out.len() + piece.len() > MAX_AUDIT_VALUE_BYTES {
            break;
        }
        out.push_str(&piece);
    }
    out
}

#[cfg(test)]
#[path = "open_tests.rs"]
mod tests;
