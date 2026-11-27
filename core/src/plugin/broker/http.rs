//! The HTTP helper's decisions (PLUG-HTTP-01; design `docs/specs/plugins-amendment-2.md`,
//! plugin API 1.1). Pure logic, like the rest of the broker: the manifest's `[http]` rules,
//! the checks on every request (section 5 of the note), the request the core writes, the
//! login header (review MEDIUM 1), the strict response reader (section 6) and the check that
//! a response does not echo the login back (review MEDIUM 2).
//!
//! The relay (`host/relay.rs`) runs the exchange on the stream worker that already owns the
//! socket, the route and the core's TLS; nothing here touches the network.

use std::io::{ErrorKind, Read};

use base64::Engine as _;
use zeroize::Zeroizing;

use super::secret::SecretCheck;
use super::Failure;

/// Path prefixes a manifest may list.
pub const MAX_PATHS: usize = 16;
pub const MAX_PATH_PREFIX_BYTES: usize = 256;
/// Extra ports a manifest may list.
pub const MAX_PORTS: usize = 16;
pub const MAX_AUTH_FORMAT_BYTES: usize = 128;
/// One request.
pub const MAX_TARGET_BYTES: usize = 8 * 1024;
pub const MAX_REQUEST_HEADERS: usize = 32;
pub const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;
/// One response.
pub const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_HEADER_LINES: usize = 100;
pub const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Whole-request time when the plugin names none, and the most it may name.
pub const MAX_TIMEOUT_MS: u32 = 60_000;
/// Idle keep-alive connections per helper and port, and how long one may stay idle.
pub const MAX_IDLE_PER_PORT: usize = 4;
pub const IDLE_MS: u64 = 30_000;

/// The methods of `http.method` in the WIT. CONNECT and TRACE do not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

impl Method {
    pub const ALL: [Method; 7] = [Method::Get, Method::Head, Method::Post, Method::Put, Method::Patch, Method::Delete, Method::Options];

    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
            Method::Options => "OPTIONS",
        }
    }

    /// The manifest spelling (upper case).
    pub fn parse(text: &str) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.as_str() == text)
    }

    /// The WIT enum case name (lower case).
    pub fn from_wit(text: &str) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.as_str().eq_ignore_ascii_case(text))
    }

    /// Whether the method may change the server: audited one by one (note section 7), and
    /// named in the install prompt.
    pub fn changes(self) -> bool {
        !matches!(self, Method::Get | Method::Head | Method::Options)
    }

    fn takes_body(self) -> bool {
        matches!(self, Method::Post | Method::Put | Method::Patch | Method::Delete)
    }
}

/// How the core turns the entry's login into a header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFormat {
    /// `Basic base64(user:secret)`.
    Basic,
    /// `Bearer {secret}`.
    Bearer,
    /// Literal text with `{secret}` once and `{user}` at most once.
    Template(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpAuth {
    /// `Authorization` or `X-…`, as the manifest spells it.
    pub header: String,
    pub format: AuthFormat,
}

/// The manifest's `[http]` table, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSpec {
    pub paths: Vec<String>,
    pub ports: Vec<u16>,
    pub methods: Vec<Method>,
    pub auth: Option<HttpAuth>,
    /// `[http.session]` (API 1.3, design D): the core logs in with a request body and keeps
    /// the session cookie. A connection type uses either this or `auth`, never both.
    pub session: Option<super::http_session::HttpSession>,
}

impl HttpSpec {
    /// Whether the install prompt says "may change things on the server".
    pub fn may_change(&self) -> bool {
        self.methods.iter().any(|m| m.changes())
    }

    /// Whether the spec has a prefix other than `/` (note section 2 and review LOW: an
    /// External plugin must list at least one, and may not list `/`).
    pub fn has_root_prefix(&self) -> bool {
        self.paths.iter().any(|p| p == "/")
    }
}

/// A prefix the manifest lists: starts and ends with `/`, printable ASCII, no `.` or `..`
/// segment, no empty segment, no `%`, `?`, `#`, `\` or `;`, at most 256 bytes.
pub fn valid_prefix(p: &str) -> bool {
    if p.is_empty() || p.len() > MAX_PATH_PREFIX_BYTES || !p.starts_with('/') || !p.ends_with('/') {
        return false;
    }
    if !p.bytes().all(|b| (0x21..=0x7e).contains(&b) && !matches!(b, b'%' | b'?' | b'#' | b'\\' | b';')) {
        return false;
    }
    if p == "/" {
        return true;
    }
    p[1..p.len() - 1].split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The header the login goes in: `Authorization`, or `X-` and 1 to 40 letters, digits or `-`.
pub fn valid_auth_header(name: &str) -> bool {
    if name.eq_ignore_ascii_case("authorization") {
        return true;
    }
    let Some(rest) = name.strip_prefix("X-").or_else(|| name.strip_prefix("x-")) else { return false };
    (1..=40).contains(&rest.len()) && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// `basic`, `bearer`, or a template: printable ASCII, `{secret}` exactly once, `{user}` at
/// most once, no other `{` or `}`.
pub fn parse_auth_format(text: &str) -> Option<AuthFormat> {
    match text {
        "basic" => return Some(AuthFormat::Basic),
        "bearer" => return Some(AuthFormat::Bearer),
        _ => {}
    }
    if text.is_empty() || text.len() > MAX_AUTH_FORMAT_BYTES || !text.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return None;
    }
    if text.matches("{secret}").count() != 1 || text.matches("{user}").count() > 1 {
        return None;
    }
    let rest = text.replace("{secret}", "").replace("{user}", "");
    if rest.contains('{') || rest.contains('}') {
        return None;
    }
    Some(AuthFormat::Template(text.to_string()))
}

/// The login header's value (review of #1332, MEDIUM 1). The core refuses to build it when
/// the user or the secret holds a byte outside printable ASCII (CR, LF, NUL and every other
/// control byte included), so a pasted or imported login cannot add a header. For `basic`
/// the user may not hold `:`, which would move the split between user and secret.
pub fn auth_value(format: &AuthFormat, user: &str, secret: &[u8]) -> Result<Zeroizing<String>, Failure> {
    let printable = |b: &[u8]| b.iter().all(|c| (0x20..=0x7e).contains(c));
    let refuse = || Failure::Denied("the entry's login holds characters that cannot go in a header".into());
    if !printable(user.as_bytes()) || !printable(secret) || secret.is_empty() {
        return Err(refuse());
    }
    // Printable ASCII is UTF-8.
    let secret = std::str::from_utf8(secret).map_err(|_| refuse())?;
    Ok(Zeroizing::new(match format {
        AuthFormat::Basic => {
            if user.contains(':') {
                return Err(Failure::Denied("the entry's user name holds a \":\", which Basic login cannot carry".into()));
            }
            let pair = Zeroizing::new(format!("{user}:{secret}"));
            format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair.as_bytes()))
        }
        AuthFormat::Bearer => format!("Bearer {secret}"),
        AuthFormat::Template(t) => t.replace("{user}", user).replace("{secret}", secret),
    }))
}

/// One request as the plugin sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginRequest {
    pub method: Method,
    pub port: Option<u16>,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub with_login: bool,
    pub timeout_ms: Option<u32>,
}

impl PluginRequest {
    /// The whole-request time limit: the plugin's, at most 60 s.
    pub fn timeout_ms(&self) -> u32 {
        self.timeout_ms.filter(|t| *t > 0).map_or(MAX_TIMEOUT_MS, |t| t.min(MAX_TIMEOUT_MS))
    }

    /// The path without the query, for the audit record.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }
}

fn hex_val(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// Step 4: the target. Returns `invalid` for a malformed one and `denied` for one outside the
/// prefixes. Nothing is normalised: what would need it is refused.
pub fn check_target(target: &str, paths: &[String]) -> Result<(), Failure> {
    let malformed = |why: &str| Err(Failure::Invalid(format!("the request target {why}")));
    if target.is_empty() || target.len() > MAX_TARGET_BYTES {
        return malformed(&format!("must be 1 to {MAX_TARGET_BYTES} bytes"));
    }
    if !target.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return malformed("must be printable ASCII with no spaces");
    }
    if !target.starts_with('/') || target.starts_with("//") {
        return malformed("must start with a single \"/\"");
    }
    if target.contains('#') || target.contains('\\') {
        return malformed("may not hold \"#\" or \"\\\"");
    }
    let path = target.split('?').next().unwrap_or("");
    if path.contains(';') {
        return malformed("may not hold \";\" path parameters");
    }
    let segments: Vec<&str> = path[1..].split('/').collect();
    let last = segments.len() - 1;
    for (i, seg) in segments.iter().enumerate() {
        // Only the last segment may be empty (a trailing "/").
        if seg.is_empty() && i != last {
            return malformed("may not hold an empty path segment");
        }
        if *seg == "." || *seg == ".." {
            return malformed("may not hold \".\" or \"..\" segments");
        }
        let bytes = seg.as_bytes();
        let mut j = 0;
        while j < bytes.len() {
            if bytes[j] == b'%' {
                let (Some(h), Some(l)) = (bytes.get(j + 1).copied().and_then(hex_val), bytes.get(j + 2).copied().and_then(hex_val)) else {
                    return malformed("holds a bad percent-encoding");
                };
                let decoded = h * 16 + l;
                if decoded < 0x20 || decoded == 0x7f || matches!(decoded, b'/' | b'\\' | b'.' | b';' | b'%') {
                    return malformed("holds a percent-encoded character that is not allowed in a path");
                }
                j += 3;
            } else {
                j += 1;
            }
        }
    }
    // Byte-exact, case-sensitive prefix match on the target as sent (review LOW).
    if !paths.iter().any(|p| path.starts_with(p.as_str())) {
        return Err(Failure::Denied("that path is not one the plugin lists".into()));
    }
    Ok(())
}

/// Header names the plugin may not set, in any case. `Proxy-*` is refused by prefix.
const REFUSED_HEADERS: [&str; 12] = ["host", "content-length", "transfer-encoding", "connection", "keep-alive", "upgrade", "te", "trailer", "expect", "cookie", "authorization", "user-agent"];

/// Step 5: the plugin's headers.
pub fn check_headers(headers: &[(String, String)], auth_header: Option<&str>) -> Result<(), Failure> {
    let bad = |why: &str| Err(Failure::Invalid(format!("a request header {why}")));
    if headers.len() > MAX_REQUEST_HEADERS {
        return bad(&format!("count is over {MAX_REQUEST_HEADERS}"));
    }
    let total: usize = headers.iter().map(|(n, v)| n.len() + v.len() + 4).sum();
    if total > MAX_REQUEST_HEADER_BYTES {
        return bad(&format!("block is over {MAX_REQUEST_HEADER_BYTES} bytes"));
    }
    for (name, value) in headers {
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return bad("name is not a valid token");
        }
        let lower = name.to_ascii_lowercase();
        if REFUSED_HEADERS.contains(&lower.as_str()) || lower.starts_with("proxy-") || auth_header.is_some_and(|a| a.eq_ignore_ascii_case(name)) {
            return Err(Failure::Invalid(format!("the core sets \"{name}\" itself, or it is not allowed")));
        }
        if !value.bytes().all(|b| (0x20..=0x7e).contains(&b) || b == b'\t') {
            return bad("value holds a character that is not allowed");
        }
    }
    Ok(())
}

/// Steps 2 and 4 to 7 of the note's section 5, in order. Step 1 (the grant) and step 3 (the
/// port) are the caller's, steps 8 to 10 the relay's. `secrets` holds the released passwords
/// and the login the core would put in the header.
pub fn check_request(spec: &HttpSpec, req: &PluginRequest, secrets: &SecretCheck) -> Result<(), Failure> {
    if !spec.methods.contains(&req.method) {
        return Err(Failure::Denied(format!("the plugin does not list the method {}", req.method.as_str())));
    }
    check_target(&req.target, &spec.paths)?;
    check_headers(&req.headers, spec.auth.as_ref().map(|a| a.header.as_str()))?;
    if !req.body.is_empty() && !req.method.takes_body() {
        return Err(Failure::Invalid(format!("a {} request has no body", req.method.as_str())));
    }
    if req.body.len() > MAX_REQUEST_BODY_BYTES {
        return Err(Failure::Invalid(format!("a request body is at most {} MiB", MAX_REQUEST_BODY_BYTES >> 20)));
    }
    if req.with_login && spec.auth.is_none() && spec.session.is_none() {
        return Err(Failure::Denied("the plugin does not describe a login".into()));
    }
    let mut seen = Vec::with_capacity(req.target.len() + req.body.len() + 256);
    seen.extend_from_slice(req.target.as_bytes());
    for (n, v) in &req.headers {
        seen.push(b'\n');
        seen.extend_from_slice(n.as_bytes());
        seen.push(b':');
        seen.extend_from_slice(v.as_bytes());
    }
    // The body on its own too, so an encoding that starts at the body's first byte is found.
    if secrets.matches(&seen) || secrets.matches(&req.body) {
        return Err(Failure::Denied("the request holds a password".into()));
    }
    Ok(())
}

/// The `Host` header: the entry's host as typed (IPv6 in brackets), with the port when it is
/// not the scheme's default.
pub fn host_header(host: &str, port: u16, tls: bool) -> String {
    let host = host.trim();
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let host = if bare.contains(':') { format!("[{bare}]") } else { bare.to_string() };
    if (tls && port == 443) || (!tls && port == 80) {
        host
    } else {
        format!("{host}:{port}")
    }
}

/// The bytes the core writes. Framing headers are the core's; the plugin's were checked.
/// Wiped on drop: it may hold the login.
pub fn encode_request(req: &PluginRequest, host: &str, plugin_id: &str, auth: Option<(&str, &str)>) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(req.target.len() + req.body.len() + 512));
    let mut line = |s: &str| {
        out.extend_from_slice(s.as_bytes());
        out.extend_from_slice(b"\r\n");
    };
    line(&format!("{} {} HTTP/1.1", req.method.as_str(), req.target));
    line(&format!("Host: {host}"));
    line(&format!("User-Agent: Gantry-plugin/{plugin_id}"));
    for (n, v) in &req.headers {
        line(&format!("{n}: {v}"));
    }
    if let Some((name, value)) = auth {
        let l = Zeroizing::new(format!("{name}: {value}"));
        line(&l);
    }
    if req.method.takes_body() {
        line(&format!("Content-Length: {}", req.body.len()));
    }
    line("");
    out.extend_from_slice(&req.body);
    out
}

/// A response as the plugin gets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Whether the connection may carry another request.
    pub keep_alive: bool,
}

/// Review of #1332, MEDIUM 2: a server or proxy that echoes request headers would hand the
/// login to a plugin that was told it cannot read it. For a request that carried the login,
/// the core runs the secret check over the response's headers and body and withholds the
/// whole response on a match.
pub fn check_echo(resp: &HttpResponse, login: &SecretCheck) -> Result<(), Failure> {
    if login.is_empty() {
        return Ok(());
    }
    let echoed = resp.headers.iter().any(|(n, v)| login.matches(n.as_bytes()) || login.matches(v.as_bytes())) || login.matches(&resp.body);
    if echoed {
        return Err(Failure::Denied("the server's answer repeated the login, so Gantry withheld it".into()));
    }
    Ok(())
}

fn values<'a>(headers: &'a [(String, String)], name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    headers.iter().filter(move |(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn bad_response(why: &str) -> Failure {
    Failure::Io(format!("bad response: {why}"))
}

/// Reads one response from `src`, strictly (note section 6). `head` is true for a HEAD
/// request. The source's read timeout is the caller's (the time left). Anything ambiguous
/// fails and the caller drops the connection.
pub struct ResponseReader<'a, R: Read> {
    src: &'a mut R,
    buf: Vec<u8>,
    at: usize,
    eof: bool,
}

impl<'a, R: Read> ResponseReader<'a, R> {
    pub fn new(src: &'a mut R) -> Self {
        ResponseReader { src, buf: Vec::with_capacity(8 * 1024), at: 0, eof: false }
    }

    fn fill(&mut self) -> Result<bool, Failure> {
        if self.eof {
            return Ok(false);
        }
        if self.at > 0 && self.at == self.buf.len() {
            self.buf.clear();
            self.at = 0;
        }
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match self.src.read(&mut chunk) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(false);
                }
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    return Ok(true);
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => return Err(Failure::TimedOut),
                Err(e) if matches!(e.kind(), ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted) => {
                    self.eof = true;
                    return Ok(false);
                }
                Err(e) => return Err(Failure::Io(e.to_string())),
            }
        }
    }

    /// One line ending in CRLF, without it. `budget` is what the header block may still use.
    fn line(&mut self, budget: &mut usize) -> Result<String, Failure> {
        loop {
            if let Some(pos) = self.buf[self.at..].iter().position(|&b| b == b'\n') {
                let end = self.at + pos;
                let used = pos + 1;
                if used > *budget {
                    return Err(bad_response("the headers are too large"));
                }
                *budget -= used;
                if end == self.at || self.buf[end - 1] != b'\r' {
                    return Err(bad_response("a line does not end in CRLF"));
                }
                let raw = &self.buf[self.at..end - 1];
                if raw.iter().any(|&b| b == b'\r' || b == 0) {
                    return Err(bad_response("a line holds CR or NUL"));
                }
                let text = String::from_utf8_lossy(raw).into_owned();
                self.at = end + 1;
                return Ok(text);
            }
            if self.buf.len() - self.at > *budget {
                return Err(bad_response("the headers are too large"));
            }
            if !self.fill()? {
                return Err(bad_response("the connection closed inside the headers"));
            }
        }
    }

    fn take(&mut self, n: usize, into: &mut Vec<u8>) -> Result<(), Failure> {
        let mut left = n;
        while left > 0 {
            if self.at == self.buf.len() && !self.fill()? {
                return Err(bad_response("the connection closed inside the body"));
            }
            let k = left.min(self.buf.len() - self.at);
            into.extend_from_slice(&self.buf[self.at..self.at + k]);
            self.at += k;
            left -= k;
        }
        Ok(())
    }

    fn crlf(&mut self) -> Result<(), Failure> {
        let mut two = Vec::with_capacity(2);
        self.take(2, &mut two)?;
        if two != b"\r\n" {
            return Err(bad_response("a chunk does not end in CRLF"));
        }
        Ok(())
    }

    /// Reads the status line and the headers. Returns (status, minor version, headers).
    fn head_block(&mut self) -> Result<(u16, u8, Vec<(String, String)>), Failure> {
        let mut budget = MAX_RESPONSE_HEADER_BYTES;
        let status_line = self.line(&mut budget)?;
        let mut parts = status_line.splitn(3, ' ');
        let minor = match parts.next() {
            Some("HTTP/1.1") => 1,
            Some("HTTP/1.0") => 0,
            _ => return Err(bad_response("not an HTTP/1.x status line")),
        };
        let code = parts.next().unwrap_or("");
        if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad_response("the status is not three digits"));
        }
        let status: u16 = code.parse().map_err(|_| bad_response("bad status"))?;
        if !(100..=599).contains(&status) {
            return Err(bad_response("the status is out of range"));
        }
        let mut headers = Vec::new();
        loop {
            let line = self.line(&mut budget)?;
            if line.is_empty() {
                break;
            }
            if headers.len() >= MAX_RESPONSE_HEADER_LINES {
                return Err(bad_response("too many header lines"));
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                return Err(bad_response("obsolete line folding"));
            }
            let Some((name, value)) = line.split_once(':') else { return Err(bad_response("a header line has no colon")) };
            if name.is_empty() || !name.bytes().all(is_tchar) {
                return Err(bad_response("a header name is not a token (or has a space before the colon)"));
            }
            headers.push((name.to_string(), value.trim_matches(|c| c == ' ' || c == '\t').to_string()));
        }
        Ok((status, minor, headers))
    }

    /// The response to one request.
    pub fn read(mut self, head: bool) -> Result<(HttpResponse, bool), Failure> {
        // 1xx before the final answer are skipped; 101 is refused (no upgrades).
        let (status, minor, headers) = loop {
            let (status, minor, headers) = self.head_block()?;
            if status == 101 {
                return Err(bad_response("the server switched protocols"));
            }
            if (100..200).contains(&status) {
                continue;
            }
            break (status, minor, headers);
        };
        let get = |name: &'static str| values(&headers, name);
        let mut lengths = get("content-length").peekable();
        let length: Option<usize> = match lengths.peek() {
            None => None,
            Some(_) => {
                let mut value: Option<&str> = None;
                for l in get("content-length") {
                    // A list in one header ("5, 5") is ambiguous too.
                    if l.is_empty() || !l.bytes().all(|b| b.is_ascii_digit()) || value.is_some_and(|v| v != l) {
                        return Err(bad_response("a bad or conflicting Content-Length"));
                    }
                    value = Some(l);
                }
                Some(value.unwrap_or("0").parse().map_err(|_| bad_response("Content-Length is too large"))?)
            }
        };
        let te: Vec<&str> = get("transfer-encoding").collect();
        let chunked = match te.as_slice() {
            [] => false,
            [one] if one.eq_ignore_ascii_case("chunked") => true,
            _ => return Err(bad_response("a transfer coding other than chunked")),
        };
        if chunked && length.is_some() {
            return Err(bad_response("both Content-Length and Transfer-Encoding"));
        }
        let close_asked = get("connection").any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")));
        let mut keep_alive = minor == 1 && !close_asked;
        let mut body = Vec::new();
        let no_body = head || status == 204 || status == 304;
        if !no_body {
            if chunked {
                let mut budget = MAX_RESPONSE_HEADER_BYTES;
                loop {
                    let size_line = self.line(&mut budget)?;
                    let size_text = size_line.split(';').next().unwrap_or("").trim_end_matches([' ', '\t']);
                    if size_text.is_empty() || size_text.len() > 8 || !size_text.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(bad_response("a bad chunk size"));
                    }
                    let size = usize::from_str_radix(size_text, 16).map_err(|_| bad_response("a bad chunk size"))?;
                    if size == 0 {
                        // Trailers, ignored, within the same header budget.
                        loop {
                            if self.line(&mut budget)?.is_empty() {
                                break;
                            }
                        }
                        break;
                    }
                    if body.len() + size > MAX_RESPONSE_BODY_BYTES {
                        return Err(Failure::Invalid("response too large".into()));
                    }
                    self.take(size, &mut body)?;
                    self.crlf()?;
                }
            } else if let Some(n) = length {
                if n > MAX_RESPONSE_BODY_BYTES {
                    return Err(Failure::Invalid("response too large".into()));
                }
                self.take(n, &mut body)?;
            } else {
                // Ended by close.
                keep_alive = false;
                loop {
                    if self.at < self.buf.len() {
                        if body.len() + (self.buf.len() - self.at) > MAX_RESPONSE_BODY_BYTES {
                            return Err(Failure::Invalid("response too large".into()));
                        }
                        body.extend_from_slice(&self.buf[self.at..]);
                        self.at = self.buf.len();
                    }
                    if !self.fill()? {
                        break;
                    }
                }
            }
        }
        // Bytes after the response mean the server sent more than one answer: do not reuse.
        if self.at < self.buf.len() {
            keep_alive = false;
        }
        Ok((HttpResponse { status, headers: headers.clone(), body, keep_alive }, keep_alive))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> HttpSpec {
        HttpSpec {
            paths: vec!["/api2/json/".into()],
            ports: vec![],
            methods: vec![Method::Get, Method::Post],
            auth: Some(HttpAuth { header: "Authorization".into(), format: parse_auth_format("PVEAPIToken={user}={secret}").unwrap() }),
            session: None,
        }
    }

    fn get(target: &str) -> PluginRequest {
        PluginRequest { method: Method::Get, port: None, target: target.into(), headers: vec![], body: vec![], with_login: false, timeout_ms: None }
    }

    fn read(bytes: &[u8], head: bool) -> Result<HttpResponse, Failure> {
        let mut src = std::io::Cursor::new(bytes.to_vec());
        ResponseReader::new(&mut src).read(head).map(|(r, _)| r)
    }

    #[test]
    fn prefixes() {
        for ok in ["/", "/api2/json/", "/sdk/", "/api/v1/"] {
            assert!(valid_prefix(ok), "{ok}");
        }
        for bad in ["", "api/", "/api", "//", "/a//b/", "/./", "/a/../", "/a%2f/", "/a?/", "/a#/", "/a\\/", "/a;b/", "/a b/", &format!("/{}/", "a".repeat(300))] {
            assert!(!valid_prefix(bad), "{bad:?}");
        }
    }

    #[test]
    fn auth_formats_and_headers() {
        assert_eq!(parse_auth_format("basic"), Some(AuthFormat::Basic));
        assert_eq!(parse_auth_format("bearer"), Some(AuthFormat::Bearer));
        assert!(parse_auth_format("PVEAPIToken={user}={secret}").is_some());
        for bad in ["", "{user}", "{secret}{secret}", "{user}{user}{secret}", "{secret}{x}", "a}{secret}", "{secret}\r\n", &format!("{}{{secret}}", "a".repeat(130))] {
            assert_eq!(parse_auth_format(bad), None, "{bad:?}");
        }
        for ok in ["Authorization", "authorization", "X-Api-Key", "x-auth-token"] {
            assert!(valid_auth_header(ok), "{ok}");
        }
        for bad in ["Cookie", "Proxy-Authorization", "Host", "X-", "X-a b", "X-é", &format!("X-{}", "a".repeat(41))] {
            assert!(!valid_auth_header(bad), "{bad:?}");
        }
    }

    /// Review of #1332, MEDIUM 1.
    #[test]
    fn a_login_with_control_bytes_never_becomes_a_header() {
        let t = parse_auth_format("PVEAPIToken={user}={secret}").unwrap();
        assert_eq!(auth_value(&t, "u@pve!t", b"abc-123").unwrap().as_str(), "PVEAPIToken=u@pve!t=abc-123");
        for (user, secret) in [("u\r\nX-Evil: 1", &b"s"[..]), ("u", b"s\r\nX-Evil: 1"), ("u", b"s\n"), ("u", b"s\0"), ("u\t", b"s"), ("u", b"\x7f"), ("u", "é".as_bytes()), ("u", b"")] {
            assert!(matches!(auth_value(&t, user, secret), Err(Failure::Denied(_))), "{user:?} {secret:?}");
            assert!(auth_value(&AuthFormat::Bearer, user, secret).is_err());
        }
        assert_eq!(auth_value(&AuthFormat::Basic, "a", b"b:c").unwrap().as_str(), "Basic YTpiOmM=");
        assert!(matches!(auth_value(&AuthFormat::Basic, "a:b", b"c"), Err(Failure::Denied(_))));
        assert_eq!(auth_value(&AuthFormat::Bearer, "", b"tok").unwrap().as_str(), "Bearer tok");
    }

    #[test]
    fn targets() {
        let p = vec!["/api2/json/".to_string()];
        for ok in ["/api2/json/nodes", "/api2/json/nodes/pve1/qemu?full=1", "/api2/json/", "/api2/json/a%20b", "/api2/json/x?q=a/../b", "/api2/json/file.txt"] {
            assert_eq!(check_target(ok, &p), Ok(()), "{ok}");
        }
        let invalid = [
            "", "api2/json/x", "//evil/api2/json/", "http://evil/api2/json/", "/api2/json/x#frag", "/api2/json/a\\b",
            "/api2/json/../x", "/api2/json/./x", "/api2/json//x", "/api2/json/%2e%2e/x", "/api2/json/%2E/x", "/api2/json/a%2fb",
            "/api2/json/a%5cb", "/api2/json/a%00", "/api2/json/a%0d%0aX:1", "/api2/json/a;b", "/api2/json/a%3bb", "/api2/json/a%zz",
            "/api2/json/a%2", "/api2/json/a b", "/api2/json/a\r\nHost: x", "/api2/json/é",
        ];
        for bad in invalid {
            assert!(matches!(check_target(bad, &p), Err(Failure::Invalid(_))), "{bad:?}");
        }
        assert!(matches!(check_target(&format!("/api2/json/{}", "a".repeat(MAX_TARGET_BYTES)), &p), Err(Failure::Invalid(_))));
        // Outside the prefixes, and case-sensitive.
        for out in ["/api2/", "/api2/jsonx", "/API2/json/nodes", "/access/ticket", "/api2/json"] {
            assert!(matches!(check_target(out, &p), Err(Failure::Denied(_))), "{out:?}");
        }
    }

    #[test]
    fn headers() {
        assert_eq!(check_headers(&[("Accept".into(), "application/json".into()), ("X-Thing".into(), "a\tb".into())], Some("Authorization")), Ok(()));
        for name in ["Host", "content-length", "Transfer-Encoding", "Connection", "Upgrade", "TE", "Expect", "Cookie", "Authorization", "Proxy-Authorization", "proxy-anything", "User-Agent", "Keep-Alive", "Trailer"] {
            assert!(check_headers(&[(name.into(), "x".into())], None).is_err(), "{name}");
        }
        assert!(check_headers(&[("X-Api-Key".into(), "x".into())], Some("x-api-key")).is_err(), "the login header is the core's");
        for (n, v) in [("Bad Name", "x"), ("Bad:Name", "x"), ("", "x"), ("X", "a\r\nInjected: 1"), ("X", "a\nb"), ("X", "a\0"), ("X", "é")] {
            assert!(check_headers(&[(n.into(), v.into())], None).is_err(), "{n:?} {v:?}");
        }
        let many: Vec<_> = (0..33).map(|i| (format!("X-{i}"), "v".to_string())).collect();
        assert!(check_headers(&many, None).is_err());
        assert!(check_headers(&[("X-Big".into(), "v".repeat(MAX_REQUEST_HEADER_BYTES))], None).is_err());
    }

    #[test]
    fn request_checks_in_order() {
        let s = spec();
        let none = SecretCheck::new();
        assert_eq!(check_request(&s, &get("/api2/json/nodes"), &none), Ok(()));
        let mut del = get("/api2/json/x");
        del.method = Method::Delete;
        assert!(matches!(check_request(&s, &del, &none), Err(Failure::Denied(_))), "DELETE not listed");
        let mut body_on_get = get("/api2/json/x");
        body_on_get.body = b"x".to_vec();
        assert!(matches!(check_request(&s, &body_on_get, &none), Err(Failure::Invalid(_))));
        let mut big = get("/api2/json/x");
        big.method = Method::Post;
        big.body = vec![b'a'; MAX_REQUEST_BODY_BYTES + 1];
        assert!(matches!(check_request(&s, &big, &none), Err(Failure::Invalid(_))));
        let mut no_auth = s.clone();
        no_auth.auth = None;
        let mut login = get("/api2/json/x");
        login.with_login = true;
        assert!(matches!(check_request(&no_auth, &login, &none), Err(Failure::Denied(_))));
        assert_eq!(check_request(&s, &login, &none), Ok(()));
    }

    /// The token cannot be moved into a query string, a header or the body, in any encoding
    /// the secret check knows.
    #[test]
    fn the_login_cannot_leave_through_the_request() {
        let s = spec();
        let secret = "0123456789abcdef-SECRET";
        let mut check = SecretCheck::new();
        check.add(secret.as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(secret);
        let mut q = get(&format!("/api2/json/x?t={secret}"));
        assert!(matches!(check_request(&s, &q, &check), Err(Failure::Denied(_))));
        q.target = format!("/api2/json/x?t={}", hex::encode(secret));
        assert!(matches!(check_request(&s, &q, &check), Err(Failure::Denied(_))));
        let mut h = get("/api2/json/x");
        h.headers = vec![("X-Leak".into(), b64.clone())];
        assert!(matches!(check_request(&s, &h, &check), Err(Failure::Denied(_))));
        let mut b = get("/api2/json/x");
        b.method = Method::Post;
        b.body = format!("a={secret}").into_bytes();
        assert!(matches!(check_request(&s, &b, &check), Err(Failure::Denied(_))));
        b.body = b64.into_bytes();
        assert!(matches!(check_request(&s, &b, &check), Err(Failure::Denied(_))));
    }

    #[test]
    fn the_request_the_core_writes() {
        let mut r = get("/api2/json/nodes?x=1");
        r.headers = vec![("Accept".into(), "application/json".into())];
        let bytes = encode_request(&r, &host_header("pve.example", 8006, true), "dev.bastion.proxmox", Some(("Authorization", "PVEAPIToken=a=b")));
        assert_eq!(
            String::from_utf8(bytes.to_vec()).unwrap(),
            "GET /api2/json/nodes?x=1 HTTP/1.1\r\nHost: pve.example:8006\r\nUser-Agent: Gantry-plugin/dev.bastion.proxmox\r\nAccept: application/json\r\nAuthorization: PVEAPIToken=a=b\r\n\r\n"
        );
        let mut p = get("/api2/json/x");
        p.method = Method::Post;
        p.body = b"a=1".to_vec();
        let bytes = encode_request(&p, &host_header("::1", 443, true), "p", None);
        assert!(String::from_utf8(bytes.to_vec()).unwrap().ends_with("Host: [::1]\r\nUser-Agent: Gantry-plugin/p\r\nContent-Length: 3\r\n\r\na=1"));
        let mut d = get("/api2/json/x");
        d.method = Method::Delete;
        assert!(String::from_utf8(encode_request(&d, "h", "p", None).to_vec()).unwrap().contains("Content-Length: 0\r\n"));
        assert_eq!(host_header("[2001:db8::1]", 8006, true), "[2001:db8::1]:8006");
        assert_eq!(host_header("h", 80, false), "h");
        assert_eq!(get("/a?b").path(), "/a");
        assert_eq!(get("/a").timeout_ms(), MAX_TIMEOUT_MS);
        let mut t = get("/a");
        t.timeout_ms = Some(5);
        assert_eq!(t.timeout_ms(), 5);
        t.timeout_ms = Some(600_000);
        assert_eq!(t.timeout_ms(), MAX_TIMEOUT_MS);
    }

    #[test]
    fn responses_that_parse() {
        let r = read(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"data\":1}\n", false).unwrap();
        assert_eq!((r.status, r.body.as_slice(), r.keep_alive), (200, &b"{\"data\":1}\n"[..], true));
        assert_eq!(r.headers[0], ("Content-Type".into(), "application/json".into()));
        let r = read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n", false).unwrap();
        assert_eq!(r.body, b"hello world");
        let r = read(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n", false).unwrap();
        assert_eq!((r.status, r.body.len()), (204, 0));
        let r = read(b"HTTP/1.0 200 OK\r\n\r\nuntil close", false).unwrap();
        assert_eq!((r.body.as_slice(), r.keep_alive), (&b"until close"[..], false));
        let r = read(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n", true).unwrap();
        assert_eq!(r.body.len(), 0, "HEAD has no body");
        let r = read(b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", false).unwrap();
        assert_eq!((r.status, r.keep_alive), (302, false), "a redirect is returned, not followed");
        let r = read(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nxEXTRA", false).unwrap();
        assert!(!r.keep_alive, "bytes after the answer: the connection is not reused");
    }

    #[test]
    fn responses_that_are_refused() {
        let cases: [&[u8]; 17] = [
            b"HTTP/2 200 OK\r\n\r\n",
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 999 X\r\n\r\n",
            b"HTTP/1.1 200 OK\nContent-Length: 0\n\n",
            b"HTTP/1.1 200 OK\r\nX: a\r\n folded\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX : a\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nNoColon\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1, 1\r\n\r\na",
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX0\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
            b"HTTP/1.1 200 OK\r\nX: a\0b\r\n\r\n",
        ];
        for c in cases {
            assert!(read(c, false).is_err(), "{:?}", String::from_utf8_lossy(c));
        }
        let mut huge = b"HTTP/1.1 200 OK\r\n".to_vec();
        huge.extend_from_slice(format!("X: {}\r\n\r\n", "a".repeat(MAX_RESPONSE_HEADER_BYTES)).as_bytes());
        assert!(read(&huge, false).is_err());
        let mut lines = b"HTTP/1.1 200 OK\r\n".to_vec();
        for i in 0..=MAX_RESPONSE_HEADER_LINES {
            lines.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        lines.extend_from_slice(b"\r\n");
        assert!(read(&lines, false).is_err());
        let big = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", MAX_RESPONSE_BODY_BYTES + 1);
        assert_eq!(read(big.as_bytes(), false), Err(Failure::Invalid("response too large".into())));
        let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        chunked.extend_from_slice(format!("{:x}\r\n", MAX_RESPONSE_BODY_BYTES + 1).as_bytes());
        assert_eq!(read(&chunked, false), Err(Failure::Invalid("response too large".into())));
        assert!(read(b"", false).is_err());
    }

    /// Review of #1332, MEDIUM 2.
    #[test]
    fn a_response_that_echoes_the_login_is_withheld() {
        let mut login = SecretCheck::new();
        login.add(b"0123456789abcdef-SECRET");
        let ok = HttpResponse { status: 200, headers: vec![("X".into(), "fine".into())], body: b"{}".to_vec(), keep_alive: true };
        assert_eq!(check_echo(&ok, &login), Ok(()));
        let in_header = HttpResponse { headers: vec![("X-Echo".into(), "PVEAPIToken=u=0123456789abcdef-SECRET".into())], ..ok.clone() };
        assert!(matches!(check_echo(&in_header, &login), Err(Failure::Denied(_))));
        let in_body = HttpResponse { body: base64::engine::general_purpose::STANDARD.encode("0123456789abcdef-SECRET").into_bytes(), ..ok.clone() };
        assert!(matches!(check_echo(&in_body, &login), Err(Failure::Denied(_))));
        assert_eq!(check_echo(&in_body, &SecretCheck::new()), Ok(()), "no login sent: nothing to look for");
    }

    #[test]
    fn methods() {
        assert_eq!(Method::parse("GET"), Some(Method::Get));
        assert_eq!(Method::parse("get"), None);
        assert_eq!(Method::parse("TRACE"), None);
        assert_eq!(Method::parse("CONNECT"), None);
        assert_eq!(Method::from_wit("delete"), Some(Method::Delete));
        assert!(Method::Post.changes() && !Method::Options.changes());
    }
}
