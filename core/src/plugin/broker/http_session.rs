//! Session logins for `[http]` (plugin API 1.3, design D; `docs/plans/PLUG-API-13.md` section 5
//! and `docs/design/VMW-ESXI.md` section 8). For servers whose login is a request, not a
//! header (VMware SOAP `Login` on a standalone ESXi): the core sends the login body itself,
//! keeps the session cookie, and adds it to the plugin's requests. The plugin never sees the
//! password, the login answer or the cookie.
//!
//! Pure logic, like the rest of the broker. The relay runs the exchange.

use std::time::Duration;

use quick_xml::events::Event;
use quick_xml::Reader;
use zeroize::Zeroizing;

use super::http::{valid_prefix, HttpResponse};
use super::Failure;

/// A login or logout body, as the manifest writes it.
pub const MAX_LOGIN_BODY_BYTES: usize = 4 * 1024;
pub const MAX_COOKIE_NAME_BYTES: usize = 64;
/// A session cookie value the core keeps.
pub const MAX_COOKIE_VALUE_BYTES: usize = 4 * 1024;
/// Failed logins per (entry, host) before the core waits [`LOGIN_BACKOFF`].
pub const MAX_FAILED_LOGINS: u32 = 3;
pub const LOGIN_BACKOFF: Duration = Duration::from_secs(60);
/// Live sessions the core holds to one host at once, over every helper.
pub const MAX_SESSIONS_PER_HOST: usize = 2;
/// A logout is best effort: this long at most, and the cookie is dropped anyway.
pub const LOGOUT_TIMEOUT: Duration = Duration::from_secs(2);

/// Fixed failure texts: never the server's own words (a SOAP fault may quote the request).
pub const LOGIN_FAILED: &str = "The server refused the login.";
pub const LOGIN_BACKING_OFF: &str = "Too many failed logins to this server. Try again in a minute.";
pub const TOO_MANY_SESSIONS: &str = "Gantry already holds the most sessions it opens to this server.";
pub const SESSION_UNENCRYPTED: &str = "The login is never sent unencrypted. Use TLS, or reach the server through a Gantry tunnel.";
pub const SESSION_CALL_REFUSED: &str = "Gantry logs in for the plugin; a plugin may not call the server's session methods.";

/// How a connection type's requests carry the entry's login. Fixed at install, from the signed
/// manifest only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginMethod {
    /// `[http] auth`: a header on each request.
    Auth,
    /// `[http.session]`: the core logs in and sends the cookie.
    Session,
}

/// The manifest's `[http.session]` table, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSession {
    pub login_path: String,
    /// XML (or JSON) with `{secret}` once and `{user}` at most once, in text only.
    pub login_body: String,
    pub content_type: String,
    pub cookie: String,
    pub logout_body: Option<String>,
    /// API 1.4: the session value is read from the login answer's JSON body at this dotted path
    /// (`data.ticket`, Proxmox VE) instead of its `Set-Cookie`; it is still sent as `cookie`.
    pub ticket: Option<String>,
}

/// The connection type's method: what it names, else `auth` when the manifest has one, else
/// `session` when only that is set, else none. `Err` when it names one the manifest lacks, or
/// names nothing while both are set.
pub fn resolve_login(named: Option<&str>, has_auth: bool, has_session: bool) -> Result<Option<LoginMethod>, &'static str> {
    match named {
        Some("auth") if has_auth => Ok(Some(LoginMethod::Auth)),
        Some("session") if has_session => Ok(Some(LoginMethod::Session)),
        Some(_) => Err("connection_types.login"),
        None if has_auth && has_session => Err("connection_types.login"),
        None if has_auth => Ok(Some(LoginMethod::Auth)),
        None if has_session => Ok(Some(LoginMethod::Session)),
        None => Ok(None),
    }
}

/// An RFC 6265 cookie name: a token.
pub fn valid_cookie_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_COOKIE_NAME_BYTES && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

pub fn valid_content_type(t: &str) -> bool {
    matches!(t, "text/xml" | "application/json")
}

/// The login path: a listed-path-style prefix without the closing `/` rule (`/sdk`), inside
/// `paths`.
pub fn valid_login_path(path: &str, paths: &[String]) -> bool {
    let as_prefix = if path.ends_with('/') { path.to_string() } else { format!("{path}/") };
    valid_prefix(&as_prefix) && paths.iter().any(|p| as_prefix.starts_with(p.as_str()) || p.trim_end_matches('/') == path)
}

/// A body template: well-formed XML with one root, no DOCTYPE, only the five predefined
/// entities and character references, and the placeholders only in text nodes. `{secret}` once
/// (`needs_secret`) or never (a logout), `{user}` at most once. A JSON body (content type
/// `application/json`) is checked by [`valid_json_template`] instead.
pub fn valid_xml_template(body: &str, needs_secret: bool) -> bool {
    if body.is_empty() || body.len() > MAX_LOGIN_BODY_BYTES {
        return false;
    }
    let mut reader = Reader::from_str(body);
    reader.config_mut().check_end_names = true;
    let (mut depth, mut roots, mut secrets, mut users) = (0usize, 0usize, 0usize, 0usize);
    loop {
        match reader.read_event() {
            Err(_) => return false,
            Ok(Event::Eof) => break,
            Ok(Event::DocType(_)) => return false,
            Ok(Event::Decl(d)) => {
                if depth > 0 || roots > 0 || placeholder(d.as_bytes()) {
                    return false;
                }
            }
            Ok(Event::Start(s)) => {
                if placeholder(s.as_bytes()) || (depth == 0 && roots > 0) {
                    return false;
                }
                if depth == 0 {
                    roots += 1;
                }
                depth += 1;
            }
            Ok(Event::Empty(s)) => {
                if placeholder(s.as_bytes()) || (depth == 0 && roots > 0) {
                    return false;
                }
                if depth == 0 {
                    roots += 1;
                }
            }
            Ok(Event::End(_)) => depth = depth.saturating_sub(1),
            Ok(Event::Text(t)) => {
                let raw: &[u8] = t.as_bytes();
                if depth == 0 {
                    if !raw.iter().all(u8::is_ascii_whitespace) {
                        return false;
                    }
                    continue;
                }
                secrets += count(raw, b"{secret}");
                users += count(raw, b"{user}");
                // Any other brace would be a placeholder the core does not fill.
                if count(raw, b"{") != count(raw, b"{secret}") + count(raw, b"{user}") {
                    return false;
                }
            }
            Ok(Event::GeneralRef(r)) => {
                let name: &[u8] = r.as_bytes();
                let predefined = matches!(name, b"lt" | b"gt" | b"amp" | b"quot" | b"apos");
                if !(predefined || r.is_char_ref()) || depth == 0 {
                    return false;
                }
            }
            Ok(Event::CData(c)) => {
                if placeholder(c.as_bytes()) {
                    return false;
                }
            }
            Ok(Event::Comment(c)) => {
                if placeholder(c.as_bytes()) {
                    return false;
                }
            }
            Ok(Event::PI(_)) => return false,
        }
    }
    depth == 0 && roots == 1 && users <= 1 && secrets == usize::from(needs_secret)
}

/// A JSON body template: `{secret}`/`{user}` only as whole JSON string values (`"{secret}"`).
pub fn valid_json_template(body: &str, needs_secret: bool) -> bool {
    const S: &str = "\u{E000}secret";
    const U: &str = "\u{E000}user";
    if body.is_empty() || body.len() > MAX_LOGIN_BODY_BYTES || body.contains('\u{E000}') {
        return false;
    }
    let probe = body.replace("\"{secret}\"", &format!("\"{S}\"")).replace("\"{user}\"", &format!("\"{U}\""));
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&probe) else { return false };
    if !v.is_object() {
        return false;
    }
    let (mut s, mut u) = (0usize, 0usize);
    if !json_text_ok(&v, S, U, &mut s, &mut u) {
        return false;
    }
    s == usize::from(needs_secret) && u <= 1
}

/// Placeholders only as whole string values; no other brace anywhere; never in a key.
fn json_text_ok(v: &serde_json::Value, s: &str, u: &str, secrets: &mut usize, users: &mut usize) -> bool {
    match v {
        serde_json::Value::String(t) if t == s => {
            *secrets += 1;
            true
        }
        serde_json::Value::String(t) if t == u => {
            *users += 1;
            true
        }
        serde_json::Value::String(t) => !t.contains('{') && !t.contains('\u{E000}'),
        serde_json::Value::Array(a) => a.iter().all(|x| json_text_ok(x, s, u, secrets, users)),
        serde_json::Value::Object(o) => o.iter().all(|(k, x)| !k.contains('{') && !k.contains('\u{E000}') && json_text_ok(x, s, u, secrets, users)),
        _ => true,
    }
}

pub fn valid_template(body: &str, content_type: &str, needs_secret: bool) -> bool {
    match content_type {
        "text/xml" => valid_xml_template(body, needs_secret),
        "application/json" => valid_json_template(body, needs_secret),
        _ => false,
    }
}

/// Any brace outside a text node: a placeholder the core would not fill there.
fn placeholder(b: &[u8]) -> bool {
    contains(b, b"{")
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    count(hay, needle) > 0
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || needle.len() > hay.len() {
        return 0;
    }
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

/// XML text escaping: `&`, `<`, `>`, `"`, `'`. A control byte other than tab, CR or LF cannot
/// be written in XML 1.0 and fails.
pub fn xml_escape(text: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() + 16));
    for &b in text {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\'' => out.extend_from_slice(b"&apos;"),
            b if b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r') => return None,
            b => out.push(b),
        }
    }
    Some(out)
}

/// A JSON string's inside, escaped.
fn json_escape(text: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let s = std::str::from_utf8(text).ok()?;
    let quoted = Zeroizing::new(serde_json::to_string(s).ok()?);
    Some(Zeroizing::new(quoted.as_bytes()[1..quoted.len() - 1].to_vec()))
}

/// The login (or logout) body with the user name and password in. Wiped on drop; never logged.
pub fn render(template: &str, content_type: &str, user: &str, secret: &[u8]) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let bad = || Failure::Invalid("the saved login cannot be written into the login request".into());
    let esc = |b: &[u8]| if content_type == "application/json" { json_escape(b) } else { xml_escape(b) };
    let user = esc(user.as_bytes()).ok_or_else(bad)?;
    let secret = esc(secret).ok_or_else(bad)?;
    let mut out = Zeroizing::new(Vec::with_capacity(template.len() + secret.len() + user.len()));
    let mut rest = template.as_bytes();
    while !rest.is_empty() {
        if rest.starts_with(b"{secret}") {
            out.extend_from_slice(&secret);
            rest = &rest[8..];
        } else if rest.starts_with(b"{user}") {
            out.extend_from_slice(&user);
            rest = &rest[6..];
        } else {
            out.push(rest[0]);
            rest = &rest[1..];
        }
    }
    Ok(out)
}

/// The XML-escaped form of a secret, for the echo check: a SOAP fault may quote it escaped.
pub fn escaped_forms(secret: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut v = Vec::new();
    if let Some(e) = xml_escape(secret).filter(|e| e.as_slice() != secret) {
        v.push(e);
    }
    if let Some(e) = json_escape(secret).filter(|e| e.as_slice() != secret) {
        v.push(e);
    }
    v
}

/// The login request the core writes. Wiped on drop.
pub fn login_request(session: &HttpSession, body: &[u8], host: &str, plugin_id: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() + 256));
    out.extend_from_slice(format!("POST {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Gantry-plugin/{plugin_id}\r\nContent-Type: {}; charset=utf-8\r\n", session.login_path, session.content_type).as_bytes());
    if session.content_type == "text/xml" {
        out.extend_from_slice(b"SOAPAction: \"urn:vim25\"\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

/// The logout request: the login request's shape, with the cookie.
pub fn logout_request(session: &HttpSession, body: &[u8], host: &str, plugin_id: &str, cookie: &str) -> Option<Zeroizing<Vec<u8>>> {
    session.logout_body.as_ref()?;
    Some(with_cookie(&login_request(session, body, host, plugin_id), &session.cookie, cookie))
}

/// The cookie's value from the login answer's own `Set-Cookie` headers: only a success status,
/// only the named cookie, and only a value an HTTP header can carry.
pub fn session_cookie(resp: &HttpResponse, name: &str) -> Option<Zeroizing<String>> {
    if !(200..300).contains(&resp.status) {
        return None;
    }
    resp.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie")).find_map(|(_, v)| {
        let pair = v.split(';').next()?.trim();
        let (n, value) = pair.split_once('=')?;
        let value = value.trim().trim_matches('"');
        let ok = n.trim() == name && cookie_value_ok(value);
        ok.then(|| Zeroizing::new(value.to_string()))
    })
}

/// A dotted JSON path (`data.ticket`): 1 to 4 segments of ASCII letters, digits and `_`.
pub fn valid_ticket_path(path: &str) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    (1..=4).contains(&parts.len()) && parts.iter().all(|p| !p.is_empty() && p.len() <= 32 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
}

/// The session value from the login answer: the JSON body's string at `spec.ticket` when the
/// manifest names one, else the `Set-Cookie` header. Only a success status, and only a value a
/// cookie header can carry.
pub fn session_value(resp: &HttpResponse, spec: &HttpSession) -> Option<Zeroizing<String>> {
    let Some(path) = spec.ticket.as_deref() else { return session_cookie(resp, &spec.cookie) };
    if !(200..300).contains(&resp.status) {
        return None;
    }
    let mut body: serde_json::Value = serde_json::from_slice(&resp.body).ok()?;
    let pointer = format!("/{}", path.replace('.', "/"));
    let value = match body.pointer_mut(&pointer).map(serde_json::Value::take) {
        Some(serde_json::Value::String(s)) => Some(Zeroizing::new(s)),
        _ => None,
    };
    // The answer's other strings (Proxmox's CSRF token) are wiped too.
    wipe_strings(&mut body);
    value.filter(|v| cookie_value_ok(v))
}

fn wipe_strings(v: &mut serde_json::Value) {
    use zeroize::Zeroize;
    match v {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(a) => a.iter_mut().for_each(wipe_strings),
        serde_json::Value::Object(o) => o.values_mut().for_each(wipe_strings),
        _ => {}
    }
}

fn cookie_value_ok(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_COOKIE_VALUE_BYTES && value.bytes().all(|b| (0x21..=0x7e).contains(&b) && !matches!(b, b'"' | b',' | b';' | b'\\'))
}

/// The plugin's request with `Cookie: name=value` after the request line. Wiped on drop.
pub fn with_cookie(wire: &[u8], name: &str, value: &str) -> Zeroizing<Vec<u8>> {
    let split = wire.windows(2).position(|w| w == b"\r\n").map(|i| i + 2).unwrap_or(wire.len());
    let mut out = Zeroizing::new(Vec::with_capacity(wire.len() + name.len() + value.len() + 12));
    out.extend_from_slice(&wire[..split]);
    out.extend_from_slice(b"Cookie: ");
    out.extend_from_slice(name.as_bytes());
    out.push(b'=');
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&wire[split..]);
    out
}

/// Session answers never carry `Set-Cookie` to the plugin.
pub fn strip_set_cookie(resp: &mut HttpResponse) {
    resp.headers.retain(|(n, _)| !n.eq_ignore_ascii_case("set-cookie") && !n.eq_ignore_ascii_case("set-cookie2"));
}

/// The session ended on the server: 401, or a SOAP `NotAuthenticated` fault.
pub fn not_authenticated(resp: &HttpResponse) -> bool {
    resp.status == 401 || (resp.status == 500 && soap_fault_is(&resp.body, b"NotAuthenticated"))
}

/// Whether the body is a SOAP fault whose `detail` names `fault` (`NotAuthenticated`, or with
/// the `Fault` suffix), as an element inside `Fault`/`detail`: the word elsewhere, such as in a
/// `faultstring` the server copied from the request, does not count (review MEDIUM 2).
fn soap_fault_is(body: &[u8], fault: &[u8]) -> bool {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().check_end_names = true;
    let mut path: Vec<Vec<u8>> = Vec::new();
    loop {
        match reader.read_event() {
            Err(_) | Ok(Event::Eof) | Ok(Event::DocType(_)) => return false,
            Ok(e @ (Event::Start(_) | Event::Empty(_))) => {
                let (Event::Start(s) | Event::Empty(s)) = &e else { unreachable!() };
                let name = s.local_name();
                let local = name.into_inner().as_bytes().to_vec();
                let n = path.len();
                let in_detail = n >= 2 && path[n - 1] == b"detail" && path[n - 2] == b"Fault";
                if in_detail && (local == fault || local == [fault, b"Fault"].concat()) {
                    return true;
                }
                if n > 32 {
                    return false;
                }
                if matches!(e, Event::Start(_)) {
                    path.push(local);
                }
            }
            Ok(Event::End(_)) => {
                path.pop();
            }
            Ok(_) => {}
        }
    }
}

/// `SessionManager` methods a plugin may not call itself (review MEDIUM 4). `/sdk` stays
/// reachable: every ESXi inventory and power call is a SOAP POST to it.
const SESSION_METHODS: [&[u8]; 9] = [b"Login", b"AcquireCloneTicket", b"AcquireSessionTicket", b"ImpersonateUser", b"SessionIsActive", b"CloneSession", b"Logout", b"TerminateSession", b"AcquireGenericServiceTicket"];

/// Whether a SOAP body calls a [`SESSION_METHODS`] method: an element whose local name starts
/// with `Login` or is one of the others, anywhere in the body, in any namespace prefix. A body
/// that does not parse as XML is refused too (it could hide one).
pub fn calls_session_method(body: &[u8]) -> bool {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().check_end_names = false;
    loop {
        match reader.read_event() {
            Err(_) => return true,
            Ok(Event::Eof) => return false,
            Ok(Event::DocType(_)) => return true,
            Ok(Event::Start(s)) | Ok(Event::Empty(s)) => {
                let name = s.local_name();
                let local: &[u8] = name.into_inner().as_bytes();
                if local.starts_with(b"Login") || SESSION_METHODS[1..].contains(&local) {
                    return true;
                }
            }
            Ok(_) => {}
        }
    }
}

/// The plugin's target is the login path or below it (`/sdk`, `/sdk/`, `/sdk/vimService`), with
/// or without a query (review HIGH 1).
pub fn targets_login_path(target: &str, login_path: &str) -> bool {
    let path = target.split(['?', '#']).next().unwrap_or("");
    let base = login_path.trim_end_matches('/');
    path == base || path.starts_with(&format!("{base}/"))
}

#[cfg(test)]
#[path = "http_session_tests.rs"]
mod tests;
