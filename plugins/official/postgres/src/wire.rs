//! The PostgreSQL frontend/backend protocol, version 3.0: the messages this plugin sends and
//! the ones it reads. Pure byte handling, no I/O.
//!
//! Every length the server sends is checked before anything is allocated: one backend message
//! is at most [`MAX_MESSAGE`] bytes, and a row's field count and field lengths must fit inside
//! the message that holds them.

use std::fmt;

/// The largest backend message this plugin accepts (a DataRow with a large value, say).
pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;
/// `SSLRequest` code.
const SSL_REQUEST: i32 = 80877103;
/// `CancelRequest` code.
const CANCEL_REQUEST: i32 = 80877102;
/// Protocol 3.0.
const PROTOCOL: i32 = 196608;

/// A protocol error: the server sent something this plugin does not accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError(pub String);

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the server sent a message this client does not understand: {}", self.0)
    }
}

fn bad(why: &str) -> ProtocolError {
    ProtocolError(why.into())
}

// ---- Frontend ------------------------------------------------------------------------------

fn framed(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(tag);
    out.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn cstr(out: &mut Vec<u8>, s: &str) -> Result<(), ProtocolError> {
    if s.as_bytes().contains(&0) {
        return Err(bad("a value holds a NUL byte"));
    }
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    Ok(())
}

/// `SSLRequest`: 8 bytes, answered by one byte, `S` or `N`.
pub fn ssl_request() -> Vec<u8> {
    let mut out = 8i32.to_be_bytes().to_vec();
    out.extend_from_slice(&SSL_REQUEST.to_be_bytes());
    out
}

/// `StartupMessage` with `user`, `database` and the client's own parameters.
pub fn startup(user: &str, database: &str, application: &str) -> Result<Vec<u8>, ProtocolError> {
    let mut body = PROTOCOL.to_be_bytes().to_vec();
    for (k, v) in [("user", user), ("database", database), ("application_name", application), ("client_encoding", "UTF8")] {
        cstr(&mut body, k)?;
        cstr(&mut body, v)?;
    }
    body.push(0);
    let mut out = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    Ok(out)
}

/// `CancelRequest` for the session with `pid` and `secret` (16 bytes, sent on a new stream).
pub fn cancel_request(pid: i32, secret: i32) -> Vec<u8> {
    let mut out = 16i32.to_be_bytes().to_vec();
    out.extend_from_slice(&CANCEL_REQUEST.to_be_bytes());
    out.extend_from_slice(&pid.to_be_bytes());
    out.extend_from_slice(&secret.to_be_bytes());
    out
}

/// `SASLInitialResponse` for `mechanism`.
pub fn sasl_initial(mechanism: &str, data: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut body = Vec::new();
    cstr(&mut body, mechanism)?;
    body.extend_from_slice(&(data.len() as i32).to_be_bytes());
    body.extend_from_slice(data);
    Ok(framed(b'p', &body))
}

/// `SASLResponse`.
pub fn sasl_response(data: &[u8]) -> Vec<u8> {
    framed(b'p', data)
}

/// `PasswordMessage` (cleartext; only ever sent once TLS is up, which the core enforces).
pub fn password(secret: &str) -> Result<Vec<u8>, ProtocolError> {
    let mut body = Vec::new();
    cstr(&mut body, secret)?;
    Ok(framed(b'p', &body))
}

/// `Query` (the simple query protocol).
pub fn query(sql: &str) -> Result<Vec<u8>, ProtocolError> {
    let mut body = Vec::new();
    cstr(&mut body, sql)?;
    Ok(framed(b'Q', &body))
}

/// One statement with the extended protocol (PLUG-08b): `Parse` (unnamed, no parameters),
/// `Bind`, `Describe` (portal), `Execute` (all rows) and `Sync`, in one write. The server's
/// `Parse` refuses text with more than one statement, so nothing can be appended after the
/// statement the plugin built. Results come back in text format.
pub fn extended(sql: &str) -> Result<Vec<u8>, ProtocolError> {
    let mut parse = Vec::new();
    cstr(&mut parse, "")?;
    cstr(&mut parse, sql)?;
    parse.extend_from_slice(&0i16.to_be_bytes());
    let mut bind = Vec::new();
    cstr(&mut bind, "")?;
    cstr(&mut bind, "")?;
    bind.extend_from_slice(&0i16.to_be_bytes()); // parameter formats
    bind.extend_from_slice(&0i16.to_be_bytes()); // parameters
    bind.extend_from_slice(&0i16.to_be_bytes()); // result formats: all text
    let mut describe = vec![b'P'];
    cstr(&mut describe, "")?;
    let mut execute = Vec::new();
    cstr(&mut execute, "")?;
    execute.extend_from_slice(&0i32.to_be_bytes());
    let mut out = framed(b'P', &parse);
    out.extend(framed(b'B', &bind));
    out.extend(framed(b'D', &describe));
    out.extend(framed(b'E', &execute));
    out.extend(framed(b'S', &[]));
    Ok(out)
}

/// `Terminate`.
pub fn terminate() -> Vec<u8> {
    framed(b'X', &[])
}

// ---- Backend -------------------------------------------------------------------------------

/// One column of a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub type_oid: u32,
}

/// The fields of an `ErrorResponse` or `NoticeResponse` this plugin shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerError {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
    /// 1-based character position in the query.
    pub position: Option<u32>,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.severity, self.message)?;
        if let Some(d) = &self.detail {
            write!(f, " ({d})")?;
        }
        Ok(())
    }
}

/// The authentication requests this plugin knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    Ok,
    Cleartext,
    Md5,
    Sasl(Vec<String>),
    SaslContinue(Vec<u8>),
    SaslFinal(Vec<u8>),
    /// Kerberos, GSSAPI, SSPI and anything newer.
    Other(i32),
}

/// A backend message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    Authentication(Auth),
    BackendKeyData { pid: i32, secret: i32 },
    ParameterStatus { name: String, value: String },
    ReadyForQuery(u8),
    RowDescription(Vec<Column>),
    /// One row: `None` is SQL NULL.
    DataRow(Vec<Option<Vec<u8>>>),
    CommandComplete(String),
    EmptyQuery,
    Error(ServerError),
    Notice(ServerError),
    /// NotificationResponse, CopyInResponse and others this plugin does not act on, by tag.
    Other(u8),
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self.at.checked_add(n).filter(|e| *e <= self.buf.len()).ok_or_else(|| bad("a field runs past the message"))?;
        let s = &self.buf[self.at..end];
        self.at = end;
        Ok(s)
    }
    fn i16(&mut self) -> Result<i16, ProtocolError> {
        Ok(i16::from_be_bytes(self.take(2)?.try_into().expect("2 bytes")))
    }
    fn i32(&mut self) -> Result<i32, ProtocolError> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }
    fn cstr(&mut self) -> Result<String, ProtocolError> {
        let rest = &self.buf[self.at..];
        let n = rest.iter().position(|b| *b == 0).ok_or_else(|| bad("a string without its end"))?;
        let s = String::from_utf8_lossy(&rest[..n]).into_owned();
        self.at += n + 1;
        Ok(s)
    }
    fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.at..];
        self.at = self.buf.len();
        s
    }
}

fn parse_error(body: &[u8]) -> Result<ServerError, ProtocolError> {
    let mut r = Reader { buf: body, at: 0 };
    let mut e = ServerError::default();
    loop {
        let code = r.take(1)?[0];
        if code == 0 {
            break;
        }
        let value = r.cstr()?;
        match code {
            b'V' => e.severity = value,
            b'S' if e.severity.is_empty() => e.severity = value,
            b'C' => e.code = value,
            b'M' => e.message = value,
            b'D' => e.detail = Some(value),
            b'H' => e.hint = Some(value),
            b'P' => e.position = value.parse().ok(),
            _ => {}
        }
    }
    Ok(e)
}

/// Parses one backend message body with its tag.
pub fn parse(tag: u8, body: &[u8]) -> Result<Backend, ProtocolError> {
    let mut r = Reader { buf: body, at: 0 };
    Ok(match tag {
        b'R' => Backend::Authentication(match r.i32()? {
            0 => Auth::Ok,
            3 => Auth::Cleartext,
            5 => Auth::Md5,
            10 => {
                let mut mechs = Vec::new();
                loop {
                    let m = r.cstr()?;
                    if m.is_empty() {
                        break;
                    }
                    mechs.push(m);
                }
                Auth::Sasl(mechs)
            }
            11 => Auth::SaslContinue(r.rest().to_vec()),
            12 => Auth::SaslFinal(r.rest().to_vec()),
            n => Auth::Other(n),
        }),
        b'K' => Backend::BackendKeyData { pid: r.i32()?, secret: r.i32()? },
        b'S' => Backend::ParameterStatus { name: r.cstr()?, value: r.cstr()? },
        b'Z' => Backend::ReadyForQuery(r.take(1)?[0]),
        b'T' => {
            let n = r.i16()?;
            if n < 0 {
                return Err(bad("a negative column count"));
            }
            // Each column takes at least 19 bytes: refuse a count the message cannot hold.
            if (n as usize).saturating_mul(19) > body.len() {
                return Err(bad("more columns than the message holds"));
            }
            let mut cols = Vec::with_capacity(n as usize);
            for _ in 0..n {
                let name = r.cstr()?;
                r.take(6)?; // table oid, column number
                let type_oid = r.i32()? as u32;
                r.take(8)?; // type size, modifier, format
                cols.push(Column { name, type_oid });
            }
            Backend::RowDescription(cols)
        }
        b'D' => {
            let n = r.i16()?;
            if n < 0 || (n as usize).saturating_mul(4) > body.len() {
                return Err(bad("more fields than the message holds"));
            }
            let mut fields = Vec::with_capacity(n as usize);
            for _ in 0..n {
                let len = r.i32()?;
                fields.push(match len {
                    -1 => None,
                    l if l < 0 => return Err(bad("a negative field length")),
                    l => Some(r.take(l as usize)?.to_vec()),
                });
            }
            Backend::DataRow(fields)
        }
        b'C' => Backend::CommandComplete(r.cstr()?),
        b'I' => Backend::EmptyQuery,
        b'E' => Backend::Error(parse_error(body)?),
        b'N' => Backend::Notice(parse_error(body)?),
        other => Backend::Other(other),
    })
}

/// Collects bytes from the stream and hands out whole messages.
#[derive(Debug, Default)]
pub struct Frames {
    buf: Vec<u8>,
}

impl Frames {
    pub fn new() -> Frames {
        Frames::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// How many more bytes the next message needs, at least one; 0 when one is ready.
    pub fn needs(&self) -> usize {
        if self.buf.len() < 5 {
            return 5 - self.buf.len();
        }
        let len = i32::from_be_bytes(self.buf[1..5].try_into().expect("4 bytes"));
        let total = (len.max(4) as usize).saturating_add(1);
        total.saturating_sub(self.buf.len())
    }

    /// The next whole message, if one is ready. The length is checked before the body is
    /// waited for, so a server cannot make the plugin hold more than [`MAX_MESSAGE`].
    pub fn next_message(&mut self) -> Result<Option<Backend>, ProtocolError> {
        if self.buf.len() < 5 {
            return Ok(None);
        }
        let tag = self.buf[0];
        let len = i32::from_be_bytes(self.buf[1..5].try_into().expect("4 bytes"));
        if len < 4 {
            return Err(bad("a message length under 4"));
        }
        let len = len as usize;
        if len > MAX_MESSAGE {
            return Err(bad("a message over 64 MiB"));
        }
        if self.buf.len() < len + 1 {
            return Ok(None);
        }
        let msg = parse(tag, &self.buf[5..len + 1]);
        self.buf.drain(..len + 1);
        msg.map(Some)
    }

    /// Takes one raw byte (the answer to `SSLRequest`), if there is one.
    pub fn take_byte(&mut self) -> Option<u8> {
        if self.buf.is_empty() {
            None
        } else {
            Some(self.buf.remove(0))
        }
    }

    /// Bytes waiting that are not a message yet.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
        framed(tag, body)
    }

    #[test]
    fn startup_and_requests_have_the_documented_layout() {
        assert_eq!(ssl_request(), vec![0, 0, 0, 8, 4, 210, 22, 47]);
        assert_eq!(cancel_request(1, 2), vec![0, 0, 0, 16, 4, 210, 22, 46, 0, 0, 0, 1, 0, 0, 0, 2]);
        let s = startup("u", "d", "Gantry").unwrap();
        assert_eq!(i32::from_be_bytes(s[0..4].try_into().unwrap()) as usize, s.len());
        assert_eq!(&s[4..8], &PROTOCOL.to_be_bytes());
        assert!(s.ends_with(b"UTF8\0\0"));
        assert_eq!(query("SELECT 1").unwrap(), b"Q\0\0\0\x0dSELECT 1\0".to_vec());
        assert_eq!(terminate(), b"X\0\0\0\x04".to_vec());
    }

    #[test]
    fn a_nul_byte_is_refused_not_sent() {
        assert!(query("SELECT 1\0; DROP TABLE x").is_err());
        assert!(startup("u\0x", "d", "a").is_err());
        assert!(password("a\0b").is_err());
    }

    #[test]
    fn rows_and_nulls_parse() {
        let mut f = Frames::new();
        let mut body = 2i16.to_be_bytes().to_vec();
        body.extend_from_slice(&3i32.to_be_bytes());
        body.extend_from_slice(b"abc");
        body.extend_from_slice(&(-1i32).to_be_bytes());
        f.push(&msg(b'D', &body));
        assert_eq!(f.next_message().unwrap(), Some(Backend::DataRow(vec![Some(b"abc".to_vec()), None])));
        assert_eq!(f.buffered(), 0);
    }

    #[test]
    fn messages_arrive_in_pieces() {
        let whole = msg(b'C', b"SELECT 1\0");
        let mut f = Frames::new();
        for b in &whole[..whole.len() - 1] {
            f.push(&[*b]);
            assert_eq!(f.next_message().unwrap(), None);
        }
        assert_eq!(f.needs(), 1);
        f.push(&whole[whole.len() - 1..]);
        assert_eq!(f.next_message().unwrap(), Some(Backend::CommandComplete("SELECT 1".into())));
    }

    #[test]
    fn hostile_lengths_are_refused_before_allocation() {
        let mut f = Frames::new();
        f.push(&[b'D', 0x7f, 0xff, 0xff, 0xff]);
        assert!(f.next_message().is_err());
        let mut f = Frames::new();
        f.push(&[b'D', 0, 0, 0, 3]);
        assert!(f.next_message().is_err());
        // A field count far larger than the message.
        assert!(parse(b'D', &[0x7f, 0xff]).is_err());
        assert!(parse(b'T', &[0x7f, 0xff]).is_err());
        // A field length past the end.
        let mut body = 1i16.to_be_bytes().to_vec();
        body.extend_from_slice(&100i32.to_be_bytes());
        assert!(parse(b'D', &body).is_err());
        let mut body = 1i16.to_be_bytes().to_vec();
        body.extend_from_slice(&(-2i32).to_be_bytes());
        assert!(parse(b'D', &body).is_err());
        // A string with no end.
        assert!(parse(b'C', b"SELECT").is_err());
    }

    #[test]
    fn errors_keep_their_fields() {
        let body = b"SERROR\0VERROR\0C42601\0Msyntax error at or near \"x\"\0P8\0Hcheck it\0\0";
        match parse(b'E', body).unwrap() {
            Backend::Error(e) => {
                assert_eq!(e.severity, "ERROR");
                assert_eq!(e.code, "42601");
                assert_eq!(e.position, Some(8));
                assert_eq!(e.hint.as_deref(), Some("check it"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn authentication_requests_parse() {
        assert_eq!(parse(b'R', &0i32.to_be_bytes()).unwrap(), Backend::Authentication(Auth::Ok));
        let mut b = 10i32.to_be_bytes().to_vec();
        b.extend_from_slice(b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0");
        assert_eq!(parse(b'R', &b).unwrap(), Backend::Authentication(Auth::Sasl(vec!["SCRAM-SHA-256-PLUS".into(), "SCRAM-SHA-256".into()])));
        assert_eq!(parse(b'R', &7i32.to_be_bytes()).unwrap(), Backend::Authentication(Auth::Other(7)));
    }
}
