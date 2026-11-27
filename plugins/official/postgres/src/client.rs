//! A PostgreSQL session over any byte [`Transport`]: TLS request, login, simple queries,
//! server-side cancel. The plugin's transport is the core's stream (`net`); tests use a
//! scripted server.
//!
//! The limits match the built-in page (`core/src/dbclient.rs`): 1,000 rows by default and
//! 100,000 at most, a 30 s timeout by default and an hour at most, 1 MiB of SQL. Read only is the
//! default (`default_transaction_read_only`); it guards against mistakes, it is not a permission
//! boundary.

use std::fmt;

use crate::scram::{Scram, MECHANISM};
use crate::wire::{self, Auth, Backend, Column, Frames, ServerError};

pub const DEFAULT_MAX_ROWS: usize = 1_000;
pub const MAX_ROWS_LIMIT: usize = 100_000;
pub const DEFAULT_TIMEOUT_SECS: u32 = 30;
pub const MAX_TIMEOUT_SECS: u32 = 3_600;
pub const MAX_SQL_BYTES: usize = 1 << 20;
/// Bytes of row data one result keeps, whatever the row count: past it the rest is dropped and
/// the result is marked cut.
pub const MAX_RESULT_BYTES: usize = 64 * 1024 * 1024;
const READ_CHUNK: usize = 256 * 1024;

/// What the plugin needs from a stream.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// At most `max` bytes; empty when the server closed the stream.
    async fn read(&mut self, max: usize) -> Result<Vec<u8>, Error>;
    async fn write(&mut self, data: &[u8]) -> Result<(), Error>;
    /// The core runs TLS with the entry's TLS mode.
    async fn start_tls(&mut self) -> Result<(), Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The core refused, or the network failed; the text is the core's.
    Transport(String),
    Protocol(String),
    Server(ServerError),
    Login(String),
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport(s) | Error::Invalid(s) => f.write_str(s),
            Error::Protocol(s) => write!(f, "the server sent something unexpected: {s}"),
            Error::Server(e) => write!(f, "{e}"),
            Error::Login(s) => write!(f, "login failed: {s}"),
        }
    }
}

impl From<wire::ProtocolError> for Error {
    fn from(e: wire::ProtocolError) -> Error {
        Error::Protocol(e.0)
    }
}

/// How to log in. The secret comes from the core's `entry-login` and is dropped after login.
pub struct Login<'a> {
    pub user: &'a str,
    pub secret: &'a str,
    pub database: &'a str,
}

/// One result set of a statement.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResultSet {
    pub columns: Vec<Column>,
    /// Text values; `None` is NULL.
    pub rows: Vec<Vec<Option<String>>>,
    /// Rows the server sent past the row limit (dropped).
    pub dropped: u64,
    /// The command tag, `SELECT 3` or `UPDATE 1`.
    pub tag: String,
}

/// What a run of SQL gave: every result set, the notices, and the error that ended it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Outcome {
    pub sets: Vec<ResultSet>,
    pub notices: Vec<ServerError>,
    pub error: Option<ServerError>,
}

pub struct Client<T: Transport> {
    t: T,
    frames: Frames,
    /// For `CancelRequest`.
    pub key: Option<(i32, i32)>,
    pub server_version: String,
    /// Whether TLS is up on this stream.
    pub tls: bool,
    read_only: bool,
}

fn utf8(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

impl<T: Transport> Client<T> {
    async fn fill(&mut self) -> Result<(), Error> {
        let want = self.frames.needs().clamp(1, READ_CHUNK);
        let got = self.t.read(want).await?;
        if got.is_empty() {
            return Err(Error::Transport("the server closed the connection".into()));
        }
        self.frames.push(&got);
        Ok(())
    }

    async fn next(&mut self) -> Result<Backend, Error> {
        loop {
            if let Some(m) = self.frames.next_message()? {
                return Ok(m);
            }
            self.fill().await?;
        }
    }

    /// Asks for TLS, logs in, and sets the session up: read only, the timeout.
    /// `nonce` is the SCRAM client nonce (random, printable).
    pub async fn connect(t: T, login: &Login<'_>, nonce: &str, timeout_secs: u32) -> Result<Client<T>, Error> {
        Self::negotiate(t).await?.sign_in(login, nonce, timeout_secs).await
    }

    /// Asks for TLS (and starts it when offered). The app's core releases the login only after
    /// this, so [`Client::sign_in`] follows once the login is in hand.
    pub async fn negotiate(t: T) -> Result<Client<T>, Error> {
        let mut c = Client { t, frames: Frames::new(), key: None, server_version: String::new(), tls: false, read_only: true };
        c.t.write(&wire::ssl_request()).await?;
        let answer = loop {
            if let Some(b) = c.frames.take_byte() {
                break b;
            }
            c.fill().await?;
        };
        match answer {
            b'S' => {
                // Bytes after `S` came before TLS: a man in the middle could have put them
                // there (CVE-2021-23222). Refuse.
                if c.frames.buffered() > 0 {
                    return Err(Error::Protocol("data before the TLS handshake".into()));
                }
                c.t.start_tls().await?;
                c.tls = true;
            }
            // No TLS on offer. The core decides: where the entry's TLS mode needs TLS, it
            // refuses the login and anything past a short preamble.
            b'N' => {}
            // An ErrorResponse to SSLRequest comes from a very old server.
            _ => return Err(Error::Protocol("the server did not answer the TLS request".into())),
        }
        Ok(c)
    }

    /// Logs in after [`Client::negotiate`] and sets the session up.
    pub async fn sign_in(mut self, login: &Login<'_>, nonce: &str, timeout_secs: u32) -> Result<Client<T>, Error> {
        self.t.write(&wire::startup(login.user, login.database, "Gantry")?).await?;
        self.login(login.secret, nonce).await?;
        self.set_up(timeout_secs).await?;
        Ok(self)
    }

    async fn login(&mut self, secret: &str, nonce: &str) -> Result<(), Error> {
        let mut scram: Option<Scram> = None;
        let mut proven = false;
        loop {
            match self.next().await? {
                Backend::Authentication(Auth::Ok) => {
                    // A server that started SCRAM must prove itself before it may say yes.
                    if scram.is_some() && !proven {
                        return Err(Error::Login("the server skipped its SCRAM proof".into()));
                    }
                }
                Backend::Authentication(Auth::Cleartext) => {
                    if !self.tls {
                        return Err(Error::Login("the server asks for the password in clear text without TLS".into()));
                    }
                    self.t.write(&wire::password(secret)?).await?;
                }
                Backend::Authentication(Auth::Md5) => {
                    return Err(Error::Login("the server uses MD5 passwords, which this client does not send; use SCRAM-SHA-256".into()));
                }
                Backend::Authentication(Auth::Sasl(mechs)) => {
                    if scram.is_some() || !mechs.iter().any(|m| m == MECHANISM) {
                        return Err(Error::Login("the server offers no SCRAM-SHA-256".into()));
                    }
                    let s = Scram::new(nonce).map_err(|e| Error::Login(e.0.into()))?;
                    self.t.write(&wire::sasl_initial(MECHANISM, &s.client_first())?).await?;
                    scram = Some(s);
                }
                Backend::Authentication(Auth::SaslContinue(data)) => {
                    let s = scram.as_mut().ok_or_else(|| Error::Protocol("SCRAM out of order".into()))?;
                    let fin = s.client_final(&data, secret.as_bytes()).map_err(|e| Error::Login(e.0.into()))?;
                    self.t.write(&wire::sasl_response(&fin)).await?;
                }
                Backend::Authentication(Auth::SaslFinal(data)) => {
                    let s = scram.as_ref().ok_or_else(|| Error::Protocol("SCRAM out of order".into()))?;
                    s.verify_server(&data).map_err(|e| Error::Login(e.0.into()))?;
                    proven = true;
                }
                Backend::Authentication(Auth::Other(_)) => {
                    return Err(Error::Login("the server asks for a login method this client does not have (Kerberos, GSSAPI or SSPI)".into()));
                }
                Backend::BackendKeyData { pid, secret } => self.key = Some((pid, secret)),
                Backend::ParameterStatus { name, value } => {
                    if name == "server_version" {
                        self.server_version = value;
                    }
                }
                Backend::Notice(_) => {}
                Backend::Error(e) => return Err(Error::Server(e)),
                Backend::ReadyForQuery(_) => return Ok(()),
                _ => return Err(Error::Protocol("an unexpected message during login".into())),
            }
        }
    }

    async fn set_up(&mut self, timeout_secs: u32) -> Result<(), Error> {
        let timeout = timeout_secs.clamp(1, MAX_TIMEOUT_SECS);
        // standard_conforming_strings on: a backslash in '...' is plain text, as the plugin's
        // own SQL checks assume (review of #1346). The checks also refuse text the two
        // settings would read differently.
        let sql = format!("SET SESSION default_transaction_read_only = on; SET SESSION statement_timeout = '{timeout}s'; SET SESSION standard_conforming_strings = on");
        let out = self.run(&sql, 0).await?;
        match out.error {
            Some(e) => Err(Error::Server(e)),
            None => Ok(()),
        }
    }

    /// The stream under the session (for abort bytes).
    pub fn transport(&self) -> &T {
        &self.t
    }

    /// Whether this session is read only.
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Turns "Allow changes" on (`false`) or off (`true`).
    pub async fn set_read_only(&mut self, on: bool) -> Result<(), Error> {
        let sql = if on { "SET SESSION default_transaction_read_only = on" } else { "SET SESSION default_transaction_read_only = off" };
        let out = self.run(sql, 0).await?;
        if let Some(e) = out.error {
            return Err(Error::Server(e));
        }
        self.read_only = on;
        Ok(())
    }

    /// Sets the statement timeout, clamped to 1 s .. 1 h.
    pub async fn set_timeout(&mut self, secs: u32) -> Result<(), Error> {
        let secs = secs.clamp(1, MAX_TIMEOUT_SECS);
        let out = self.run(&format!("SET SESSION statement_timeout = '{secs}s'"), 0).await?;
        out.error.map_or(Ok(()), |e| Err(Error::Server(e)))
    }

    /// The bytes to send on a new stream to cancel what runs now.
    pub fn cancel_bytes(&self) -> Option<Vec<u8>> {
        self.key.map(|(pid, secret)| wire::cancel_request(pid, secret))
    }

    /// Runs `sql` (one or more statements, the simple protocol) and keeps at most `max_rows`
    /// rows per result set. A server error ends the run and is in [`Outcome::error`]; the
    /// session stays usable. `Err` means the session is gone.
    pub async fn run(&mut self, sql: &str, max_rows: usize) -> Result<Outcome, Error> {
        if sql.len() > MAX_SQL_BYTES {
            return Err(Error::Invalid(format!("the SQL is over {} KiB", MAX_SQL_BYTES / 1024)));
        }
        if sql.trim().is_empty() {
            return Err(Error::Invalid("there is no SQL to run".into()));
        }
        self.t.write(&wire::query(sql)?).await?;
        self.collect(max_rows).await
    }

    /// Runs exactly one statement with the extended protocol (PLUG-08b). The server refuses
    /// text with more than one statement ("cannot insert multiple commands into a prepared
    /// statement"); that comes back as [`Outcome::error`].
    pub async fn run_one(&mut self, sql: &str, max_rows: usize) -> Result<Outcome, Error> {
        if sql.len() > MAX_SQL_BYTES {
            return Err(Error::Invalid(format!("the SQL is over {} KiB", MAX_SQL_BYTES / 1024)));
        }
        if sql.trim().is_empty() {
            return Err(Error::Invalid("there is no SQL to run".into()));
        }
        self.t.write(&wire::extended(sql)?).await?;
        self.collect(max_rows).await
    }

    /// Runs one statement inside `BEGIN READ ONLY` ... `ROLLBACK`, whatever the session's
    /// "Allow changes" says, with the extended protocol. Anything the statement changes in the
    /// session (a `set_config` call, say) is rolled back with it.
    pub async fn run_one_read_only(&mut self, sql: &str, max_rows: usize) -> Result<Outcome, Error> {
        let begin = self.run("BEGIN READ ONLY", 0).await?;
        if let Some(e) = begin.error {
            return Ok(Outcome { error: Some(e), ..Default::default() });
        }
        let out = self.run_one(sql, max_rows).await;
        let end = self.run("ROLLBACK", 0).await?;
        let out = out?;
        if out.error.is_none() {
            if let Some(e) = end.error {
                return Ok(Outcome { error: Some(e), ..out });
            }
        }
        Ok(out)
    }

    async fn collect(&mut self, max_rows: usize) -> Result<Outcome, Error> {
        let max_rows = max_rows.min(MAX_ROWS_LIMIT);
        let mut out = Outcome::default();
        let mut set: Option<ResultSet> = None;
        let mut bytes = 0usize;
        loop {
            match self.next().await? {
                Backend::RowDescription(columns) => set = Some(ResultSet { columns, ..Default::default() }),
                Backend::DataRow(fields) => {
                    let s = set.as_mut().ok_or_else(|| Error::Protocol("a row before its columns".into()))?;
                    if fields.len() != s.columns.len() {
                        return Err(Error::Protocol("a row with the wrong number of fields".into()));
                    }
                    let size: usize = fields.iter().map(|f| f.as_ref().map_or(0, Vec::len)).sum();
                    if s.rows.len() >= max_rows || bytes.saturating_add(size) > MAX_RESULT_BYTES {
                        s.dropped += 1;
                    } else {
                        bytes += size;
                        s.rows.push(fields.into_iter().map(|f| f.map(utf8)).collect());
                    }
                }
                Backend::CommandComplete(tag) => {
                    let mut s = set.take().unwrap_or_default();
                    s.tag = tag;
                    out.sets.push(s);
                }
                Backend::EmptyQuery => {}
                Backend::Notice(n) => {
                    if out.notices.len() < 100 {
                        out.notices.push(n);
                    }
                }
                Backend::Error(e) => out.error = Some(e),
                Backend::ReadyForQuery(_) => return Ok(out),
                // ParseComplete, BindComplete, NoData, PortalSuspended (extended protocol).
                Backend::ParameterStatus { .. } | Backend::Other(b'A' | b'1' | b'2' | b'n' | b's') => {}
                Backend::Other(b'G') | Backend::Other(b'H') | Backend::Other(b'W') => {
                    // COPY needs files the plugin does not have here.
                    return Err(Error::Invalid("COPY is not supported in the query tool".into()));
                }
                _ => return Err(Error::Protocol("an unexpected message during a query".into())),
            }
        }
    }

    /// Sends `Terminate`.
    pub async fn close(mut self) {
        let _ = self.t.write(&wire::terminate()).await;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    pub fn block_on<F: Future>(f: F) -> F::Output {
        let mut f = pin!(f);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    pub fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    pub fn auth(code: i32, rest: &[u8]) -> Vec<u8> {
        let mut b = code.to_be_bytes().to_vec();
        b.extend_from_slice(rest);
        msg(b'R', &b)
    }

    pub fn ready() -> Vec<u8> {
        msg(b'Z', b"I")
    }

    pub fn row_desc(names: &[&str]) -> Vec<u8> {
        let mut b = (names.len() as i16).to_be_bytes().to_vec();
        for n in names {
            b.extend_from_slice(n.as_bytes());
            b.push(0);
            b.extend_from_slice(&[0; 6]);
            b.extend_from_slice(&25i32.to_be_bytes());
            b.extend_from_slice(&[0; 8]);
        }
        msg(b'T', &b)
    }

    pub fn data_row(cells: &[Option<&str>]) -> Vec<u8> {
        let mut b = (cells.len() as i16).to_be_bytes().to_vec();
        for c in cells {
            match c {
                None => b.extend_from_slice(&(-1i32).to_be_bytes()),
                Some(s) => {
                    b.extend_from_slice(&(s.len() as i32).to_be_bytes());
                    b.extend_from_slice(s.as_bytes());
                }
            }
        }
        msg(b'D', &b)
    }

    pub fn complete(tag: &str) -> Vec<u8> {
        msg(b'C', format!("{tag}\0").as_bytes())
    }

    pub fn error(code: &str, text: &str) -> Vec<u8> {
        msg(b'E', format!("SERROR\0C{code}\0M{text}\0\0").as_bytes())
    }

    /// A scripted server: each write is answered by the next scripted reply.
    #[derive(Default)]
    pub struct Script {
        pub replies: VecDeque<Vec<u8>>,
        pub incoming: VecDeque<u8>,
        pub written: Vec<Vec<u8>>,
        pub tls_started: bool,
        /// Bytes come back in pieces of this size, to test reassembly.
        pub piece: usize,
    }

    impl Script {
        pub fn new(replies: Vec<Vec<u8>>) -> Script {
            Script { replies: replies.into(), piece: 7, ..Default::default() }
        }
    }

    impl Transport for &mut Script {
        async fn read(&mut self, max: usize) -> Result<Vec<u8>, Error> {
            let n = max.min(self.piece).min(self.incoming.len());
            Ok(self.incoming.drain(..n).collect())
        }
        async fn write(&mut self, data: &[u8]) -> Result<(), Error> {
            self.written.push(data.to_vec());
            if let Some(r) = self.replies.pop_front() {
                self.incoming.extend(r);
            }
            Ok(())
        }
        async fn start_tls(&mut self) -> Result<(), Error> {
            self.tls_started = true;
            Ok(())
        }
    }

    fn login() -> Login<'static> {
        Login { user: "app", secret: "pw", database: "db" }
    }

    const NONCE: &str = "abcdefghijklmnopqrstuvwx";

    /// TLS yes, trust login, set-up answered.
    pub fn trusted_start() -> Vec<Vec<u8>> {
        let mut login_reply = auth(0, b"");
        login_reply.extend(msg(b'K', &[0, 0, 0, 42, 0, 0, 0, 7]));
        login_reply.extend(msg(b'S', b"server_version\x0017.2\0"));
        login_reply.extend(ready());
        let mut setup = complete("SET");
        setup.extend(complete("SET"));
        setup.extend(ready());
        vec![b"S".to_vec(), login_reply, setup]
    }

    #[test]
    fn connect_asks_for_tls_then_logs_in_and_sets_read_only() {
        let mut s = Script::new(trusted_start());
        let c = block_on(Client::connect(&mut s, &login(), NONCE, 30)).unwrap();
        assert!(c.tls && c.read_only());
        assert_eq!(c.key, Some((42, 7)));
        assert_eq!(c.server_version, "17.2");
        assert_eq!(c.cancel_bytes().unwrap(), wire::cancel_request(42, 7));
        drop(c);
        assert!(s.tls_started);
        assert_eq!(s.written[0], wire::ssl_request());
        let setup = String::from_utf8_lossy(&s.written[2]).to_string();
        assert!(setup.contains("default_transaction_read_only = on") && setup.contains("statement_timeout = '30s'"), "{setup}");
        // Review of #1346: backslashes in '...' are plain text, as the plugin's SQL checks assume.
        assert!(setup.contains("standard_conforming_strings = on"), "{setup}");
    }

    #[test]
    fn run_one_uses_the_extended_protocol_and_reads_its_replies() {
        let mut reply = msg(b'1', &[]);
        reply.extend(msg(b'2', &[]));
        reply.extend(row_desc(&["n"]));
        reply.extend(data_row(&[Some("1")]));
        reply.extend(complete("SELECT 1"));
        reply.extend(ready());
        let mut script = trusted_start();
        script.push(reply);
        let mut s = Script::new(script);
        let mut c = block_on(Client::connect(&mut s, &login(), NONCE, 30)).unwrap();
        let out = block_on(c.run_one("SELECT 1", 10)).unwrap();
        assert_eq!(out.sets[0].rows, vec![vec![Some("1".to_string())]]);
        drop(c);
        let w = s.written.last().unwrap();
        assert_eq!(w, &wire::extended("SELECT 1").unwrap());
        // Parse, Bind, Describe, Execute, Sync; no simple Query.
        let tags: Vec<u8> = {
            let mut at = 0;
            let mut t = Vec::new();
            while at < w.len() {
                t.push(w[at]);
                at += 1 + i32::from_be_bytes(w[at + 1..at + 5].try_into().unwrap()) as usize;
            }
            t
        };
        assert_eq!(tags, b"PBDES");
    }

    #[test]
    fn the_server_refusing_two_statements_keeps_the_session() {
        // What PostgreSQL answers to Parse with "a; b": an error, then ReadyForQuery after Sync.
        let mut reply = error("42601", "cannot insert multiple commands into a prepared statement");
        reply.extend(ready());
        let mut again = complete("SELECT 0");
        again.extend(ready());
        let mut script = trusted_start();
        script.extend([reply, again]);
        let mut s = Script::new(script);
        let mut c = block_on(Client::connect(&mut s, &login(), NONCE, 30)).unwrap();
        let out = block_on(c.run_one("SELECT 1; DELETE FROM t", 10)).unwrap();
        assert!(out.error.unwrap().message.contains("multiple commands"));
        assert!(block_on(c.run_one("SELECT 1", 10)).unwrap().error.is_none());
    }

    #[test]
    fn read_only_runs_are_wrapped_and_rolled_back_even_after_an_error() {
        let mut begin = complete("BEGIN");
        begin.extend(ready());
        let mut fail = error("25006", "cannot execute DELETE in a read-only transaction");
        fail.extend(ready());
        let mut end = complete("ROLLBACK");
        end.extend(ready());
        let mut script = trusted_start();
        script.extend([begin, fail, end]);
        let mut s = Script::new(script);
        let mut c = block_on(Client::connect(&mut s, &login(), NONCE, 30)).unwrap();
        let out = block_on(c.run_one_read_only("SELECT 1", 10)).unwrap();
        assert!(out.error.is_some());
        drop(c);
        let n = s.written.len();
        assert!(String::from_utf8_lossy(&s.written[n - 3]).contains("BEGIN READ ONLY"));
        assert_eq!(s.written[n - 2][0], b'P');
        assert!(String::from_utf8_lossy(&s.written[n - 1]).contains("ROLLBACK"));
    }

    #[test]
    fn bytes_after_the_tls_yes_are_refused() {
        let mut s = Script::new(vec![b"Sxxxx".to_vec()]);
        assert!(matches!(block_on(Client::connect(&mut s, &login(), NONCE, 30)), Err(Error::Protocol(_))));
        assert!(!s.tls_started);
    }

    #[test]
    fn cleartext_without_tls_and_md5_are_refused() {
        let mut s = Script::new(vec![b"N".to_vec(), auth(3, b"")]);
        assert!(matches!(block_on(Client::connect(&mut s, &login(), NONCE, 30)), Err(Error::Login(_))));
        // The password never went out.
        assert!(!s.written.iter().any(|w| w.windows(2).any(|x| x == b"pw")));
        let mut s = Script::new(vec![b"S".to_vec(), auth(5, b"salt")]);
        assert!(matches!(block_on(Client::connect(&mut s, &login(), NONCE, 30)), Err(Error::Login(_))));
    }

    #[test]
    fn a_server_that_skips_the_scram_proof_is_refused() {
        let mut s = Script::new(vec![b"S".to_vec(), auth(10, b"SCRAM-SHA-256\0\0"), auth(0, b"")]);
        assert!(matches!(block_on(Client::connect(&mut s, &login(), NONCE, 30)), Err(Error::Login(_))));
    }

    #[test]
    fn a_query_keeps_columns_rows_nulls_and_the_row_limit() {
        let mut s = Script::new(trusted_start());
        let mut c = block_on(Client::connect(&mut s, &login(), NONCE, 30)).unwrap();
        let mut r = row_desc(&["id", "name"]);
        for i in 0..5 {
            r.extend(data_row(&[Some(&i.to_string()), if i == 2 { None } else { Some("x") }]));
        }
        r.extend(complete("SELECT 5"));
        r.extend(ready());
        c.t.replies.push_back(r);
        let out = block_on(c.run("SELECT id, name FROM t", 3)).unwrap();
        assert_eq!(out.error, None);
        let set = &out.sets[0];
        assert_eq!(set.columns.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["id", "name"]);
        assert_eq!(set.rows.len(), 3);
        assert_eq!(set.rows[2][1], None);
        assert_eq!(set.dropped, 2);
        assert_eq!(set.tag, "SELECT 5");
    }

    #[test]
    fn a_server_error_leaves_the_session_usable() {
        let mut s = Script::new(trusted_start());
        let mut c = block_on(Client::connect(&mut s, &login(), NONCE, 30)).unwrap();
        let mut r = error("42601", "syntax error");
        r.extend(ready());
        c.t.replies.push_back(r);
        let out = block_on(c.run("SELEC 1", 10)).unwrap();
        assert_eq!(out.error.unwrap().code, "42601");
        let mut r = row_desc(&["?column?"]);
        r.extend(data_row(&[Some("1")]));
        r.extend(complete("SELECT 1"));
        r.extend(ready());
        c.t.replies.push_back(r);
        assert_eq!(block_on(c.run("SELECT 1", 10)).unwrap().sets[0].rows, vec![vec![Some("1".to_string())]]);
    }

    #[test]
    fn several_statements_give_several_sets() {
        let mut s = Script::new(trusted_start());
        let mut c = block_on(Client::connect(&mut s, &login(), NONCE, 30)).unwrap();
        let mut r = complete("BEGIN");
        r.extend(row_desc(&["a"]));
        r.extend(data_row(&[Some("1")]));
        r.extend(complete("SELECT 1"));
        r.extend(ready());
        c.t.replies.push_back(r);
        let out = block_on(c.run("BEGIN; SELECT 1 AS a", 10)).unwrap();
        assert_eq!(out.sets.len(), 2);
        assert_eq!(out.sets[0].tag, "BEGIN");
        assert!(out.sets[0].columns.is_empty());
    }

    #[test]
    fn sql_limits_and_hostile_rows() {
        let mut s = Script::new(trusted_start());
        let mut c = block_on(Client::connect(&mut s, &login(), NONCE, 30)).unwrap();
        assert!(matches!(block_on(c.run(&"x".repeat(MAX_SQL_BYTES + 1), 10)), Err(Error::Invalid(_))));
        assert!(matches!(block_on(c.run("   ", 10)), Err(Error::Invalid(_))));
        assert!(block_on(c.run("SELECT 1\0", 10)).is_err());
        // A row before its columns, and a row with too many fields.
        let mut r = data_row(&[Some("1")]);
        r.extend(ready());
        c.t.replies.push_back(r);
        assert!(matches!(block_on(c.run("SELECT 1", 10)), Err(Error::Protocol(_))));
    }

    #[test]
    fn allow_changes_switches_the_session() {
        let mut s = Script::new(trusted_start());
        let mut c = block_on(Client::connect(&mut s, &login(), NONCE, 30)).unwrap();
        let mut r = complete("SET");
        r.extend(ready());
        c.t.replies.push_back(r);
        block_on(c.set_read_only(false)).unwrap();
        assert!(!c.read_only());
        drop(c);
        assert!(String::from_utf8_lossy(s.written.last().unwrap()).contains("read_only = off"));
    }
}
