//! Session logins on the relay (design D, `docs/design/VMW-ESXI.md` section 8). A child of the
//! relay: it uses the worker's connection, TLS and route, so the login travels on the same
//! pinned connection as the request it serves, and the cookie never goes anywhere else.
//!
//! The cookie's scope is one [`SessionState`]: one view (entry, plugin, resolved connection
//! type) and the entry's host, per port. It is attached only on a connection the relay opened
//! to the entry's host; the relay never follows a redirect, so a `Location` elsewhere gets
//! nothing.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};

use zeroize::Zeroizing;

use super::{io_failure, Conn, EntryRoute, Job, Timed};
use crate::plugin::broker::http::{host_header, HttpResponse, ResponseReader};
use crate::plugin::broker::http_session::{self as hs, HttpSession};
use crate::plugin::broker::secret::SecretCheck;
use crate::plugin::broker::stream::TlsMode;
use crate::plugin::broker::Failure;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

/// Live sessions per host, and failed logins per (entry, host), over every helper.
#[derive(Default)]
struct Book {
    live: HashMap<String, usize>,
    fails: HashMap<String, (u32, Option<Instant>)>,
}

fn book() -> std::sync::MutexGuard<'static, Book> {
    static BOOK: OnceLock<Mutex<Book>> = OnceLock::new();
    BOOK.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

fn host_key(host: &str, port: u16) -> String {
    format!("{}:{port}", host.trim().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase())
}

/// The session login one view holds: the manifest's `[http.session]`, the entry's login, the
/// cookies per port, and the secret check over the password and every cookie.
pub struct SessionState {
    /// One login at a time per port (review MEDIUM 3): a second worker waits and reuses it.
    logins: Mutex<BTreeMap<u16, Arc<Mutex<()>>>>,
    spec: HttpSession,
    user: String,
    secret: Zeroizing<Vec<u8>>,
    plugin_id: String,
    entry_id: String,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// Per port: the cookie and the host key whose live count it holds.
    cookies: BTreeMap<u16, (Zeroizing<String>, String)>,
    check: SecretCheck,
}

impl std::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionState(<withheld>)")
    }
}

impl SessionState {
    pub fn new(spec: HttpSession, user: String, secret: Zeroizing<Vec<u8>>, plugin_id: &str, entry_id: &str) -> Arc<SessionState> {
        let mut check = SecretCheck::new();
        check.add(&secret);
        for form in hs::escaped_forms(&secret) {
            check.add(&form);
        }
        Arc::new(SessionState { logins: Mutex::new(BTreeMap::new()), spec, user, secret, plugin_id: plugin_id.to_string(), entry_id: entry_id.to_string(), inner: Mutex::new(Inner { cookies: BTreeMap::new(), check }) })
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `bytes` hold the password or a cookie, in any form the check knows.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.inner().check.matches(bytes)
    }

    pub fn spec(&self) -> &HttpSession {
        &self.spec
    }

    /// Live cookies (tests).
    pub fn cookies(&self) -> usize {
        self.inner().cookies.len()
    }

    fn cookie(&self, port: u16) -> Option<Zeroizing<String>> {
        self.inner().cookies.get(&port).map(|(c, _)| c.clone())
    }

    fn port_lock(&self, port: u16) -> Arc<Mutex<()>> {
        self.logins.lock().unwrap_or_else(|e| e.into_inner()).entry(port).or_default().clone()
    }

    /// The server ended the session `cookie`: drop it and its place in the host count, and
    /// return it for a logout. A cookie another worker already replaced is left alone.
    fn forget(&self, port: u16, cookie: &str) -> Option<Zeroizing<String>> {
        let mut inner = self.inner();
        if inner.cookies.get(&port).is_none_or(|(c, _)| c.as_str() != cookie) {
            return None;
        }
        let (old, key) = inner.cookies.remove(&port)?;
        drop(inner);
        release(&key);
        Some(old)
    }

    fn fail_key(&self, job: &Job) -> String {
        format!("{}|{}", self.entry_id, host_key(&job.host, job.port))
    }

    /// A failed login, or a fresh session the server refused at once (review MEDIUM 2): after
    /// [`hs::MAX_FAILED_LOGINS`] the core waits [`hs::LOGIN_BACKOFF`].
    fn record_failure(&self, job: &Job) {
        let mut b = book();
        let entry = b.fails.entry(self.fail_key(job)).or_insert((0, None));
        entry.0 += 1;
        if entry.0 >= hs::MAX_FAILED_LOGINS {
            entry.1 = Some(Instant::now() + hs::LOGIN_BACKOFF);
        }
    }

    /// A fresh session served a request: the failure count starts again.
    fn clear_failures(&self, job: &Job) {
        book().fails.remove(&self.fail_key(job));
    }

    /// Takes every cookie (helper stop, vault lock, entry close), releasing the host count.
    pub fn take_all(&self) -> Vec<(u16, Zeroizing<String>)> {
        let all = std::mem::take(&mut self.inner().cookies);
        all.into_iter()
            .map(|(port, (c, key))| {
                release(&key);
                (port, c)
            })
            .collect()
    }

    /// Logs in on `conn` (TLS already up, or the core's tunnel): the core writes the body and
    /// reads the answer; the plugin sees neither. The cookie joins the secret check before
    /// anything else can read it. Returns the cookie and the one it replaced, if any (for a
    /// logout). The caller holds the port's login lock.
    fn login(&self, job: &Job, conn: &mut Conn, deadline: Instant) -> Result<(Zeroizing<String>, Option<Zeroizing<String>>), Failure> {
        let key = host_key(&job.host, job.port);
        let fail_key = self.fail_key(job);
        {
            // The check and the reservation in one critical section (review LOW 4).
            let mut b = book();
            if let Some((_, Some(until))) = b.fails.get(&fail_key) {
                if Instant::now() < *until {
                    return Err(Failure::Denied(hs::LOGIN_BACKING_OFF.into()));
                }
                b.fails.remove(&fail_key);
            }
            let live = b.live.entry(key.clone()).or_insert(0);
            if *live >= hs::MAX_SESSIONS_PER_HOST {
                return Err(Failure::Denied(hs::TOO_MANY_SESSIONS.into()));
            }
            *live += 1;
        }
        let body = hs::render(&self.spec.login_body, &self.spec.content_type, &self.user, &self.secret).inspect_err(|_| release(&key))?;
        let host = host_header(&job.host, job.port, job.tls.mode != TlsMode::Off);
        let wire = hs::login_request(&self.spec, &body, &host, &self.plugin_id);
        drop(body);
        let answer = raw_exchange(conn, &wire, deadline, false);
        drop(wire);
        let (found, keep, failed) = match answer {
            Ok((mut resp, keep)) => {
                let c = hs::session_value(&resp, &self.spec);
                wipe(&mut resp);
                (c, keep, None)
            }
            Err(f) => (None, false, Some(f)),
        };
        let Some(cookie) = found else {
            release(&key);
            self.record_failure(job);
            // A network failure keeps its kind (timed out, refused); a refusal gets fixed words.
            return Err(match failed {
                Some(f @ (Failure::TimedOut | Failure::Io(_))) => f,
                _ => Failure::Denied(hs::LOGIN_FAILED.into()),
            });
        };
        let replaced = {
            let mut inner = self.inner();
            inner.check.add(cookie.as_bytes());
            inner.cookies.insert(job.port, (cookie.clone(), key))
        };
        let replaced = replaced.map(|(old, old_key)| {
            release(&old_key);
            old
        });
        if !keep {
            if let Some(old) = replaced {
                job.logout_later(self, old);
            }
            return Err(Failure::Io("the server closed the connection after the login; try again".into()));
        }
        Ok((cookie, replaced))
    }
}

/// The login answer is wiped once the cookie is read (review LOW 5).
fn wipe(resp: &mut HttpResponse) {
    use zeroize::Zeroize;
    resp.body.zeroize();
    for (n, v) in resp.headers.iter_mut() {
        n.zeroize();
        v.zeroize();
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        let _ = self.take_all();
    }
}

fn release(key: &str) {
    let mut b = book();
    if let Some(n) = b.live.get_mut(key) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            b.live.remove(key);
        }
    }
}

/// One write and one answer on `conn`, within `deadline`.
fn raw_exchange(conn: &mut Conn, wire: &[u8], deadline: Instant, head: bool) -> Result<(HttpResponse, bool), Failure> {
    let mut timed = Timed { conn, deadline, cancel: None };
    timed.set_timeouts()?;
    match &mut timed.conn {
        Conn::Plain(s) => s.write_all(wire).and_then(|_| s.flush()),
        Conn::Tls(t) => t.write_all(wire).and_then(|_| t.flush()),
        Conn::Dead => return Err(Failure::Io("the connection failed".into())),
    }
    .map_err(|e| io_failure(&e))?;
    ResponseReader::new(&mut timed).read(head)
}

impl Job {
    /// Plain HTTP carries a session login only through the core's own tunnel listener: never
    /// because the entry's host is a loopback address.
    fn session_transport_ok(&self) -> bool {
        self.tls.mode != TlsMode::Off || matches!(self.tls.route, EntryRoute::Forward { .. })
    }

    /// TLS up (the pin checked) before any byte of a login goes out. A failed handshake sends
    /// nothing.
    fn session_ready(&self, conn: &mut Conn, tls_up: impl FnOnce(bool)) -> Result<(), Failure> {
        if !self.session_transport_ok() {
            return Err(Failure::Denied(hs::SESSION_UNENCRYPTED.into()));
        }
        if self.tls.mode != TlsMode::Off && matches!(conn, Conn::Plain(_)) {
            self.start_tls(conn)?;
            tls_up(true);
        }
        Ok(())
    }

    /// The port's cookie, or a fresh login under the port's lock (review MEDIUM 3): a worker
    /// that waited reuses the login another one just made. `refused` is a cookie the server
    /// just refused; it is never handed out again. Returns whether the cookie is fresh.
    fn session_cookie(&self, conn: &mut Conn, state: &Arc<SessionState>, deadline: Instant, refused: Option<&str>) -> Result<(Zeroizing<String>, bool), Failure> {
        let lock = state.port_lock(self.port);
        let _one = lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = state.cookie(self.port).filter(|c| Some(c.as_str()) != refused) {
            return Ok((c, false));
        }
        let (cookie, replaced) = state.login(self, conn, deadline)?;
        if let Some(old) = replaced {
            self.logout_later(state, old);
        }
        Ok((cookie, true))
    }

    /// The plugin's request with the session cookie: logs in first when this port has none,
    /// and once more after a 401 or `NotAuthenticated` fault. No retry loop: a second refusal
    /// is the plugin's answer, and a fresh session refused at once counts as a failed login
    /// (review MEDIUM 2). `Set-Cookie` never reaches the plugin.
    pub(super) fn session_exchange(&self, conn: &mut Conn, wire: &[u8], head: bool, state: &Arc<SessionState>, deadline: Instant, tls_up: impl FnOnce(bool)) -> Result<(HttpResponse, bool), Failure> {
        self.session_ready(conn, tls_up)?;
        let (mut cookie, mut fresh) = self.session_cookie(conn, state, deadline, None)?;
        let mut relogged = false;
        loop {
            let with = hs::with_cookie(wire, &state.spec.cookie, &cookie);
            let (mut resp, keep) = raw_exchange(conn, &with, deadline, head)?;
            if hs::not_authenticated(&resp) {
                if fresh {
                    state.record_failure(self);
                }
                if let Some(old) = state.forget(self.port, &cookie) {
                    self.logout_later(state, old);
                }
                if !relogged && keep {
                    relogged = true;
                    (cookie, fresh) = self.session_cookie(conn, state, deadline, Some(&cookie))?;
                    continue;
                }
            } else if fresh {
                state.clear_failures(self);
            }
            hs::strip_set_cookie(&mut resp);
            return Ok((resp, keep));
        }
    }

    /// A logout of `cookie` on a thread of its own (review MEDIUM 3): an old or refused cookie
    /// is ended on the server too, best effort.
    fn logout_later(&self, state: &SessionState, cookie: Zeroizing<String>) {
        let Some(template) = state.spec.logout_body.clone() else { return };
        let (job, spec, user, plugin_id) = (self.clone(), state.spec.clone(), state.user.clone(), state.plugin_id.clone());
        let _ = std::thread::Builder::new().name("bastion-plugin-logout".into()).spawn(move || job.logout_with(&spec, &template, &user, &plugin_id, &cookie));
    }

    /// Best-effort logout of one cookie, within [`hs::LOGOUT_TIMEOUT`].
    pub(super) fn logout(&self, state: &SessionState, cookie: &str) {
        if let Some(template) = state.spec.logout_body.as_deref() {
            self.logout_with(&state.spec, template, &state.user, &state.plugin_id, cookie);
        }
    }

    fn logout_with(&self, spec: &HttpSession, template: &str, user: &str, plugin_id: &str, cookie: &str) {
        if !self.session_transport_ok() {
            return;
        }
        let Ok(body) = hs::render(template, &spec.content_type, user, b"") else { return };
        let host = host_header(&self.host, self.port, self.tls.mode != TlsMode::Off);
        let Some(wire) = hs::logout_request(spec, &body, &host, plugin_id, cookie) else { return };
        let deadline = Instant::now() + hs::LOGOUT_TIMEOUT;
        let Ok((sock, _gate)) = self.connect() else { return };
        let _ = sock.set_read_timeout(Some(hs::LOGOUT_TIMEOUT));
        let _ = sock.set_write_timeout(Some(hs::LOGOUT_TIMEOUT));
        let mut conn = Conn::Plain(sock);
        if self.tls.mode != TlsMode::Off && self.start_tls(&mut conn).is_err() {
            return;
        }
        if let Ok((mut resp, _)) = raw_exchange(&mut conn, &wire, deadline, false) {
            wipe(&mut resp);
        }
    }
}

/// Logs out every cookie on a thread of its own, the cookies already taken from `state`.
pub(super) fn logout_all(jobs: Vec<Job>, state: Arc<SessionState>) -> Option<std::thread::JoinHandle<()>> {
    let cookies = state.take_all();
    if cookies.is_empty() || state.spec.logout_body.is_none() {
        return None;
    }
    std::thread::Builder::new()
        .name("bastion-plugin-logout".into())
        .spawn(move || {
            for (port, cookie) in cookies {
                if let Some(job) = jobs.iter().find(|j| j.port == port) {
                    job.logout(&state, &cookie);
                }
            }
        })
        .ok()
}
