//! The plugin stream relay: `net.*` for real (PLUG-02b part 3; spec section 5, `network` row,
//! "Abort bytes" and "Caps"; T18.2, T18.8, T18.23, T18.24).
//!
//! The helper has no network. A plugin asks the core for a stream to its entry's host, and the
//! core opens the socket, runs TLS with the entry's TLS mode and passes bytes. Every decision is
//! the 02a broker's pure logic: [`StreamGate`] (local per route, the TLS mode, the 512-byte
//! preamble and its secret check), [`StreamCaps`] (16 streams, 30 connects a minute) and
//! [`AbortRegistry`] (abort bytes). This file only does the I/O.
//!
//! - Only the entry's host, on the entry's port or a port the manifest's connection types list.
//! - Direct route only in this build. An entry the app has not marked direct (a gateway, an SSH
//!   tunnel, SOCKS, or not stated) is refused with `denied`: the relay through the core's routes
//!   is a later pull request, and connecting directly would bypass the route the user chose.
//! - The offline guard applies; the name is resolved within the core's lookup budget.
//! - Each stream has one worker thread that owns the socket; the dispatch thread never blocks on
//!   the network. `close` shuts the socket down, so a waiting read ends at once.
//! - TLS is the core's rustls: verify-full against the bundled web roots, or the entry's pin
//!   (SHA-256 of the server's certificate). A certificate that fails gives `denied` naming the
//!   TLS mode; there is no "accept anyway". TLS mode off refuses `start-tls`.
//! - On an ordinary stop the abort bytes go once each, on a new connection to the same address
//!   and port, before TLS. A trust-withdrawing stop sends none.

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use sha2::{Digest, Sha256};

use crate::plugin::broker::abort::{AbortRegistry, ABORT_CLOSE_WAIT_MS, ABORT_CONNECT_TIMEOUT_MS};
use crate::plugin::broker::http::{HttpResponse, ResponseReader, IDLE_MS, MAX_IDLE_PER_PORT, MAX_RESPONSE_BODY_BYTES};
use crate::plugin::broker::secret::SecretCheck;
use crate::plugin::broker::stream::{Route, RoutedTarget, StreamCaps, StreamGate, TlsMode, TLS_MODE_HINT};
use crate::plugin::broker::{Failure, StopReason};
use crate::policy::Policy;

/// One `net.read` returns at most this much; one `net.write` takes at most this much.
pub const MAX_IO_BYTES: usize = 1024 * 1024;
/// Time for the TCP connect to one address.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Time for the whole TLS handshake.
pub const TLS_TIMEOUT: Duration = Duration::from_secs(15);
/// Commands queued on one stream before the plugin is told to wait for its replies.
const MAX_QUEUED_PER_STREAM: usize = 64;
/// Stream requests a helper may have waiting: accepted, and the reply not yet handed to the
/// plugin (security review of #1331, MEDIUM: replies must not pile up in the core).
pub const MAX_WAITING_REQUESTS: usize = 256;
/// Bytes those requests may hold in the core: a read reserves its `max`, a write its data,
/// from acceptance until the plugin takes the reply. The core never holds more stream data
/// for one helper than this, whatever the plugin does.
pub const MAX_WAITING_BYTES: usize = 32 * 1024 * 1024;

/// How the entry reaches its server, as the app states it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum EntryRoute {
    /// A direct socket from this computer.
    Direct,
    /// An SSH local forward the app runs (a saved tunnel running now, or one it started through
    /// the entry's gateway), listening on loopback `port` and reaching the entry's host and port.
    /// `target` is what the SSH server is asked to reach: local only when it is a loopback IP
    /// literal. Serves the entry's own port only.
    Forward { port: u16, target: String },
    /// A SOCKS5 proxy the app runs (`ssh -D`) on loopback `port`: never local.
    Socks { port: u16 },
    /// A gateway with no running forward, or not stated: refused.
    #[default]
    NotDirect,
}

impl EntryRoute {
    /// The audit word for the route.
    pub fn audit_name(&self) -> &'static str {
        match self {
            EntryRoute::Direct => "direct",
            EntryRoute::Forward { .. } => "tunnel",
            EntryRoute::Socks { .. } => "socks",
            EntryRoute::NotDirect => "routed",
        }
    }

    /// Whether a stream to `port` can go this way: a forward reaches only the entry's port.
    fn serves(&self, port: u16, entry_port: u16) -> Result<(), Failure> {
        match self {
            EntryRoute::NotDirect => Err(Failure::Denied("the entry's gateway has no running tunnel; open the entry again to start one".into())),
            EntryRoute::Forward { .. } if port != entry_port => Err(Failure::Denied("through a tunnel, only the entry's own port can be reached".into())),
            _ => Ok(()),
        }
    }
}

/// The entry's TLS settings, owned by the core (never a plugin field).
#[derive(Debug, Clone, Default)]
pub struct EntryTls {
    pub mode: TlsMode,
    /// Lowercase hex SHA-256 of the server's certificate, for [`TlsMode::Pinned`].
    pub pin_sha256: Option<String>,
    /// "Allow unencrypted" (off by default).
    pub allow_unencrypted: bool,
    pub route: EntryRoute,
}

/// What a finished request gives the plugin.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Opened(u32),
    Data(Vec<u8>),
    None,
    /// The answer to `http.send` (API 1.1).
    Http(HttpResponse),
}

/// One `http.send` for the stream worker: the bytes the core built (they may hold the login,
/// so they are wiped on drop) and how to read the answer.
pub struct HttpJob {
    pub wire: zeroize::Zeroizing<Vec<u8>>,
    pub head: bool,
    pub timeout: Duration,
    /// The request carries the entry's login: never in cleartext to a destination that is not
    /// local (note section 5, step 9).
    pub with_login: bool,
    /// A session-login request (design D): the relay logs in on this connection and adds the
    /// cookie. `wire` then holds no login.
    pub session: Option<Arc<SessionState>>,
}

/// A finished request, for the plugin's `events.next`.
#[derive(Debug)]
pub struct Done {
    pub request: u32,
    pub outcome: Result<Outcome, Failure>,
}

enum Cmd {
    Read { request: u32, max: usize },
    Write { request: u32, data: Vec<u8> },
    StartTls { request: u32 },
    Http { request: u32, job: HttpJob },
}

enum Kind {
    Connected { gate: StreamGate, peer: SocketAddr, shut: TcpStream },
    ConnectFailed,
    TlsUp,
    Plain,
    /// An `http.send` finished; the connection may carry another one when `keep_alive`.
    HttpDone { keep_alive: bool },
    /// The worker ended: the stream no longer counts toward the cap.
    Closed,
}

struct Msg {
    stream: u32,
    request: u32,
    kind: Kind,
    outcome: Result<Outcome, Failure>,
}

struct Handle {
    cmds: mpsc::SyncSender<Cmd>,
    port: u16,
    /// Set once connected.
    open: Option<OpenStream>,
    /// A connection the core opened for `http.send`: never reachable through `net.*`.
    http: Option<HttpConn>,
}

/// The keep-alive state of a connection opened for `http.send`.
struct HttpConn {
    /// The request it is serving now.
    busy: Option<u32>,
    idle_since: Instant,
    /// The request `http.cancel` ended, plus one (0: none), shared with the worker. Shutting
    /// the socket alone does not wake a blocked read on Windows, and a cancel that comes
    /// before the worker has connected has no socket to shut.
    cancelled: Arc<AtomicU64>,
}

/// How often a waiting HTTP read checks for a cancel.
const CANCEL_POLL: Duration = Duration::from_millis(100);

struct OpenStream {
    gate: StreamGate,
    peer: SocketAddr,
    shut: TcpStream,
}

/// The streams of one helper.
pub struct Relay {
    host: String,
    entry_port: u16,
    ports: Vec<u16>,
    tls: EntryTls,
    policy: Policy,
    caps: StreamCaps,
    aborts: AbortRegistry,
    /// Where each stream's abort bytes go: the connected address and port.
    abort_peers: BTreeMap<u32, SocketAddr>,
    streams: BTreeMap<u32, Handle>,
    next_stream: u32,
    started: Instant,
    /// Requests from acceptance until [`Relay::consumed`], with the bytes each reserves.
    waiting: BTreeMap<u32, usize>,
    waiting_bytes: usize,
    tx: mpsc::Sender<Msg>,
    rx: mpsc::Receiver<Msg>,
    stopped: bool,
    /// Ports the manifest's `[http]` table lists (API 1.1), besides the entry's port.
    http_ports: Vec<u16>,
    /// The view's session login (design D), logged out when the relay stops.
    session: Option<Arc<SessionState>>,
    /// Tests only: treat the loopback test server as a remote one, so the TLS gate applies.
    #[cfg(test)]
    test_remote: bool,
}

impl Relay {
    /// `ports` are the extra ports the manifest lists (its connection types' default ports).
    pub fn new(host: &str, entry_port: u16, ports: Vec<u16>, tls: EntryTls, policy: Policy) -> Relay {
        let (tx, rx) = mpsc::channel();
        Relay {
            host: host.trim().to_string(),
            entry_port,
            ports,
            tls,
            policy,
            caps: StreamCaps::new(),
            aborts: AbortRegistry::new(),
            abort_peers: BTreeMap::new(),
            streams: BTreeMap::new(),
            next_stream: 1,
            started: Instant::now(),
            waiting: BTreeMap::new(),
            waiting_bytes: 0,
            tx,
            rx,
            stopped: false,
            http_ports: Vec::new(),
            session: None,
            #[cfg(test)]
            test_remote: false,
        }
    }

    /// The extra ports of the manifest's `[http]` table.
    pub fn set_http_ports(&mut self, ports: Vec<u16>) {
        self.http_ports = ports;
    }

    /// The view's session login (design D): logged out and dropped when the relay stops.
    pub fn set_session(&mut self, state: Arc<SessionState>) {
        self.session = Some(state);
    }

    /// A worker's settings for `port`.
    fn job(&self, port: u16) -> Job {
        Job {
            host: self.host.clone(),
            port,
            tls: self.tls.clone(),
            policy: self.policy.clone(),
            #[cfg(test)]
            test_remote: self.test_remote,
        }
    }

    fn port_granted(&self, port: u16) -> bool {
        port != 0 && (port == self.entry_port || self.ports.contains(&port))
    }

    fn live(&self) -> Result<(), Failure> {
        if self.stopped {
            return Err(Failure::Invalid("the helper is stopping".into()));
        }
        Ok(())
    }

    /// Reserves room for `request` and its `bytes`, or refuses it: the plugin must take the
    /// replies it has before it asks for more.
    fn admit(&mut self, request: u32, bytes: usize) -> Result<(), Failure> {
        if self.waiting.len() >= MAX_WAITING_REQUESTS {
            return Err(Failure::Invalid(format!("{MAX_WAITING_REQUESTS} stream requests are waiting; take their replies first")));
        }
        if self.waiting_bytes.saturating_add(bytes) > MAX_WAITING_BYTES {
            return Err(Failure::Invalid(format!("{} MiB of stream data is waiting; take the replies first", MAX_WAITING_BYTES >> 20)));
        }
        if let Some(old) = self.waiting.insert(request, bytes) {
            self.waiting_bytes -= old;
        }
        self.waiting_bytes += bytes;
        Ok(())
    }

    /// Gives back what [`Relay::admit`] reserved, when a request is refused after all.
    fn unadmit(&mut self, request: u32) {
        if let Some(bytes) = self.waiting.remove(&request) {
            self.waiting_bytes -= bytes;
        }
    }

    /// The plugin has taken the reply to `request`: its room is free again.
    pub fn consumed(&mut self, request: u32) {
        self.unadmit(request);
    }

    /// Stream requests waiting, and the bytes they hold, for tests and the review's bound.
    pub fn waiting(&self) -> (usize, usize) {
        (self.waiting.len(), self.waiting_bytes)
    }

    /// Streams open or connecting.
    pub fn open_streams(&self) -> usize {
        self.caps.open_streams()
    }

    /// `net.connect`. `Ok` means the reply comes later from [`Relay::poll`]. The grant is the
    /// caller's check.
    pub fn connect(&mut self, request: u32, port: Option<u16>) -> Result<(), Failure> {
        self.live()?;
        if self.host.is_empty() {
            return Err(Failure::Invalid("the entry has no host".into()));
        }
        let port = port.unwrap_or(self.entry_port);
        if !self.port_granted(port) {
            return Err(Failure::Denied("that port is not the entry's port or one the plugin lists".into()));
        }
        self.tls.route.serves(port, self.entry_port)?;
        self.admit(request, 0)?;
        if let Err(f) = self.caps.try_connect(self.started.elapsed().as_millis() as u64) {
            self.unadmit(request);
            return Err(f);
        }
        let stream = self.next_stream;
        self.next_stream = self.next_stream.wrapping_add(1).max(1);
        let (cmds, cmd_rx) = mpsc::sync_channel(MAX_QUEUED_PER_STREAM);
        let job = Job {
            host: self.host.clone(),
            port,
            tls: self.tls.clone(),
            policy: self.policy.clone(),
            #[cfg(test)]
            test_remote: self.test_remote,
        };
        let out = self.tx.clone();
        let spawned = std::thread::Builder::new().name("bastion-plugin-stream".into()).spawn(move || job.run(stream, request, cmd_rx, out));
        if let Err(e) = spawned {
            self.caps.connect_failed();
            self.unadmit(request);
            return Err(Failure::Io(e.to_string()));
        }
        self.streams.insert(stream, Handle { cmds, port, open: None, http: None });
        Ok(())
    }

    /// `http.send` (API 1.1), after the dispatch's checks. Reuses an idle keep-alive connection
    /// on the port, or opens one (counted against the stream cap and the connection rate).
    /// Returns `Ok(true)` when it opened a new connection, for the `plugin.http.connect` audit.
    /// The reply comes later from [`Relay::poll`].
    pub fn http(&mut self, request: u32, port: Option<u16>, job: HttpJob) -> Result<bool, Failure> {
        self.live()?;
        if self.host.is_empty() {
            return Err(Failure::Invalid("the entry has no host".into()));
        }
        let port = port.unwrap_or(self.entry_port);
        if port == 0 || !(port == self.entry_port || self.http_ports.contains(&port)) {
            return Err(Failure::Denied("that port is not the entry's port or one the plugin lists".into()));
        }
        self.tls.route.serves(port, self.entry_port)?;
        if self.tls.mode == TlsMode::Pinned && self.tls.pin_sha256.is_none() {
            return Err(Failure::Denied(format!("the entry has no pinned certificate; {TLS_MODE_HINT}")));
        }
        self.expire_idle();
        // The answer may be up to 16 MiB, held until the plugin takes it.
        self.admit(request, MAX_RESPONSE_BODY_BYTES)?;
        let idle = self.streams.iter().find(|(_, h)| h.port == port && h.open.is_some() && h.http.as_ref().is_some_and(|c| c.busy.is_none())).map(|(id, _)| *id);
        // A server may close an idle keep-alive connection before our 30 s (pveproxy does): a
        // request sent on it would read only the close. Such a connection is dropped here.
        let idle = idle.filter(|id| {
            let alive = self.streams.get(id).and_then(|h| h.open.as_ref()).is_some_and(|o| still_open(&o.shut));
            if !alive {
                if let Some(h) = self.streams.remove(id) {
                    if let Some(o) = &h.open {
                        let _ = o.shut.shutdown(Shutdown::Both);
                    }
                }
            }
            alive
        });
        if let Some(stream) = idle {
            let h = self.streams.get_mut(&stream).expect("found");
            match h.cmds.try_send(Cmd::Http { request, job }) {
                Ok(()) => {
                    h.http.as_mut().expect("http").busy = Some(request);
                    return Ok(false);
                }
                Err(mpsc::TrySendError::Full(Cmd::Http { job: j, .. }) | mpsc::TrySendError::Disconnected(Cmd::Http { job: j, .. })) => {
                    // The worker is gone: drop it and open a new one with the same job.
                    self.streams.remove(&stream);
                    return self.http_open(request, port, j).map(|()| true);
                }
                Err(_) => unreachable!("only Http is sent here"),
            }
        }
        self.http_open(request, port, job).map(|()| true)
    }

    fn http_open(&mut self, request: u32, port: u16, job: HttpJob) -> Result<(), Failure> {
        if let Err(f) = self.caps.try_connect(self.started.elapsed().as_millis() as u64) {
            self.unadmit(request);
            return Err(f);
        }
        let stream = self.next_stream;
        self.next_stream = self.next_stream.wrapping_add(1).max(1);
        let (cmds, cmd_rx) = mpsc::sync_channel(1);
        let worker = Job {
            host: self.host.clone(),
            port,
            tls: self.tls.clone(),
            policy: self.policy.clone(),
            #[cfg(test)]
            test_remote: self.test_remote,
        };
        let out = self.tx.clone();
        let cancelled = Arc::new(AtomicU64::new(0));
        let flag = cancelled.clone();
        let spawned = std::thread::Builder::new().name("bastion-plugin-http".into()).spawn(move || worker.run_http(stream, request, job, cmd_rx, out, flag));
        if let Err(e) = spawned {
            self.caps.connect_failed();
            self.unadmit(request);
            return Err(Failure::Io(e.to_string()));
        }
        self.streams.insert(stream, Handle { cmds, port, open: None, http: Some(HttpConn { busy: Some(request), idle_since: Instant::now(), cancelled }) });
        Ok(())
    }

    /// `http.cancel`: shuts the connection serving `request`; its reply becomes a failure.
    /// Returns whether a request was found.
    pub fn http_cancel(&mut self, request: u32) -> bool {
        let found = self.streams.iter().find(|(_, h)| h.http.as_ref().is_some_and(|c| c.busy == Some(request))).map(|(id, _)| *id);
        match found.and_then(|id| self.streams.get(&id)) {
            Some(h) => {
                if let Some(c) = &h.http {
                    c.cancelled.store(u64::from(request) + 1, Ordering::SeqCst);
                }
                if let Some(o) = &h.open {
                    let _ = o.shut.shutdown(Shutdown::Both);
                }
                true
            }
            None => false,
        }
    }

    /// Closes idle `http` connections past 30 s, and the oldest beyond 4 per port.
    fn expire_idle(&mut self) {
        let now = Instant::now();
        let mut idle: Vec<(u16, Instant, u32)> = Vec::new();
        let mut close = Vec::new();
        for (id, h) in &self.streams {
            if let (Some(c), Some(_)) = (&h.http, &h.open) {
                if c.busy.is_none() {
                    if now.duration_since(c.idle_since) > Duration::from_millis(IDLE_MS) {
                        close.push(*id);
                    } else {
                        idle.push((h.port, c.idle_since, *id));
                    }
                }
            }
        }
        idle.sort();
        let mut per_port: BTreeMap<u16, usize> = BTreeMap::new();
        for (port, _, id) in idle.into_iter().rev() {
            let n = per_port.entry(port).or_default();
            *n += 1;
            if *n > MAX_IDLE_PER_PORT {
                close.push(id);
            }
        }
        for id in close {
            if let Some(h) = self.streams.remove(&id) {
                if let Some(o) = &h.open {
                    let _ = o.shut.shutdown(Shutdown::Both);
                }
            }
        }
    }

    /// Connections open for `http.send`, busy or idle (tests).
    pub fn http_connections(&self) -> usize {
        self.streams.values().filter(|h| h.http.is_some()).count()
    }

    fn opened(&mut self, stream: u32) -> Result<&mut Handle, Failure> {
        match self.streams.get_mut(&stream) {
            Some(h) if h.open.is_some() && h.http.is_none() => Ok(h),
            _ => Err(Failure::Invalid("unknown stream".into())),
        }
    }

    fn queue(h: &Handle, cmd: Cmd) -> Result<(), Failure> {
        h.cmds.try_send(cmd).map_err(|e| match e {
            mpsc::TrySendError::Full(_) => Failure::Invalid("too many requests waiting on this stream".into()),
            mpsc::TrySendError::Disconnected(_) => Failure::Io("the stream is closed".into()),
        })
    }

    /// `net.read`.
    pub fn read(&mut self, request: u32, stream: u32, max: u32) -> Result<(), Failure> {
        self.live()?;
        let max = max as usize;
        if max == 0 || max > MAX_IO_BYTES {
            return Err(Failure::Invalid(format!("a read asks for 1 to {MAX_IO_BYTES} bytes")));
        }
        self.opened(stream)?;
        self.admit(request, max)?;
        let h = self.opened(stream)?;
        let r = Relay::queue(h, Cmd::Read { request, max });
        if r.is_err() {
            self.unadmit(request);
        }
        r
    }

    /// `net.write`. Before TLS, where TLS is required, the stream gate holds the preamble to
    /// 512 bytes and the secret check.
    pub fn write(&mut self, request: u32, stream: u32, data: Vec<u8>, released: &SecretCheck) -> Result<(), Failure> {
        self.live()?;
        if data.len() > MAX_IO_BYTES {
            return Err(Failure::Invalid(format!("a write is at most {MAX_IO_BYTES} bytes")));
        }
        self.opened(stream)?;
        self.admit(request, data.len())?;
        let h = self.opened(stream)?;
        let r = h.open.as_mut().expect("opened").gate.check_write(&data, released).and_then(|()| Relay::queue(h, Cmd::Write { request, data }));
        if r.is_err() {
            self.unadmit(request);
        }
        r
    }

    /// `net.start-tls`, with the entry's TLS mode.
    pub fn start_tls(&mut self, request: u32, stream: u32) -> Result<(), Failure> {
        self.live()?;
        if self.tls.mode == TlsMode::Off {
            return Err(Failure::Denied(format!("the entry's TLS mode is off; {TLS_MODE_HINT}")));
        }
        if self.tls.mode == TlsMode::Pinned && self.tls.pin_sha256.is_none() {
            return Err(Failure::Denied(format!("the entry has no pinned certificate; {TLS_MODE_HINT}")));
        }
        self.opened(stream)?;
        self.admit(request, 0)?;
        let h = self.opened(stream)?;
        let r = Relay::queue(h, Cmd::StartTls { request });
        if r.is_err() {
            self.unadmit(request);
        }
        r
    }

    /// Whether `entry-login` may go on `stream` now (TLS is up where it is required).
    pub fn check_login(&self, stream: u32) -> Result<(), Failure> {
        match self.streams.get(&stream).and_then(|h| h.open.as_ref()) {
            Some(o) => o.gate.check_login(),
            None => Err(Failure::Invalid("unknown stream".into())),
        }
    }

    /// Whether `entry-login` may be released now: at least one stream is open and every open
    /// stream passes its login gate (TLS is up where it is required). `entry-login` names no
    /// stream, so one stream still waiting for TLS holds the release back.
    pub fn check_login_all(&self) -> Result<(), Failure> {
        let mut open = self.streams.values().filter(|h| h.http.is_none()).filter_map(|h| h.open.as_ref()).peekable();
        if open.peek().is_none() {
            return Err(Failure::Denied("the login is released only after the plugin opens a stream to the entry".into()));
        }
        open.try_for_each(|o| o.gate.check_login())
    }

    /// `net.close`. Clears the stream's abort bytes (ignored after `stop`, so they stay).
    pub fn close(&mut self, stream: u32) {
        if self.stopped {
            return;
        }
        if self.streams.get(&stream).is_some_and(|h| h.http.is_some()) {
            return;
        }
        if let Some(h) = self.streams.remove(&stream) {
            if let Some(o) = &h.open {
                let _ = o.shut.shutdown(Shutdown::Both);
            }
            // Dropping `h.cmds` ends the worker once its current command returns.
        }
        self.aborts.stream_closed(stream);
        self.abort_peers.remove(&stream);
    }

    /// `net.register-abort`.
    pub fn register_abort(&mut self, stream: u32, data: &[u8], released: &SecretCheck) -> Result<(), Failure> {
        if self.stopped {
            return Err(Failure::Denied("the helper is stopping".into()));
        }
        let (port, peer) = match self.streams.get(&stream) {
            Some(Handle { port, open: Some(o), http: None, .. }) => (*port, o.peer),
            _ => return Err(Failure::Invalid("unknown stream".into())),
        };
        let granted = self.port_granted(port);
        self.aborts.register(stream, port, granted, data, released)?;
        self.abort_peers.insert(stream, peer);
        Ok(())
    }

    /// `net.clear-abort`. Ignored after `stop`.
    pub fn clear_abort(&mut self, stream: u32) {
        if self.aborts.clear(stream).is_ok() {
            self.abort_peers.remove(&stream);
        }
    }

    /// Replies that are ready. Never blocks.
    pub fn poll(&mut self) -> Vec<Done> {
        let mut done = Vec::new();
        while let Ok(msg) = self.rx.try_recv() {
            let Msg { stream, request, kind, mut outcome } = msg;
            match kind {
                Kind::Connected { gate, peer, shut } => match self.streams.get_mut(&stream) {
                    Some(h) if !self.stopped => h.open = Some(OpenStream { gate, peer, shut }),
                    // Closed by the plugin (or the helper stopped) while connecting.
                    _ => {
                        let _ = shut.shutdown(Shutdown::Both);
                        outcome = Err(Failure::Io("the stream was closed".into()));
                    }
                },
                Kind::ConnectFailed => {
                    self.caps.connect_failed();
                    self.streams.remove(&stream);
                }
                Kind::TlsUp => {
                    if let Some(o) = self.streams.get_mut(&stream).and_then(|h| h.open.as_mut()) {
                        o.gate.tls_started();
                    }
                }
                Kind::Plain => {}
                Kind::HttpDone { keep_alive } => {
                    if let Some(c) = self.streams.get_mut(&stream).and_then(|h| h.http.as_mut()) {
                        c.busy = None;
                        c.idle_since = Instant::now();
                    }
                    if !keep_alive {
                        // The worker ends; `Closed` follows. Until then nothing reuses it.
                        if let Some(h) = self.streams.remove(&stream) {
                            if let Some(o) = &h.open {
                                let _ = o.shut.shutdown(Shutdown::Both);
                            }
                        }
                    }
                }
                Kind::Closed => {
                    self.caps.closed();
                    if !self.stopped {
                        self.streams.remove(&stream);
                        self.aborts.stream_closed(stream);
                        self.abort_peers.remove(&stream);
                    }
                    continue;
                }
            }
            // Request 0 is the core's own step on an `http` connection (its connect, its TLS):
            // nothing the plugin asked for.
            if request != 0 {
                done.push(Done { request, outcome });
            }
        }
        self.expire_idle();
        done
    }

    /// The helper stops: every stream is shut, and on an ordinary stop the abort bytes go out
    /// once each, on a thread of their own. Returns that thread, if any.
    pub fn stop(&mut self, reason: StopReason) -> Option<JoinHandle<()>> {
        if self.stopped {
            return None;
        }
        self.stopped = true;
        // Design D: log the session out (best effort, its own thread); the cookies go now.
        if let Some(state) = self.session.take() {
            let mut ports = vec![self.entry_port];
            ports.extend(self.http_ports.iter().copied());
            let jobs = ports.into_iter().map(|port| self.job(port)).collect();
            let _ = session::logout_all(jobs, state);
        }
        let sends = self.aborts.on_stop(reason);
        for h in self.streams.values() {
            if let Some(o) = &h.open {
                let _ = o.shut.shutdown(Shutdown::Both);
            }
        }
        self.streams.clear();
        self.waiting.clear();
        self.waiting_bytes = 0;
        let jobs: Vec<(SocketAddr, Vec<u8>)> = sends.into_iter().filter_map(|s| self.abort_peers.get(&s.stream_id).map(|peer| (SocketAddr::new(peer.ip(), s.port), s.bytes))).collect();
        self.abort_peers.clear();
        if jobs.is_empty() {
            return None;
        }
        std::thread::Builder::new()
            .name("bastion-plugin-abort".into())
            .spawn(move || {
                for (to, bytes) in jobs {
                    send_abort(to, &bytes);
                }
            })
            .ok()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // Without a stated reason, nothing is sent: the safe default.
        if !self.stopped {
            self.stop(StopReason::ProtocolViolation);
        }
    }
}

/// Sends abort bytes once, cleartext, and waits briefly for the server to close.
fn send_abort(to: SocketAddr, bytes: &[u8]) {
    let Ok(mut sock) = TcpStream::connect_timeout(&to, Duration::from_millis(ABORT_CONNECT_TIMEOUT_MS)) else { return };
    let wait = Some(Duration::from_millis(ABORT_CLOSE_WAIT_MS));
    let _ = sock.set_write_timeout(wait);
    let _ = sock.set_read_timeout(wait);
    if sock.write_all(bytes).is_err() {
        return;
    }
    let _ = sock.shutdown(Shutdown::Write);
    let deadline = Instant::now() + Duration::from_millis(ABORT_CLOSE_WAIT_MS);
    let mut sink = [0u8; 512];
    while Instant::now() < deadline {
        match sock.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

#[derive(Clone)]
struct Job {
    host: String,
    port: u16,
    tls: EntryTls,
    policy: Policy,
    #[cfg(test)]
    test_remote: bool,
}

enum Conn {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
    Dead,
}

fn io_failure(e: &std::io::Error) -> Failure {
    match e.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => Failure::TimedOut,
        _ => Failure::Io(e.to_string()),
    }
}

impl Job {
    fn connect(&self) -> Result<(TcpStream, StreamGate), Failure> {
        crate::offline::check_host(&self.host, self.port).map_err(|e| Failure::Denied(e.to_string()))?;
        match &self.tls.route {
            EntryRoute::Direct => self.connect_direct(),
            EntryRoute::Forward { port, target } => {
                let sock = loopback(*port)?;
                let target = target.trim_start_matches('[').trim_end_matches(']');
                let target = match target.parse::<std::net::IpAddr>() {
                    Ok(ip) => RoutedTarget::Ip(ip),
                    Err(_) => RoutedTarget::Name(target.to_string()),
                };
                let gate = StreamGate::open(&Route::Routed { target }, self.tls.mode, self.tls.allow_unencrypted, &self.policy)?;
                Ok((sock, gate))
            }
            EntryRoute::Socks { port } => {
                let gate = StreamGate::open(&Route::Socks, self.tls.mode, self.tls.allow_unencrypted, &self.policy)?;
                let mut sock = loopback(*port)?;
                socks5_connect(&mut sock, self.host.trim_start_matches('[').trim_end_matches(']'), self.port)?;
                Ok((sock, gate))
            }
            EntryRoute::NotDirect => Err(Failure::Denied("the entry's gateway has no running tunnel; open the entry again to start one".into())),
        }
    }

    fn connect_direct(&self) -> Result<(TcpStream, StreamGate), Failure> {
        let host = self.host.trim_start_matches('[').trim_end_matches(']');
        let netloc = if host.contains(':') { format!("[{host}]:{}", self.port) } else { format!("{host}:{}", self.port) };
        let addrs = crate::offline::resolve(&netloc).map_err(|e| io_failure(&e))?;
        let mut last = Failure::Io(format!("{host} has no address"));
        for addr in addrs {
            // `0.0.0.0` and `::` are not destinations.
            if let Err(f) = (Route::Direct { peer: addr.ip() }).check_destination() {
                last = f;
                continue;
            }
            match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(sock) => {
                    // "Local" is decided on the connected socket's peer, not on the name.
                    let peer = sock.peer_addr().map_err(|e| io_failure(&e))?;
                    #[allow(unused_mut)]
                    let mut peer_ip = peer.ip();
                    #[cfg(test)]
                    if self.test_remote {
                        peer_ip = std::net::IpAddr::from([192, 0, 2, 1]);
                    }
                    let gate = StreamGate::open(&Route::Direct { peer: peer_ip }, self.tls.mode, self.tls.allow_unencrypted, &self.policy)?;
                    let _ = sock.set_nodelay(true);
                    return Ok((sock, gate));
                }
                Err(e) => last = io_failure(&e),
            }
        }
        Err(last)
    }

    fn run(self, stream: u32, request: u32, cmds: mpsc::Receiver<Cmd>, out: mpsc::Sender<Msg>) {
        let sock = match self.connect() {
            Ok((sock, gate)) => {
                let (peer, shut) = match (sock.peer_addr(), sock.try_clone()) {
                    (Ok(p), Ok(s)) => (p, s),
                    (Err(e), _) | (_, Err(e)) => {
                        let _ = out.send(Msg { stream, request, kind: Kind::ConnectFailed, outcome: Err(io_failure(&e)) });
                        return;
                    }
                };
                if out.send(Msg { stream, request, kind: Kind::Connected { gate, peer, shut }, outcome: Ok(Outcome::Opened(stream)) }).is_err() {
                    return;
                }
                sock
            }
            Err(f) => {
                let _ = out.send(Msg { stream, request, kind: Kind::ConnectFailed, outcome: Err(f) });
                return;
            }
        };
        let mut conn = Conn::Plain(sock);
        for cmd in cmds {
            let (request, kind, outcome) = match cmd {
                Cmd::Read { request, max } => (request, Kind::Plain, read(&mut conn, max)),
                Cmd::Write { request, data } => (request, Kind::Plain, write(&mut conn, &data)),
                Cmd::StartTls { request } => match self.start_tls(&mut conn) {
                    Ok(()) => (request, Kind::TlsUp, Ok(Outcome::None)),
                    Err(f) => (request, Kind::Plain, Err(f)),
                },
                // Never queued on a `net` stream.
                Cmd::Http { request, .. } => (request, Kind::Plain, Err(Failure::Invalid("not an http connection".into()))),
            };
            if out.send(Msg { stream, request, kind, outcome }).is_err() {
                break;
            }
        }
        if let Conn::Tls(mut t) = conn {
            t.conn.send_close_notify();
            let _ = t.flush();
        }
        let _ = out.send(Msg { stream, request: 0, kind: Kind::Closed, outcome: Ok(Outcome::None) });
    }

    /// The worker of a connection opened for `http.send`: connect, then serve `first` and each
    /// later job until the server or the core ends the connection.
    fn run_http(self, stream: u32, first_request: u32, first: HttpJob, cmds: mpsc::Receiver<Cmd>, out: mpsc::Sender<Msg>, cancelled: Arc<AtomicU64>) {
        let (sock, local) = match self.connect() {
            Ok((sock, gate)) => {
                let (peer, shut) = match (sock.peer_addr(), sock.try_clone()) {
                    (Ok(p), Ok(s)) => (p, s),
                    (Err(e), _) | (_, Err(e)) => {
                        let _ = out.send(Msg { stream, request: first_request, kind: Kind::ConnectFailed, outcome: Err(io_failure(&e)) });
                        return;
                    }
                };
                // "Local" on the connected socket's peer, as for a `net` stream.
                let local = (Route::Direct { peer: self.peer_ip(peer) }).is_local();
                if out.send(Msg { stream, request: 0, kind: Kind::Connected { gate, peer, shut }, outcome: Ok(Outcome::None) }).is_err() {
                    return;
                }
                (sock, local)
            }
            Err(f) => {
                let _ = out.send(Msg { stream, request: first_request, kind: Kind::ConnectFailed, outcome: Err(f) });
                return;
            }
        };
        let mut conn = Conn::Plain(sock);
        let mut next = Some((first_request, first));
        loop {
            let (request, job) = match next.take() {
                Some(j) => j,
                None => match cmds.recv() {
                    Ok(Cmd::Http { request, job }) => (request, job),
                    // Only `Http` is ever queued on an `http` connection.
                    Ok(_) | Err(_) => break,
                },
            };
            let deadline = Instant::now() + job.timeout;
            let cancel = Cancel { flag: &cancelled, request };
            let result = self.http_exchange(&mut conn, &job, local, deadline, cancel, |tls_up| {
                if tls_up {
                    let _ = out.send(Msg { stream, request: 0, kind: Kind::TlsUp, outcome: Ok(Outcome::None) });
                }
            });
            let (keep_alive, outcome) = match result {
                Ok((resp, keep)) => (keep, Ok(Outcome::Http(resp))),
                Err(f) => (false, Err(f)),
            };
            if out.send(Msg { stream, request, kind: Kind::HttpDone { keep_alive }, outcome }).is_err() || !keep_alive {
                break;
            }
        }
        if let Conn::Tls(mut t) = conn {
            t.conn.send_close_notify();
            let _ = t.flush();
        }
        let _ = out.send(Msg { stream, request: 0, kind: Kind::Closed, outcome: Ok(Outcome::None) });
    }

    #[allow(unused_variables)]
    fn peer_ip(&self, peer: SocketAddr) -> std::net::IpAddr {
        #[cfg(test)]
        if self.test_remote {
            return std::net::IpAddr::from([192, 0, 2, 1]);
        }
        peer.ip()
    }

    /// One request and its answer on `conn`, within `deadline`. TLS goes up first whenever
    /// the entry's TLS mode is not off (HTTP has no pre-TLS preamble); with TLS off, a request
    /// carrying the login goes only to a local destination.
    fn http_exchange(&self, conn: &mut Conn, job: &HttpJob, local: bool, deadline: Instant, cancel: Cancel<'_>, tls_up: impl FnOnce(bool)) -> Result<(HttpResponse, bool), Failure> {
        if cancel.is_set() {
            return Err(Failure::Io("the request was cancelled".into()));
        }
        if let Some(state) = &job.session {
            return self.session_exchange(conn, &job.wire, job.head, &state.clone(), deadline, tls_up);
        }
        if self.tls.mode != TlsMode::Off {
            if matches!(conn, Conn::Plain(_)) {
                self.start_tls(conn)?;
                tls_up(true);
            }
        } else if job.with_login && !local {
            return Err(Failure::Denied(format!("the login is never sent unencrypted; {TLS_MODE_HINT}")));
        }
        let mut timed = Timed { conn, deadline, cancel: Some(cancel) };
        timed.set_timeouts()?;
        match &mut timed.conn {
            Conn::Plain(s) => s.write_all(&job.wire).and_then(|_| s.flush()),
            Conn::Tls(t) => t.write_all(&job.wire).and_then(|_| t.flush()),
            Conn::Dead => return Err(Failure::Io("the connection failed".into())),
        }
        .map_err(|e| io_failure(&e))?;
        ResponseReader::new(&mut timed).read(job.head)
    }

    fn start_tls(&self, conn: &mut Conn) -> Result<(), Failure> {
        let Conn::Plain(_) = conn else { return Err(Failure::Invalid("TLS is already up on this stream, or the stream failed".into())) };
        let Conn::Plain(mut sock) = std::mem::replace(conn, Conn::Dead) else { unreachable!() };
        let config = client_config(&self.tls)?;
        let host = self.host.trim_start_matches('[').trim_end_matches(']').to_string();
        let name = ServerName::try_from(host).map_err(|_| Failure::Invalid("the entry's host is not a valid TLS name".into()))?;
        let mut tls = ClientConnection::new(Arc::new(config), name).map_err(|e| Failure::Io(e.to_string()))?;
        let deadline = Instant::now() + TLS_TIMEOUT;
        while tls.is_handshaking() {
            // Each step gets only the time left, so the whole handshake ends within TLS_TIMEOUT.
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Failure::TimedOut);
            }
            let _ = sock.set_read_timeout(Some(left));
            let _ = sock.set_write_timeout(Some(left));
            if let Err(e) = tls.complete_io(&mut sock) {
                // A rustls certificate error comes back wrapped in an InvalidData I/O error.
                let bad_cert = e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()).is_some_and(|r| matches!(r, rustls::Error::InvalidCertificate(_)));
                return Err(if bad_cert { StreamGate::tls_failed() } else { io_failure(&e) });
            }
        }
        let _ = sock.set_read_timeout(None);
        let _ = sock.set_write_timeout(None);
        *conn = Conn::Tls(Box::new(StreamOwned::new(tls, sock)));
        Ok(())
    }
}

/// A connection read and written within a deadline: each read gets only the time left.
struct Timed<'a> {
    conn: &'a mut Conn,
    deadline: Instant,
    /// When set, a read waits in CANCEL_POLL slices and ends early once cancelled.
    cancel: Option<Cancel<'a>>,
}

/// The cancel flag of an HTTP connection, for the request it is serving.
#[derive(Clone, Copy)]
struct Cancel<'a> {
    flag: &'a AtomicU64,
    request: u32,
}

impl Cancel<'_> {
    fn is_set(&self) -> bool {
        self.flag.load(Ordering::SeqCst) == u64::from(self.request) + 1
    }
}

impl Timed<'_> {
    fn set_timeouts(&mut self) -> Result<(), Failure> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Failure::TimedOut);
        }
        let sock = match &mut self.conn {
            Conn::Plain(s) => &*s,
            Conn::Tls(t) => t.get_ref(),
            Conn::Dead => return Err(Failure::Io("the connection failed".into())),
        };
        let _ = sock.set_read_timeout(Some(left));
        let _ = sock.set_write_timeout(Some(left));
        Ok(())
    }
}

impl Timed<'_> {
    fn socket(&self) -> Option<&TcpStream> {
        match &self.conn {
            Conn::Plain(s) => Some(s),
            Conn::Tls(t) => Some(t.get_ref()),
            Conn::Dead => None,
        }
    }

    fn read_once(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.conn {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(t) => t.read(buf),
            Conn::Dead => Err(std::io::Error::new(ErrorKind::NotConnected, "dead")),
        }
    }
}

impl Read for Timed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.set_timeouts().map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "deadline"))?;
            let Some(cancel) = self.cancel else { return self.read_once(buf) };
            if cancel.is_set() {
                return Err(std::io::Error::new(ErrorKind::ConnectionAborted, "the request was cancelled"));
            }
            let left = self.deadline.saturating_duration_since(Instant::now());
            if let Some(sock) = self.socket() {
                let _ = sock.set_read_timeout(Some(left.min(CANCEL_POLL).max(Duration::from_millis(1))));
            }
            match self.read_once(buf) {
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) && Instant::now() < self.deadline => continue,
                other => return other,
            }
        }
    }
}

fn read(conn: &mut Conn, max: usize) -> Result<Outcome, Failure> {
    let mut buf = vec![0u8; max];
    let n = match conn {
        Conn::Plain(s) => s.read(&mut buf),
        Conn::Tls(t) => t.read(&mut buf),
        Conn::Dead => return Err(Failure::Io("the stream failed".into())),
    };
    match n {
        Ok(n) => {
            buf.truncate(n);
            Ok(Outcome::Data(buf))
        }
        // A server that closes without a TLS close_notify, or a stream shut by `close`: ended.
        Err(e) if matches!(e.kind(), ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted) => Ok(Outcome::Data(Vec::new())),
        Err(e) => Err(io_failure(&e)),
    }
}

fn write(conn: &mut Conn, data: &[u8]) -> Result<Outcome, Failure> {
    let r = match conn {
        Conn::Plain(s) => s.write_all(data).and_then(|_| s.flush()),
        Conn::Tls(t) => t.write_all(data).and_then(|_| t.flush()),
        Conn::Dead => return Err(Failure::Io("the stream failed".into())),
    };
    r.map(|_| Outcome::None).map_err(|e| io_failure(&e))
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The client config for the entry's TLS mode. Verify-full: the bundled web roots and the host
/// name. Pinned: exactly the pinned certificate.
fn client_config(tls: &EntryTls) -> Result<ClientConfig, Failure> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().map_err(|e| Failure::Io(e.to_string()))?;
    let config = match (tls.mode, &tls.pin_sha256) {
        (TlsMode::VerifyFull, _) => {
            let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        (TlsMode::Pinned, Some(pin)) => builder.dangerous().with_custom_certificate_verifier(Arc::new(PinVerifier { pin: pin.trim().to_ascii_lowercase(), provider })).with_no_client_auth(),
        _ => return Err(Failure::Denied(format!("the entry's TLS mode does not allow TLS here; {TLS_MODE_HINT}"))),
    };
    Ok(config)
}

/// Accepts exactly the pinned certificate (SHA-256 of its DER), with real signature checks.
#[derive(Debug)]
struct PinVerifier {
    pin: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

/// Lowercase hex SHA-256 of a DER certificate: the form the entry's pin is stored in.
pub fn certificate_pin(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        let seen = certificate_pin(end_entity.as_ref());
        // Constant-time is not needed: the pin is not secret.
        if !self.pin.is_empty() && seen == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[path = "relay_session.rs"]
pub mod session;
pub use session::SessionState;

#[cfg(test)]
#[path = "relay_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "relay_http_tests.rs"]
mod http_tests;

#[cfg(test)]
#[path = "relay_session_tests.rs"]
mod session_tests;

/// Records the server's certificate and then fails the handshake: nothing is trusted, sent or
/// read after it.
#[derive(Debug)]
struct Capture {
    seen: std::sync::Mutex<Option<String>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut s) = self.seen.lock() {
            *s = Some(certificate_pin(end_entity.as_ref()));
        }
        Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// The pin ([`certificate_pin`]) of the certificate `host:port` presents, for the user to
/// compare and trust in the entry's TLS settings. Only the TLS handshake runs: no request and
/// no login is sent. The same offline and destination checks as a plugin connection apply.
pub fn probe_certificate_pin(host: &str, port: u16, policy: &Policy) -> Result<String, Failure> {
    if host.is_empty() || port == 0 {
        return Err(Failure::Invalid("the entry has no host or port".into()));
    }
    let tls = EntryTls { mode: TlsMode::Pinned, pin_sha256: None, allow_unencrypted: false, route: EntryRoute::Direct };
    let job = Job {
        host: host.to_string(),
        port,
        tls,
        policy: policy.clone(),
        #[cfg(test)]
        test_remote: false,
    };
    // A server that speaks TLS only after a protocol's own request (PostgreSQL) presents no
    // certificate to a bare handshake: then once more after PostgreSQL's SSLRequest.
    match probe_once(&job, host, false)? {
        Some(pin) => Ok(pin),
        None => probe_once(&job, host, true)?.ok_or_else(|| Failure::Io("the server presented no TLS certificate".into())),
    }
}

/// PostgreSQL's SSLRequest (protocol 1234.5679): the server answers `S` and then speaks TLS.
const PG_SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];

/// Sends PostgreSQL's SSLRequest; true when the server agreed to TLS.
fn pg_ssl_request(sock: &mut TcpStream) -> std::io::Result<bool> {
    use std::io::{Read, Write};
    sock.write_all(&PG_SSL_REQUEST)?;
    let mut b = [0u8; 1];
    sock.read_exact(&mut b)?;
    Ok(b[0] == b'S')
}

/// One certificate probe; `pg` sends PostgreSQL's SSLRequest first. `None` when no certificate came.
fn probe_once(job: &Job, host: &str, pg: bool) -> Result<Option<String>, Failure> {
    let (mut sock, _gate) = job.connect()?;
    sock.set_read_timeout(Some(CONNECT_TIMEOUT)).map_err(|e| io_failure(&e))?;
    sock.set_write_timeout(Some(CONNECT_TIMEOUT)).map_err(|e| io_failure(&e))?;
    if pg && !pg_ssl_request(&mut sock).unwrap_or(false) {
        return Ok(None);
    }
    let provider = provider();
    let capture = Arc::new(Capture { seen: std::sync::Mutex::new(None), provider: provider.clone() });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Failure::Io(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(capture.clone())
        .with_no_client_auth();
    let bare = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let name = ServerName::try_from(bare).map_err(|_| Failure::Invalid("the entry's host is not a valid TLS name".into()))?;
    let mut tls = ClientConnection::new(Arc::new(config), name).map_err(|e| Failure::Io(e.to_string()))?;
    // Ends with the verifier's refusal once the certificate was seen.
    let _ = tls.complete_io(&mut sock);
    let _ = sock.shutdown(Shutdown::Both);
    Ok(capture.seen.lock().ok().and_then(|s| s.clone()))
}

/// Test Connection for a plugin entry: a full TLS handshake under the entry's own rule (system
/// trust and the host name, or exactly the pinned certificate), over a direct route. Nothing is
/// sent after the handshake. `Err` carries the reason, worded as on the dashboard.
pub fn check_entry_certificate(host: &str, port: u16, pin_sha256: Option<&str>, policy: &Policy) -> Result<(), Failure> {
    if host.is_empty() || port == 0 {
        return Err(Failure::Invalid("the entry has no host or port".into()));
    }
    let pin = pin_sha256.map(str::trim).filter(|p| !p.is_empty()).map(str::to_ascii_lowercase);
    let mode = if pin.is_some() { TlsMode::Pinned } else { TlsMode::VerifyFull };
    let tls = EntryTls { mode, pin_sha256: pin, allow_unencrypted: false, route: EntryRoute::Direct };
    let config = client_config(&tls)?;
    let job = Job {
        host: host.to_string(),
        port,
        tls,
        policy: policy.clone(),
        #[cfg(test)]
        test_remote: false,
    };
    let config = Arc::new(config);
    let mut result = check_once(&job, host, config.clone(), false)?;
    // Any failure but a refused certificate (PostgreSQL answers a bare ClientHello with an error and
    // closes): a server that wants PostgreSQL's SSLRequest first. The first error stays if that fails too.
    if matches!(&result, Err(e) if !is_certificate_error(e)) {
        if let Ok(again) = check_once(&job, host, config, true) {
            result = again;
        }
    }
    match result {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::InvalidData => Err(Failure::Denied(format!("the server's certificate did not pass the TLS mode; {TLS_MODE_HINT}"))),
        Err(e) => Err(io_failure(&e)),
    }
}

/// One handshake for [`check_entry_certificate`]; `pg` sends PostgreSQL's SSLRequest first.
fn check_once(job: &Job, host: &str, config: Arc<ClientConfig>, pg: bool) -> Result<std::io::Result<()>, Failure> {
    let (mut sock, _gate) = job.connect()?;
    sock.set_read_timeout(Some(CONNECT_TIMEOUT)).map_err(|e| io_failure(&e))?;
    sock.set_write_timeout(Some(CONNECT_TIMEOUT)).map_err(|e| io_failure(&e))?;
    if pg && !pg_ssl_request(&mut sock).map_err(|e| io_failure(&e))? {
        return Err(Failure::Denied("the server does not offer TLS".into()));
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let name = ServerName::try_from(bare).map_err(|_| Failure::Invalid("the entry's host is not a valid TLS name".into()))?;
    let mut conn = ClientConnection::new(config, name).map_err(|e| Failure::Io(e.to_string()))?;
    let result = conn.complete_io(&mut sock).map(|_| ());
    let _ = sock.shutdown(Shutdown::Both);
    Ok(result)
}

/// Whether a handshake error is rustls refusing the certificate (not a peer that is not TLS).
fn is_certificate_error(e: &std::io::Error) -> bool {
    matches!(e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()), Some(rustls::Error::InvalidCertificate(_)))
}

/// An idle connection the server has not closed and sent nothing on: a peek that would block.
/// End of stream, a TLS close_notify or any other unread byte means it cannot carry a request.
/// The worker is waiting on its command queue, not on the socket, while this runs.
fn still_open(sock: &TcpStream) -> bool {
    if sock.set_nonblocking(true).is_err() {
        return false;
    }
    let alive = matches!(sock.peek(&mut [0u8; 1]), Err(e) if e.kind() == ErrorKind::WouldBlock);
    sock.set_nonblocking(false).is_ok() && alive
}

/// A socket to the app's own tunnel listener on loopback `port`.
fn loopback(port: u16) -> Result<TcpStream, Failure> {
    if port == 0 {
        return Err(Failure::Invalid("the tunnel has no port".into()));
    }
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let sock = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|e| io_failure(&e))?;
    let _ = sock.set_nodelay(true);
    Ok(sock)
}

/// SOCKS5 CONNECT with no authentication (RFC 1928), by name so the proxy resolves it.
fn socks5_connect(sock: &mut TcpStream, host: &str, port: u16) -> Result<(), Failure> {
    use std::io::{Read, Write};
    let io = |e: std::io::Error| io_failure(&e);
    let refused = |why: &str| Failure::Io(format!("the SOCKS proxy refused: {why}"));
    let name = host.as_bytes();
    if name.is_empty() || name.len() > 255 {
        return Err(Failure::Invalid("the entry's host name is too long for SOCKS".into()));
    }
    sock.set_read_timeout(Some(CONNECT_TIMEOUT)).map_err(io)?;
    sock.write_all(&[5, 1, 0]).map_err(io)?;
    let mut hello = [0u8; 2];
    sock.read_exact(&mut hello).map_err(io)?;
    if hello != [5, 0] {
        return Err(refused("no supported authentication"));
    }
    let mut req = vec![5, 1, 0, 3, name.len() as u8];
    req.extend_from_slice(name);
    req.extend_from_slice(&port.to_be_bytes());
    sock.write_all(&req).map_err(io)?;
    let mut head = [0u8; 4];
    sock.read_exact(&mut head).map_err(io)?;
    if head[0] != 5 || head[1] != 0 {
        return Err(refused(&format!("reply {}", head[1])));
    }
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0u8; 1];
            sock.read_exact(&mut n).map_err(io)?;
            usize::from(n[0])
        }
        _ => return Err(refused("bad address type")),
    };
    let mut rest = vec![0u8; skip + 2];
    sock.read_exact(&mut rest).map_err(io)?;
    sock.set_read_timeout(None).map_err(io)?;
    Ok(())
}
