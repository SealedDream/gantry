//! The fake core: the store's state and every `bastion:plugin` import.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use wasmtime::StoreLimits;

use crate::bindings::bastion::plugin::events::{Event, Reply, ReplyValue};
use crate::bindings::bastion::plugin::log::Level;
use crate::bindings::bastion::plugin::types::{Entry, Failure, Login};
use crate::bindings::bastion::plugin::ui::{
    Completion, ConfirmKind, ErrorMark, Node, Row, TreeItem,
};
use crate::bindings::bastion::plugin::{
    clipboard, credentials, events, exec, files, host, http, library, log, net, open, storage, types, ui,
};
use crate::fake::{FakeConnection, FakeHttpRequest, FakeServer};
use crate::manifest::Permissions;
use crate::view;

/// Caps from the spec (section 5, "Limits and failures").
pub const MAX_STREAMS: usize = 16;
pub const MAX_CONNECTS_PER_MINUTE: usize = 30;
pub const CHUNK: usize = 1024 * 1024;
pub const MAX_ABORT: usize = 512;
pub const MAX_ROWS: usize = 1_000;

/// Everything the plugin did that a test may look at.
#[derive(Default, Debug)]
pub struct Outputs {
    /// Each open view's current nodes.
    pub views: HashMap<u32, Vec<Node>>,
    /// Open dialogs: id to (view it is over, title, nodes).
    pub dialogs: HashMap<u32, (u32, String, Vec<Node>)>,
    pub logs: Vec<(Level, String)>,
    /// View lists the host refused, with the reason.
    pub refused_views: Vec<String>,
    pub marks: Vec<(u32, u32, Vec<ErrorMark>)>,
    pub rows: HashMap<u32, (Vec<Row>, Option<u64>)>,
    pub children: HashMap<u32, Vec<TreeItem>>,
    pub completions: HashMap<u32, Vec<Completion>>,
    pub refused_asks: HashMap<u32, String>,
    pub confirms: Vec<(ConfirmKind, String)>,
    pub clipboard: Vec<String>,
    pub saved_files: Vec<(String, Vec<u8>)>,
    pub storage: HashMap<String, Vec<u8>>,
    /// How many times the login was released (at most once per helper).
    pub logins_released: u32,
    /// Bytes written to each stream, in order, for tests that check what the plugin sent.
    pub written: Vec<(u32, Vec<u8>)>,
    /// Abort bytes registered per stream and still in force.
    pub aborts: HashMap<u32, Vec<u8>>,
    /// Every `open.connection` that reached the user's sheet, in order.
    pub opens: Vec<open::OpenRequest>,
    /// Every `exec.run` and `exec.terminal` that reached the fake server: template and arguments.
    pub execs: Vec<(String, Vec<(String, String)>)>,
    /// Every `library.propose` that reached the user's sheet, in order.
    pub proposals: Vec<Vec<library::Proposal>>,
    /// Every `http.send` the fake server answered or the host refused, in order.
    pub http_requests: Vec<FakeHttpRequest>,
    /// Calls refused by the secret check, by kind.
    pub secret_refusals: Vec<&'static str>,
    /// Set when `run` ended: `Ok` when it returned, `Err` with the trap.
    pub finished: Option<Result<(), String>>,
    /// Bumped on every change, so a waiter can tell that something happened.
    pub changes: u64,
}

/// Outputs shared between the plugin's thread and the test.
#[derive(Default)]
pub struct Shared {
    pub outputs: Mutex<Outputs>,
    pub changed: Condvar,
}

impl Shared {
    pub fn update<R>(&self, f: impl FnOnce(&mut Outputs) -> R) -> R {
        let mut o = self.outputs.lock().unwrap_or_else(|e| e.into_inner());
        let r = f(&mut o);
        o.changes += 1;
        self.changed.notify_all();
        r
    }
}

/// Settings for one run.
pub struct Config {
    pub permissions: Permissions,
    pub entry: Option<Entry>,
    pub settings: Vec<(String, String)>,
    /// The login the fake core releases; `None` answers `cancelled`, as a user who closes the
    /// core's prompt would.
    pub login: Option<Login>,
    /// The user's answer to every confirmation.
    pub confirm: bool,
    /// The user's answer to every `open.connection` sheet (API 1.2).
    pub open_answer: bool,
    /// The file the user picks in an Open dialog; `None` answers `cancelled`.
    pub file_to_open: Option<(String, Vec<u8>)>,
    pub memory_limit: usize,
    pub compute_limit: Duration,
    /// How long `next` waits for the test before it tells the plugin to stop.
    pub idle_limit: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            permissions: Permissions::default(),
            entry: None,
            settings: Vec::new(),
            login: None,
            confirm: true,
            open_answer: true,
            file_to_open: None,
            memory_limit: 64 * 1024 * 1024,
            compute_limit: Duration::from_secs(2),
            idle_limit: Duration::from_secs(30),
        }
    }
}

pub struct State {
    pub limits: StoreLimits,
    pub started: Instant,
    /// When the plugin last got control back from `next`; the compute limit counts from here.
    pub event_started: Instant,
    pub compute_limit: Duration,
    pub config: Config,
    pub shared: Arc<Shared>,
    pub asks: Arc<Mutex<HashSet<u32>>>,
    inbox: Receiver<Event>,
    local: VecDeque<Event>,
    server: Box<dyn FakeServer>,
    streams: HashMap<u32, Box<dyn FakeConnection>>,
    pending_reads: Vec<(u32, u32, usize)>,
    connects: VecDeque<Instant>,
    next_request: u32,
    next_stream: u32,
    next_dialog: u32,
    released: Option<Login>,
    /// When the test last sent a command or view input: `open.connection` needs one within
    /// 10 s, once, as in the core (API 1.2).
    user_action: Option<Instant>,
    /// Set once `stop` went to the plugin: from then on, closing a stream no longer clears its
    /// abort bytes, because the core decided to stop while they were in force.
    stopping: bool,
}

impl State {
    pub fn new(
        config: Config,
        server: Box<dyn FakeServer>,
        inbox: Receiver<Event>,
        shared: Arc<Shared>,
        asks: Arc<Mutex<HashSet<u32>>>,
    ) -> State {
        let limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(config.memory_limit)
            .instances(16)
            .tables(64)
            .memories(4)
            .build();
        let now = Instant::now();
        State {
            limits,
            started: now,
            event_started: now,
            compute_limit: config.compute_limit,
            config,
            shared,
            asks,
            inbox,
            local: VecDeque::new(),
            server,
            streams: HashMap::new(),
            pending_reads: Vec::new(),
            connects: VecDeque::new(),
            next_request: 1,
            next_stream: 1,
            // Dialog ids are far from the view ids the test hands out.
            next_dialog: 1_000_000,
            released: None,
            user_action: None,
            stopping: false,
        }
    }

    fn request(&mut self) -> u32 {
        let id = self.next_request;
        self.next_request += 1;
        id
    }

    fn answer(&mut self, request: u32, outcome: Result<ReplyValue, Failure>) -> u32 {
        self.local.push_back(Event::Reply(Reply { request, outcome }));
        request
    }

    fn reply(&mut self, outcome: Result<ReplyValue, Failure>) -> u32 {
        let id = self.request();
        self.answer(id, outcome)
    }

    /// The test host's secret check: the exact bytes of the released password (the core also
    /// matches base64, hex and percent-encoding; see the spec, "Released secrets").
    fn holds_secret(&self, bytes: &[u8]) -> bool {
        match &self.released {
            Some(login) if !login.secret.is_empty() => {
                let s = login.secret.as_bytes();
                bytes.windows(s.len()).any(|w| w == s)
            }
            _ => false,
        }
    }

    fn refuse_secret(&mut self, what: &'static str) -> Failure {
        self.shared.update(|o| o.secret_refusals.push(what));
        Failure::Denied(format!("{what}: refused by the secret check"))
    }

    fn poll_reads(&mut self) {
        let mut i = 0;
        while i < self.pending_reads.len() {
            let (request, stream, max) = self.pending_reads[i];
            let got = match self.streams.get_mut(&stream) {
                Some(conn) => conn.read(max),
                None => Some(Vec::new()),
            };
            match got {
                Some(data) => {
                    self.pending_reads.swap_remove(i);
                    self.answer(request, Ok(ReplyValue::Data(data)));
                }
                None => i += 1,
            }
        }
    }

    fn view_known(&self, view: u32) -> bool {
        let o = self.shared.outputs.lock().unwrap_or_else(|e| e.into_inner());
        o.views.contains_key(&view) || o.dialogs.contains_key(&view)
    }

    fn take_ask(&self, ask: u32) -> Result<(), Failure> {
        if self.asks.lock().unwrap_or_else(|e| e.into_inner()).remove(&ask) {
            Ok(())
        } else {
            Err(Failure::Invalid(format!("ask {ask} is not open")))
        }
    }

    /// Sends every registered abort as the core would on an ordinary stop.
    pub fn send_aborts(&mut self) {
        let aborts: Vec<(u32, Vec<u8>)> = self.shared.update(|o| o.aborts.drain().collect());
        let port = self.config.entry.as_ref().map_or(0, |e| e.port);
        for (_, bytes) in aborts {
            if let Ok(mut conn) = self.server.connect(port) {
                let _ = conn.write(&bytes);
            }
        }
    }
}

impl types::Host for State {}

impl host::Host for State {
    fn entry_info(&mut self) -> Option<Entry> {
        self.config.entry.clone()
    }
    fn settings(&mut self) -> Vec<(String, String)> {
        self.config.settings.clone()
    }
}

impl log::Host for State {
    fn line(&mut self, level: Level, text: String) {
        if self.holds_secret(text.as_bytes()) {
            // Dropped whole, as the core does.
            self.refuse_secret("log");
            return;
        }
        self.shared.update(|o| o.logs.push((level, text)));
    }
}

impl ui::Host for State {
    fn set_view(&mut self, view: u32, nodes: Vec<Node>) -> Result<(), Failure> {
        if !self.view_known(view) {
            return Err(Failure::Invalid(format!("view {view} is not open")));
        }
        if let Err(why) = view::check(&nodes) {
            self.shared.update(|o| o.refused_views.push(why.clone()));
            return Err(Failure::Invalid(why));
        }
        self.shared.update(|o| {
            if let Some(d) = o.dialogs.get_mut(&view) {
                d.2 = nodes;
            } else {
                o.views.insert(view, nodes);
            }
        });
        Ok(())
    }

    fn patch_view(&mut self, view: u32, upsert: Vec<Node>, remove: Vec<u32>) -> Result<(), Failure> {
        let current = {
            let o = self.shared.outputs.lock().unwrap_or_else(|e| e.into_inner());
            o.views.get(&view).cloned().or_else(|| o.dialogs.get(&view).map(|d| d.2.clone()))
        };
        let Some(current) = current else {
            return Err(Failure::Invalid(format!("view {view} is not open")));
        };
        let next = view::patch(&current, upsert, &remove);
        if let Err(why) = view::check(&next) {
            self.shared.update(|o| o.refused_views.push(why.clone()));
            return Err(Failure::Invalid(why));
        }
        self.shared.update(|o| {
            if let Some(d) = o.dialogs.get_mut(&view) {
                d.2 = next;
            } else {
                o.views.insert(view, next);
            }
        });
        Ok(())
    }

    fn open_dialog(&mut self, over: u32, title: String, nodes: Vec<Node>) -> Result<u32, Failure> {
        if !self.view_known(over) {
            return Err(Failure::Invalid(format!("view {over} is not open")));
        }
        if title.chars().count() > bastion_plugin_sdk::ui::MAX_LABEL {
            return Err(Failure::Invalid("dialog title too long".into()));
        }
        view::check(&nodes).map_err(Failure::Invalid)?;
        let id = self.next_dialog;
        self.next_dialog += 1;
        self.shared.update(|o| o.dialogs.insert(id, (over, title, nodes)));
        Ok(id)
    }

    fn close_dialog(&mut self, dialog: u32) {
        self.shared.update(|o| o.dialogs.remove(&dialog));
    }

    fn mark_errors(&mut self, view: u32, editor: u32, marks: Vec<ErrorMark>) -> Result<(), Failure> {
        if !self.view_known(view) {
            return Err(Failure::Invalid(format!("view {view} is not open")));
        }
        self.shared.update(|o| o.marks.push((view, editor, marks)));
        Ok(())
    }

    fn provide_rows(&mut self, ask: u32, rows: Vec<Row>, total: Option<u64>) -> Result<(), Failure> {
        if rows.len() > MAX_ROWS {
            return Err(Failure::Invalid(format!("more than {MAX_ROWS} rows in one page")));
        }
        self.take_ask(ask)?;
        self.shared.update(|o| o.rows.insert(ask, (rows, total)));
        Ok(())
    }

    fn provide_children(&mut self, ask: u32, items: Vec<TreeItem>) -> Result<(), Failure> {
        self.take_ask(ask)?;
        self.shared.update(|o| o.children.insert(ask, items));
        Ok(())
    }

    fn provide_completions(&mut self, ask: u32, items: Vec<Completion>) -> Result<(), Failure> {
        self.take_ask(ask)?;
        self.shared.update(|o| o.completions.insert(ask, items));
        Ok(())
    }

    fn refuse(&mut self, ask: u32, message: String) {
        if self.take_ask(ask).is_ok() {
            self.shared.update(|o| o.refused_asks.insert(ask, message));
        }
    }

    fn confirm(&mut self, kind: ConfirmKind, text: String) -> u32 {
        self.shared.update(|o| o.confirms.push((kind, text)));
        let yes = self.config.confirm;
        self.reply(Ok(ReplyValue::Confirmed(yes)))
    }
}

impl events::Host for State {
    fn next(&mut self) -> Event {
        let event = loop {
            if let Some(e) = self.local.pop_front() {
                break e;
            }
            self.poll_reads();
            if !self.local.is_empty() {
                continue;
            }
            // Nothing the host can answer by itself: wait for the test. While reads are
            // pending, look again soon, since a fake connection may have data by then.
            let wait = if self.pending_reads.is_empty() { self.config.idle_limit } else { Duration::from_millis(5) };
            match self.inbox.recv_timeout(wait) {
                Ok(e) => break e,
                Err(RecvTimeoutError::Timeout) if !self.pending_reads.is_empty() => continue,
                // The test went quiet or went away: stop the plugin.
                Err(_) => break Event::Stop,
            }
        };
        if matches!(event, Event::Stop) {
            self.stopping = true;
        }
        if matches!(event, Event::Command(_) | Event::Ui(_)) {
            self.user_action = Some(Instant::now());
        }
        self.event_started = Instant::now();
        event
    }
}

impl net::Host for State {
    fn connect(&mut self, port: Option<u16>) -> u32 {
        let now = Instant::now();
        while self.connects.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60)) {
            self.connects.pop_front();
        }
        // Attempts count, not only connections that succeed.
        if self.connects.len() >= MAX_CONNECTS_PER_MINUTE {
            return self.reply(Err(Failure::Denied(format!(
                "more than {MAX_CONNECTS_PER_MINUTE} new connections a minute"
            ))));
        }
        self.connects.push_back(now);
        if self.streams.len() >= MAX_STREAMS {
            return self.reply(Err(Failure::Denied(format!("more than {MAX_STREAMS} streams at once"))));
        }
        let Some(entry_port) = self.config.entry.as_ref().map(|e| e.port) else {
            return self.reply(Err(Failure::Denied("this helper serves no entry".into())));
        };
        match self.server.connect(port.unwrap_or(entry_port)) {
            Ok(conn) => {
                let id = self.next_stream;
                self.next_stream += 1;
                self.streams.insert(id, conn);
                self.reply(Ok(ReplyValue::Opened(id)))
            }
            Err(why) => self.reply(Err(Failure::Io(why))),
        }
    }

    fn read(&mut self, stream: u32, max: u32) -> u32 {
        let id = self.request();
        if !self.streams.contains_key(&stream) {
            return self.answer(id, Err(Failure::Invalid(format!("stream {stream} is not open"))));
        }
        self.pending_reads.push((id, stream, (max as usize).clamp(1, CHUNK)));
        id
    }

    fn write(&mut self, stream: u32, data: Vec<u8>) -> u32 {
        if data.len() > CHUNK {
            return self.reply(Err(Failure::Invalid(format!("more than {CHUNK} bytes in one write"))));
        }
        let outcome = match self.streams.get_mut(&stream) {
            None => Err(Failure::Invalid(format!("stream {stream} is not open"))),
            Some(conn) => conn.write(&data).map(|()| ReplyValue::None).map_err(Failure::Io),
        };
        if outcome.is_ok() {
            self.shared.update(|o| o.written.push((stream, data)));
        }
        self.reply(outcome)
    }

    fn start_tls(&mut self, stream: u32) -> u32 {
        let outcome = match self.streams.get_mut(&stream) {
            None => Err(Failure::Invalid(format!("stream {stream} is not open"))),
            Some(conn) => conn.start_tls().map(|()| ReplyValue::None).map_err(Failure::Io),
        };
        self.reply(outcome)
    }

    fn close(&mut self, stream: u32) {
        self.streams.remove(&stream);
        self.pending_reads.retain(|(_, s, _)| *s != stream);
        if !self.stopping {
            self.shared.update(|o| o.aborts.remove(&stream));
        }
    }

    fn register_abort(&mut self, stream: u32, data: Vec<u8>) -> u32 {
        // After `stop` nothing about abort bytes may change (spec section 5, amendment A1-C3.1).
        if self.stopping {
            return self.reply(Err(Failure::Denied("abort bytes: the helper is stopping".into())));
        }
        if data.len() > MAX_ABORT {
            return self.reply(Err(Failure::Invalid(format!("abort bytes: more than {MAX_ABORT}"))));
        }
        if !self.streams.contains_key(&stream) {
            return self.reply(Err(Failure::Invalid(format!("stream {stream} is not open"))));
        }
        if self.holds_secret(&data) {
            let f = self.refuse_secret("abort bytes");
            return self.reply(Err(f));
        }
        // One registration per stream: a new one replaces the old one.
        self.shared.update(|o| o.aborts.insert(stream, data));
        self.reply(Ok(ReplyValue::None))
    }

    fn clear_abort(&mut self, stream: u32) {
        // Ignored after `stop`: the abort bytes in force then are sent.
        if !self.stopping {
            self.shared.update(|o| o.aborts.remove(&stream));
        }
    }
}

/// The test host's `http` (API 1.1): a few of the core's checks, then the fake server. The
/// full set (path prefixes, header rules, the encoded secret check) is the core's
/// (`core/src/plugin/broker/http.rs`); this host keeps the ones a plugin author trips first.
impl http::Host for State {
    fn send(&mut self, req: http::HttpRequest) -> u32 {
        let Some(entry_port) = self.config.entry.as_ref().map(|e| e.port) else {
            return self.reply(Err(Failure::Denied("this helper serves no entry".into())));
        };
        let target_ok = req.target.starts_with('/') && !req.target.starts_with("//") && req.target.bytes().all(|b| (0x21..=0x7e).contains(&b)) && !req.target.contains('#');
        if !target_ok {
            return self.reply(Err(Failure::Invalid("the request target must be origin form: \"/path?query\"".into())));
        }
        let framing = ["host", "content-length", "transfer-encoding", "connection", "cookie", "authorization", "user-agent"];
        if req.headers.iter().any(|(n, v)| framing.contains(&n.to_ascii_lowercase().as_str()) || n.to_ascii_lowercase().starts_with("proxy-") || v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)) {
            return self.reply(Err(Failure::Invalid("a request header is the core's or holds a line break".into())));
        }
        let mut seen = req.target.clone().into_bytes();
        for (n, v) in &req.headers {
            seen.extend_from_slice(format!("\n{n}:{v}").as_bytes());
        }
        if self.holds_secret(&seen) || self.holds_secret(&req.body) {
            let f = self.refuse_secret("http request");
            return self.reply(Err(f));
        }
        let login = match (req.with_login, &self.config.login) {
            (false, _) => None,
            (true, Some(l)) => Some(format!("{}:{}", l.user, l.secret)),
            (true, None) => return self.reply(Err(Failure::Denied("no login configured for this test".into()))),
        };
        let method = match req.method {
            http::Method::Get => "GET",
            http::Method::Head => "HEAD",
            http::Method::Post => "POST",
            http::Method::Put => "PUT",
            http::Method::Patch => "PATCH",
            http::Method::Delete => "DELETE",
            http::Method::Options => "OPTIONS",
        }
        .to_string();
        let fake = FakeHttpRequest { method, port: req.port.unwrap_or(entry_port), target: req.target, headers: req.headers, body: req.body, login };
        let answer = self.server.http(&fake);
        self.shared.update(|o| o.http_requests.push(fake));
        let outcome = answer
            .map(|r| ReplyValue::Http(types::HttpResponse { status: r.status, headers: r.headers, body: r.body }))
            .map_err(Failure::Io);
        self.reply(outcome)
    }

    fn cancel(&mut self, _req: u32) {}
}

/// The test host's `open` (API 1.2): the protocol grant, the user-action stamp and simple
/// host and label checks, then the configured answer. The full checks (address classes, the
/// reported set, the rate, policy) are the core's (`core/src/plugin/broker/open.rs`).
impl open::Host for State {
    fn connection(&mut self, req: open::OpenRequest) -> u32 {
        if self.config.entry.is_none() {
            return self.reply(Err(Failure::Denied("this helper serves no entry".into())));
        }
        // As in the core: the stamp is used before the protocol check, so a refused request
        // still uses up the user action.
        let fresh = self.user_action.take().is_some_and(|t| t.elapsed() <= Duration::from_secs(10));
        if !fresh {
            return self.reply(Err(Failure::Denied("not-now: a plugin may ask only right after a user action".into())));
        }
        let granted = match req.protocol {
            open::Protocol::Ssh => self.config.permissions.open_ssh,
            open::Protocol::Rdp => self.config.permissions.open_rdp,
            open::Protocol::Vnc => self.config.permissions.open_vnc,
        };
        if !granted {
            return self.reply(Err(Failure::Denied("the plugin may not open this protocol".into())));
        }
        let host_ok = !req.host.is_empty() && req.host.len() <= 253 && req.host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b));
        let label_ok = !req.label.is_empty() && req.label.chars().count() <= 128 && !req.label.chars().any(char::is_control);
        if !host_ok || !label_ok || req.port == Some(0) {
            return self.reply(Err(Failure::Denied("the host, port or label is not allowed".into())));
        }
        let yes = self.config.open_answer;
        self.shared.update(|o| o.opens.push(req));
        self.reply(Ok(ReplyValue::Connection(yes)))
    }
}

/// The test host's `exec` (API 1.5): the grant, the entry and the user-action stamp for
/// `terminal`, then the fake server. The template and argument checks are the core's
/// (`core/src/plugin/broker/exec.rs`); the test host passes what the plugin gave.
impl exec::Host for State {
    fn run(&mut self, template: String, args: Vec<(String, String)>, _timeout_ms: u32) -> u32 {
        if !self.config.permissions.exec || self.config.entry.is_none() {
            return self.reply(Err(Failure::Denied("the plugin has no exec permission or no entry".into())));
        }
        self.shared.update(|o| o.execs.push((template.clone(), args.clone())));
        match self.server.exec(&template, &args) {
            Ok(out) => {
                let truncated = false;
                self.reply(Ok(ReplyValue::Exec(types::ExecOutput { exit: out.exit, stdout: out.stdout, stderr: out.stderr, truncated })))
            }
            Err(why) => self.reply(Err(Failure::Io(why))),
        }
    }

    fn cancel(&mut self, _req: u32) {}

    fn terminal(&mut self, template: String, args: Vec<(String, String)>, _label: String) -> u32 {
        if !self.config.permissions.exec || self.config.entry.is_none() {
            return self.reply(Err(Failure::Denied("the plugin has no exec permission or no entry".into())));
        }
        let fresh = self.user_action.take().is_some_and(|t| t.elapsed() <= Duration::from_secs(10));
        if !fresh {
            return self.reply(Err(Failure::Denied("a change needs a user action just before".into())));
        }
        self.shared.update(|o| o.execs.push((template, args)));
        let yes = self.config.open_answer;
        self.reply(Ok(ReplyValue::Connection(yes)))
    }
}

impl library::Host for State {
    fn propose(&mut self, proposals: Vec<library::Proposal>) -> u32 {
        if self.config.entry.is_none() {
            return self.reply(Err(Failure::Denied("this helper serves no entry".into())));
        }
        let fresh = self.user_action.take().is_some_and(|t| t.elapsed() <= Duration::from_secs(10));
        if !fresh {
            return self.reply(Err(Failure::Denied("not-now: a plugin may ask only right after a user action".into())));
        }
        if proposals.is_empty() || proposals.len() > 100 {
            return self.reply(Err(Failure::Invalid("between 1 and 100 proposals at a time".into())));
        }
        let label_ok = |l: &str| !l.is_empty() && l.chars().count() <= 128 && l.trim() == l && !l.chars().any(char::is_control);
        let host_ok = |h: &str| !h.is_empty() && h.len() <= 253 && h.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b));
        let hint_ok = |o: &str| ["windows", "linux", "bsd", "macos", "other"].contains(&o);
        if !proposals.iter().all(|p| label_ok(&p.label) && p.host.as_deref().map_or(true, host_ok) && p.os_hint.as_deref().map_or(true, hint_ok)) {
            return self.reply(Err(Failure::Denied("a label, host or os-hint is not allowed".into())));
        }
        // The fake user saves every proposal.
        let n = proposals.len() as u32;
        self.shared.update(|o| o.proposals.push(proposals));
        self.reply(Ok(ReplyValue::Created(n)))
    }
}

impl credentials::Host for State {
    fn entry_login(&mut self) -> u32 {
        if self.config.entry.is_none() {
            return self.reply(Err(Failure::Denied("this helper serves no entry".into())));
        }
        if let Some(login) = self.released.clone() {
            return self.reply(Ok(ReplyValue::Login(login)));
        }
        match self.config.login.clone() {
            Some(login) => {
                self.released = Some(login.clone());
                self.shared.update(|o| o.logins_released += 1);
                self.reply(Ok(ReplyValue::Login(login)))
            }
            None => self.reply(Err(Failure::Cancelled)),
        }
    }
}

impl storage::Host for State {
    fn get(&mut self, key: String) -> u32 {
        let value = self.shared.update(|o| o.storage.get(&key).cloned());
        self.reply(Ok(ReplyValue::Value(value)))
    }
    fn set(&mut self, key: String, value: Vec<u8>) -> u32 {
        if self.holds_secret(&value) || self.holds_secret(key.as_bytes()) {
            let f = self.refuse_secret("storage");
            return self.reply(Err(f));
        }
        self.shared.update(|o| o.storage.insert(key, value));
        self.reply(Ok(ReplyValue::None))
    }
    fn delete(&mut self, key: String) -> u32 {
        self.shared.update(|o| o.storage.remove(&key));
        self.reply(Ok(ReplyValue::None))
    }
    fn keys(&mut self, prefix: String) -> u32 {
        let mut keys: Vec<String> =
            self.shared.update(|o| o.storage.keys().filter(|k| k.starts_with(&prefix)).cloned().collect());
        keys.sort();
        self.reply(Ok(ReplyValue::Keys(keys)))
    }
}

impl clipboard::Host for State {
    fn write_text(&mut self, text: String) -> u32 {
        if self.holds_secret(text.as_bytes()) {
            let f = self.refuse_secret("clipboard");
            return self.reply(Err(f));
        }
        self.shared.update(|o| o.clipboard.push(text));
        self.reply(Ok(ReplyValue::None))
    }
}

impl files::Host for State {
    fn save(&mut self, suggested_name: String, data: Vec<u8>) -> u32 {
        if !self.config.permissions.files_save {
            return self.reply(Err(Failure::Denied("no permission to save files".into())));
        }
        if data.len() > 100 * 1024 * 1024 {
            return self.reply(Err(Failure::Invalid("more than 100 MiB".into())));
        }
        self.shared.update(|o| o.saved_files.push((suggested_name, data)));
        self.reply(Ok(ReplyValue::None))
    }
    fn open(&mut self) -> u32 {
        if !self.config.permissions.files_open {
            return self.reply(Err(Failure::Denied("no permission to open files".into())));
        }
        match self.config.file_to_open.clone() {
            Some(file) => self.reply(Ok(ReplyValue::File(file))),
            None => self.reply(Err(Failure::Cancelled)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::bastion::plugin::events::Host as _;
    use crate::bindings::bastion::plugin::net::Host as _;
    use std::sync::mpsc::channel;

    fn state() -> (State, std::sync::mpsc::Sender<Event>, Arc<Shared>) {
        let (tx, rx) = channel();
        let shared = Arc::new(Shared::default());
        let config = Config {
            entry: Some(Entry { id: "e".into(), name: "e".into(), host: "127.0.0.1".into(), port: 7, fields: vec![] }),
            idle_limit: Duration::from_millis(200),
            ..Config::default()
        };
        let s = State::new(config, Box::new(crate::LineEcho), rx, shared.clone(), Arc::default());
        (s, tx, shared)
    }

    /// Hands out events until `stop`, returning the replies seen on the way.
    fn drain_to_stop(s: &mut State) -> Vec<Reply> {
        let mut replies = Vec::new();
        loop {
            match s.next() {
                Event::Stop => return replies,
                Event::Reply(r) => replies.push(r),
                _ => {}
            }
        }
    }

    fn aborts(shared: &Shared) -> HashMap<u32, Vec<u8>> {
        shared.outputs.lock().unwrap().aborts.clone()
    }

    #[test]
    fn a_second_registration_replaces_the_first() {
        let (mut s, tx, shared) = state();
        s.connect(None);
        s.register_abort(1, b"first".to_vec());
        s.register_abort(1, b"second".to_vec());
        tx.send(Event::Stop).unwrap();
        let replies = drain_to_stop(&mut s);
        assert!(replies.iter().all(|r| r.outcome.is_ok()), "{replies:?}");
        assert_eq!(aborts(&shared).get(&1).map(Vec::as_slice), Some(&b"second"[..]));
    }

    #[test]
    fn after_stop_abort_bytes_can_be_neither_cleared_nor_registered() {
        let (mut s, tx, shared) = state();
        s.connect(None);
        s.connect(None);
        s.register_abort(1, b"cancel".to_vec());
        tx.send(Event::Stop).unwrap();
        drain_to_stop(&mut s);
        s.clear_abort(1);
        s.close(1);
        let refused = s.register_abort(2, b"late".to_vec());
        let replace = s.register_abort(1, b"other".to_vec());
        let late: Vec<Reply> = std::iter::from_fn(|| s.local.pop_front())
            .filter_map(|e| match e { Event::Reply(r) => Some(r), _ => None })
            .collect();
        for id in [refused, replace] {
            let r = late.iter().find(|r| r.request == id).unwrap();
            assert!(matches!(r.outcome, Err(Failure::Denied(_))), "{r:?}");
        }
        assert_eq!(aborts(&shared), HashMap::from([(1, b"cancel".to_vec())]));
    }

    #[test]
    fn before_stop_clear_removes_the_registration() {
        let (mut s, _tx, shared) = state();
        s.connect(None);
        s.register_abort(1, b"cancel".to_vec());
        s.clear_abort(1);
        assert!(aborts(&shared).is_empty());
    }
}
