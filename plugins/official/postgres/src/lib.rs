//! The Official PostgreSQL plugin, stage 1, plugin side (spec section 11; PLUG-08).
//!
//! One view per query tab ("New Query" opens another): an object browser on the left, a query
//! tool and a details pane on the right. Each view has two sessions on the entry's server: one
//! for queries, one for the browser, so browsing works while a query runs.
//!
//! - The login comes from the core (`credentials.entry-login`), released once per helper. The
//!   plugin keeps it in memory for the helper's life so a second view can log in, and never
//!   logs, stores or shows it.
//! - The core runs TLS with the entry's TLS mode; the plugin asks the server for TLS first.
//! - Read only by default ("Allow changes" per view); row limit and timeout as in the built-in
//!   page. Cancel sends PostgreSQL's cancel request on a second stream; the same bytes are
//!   registered as abort bytes while a query runs, so a stopped helper cancels too.
//! - Results page through the core's table, sort locally, copy as tab-separated text and
//!   export to CSV.

// `Error` carries the server's error fields; results are not on a hot path, so the size of
// the `Err` variant is fine.
#![allow(clippy::result_large_err)]

pub mod catalog;
pub mod client;
pub mod csv;
pub mod json;
pub mod plan;
pub mod scram;
pub mod sqllex;
pub mod types;
pub mod wire;

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bastion_plugin_sdk::net::Stream;
use bastion_plugin_sdk::ui::{self, BannerLevel, Cell, ChoiceField, Column, Component, ErrorMark, NumberField, Row, Table, ToggleField, Tree, TreeItem, MenuItem, ViewBuilder};
use bastion_plugin_sdk::{clipboard, credentials, done, export_plugin, files, host, log, task, ChildrenAsk, Failure, Input, NodeId, Plugin, RowsAsk, Task, View};

use catalog::Node as Obj;
use client::{Client, Error, Login, ResultSet, Transport, DEFAULT_MAX_ROWS, DEFAULT_TIMEOUT_SECS, MAX_ROWS_LIMIT, MAX_TIMEOUT_SECS};

// ---- The view ------------------------------------------------------------------------------

// Node ids, in the order `view_nodes` builds them. The frame matches the other official
// plugins: a header bar (server, database and user, Refresh), then a navigator tree on the
// left and, on the right, an SQL editor tab (toolbar, editor, then Results, Messages and Plan
// tabs over a status line) and an object editor tab with Properties, DDL and Data.
const HEADER: NodeId = 1;
const SERVER: NodeId = 2;
const TARGET: NodeId = 3;
const REFRESH: NodeId = 4;
const BODY: NodeId = 5;
const TREE: NodeId = 6;
const TABS: NodeId = 7;
const SQL_TAB: NodeId = 8;
const SQL_SPLIT: NodeId = 9;
const EDITOR_TOP: NodeId = 10;
const EDITOR_BAR: NodeId = 11;
const RUN: NodeId = 12;
const CANCEL: NodeId = 13;
const EXPLAIN: NodeId = 14;
const ANALYZE: NodeId = 15;
const CHANGES: NodeId = 16;
const LIMIT: NodeId = 17;
const TIMEOUT: NodeId = 18;
const EDITOR: NodeId = 19;
const RESULTS_AREA: NodeId = 20;
const RESULT_TABS: NodeId = 21;
const RESULTS_TAB: NodeId = 22;
const RESULTS_BAR: NodeId = 23;
const SET_PICK: NodeId = 24;
const COPY: NodeId = 25;
const EXPORT: NodeId = 26;
const RESULTS: NodeId = 27;
const MESSAGES_TAB: NodeId = 28;
const MESSAGES: NodeId = 29;
const PLAN_TAB: NodeId = 30;
const PLAN_STATUS: NodeId = 31;
const PLAN: NodeId = 32;
const STATUS: NodeId = 33;
const OBJECT_TAB: NodeId = 34;
const OBJ_TITLE: NodeId = 35;
const OBJ_TABS: NodeId = 36;
const PROPS_TAB: NodeId = 37;
const PROPS: NodeId = 38;
const DDL_TAB: NodeId = 39;
const DDL: NodeId = 40;
const DATA_TAB: NodeId = 41;
const DATA_BAR: NodeId = 42;
const FILTER: NodeId = 43;
const APPLY: NodeId = 44;
const PREV: NodeId = 45;
const NEXT: NodeId = 46;
const DATA_STATUS: NodeId = 47;
const DATA: NodeId = 48;

/// Characters of one cell the table shows (CSV and copy get the whole value).
const MAX_CELL_CHARS: usize = 4_000;
/// The most characters in a column title.
const MAX_TITLE: usize = 32;

fn column(title: &str, sortable: bool) -> Column {
    Column { title: title.chars().take(MAX_TITLE).collect(), sortable, editable: false }
}

fn number(label: &str, value: f64, max: f64) -> Component {
    Component::NumberField(NumberField { label: label.into(), value, min: Some(1.0), max: Some(max) })
}

fn results_table(set: Option<&ResultSet>) -> Component {
    let columns = set.map(|s| s.columns.iter().map(|c| column(&c.name, true)).collect()).unwrap_or_default();
    Component::Table(Table { columns, total_rows: Some(set.map_or(0, |s| s.rows.len() as u64)) })
}

fn set_picker(sets: &[ResultSet], current: usize) -> Component {
    let options = sets.iter().enumerate().map(|(i, s)| format!("{}: {}", i + 1, if s.tag.is_empty() { "result" } else { &s.tag }).chars().take(MAX_TITLE).collect()).collect();
    Component::Choice(ChoiceField { label: "Result".into(), options, selected: if sets.is_empty() { None } else { Some(current as u32) } })
}

fn plan_tree() -> Component {
    let cols = ["Node", "Startup cost", "Total cost", "Est. rows", "Actual ms", "Actual rows", "Loops"];
    Component::Tree(Tree { columns: cols.iter().map(|c| column(c, false)).collect() })
}

fn props_table(rows: usize) -> Component {
    Component::Table(Table { columns: vec![column("Property", false), column("Value", false)], total_rows: Some(rows as u64) })
}

/// The whole view, in id order.
pub fn view_nodes(sql: &str) -> Vec<ui::Node> {
    let mut b = ViewBuilder::new(ui::stack());
    let root = b.root();
    assert_eq!(b.add(root, Component::Toolbar), HEADER);
    assert_eq!(b.add(HEADER, ui::label("PostgreSQL")), SERVER);
    assert_eq!(b.add(HEADER, ui::label("Not connected")), TARGET);
    assert_eq!(b.add(HEADER, ui::icon_button("Refresh", "refresh", true)), REFRESH);
    assert_eq!(b.add(root, Component::Split(ui::Axis::Horizontal)), BODY);
    assert_eq!(b.add(BODY, navigator()), TREE);
    assert_eq!(b.add(BODY, Component::Tabs), TABS);
    assert_eq!(b.add(TABS, Component::Tab("SQL Editor".into())), SQL_TAB);
    assert_eq!(b.add(SQL_TAB, Component::Split(ui::Axis::Vertical)), SQL_SPLIT);
    assert_eq!(b.add(SQL_SPLIT, ui::stack()), EDITOR_TOP);
    assert_eq!(b.add(EDITOR_TOP, Component::Toolbar), EDITOR_BAR);
    assert_eq!(b.add(EDITOR_BAR, ui::button("Run")), RUN);
    assert_eq!(b.add(EDITOR_BAR, ui::button("Cancel")), CANCEL);
    assert_eq!(b.add(EDITOR_BAR, ui::button("Explain")), EXPLAIN);
    assert_eq!(b.add(EDITOR_BAR, ui::button("Explain Analyze")), ANALYZE);
    assert_eq!(b.add(EDITOR_BAR, Component::Toggle(ToggleField { label: "Allow changes".into(), value: false })), CHANGES);
    assert_eq!(b.add(EDITOR_BAR, number("Row limit", DEFAULT_MAX_ROWS as f64, MAX_ROWS_LIMIT as f64)), LIMIT);
    assert_eq!(b.add(EDITOR_BAR, number("Timeout (s)", DEFAULT_TIMEOUT_SECS as f64, MAX_TIMEOUT_SECS as f64)), TIMEOUT);
    assert_eq!(b.add(EDITOR_TOP, ui::code_editor("sql", sql)), EDITOR);
    assert_eq!(b.add(SQL_SPLIT, ui::stack()), RESULTS_AREA);
    assert_eq!(b.add(RESULTS_AREA, Component::Tabs), RESULT_TABS);
    assert_eq!(b.add(RESULT_TABS, Component::Tab("Results".into())), RESULTS_TAB);
    assert_eq!(b.add(RESULTS_TAB, Component::Toolbar), RESULTS_BAR);
    assert_eq!(b.add(RESULTS_BAR, set_picker(&[], 0)), SET_PICK);
    assert_eq!(b.add(RESULTS_BAR, ui::button("Copy")), COPY);
    assert_eq!(b.add(RESULTS_BAR, ui::button("Export CSV")), EXPORT);
    assert_eq!(b.add(RESULTS_TAB, results_table(None)), RESULTS);
    assert_eq!(b.add(RESULT_TABS, Component::Tab("Messages".into())), MESSAGES_TAB);
    assert_eq!(b.add(MESSAGES_TAB, ui::label("No messages.")), MESSAGES);
    assert_eq!(b.add(RESULT_TABS, Component::Tab("Plan".into())), PLAN_TAB);
    assert_eq!(b.add(PLAN_TAB, ui::label("Explain or Explain Analyze shows the plan here.")), PLAN_STATUS);
    assert_eq!(b.add(PLAN_TAB, plan_tree()), PLAN);
    assert_eq!(b.add(RESULTS_AREA, ui::label("Not connected.")), STATUS);
    assert_eq!(b.add(TABS, Component::Tab("Object".into())), OBJECT_TAB);
    assert_eq!(b.add(OBJECT_TAB, ui::label("Select an object in the navigator.")), OBJ_TITLE);
    assert_eq!(b.add(OBJECT_TAB, Component::Tabs), OBJ_TABS);
    assert_eq!(b.add(OBJ_TABS, Component::Tab("Properties".into())), PROPS_TAB);
    assert_eq!(b.add(PROPS_TAB, props_table(0)), PROPS);
    assert_eq!(b.add(OBJ_TABS, Component::Tab("DDL".into())), DDL_TAB);
    assert_eq!(b.add(DDL_TAB, Component::CodeEditor(ui::CodeEditor { language: "sql".into(), text: String::new(), read_only: true })), DDL);
    assert_eq!(b.add(OBJ_TABS, Component::Tab("Data".into())), DATA_TAB);
    assert_eq!(b.add(DATA_TAB, Component::Toolbar), DATA_BAR);
    assert_eq!(b.add(DATA_BAR, ui::text_field("Filter (WHERE)", "")), FILTER);
    assert_eq!(b.add(DATA_BAR, ui::button("Apply")), APPLY);
    assert_eq!(b.add(DATA_BAR, ui::button("Previous")), PREV);
    assert_eq!(b.add(DATA_BAR, ui::button("Next")), NEXT);
    assert_eq!(b.add(DATA_TAB, ui::label("Tables and views show their rows here.")), DATA_STATUS);
    assert_eq!(b.add(DATA_TAB, results_table(None)), DATA);
    b.finish()
}

fn navigator() -> Component {
    Component::Tree(Tree { columns: vec![column("Object", false)] })
}

fn parent_of(id: NodeId) -> NodeId {
    match id {
        SERVER..=REFRESH => HEADER,
        TREE => BODY,
        RUN..=TIMEOUT => EDITOR_BAR,
        EDITOR => EDITOR_TOP,
        SET_PICK..=EXPORT => RESULTS_BAR,
        RESULTS => RESULTS_TAB,
        MESSAGES => MESSAGES_TAB,
        PLAN_STATUS | PLAN => PLAN_TAB,
        STATUS => RESULTS_AREA,
        OBJ_TITLE => OBJECT_TAB,
        PROPS => PROPS_TAB,
        DDL => DDL_TAB,
        FILTER..=NEXT => DATA_BAR,
        DATA_STATUS | DATA => DATA_TAB,
        _ => 0,
    }
}

fn patch(view: View, id: NodeId, component: Component) {
    let _ = view.patch(vec![ui::Node { id, parent: Some(parent_of(id)), component }], vec![]);
}

// ---- Glue to the core's stream -------------------------------------------------------------

/// The core's words for a failure.
pub fn describe(f: &Failure) -> String {
    match f {
        Failure::Denied(why) | Failure::Invalid(why) | Failure::Io(why) => why.clone(),
        Failure::TimedOut => "The server did not answer in time.".into(),
        Failure::Cancelled => "Cancelled.".into(),
    }
}

/// A [`Transport`] over the core's stream.
pub struct Net(pub Stream);

impl Transport for Net {
    async fn read(&mut self, max: usize) -> Result<Vec<u8>, Error> {
        self.0.read(max).await.map_err(|f| Error::Transport(describe(&f)))
    }
    async fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.0.write(data).await.map_err(|f| Error::Transport(describe(&f)))
    }
    async fn start_tls(&mut self) -> Result<(), Error> {
        self.0.start_tls().await.map_err(|f| Error::Transport(describe(&f)))
    }
}

/// `wasi:random/random`: the host's secure random source.
#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code, clippy::all)]
mod wasi_random {
    wit_bindgen::generate!({ world: "nonce", path: "wit" });
    pub use self::wasi::random::random::get_random_bytes;
}

/// 24 secure random bytes. On a build machine (unit tests only) std's hasher keys stand in.
fn random_bytes() -> Vec<u8> {
    #[cfg(target_arch = "wasm32")]
    {
        wasi_random::get_random_bytes(24)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::hash::{BuildHasher, Hasher};
        let state = std::collections::hash_map::RandomState::new();
        (0..3u64).flat_map(|i| {
            let mut h = state.build_hasher();
            h.write_u64(i);
            h.finish().to_le_bytes()
        }).collect()
    }
}

/// A SCRAM client nonce: 24 random bytes as base64, so it is printable and has no comma.
fn nonce() -> String {
    STANDARD.encode(random_bytes())
}

// ---- State ---------------------------------------------------------------------------------

#[derive(Default)]
struct Session {
    /// Taken out while a query runs.
    query: Option<Client<Net>>,
    browse: Option<Client<Net>>,
    running: bool,
    cancel: Option<Vec<u8>>,
    sql: String,
    allow_changes: bool,
    limit: usize,
    timeout: u32,
    /// Every result set of the last run (DBeaver shows one results tab per set); `current`
    /// is the one in the grid.
    sets: Vec<ResultSet>,
    current: usize,
    selected: Vec<usize>,
    /// The object editor: the selected object's properties and first rows.
    props: Vec<Vec<Option<String>>>,
    data: Option<ResultSet>,
    /// The Data tab's object, filter, server-side sort and page (PLUG-08b).
    data_obj: Option<Obj>,
    filter: String,
    data_order: Option<(String, bool)>,
    data_offset: u64,
    data_more: bool,
    /// The last EXPLAIN, shown in the Plan tab.
    plan: Option<plan::Plan>,
}

impl Session {
    fn result(&self) -> Option<&ResultSet> {
        self.sets.get(self.current)
    }
}

/// The entry's login, asked for once: views that start together wait for the first ask.
#[derive(Default)]
enum LoginSlot {
    #[default]
    Idle,
    Asking(Vec<Waker>),
    Done(Result<(String, String), String>),
}

/// Waits until the first ask for the login has finished.
struct WaitLogin<'a>(&'a RefCell<LoginSlot>);

impl Future for WaitLogin<'_> {
    type Output = Result<(String, String), String>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut slot = self.0.borrow_mut();
        match &mut *slot {
            LoginSlot::Done(r) => Poll::Ready(r.clone()),
            LoginSlot::Asking(wakers) => {
                wakers.push(cx.waker().clone());
                Poll::Pending
            }
            LoginSlot::Idle => Poll::Ready(Err("the login was not asked for".into())),
        }
    }
}

#[derive(Default)]
pub struct Postgres {
    sessions: RefCell<HashMap<View, Session>>,
    /// The entry's login, released once per helper; kept in memory only. A refusal is kept
    /// too: the core releases the login once, so asking again cannot succeed.
    login: RefCell<LoginSlot>,
}

const START_SQL: &str = "SELECT version();";

impl Postgres {
    fn with<R>(&self, view: View, f: impl FnOnce(&mut Session) -> R) -> Option<R> {
        self.sessions.borrow_mut().get_mut(&view).map(f)
    }

    async fn login(&self) -> Result<(String, String), String> {
        let first = {
            let mut slot = self.login.borrow_mut();
            match &*slot {
                LoginSlot::Done(r) => return r.clone(),
                LoginSlot::Asking(_) => false,
                LoginSlot::Idle => {
                    *slot = LoginSlot::Asking(Vec::new());
                    true
                }
            }
        };
        if !first {
            return WaitLogin(&self.login).await;
        }
        let r = credentials::entry_login().await.map(|l| (l.user, l.secret)).map_err(|f| describe(&f));
        let waiting = std::mem::replace(&mut *self.login.borrow_mut(), LoginSlot::Done(r.clone()));
        if let LoginSlot::Asking(wakers) = waiting {
            wakers.into_iter().for_each(Waker::wake);
        }
        r
    }

    async fn open_client(&self, view: View, timeout: u32) -> Result<Client<Net>, String> {
        let entry = host::entry().ok_or("This view is not opened on a connection.")?;
        // The stream and TLS first: the core releases the login only once TLS is up where the
        // entry needs it (spec section 5).
        let stream = Stream::connect(None).await.map_err(|f| describe(&f))?;
        let client = Client::negotiate(Net(stream)).await.map_err(|e| e.to_string())?;
        let (user, secret) = self.login().await?;
        let database = entry.fields.iter().find(|(k, _)| k == "database").map(|(_, v)| v.trim().to_string()).filter(|d| !d.is_empty()).unwrap_or_else(|| user.clone());
        let login = Login { user: &user, secret: &secret, database: &database };
        let client = client.sign_in(&login, &nonce(), timeout).await.map_err(|e| e.to_string())?;
        patch(view, SERVER, ui::label(&header_server(&client.server_version)));
        patch(view, TARGET, ui::label(&header_target(&database, &user)));
        Ok(client)
    }

    fn status(&self, view: View, text: &str, error: bool) {
        let c = if error { ui::banner(BannerLevel::Error, text) } else { ui::label(text) };
        patch(view, STATUS, c);
        patch(view, MESSAGES, ui::label(text));
    }

    async fn run(self: Rc<Self>, view: View, sql: String) {
        let Some((client, limit, timeout, changes)) = self.with(view, |s| {
            if s.running {
                return None;
            }
            s.running = true;
            Some((s.query.take(), s.limit, s.timeout, s.allow_changes))
        }).flatten() else {
            return self.status(view, "A query is already running.", true);
        };
        patch(view, STATUS, Component::Progress(None));
        let mut client = match client {
            Some(c) => c,
            None => match self.open_client(view, timeout).await {
                Ok(c) => c,
                Err(e) => {
                    self.with(view, |s| s.running = false);
                    return self.status(view, &e, true);
                }
            },
        };
        if client.read_only() == changes {
            if let Err(e) = client.set_read_only(!changes).await {
                self.with(view, |s| s.running = false);
                return self.status(view, &e.to_string(), true);
            }
        }
        let cancel = client.cancel_bytes();
        if let Some(bytes) = &cancel {
            // If the helper stops while this runs, the core sends the cancel request.
            let _ = client.transport().0.register_abort(bytes).await;
        }
        self.with(view, |s| s.cancel = cancel.clone());
        let started = std::time::Instant::now();
        let outcome = client.run(&sql, limit).await;
        let took = started.elapsed().as_millis();
        if cancel.is_some() {
            client.transport().0.clear_abort();
        }
        let ran_whole = self.with(view, |s| s.sql.trim() == sql.trim()).unwrap_or(false);
        let (text, error, set, sets, current) = match outcome {
            Ok(out) => {
                let current = out.sets.iter().rposition(|s| !s.columns.is_empty()).unwrap_or(out.sets.len().saturating_sub(1));
                let set = out.sets.get(current).cloned();
                let mut marks = Vec::new();
                let text = match &out.error {
                    Some(e) => {
                        if let (Some(pos), true) = (e.position, ran_whole) {
                            marks.push(mark_at(&sql, pos, &e.message));
                        }
                        e.to_string()
                    }
                    None => status_line(&summary(set.as_ref(), limit), took, changes),
                };
                let _ = view.mark_errors(EDITOR, &marks);
                self.with(view, |s| s.query = Some(client));
                (text, out.error.is_some(), set, out.sets, current)
            }
            // The session is gone; the next run opens a new one.
            Err(e) => (e.to_string(), true, None, Vec::new(), 0),
        };
        patch(view, SET_PICK, set_picker(&sets, current));
        self.with(view, |s| {
            s.running = false;
            s.cancel = None;
            s.selected.clear();
            s.sets = sets;
            s.current = current;
        });
        patch(view, RESULTS, results_table(set.as_ref()));
        self.status(view, &text, error);
    }

    async fn cancel_running(self: Rc<Self>, view: View) {
        let Some(bytes) = self.with(view, |s| s.cancel.clone()).flatten() else { return };
        match Stream::connect(None).await {
            Ok(stream) => {
                if stream.write(&bytes).await.is_err() {
                    log::warn("the cancel request did not go out");
                }
            }
            Err(f) => self.status(view, &format!("Cancel failed: {}", describe(&f)), true),
        }
    }

    /// A query on the browser's session, which it opens when needed.
    async fn browse(&self, view: View, sql: &str) -> Result<ResultSet, String> {
        self.browse_with(view, sql, false).await
    }

    /// `browse`, or for SQL with user text in it (`user_text`, the Data tab's filter): one
    /// statement with the extended protocol, inside `BEGIN READ ONLY` ... `ROLLBACK`.
    async fn browse_with(&self, view: View, sql: &str, user_text: bool) -> Result<ResultSet, String> {
        let timeout = self.with(view, |s| s.timeout).unwrap_or(DEFAULT_TIMEOUT_SECS);
        let taken = self.with(view, |s| s.browse.take()).flatten();
        let mut client = match taken {
            Some(c) => c,
            None => self.open_client(view, timeout).await?,
        };
        let out = if user_text { client.run_one_read_only(sql, MAX_ROWS_LIMIT).await } else { client.run(sql, MAX_ROWS_LIMIT).await };
        match out {
            Ok(out) => {
                self.with(view, |s| s.browse = Some(client));
                match out.error {
                    Some(e) => Err(e.to_string()),
                    None => Ok(out.sets.into_iter().last().unwrap_or_default()),
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }

    async fn children(self: Rc<Self>, ask: ChildrenAsk) {
        let parent = match ask.parent.as_deref() {
            None => None,
            Some(key) => match Obj::parse(key) {
                Some(o) => Some(o),
                None => return ui::refuse(ask.ask, "Unknown item."),
            },
        };
        let nodes = match parent {
            None => vec![Obj::Databases, Obj::Schemas, Obj::Extensions, Obj::Roles],
            Some(p) => match (p.fixed_children(), p.children_sql()) {
                (Some(fixed), _) => fixed,
                (None, Some(Ok(sql))) => match self.browse(View(ask.view), &sql).await {
                    Ok(set) => set.rows.into_iter().filter_map(|r| {
                        let name = r.first().cloned().flatten()?;
                        let oid = r.get(1).cloned().flatten().and_then(|o| o.parse().ok());
                        p.child(name, oid)
                    }).collect(),
                    Err(e) => return ui::refuse(ask.ask, &e),
                },
                _ => return ui::refuse(ask.ask, "This item has no children."),
            },
        };
        // Navigator counts ("Tables (3)"): one query for the level; without an answer, plain labels.
        let counts: Vec<Option<String>> = match Obj::count_sql(&nodes) {
            Some(sql) => match self.browse(View(ask.view), &sql).await {
                Ok(set) => set.rows.into_iter().next().unwrap_or_default(),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };
        let mut next = counts.into_iter();
        let items: Vec<TreeItem> = nodes.iter().filter_map(|o| {
            let count = if o.children_sql().is_some() { next.next().flatten() } else { None };
            let mut item = tree_item(o)?;
            item.label = o.label_with_count(count.as_deref());
            Some(item)
        }).collect();
        let _ = ui::provide_children(ask.ask, &items);
    }

    /// The object editor: title, Properties, DDL and, for tables and views, Data.
    async fn show_details(self: Rc<Self>, view: View, obj: Obj) {
        patch(view, OBJ_TITLE, ui::label(&obj.label().chars().take(200).collect::<String>()));
        let props: Vec<Vec<Option<String>>> = match obj.properties_sql() {
            Some(Ok(sql)) => self.browse(view, &sql).await.map(|s| s.rows).unwrap_or_default(),
            _ => Vec::new(),
        };
        let n = props.len();
        self.with(view, |s| s.props = props);
        patch(view, PROPS, props_table(n));
        let ddl = match obj.ddl_sql() {
            Some(Ok(sql)) => match self.browse(view, &sql).await {
                Ok(set) => set.rows.first().and_then(|r| r.first().cloned().flatten()).unwrap_or_default(),
                Err(e) => format!("-- {e}"),
            },
            _ => String::new(),
        };
        patch(view, DDL, Component::CodeEditor(ui::CodeEditor { language: "sql".into(), text: ddl, read_only: true }));
        let is_data = obj.data_sql("", None, 1).is_some();
        self.with(view, |s| {
            s.data_obj = is_data.then(|| obj.clone());
            s.data_order = None;
            s.data_offset = 0;
        });
        self.load_data(view).await;
    }

    /// One page of the Data tab's object, with the filter and sort run on the server
    /// (PLUG-08b). Asks for one row more than a page to know whether there is a next page.
    async fn load_data(&self, view: View) {
        let Some((obj, filter, order, offset)) = self.with(view, |s| (s.data_obj.clone(), s.filter.clone(), s.data_order.clone(), s.data_offset)) else { return };
        let Some(obj) = obj else {
            self.with(view, |s| s.data = None);
            patch(view, DATA_STATUS, ui::label("Tables and views show their rows here."));
            patch(view, DATA, results_table(None));
            return;
        };
        let (data, text, error) = match obj.data_page_sql(&filter, order.as_ref().map(|(c, a)| (c.as_str(), *a)), DATA_PAGE_ROWS + 1, offset) {
            Some(Ok(sql)) => match self.browse_with(view, &sql, true).await {
                Ok(mut set) => {
                    let more = set.rows.len() > DATA_PAGE_ROWS;
                    set.rows.truncate(DATA_PAGE_ROWS);
                    self.with(view, |s| s.data_more = more);
                    let t = data_summary(offset, set.rows.len(), more);
                    (Some(set), t, false)
                }
                Err(e) => (None, e, true),
            },
            Some(Err(_)) => (None, "The filter must be one expression: no ';', comments, dollar quotes or unbalanced quotes and parentheses.".into(), true),
            None => (None, "Tables and views show their rows here.".into(), false),
        };
        patch(view, DATA_STATUS, if error { ui::banner(BannerLevel::Error, &text) } else { ui::label(&text) });
        patch(view, DATA, results_table(data.as_ref()));
        self.with(view, |s| s.data = data);
    }

    async fn data_page(self: Rc<Self>, view: View, forward: bool) {
        let go = self.with(view, |s| {
            if forward && s.data_more {
                s.data_offset += DATA_PAGE_ROWS as u64;
                true
            } else if !forward && s.data_offset > 0 {
                s.data_offset = s.data_offset.saturating_sub(DATA_PAGE_ROWS as u64);
                true
            } else {
                false
            }
        });
        if go == Some(true) {
            self.load_data(view).await;
        }
    }

    /// Sorting the Data tab sorts on the server, so every page is in order.
    async fn data_sort(self: Rc<Self>, view: View, col: u32, asc: bool) {
        let name = self.with(view, |s| s.data.as_ref().and_then(|d| d.columns.get(col as usize)).map(|c| c.name.clone())).flatten();
        let Some(name) = name else { return };
        self.with(view, |s| {
            s.data_order = Some((name, asc));
            s.data_offset = 0;
        });
        self.load_data(view).await;
    }

    /// EXPLAIN (or EXPLAIN ANALYZE) of the editor's SQL, on the tab's query session, shown as
    /// a tree in the Plan tab.
    async fn explain(self: Rc<Self>, view: View, analyze: bool) {
        let sql = self.with(view, |s| s.sql.clone()).unwrap_or_default();
        let wrapped = match plan::explain_sql(&sql, analyze) {
            Ok(w) => w,
            Err(e) => return patch(view, PLAN_STATUS, ui::banner(BannerLevel::Error, &e)),
        };
        patch(view, PLAN_STATUS, Component::Progress(None));
        let Some((client, timeout, changes)) = self.with(view, |s| {
            if s.running {
                return None;
            }
            s.running = true;
            Some((s.query.take(), s.timeout, s.allow_changes))
        }).flatten() else {
            return patch(view, PLAN_STATUS, ui::banner(BannerLevel::Error, "A query is already running."));
        };
        let result = async {
            let mut client = match client {
                Some(c) => c,
                None => self.open_client(view, timeout).await?,
            };
            if client.read_only() == changes {
                client.set_read_only(!changes).await.map_err(|e| e.to_string())?;
            }
            let cancel = client.cancel_bytes();
            if let Some(bytes) = &cancel {
                let _ = client.transport().0.register_abort(bytes).await;
            }
            self.with(view, |s| s.cancel = cancel.clone());
            // One statement only, enforced by the server's Parse (extended protocol).
            let out = client.run_one(&wrapped, 10).await;
            if cancel.is_some() {
                client.transport().0.clear_abort();
            }
            let out = out.map_err(|e| e.to_string())?;
            self.with(view, |s| s.query = Some(client));
            if let Some(e) = out.error {
                return Err(e.to_string());
            }
            let text: String = out.sets.iter().rev().find(|s| !s.columns.is_empty()).and_then(|s| s.rows.iter().filter_map(|r| r.first().cloned().flatten()).next()).ok_or("The server sent no plan.")?;
            plan::parse(&text, analyze)
        }.await;
        self.with(view, |s| {
            s.running = false;
            s.cancel = None;
        });
        match result {
            Ok(p) => {
                patch(view, PLAN_STATUS, ui::label(&plan::summary(&p)));
                self.with(view, |s| s.plan = Some(p));
            }
            Err(e) => {
                self.with(view, |s| s.plan = None);
                patch(view, PLAN_STATUS, ui::banner(BannerLevel::Error, &e));
            }
        }
        // A fresh tree: the app asks for its top level again.
        patch(view, PLAN, plan_tree());
    }

    fn plan_children(&self, ask: &ChildrenAsk) -> Result<Vec<TreeItem>, &'static str> {
        self.with(View(ask.view), |s| {
            let p = s.plan.as_ref().ok_or("There is no plan yet.")?;
            let num = |v: Option<f64>| v.map_or(Cell::Null, Cell::Number);
            let item = |i: usize| {
                let n = &p.nodes[i];
                TreeItem {
                    key: plan::key(i),
                    label: n.label.chars().take(500).collect(),
                    icon: Some("plan".into()),
                    has_children: !n.children.is_empty() || !n.details.is_empty(),
                    cells: vec![num(n.startup_cost), num(n.total_cost), num(n.plan_rows), num(n.actual_total_ms), num(n.actual_rows), num(n.loops)],
                    menu: vec![],
                }
            };
            match ask.parent.as_deref() {
                None => Ok(if p.nodes.is_empty() { vec![] } else { vec![item(0)] }),
                Some(k) => {
                    let i = plan::parse_key(k).filter(|i| *i < p.nodes.len()).ok_or("Unknown item.")?;
                    let n = &p.nodes[i];
                    let mut items: Vec<TreeItem> = n.details.iter().enumerate().map(|(d, text)| TreeItem {
                        key: format!("{}:{d}", plan::key(i)),
                        label: text.chars().take(500).collect(),
                        icon: None,
                        has_children: false,
                        cells: vec![],
                        menu: vec![],
                    }).collect();
                    items.extend(n.children.iter().map(|c| item(*c)));
                    Ok(items)
                }
            }
        }).unwrap_or(Err("This view is closed."))
    }

    fn pick_set(&self, view: View, i: u32) {
        let set = self.with(view, |s| {
            if (i as usize) < s.sets.len() {
                s.current = i as usize;
                s.selected.clear();
            }
            s.result().cloned()
        }).flatten();
        patch(view, RESULTS, results_table(set.as_ref()));
    }

    fn sort(&self, view: View, col: u32, asc: bool) {
        self.with(view, |s| {
            if let Some(set) = s.sets.get_mut(s.current) {
                let c = col as usize;
                set.rows.sort_by(|a, b| {
                    let (x, y) = (a.get(c).cloned().flatten(), b.get(c).cloned().flatten());
                    let ord = match (x.as_deref().and_then(|v| v.parse::<f64>().ok()), y.as_deref().and_then(|v| v.parse::<f64>().ok())) {
                        (Some(p), Some(q)) => p.partial_cmp(&q).unwrap_or(std::cmp::Ordering::Equal),
                        // NULLs sort last, as PostgreSQL does by default.
                        _ => match (&x, &y) {
                            (None, None) => std::cmp::Ordering::Equal,
                            (None, _) => std::cmp::Ordering::Greater,
                            (_, None) => std::cmp::Ordering::Less,
                            (Some(p), Some(q)) => p.cmp(q),
                        },
                    };
                    if asc { ord } else { ord.reverse() }
                });
                s.selected.clear();
            }
        });
        let set = self.with(view, |s| s.result().cloned()).flatten();
        patch(view, RESULTS, results_table(set.as_ref()));
    }

    async fn copy(self: Rc<Self>, view: View) {
        let text = self.with(view, |s| {
            let set = s.result()?;
            let rows: Vec<&Vec<Option<String>>> = if s.selected.is_empty() { set.rows.iter().collect() } else { s.selected.iter().filter_map(|i| set.rows.get(*i)).collect() };
            Some(csv::tsv(&rows))
        }).flatten();
        if let Some(text) = text {
            if let Err(f) = clipboard::write_text(&text).await {
                self.status(view, &describe(&f), true);
            }
        }
    }

    async fn export(self: Rc<Self>, view: View) {
        let Some(data) = self.with(view, |s| s.result().map(|set| csv::csv(&set.columns.iter().map(|c| c.name.clone()).collect::<Vec<_>>(), &set.rows))).flatten() else {
            return self.status(view, "There is no result to export.", true);
        };
        match files::save("result.csv", data.as_bytes()).await {
            Ok(()) | Err(Failure::Cancelled) => {}
            Err(f) => self.status(view, &describe(&f), true),
        }
    }
}

/// Rows per page in the Data tab.
const DATA_PAGE_ROWS: usize = 200;

/// The Data tab's status line.
pub fn data_summary(offset: u64, rows: usize, more: bool) -> String {
    if rows == 0 {
        return if offset == 0 { "No rows.".into() } else { "No more rows.".into() };
    }
    let more = if more { "; more on the next page" } else { "" };
    format!("Rows {} to {}{more}.", offset + 1, offset + rows as u64)
}

fn tree_item(o: &Obj) -> Option<TreeItem> {
    let menu = match o {
        Obj::Table(..) | Obj::View(..) | Obj::MatView(..) => vec![MenuItem { id: "data".into(), title: "View Data".into() }],
        _ => vec![],
    };
    Some(TreeItem { key: o.key()?, label: o.label(), icon: Some(o.icon().into()), has_children: o.has_children(), cells: vec![], menu })
}

/// The header's server label: "PostgreSQL 16.4" (the version without the build text).
pub fn header_server(version: &str) -> String {
    match version.split_whitespace().next() {
        Some(v) => format!("PostgreSQL {v}"),
        None => "PostgreSQL".into(),
    }
}

/// The header's database and user, cut to a label's length.
pub fn header_target(database: &str, user: &str) -> String {
    format!("{database} · {user}").chars().take(ui::MAX_LABEL).collect()
}

/// The status line after a run: rows, time and whether the session may change data.
pub fn status_line(summary: &str, millis: u128, changes: bool) -> String {
    let mode = if changes { "Read and write" } else { "Read only" };
    format!("{} · {millis} ms · {mode}", summary.trim_end_matches('.'))
}

/// What the status line says after a run.
pub fn summary(set: Option<&ResultSet>, limit: usize) -> String {
    match set {
        None => "Done.".into(),
        Some(s) if s.columns.is_empty() => s.tag.clone(),
        Some(s) if s.dropped > 0 => format!("{} rows shown; {} more not kept (row limit {limit}).", s.rows.len(), s.dropped),
        Some(s) => format!("{} rows.", s.rows.len()),
    }
}

/// A server error position (1-based characters) as an editor mark (0-based line and column).
pub fn mark_at(sql: &str, position: u32, message: &str) -> ErrorMark {
    let before: String = sql.chars().take(position.saturating_sub(1) as usize).collect();
    let line = before.matches('\n').count() as u32;
    let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) as u32;
    ErrorMark { line, column, message: message.chars().take(500).collect() }
}

/// A result row as typed table cells (PLUG-08b): numbers and booleans by column type, NULL
/// stays NULL (the app shows it dimmed). Columns with no type (`types` shorter) are text.
pub fn cells(types: &[u32], row: &[Option<String>]) -> Vec<Cell> {
    row.iter().enumerate().map(|(i, c)| types::cell(types.get(i).copied().unwrap_or(0), c.as_deref(), MAX_CELL_CHARS)).collect()
}

fn page(types: &[u32], rows: &[Vec<Option<String>>], offset: u64, count: u32) -> Vec<Row> {
    let start = (offset as usize).min(rows.len());
    let end = start.saturating_add((count as usize).min(ui::MAX_ROWS)).min(rows.len());
    rows[start..end].iter().enumerate().map(|(i, r)| Row { key: (start + i).to_string(), cells: cells(types, r) }).collect()
}

fn set_page(set: &ResultSet, offset: u64, count: u32) -> Vec<Row> {
    let types: Vec<u32> = set.columns.iter().map(|c| c.type_oid).collect();
    page(&types, &set.rows, offset, count)
}

impl Plugin for Postgres {
    fn start() -> Self {
        Postgres::default()
    }

    fn open_view(self: Rc<Self>, view: View, _name: String) -> Task {
        self.sessions.borrow_mut().insert(view, Session { sql: START_SQL.into(), limit: DEFAULT_MAX_ROWS, timeout: DEFAULT_TIMEOUT_SECS, ..Default::default() });
        task(async move {
            if let Err(e) = view.set(view_nodes(START_SQL)) {
                log::error(&format!("view refused: {e:?}"));
            }
        })
    }

    fn close_view(self: Rc<Self>, view: View) -> Task {
        // Dropping the clients closes their streams.
        self.sessions.borrow_mut().remove(&view);
        done()
    }

    fn command(self: Rc<Self>, id: String, view: Option<View>) -> Task {
        match (id.as_str(), view) {
            ("new-query", Some(view)) => {
                let sql = self.with(view, |s| s.sql.clone()).unwrap_or_default();
                task(self.run(view, sql))
            }
            _ => done(),
        }
    }

    fn input(self: Rc<Self>, view: View, node: NodeId, input: Input) -> Task {
        match (node, input) {
            (EDITOR, Input::Text(t)) => {
                self.with(view, |s| s.sql = t);
                done()
            }
            (EDITOR, Input::Run(sql)) => {
                // The run's text is the editor's text: Explain and New Query use it too, also for an app
                // that sends the text only with the run (Windows).
                self.with(view, |s| s.sql = sql.clone());
                task(self.run(view, sql))
            }
            (RUN, Input::Pressed) => {
                let sql = self.with(view, |s| s.sql.clone()).unwrap_or_default();
                task(self.run(view, sql))
            }
            (REFRESH, Input::Pressed) => {
                let _ = view.patch(vec![ui::Node { id: TREE, parent: Some(BODY), component: navigator() }], vec![]);
                done()
            }
            (CANCEL, Input::Pressed) => task(self.cancel_running(view)),
            (EXPLAIN, Input::Pressed) => task(self.explain(view, false)),
            (ANALYZE, Input::Pressed) => task(self.explain(view, true)),
            (FILTER, Input::Text(t)) => {
                self.with(view, |s| s.filter = t);
                done()
            }
            (FILTER, Input::Run(t)) => {
                self.with(view, |s| {
                    s.filter = t;
                    s.data_offset = 0;
                });
                task(async move { self.load_data(view).await })
            }
            (APPLY, Input::Pressed) => {
                self.with(view, |s| s.data_offset = 0);
                task(async move { self.load_data(view).await })
            }
            (PREV, Input::Pressed) => task(self.data_page(view, false)),
            (NEXT, Input::Pressed) => task(self.data_page(view, true)),
            (DATA, Input::Sorted((col, asc))) => task(self.data_sort(view, col, asc)),
            (CHANGES, Input::Toggled(on)) => {
                // Applied before the next run, on that run's session.
                self.with(view, |s| s.allow_changes = on);
                done()
            }
            (LIMIT, Input::Number(n)) => {
                self.with(view, |s| s.limit = (n.max(1.0) as usize).min(MAX_ROWS_LIMIT));
                done()
            }
            (TIMEOUT, Input::Number(n)) => {
                let secs = (n.max(1.0) as u32).min(MAX_TIMEOUT_SECS);
                self.with(view, |s| s.timeout = secs);
                task(async move {
                    let taken = self.with(view, |s| s.query.take()).flatten();
                    if let Some(mut c) = taken {
                        let ok = c.set_timeout(secs).await.is_ok();
                        if ok {
                            self.with(view, |s| s.query = Some(c));
                        }
                    }
                })
            }
            (COPY, Input::Pressed) => task(self.copy(view)),
            (EXPORT, Input::Pressed) => task(self.export(view)),
            (SET_PICK, Input::Choice(i)) => {
                self.pick_set(view, i);
                done()
            }
            (RESULTS, Input::Selected(keys)) => {
                self.with(view, |s| s.selected = keys.iter().filter_map(|k| k.parse().ok()).collect());
                done()
            }
            (RESULTS, Input::Sorted((col, asc))) => {
                self.sort(view, col, asc);
                done()
            }
            (TREE, Input::Selected(keys)) => match keys.first().and_then(|k| Obj::parse(k)) {
                Some(obj) => task(self.show_details(view, obj)),
                None => done(),
            },
            (TREE, Input::Menu((key, id))) if id == "data" => match Obj::parse(&key).and_then(|o| o.data_sql("", None, DEFAULT_MAX_ROWS)) {
                Some(Ok(sql)) => {
                    let _ = view.patch(vec![ui::Node { id: EDITOR, parent: Some(parent_of(EDITOR)), component: ui::code_editor("sql", &sql) }], vec![]);
                    self.with(view, |s| s.sql = sql.clone());
                    task(self.run(view, sql))
                }
                _ => done(),
            },
            _ => done(),
        }
    }

    fn rows(self: Rc<Self>, ask: RowsAsk) -> Task {
        let view = View(ask.view);
        let rows = match ask.node {
            RESULTS => self.with(view, |s| s.result().map(|set| set_page(set, ask.offset, ask.count))).flatten(),
            PROPS => self.with(view, |s| page(&[], &s.props, ask.offset, ask.count)),
            DATA => self.with(view, |s| s.data.as_ref().map(|set| set_page(set, ask.offset, ask.count))).flatten(),
            _ => None,
        };
        match rows {
            Some(rows) => {
                let _ = ui::provide_rows(ask.ask, &rows, None);
            }
            None => ui::refuse(ask.ask, "There are no rows yet."),
        }
        done()
    }

    fn children(self: Rc<Self>, ask: ChildrenAsk) -> Task {
        if ask.node == PLAN {
            match self.plan_children(&ask) {
                Ok(items) => {
                    let _ = ui::provide_children(ask.ask, &items);
                }
                Err(e) => ui::refuse(ask.ask, e),
            }
            return done();
        }
        task(Postgres::children(self, ask))
    }

    fn cancel(self: Rc<Self>, view: View) -> Task {
        task(self.cancel_running(view))
    }
}

export_plugin!(Postgres);

#[cfg(test)]
mod tests;
