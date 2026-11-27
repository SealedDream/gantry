//! The plugin against the SDK's fake core, with a scripted PostgreSQL server behind `net`.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use bastion_plugin_sdk::bindings::bastion::plugin::events::{ChildrenAsk, Event, OpenView, ReplyValue, RowsAsk, UiEvent};
use bastion_plugin_sdk::testing::{reply, run_plugin, Call, FakeCore};
use bastion_plugin_sdk::{Entry, Login as CoreLogin};

use super::*;
use crate::client::tests::{auth, complete, data_row, error, msg, ready, row_desc};

/// What the fake server answers to each write on the main stream, in order.
struct Server {
    replies: VecDeque<Vec<u8>>,
    incoming: VecDeque<u8>,
}

fn entry() -> Entry {
    Entry { id: "e1".into(), name: "db".into(), host: "db.example".into(), port: 5432, fields: vec![("database".into(), "app".into())] }
}

fn trusted_login() -> Vec<Vec<u8>> {
    let mut login = auth(0, b"");
    login.extend(msg(b'K', &[0, 0, 0, 42, 0, 0, 0, 7]));
    login.extend(ready());
    let mut setup = complete("SET");
    setup.extend(complete("SET"));
    setup.extend(ready());
    vec![b"S".to_vec(), login, setup]
}

/// A core whose `net` is one scripted server; every stream shares it.
fn core(script: Vec<Vec<u8>>) -> FakeCore {
    core_then(script, vec![])
}

/// As [`core`], and `after` is queued once the server has said everything in its script
/// (the fake core queues replies behind events already waiting, so this is how a test acts
/// after a run has finished).
fn core_then(script: Vec<Vec<u8>>, after: Vec<Event>) -> FakeCore {
    core_steps(script, vec![(0, after)])
}

/// As [`core_then`], with several steps: each `(n, events)` is queued once the server has
/// said everything but its last `n` replies.
fn core_steps(script: Vec<Vec<u8>>, steps: Vec<(usize, Vec<Event>)>) -> FakeCore {
    let server = Rc::new(RefCell::new(Server { replies: script.into(), incoming: VecDeque::new() }));
    let mut steps = steps;
    let mut c = FakeCore::new().respond(move |id, call| {
        let mut s = server.borrow_mut();
        let value = match call {
            Call::Connect(_) => ReplyValue::Opened(1),
            Call::EntryLogin => ReplyValue::Login(CoreLogin { user: "app".into(), secret: "s3cret-pw".into() }),
            Call::Write(..) => {
                if let Some(r) = s.replies.pop_front() {
                    s.incoming.extend(r);
                }
                ReplyValue::None
            }
            Call::Read(_, max) => {
                let n = (*max as usize).min(s.incoming.len());
                let data: Vec<u8> = s.incoming.drain(..n).collect();
                if s.incoming.is_empty() {
                    let left = s.replies.len();
                    if let Some(i) = steps.iter().position(|(n, _)| *n == left) {
                        let mut events = vec![reply(id, Ok(ReplyValue::Data(data)))];
                        events.extend(steps.remove(i).1);
                        return events;
                    }
                }
                ReplyValue::Data(data)
            }
            Call::StartTls(_) | Call::RegisterAbort(..) => ReplyValue::None,
            Call::FilesSave(..) | Call::ClipboardWrite(_) => ReplyValue::None,
            _ => return vec![],
        };
        vec![reply(id, Ok(value))]
    });
    c.entry = Some(entry());
    c.with(Event::OpenView(OpenView { view: 1, name: "postgres".into() }))
}

fn ui(view: u32, node: NodeId, input: Input) -> Event {
    Event::Ui(UiEvent { view, node, input })
}

fn status_of(core: &FakeCore) -> Option<Component> {
    core.plain_calls().into_iter().rev().find_map(|c| match c {
        Call::PatchView(_, nodes, _) if nodes[0].id == STATUS => Some(nodes[0].component.clone()),
        _ => None,
    })
}

fn query_reply() -> Vec<u8> {
    let mut r = row_desc(&["id", "name"]);
    r.extend(data_row(&[Some("1"), Some("a")]));
    r.extend(data_row(&[Some("2"), None]));
    r.extend(complete("SELECT 2"));
    r.extend(ready());
    r
}

#[test]
fn the_view_passes_the_checks() {
    assert_eq!(ui::check(&view_nodes(START_SQL)), Ok(()));
    // Every node the plugin patches keeps its parent.
    for n in view_nodes(START_SQL) {
        if parent_of(n.id) != 0 {
            assert_eq!(n.parent, Some(parent_of(n.id)), "node {}", n.id);
        }
    }
}

#[test]
fn run_connects_with_tls_logs_in_and_shows_rows() {
    let mut script = trusted_login();
    script.push(query_reply());
    let c = core_then(script, vec![Event::Rows(RowsAsk { ask: 9, view: 1, node: RESULTS, offset: 0, count: 100 })])
        .with(ui(1, EDITOR, Input::Text("SELECT id, name FROM t".into())))
        .with(ui(1, RUN, Input::Pressed));
    let c = run_plugin::<Postgres>(c);
    let calls = c.plain_calls();
    // TLS requested and started before the startup message.
    let tls_at = calls.iter().position(|c| matches!(c, Call::StartTls(_))).expect("start-tls");
    let first_write = calls.iter().position(|c| matches!(c, Call::Write(..))).unwrap();
    assert!(first_write < tls_at);
    assert!(matches!(&calls[first_write], Call::Write(_, d) if *d == wire::ssl_request()));
    // The cancel request is registered while the query runs, then cleared.
    assert!(calls.iter().any(|c| matches!(c, Call::RegisterAbort(_, b) if *b == wire::cancel_request(42, 7))));
    assert!(calls.iter().any(|c| matches!(c, Call::ClearAbort(_))));
    assert!(matches!(status_of(&c), Some(Component::Label(ref t)) if t.starts_with("2 rows · ") && t.ends_with(" ms · Read only")), "{:?}", status_of(&c));
    // The header shows the server and the database and user once signed in.
    let header: Vec<String> = calls.iter().filter_map(|c| match c {
        Call::PatchView(_, nodes, _) if nodes[0].id == SERVER || nodes[0].id == TARGET => match &nodes[0].component {
            Component::Label(t) => Some(t.clone()),
            _ => None,
        },
        _ => None,
    }).collect();
    assert!(header.iter().any(|t| t.starts_with("PostgreSQL")) && header.iter().any(|t| t.contains(" · ")), "{header:?}");
    let rows = calls.iter().find_map(|c| match c {
        Call::ProvideRows(9, rows, _) => Some(rows.clone()),
        _ => None,
    });
    let rows = rows.expect("rows");
    assert_eq!(rows.len(), 2);
    assert!(matches!(rows[1].cells[1], Cell::Null));
    // The password never reached a log line.
    assert!(!calls.iter().any(|c| matches!(c, Call::Log(_, t) if t.contains("s3cret"))));
}

#[test]
fn a_second_view_reuses_the_released_login() {
    let mut script = trusted_login();
    script.push(query_reply());
    script.extend(trusted_login());
    script.push(query_reply());
    // The second view starts once the first has run (both share one scripted server).
    let second = vec![Event::OpenView(OpenView { view: 2, name: "postgres".into() }), ui(2, RUN, Input::Pressed)];
    let c = core_steps(script, vec![(4, second)]).with(ui(1, RUN, Input::Pressed));
    let c = run_plugin::<Postgres>(c);
    assert_eq!(c.plain_calls().iter().filter(|c| matches!(c, Call::EntryLogin)).count(), 1);
    assert_eq!(c.plain_calls().iter().filter(|c| matches!(c, Call::Connect(..))).count(), 2, "two streams, one login");
    // TLS starts on the stream before the login is asked for (the core's gate needs that).
    let calls = c.plain_calls();
    let tls = calls.iter().position(|c| matches!(c, Call::StartTls(..))).expect("start-tls");
    let login = calls.iter().position(|c| matches!(c, Call::EntryLogin)).expect("entry-login");
    assert!(tls < login, "TLS before the login");
}

#[test]
fn an_md5_server_is_refused_and_the_password_never_goes_out() {
    let c = core(vec![b"S".to_vec(), auth(5, b"salt")]).with(ui(1, RUN, Input::Pressed));
    let c = run_plugin::<Postgres>(c);
    assert!(matches!(status_of(&c), Some(Component::Banner(ref b)) if b.text.contains("MD5")), "{:?}", status_of(&c));
    assert!(!c.plain_calls().iter().any(|c| matches!(c, Call::Write(_, d) if d.windows(9).any(|w| w == b"s3cret-pw"))));
}

#[test]
fn a_server_error_is_shown_and_marked_in_the_editor() {
    let mut script = trusted_login();
    let mut e = msg(b'E', b"SERROR\0C42601\0Msyntax error\0P8\0\0");
    e.extend(ready());
    script.push(e);
    let c = core(script).with(ui(1, EDITOR, Input::Text("SELECT\nFRM x".into()))).with(ui(1, RUN, Input::Pressed));
    let c = run_plugin::<Postgres>(c);
    assert!(matches!(status_of(&c), Some(Component::Banner(_))));
    let marks = c.plain_calls().into_iter().find_map(|c| match c {
        Call::MarkErrors(_, EDITOR, m) if !m.is_empty() => Some(m.clone()),
        _ => None,
    });
    let m = marks.expect("marks");
    // Position 8 is the `F` of `FRM`: line 1, column 0.
    assert_eq!((m[0].line, m[0].column), (1, 0));
}

#[test]
fn allow_changes_turns_read_only_off_before_the_run() {
    let mut script = trusted_login();
    let mut set = complete("SET");
    set.extend(ready());
    script.push(set);
    script.push(query_reply());
    let c = core(script).with(ui(1, CHANGES, Input::Toggled(true))).with(ui(1, RUN, Input::Pressed));
    let c = run_plugin::<Postgres>(c);
    let writes: Vec<String> = c.plain_calls().iter().filter_map(|c| match c {
        Call::Write(_, d) => Some(String::from_utf8_lossy(d).to_string()),
        _ => None,
    }).collect();
    let off = writes.iter().position(|w| w.contains("read_only = off")).expect("read only off");
    let run = writes.iter().position(|w| w.contains("SELECT version()")).expect("the run");
    assert!(off < run);
}

#[test]
fn the_browser_lists_top_folders_then_schemas_from_the_catalog() {
    // Top folders with navigator counts: one row, one count each.
    let mut script = trusted_login();
    let mut n = row_desc(&["a", "b", "c", "d"]);
    n.extend(data_row(&[Some("1"), Some("2"), Some("0"), Some("3")]));
    n.extend(complete("SELECT 1"));
    n.extend(ready());
    script.push(n);
    let c = run_plugin::<Postgres>(core(script).with(Event::Children(ChildrenAsk { ask: 1, view: 1, node: TREE, parent: None })));
    let top = c.plain_calls().into_iter().find_map(|c| match c {
        Call::ProvideChildren(a, items) => Some((*a, items.iter().map(|i| i.label.clone()).collect::<Vec<_>>())),
        _ => None,
    });
    assert_eq!(top, Some((1, vec!["Databases (1)".into(), "Schemas (2)".into(), "Extensions (0)".into(), "Roles (3)".into()])));

    // Schemas from the catalog (schemas have fixed children, so no count query), then a bad key.
    let mut script = trusted_login();
    let mut r = row_desc(&["nspname"]);
    r.extend(data_row(&[Some("public")]));
    r.extend(data_row(&[Some("we'ird")]));
    r.extend(complete("SELECT 2"));
    r.extend(ready());
    script.push(r);
    let c = core(script)
        .with(Event::Children(ChildrenAsk { ask: 2, view: 1, node: TREE, parent: Obj::Schemas.key() }))
        .with(Event::Children(ChildrenAsk { ask: 3, view: 1, node: TREE, parent: Some("nonsense".into()) }));
    let c = run_plugin::<Postgres>(c);
    let mut provided = c.plain_calls().into_iter().filter_map(|c| match c {
        Call::ProvideChildren(a, items) => Some((*a, items.iter().map(|i| i.label.clone()).collect::<Vec<_>>())),
        _ => None,
    });
    assert_eq!(provided.next(), Some((2, vec!["public".into(), "we'ird".into()])));
    assert!(c.plain_calls().iter().any(|c| matches!(c, Call::Refuse(3, _))));
}

#[test]
fn export_and_copy_use_the_whole_values() {
    let mut script = trusted_login();
    script.push(query_reply());
    let after = vec![ui(1, RESULTS, Input::Selected(vec!["1".into()])), ui(1, COPY, Input::Pressed), ui(1, EXPORT, Input::Pressed)];
    let c = core_then(script, after).with(ui(1, RUN, Input::Pressed));
    let c = run_plugin::<Postgres>(c);
    let calls = c.plain_calls();
    assert!(calls.iter().any(|c| matches!(c, Call::ClipboardWrite(t) if t == "2\t")));
    assert!(calls.iter().any(|c| matches!(c, Call::FilesSave(n, d) if n == "result.csv" && d == b"id,name\r\n1,a\r\n2,\r\n")));
}

#[test]
fn sorting_puts_numbers_in_order_and_nulls_last() {
    let mut script = trusted_login();
    let mut r = row_desc(&["n"]);
    for v in [Some("10"), None, Some("9"), Some("100")] {
        r.extend(data_row(&[v]));
    }
    r.extend(complete("SELECT 4"));
    r.extend(ready());
    script.push(r);
    let after = vec![ui(1, RESULTS, Input::Sorted((0, true))), Event::Rows(RowsAsk { ask: 5, view: 1, node: RESULTS, offset: 0, count: 10 })];
    let c = core_then(script, after).with(ui(1, RUN, Input::Pressed));
    let c = run_plugin::<Postgres>(c);
    let rows = c.plain_calls().into_iter().find_map(|c| match c {
        Call::ProvideRows(5, rows, _) => Some(rows.clone()),
        _ => None,
    }).unwrap();
    let cells: Vec<Option<String>> = rows.into_iter().map(|r| match &r.cells[0] {
        Cell::Text(t) => Some(t.clone()),
        Cell::Null => None,
        other => panic!("{other:?}"),
    }).collect();
    assert_eq!(cells, vec![Some("9".into()), Some("10".into()), Some("100".into()), None]);
}

#[test]
fn small_helpers() {
    assert_eq!(summary(None, 10), "Done.");
    let set = ResultSet { columns: vec![wire::Column { name: "a".into(), type_oid: 25 }], rows: vec![vec![None]], dropped: 3, tag: "SELECT 4".into() };
    assert!(summary(Some(&set), 1).contains("3 more not kept"));
    let long = "x".repeat(MAX_CELL_CHARS + 10);
    assert!(matches!(&cells(&[], &[Some(long)])[0], Cell::Text(t) if t.chars().count() == MAX_CELL_CHARS + 1));
    assert_eq!(page(&[], &[vec![None], vec![None]], 5, 10).len(), 0);
    let m = mark_at("a\nbc", 4, "x");
    assert_eq!((m.line, m.column), (1, 1));
    let n = nonce();
    assert!(n.len() >= 18 && !n.contains(','));
    assert_ne!(nonce(), nonce());
    let _ = error("1", "x");
}

fn rows_of(c: &FakeCore, ask: u32) -> Vec<Vec<Option<String>>> {
    let rows = c.plain_calls().into_iter().find_map(|c| match c {
        Call::ProvideRows(a, rows, _) if *a == ask => Some(rows.clone()),
        _ => None,
    });
    rows.expect("rows").into_iter().map(|r| r.cells.into_iter().map(|c| match c {
        Cell::Text(t) => Some(t),
        Cell::Null => None,
        other => panic!("{other:?}"),
    }).collect()).collect()
}

#[test]
fn every_result_set_is_kept_and_the_picker_switches_the_grid() {
    let mut script = trusted_login();
    let mut r = row_desc(&["a"]);
    r.extend(data_row(&[Some("first")]));
    r.extend(complete("SELECT 1"));
    r.extend(complete("UPDATE 0"));
    r.extend(row_desc(&["b"]));
    r.extend(data_row(&[Some("second")]));
    r.extend(complete("SELECT 1"));
    r.extend(ready());
    script.push(r);
    let after = vec![
        Event::Rows(RowsAsk { ask: 1, view: 1, node: RESULTS, offset: 0, count: 10 }),
        ui(1, SET_PICK, Input::Choice(0)),
        Event::Rows(RowsAsk { ask: 2, view: 1, node: RESULTS, offset: 0, count: 10 }),
    ];
    let c = run_plugin::<Postgres>(core_then(script, after).with(ui(1, RUN, Input::Pressed)));
    // The grid starts on the last set with columns, as DBeaver opens the last results tab.
    assert_eq!(rows_of(&c, 1), vec![vec![Some("second".to_string())]]);
    assert_eq!(rows_of(&c, 2), vec![vec![Some("first".to_string())]]);
    let picker = c.plain_calls().into_iter().find_map(|c| match c {
        Call::PatchView(_, nodes, _) if nodes[0].id == SET_PICK => Some(nodes[0].component.clone()),
        _ => None,
    });
    match picker {
        Some(Component::Choice(ch)) => {
            assert_eq!(ch.options, vec!["1: SELECT 1", "2: UPDATE 0", "3: SELECT 1"]);
            assert_eq!(ch.selected, Some(2));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn selecting_a_table_fills_properties_ddl_and_data() {
    let mut script = trusted_login();
    let mut props = row_desc(&["k", "v"]);
    props.extend(data_row(&[Some("Owner"), Some("app")]));
    props.extend(complete("SELECT 1"));
    props.extend(ready());
    let mut ddl = row_desc(&["ddl"]);
    ddl.extend(data_row(&[Some("CREATE TABLE \"s\".\"t\" (id integer);")]));
    ddl.extend(complete("SELECT 1"));
    ddl.extend(ready());
    let mut data = row_desc(&["id"]);
    data.extend(data_row(&[Some("7")]));
    data.extend(complete("SELECT 1"));
    data.extend(ready());
    script.extend([props, ddl]);
    script.extend(read_only(data));
    let key = Obj::Table("s".into(), "t".into()).key().unwrap();
    let after = vec![
        Event::Rows(RowsAsk { ask: 1, view: 1, node: PROPS, offset: 0, count: 10 }),
        Event::Rows(RowsAsk { ask: 2, view: 1, node: DATA, offset: 0, count: 10 }),
    ];
    let c = run_plugin::<Postgres>(core_then(script, after).with(ui(1, TREE, Input::Selected(vec![key]))));
    assert_eq!(rows_of(&c, 1), vec![vec![Some("Owner".to_string()), Some("app".to_string())]]);
    assert_eq!(rows_of(&c, 2), vec![vec![Some("7".to_string())]]);
    let ddl = c.plain_calls().into_iter().find_map(|c| match c {
        Call::PatchView(_, nodes, _) if nodes[0].id == DDL => Some(nodes[0].component.clone()),
        _ => None,
    });
    assert!(matches!(ddl, Some(Component::CodeEditor(ref e)) if e.read_only && e.text.starts_with("CREATE TABLE")), "{ddl:?}");
    // The data query names the table quoted, with the preview limit.
    let w = writes(&c);
    let at = w.iter().position(|q| q.contains("SELECT * FROM \"s\".\"t\" LIMIT 201")).expect("data query");
    // The data query goes with the extended protocol (Parse first), inside BEGIN READ ONLY
    // and ROLLBACK.
    assert!(w[at].starts_with('P'));
    assert!(w[at - 1].contains("BEGIN READ ONLY"));
    assert!(w[at + 1].contains("ROLLBACK"));
}

macro_rules! same {
    ($a:expr, $b:expr) => { assert_eq!(format!("{:?}", $a), format!("{:?}", $b)) };
}

// ---- PLUG-08b ------------------------------------------------------------------------------

/// A row description with the given type oids.
fn typed_desc(cols: &[(&str, u32)]) -> Vec<u8> {
    let mut b = (cols.len() as i16).to_be_bytes().to_vec();
    for (n, oid) in cols {
        b.extend_from_slice(n.as_bytes());
        b.push(0);
        b.extend_from_slice(&[0; 6]);
        b.extend_from_slice(&oid.to_be_bytes());
        b.extend_from_slice(&[0; 8]);
    }
    msg(b'T', &b)
}

fn writes(c: &FakeCore) -> Vec<String> {
    c.plain_calls().iter().filter_map(|c| match c {
        Call::Write(_, d) => Some(String::from_utf8_lossy(d).into_owned()),
        _ => None,
    }).collect()
}

fn patched(c: &FakeCore, id: NodeId) -> Option<Component> {
    c.plain_calls().into_iter().rev().find_map(|c| match c {
        Call::PatchView(_, nodes, _) if nodes[0].id == id => Some(nodes[0].component.clone()),
        _ => None,
    })
}

#[test]
fn results_have_typed_cells() {
    let mut script = trusted_login();
    let mut r = typed_desc(&[("n", types::INT4), ("big", types::INT8), ("ok", types::BOOL), ("price", types::NUMERIC), ("t", 25)]);
    r.extend(data_row(&[Some("42"), Some("9007199254740993"), Some("t"), Some("1.10"), Some("7")]));
    r.extend(data_row(&[None, Some("5"), Some("f"), Some("2.5"), None]));
    r.extend(complete("SELECT 2"));
    r.extend(ready());
    script.push(r);
    let c = run_plugin::<Postgres>(core_then(script, vec![Event::Rows(RowsAsk { ask: 3, view: 1, node: RESULTS, offset: 0, count: 10 })]).with(ui(1, RUN, Input::Pressed)));
    let rows = c.plain_calls().into_iter().find_map(|c| match c {
        Call::ProvideRows(3, rows, _) => Some(rows.clone()),
        _ => None,
    }).expect("rows");
    same!(rows[0].cells, vec![Cell::Number(42.0), Cell::Text("9007199254740993".into()), Cell::Boolean(true), Cell::Text("1.10".into()), Cell::Text("7".into())]);
    same!(rows[1].cells, vec![Cell::Null, Cell::Number(5.0), Cell::Boolean(false), Cell::Number(2.5), Cell::Null]);
}

fn page_reply(n: usize) -> Vec<u8> {
    let mut r = typed_desc(&[("id", types::INT4)]);
    for i in 0..n {
        r.extend(data_row(&[Some(&i.to_string())]));
    }
    r.extend(complete(&format!("SELECT {n}")));
    r.extend(ready());
    r
}

/// The replies for a Data tab query: `BEGIN READ ONLY`, the statement, `ROLLBACK`.
fn read_only(reply: Vec<u8>) -> [Vec<u8>; 3] {
    let mut begin = complete("BEGIN");
    begin.extend(ready());
    let mut end = complete("ROLLBACK");
    end.extend(ready());
    [begin, reply, end]
}

fn empty_reply() -> Vec<u8> {
    let mut r = row_desc(&["x"]);
    r.extend(complete("SELECT 0"));
    r.extend(ready());
    r
}

#[test]
fn the_data_tab_pages_filters_and_sorts_on_the_server() {
    let mut script = trusted_login();
    // Selecting the table: properties, DDL, then the first page (201 rows: there is more).
    script.extend([empty_reply(), empty_reply()]);
    for r in [page_reply(201), page_reply(3), page_reply(2), page_reply(1)] {
        script.extend(read_only(r));
    }
    let key = Obj::Table("s".into(), "t\"x".into()).key().unwrap();
    // Each step goes in once the server has answered the one before.
    let steps = vec![
        (9, vec![ui(1, NEXT, Input::Pressed)]),
        (6, vec![ui(1, FILTER, Input::Text("id > 3 AND note = 'a;b'".into())), ui(1, APPLY, Input::Pressed)]),
        (3, vec![ui(1, DATA, Input::Sorted((0, false)))]),
    ];
    let c = run_plugin::<Postgres>(core_steps(script, steps).with(ui(1, TREE, Input::Selected(vec![key]))));
    let w = writes(&c);
    let data: Vec<&String> = w.iter().filter(|q| q.contains("SELECT * FROM")).collect();
    assert_eq!(data.len(), 4, "{data:?}");
    assert!(data[0].contains("SELECT * FROM \"s\".\"t\"\"x\" LIMIT 201") && !data[0].contains("OFFSET"));
    assert!(data[1].contains("LIMIT 201 OFFSET 200"), "{}", data[1]);
    assert!(data[2].contains("WHERE (id > 3 AND note = 'a;b') LIMIT 201") && !data[2].contains("OFFSET"), "{}", data[2]);
    assert!(data[3].contains("WHERE (id > 3 AND note = 'a;b') ORDER BY \"id\" DESC LIMIT 201"), "{}", data[3]);
    assert!(matches!(patched(&c, DATA_STATUS), Some(Component::Label(ref t)) if t == "Rows 1 to 1."), "{:?}", patched(&c, DATA_STATUS));
}

#[test]
fn a_filter_that_could_end_the_where_is_refused_and_never_sent() {
    let mut script = trusted_login();
    script.extend([empty_reply(), empty_reply()]);
    script.extend(read_only(page_reply(1)));
    let key = Obj::Table("s".into(), "t".into()).key().unwrap();
    let after = vec![ui(1, FILTER, Input::Text("1=1); DROP TABLE t; --".into())), ui(1, APPLY, Input::Pressed)];
    let c = run_plugin::<Postgres>(core_then(script, after).with(ui(1, TREE, Input::Selected(vec![key]))));
    assert!(!writes(&c).iter().any(|q| q.contains("DROP")));
    assert!(matches!(patched(&c, DATA_STATUS), Some(Component::Banner(..))), "{:?}", patched(&c, DATA_STATUS));
}

#[test]
fn the_review_payload_is_refused_and_never_sent() {
    // Review #1346 HIGH: `xE` is a word, so PostgreSQL reads `'\'` as a plain string and the
    // rest would leave the WHERE. The plugin refuses it before anything goes out.
    let payload = "xE'\\'); SET default_transaction_read_only = off; DELETE FROM t; --'";
    let mut script = trusted_login();
    script.extend([empty_reply(), empty_reply()]);
    script.extend(read_only(page_reply(1)));
    let key = Obj::Table("s".into(), "t".into()).key().unwrap();
    let after = vec![ui(1, FILTER, Input::Text(payload.into())), ui(1, APPLY, Input::Pressed)];
    let c = run_plugin::<Postgres>(core_then(script, after).with(ui(1, TREE, Input::Selected(vec![key]))));
    assert!(!writes(&c).iter().any(|q| q.contains("DELETE") || q.contains("read_only = off")));
    assert!(matches!(patched(&c, DATA_STATUS), Some(Component::Banner(..))));
}

fn plan_reply() -> Vec<u8> {
    let json = r#"[{"Plan": {"Node Type": "Seq Scan", "Relation Name": "t", "Schema": "public", "Startup Cost": 0.0, "Total Cost": 35.5, "Plan Rows": 2550, "Filter": "(id > 1)",
        "Actual Total Time": 0.02, "Actual Rows": 4, "Actual Loops": 1,
        "Plans": [{"Node Type": "Result", "Startup Cost": 0, "Total Cost": 0.01, "Plan Rows": 1}]}, "Planning Time": 0.05, "Execution Time": 0.08}]"#;
    let mut r = row_desc(&["QUERY PLAN"]);
    r.extend(data_row(&[Some(json)]));
    r.extend(complete("EXPLAIN"));
    r.extend(ready());
    r
}

#[test]
fn explain_analyze_shows_a_plan_tree_with_cost_and_time() {
    let mut script = trusted_login();
    script.push(plan_reply());
    let after = vec![
        Event::Children(ChildrenAsk { ask: 4, view: 1, node: PLAN, parent: None }),
        Event::Children(ChildrenAsk { ask: 5, view: 1, node: PLAN, parent: Some(plan::key(0)) }),
        Event::Children(ChildrenAsk { ask: 6, view: 1, node: PLAN, parent: Some("plan:99".into()) }),
    ];
    let c = core_then(script, after).with(ui(1, EDITOR, Input::Text("SELECT * FROM t WHERE id > 1;".into()))).with(ui(1, ANALYZE, Input::Pressed));
    let c = run_plugin::<Postgres>(c);
    assert!(writes(&c).iter().any(|q| q.contains("EXPLAIN (FORMAT JSON, ANALYZE, BUFFERS) SELECT * FROM t WHERE id > 1\0")));
    // Sent with Parse (extended protocol), so the server allows one statement only.
    assert!(writes(&c).iter().any(|q| q.starts_with('P') && q.contains("EXPLAIN (FORMAT JSON")));
    // Run in the tab's read-only session: no "Allow changes" means no read-write switch.
    assert!(!writes(&c).iter().any(|q| q.contains("read_only = off") || q.contains("READ WRITE")));
    let kids = |ask: u32| c.plain_calls().into_iter().find_map(|c| match c {
        Call::ProvideChildren(a, items) if *a == ask => Some(items.clone()),
        _ => None,
    });
    let top = kids(4).expect("top");
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].label, "Seq Scan on public.t");
    same!(top[0].cells, vec![Cell::Number(0.0), Cell::Number(35.5), Cell::Number(2550.0), Cell::Number(0.02), Cell::Number(4.0), Cell::Number(1.0)]);
    let under = kids(5).expect("children");
    assert_eq!(under.iter().map(|i| i.label.as_str()).collect::<Vec<_>>(), vec!["Filter: (id > 1)", "Result"]);
    assert!(c.plain_calls().iter().any(|c| matches!(c, Call::Refuse(6, _))));
    assert!(matches!(patched(&c, PLAN_STATUS), Some(Component::Label(ref t)) if t.contains("execution 0.080 ms")), "{:?}", patched(&c, PLAN_STATUS));
}

#[test]
fn explain_refuses_several_statements_without_sending_anything() {
    let c = core(trusted_login()).with(ui(1, EDITOR, Input::Text("SELECT 1; DELETE FROM t".into()))).with(ui(1, EXPLAIN, Input::Pressed));
    let c = run_plugin::<Postgres>(c);
    assert!(!c.plain_calls().iter().any(|c| matches!(c, Call::Connect(_))));
    assert!(matches!(patched(&c, PLAN_STATUS), Some(Component::Banner(..))));
}

#[test]
fn data_summaries() {
    assert_eq!(data_summary(0, 0, false), "No rows.");
    assert_eq!(data_summary(200, 0, false), "No more rows.");
    assert_eq!(data_summary(200, 200, true), "Rows 201 to 400; more on the next page.");
}

#[test]
fn header_and_status_line_read_like_the_console() {
    assert_eq!(header_server("16.4 (Debian 16.4-1)"), "PostgreSQL 16.4");
    assert_eq!(header_server(""), "PostgreSQL");
    assert_eq!(header_target("billing", "app"), "billing · app");
    assert_eq!(header_target(&"d".repeat(40), "app").chars().count(), ui::MAX_LABEL);
    assert_eq!(status_line("5 rows.", 12, false), "5 rows · 12 ms · Read only");
    assert_eq!(status_line("INSERT 0 1", 3, true), "INSERT 0 1 · 3 ms · Read and write");
}

#[test]
fn view_has_the_header_and_result_tabs() {
    let nodes = view_nodes("SELECT 1;");
    let tabs: Vec<&str> = nodes.iter().filter(|n| n.parent == Some(RESULT_TABS)).filter_map(|n| match &n.component {
        Component::Tab(t) => Some(t.as_str()),
        _ => None,
    }).collect();
    assert_eq!(tabs, ["Results", "Messages", "Plan"]);
    assert!(matches!(nodes[REFRESH as usize].component, Component::Button(ref b) if b.label == "Refresh"));
}

#[test]
fn a_run_from_the_editor_is_what_explain_plans() {
    let p = Rc::new(Postgres::start());
    let view = View(1);
    let _ = p.clone().open_view(view, String::new());
    let _ = p.clone().input(view, EDITOR, Input::Run("select count(*) from shop.customers".into()));
    assert_eq!(p.with(view, |s| s.sql.clone()).as_deref(), Some("select count(*) from shop.customers"));
}
