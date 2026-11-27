//! The SDK's event loop against the fake core.

use std::cell::RefCell;
use std::rc::Rc;

use bastion_plugin_sdk::bindings::bastion::plugin::events::{Command, Event, OpenView, ReplyValue, UiEvent};
use bastion_plugin_sdk::net::Stream;
use bastion_plugin_sdk::testing::{reply, run_plugin, Call, FakeCore};
use bastion_plugin_sdk::{credentials, log, storage, task, ui, Failure, Input, NodeId, Plugin, Task, View};

fn open(view: u32, name: &str) -> Event {
    Event::OpenView(OpenView { view, name: name.into() })
}

fn command(id: &str) -> Event {
    Event::Command(Command { id: id.into(), view: None })
}

/// Echo: connect, write the command id, read the answer, log it.
struct Echo;

impl Plugin for Echo {
    fn start() -> Self {
        Echo
    }
    fn open_view(self: Rc<Self>, view: View, name: String) -> Task {
        task(async move {
            let mut b = ui::ViewBuilder::new(ui::stack());
            b.add(b.root(), ui::label(&name));
            view.set(b.finish()).unwrap();
        })
    }
    fn command(self: Rc<Self>, id: String, _view: Option<View>) -> Task {
        task(async move {
            let outcome = async {
                let stream = Stream::connect(None).await?;
                stream.write(id.as_bytes()).await?;
                let answer = stream.read(64).await?;
                Ok::<_, Failure>(String::from_utf8_lossy(&answer).into_owned())
            }
            .await;
            match outcome {
                Ok(text) => log::info(&format!("{id} -> {text}")),
                Err(e) => log::error(&format!("{id} failed: {e:?}")),
            }
        })
    }
}

/// Answers every network call at once: connect opens stream 7, a write is taken, a read gives
/// back what was last written in upper case.
fn echo_server() -> FakeCore {
    let last = Rc::new(RefCell::new(Vec::new()));
    FakeCore::new().respond(move |id, call| match call {
        Call::Connect(_) => vec![reply(id, Ok(ReplyValue::Opened(7)))],
        Call::Write(_, data) => {
            *last.borrow_mut() = data.to_ascii_uppercase();
            vec![reply(id, Ok(ReplyValue::None))]
        }
        Call::Read(_, _) => vec![reply(id, Ok(ReplyValue::Data(last.borrow().clone())))],
        _ => vec![],
    })
}

fn logs(core: &FakeCore) -> Vec<String> {
    core.plain_calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::Log(_, text) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn open_view_sets_a_checked_view() {
    let core = run_plugin::<Echo>(FakeCore::new().with(open(3, "main")));
    let views: Vec<_> = core
        .plain_calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::SetView(v, nodes) => Some((*v, nodes.len())),
            _ => None,
        })
        .collect();
    assert_eq!(views, vec![(3, 2)]);
}

#[test]
fn a_request_resumes_when_its_reply_arrives() {
    let core = run_plugin::<Echo>(echo_server().with(command("ping")));
    assert_eq!(logs(&core), vec!["ping -> PING"]);
    // The stream was closed when it dropped.
    assert!(core.plain_calls().iter().any(|c| matches!(c, Call::Close(7))));
}

#[test]
fn a_failure_reaches_the_plugin() {
    let core = FakeCore::new()
        .respond(|id, call| match call {
            Call::Connect(_) => vec![reply(id, Err(Failure::Denied("no network permission".into())))],
            _ => vec![],
        })
        .with(command("ping"));
    let core = run_plugin::<Echo>(core);
    assert_eq!(logs(&core), vec![r#"ping failed: Failure::Denied("no network permission")"#]);
}

#[test]
fn a_wrong_reply_kind_is_an_invalid_failure() {
    let core = FakeCore::new()
        .respond(|id, call| match call {
            Call::Connect(_) => vec![reply(id, Ok(ReplyValue::Confirmed(true)))],
            _ => vec![],
        })
        .with(command("ping"));
    let core = run_plugin::<Echo>(core);
    assert!(logs(&core)[0].starts_with("ping failed: Failure::Invalid"), "{:?}", logs(&core));
}

#[test]
fn a_reply_for_an_unknown_request_is_ignored() {
    let core = run_plugin::<Echo>(
        echo_server().with(reply(999, Ok(ReplyValue::None))).with(command("a")),
    );
    assert_eq!(logs(&core), vec!["a -> A"]);
}

/// The second call is answered while the first still waits for its reply.
#[test]
fn a_second_call_is_answered_while_the_first_waits() {
    // Reads on the first stream are answered only when the core is told to (the test pushes
    // the reply later); everything else at once.
    let held: Rc<RefCell<Vec<u32>>> = Rc::default();
    let held_in = held.clone();
    let mut streams = 0;
    let core = FakeCore::new()
        .respond(move |id, call| match call {
            Call::Connect(_) => {
                streams += 1;
                vec![reply(id, Ok(ReplyValue::Opened(streams)))]
            }
            Call::Write(..) => vec![reply(id, Ok(ReplyValue::None))],
            Call::Read(1, _) => {
                held_in.borrow_mut().push(id);
                vec![]
            }
            Call::Read(_, _) => vec![reply(id, Ok(ReplyValue::Data(b"fast".to_vec())))],
            _ => vec![],
        })
        .with(command("slow"))
        .with(command("quick"));
    // Run once: the slow call waits, the quick one finishes; the queue then empties and the
    // fake core says stop. The slow call's log line must not be there.
    let core = run_plugin::<Echo>(core);
    assert_eq!(logs(&core), vec!["quick -> fast"]);
    assert_eq!(held.borrow().len(), 1, "the slow read was asked for and is still held");
}

#[test]
fn stop_ends_run_and_drops_waiting_tasks() {
    let core = FakeCore::new()
        .respond(|id, call| match call {
            Call::Connect(_) => vec![reply(id, Ok(ReplyValue::Opened(4)))],
            Call::Write(..) => vec![reply(id, Ok(ReplyValue::None))],
            // The read is never answered: the core stops the helper instead.
            Call::Read(..) => vec![Event::Stop, command("never")],
            _ => vec![],
        })
        .with(command("hang"));
    let core = run_plugin::<Echo>(core);
    let calls = core.plain_calls();
    // The hanging task's stream was closed on the way out, and the event after stop never ran.
    assert!(calls.iter().any(|c| matches!(c, Call::Close(4))));
    assert_eq!(calls.iter().filter(|c| matches!(c, Call::Connect(_))).count(), 1);
}

/// A plugin that registers abort bytes and handles Cancel.
struct Aborter;

impl Plugin for Aborter {
    fn start() -> Self {
        Aborter
    }
    fn open_view(self: Rc<Self>, _view: View, name: String) -> Task {
        task(async move {
            let stream = Stream::connect(None).await.unwrap();
            let size: usize = name.parse().unwrap();
            match stream.register_abort(&vec![b'x'; size]).await {
                Ok(()) => log::info("registered"),
                Err(e) => log::info(&format!("{e:?}")),
            }
        })
    }
    fn cancel(self: Rc<Self>, view: View) -> Task {
        task(async move { log::info(&format!("cancel {}", view.0)) })
    }
    fn input(self: Rc<Self>, view: View, node: NodeId, input: Input) -> Task {
        task(async move { log::info(&format!("input {} {node} {input:?}", view.0)) })
    }
}

fn net_ok() -> FakeCore {
    FakeCore::new().respond(|id, call| match call {
        Call::Connect(_) => vec![reply(id, Ok(ReplyValue::Opened(1)))],
        Call::RegisterAbort(..) => vec![reply(id, Ok(ReplyValue::None))],
        _ => vec![],
    })
}

#[test]
fn abort_bytes_up_to_512_go_to_the_core() {
    let core = run_plugin::<Aborter>(net_ok().with(open(1, "512")));
    assert_eq!(logs(&core), vec!["registered"]);
}

#[test]
fn abort_bytes_over_512_are_refused_without_asking_the_core() {
    let core = run_plugin::<Aborter>(net_ok().with(open(1, "513")));
    assert!(logs(&core)[0].contains("513 bytes"), "{:?}", logs(&core));
    assert!(!core.plain_calls().iter().any(|c| matches!(c, Call::RegisterAbort(..))));
}

#[test]
fn cancel_and_input_reach_the_plugin() {
    let core = run_plugin::<Aborter>(
        FakeCore::new()
            .with(Event::Cancel(5))
            .with(Event::Ui(UiEvent { view: 5, node: 2, input: Input::Pressed })),
    );
    assert_eq!(logs(&core), vec!["cancel 5", "input 5 2 Input::Pressed"]);
}

/// Default answers: rows and children are refused, completions are empty.
struct Defaults;

impl Plugin for Defaults {
    fn start() -> Self {
        Defaults
    }
    fn open_view(self: Rc<Self>, _view: View, _name: String) -> Task {
        task(async {})
    }
}

#[test]
fn asks_get_default_answers() {
    use bastion_plugin_sdk::{ChildrenAsk, CompletionsAsk, RowsAsk};
    let core = run_plugin::<Defaults>(
        FakeCore::new()
            .with(Event::Rows(RowsAsk { ask: 1, view: 1, node: 1, offset: 0, count: 10 }))
            .with(Event::Children(ChildrenAsk { ask: 2, view: 1, node: 1, parent: None }))
            .with(Event::Completions(CompletionsAsk { ask: 3, view: 1, node: 1, text: "s".into(), offset: 1 })),
    );
    let calls = core.plain_calls();
    assert!(matches!(calls[0], Call::Refuse(1, _)));
    assert!(matches!(calls[1], Call::Refuse(2, _)));
    assert!(matches!(calls[2], Call::ProvideCompletions(3, v) if v.is_empty()));
}

/// Login and storage round trips.
struct Store;

impl Plugin for Store {
    fn start() -> Self {
        Store
    }
    fn open_view(self: Rc<Self>, _view: View, _name: String) -> Task {
        task(async {
            let login = credentials::entry_login().await.unwrap();
            storage::set("user", login.user.as_bytes()).await.unwrap();
            let back = storage::get("user").await.unwrap().unwrap();
            log::info(&String::from_utf8(back).unwrap());
        })
    }
}

#[test]
fn login_and_storage_round_trip() {
    use bastion_plugin_sdk::Login;
    let stored = Rc::new(RefCell::new(None));
    let core = FakeCore::new()
        .respond(move |id, call| match call {
            Call::EntryLogin => vec![reply(
                id,
                Ok(ReplyValue::Login(Login { user: "alice".into(), secret: "pw".into() })),
            )],
            Call::StorageSet(_, v) => {
                *stored.borrow_mut() = Some(v.clone());
                vec![reply(id, Ok(ReplyValue::None))]
            }
            Call::StorageGet(_) => vec![reply(id, Ok(ReplyValue::Value(stored.borrow().clone())))],
            _ => vec![],
        })
        .with(open(1, "v"));
    let core = run_plugin::<Store>(core);
    assert_eq!(logs(&core), vec!["alice"]);
}

#[test]
fn a_bad_view_is_refused_before_the_core_sees_it() {
    struct Bad;
    impl Plugin for Bad {
        fn start() -> Self {
            Bad
        }
        fn open_view(self: Rc<Self>, view: View, _name: String) -> Task {
            task(async move {
                let mut b = ui::ViewBuilder::new(ui::label("leaf"));
                b.add(b.root(), ui::label("child of a leaf"));
                let e = view.set(b.finish()).unwrap_err();
                log::info(&format!("{e:?}"));
            })
        }
    }
    let core = run_plugin::<Bad>(FakeCore::new().with(open(1, "v")));
    assert!(!core.plain_calls().iter().any(|c| matches!(c, Call::SetView(..))));
    assert!(logs(&core)[0].contains("cannot hold children"));
}

#[test]
fn large_writes_are_split_into_one_mib_pieces() {
    struct Big;
    impl Plugin for Big {
        fn start() -> Self {
            Big
        }
        fn open_view(self: Rc<Self>, _view: View, _name: String) -> Task {
            task(async {
                let s = Stream::connect(None).await.unwrap();
                s.write(&vec![0u8; 2 * 1024 * 1024 + 1]).await.unwrap();
            })
        }
    }
    let core = FakeCore::new()
        .respond(|id, call| match call {
            Call::Connect(_) => vec![reply(id, Ok(ReplyValue::Opened(1)))],
            Call::Write(..) => vec![reply(id, Ok(ReplyValue::None))],
            _ => vec![],
        })
        .with(open(1, "v"));
    let core = run_plugin::<Big>(core);
    let sizes: Vec<usize> = core
        .plain_calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::Write(_, d) => Some(d.len()),
            _ => None,
        })
        .collect();
    assert_eq!(sizes, vec![1024 * 1024, 1024 * 1024, 1]);
}
