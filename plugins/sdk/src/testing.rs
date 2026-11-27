//! Unit tests for plugin logic on a build machine: a scripted fake core.
//!
//! [`FakeCore`] records every call the plugin makes. Each call that expects a reply gets a
//! request number; your `responder` sees the call and returns the events to queue (usually a
//! `reply` for that number). `next` hands out queued events and returns `stop` once the queue
//! is empty, so a test ends when the plugin has nothing left to do.
//!
//! This exercises the SDK and the plugin's own logic, not the component. Use the test host
//! (`plugins/testhost`) to run the real `.wasm`.

use std::cell::RefCell;
use std::collections::VecDeque;

use crate::bindings::bastion::plugin::events::{Event, Reply, ReplyValue};
use crate::bindings::bastion::plugin::log::Level;
use crate::bindings::bastion::plugin::types::{Entry, Failure};
use crate::bindings::bastion::plugin::ui::{Completion, ConfirmKind, ErrorMark, Node, Row, TreeItem};
use crate::Plugin;

/// A call the plugin made.
#[derive(Clone, Debug)]
pub enum Call {
    Log(Level, String),
    SetView(u32, Vec<Node>),
    PatchView(u32, Vec<Node>, Vec<u32>),
    OpenDialog(u32, String, Vec<Node>),
    CloseDialog(u32),
    MarkErrors(u32, u32, Vec<ErrorMark>),
    ProvideRows(u32, Vec<Row>, Option<u64>),
    ProvideChildren(u32, Vec<TreeItem>),
    ProvideCompletions(u32, Vec<Completion>),
    Refuse(u32, String),
    Confirm(ConfirmKind, String),
    Connect(Option<u16>),
    Read(u32, u32),
    Write(u32, Vec<u8>),
    StartTls(u32),
    Close(u32),
    RegisterAbort(u32, Vec<u8>),
    ClearAbort(u32),
    EntryLogin,
    HttpSend(crate::bindings::bastion::plugin::http::HttpRequest),
    OpenConnection(crate::bindings::bastion::plugin::open::OpenRequest),
    /// `exec.run`: template, arguments, time limit in ms (API 1.5).
    ExecRun(String, Vec<(String, String)>, u32),
    ExecCancel(u32),
    /// `exec.terminal`: template, arguments, label.
    ExecTerminal(String, Vec<(String, String)>, String),
    LibraryPropose(Vec<crate::bindings::bastion::plugin::library::Proposal>),
    StorageGet(String),
    StorageSet(String, Vec<u8>),
    StorageDelete(String),
    StorageKeys(String),
    ClipboardWrite(String),
    FilesSave(String, Vec<u8>),
    FilesOpen,
}

type Responder = Box<dyn FnMut(u32, &Call) -> Vec<Event>>;

/// A scripted fake core.
pub struct FakeCore {
    /// Every call, in order, with the number it was given.
    pub calls: Vec<(u32, Call)>,
    /// What `host::entry` returns.
    pub entry: Option<Entry>,
    /// What `host::settings` returns.
    pub settings: Vec<(String, String)>,
    queue: VecDeque<Event>,
    next_id: u32,
    responder: Responder,
}

impl FakeCore {
    /// A fake core that answers nothing by itself.
    pub fn new() -> FakeCore {
        FakeCore {
            calls: Vec::new(),
            entry: None,
            settings: Vec::new(),
            queue: VecDeque::new(),
            next_id: 1,
            responder: Box::new(|_, _| Vec::new()),
        }
    }

    /// Sets the function that answers calls. It gets the call's number and the call.
    pub fn respond(mut self, responder: impl FnMut(u32, &Call) -> Vec<Event> + 'static) -> FakeCore {
        self.responder = Box::new(responder);
        self
    }

    /// Queues an event for the plugin.
    pub fn push(&mut self, event: Event) {
        self.queue.push_back(event);
    }

    /// Queues an event; builder form.
    pub fn with(mut self, event: Event) -> FakeCore {
        self.push(event);
        self
    }

    /// The calls without their numbers.
    pub fn plain_calls(&self) -> Vec<&Call> {
        self.calls.iter().map(|(_, c)| c).collect()
    }

    pub(crate) fn next(&mut self) -> Event {
        self.queue.pop_front().unwrap_or(Event::Stop)
    }

    pub(crate) fn new_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub(crate) fn call(&mut self, call: Call) -> u32 {
        let id = self.new_id();
        let events = (self.responder)(id, &call);
        self.calls.push((id, call));
        self.queue.extend(events);
        id
    }

    pub(crate) fn call_result(&mut self, call: Call) -> Result<(), Failure> {
        self.call(call);
        Ok(())
    }
}

impl Default for FakeCore {
    fn default() -> Self {
        FakeCore::new()
    }
}

/// A `reply` event.
pub fn reply(request: u32, outcome: Result<ReplyValue, Failure>) -> Event {
    Event::Reply(Reply { request, outcome })
}

thread_local! {
    static HOST: RefCell<Option<FakeCore>> = const { RefCell::new(None) };
}

pub(crate) fn with_host<R>(f: impl FnOnce(&mut FakeCore) -> R) -> R {
    HOST.with(|h| {
        let mut h = h.borrow_mut();
        let host = h.as_mut().expect("no fake core: run the plugin with testing::run_plugin");
        f(host)
    })
}

/// Runs plugin `P` against `core` until the queue is empty, and returns the core with the
/// calls the plugin made.
pub fn run_plugin<P: Plugin>(core: FakeCore) -> FakeCore {
    HOST.with(|h| *h.borrow_mut() = Some(core));
    crate::run::<P>();
    HOST.with(|h| h.borrow_mut().take()).expect("fake core")
}
