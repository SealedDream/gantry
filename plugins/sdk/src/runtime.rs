//! The event loop: a single-threaded executor plus a table of requests waiting for a reply.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use futures::channel::oneshot;
use futures::executor::LocalPool;
use futures::task::LocalSpawnExt;

use crate::bindings::bastion::plugin::events::{Event, ReplyValue};
use crate::bindings::bastion::plugin::types::Failure;
use crate::{sys, Plugin, View};

type Outcome = Result<ReplyValue, Failure>;

thread_local! {
    static WAITING: RefCell<HashMap<u32, oneshot::Sender<Outcome>>> = RefCell::new(HashMap::new());
}

/// A request the core will answer with a `reply` event. Registered as soon as it is made, so a
/// reply can never arrive before anyone waits for it.
pub(crate) struct Pending(oneshot::Receiver<Outcome>);

pub(crate) fn pending(request: u32) -> Pending {
    let (tx, rx) = oneshot::channel();
    WAITING.with(|w| w.borrow_mut().insert(request, tx));
    Pending(rx)
}

impl Future for Pending {
    type Output = Outcome;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Outcome> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|r| r.unwrap_or_else(|_| Err(Failure::Io("the runtime stopped".into()))))
    }
}

/// The answer to an unexpected reply value.
pub(crate) fn unexpected(what: &str, value: ReplyValue) -> Failure {
    Failure::Invalid(format!("the core answered {what} with {value:?}"))
}

fn deliver(request: u32, outcome: Outcome) {
    // A reply for a request nobody waits for (its future was dropped) is ignored.
    if let Some(tx) = WAITING.with(|w| w.borrow_mut().remove(&request)) {
        let _ = tx.send(outcome);
    }
}

/// Runs a plugin until the core sends `stop`. [`crate::export_plugin!`] calls this.
pub fn run<P: Plugin>() {
    let plugin = Rc::new(P::start());
    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    loop {
        // Run every task as far as it can go, then wait for the core.
        pool.run_until_stalled();
        let task = match sys::next() {
            Event::Stop => break,
            Event::Reply(reply) => {
                deliver(reply.request, reply.outcome);
                continue;
            }
            Event::OpenView(open) => plugin.clone().open_view(View(open.view), open.name),
            Event::CloseView(view) => plugin.clone().close_view(View(view)),
            Event::Command(command) => plugin.clone().command(command.id, command.view.map(View)),
            Event::Ui(event) => plugin.clone().input(View(event.view), event.node, event.input),
            Event::TableEdits(edits) => plugin.clone().table_edits(edits),
            Event::Rows(ask) => plugin.clone().rows(ask),
            Event::Children(ask) => plugin.clone().children(ask),
            Event::Completions(ask) => plugin.clone().completions(ask),
            Event::Cancel(view) => plugin.clone().cancel(View(view)),
        };
        // The executor is local and lives until `run` returns, so spawning cannot fail.
        let _ = spawner.spawn_local(task);
    }
    // Dropping the pool drops every task still waiting; their streams close as they drop.
    drop(pool);
    WAITING.with(|w| w.borrow_mut().clear());
}
