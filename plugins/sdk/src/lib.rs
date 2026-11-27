//! Write Bastion plugins in Rust.
//!
//! A plugin is a WebAssembly component built for `wasm32-wasip2` against the WIT package
//! `bastion:plugin@1.6.0` (`plugins/wit/plugin.wit`). The API is an event loop: the plugin
//! exports `run`, and one import, `next`, waits for the next event. This crate hides that loop.
//! You implement [`Plugin`] with ordinary `async` code and call [`export_plugin!`]:
//!
//! ```ignore
//! use std::rc::Rc;
//! use bastion_plugin_sdk::{export_plugin, task, ui, Plugin, Task, View};
//!
//! struct Hello;
//!
//! impl Plugin for Hello {
//!     fn start() -> Self { Hello }
//!     fn open_view(self: Rc<Self>, view: View, _name: String) -> Task {
//!         task(async move {
//!             let mut b = ui::ViewBuilder::new(ui::stack());
//!             b.add(b.root(), ui::label("Hello"));
//!             let _ = view.set(b.finish());
//!         })
//!     }
//! }
//!
//! export_plugin!(Hello);
//! ```
//!
//! Only `wasi:clocks` and `wasi:random` work inside a plugin. Anything in the standard library
//! that touches files, environment variables, standard input or output, threads or sockets
//! ends the plugin. Use [`log`] for output, [`net`] for the network and [`storage`] for data.
//!
//! On a build machine (not `wasm32`), [`testing`] runs a plugin against a scripted fake core,
//! so plugin logic can have ordinary unit tests. To run the real component, use the test host
//! (`plugins/testhost`).

#![deny(unsafe_code)]

/// Bindings generated from `plugins/wit/plugin.wit`. Most plugins need only the re-exports.
#[allow(missing_docs, unsafe_code, clippy::all)]
pub mod bindings {
    wit_bindgen::generate!({
        world: "plugin",
        path: "../wit",
        pub_export_macro: true,
        export_macro_name: "__export_plugin_world",
        default_bindings_module: "bastion_plugin_sdk::bindings",
    });
}

mod api;
mod runtime;
mod sys;
pub mod ui;

#[cfg(not(target_arch = "wasm32"))]
pub mod testing;

pub use api::{clipboard, credentials, exec, files, host, http, library, log, net, open, storage};
pub use bindings::bastion::plugin::events::{
    ChildrenAsk, CompletionsAsk, Input, RowsAsk, TableEdits,
};
pub use bindings::bastion::plugin::types::{Entry, Failure, Login};
pub use runtime::run;
pub use ui::View;

use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

/// The id of a node in a view.
pub type NodeId = u32;

/// Work the plugin does for one event. Build one with [`task`].
pub type Task = Pin<Box<dyn Future<Output = ()>>>;

/// Wraps an `async` block as a [`Task`].
pub fn task(future: impl Future<Output = ()> + 'static) -> Task {
    Box::pin(future)
}

/// A task that does nothing.
pub fn done() -> Task {
    Box::pin(async {})
}

/// A plugin. One value is made per helper with [`Plugin::start`]; each event runs as its own
/// task, so a second event is handled while the first one waits on the network. Keep mutable
/// state in a `RefCell` and do not hold a borrow across an `.await`.
pub trait Plugin: 'static {
    /// Called once, before the first event.
    fn start() -> Self
    where
        Self: Sized;

    /// The core opened a view: a connection type's view, a command's view, or `settings`.
    fn open_view(self: Rc<Self>, view: View, name: String) -> Task;

    /// The view was closed. Its streams are not closed for you.
    fn close_view(self: Rc<Self>, view: View) -> Task {
        let _ = view;
        done()
    }

    /// A command from the context menu or the command palette.
    fn command(self: Rc<Self>, id: String, view: Option<View>) -> Task {
        let _ = (id, view);
        done()
    }

    /// The user did something on a node: pressed a button, typed, ran a selection, sorted.
    fn input(self: Rc<Self>, view: View, node: NodeId, input: Input) -> Task {
        let _ = (view, node, input);
        done()
    }

    /// Edits in an editable table.
    fn table_edits(self: Rc<Self>, edits: TableEdits) -> Task {
        let _ = edits;
        done()
    }

    /// The core wants rows for a table. Answer with [`ui::provide_rows`] or [`ui::refuse`].
    fn rows(self: Rc<Self>, ask: RowsAsk) -> Task {
        ui::refuse(ask.ask, "This table has no rows.");
        done()
    }

    /// The core wants a tree node's children. Answer with [`ui::provide_children`].
    fn children(self: Rc<Self>, ask: ChildrenAsk) -> Task {
        ui::refuse(ask.ask, "This tree has no items.");
        done()
    }

    /// The core wants completions for a code editor. The default offers none.
    fn completions(self: Rc<Self>, ask: CompletionsAsk) -> Task {
        let _ = ui::provide_completions(ask.ask, &[]);
        done()
    }

    /// The user pressed Cancel in a view. Stop its running work, for example by sending the
    /// protocol's cancel request on a second stream.
    fn cancel(self: Rc<Self>, view: View) -> Task {
        let _ = view;
        done()
    }
}

/// Exports a [`Plugin`] as the component's `run` function.
#[macro_export]
macro_rules! export_plugin {
    ($plugin:ty) => {
        struct __BastionPluginEntry;
        impl $crate::bindings::Guest for __BastionPluginEntry {
            fn run() {
                $crate::run::<$plugin>()
            }
        }
        $crate::bindings::__export_plugin_world!(__BastionPluginEntry with_types_in $crate::bindings);
    };
}
