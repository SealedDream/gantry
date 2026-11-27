//! The SDK's test host: runs a plugin component with a fake core.
//!
//! It loads a component, checks its imports against the manifest's permissions, links the
//! `bastion:plugin` imports to a fake core, and runs `run` on a thread of its own. The test
//! drives it like the core would (open a view, press a button, answer an ask) and reads back
//! what the plugin did: views drawn as text, logs, stream traffic, storage.
//!
//! What it shares with the real helper (spec section 5): the import policy, real
//! `wasi:clocks` and `wasi:random` with every other `wasi:*` import a trap, the memory cap, the
//! stream and connection caps, the abort-byte cap, the view checks. What differs: the compute
//! limit counts wall-clock time per event (the helper counts the thread's CPU time); there is
//! no OS sandbox, no helper process and no message protocol; the secret check matches exact
//! bytes only; the update rate is not enforced; clipboard writes are not limited to "right after
//! a user action"; `wasi:clocks/wall-clock` has nanosecond resolution (the review of #913
//! suggests 1 ms in the real helper).

pub mod fake;
pub mod host;
pub mod manifest;
pub mod view;
mod wasi;

/// Host-side bindings generated from `plugins/wit/plugin.wit`.
pub mod bindings {
    wasmtime::component::bindgen!({
        world: "plugin",
        path: "../wit",
    });
}

use std::collections::HashSet;
use std::path::Path;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config as EngineConfig, Engine, Store, UpdateDeadline};

use bindings::bastion::plugin as api;
use bindings::bastion::plugin::events::{
    ChildrenAsk, Command, CompletionsAsk, Event, Input, OpenView, RowsAsk, UiEvent,
};

pub use fake::{FakeConnection, FakeExecOutput, FakeHttpRequest, FakeHttpResponse, FakeServer, LineEcho, NoServer};
pub use host::{Config, Outputs};
pub use manifest::Permissions;

const PACKAGE: &str = "bastion:plugin/";
const VERSION: &str = "@1.6.0";
/// The ticker's period for the compute limit (as in the helper).
const TICK: Duration = Duration::from_millis(20);

/// The names a component imports.
pub fn imports(engine: &Engine, component: &Component) -> Vec<String> {
    component.component_type().imports(engine).map(|(name, _)| name.to_string()).collect()
}

/// The import policy: `wasi:*` is allowed (most of it as traps); `bastion:plugin/*@1.6.0` only
/// where the permissions allow; anything else is refused.
pub fn check_imports(names: &[String], permissions: &Permissions) -> Result<(), String> {
    for name in names {
        if name.starts_with("wasi:") {
            continue;
        }
        let Some(rest) = name.strip_prefix(PACKAGE) else {
            return Err(format!("import `{name}` is outside wasi:* and bastion:plugin: refused"));
        };
        let Some(interface) = rest.strip_suffix(VERSION) else {
            return Err(format!("import `{name}`: this host runs bastion:plugin {VERSION} only"));
        };
        if !permissions.allows(interface) {
            return Err(format!("import `{name}` needs a permission the manifest does not grant: refused"));
        }
    }
    Ok(())
}

fn engine() -> wasmtime::Result<Engine> {
    let mut config = EngineConfig::new();
    config.epoch_interruption(true);
    // No component-model async: API 1 is the synchronous event-loop world.
    config.wasm_component_model(true);
    Engine::new(&config)
}

fn linker(
    engine: &Engine,
    component: &Component,
    names: &[String],
    permissions: &Permissions,
) -> wasmtime::Result<Linker<host::State>> {
    let mut linker = Linker::<host::State>::new(engine);
    for name in names {
        wasi::add(&mut linker, name)?;
    }
    type D = HasSelf<host::State>;
    fn get(s: &mut host::State) -> &mut host::State {
        s
    }
    api::types::add_to_linker::<_, D>(&mut linker, get)?;
    api::host::add_to_linker::<_, D>(&mut linker, get)?;
    api::log::add_to_linker::<_, D>(&mut linker, get)?;
    api::ui::add_to_linker::<_, D>(&mut linker, get)?;
    api::events::add_to_linker::<_, D>(&mut linker, get)?;
    // Only the interfaces the manifest grants are linked at all.
    if permissions.network {
        api::net::add_to_linker::<_, D>(&mut linker, get)?;
    }
    if permissions.credentials {
        api::credentials::add_to_linker::<_, D>(&mut linker, get)?;
    }
    if permissions.storage {
        api::storage::add_to_linker::<_, D>(&mut linker, get)?;
    }
    if permissions.clipboard {
        api::clipboard::add_to_linker::<_, D>(&mut linker, get)?;
    }
    if permissions.files_save || permissions.files_open {
        api::files::add_to_linker::<_, D>(&mut linker, get)?;
    }
    if permissions.http {
        api::http::add_to_linker::<_, D>(&mut linker, get)?;
    }
    if permissions.open_ssh || permissions.open_rdp || permissions.open_vnc {
        api::open::add_to_linker::<_, D>(&mut linker, get)?;
    }
    if permissions.exec {
        api::exec::add_to_linker::<_, D>(&mut linker, get)?;
    }
    if permissions.library {
        api::library::add_to_linker::<_, D>(&mut linker, get)?;
    }
    // Everything still undefined is a wasi:* import (check_imports ran first): a stub that traps.
    linker.define_unknown_imports_as_traps(component)?;
    Ok(linker)
}

/// A loaded plugin, ready to start sessions.
pub struct TestHost {
    engine: Engine,
    component: Component,
    imports: Vec<String>,
}

impl TestHost {
    /// Loads a component from bytes and checks its imports against `permissions`.
    pub fn load(bytes: &[u8], permissions: &Permissions) -> Result<TestHost, String> {
        let engine = engine().map_err(|e| format!("engine: {e}"))?;
        let component = Component::new(&engine, bytes).map_err(|e| format!("not a component: {e}"))?;
        let imports = imports(&engine, &component);
        check_imports(&imports, permissions)?;
        Ok(TestHost { engine, component, imports })
    }

    /// Loads `plugin.wasm` with the permissions of `plugin.toml`.
    pub fn load_files(wasm: &Path, manifest: &Path) -> Result<(TestHost, Permissions), String> {
        let text = std::fs::read_to_string(manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
        let permissions = Permissions::from_manifest(&text)?;
        let bytes = std::fs::read(wasm).map_err(|e| format!("{}: {e}", wasm.display()))?;
        Ok((TestHost::load(&bytes, &permissions)?, permissions))
    }

    /// The component's import names.
    pub fn import_names(&self) -> &[String] {
        &self.imports
    }

    /// Starts the plugin on its own thread.
    pub fn start(&self, config: Config, server: Box<dyn FakeServer>) -> Result<Session, String> {
        let permissions = config.permissions.clone();
        check_imports(&self.imports, &permissions)?;
        let linker = linker(&self.engine, &self.component, &self.imports, &permissions)
            .map_err(|e| format!("link: {e}"))?;
        let shared = Arc::new(host::Shared::default());
        let asks = Arc::new(Mutex::new(HashSet::new()));
        let (tx, rx) = channel();
        let state = host::State::new(config, server, rx, shared.clone(), asks.clone());
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(|cx| {
            let s = cx.data();
            if s.event_started.elapsed() > s.compute_limit {
                wasmtime::bail!("compute limit: the plugin computed for more than {:?} on one event", s.compute_limit)
            }
            Ok(UpdateDeadline::Continue(1))
        });

        // The ticker drives the compute limit; it ends when the session drops its handle.
        let ticking = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let ticker = {
            let engine = self.engine.clone();
            let ticking = ticking.clone();
            std::thread::spawn(move || {
                while ticking.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(TICK);
                    engine.increment_epoch();
                }
            })
        };

        let component = self.component.clone();
        let finished = shared.clone();
        let thread = std::thread::spawn(move || {
            let outcome = (|| -> wasmtime::Result<()> {
                let plugin = bindings::Plugin::instantiate(&mut store, &component, &linker)?;
                // Instantiation counts from the first event, like everything else.
                store.data_mut().event_started = Instant::now();
                plugin.call_run(&mut store)?;
                Ok(())
            })();
            // An ordinary stop sends the abort bytes; a trap is an ordinary stop too.
            store.data_mut().send_aborts();
            let outcome = outcome.map_err(|e| format!("{e:?}"));
            finished.update(|o| o.finished = Some(outcome));
        });

        Ok(Session { tx, shared, asks, thread: Some(thread), ticking, ticker: Some(ticker), next_view: 1, next_ask: 1 })
    }
}

/// A running plugin.
pub struct Session {
    tx: Sender<Event>,
    shared: Arc<host::Shared>,
    asks: Arc<Mutex<HashSet<u32>>>,
    thread: Option<JoinHandle<()>>,
    ticking: Arc<std::sync::atomic::AtomicBool>,
    ticker: Option<JoinHandle<()>>,
    next_view: u32,
    next_ask: u32,
}

/// How long the waiting helpers wait by default.
pub const WAIT: Duration = Duration::from_secs(10);

impl Session {
    fn send(&self, event: Event) {
        // A plugin that already ended leaves the channel closed; `finished` says why.
        let _ = self.tx.send(event);
    }

    /// Opens a view (as the core does when the user opens an entry or runs a command).
    pub fn open_view(&mut self, name: &str) -> u32 {
        let view = self.next_view;
        self.next_view += 1;
        self.shared.update(|o| o.views.insert(view, Vec::new()));
        self.send(Event::OpenView(OpenView { view, name: name.into() }));
        view
    }

    pub fn close_view(&mut self, view: u32) {
        self.shared.update(|o| o.views.remove(&view));
        self.send(Event::CloseView(view));
    }

    pub fn command(&self, id: &str, view: Option<u32>) {
        self.send(Event::Command(Command { id: id.into(), view }));
    }

    pub fn input(&self, view: u32, node: u32, input: Input) {
        self.send(Event::Ui(UiEvent { view, node, input }));
    }

    /// Presses the button labelled `label` in `view`. Fails if there is none.
    pub fn press(&self, view: u32, label: &str) -> Result<(), String> {
        let node = self
            .with_outputs(|o| o.views.get(&view).and_then(|n| view::find_by_label(n, label)))
            .ok_or_else(|| format!("no node labelled {label:?} in view {view}"))?;
        self.input(view, node, Input::Pressed);
        Ok(())
    }

    /// Types `text` into the field labelled `label`.
    pub fn type_text(&self, view: u32, label: &str, text: &str) -> Result<(), String> {
        let node = self
            .with_outputs(|o| o.views.get(&view).and_then(|n| view::find_by_label(n, label)))
            .ok_or_else(|| format!("no node labelled {label:?} in view {view}"))?;
        self.input(view, node, Input::Text(text.into()));
        Ok(())
    }

    pub fn cancel(&self, view: u32) {
        self.send(Event::Cancel(view));
    }

    fn ask(&mut self) -> u32 {
        let ask = self.next_ask;
        self.next_ask += 1;
        self.asks.lock().unwrap_or_else(|e| e.into_inner()).insert(ask);
        ask
    }

    /// Asks for a page of rows. Returns the ask number to look up in [`Outputs::rows`].
    pub fn ask_rows(&mut self, view: u32, node: u32, offset: u64, count: u32) -> u32 {
        let ask = self.ask();
        self.send(Event::Rows(RowsAsk { ask, view, node, offset, count: count.min(1_000) }));
        ask
    }

    pub fn ask_children(&mut self, view: u32, node: u32, parent: Option<&str>) -> u32 {
        let ask = self.ask();
        self.send(Event::Children(ChildrenAsk { ask, view, node, parent: parent.map(Into::into) }));
        ask
    }

    pub fn ask_completions(&mut self, view: u32, node: u32, text: &str, offset: u32) -> u32 {
        let ask = self.ask();
        self.send(Event::Completions(CompletionsAsk { ask, view, node, text: text.into(), offset }));
        ask
    }

    /// Reads the outputs.
    pub fn with_outputs<R>(&self, f: impl FnOnce(&Outputs) -> R) -> R {
        f(&self.shared.outputs.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Waits until `ready` holds, or `limit` passes, or the plugin ended.
    pub fn wait_for(&self, limit: Duration, mut ready: impl FnMut(&Outputs) -> bool) -> Result<(), String> {
        let deadline = Instant::now() + limit;
        let mut o = self.shared.outputs.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if ready(&o) {
                return Ok(());
            }
            if let Some(end) = &o.finished {
                return Err(format!("the plugin ended: {end:?}"));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(format!("nothing after {limit:?}"));
            }
            o = self.shared.changed.wait_timeout(o, deadline - now).unwrap_or_else(|e| e.into_inner()).0;
        }
    }

    /// Waits until the outputs have not changed for `quiet`, at most `limit`.
    pub fn settle(&self, quiet: Duration, limit: Duration) {
        let deadline = Instant::now() + limit;
        let mut last = self.with_outputs(|o| o.changes);
        while Instant::now() < deadline {
            std::thread::sleep(quiet);
            let now = self.with_outputs(|o| o.changes);
            if now == last {
                return;
            }
            last = now;
        }
    }

    /// The view drawn as text.
    pub fn render(&self, view: u32) -> String {
        self.with_outputs(|o| o.views.get(&view).map(|n| view::render(n)).unwrap_or_default())
    }

    /// Tells the plugin to stop and waits for `run` to return. Returns how it ended.
    pub fn stop(mut self) -> Result<(), String> {
        self.send(Event::Stop);
        self.join()
    }

    fn join(&mut self) -> Result<(), String> {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        self.ticking.store(false, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.ticker.take() {
            let _ = t.join();
        }
        self.with_outputs(|o| o.finished.clone()).unwrap_or(Err("the plugin did not end".into()))
    }

    /// Waits for the plugin to end by itself (a trap, or `run` returning).
    pub fn wait_end(mut self, limit: Duration) -> Result<(), String> {
        self.wait_for(limit, |o| o.finished.is_some()).ok();
        if self.with_outputs(|o| o.finished.is_none()) {
            return Err(format!("the plugin did not end within {limit:?}"));
        }
        self.join()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.tx.send(Event::Stop);
        self.ticking.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}
