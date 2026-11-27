//! Wasmtime inside the helper: the engine, compiling, loading compiled code, the memory and
//! compute limits, and the forwarding of every `bastion:plugin` import to the core.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use wasmtime::component::types::ComponentItem;
use wasmtime::component::{Component, Linker, Val};
use wasmtime::{bail, Config, Engine, ResourceLimiter, Store, UpdateDeadline};

use bastion_plugin_host::proto::{ToCore, Value, MAX_STORAGE_VALUE_BYTES};

use crate::cpu::thread_cpu;
use crate::relay::{Link, Work};

/// Kept in step with the pin in Cargo.toml.
pub const WASMTIME_VERSION: &str = "48.0.8";
/// How often the epoch advances while plugin code runs: the compute limit's granularity.
const TICK: Duration = Duration::from_millis(20);
const TABLE_ELEMENTS_MAX: usize = 1_000_000;
const PACKAGE: &str = "bastion:plugin/";
/// API 1.0 to 1.6 (1.1 adds `http`, 1.2 adds `open`, 1.3 changes no types, 1.4 only the manifest,
/// 1.5 adds `exec`, 1.6 adds UI types). The core decides which calls a plugin may make.
const API_VERSIONS: [&str; 6] = ["@1.0.0", "@1.1.0", "@1.2.0", "@1.3.0", "@1.5.0", "@1.6.0"];
/// The import whose return starts a new event: the compute limit counts per event.
/// The storage interface, any API version.
const STORAGE: &str = "bastion:plugin/storage@";
/// The import whose return starts a new event: the compute limit counts per event.
const NEXT_EVENTS: [&str; 6] = [
    "bastion:plugin/events@1.0.0#next",
    "bastion:plugin/events@1.1.0#next",
    "bastion:plugin/events@1.2.0#next",
    "bastion:plugin/events@1.3.0#next",
    "bastion:plugin/events@1.5.0#next",
    "bastion:plugin/events@1.6.0#next",
];
/// Exit code for a core that answers out of turn.
const EXIT_PROTOCOL: i32 = 2;
const EXIT_PIPE_CLOSED: i32 = 0;

pub fn build_engine() -> wasmtime::Result<Engine> {
    let mut config = Config::new();
    config.epoch_interruption(true);
    config.wasm_component_model(true);
    // Plain Unix signals for traps: nothing to look up outside the process, which suits the
    // sandbox PLUG-05 adds (it denies Mach lookups).
    config.macos_use_mach_ports(false);
    Engine::new(&config)
}

/// What compiled code depends on besides the component: the Wasmtime version, the system, the
/// CPU type and every engine setting that changes generated code (PLUG-01 decision 8). The core
/// keys its compiled-code store with it.
pub fn engine_key(engine: &Engine) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    engine.precompile_compatibility_hash().hash(&mut hasher);
    format!("wasmtime-{WASMTIME_VERSION}-{}-{}-{:016x}", std::env::consts::OS, std::env::consts::ARCH, hasher.finish())
}

/// Compile helper: the component's compiled code, refused when over `max_output`.
pub fn compile(engine: &Engine, component: &[u8], max_output: u64) -> Result<Vec<u8>, String> {
    let code = engine.precompile_component(component).map_err(|e| format!("compile: {e:#}"))?;
    if code.len() as u64 > max_output {
        return Err(format!("compiled code of {} bytes is over the cap of {max_output} bytes", code.len()));
    }
    Ok(code)
}

pub struct State {
    pub started: Instant,
    link: Arc<Link>,
    limiter: TotalLimiter,
    cpu_start: Duration,
    budget: Duration,
    ticker: Ticker,
    seq: u64,
    /// Set when `run` starts: the reader thread's channel, for the core's replies.
    replies: Option<mpsc::Receiver<Work>>,
}

/// Caps the sum of all linear memories of the plugin, not each one: a component can hold
/// several memories.
struct TotalLimiter {
    limit: usize,
    total: usize,
}

impl ResourceLimiter for TotalLimiter {
    fn memory_growing(&mut self, current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        let total = self.total.saturating_sub(current).saturating_add(desired);
        if total > self.limit {
            bail!("memory limit: the plugin asked for {total} bytes, the cap is {} MiB", self.limit >> 20);
        }
        self.total = total;
        Ok(true)
    }

    fn table_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        Ok(desired <= TABLE_ELEMENTS_MAX)
    }
}

/// Advances the epoch while plugin code runs and sleeps otherwise, so an idle helper (a plugin
/// waiting for its next event) uses no CPU.
struct Ticker {
    active: Arc<AtomicUsize>,
    thread: std::thread::Thread,
}

impl Ticker {
    fn start(engine: &Engine) -> Ticker {
        let weak = engine.weak();
        let active = Arc::new(AtomicUsize::new(0));
        let seen = active.clone();
        let handle = std::thread::spawn(move || loop {
            if seen.load(Ordering::SeqCst) == 0 {
                std::thread::park();
                continue;
            }
            std::thread::sleep(TICK);
            match weak.upgrade() {
                Some(engine) => engine.increment_epoch(),
                None => return,
            }
        });
        Ticker { active, thread: handle.thread().clone() }
    }

    fn enter(&self) {
        self.active.fetch_add(1, Ordering::SeqCst);
        self.thread.unpark();
    }

    fn leave(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Plugin {
    store: Store<State>,
    component: Component,
    linker: Linker<State>,
}

/// Only `wasi:*` and `bastion:plugin/*@1.0.0` to `@1.6.0` may be imported (spec section 5, "Imports"). Which
/// `bastion:plugin` calls a plugin may make is the core's decision, on every call.
fn check_imports(engine: &Engine, component: &Component) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for (name, _) in component.component_type().imports(engine) {
        let ok = name.starts_with("wasi:") || (name.starts_with(PACKAGE) && API_VERSIONS.iter().any(|v| name.ends_with(v)));
        if !ok {
            return Err(format!("import `{name}` is not offered to plugins"));
        }
        names.push(name.to_string());
    }
    Ok(names)
}

fn build_linker(engine: &Engine, component: &Component, names: &[String]) -> wasmtime::Result<Linker<State>> {
    let mut linker = Linker::<State>::new(engine);
    let ty = component.component_type();
    for name in names {
        if !name.starts_with(PACKAGE) {
            crate::wasi::add(&mut linker, name)?;
            continue;
        }
        let Some(item) = ty.get_import(engine, name) else { continue };
        let ComponentItem::ComponentInstance(instance) = item.ty else { continue };
        let mut scope = linker.instance(name)?;
        for (function, export) in instance.exports(engine) {
            if let ComponentItem::ComponentFunc(_) = export.ty {
                if function == "set" && name.starts_with(STORAGE) {
                    // Typed: `list<u8>` is lifted as bytes, not one `Val` per byte (a 4 MiB value
                    // as `Val`s ran the helper out of memory), and the size is checked before framing.
                    let full = format!("{name}#{function}");
                    scope.func_wrap(function, move |mut cx, (key, value): (String, Vec<u8>)| {
                        let value = if value.len() > MAX_STORAGE_VALUE_BYTES { Value::U64(value.len() as u64) } else { Value::Bytes(value) };
                        let mut reply = call_core(&mut cx, &full, vec![Value::String(key), value])?;
                        match (reply.pop(), reply.is_empty()) {
                            (Some(Value::U32(request)), true) => Ok((request,)),
                            _ => bail!("the core answered {full} with something other than a request"),
                        }
                    })?;
                    continue;
                }
                let full = format!("{name}#{function}");
                scope.func_new(function, move |mut cx, _ty, args, results| forward(&mut cx, &full, args, results))?;
            }
        }
    }
    // Everything still undefined is a `wasi:*` function the helper does not offer: it traps.
    linker.define_unknown_imports_as_traps(component)?;
    Ok(linker)
}

/// One `bastion:plugin` call: sent to the core, which answers with the results. The plugin
/// thread waits; its CPU clock does not run while it waits, and the epoch ticker sleeps.
fn forward(cx: &mut wasmtime::StoreContextMut<'_, State>, name: &str, args: &[Val], results: &mut [Val]) -> wasmtime::Result<()> {
    let args = args.iter().map(to_value).collect::<wasmtime::Result<Vec<_>>>()?;
    let reply = call_core(cx, name, args)?;
    if reply.len() != results.len() {
        bail!("the core answered {name} with {} results, {} expected", reply.len(), results.len());
    }
    for (slot, value) in results.iter_mut().zip(reply) {
        *slot = to_val(value);
    }
    Ok(())
}

/// Sends one import to the core and waits for its results.
fn call_core(cx: &mut wasmtime::StoreContextMut<'_, State>, name: &str, args: Vec<Value>) -> wasmtime::Result<Vec<Value>> {
    let state = cx.data_mut();
    state.seq += 1;
    let seq = state.seq;
    if state.link.send(&ToCore::Import { seq, name: name.to_string(), args }).is_err() {
        std::process::exit(EXIT_PIPE_CLOSED);
    }
    state.ticker.leave();
    let reply = match state.replies.as_ref().map(|r| r.recv()) {
        Some(Ok(Work::Reply { seq: got, results })) if got == seq => results,
        Some(Ok(_)) => std::process::exit(EXIT_PROTOCOL),
        Some(Err(_)) | None => std::process::exit(EXIT_PIPE_CLOSED),
    };
    state.ticker.enter();
    if NEXT_EVENTS.contains(&name) {
        state.cpu_start = thread_cpu();
    }
    Ok(reply)
}

/// Loads compiled code. The core sends only code from its compiled-code store, whose entries it
/// checks against the SHA-256 recorded at compile time before every load (spec section 4).
pub fn load(engine: &Engine, code: &[u8], link: Arc<Link>, memory_limit: u64, compute_ms: u32) -> Result<Plugin, String> {
    // SAFETY: `deserialize` runs native code produced by a compile helper with the same engine
    // key. The core sends only store entries whose SHA-256 matches the one it recorded when the
    // compile helper made them; Wasmtime itself refuses code from another engine or version.
    let component = unsafe { Component::deserialize(engine, code) }.map_err(|e| format!("compiled code: {e:#}"))?;
    let names = check_imports(engine, &component)?;
    let linker = build_linker(engine, &component, &names).map_err(|e| format!("link: {e:#}"))?;
    let state = State {
        started: Instant::now(),
        link,
        limiter: TotalLimiter { limit: usize::try_from(memory_limit).unwrap_or(usize::MAX), total: 0 },
        cpu_start: thread_cpu(),
        budget: Duration::from_millis(compute_ms as u64),
        ticker: Ticker::start(engine),
        seq: 0,
        replies: None,
    };
    let mut store = Store::new(engine, state);
    store.limiter(|state| &mut state.limiter);
    // Runs on every epoch tick while plugin code executes. A call waiting in an import is not
    // executing plugin code, and the thread's CPU time does not move while it waits.
    store.epoch_deadline_callback(|cx| {
        let state = cx.data();
        if thread_cpu().saturating_sub(state.cpu_start) > state.budget {
            bail!("compute limit: more than {} ms of CPU for one event", state.budget.as_millis());
        }
        Ok(UpdateDeadline::Continue(1))
    });
    store.set_epoch_deadline(1);
    Ok(Plugin { store, component, linker })
}

impl Plugin {
    /// Instantiates the plugin and calls `run` until it returns or traps. A trap ends the plugin
    /// for good (PLUG-01 decision 13).
    pub fn run(mut self, replies: mpsc::Receiver<Work>) -> Result<(), String> {
        self.store.data_mut().replies = Some(replies);
        self.store.data_mut().cpu_start = thread_cpu();
        self.store.data().ticker.enter();
        let result = (|| {
            let instance = self.linker.instantiate(&mut self.store, &self.component)?;
            let run = instance.get_typed_func::<(), ()>(&mut self.store, "run")?;
            run.call(&mut self.store, ())
        })();
        self.store.data().ticker.leave();
        result.map_err(|e| format!("{e:#}"))
    }
}

fn to_value(v: &Val) -> wasmtime::Result<Value> {
    let many = |list: &[Val]| list.iter().map(to_value).collect::<wasmtime::Result<Vec<_>>>();
    let boxed = |v: &Option<Box<Val>>| -> wasmtime::Result<Option<Box<Value>>> {
        Ok(match v {
            Some(v) => Some(Box::new(to_value(v)?)),
            None => None,
        })
    };
    Ok(match v {
        Val::Bool(b) => Value::Bool(*b),
        Val::S8(x) => Value::S8(*x),
        Val::U8(x) => Value::U8(*x),
        Val::S16(x) => Value::S16(*x),
        Val::U16(x) => Value::U16(*x),
        Val::S32(x) => Value::S32(*x),
        Val::U32(x) => Value::U32(*x),
        Val::S64(x) => Value::S64(*x),
        Val::U64(x) => Value::U64(*x),
        Val::Float32(x) => Value::F32(*x),
        Val::Float64(x) => Value::F64(*x),
        Val::Char(c) => Value::Char(*c),
        Val::String(s) => Value::String(s.clone()),
        Val::List(list) if !list.is_empty() && list.iter().all(|x| matches!(x, Val::U8(_))) => {
            Value::Bytes(list.iter().map(|x| if let Val::U8(b) = x { *b } else { 0 }).collect())
        }
        Val::List(list) | Val::FixedLengthList(list) => Value::List(many(list)?),
        Val::Record(fields) => Value::Record(fields.iter().map(|(n, v)| Ok((n.clone(), to_value(v)?))).collect::<wasmtime::Result<_>>()?),
        Val::Tuple(t) => Value::Tuple(many(t)?),
        Val::Variant(name, payload) => Value::Variant(name.clone(), boxed(payload)?),
        Val::Enum(name) => Value::Enum(name.clone()),
        Val::Option(v) => Value::Option(boxed(v)?),
        Val::Result(Ok(v)) => Value::Result(Ok(boxed(v)?)),
        Val::Result(Err(v)) => Value::Result(Err(boxed(v)?)),
        Val::Flags(names) => Value::Flags(names.clone()),
        Val::Map(_) | Val::Resource(_) | Val::Future(_) | Val::Stream(_) | Val::ErrorContext(_) => {
            bail!("API 1 passes no maps, resources, futures or streams")
        }
    })
}

fn to_val(v: Value) -> Val {
    let boxed = |v: Option<Box<Value>>| v.map(|v| Box::new(to_val(*v)));
    match v {
        Value::Bool(b) => Val::Bool(b),
        Value::S8(x) => Val::S8(x),
        Value::U8(x) => Val::U8(x),
        Value::S16(x) => Val::S16(x),
        Value::U16(x) => Val::U16(x),
        Value::S32(x) => Val::S32(x),
        Value::U32(x) => Val::U32(x),
        Value::S64(x) => Val::S64(x),
        Value::U64(x) => Val::U64(x),
        Value::F32(x) => Val::Float32(x),
        Value::F64(x) => Val::Float64(x),
        Value::Char(c) => Val::Char(c),
        Value::String(s) => Val::String(s),
        Value::Bytes(b) => Val::List(b.into_iter().map(Val::U8).collect()),
        Value::List(l) => Val::List(l.into_iter().map(to_val).collect()),
        Value::Record(f) => Val::Record(f.into_iter().map(|(n, v)| (n, to_val(v))).collect()),
        Value::Tuple(t) => Val::Tuple(t.into_iter().map(to_val).collect()),
        Value::Variant(n, p) => Val::Variant(n, boxed(p)),
        Value::Enum(n) => Val::Enum(n),
        Value::Option(v) => Val::Option(boxed(v)),
        Value::Result(Ok(v)) => Val::Result(Ok(boxed(v))),
        Value::Result(Err(v)) => Val::Result(Err(boxed(v))),
        Value::Flags(f) => Val::Flags(f),
    }
}
