//! `bastion-plugin-host`: one helper process runs one plugin (spec section 5) or compiles one
//! component (section 4). The core starts it with two pipe ends and nothing else, and an empty
//! environment (`core/src/plugin/host/spawn.rs`).
//!
//! - `bastion-plugin-host` (no role argument): a view helper. It loads compiled code the core
//!   sends, calls `run`, and forwards every `bastion:plugin` import to the core.
//! - `bastion-plugin-host --compile`: a compile helper. It compiles one component and sends the
//!   code back; it runs no plugin code.
//! - `--handles-from-stdin` (Windows): standard input is a one-shot pipe carrying the values of
//!   the two real pipe handles, which the core duplicated into this process (PLUG-01 decision 9).
//!
//! The helper opens no file and no socket. It leaves as soon as its input pipe closes: that is
//! also how it notices the core going away (PLUG-01 decision 10).

mod cpu;
mod limits;
mod pipes;
mod relay;
mod runtime;
mod sandbox;
mod wasi;

use std::sync::mpsc;
use std::sync::Arc;

use bastion_plugin_host::proto::{Role, ToCore, ToHelper, CHUNK, PROTOCOL_VERSION};

use relay::{Link, Work};

/// Exit codes the core can tell apart in its log.
const EXIT_OK: i32 = 0;
const EXIT_PROTOCOL: i32 = 2;
const EXIT_START: i32 = 3;

/// Largest component or compiled code the helper accepts (spec section 4: compiled code is at
/// most 64 MiB; a component bigger than that cannot produce code under the cap either).
const MAX_CODE_BYTES: u64 = 64 * 1024 * 1024;

fn main() {
    let mut role = Role::View;
    let mut handles_from_stdin = false;
    let mut memory_cap = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--compile" => role = Role::Compile,
            "--handles-from-stdin" => handles_from_stdin = true,
            other => match limits::parse_cap(other) {
                Some(Ok(cap)) => memory_cap = Some(cap),
                _ => std::process::exit(EXIT_START),
            },
        }
    }
    let Ok((input, output)) = pipes::open(handles_from_stdin) else { std::process::exit(EXIT_START) };
    // PLUG-01 part 2: the process limits go on before the sandbox and before any byte from the
    // core is read. On macOS the core always passes the memory cap; a helper without one exits.
    if limits::lower_rlimits().is_err() {
        std::process::exit(EXIT_START);
    }
    match memory_cap {
        Some(cap) => {
            if limits::watch_memory(cap).is_err() {
                std::process::exit(EXIT_START);
            }
        }
        None if cfg!(target_os = "macos") => std::process::exit(EXIT_START),
        None => {}
    }
    // PLUG-05: the OS sandbox goes on here, before the engine exists and before any byte from the
    // core is read. A helper that cannot sandbox itself exits; it never says Hello.
    let Ok(sandbox) = sandbox::enter() else { std::process::exit(EXIT_START) };
    let Ok(engine) = runtime::build_engine() else { std::process::exit(EXIT_START) };
    let link = Arc::new(Link::new(output));
    let hello = ToCore::Hello {
        protocol: PROTOCOL_VERSION,
        role,
        pid: std::process::id(),
        sandbox,
        engine_key: runtime::engine_key(&engine),
    };
    if link.send(&hello).is_err() {
        std::process::exit(EXIT_START);
    }
    let work = relay::start_reader(input, link.clone());
    let code = match role {
        Role::View => view(&engine, &link, work),
        Role::Compile => compile(&engine, &link, &work),
    };
    std::process::exit(code);
}

/// The next message, or the exit code when the core said Shutdown, closed the pipe, or sent
/// something that does not fit here.
fn next(work: &mpsc::Receiver<Work>) -> Result<ToHelper, i32> {
    match work.recv() {
        Ok(Work::Message(ToHelper::Shutdown)) | Err(_) => Err(EXIT_OK),
        Ok(Work::Message(m)) => Ok(m),
        Ok(Work::Reply { .. }) => Err(EXIT_PROTOCOL),
    }
}

/// Collects `Chunk`s up to `End`. The declared total is checked against the cap first and the
/// pieces against the total, so a lying core cannot make the helper grow without bound.
fn collect(work: &mpsc::Receiver<Work>, total: u64) -> Result<Vec<u8>, i32> {
    if total > MAX_CODE_BYTES {
        return Err(EXIT_PROTOCOL);
    }
    let mut bytes = Vec::with_capacity(total as usize);
    loop {
        match next(work)? {
            ToHelper::Chunk(piece) if bytes.len() as u64 + piece.len() as u64 <= total => bytes.extend_from_slice(&piece),
            ToHelper::End if bytes.len() as u64 == total => return Ok(bytes),
            _ => return Err(EXIT_PROTOCOL),
        }
    }
}

fn view(engine: &wasmtime::Engine, link: &Arc<Link>, work: mpsc::Receiver<Work>) -> i32 {
    let prepared = (|| -> Result<runtime::Plugin, i32> {
        let ToHelper::Load { memory_limit, compute_ms, total } = next(&work)? else { return Err(EXIT_PROTOCOL) };
        let code = collect(&work, total)?;
        let plugin = runtime::load(engine, &code, link.clone(), memory_limit, compute_ms).map_err(|error| {
            let _ = link.send(&ToCore::Loaded { error: Some(error) });
            EXIT_OK
        })?;
        link.send(&ToCore::Loaded { error: None }).map_err(|_| EXIT_OK)?;
        let ToHelper::Run = next(&work)? else { return Err(EXIT_PROTOCOL) };
        Ok(plugin)
    })();
    let plugin = match prepared {
        Ok(plugin) => plugin,
        Err(exit) => return exit,
    };
    // From here the reader thread's replies go to this thread, which runs the plugin.
    let error = plugin.run(work).err();
    let _ = link.send(&ToCore::Ended { error });
    EXIT_OK
}

fn compile(engine: &wasmtime::Engine, link: &Arc<Link>, work: &mpsc::Receiver<Work>) -> i32 {
    let run = || -> Result<i32, i32> {
        let ToHelper::Compile { total, max_output } = next(work)? else { return Err(EXIT_PROTOCOL) };
        let component = collect(work, total)?;
        let result = runtime::compile(engine, &component, max_output);
        drop(component);
        let sent = match result {
            Ok(code) => code
                .chunks(CHUNK)
                .try_for_each(|piece| link.send(&ToCore::Compiled(piece.to_vec())))
                .and_then(|()| link.send(&ToCore::CompileDone { error: None })),
            Err(error) => link.send(&ToCore::CompileDone { error: Some(error) }),
        };
        sent.map_err(|_| EXIT_OK)?;
        // The job is done: wait for Shutdown or the pipe to close. Anything else is a violation.
        next(work).map(|_| EXIT_PROTOCOL)
    };
    run().unwrap_or_else(|exit| exit)
}
