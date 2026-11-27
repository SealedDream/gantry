//! Plugin helper processes (PLUG-02b; spec sections 4 and 5).
//!
//! - `spawn`: starting `bastion-plugin-host` with two pipe ends and nothing else.
//! - `helper`: one running helper: hello, message checks, ping watchdog, stop.
//! - `Pool`: the gate before any start: `gate::may_load` (02a) on every start, at most
//!   `MAX_HELPERS` helpers at once with compile helpers counted, and at most one compile helper
//!   per plugin hash.
//! - `CrashBackoff`: a helper that keeps crashing restarts after 1 s, 5 s, then 30 s.
//!
//! PLUG-02b part 2:
//! - `store`: the compiled-code store on disk, checked by SHA-256 before every load.
//! - `storage`: a plugin's storage (per entry, 50 MiB per plugin) and log file, with the
//!   secret check on every write.
//! - `view`: one open view: helper, code, and the answers to every plugin call.
//! - [`write_audit`]: the broker's `Category::Plugin` records into the hash-chained `AuditLog`.
//! - [`helper_path_allowed`]: the helper program must sit inside the app's own files.
//!
//! Not here yet: the stream relay through the core's routes and TLS (`net` and `credentials`
//! are refused until it lands).

pub mod helper;
pub mod relay;
pub mod spawn;
pub mod storage;
pub mod store;
pub mod view;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bastion_plugin_host::proto::Role;

pub use bastion_plugin_host::proto;
pub use helper::{Event, Helper, StartError, Stopped, Timing};

use crate::plugin::broker::cache::COMPILE_MEMORY_LIMIT_BYTES;
use crate::plugin::broker::gate::{may_load, Rollout};
use crate::plugin::broker::{Failure, MAX_HELPERS};
use crate::plugin::Tier;
use crate::policy::Policy;

/// The program file's name next to the app (PLUG-14 puts it at
/// `Contents/Helpers/bastion-plugin-host` on the Mac and beside `Gantry.exe` on Windows).
pub const HELPER_PROGRAM: &str = if cfg!(windows) { "bastion-plugin-host.exe" } else { "bastion-plugin-host" };

/// Writes one broker audit record to the hash-chained log at `audit_path`.
pub fn write_audit(audit_path: &Path, a: &crate::plugin::broker::audit::PluginAudit) -> crate::Result<()> {
    let mut log = crate::audit::AuditLog::open(audit_path)?;
    log.confirm()?;
    log.record(a.category, a.action, a.target.as_deref(), a.outcome, a.details.clone()).map(|_| ())
}

/// Whether `program` may be started as the plugin helper by the app at `app_exe`: it must be
/// `HELPER_PROGRAM` inside the app's own files, after every link is resolved. On macOS that is
/// `Gantry.app/Contents/Helpers/`; elsewhere the folder of the app's program. A path anywhere
/// else is refused, so a changed setting or a planted file cannot make the core start another
/// program as a helper.
pub fn helper_path_allowed(program: &Path, app_exe: &Path) -> bool {
    let (Ok(program), Ok(exe)) = (program.canonicalize(), app_exe.canonicalize()) else { return false };
    if program.file_name().and_then(|n| n.to_str()) != Some(HELPER_PROGRAM) || !program.is_file() {
        return false;
    }
    let Some(exe_dir) = exe.parent() else { return false };
    let allowed = if cfg!(target_os = "macos") {
        // .../Gantry.app/Contents/MacOS/Gantry -> .../Gantry.app/Contents/Helpers
        match exe_dir.parent() {
            Some(contents) if exe_dir.file_name().is_some_and(|n| n == "MacOS") => contents.join("Helpers"),
            _ => return false,
        }
    } else {
        exe_dir.to_path_buf()
    };
    program.parent() == Some(allowed.as_path())
}

/// Process memory beyond the plugin's own memory: the engine, the code and the pipe buffers.
pub const HELPER_OVERHEAD_BYTES: u64 = 128 * 1024 * 1024;

/// The growing delay before a crashed helper starts again (spec section 5, "Crashes").
pub const RESTART_DELAYS: [Duration; 3] = [Duration::from_secs(1), Duration::from_secs(5), Duration::from_secs(30)];
/// A helper that has run this long since its last crash is healthy again: the next crash waits
/// the first delay. (The spec names the delays only; this keeps one crash an hour from
/// growing into the 30 s wait.)
pub const HEALTHY_AFTER: Duration = Duration::from_secs(120);

/// The delays of one plugin's restarts after crashes.
#[derive(Debug, Clone, Default)]
pub struct CrashBackoff {
    crashes: usize,
    last_crash: Option<Instant>,
}

impl CrashBackoff {
    /// A crash at `now`: how long to wait before starting the helper again.
    pub fn on_crash(&mut self, now: Instant) -> Duration {
        if self.last_crash.is_some_and(|last| now.saturating_duration_since(last) >= HEALTHY_AFTER) {
            self.crashes = 0;
        }
        let delay = RESTART_DELAYS[self.crashes.min(RESTART_DELAYS.len() - 1)];
        self.crashes += 1;
        self.last_crash = Some(now);
        delay
    }

    /// The user pressed Restart: the next start is not delayed by earlier crashes.
    pub fn reset(&mut self) {
        *self = CrashBackoff::default();
    }
}

/// Who asks for a helper, for the load gate (02a `gate::may_load`).
#[derive(Debug, Clone, Copy)]
pub struct Launch<'a> {
    pub policy: &'a Policy,
    pub rollout: Rollout,
    pub plugin_id: &'a str,
    pub tier: Tier,
    pub allow_unverified: bool,
    pub safe_mode: bool,
}

/// Counts running helpers and compile jobs. Each started helper holds a `Slot`; dropping the
/// slot stops the helper and frees its place.
pub struct Pool {
    program: PathBuf,
    timing: Timing,
    require_sandbox: bool,
    state: Arc<Mutex<Counts>>,
}

#[derive(Default)]
struct Counts {
    running: usize,
    compiling: HashSet<String>,
}

/// A started helper and its place in the pool.
pub struct Slot {
    pub helper: Helper,
    _place: Place,
}

struct Place {
    state: Arc<Mutex<Counts>>,
    compile_hash: Option<String>,
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut counts = self.state.lock().unwrap_or_else(|e| e.into_inner());
        counts.running = counts.running.saturating_sub(1);
        if let Some(hash) = &self.compile_hash {
            counts.compiling.remove(hash);
        }
    }
}

const TOO_MANY: &str = "too many plugins are running; close a plugin tab and try again";
const ALREADY_COMPILING: &str = "this plugin is already being prepared";

impl Pool {
    /// `app_dir` holds the helper program (`HELPER_PROGRAM`).
    pub fn new(app_dir: &Path) -> Pool {
        Pool::with_program(app_dir.join(HELPER_PROGRAM), Timing::DEFAULT)
    }

    pub fn with_program(program: PathBuf, timing: Timing) -> Pool {
        // PLUG-01 part 2 (THREAT_MODEL T18.4): a Mac helper left by a core that died may still
        // run; end it before this core starts any.
        spawn::kill_orphaned_helpers(&program);
        // PLUG-05: required on macOS (the helper's own profile) and Windows (the AppContainer the
        // core starts it in).
        Pool { program, timing, require_sandbox: cfg!(any(target_os = "macos", windows)), state: Arc::new(Mutex::new(Counts::default())) }
    }

    /// The helper program this pool starts.
    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn running(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).running
    }

    /// Takes a place, or says why not. The gate is asked first, every time.
    fn reserve(&self, launch: &Launch<'_>, compile_hash: Option<&str>) -> Result<Place, Failure> {
        may_load(launch.policy, launch.rollout, launch.plugin_id, launch.tier, launch.allow_unverified, launch.safe_mode)?;
        let mut counts = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if counts.running >= MAX_HELPERS {
            return Err(Failure::Invalid(TOO_MANY.into()));
        }
        if let Some(hash) = compile_hash {
            if !counts.compiling.insert(hash.to_string()) {
                return Err(Failure::Invalid(ALREADY_COMPILING.into()));
            }
        }
        counts.running += 1;
        Ok(Place { state: self.state.clone(), compile_hash: compile_hash.map(str::to_string) })
    }

    fn start(&self, launch: &Launch<'_>, role: Role, memory_cap: u64, compile_hash: Option<&str>) -> Result<Slot, Failure> {
        let place = self.reserve(launch, compile_hash)?;
        let helper = Helper::start(&self.program, role, memory_cap, self.timing, self.require_sandbox).map_err(|e| Failure::Invalid(e.to_string()))?;
        Ok(Slot { helper, _place: place })
    }

    /// A helper to run a plugin whose memory limit is `plugin_memory` bytes.
    pub fn start_view(&self, launch: &Launch<'_>, plugin_memory: u64) -> Result<Slot, Failure> {
        self.start(launch, Role::View, plugin_memory.saturating_add(HELPER_OVERHEAD_BYTES), None)
    }

    /// A helper to compile the component with SHA-256 `plugin_hash`; at most one per hash.
    pub fn start_compile(&self, launch: &Launch<'_>, plugin_hash: &str) -> Result<Slot, Failure> {
        self.start(launch, Role::Compile, COMPILE_MEMORY_LIMIT_BYTES, Some(plugin_hash))
    }
}

#[cfg(test)]
mod tests;
