//! The compiled-code store index and the compile helper's limits (spec section 4, "Where code
//! is compiled"; T18.22).
//!
//! The store's files live in app-owned storage (PLUG-02b). This index records the SHA-256 of
//! what a compile helper returned, and the core checks it before every load.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

/// Compile helper limits (PLUG-01's proposal, question 12).
pub const COMPILE_TIME_LIMIT_MS: u64 = 30_000;
pub const COMPILE_MEMORY_LIMIT_BYTES: u64 = 512 * 1024 * 1024;
pub const COMPILE_OUTPUT_RATIO: u64 = 16;
pub const COMPILE_OUTPUT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The largest compiled output accepted for a component of `component_bytes`.
pub fn max_compiled_bytes(component_bytes: u64) -> u64 {
    component_bytes.saturating_mul(COMPILE_OUTPUT_RATIO).min(COMPILE_OUTPUT_MAX_BYTES)
}

/// What the compiled code was made for. Code made for another engine is never loaded.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CacheKey {
    /// SHA-256 of the component (hex).
    pub component_sha256: String,
    pub wasmtime_version: String,
    pub os: String,
    /// The CPU type, or `pulley64`.
    pub target: String,
    /// Wasmtime's own hash of the settings that change generated code.
    pub settings_hash: String,
}

/// The result of checking stored code before a load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheCheck {
    /// The bytes are what the compile helper returned: load them.
    Valid,
    /// Nothing recorded for this key: compile.
    Missing,
    /// The bytes differ from the recorded hash. The entry is gone from the index; the caller
    /// deletes the file, writes `plugin.cache.mismatch` and compiles again.
    Mismatch,
}

/// The index of compiled code, and the compile helpers running.
#[derive(Debug, Default)]
pub struct CacheIndex {
    entries: BTreeMap<CacheKey, [u8; 32]>,
    compiling: BTreeSet<String>,
}

impl CacheIndex {
    pub fn new() -> CacheIndex {
        CacheIndex::default()
    }

    /// Record what a compile helper returned for `key`. Refused if it is over the output cap.
    pub fn record(&mut self, key: CacheKey, component_bytes: u64, compiled: &[u8]) -> Result<(), super::Failure> {
        if compiled.len() as u64 > max_compiled_bytes(component_bytes) {
            return Err(super::Failure::Invalid("Plugin could not be prepared".into()));
        }
        self.entries.insert(key, Sha256::digest(compiled).into());
        Ok(())
    }

    /// Check stored bytes before handing them to a view helper.
    pub fn check(&mut self, key: &CacheKey, stored: &[u8]) -> CacheCheck {
        let Some(want) = self.entries.get(key) else { return CacheCheck::Missing };
        let got: [u8; 32] = Sha256::digest(stored).into();
        if &got == want {
            CacheCheck::Valid
        } else {
            self.entries.remove(key);
            CacheCheck::Mismatch
        }
    }

    /// Remove every entry for a component (plugin removed or updated).
    pub fn forget_component(&mut self, component_sha256: &str) {
        self.entries.retain(|k, _| k.component_sha256 != component_sha256);
    }

    /// Start a compile helper for a component. At most one runs per plugin hash, and it counts
    /// toward the helper limit (`running_helpers` includes every helper now running).
    pub fn begin_compile(&mut self, component_sha256: &str, running_helpers: usize) -> Result<(), super::Failure> {
        if self.compiling.contains(component_sha256) {
            return Err(super::Failure::Invalid("this plugin is already being prepared".into()));
        }
        if running_helpers >= super::MAX_HELPERS {
            return Err(super::Failure::Invalid(format!("at most {} plugin helpers at once", super::MAX_HELPERS)));
        }
        self.compiling.insert(component_sha256.to_string());
        Ok(())
    }

    /// The compile helper ended (with code, a limit kill or a crash).
    pub fn end_compile(&mut self, component_sha256: &str) {
        self.compiling.remove(component_sha256);
    }
}
