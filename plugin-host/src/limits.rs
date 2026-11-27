//! The helper's process limits on macOS (PLUG-01 part 2): what the Windows job object gives the
//! helper there (a memory cap, one process, killed with the core).
//!
//! - Memory: the core passes `--memory-cap=<bytes>`. A watchdog thread reads the process's
//!   physical footprint (`TASK_VM_INFO`, the number Activity Monitor and jetsam use) every
//!   `WATCH_EVERY` and ends the process with `EXIT_MEMORY` above the cap. The core checks the same
//!   number from outside (`core/src/plugin/host/helper.rs`, `footprint`), so a helper that stops
//!   its own watchdog is still killed.
//! - One process: the sandbox profile has no `process-fork` or `process-exec` rule.
//! - Leaves when the core goes: the reader thread exits when the input pipe closes, which the
//!   kernel does when the core dies (`relay.rs`). Unlike the Windows job object this is the
//!   helper's own code, so a helper that has escaped Wasmtime can stay; the core ends such
//!   orphans when it next starts (`spawn::kill_orphaned_helpers`). THREAT_MODEL T18.4.
//! - No core dumps (`RLIMIT_CORE` 0): a crash must not write plugin memory to disk. Few
//!   descriptors (`RLIMIT_NOFILE`): the helper needs its two pipe ends and `/dev/null`.
//!
//! Both rlimits are lowered soft and hard, so nothing in the process can raise them again.

/// Exit code when the footprint passed the cap.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const EXIT_MEMORY: i32 = 4;

/// The highest descriptor count the helper may hold.
#[cfg_attr(not(unix), allow(dead_code))]
pub const MAX_FILES: u64 = 64;

/// How often the watchdog reads the footprint.
#[cfg(target_os = "macos")]
const WATCH_EVERY: std::time::Duration = std::time::Duration::from_millis(50);

/// The value of `--memory-cap=<bytes>`, if `arg` is that option. `Err` on a malformed value.
pub fn parse_cap(arg: &str) -> Option<Result<u64, ()>> {
    let value = arg.strip_prefix("--memory-cap=")?;
    Some(value.parse::<u64>().ok().filter(|v| *v > 0).ok_or(()))
}

/// Lowers `RLIMIT_CORE` and `RLIMIT_NOFILE` for good.
#[cfg(unix)]
pub fn lower_rlimits() -> Result<(), String> {
    for (resource, value) in [(libc::RLIMIT_CORE, 0), (libc::RLIMIT_NOFILE, MAX_FILES as libc::rlim_t)] {
        let limit = libc::rlimit { rlim_cur: value, rlim_max: value };
        // SAFETY: a valid rlimit struct; lowering a limit needs no privilege.
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(format!("setrlimit {resource}: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn lower_rlimits() -> Result<(), String> {
    Ok(())
}

/// The physical footprint of this process in bytes (`task_vm_info.phys_footprint`).
#[cfg(target_os = "macos")]
pub fn own_footprint() -> Option<u64> {
    const TASK_VM_INFO: u32 = 22;
    // `phys_footprint` is the u64 at byte 144 of `task_vm_info_data_t` (revision 1 and later).
    const PHYS_FOOTPRINT_OFFSET: usize = 144;
    const REV1_COUNT: u32 = ((PHYS_FOOTPRINT_OFFSET + 8) / 4) as u32;
    extern "C" {
        static mach_task_self_: u32;
        fn task_info(task: u32, flavor: u32, info: *mut u32, count: *mut u32) -> i32;
    }
    let mut buffer = [0u32; 128];
    let mut count = buffer.len() as u32;
    // SAFETY: `count` tells the kernel the buffer's size in naturals; it fills at most that.
    let rc = unsafe { task_info(mach_task_self_, TASK_VM_INFO, buffer.as_mut_ptr(), &mut count) };
    if rc != 0 || count < REV1_COUNT {
        return None;
    }
    let lo = buffer[PHYS_FOOTPRINT_OFFSET / 4] as u64;
    let hi = buffer[PHYS_FOOTPRINT_OFFSET / 4 + 1] as u64;
    Some(lo | (hi << 32))
}

/// Starts the watchdog. Exits the process with `EXIT_MEMORY` once the footprint passes `cap`.
#[cfg(target_os = "macos")]
pub fn watch_memory(cap: u64) -> Result<(), String> {
    if own_footprint().is_none() {
        return Err("cannot read the process footprint".into());
    }
    std::thread::Builder::new()
        .name("memory-cap".into())
        .spawn(move || loop {
            if own_footprint().is_none_or(|bytes| bytes > cap) {
                // SAFETY: `_exit` ends the process at once: no atexit handlers run in a process
                // already over its cap, and no race with another thread's `exit`.
                unsafe { libc::_exit(EXIT_MEMORY) };
            }
            std::thread::sleep(WATCH_EVERY);
        })
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Elsewhere the OS enforces the cap (the Windows job object), or no app ships (Linux).
#[cfg(not(target_os = "macos"))]
pub fn watch_memory(_cap: u64) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cap_option_is_read_and_checked() {
        assert_eq!(parse_cap("--memory-cap=1048576"), Some(Ok(1 << 20)));
        assert_eq!(parse_cap("--memory-cap=0"), Some(Err(())));
        assert_eq!(parse_cap("--memory-cap=-1"), Some(Err(())));
        assert_eq!(parse_cap("--memory-cap="), Some(Err(())));
        assert_eq!(parse_cap("--compile"), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_footprint_is_read_and_grows_with_touched_memory() {
        let before = own_footprint().unwrap();
        assert!(before > 1 << 20, "footprint {before}");
        let block = std::hint::black_box(vec![1u8; 64 << 20]);
        let after = own_footprint().unwrap();
        assert!(after >= before + (48 << 20), "before {before}, after {after}");
        drop(block);
    }
}
