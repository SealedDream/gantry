//! CPU time used by the calling thread. The compute limit is measured in CPU time of the
//! thread that runs the plugin, so time spent blocked on the pipe (waiting for the network)
//! does not count.

use std::time::Duration;

#[cfg(unix)]
pub fn thread_cpu() -> Duration {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid timespec and the clock id is a constant the platform defines.
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

#[cfg(windows)]
pub fn thread_cpu() -> Duration {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, GetThreadTimes};
    let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: all four out-pointers are valid; the pseudo-handle needs no close.
    unsafe { GetThreadTimes(GetCurrentThread(), &mut created, &mut exited, &mut kernel, &mut user) };
    let ticks = |f: FILETIME| ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64;
    Duration::from_nanos((ticks(kernel) + ticks(user)) * 100)
}
