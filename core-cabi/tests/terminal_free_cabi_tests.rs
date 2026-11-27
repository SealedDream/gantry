//! A freed terminal gives its memory back (WIN-TAB-LEAK round 5). The Windows soak found ~100 KB of native heap kept
//! per opened-and-closed local shell tab; this test opens and frees local shells through the C ABI the way the tab
//! does (open, resize, write, read the screen, free) under a counting allocator and checks that the live heap does not
//! grow with the number of terminals. Its own test binary, so the allocator counts only this process.
use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::c_char;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::{Duration, Instant};

use bastion_cabi::*;

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        System.dealloc(p, layout);
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let q = System.realloc(p, layout, new_size);
        if !q.is_null() {
            LIVE.fetch_add(new_size as isize - layout.size() as isize, Ordering::Relaxed);
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const WARM_CYCLES: usize = 5;
const CYCLES: usize = 20;
/// Allowed growth per opened-and-freed terminal: far below one 80x24 grid (~46 KB), far above allocator noise.
const MAX_GROWTH_PER_TERMINAL: isize = 8 * 1024;
/// One open 125x37 terminal holds at least its visible grid (4625 cells of more than 8 bytes).
const MIN_OPEN_TERMINAL: isize = 37 * 1024;
const SETTLE: Duration = Duration::from_millis(1500);

unsafe fn screen_text(t: *const BastionTerminal) -> String {
    let mut err: *mut c_char = null_mut();
    let s = bastion_terminal_screen(t, &mut err);
    assert!(!s.is_null(), "screen failed");
    let r = &*s;
    let text = String::from_utf8_lossy(std::slice::from_raw_parts(r.text, r.text_len as usize)).into_owned();
    bastion_screen_free(s);
    text
}

/// One tab's life: open at the app's start size, resize to the shown area, type, read the screen, close.
unsafe fn one_terminal() {
    let mut err: *mut c_char = null_mut();
    let t = bastion_terminal_local_shell(80, 24, &mut err);
    assert!(!t.is_null(), "local shell did not open");
    let mut e = null_mut();
    assert_eq!(bastion_terminal_resize(t, 125, 37, &mut e), 0);
    let cmd = "echo leak-probe\n";
    assert_eq!(bastion_terminal_write(t, cmd.as_ptr(), cmd.len(), &mut e), 0);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !screen_text(t).contains("leak-probe") {
        assert!(bastion_terminal_is_alive(t) != 0, "shell ended early");
        assert!(Instant::now() < deadline, "no echo from the shell");
        std::thread::sleep(Duration::from_millis(20));
    }
    bastion_terminal_free(t);
}

fn live_after_settle() -> isize {
    std::thread::sleep(SETTLE);
    LIVE.load(Ordering::Relaxed)
}

/// Windows: bytes allocated in all of the process's heaps. The counting allocator sees only Rust's allocations; ConPTY's
/// in-process side (kernelbase) allocates from the same process heap without passing through it. Measured and printed,
/// not asserted: the Windows baseline comes first (WIN-TAB-LEAK round 5).
#[cfg(windows)]
mod process_heaps {
    use std::ffi::c_void;

    #[repr(C)]
    struct HeapSummaryData {
        cb: u32,
        allocated: usize,
        committed: usize,
        reserved: usize,
        max_reserve: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetProcessHeaps(count: u32, heaps: *mut *mut c_void) -> u32;
        fn HeapSummary(heap: *mut c_void, flags: u32, summary: *mut HeapSummaryData) -> i32;
    }

    const MAX_HEAPS: usize = 256;

    pub fn allocated() -> Option<isize> {
        let mut heaps = [std::ptr::null_mut::<c_void>(); MAX_HEAPS];
        // SAFETY: the buffer holds MAX_HEAPS handles; only the returned count is read.
        let n = unsafe { GetProcessHeaps(MAX_HEAPS as u32, heaps.as_mut_ptr()) } as usize;
        if n == 0 || n > MAX_HEAPS {
            return None;
        }
        let mut total = 0isize;
        for heap in &heaps[..n] {
            let mut s = HeapSummaryData { cb: std::mem::size_of::<HeapSummaryData>() as u32, allocated: 0, committed: 0, reserved: 0, max_reserve: 0 };
            // SAFETY: `heap` came from GetProcessHeaps; `s` is a writable, sized HEAP_SUMMARY.
            if unsafe { HeapSummary(*heap, 0, &mut s) } != 0 {
                total += s.allocated as isize;
            }
        }
        Some(total)
    }
}

#[cfg(not(windows))]
mod process_heaps {
    pub fn allocated() -> Option<isize> {
        None
    }
}

#[test]
fn freed_local_shells_return_their_memory() {
    unsafe {
        for _ in 0..WARM_CYCLES {
            one_terminal();
        }
        let base = live_after_settle();
        let heap_base = process_heaps::allocated();
        for _ in 0..CYCLES {
            one_terminal();
        }
        let end = live_after_settle();
        let heap_end = process_heaps::allocated();
        let per = (end - base) / CYCLES as isize;
        if let (Some(hb), Some(he)) = (heap_base, heap_end) {
            eprintln!("process heaps allocated (Rust + ConPTY + system): base {hb} B, after {CYCLES} more terminals {he} B, {} B per terminal", (he - hb) / CYCLES as isize);
        }
        // The counter must see a terminal's memory, or "no growth" proves nothing: one open 125x37 terminal holds its grids.
        let mut err: *mut c_char = null_mut();
        let t = bastion_terminal_local_shell(125, 37, &mut err);
        assert!(!t.is_null(), "local shell did not open");
        let open = LIVE.load(Ordering::Relaxed) - end;
        bastion_terminal_free(t);
        eprintln!("live heap: base {base} B, after {CYCLES} more terminals {end} B, {per} B per terminal; one open terminal {open} B");
        assert!(open > MIN_OPEN_TERMINAL, "the counter saw only {open} bytes for an open terminal");
        assert!(per <= MAX_GROWTH_PER_TERMINAL, "each freed terminal keeps {per} bytes (base {base}, end {end})");
    }
}
