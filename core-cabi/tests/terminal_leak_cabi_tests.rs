//! WIN-SHELL-LEAK: a closed local shell gives back all the memory it took. Opens and closes local
//! shells through the C ABI in batches of ten, the way the Native Windows memory soak does with
//! Ctrl+Shift+T / close (q-mem-long), and checks that the Rust heap (a counting allocator) and, on
//! Windows, the process heaps (HeapSummary: Rust, ConPTY and every other HeapAlloc user in the
//! process) return to where they were. One test per file: the allocator counts the whole binary.
use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::{c_char, CString};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::{Duration, Instant};

use bastion_cabi::*;

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let q = System.realloc(p, l, new_size);
        if !q.is_null() {
            LIVE.fetch_add(new_size as isize - l.size() as isize, Ordering::Relaxed);
        }
        q
    }
}

#[global_allocator]
static A: Counting = Counting;

/// Shells per batch and batches per measured run (the soak opens 10 and closes 10 per cycle).
const BATCH: usize = 10;
const BATCHES: usize = 6;
/// What one closed shell may leave behind on average. The soak's leak was ~9 KB per shell.
const MAX_BYTES_PER_SHELL: isize = 512;
/// The same for all process heaps on Windows (Rust, ConPTY's in-process side, the loader, the thread pool).
#[cfg(windows)]
const MAX_HEAP_BYTES_PER_SHELL: isize = 2048;
/// Less than one open 120x30 shell's grid, to prove the counter sees a terminal's memory.
const MIN_OPEN_SHELL_BYTES: isize = 32 * 1024;
/// Longest wait for closed shells' reader, exit-watch and reaper threads to end.
const SETTLE: Duration = Duration::from_secs(20);
/// The heap counts as settled when it has not changed for this many polls in a row (1.5 s).
const STABLE_POLLS: u32 = 15;
const POLL: Duration = Duration::from_millis(100);

fn live() -> isize {
    LIVE.load(Ordering::SeqCst)
}

#[cfg(windows)]
mod heaps {
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
        fn GetProcessHeaps(count: u32, heaps: *mut isize) -> u32;
        fn HeapSummary(heap: isize, flags: u32, summary: *mut HeapSummaryData) -> i32;
    }

    /// Bytes allocated in all of the process's heaps (what LeakProbe's heap-allocated column sums).
    pub fn allocated() -> isize {
        let mut list = [0isize; 256];
        let n = unsafe { GetProcessHeaps(list.len() as u32, list.as_mut_ptr()) }.min(list.len() as u32) as usize;
        let mut total = 0isize;
        for &h in &list[..n] {
            let mut s = HeapSummaryData { cb: std::mem::size_of::<HeapSummaryData>() as u32, allocated: 0, committed: 0, reserved: 0, max_reserve: 0 };
            if unsafe { HeapSummary(h, 0, &mut s) } != 0 {
                total += s.allocated as isize;
            }
        }
        total
    }
}

/// Wait (bounded) until the Rust heap has stopped changing for a while: closed shells free their
/// state on their own threads once the program has gone.
fn settle() -> isize {
    let deadline = Instant::now() + SETTLE;
    let mut last = live();
    let mut still = 0;
    while Instant::now() < deadline && still < STABLE_POLLS {
        std::thread::sleep(POLL);
        let now = live();
        still = if now == last { still + 1 } else { 0 };
        last = now;
    }
    last
}

unsafe fn screen_rows(t: *const BastionTerminal) -> Vec<String> {
    let mut err: *mut c_char = null_mut();
    let s = bastion_terminal_screen(t, &mut err);
    assert!(!s.is_null(), "screen failed");
    let r = &*s;
    let cells = std::slice::from_raw_parts(r.cells, r.cell_count as usize);
    let text = std::slice::from_raw_parts(r.text, r.text_len as usize);
    let mut rows = Vec::new();
    for row in 0..r.rows as usize {
        let mut line = String::new();
        for c in &cells[row * r.cols as usize..(row + 1) * r.cols as usize] {
            let end = (c.ch_offset + c.ch_len as u32) as usize;
            line.push_str(std::str::from_utf8(&text[c.ch_offset as usize..end]).unwrap_or(""));
        }
        rows.push(line.trim_end().to_string());
    }
    bastion_screen_free(s);
    rows
}

/// Open one shell and use it the way the terminal view does until its prompt is drawn.
unsafe fn open_ready() -> *mut BastionTerminal {
    let mut err: *mut c_char = null_mut();
    let t = bastion_terminal_local_shell(120, 30, &mut err);
    assert!(!t.is_null(), "local shell did not start");
    let theme = CString::new("bastion-dark").unwrap();
    assert_eq!(bastion_terminal_set_theme(t, theme.as_ptr(), &mut err), 0);
    assert_eq!(bastion_terminal_set_scrollback(t, 10_000, &mut err), 0);
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut seen = 0u64;
    loop {
        seen = bastion_terminal_wait_change(t, seen, 50);
        let _ = bastion_terminal_background(t);
        let _ = bastion_terminal_take_bell(t);
        for p in [bastion_terminal_take_events_json(t), bastion_terminal_take_clipboard_json(t), bastion_terminal_cwd(t)] {
            if !p.is_null() {
                bastion_string_free(p);
            }
        }
        let rows = screen_rows(t);
        let ready = if cfg!(windows) { rows.iter().any(|r| r.ends_with('>')) } else { rows.iter().any(|r| !r.is_empty()) };
        if ready {
            return t;
        }
        assert!(Instant::now() < deadline, "no prompt within 15 s:\n{}", rows.join("\n"));
    }
}

/// One soak cycle: open a batch of shells, then close them all.
unsafe fn cycle() {
    let shells: Vec<_> = (0..BATCH).map(|_| open_ready()).collect();
    for t in shells {
        bastion_terminal_free(t);
    }
}

#[test]
fn closed_local_shells_give_their_memory_back() {
    unsafe {
        // Warm up: one-time state (ConPTY entry points, thread-locals, the plugin spawn lock) is not a leak.
        cycle();
        let base = settle();
        // The counter sees a terminal's memory: one open shell holds at least its 120x30 grid.
        let one = open_ready();
        let open_bytes = live() - base;
        bastion_terminal_free(one);
        eprintln!("one open shell: {open_bytes} B of Rust heap");
        assert!(open_bytes > MIN_OPEN_SHELL_BYTES, "one open shell counted only {open_bytes} B");
        let base = settle();
        #[cfg(windows)]
        let heap_base = heaps::allocated();
        for _ in 0..BATCHES {
            cycle();
        }
        let shells = (BATCH * BATCHES) as isize;
        let after = settle();
        let grew = after - base;
        eprintln!("rust heap: base {base} B, after {shells} shells {after} B, {grew:+} B ({:+} B per shell)", grew / shells);
        assert!(grew <= shells * MAX_BYTES_PER_SHELL, "{shells} closed shells kept {grew} B of Rust heap ({} B each)", grew / shells);
        #[cfg(windows)]
        {
            let heap_after = heaps::allocated();
            let heap_grew = heap_after - heap_base;
            eprintln!("process heaps allocated: base {heap_base} B, after {heap_after} B, {heap_grew:+} B ({:+} B per shell)", heap_grew / shells);
            // ConPTY's in-process side (kernelbase) allocates outside the counting allocator; a looser bound, since
            // the loader and the thread pool may also allocate while the shells close.
            assert!(heap_grew <= shells * MAX_HEAP_BYTES_PER_SHELL, "{shells} closed shells kept {heap_grew} B of process heap ({} B each)", heap_grew / shells);
        }
    }
}
