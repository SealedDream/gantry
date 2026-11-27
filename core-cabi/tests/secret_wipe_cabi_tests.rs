//! F09: a generated password returned over the C ABI is wiped when `bastion_string_free`
//! releases it. A watching allocator checks every freed block for the password bytes.
use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::CStr;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bastion_cabi::textgen::*;
use bastion_cabi::*;

struct Watch;

static WATCHING: AtomicBool = AtomicBool::new(false);
static SEEN: AtomicBool = AtomicBool::new(false);
static NEEDLE_LEN: AtomicUsize = AtomicUsize::new(0);
static mut NEEDLE: [u8; 128] = [0; 128];

unsafe impl GlobalAlloc for Watch {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        let n = NEEDLE_LEN.load(Ordering::SeqCst);
        if WATCHING.load(Ordering::SeqCst) && n > 0 && l.size() >= n {
            let block = std::slice::from_raw_parts(p, l.size());
            let needle = &*std::ptr::addr_of!(NEEDLE);
            if block.windows(n).any(|w| w == &needle[..n]) {
                SEEN.store(true, Ordering::SeqCst);
            }
        }
        System.dealloc(p, l)
    }
}

#[global_allocator]
static A: Watch = Watch;

#[test]
fn generated_password_is_wiped_when_freed() {
    unsafe {
        let mut err = null_mut();
        let p = bastion_generate_password(40, &mut err);
        assert!(!p.is_null());
        let bytes = CStr::from_ptr(p).to_bytes();
        let n = bytes.len();
        (&mut *std::ptr::addr_of_mut!(NEEDLE))[..n].copy_from_slice(bytes);
        NEEDLE_LEN.store(n, Ordering::SeqCst);
        WATCHING.store(true, Ordering::SeqCst);
        bastion_string_free(p);
        WATCHING.store(false, Ordering::SeqCst);
        assert!(!SEEN.load(Ordering::SeqCst), "freed memory still held the password");
    }
}
