#![no_main]
//! PLUG-09: the pipe's frame reader (length checked before allocation).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut r = data;
    while let Ok(Some(_)) = bastion_core::plugin::host::proto::read_frame(&mut r) {}
});
