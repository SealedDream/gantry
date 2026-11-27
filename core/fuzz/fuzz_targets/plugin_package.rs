#![no_main]
//! PLUG-09: a whole `.bastionplugin` (zip, manifest, sizes, ratios).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| { let _ = bastion_core::plugin::read_package(data); });
