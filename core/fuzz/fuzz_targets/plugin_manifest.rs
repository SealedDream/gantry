#![no_main]
//! PLUG-09: `plugin.toml` from an untrusted package.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| { let _ = bastion_core::plugin::parse_manifest(data); });
