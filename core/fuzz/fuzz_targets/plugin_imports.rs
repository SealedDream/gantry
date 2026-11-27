#![no_main]
//! PLUG-09: the component import-list reader used at install.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| { let _ = bastion_core::plugin::component_imports(data); });
