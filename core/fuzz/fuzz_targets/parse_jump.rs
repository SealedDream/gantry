#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| { let Ok(s) = std::str::from_utf8(data) else { return }; let _ = bastion_core::sshworkflow::parse_jump(s); });
