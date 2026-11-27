#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    use bastion_core::sshforwards::{parse, ForwardKind};
    for k in [ForwardKind::Local, ForwardKind::Remote, ForwardKind::Dynamic] { let _ = parse(k, s); }
});
