#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let cfg = bastion_core::sshconfig::SshConfig::parse_str(s, "config");
    for h in cfg.hosts() { let _ = cfg.resolve(&h.alias); let _ = h.to_connection(); }
    let _ = cfg.resolve("fuzz-host");
});
