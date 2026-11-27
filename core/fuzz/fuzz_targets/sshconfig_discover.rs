#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The input is a config.d fragment reached through Include, plus a main file that includes
    // it, so Include globbing, depth and file limits run against the real file system.
    use bastion_core::sshconfig::{Limits, SshConfig};
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join(".ssh");
    std::fs::create_dir_all(ssh.join("config.d")).unwrap();
    std::fs::write(ssh.join("config"), b"Include config.d/*\nHost main\n  HostName example.invalid\n").unwrap();
    std::fs::write(ssh.join("config.d").join("a.conf"), data).unwrap();
    let cfg = SshConfig::discover(&ssh, &Limits::default());
    for h in cfg.hosts() { let _ = h.to_connection(); }
});
