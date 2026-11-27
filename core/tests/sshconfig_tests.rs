//! Fixture-based tests for OpenSSH config discovery and resolution.
use std::fs;
use std::path::Path;

use bastion_core::sshconfig::{host_matches, HostFlag, Limits, SshConfig};

fn write(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, text).unwrap();
}

fn tree() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    write(r, "config", "Include config.d/*\nInclude common/defaults\n\nHost personal\n  HostName home.example\n  User me\n\nHost *\n  User fallback\n  ServerAliveInterval 30\n  IdentitiesOnly yes\n");
    write(r, "config.d/acme", "Host acme-web acme-db !acme-bad\n  HostName %h.acme.example\n  User acme\n  ProxyJump acme-jump\n  IdentityFile ~/.ssh/acme_ed25519\n  IdentityFile ~/.ssh/acme_rsa\n\nHost acme-jump\n  HostName jump.acme.example\n  Port 2200\n  LocalForward 5432 db:5432\n  ForwardAgent yes\n\nHost acme-*\n  User overridden-never\n  ConnectTimeout 7\n");
    write(r, "config.d/globex", "Host globex-legacy\n  HostName 10.0.0.5\n  ProxyCommand ssh -W \"%h:%p\" gw.globex\n  StrictHostKeyChecking yes\n  UserKnownHostsFile ~/.ssh/known_globex\n  HostKeyAlias globex-legacy-key\n  CertificateFile ~/.ssh/globex-cert.pub\n  IdentityAgent ~/.1password/agent.sock\n  RemoteForward 9000 localhost:9000\n  DynamicForward 1080\n\nMatch exec \"touch /tmp/bastion-pwned\"\n  User matched\n");
    write(r, "common/defaults", "Host *.internal\n  User ops\n");
    d
}

#[test]
fn nested_include_and_config_d_customers() {
    let d = tree();
    let cfg = SshConfig::discover(d.path(), &Limits::default());
    assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
    let hosts = cfg.hosts();
    let names: Vec<_> = hosts.iter().map(|h| h.alias.as_str()).collect();
    assert_eq!(names, ["acme-web", "acme-db", "acme-jump", "globex-legacy", "personal"]);
    let web = &hosts[0];
    assert_eq!(web.group, "acme");
    assert_eq!(web.source_file, "config.d/acme");
    assert_eq!(web.source_line, 1);
    assert_eq!(web.hostname, "acme-web.acme.example");
    assert_eq!(web.user.as_deref(), Some("acme"), "first match wins over later acme-* and Host *");
    assert_eq!(web.identity_files, ["~/.ssh/acme_ed25519", "~/.ssh/acme_rsa"]);
    assert_eq!(web.connect_timeout, Some(7));
    assert_eq!(web.server_alive_interval, Some(30));
    assert_eq!(web.identities_only, Some(true));
    assert_eq!(web.proxy_jump.as_deref(), Some("acme-jump"));
    let jump = &hosts[2];
    assert_eq!(jump.port, Some(2200));
    assert_eq!(jump.user.as_deref(), Some("overridden-never"), "acme-* is the first User for acme-jump");
    assert_eq!(jump.local_forwards, ["5432 db:5432"]);
    assert!(jump.flags.contains(&HostFlag::ForwardAgentEnabled));
    assert_eq!(hosts[4].group, "config");
    assert_eq!(hosts[4].user.as_deref(), Some("me"));
}

#[test]
fn every_listed_directive_is_resolved() {
    let d = tree();
    let g = SshConfig::discover(d.path(), &Limits::default()).resolve("globex-legacy");
    assert_eq!(g.proxy_command.as_deref(), Some("ssh -W \"%h:%p\" gw.globex"));
    assert!(g.flags.contains(&HostFlag::ProxyCommandInert));
    assert_eq!(g.strict_host_key_checking.as_deref(), Some("yes"));
    assert_eq!(g.user_known_hosts_file.as_deref(), Some("~/.ssh/known_globex"));
    assert_eq!(g.host_key_alias.as_deref(), Some("globex-legacy-key"));
    assert_eq!(g.certificate_files, ["~/.ssh/globex-cert.pub"]);
    assert_eq!(g.identity_agent.as_deref(), Some("~/.1password/agent.sock"));
    assert_eq!(g.remote_forwards, ["9000 localhost:9000"]);
    assert_eq!(g.dynamic_forwards, ["1080"]);
}

#[test]
fn wildcards_and_negations_are_never_hosts() {
    let d = tree();
    let cfg = SshConfig::discover(d.path(), &Limits::default());
    assert!(cfg.hosts().iter().all(|h| !h.alias.contains(['*', '?', '!'])));
    let p: Vec<String> = ["acme-*", "!acme-bad"].map(String::from).to_vec();
    assert!(host_matches(&p, "acme-web"));
    assert!(!host_matches(&p, "acme-bad"));
    assert!(!host_matches(&p, "other"));
    assert!(host_matches(&["*.INTERNAL".into()], "db.internal"));
    assert_eq!(cfg.resolve("db.internal").user.as_deref(), Some("ops"));
}

#[test]
fn match_blocks_are_recorded_but_never_applied_or_executed() {
    let d = tree();
    let cfg = SshConfig::discover(d.path(), &Limits::default());
    assert_eq!(cfg.match_blocks.len(), 1);
    assert!(cfg.match_blocks[0].criteria.starts_with("exec"));
    let p = cfg.resolve("personal");
    assert_eq!(p.user.as_deref(), Some("me"));
    assert!(p.flags.contains(&HostFlag::MatchBlocksIgnored));
    assert_ne!(cfg.resolve("unknown-host").user.as_deref(), Some("matched"));
    assert!(!Path::new("/tmp/bastion-pwned").exists());
}

#[test]
fn include_cycles_are_detected() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "config", "Include a\nHost top\n");
    write(d.path(), "a", "Include b\nHost in-a\n");
    write(d.path(), "b", "Include a\nInclude config\nHost in-b\n");
    let cfg = SshConfig::discover(d.path(), &Limits::default());
    let names: Vec<_> = cfg.hosts().into_iter().map(|h| h.alias).collect();
    assert_eq!(names, ["in-b", "in-a", "top"]);
    assert_eq!(cfg.warnings.iter().filter(|w| w.message.contains("cycle")).count(), 2);
}

#[test]
fn include_depth_is_limited() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "config", "Include f0\n");
    for i in 0..30 {
        write(d.path(), &format!("f{i}"), &format!("Include f{}\nHost h{i}\n", i + 1));
    }
    let limits = Limits { max_include_depth: 5, ..Limits::default() };
    let cfg = SshConfig::discover(d.path(), &limits);
    assert_eq!(cfg.hosts().len(), 5);
    assert!(cfg.warnings.iter().any(|w| w.message.contains("depth")));
}

#[test]
fn oversize_binary_and_non_utf8_files_are_refused() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "config", "Host ok\n");
    write(d.path(), "config.d/huge", &format!("Host huge\n#{}\n", "x".repeat(2000)));
    fs::write(d.path().join("config.d/latin1"), b"Host caf\xe9\n").unwrap();
    // Not named `nul`: that is a reserved device name on Windows.
    fs::write(d.path().join("config.d/nulbyte"), b"Host n\0ul\n").unwrap();
    let cfg = SshConfig::discover(d.path(), &Limits { max_file_bytes: 1000, ..Limits::default() });
    let names: Vec<_> = cfg.hosts().into_iter().map(|h| h.alias).collect();
    assert_eq!(names, ["ok"]);
    let msgs: Vec<_> = cfg.warnings.iter().map(|w| w.message.as_str()).collect();
    assert!(msgs.iter().any(|m| m.contains("limit")), "{msgs:?}");
    assert!(msgs.iter().any(|m| m.contains("UTF-8")));
    assert!(msgs.iter().any(|m| m.contains("NUL")));
}

#[test]
fn traversal_outside_root_is_refused() {
    let outer = tempfile::tempdir().unwrap();
    write(outer.path(), "secret", "Host stolen\n");
    let root = outer.path().join("ssh");
    write(&root, "config", "Include ../secret\nInclude /etc/ssh/ssh_config\nInclude link\nHost fine\n");
    #[cfg(unix)]
    std::os::unix::fs::symlink(outer.path().join("secret"), root.join("link")).unwrap();
    let cfg = SshConfig::discover(&root, &Limits::default());
    let names: Vec<_> = cfg.hosts().into_iter().map(|h| h.alias).collect();
    assert_eq!(names, ["fine"]);
    assert!(cfg.warnings.len() >= 3, "{:?}", cfg.warnings);
}

#[test]
fn identity_is_stable_across_clone_locations() {
    let a = tree();
    let b = tree();
    let ha = SshConfig::discover(a.path(), &Limits::default()).hosts();
    let hb = SshConfig::discover(b.path(), &Limits::default()).hosts();
    assert_eq!(ha.iter().map(|h| &h.identity).collect::<Vec<_>>(), hb.iter().map(|h| &h.identity).collect::<Vec<_>>());
    let ids: std::collections::BTreeSet<_> = ha.iter().map(|h| &h.identity).collect();
    assert_eq!(ids.len(), ha.len());
}

#[test]
fn to_connection_carries_provenance_and_inert_proxycommand() {
    let d = tree();
    let c = SshConfig::discover(d.path(), &Limits::default()).resolve("globex-legacy").to_connection();
    assert_eq!(c.host, "10.0.0.5");
    assert_eq!(c.metadata["Group"], "globex");
    assert!(c.metadata.contains_key("ProxyCommand"));
    assert!(c.metadata.contains_key("SshConfigIdentity"));
}
