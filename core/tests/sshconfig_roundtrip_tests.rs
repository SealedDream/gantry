//! SSH config round trips: Bastion's resolution and its export are checked against `ssh -G`,
//! hostile inputs fail safely, and re-importing a config.d tree never duplicates hosts.
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use bastion_core::model::{Document, Folder, Node};
use bastion_core::sshconfig::{Limits, ResolvedHost, SshConfig};
use bastion_core::sshconfig_export::{export_connections, export_hosts, from_connection, host_block};
use bastion_core::sshworkflow::reimport_hosts;

fn write(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, text).unwrap();
}

/// A tree that uses every directive Bastion resolves, nested and globbed Includes, config.d
/// customers and `Host *` defaults. Includes are absolute so `ssh -G -F` reads the same files.
fn tree() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().canonicalize().unwrap();
    let root = include_root(&r);
    write(&r, "config", &format!(
        "Include {root}/config.d/*\nInclude {root}/common/defaults\n\n\
         Host personal\n  HostName home.example\n  User me\n  Port 2222\n  Compression yes\n\n\
         Host *\n  User fallback\n  ServerAliveInterval 30\n  IdentitiesOnly yes\n"));
    write(&r, "config.d/acme", "Host acme-web acme-db !acme-bad\n  HostName %h.acme.example\n  User acme\n  ProxyJump ops@acme-jump:2200\n  IdentityFile /keys/acme_ed25519\n  IdentityFile /keys/acme_rsa\n  KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256\n  Ciphers +aes128-cbc\n  MACs -hmac-sha1\n  HostKeyAlgorithms ssh-ed25519,rsa-sha2-512\n  PubkeyAcceptedAlgorithms +ssh-rsa\n  SendEnv LANG LC_*\n  SetEnv FOO=bar \"BAZ=a b\"\n  RequestTTY force\n  RemoteCommand tmux new -A -s main\n  AddKeysToAgent confirm\n  ExitOnForwardFailure yes\n\nHost acme-jump\n  HostName jump.acme.example\n  Port 2200\n  LocalForward 5432 db:5432\n  ForwardAgent yes\n  ConnectTimeout 7\n\nHost acme-*\n  User overridden-never\n  ConnectTimeout 9\n");
    write(&r, "config.d/globex", "Host globex-legacy\n  HostName 10.0.0.5\n  ProxyCommand ssh -W \"%h:%p\" gw.globex\n  StrictHostKeyChecking yes\n  UserKnownHostsFile /keys/known_globex\n  HostKeyAlias globex-legacy-key\n  CertificateFile /keys/globex-cert.pub\n  RemoteForward 9000 localhost:9000\n  DynamicForward 1080\n  LocalForward 8443 [::1]:443\n");
    write(&r, "common/defaults", "Host *.internal\n  User ops\n");
    d
}

/// The tree's root as an `Include` path both OpenSSH and Bastion read. On Windows the canonical
/// path is `\\?\C:\...`, which OpenSSH for Windows cannot open; `C:/...` is the same folder.
fn include_root(r: &Path) -> String {
    let s = r.display().to_string();
    if cfg!(windows) {
        s.strip_prefix(r"\\?\").unwrap_or(&s).replace('\\', "/")
    } else {
        s
    }
}

fn ssh_available() -> bool {
    Command::new("ssh").arg("-V").output().is_ok_and(|o| o.status.success())
}

/// `ssh -G` for one alias, as key → values (multi-valued keys keep their order).
fn ssh_g(config: &Path, alias: &str) -> BTreeMap<String, Vec<String>> {
    let out = Command::new("ssh").arg("-G").arg("-F").arg(config).arg(alias).output().expect("ssh -G");
    assert!(out.status.success(), "ssh -G {alias}: {}", String::from_utf8_lossy(&out.stderr));
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in String::from_utf8(out.stdout).unwrap().lines() {
        let (k, v) = line.split_once(' ').unwrap_or((line, ""));
        m.entry(k.to_ascii_lowercase()).or_default().push(v.to_string());
    }
    m
}

/// What Bastion resolved, in `ssh -G`'s spelling. Only directives the host actually sets; lists
/// with `+`/`-`/`^` are left out because `ssh -G` expands them against OpenSSH's own defaults.
fn bastion_view(h: &ResolvedHost) -> BTreeMap<String, Vec<String>> {
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut put = |k: &str, v: Option<String>| {
        if let Some(v) = v {
            m.entry(k.into()).or_default().push(v);
        }
    };
    let yn = |b: Option<bool>| b.map(|b| if b { "yes" } else { "no" }.to_string());
    let plain = |v: &Option<String>| v.clone().filter(|v| !v.starts_with(['+', '-', '^']));
    put("hostname", Some(h.hostname.clone()));
    put("user", h.user.clone());
    put("port", Some(h.port.unwrap_or(22).to_string()));
    for f in &h.identity_files {
        put("identityfile", Some(f.clone()));
    }
    for f in &h.certificate_files {
        put("certificatefile", Some(f.clone()));
    }
    put("identitiesonly", yn(h.identities_only));
    put("proxyjump", h.proxy_jump.clone());
    put("proxycommand", h.proxy_command.clone());
    put("forwardagent", yn(h.forward_agent));
    for f in &h.local_forwards {
        put("localforward", Some(f.clone()));
    }
    for f in &h.remote_forwards {
        put("remoteforward", Some(f.clone()));
    }
    for f in &h.dynamic_forwards {
        put("dynamicforward", Some(f.clone()));
    }
    put("hostkeyalias", h.host_key_alias.clone());
    put("userknownhostsfile", h.user_known_hosts_file.clone());
    put("stricthostkeychecking", h.strict_host_key_checking.clone().map(|v| if v == "yes" { "true".into() } else { v }));
    put("serveraliveinterval", h.server_alive_interval.map(|v| v.to_string()));
    put("connecttimeout", h.connect_timeout.map(|v| v.to_string()));
    put("kexalgorithms", plain(&h.kex_algorithms));
    put("ciphers", plain(&h.ciphers));
    put("macs", plain(&h.macs));
    put("hostkeyalgorithms", plain(&h.host_key_algorithms));
    put("compression", yn(h.compression));
    for e in &h.send_env {
        put("sendenv", Some(e.clone()));
    }
    for e in &h.set_env {
        put("setenv", Some(e.clone()));
    }
    put("requesttty", h.request_tty.clone());
    put("remotecommand", h.remote_command.clone());
    put("addkeystoagent", h.add_keys_to_agent.clone());
    put("exitonforwardfailure", yn(h.exit_on_forward_failure));
    m
}

/// `ssh -G` prints forward hosts in brackets (`5432 [db]:5432`).
fn unbracket(v: &str) -> String {
    v.replace(['[', ']'], "")
}

fn assert_agrees(config: &Path, h: &ResolvedHost) {
    let g = ssh_g(config, &h.alias);
    for (k, want) in bastion_view(h) {
        let got = g.get(&k).unwrap_or_else(|| panic!("{}: ssh -G has no {k}", h.alias));
        let got: Vec<_> = got.iter().map(|v| unbracket(v)).collect();
        let want: Vec<_> = want.iter().map(|v| unbracket(v)).collect();
        assert_eq!(got, want, "{}: {k}", h.alias);
    }
}

/// Clear what depends on where a host came from, not on what it is.
fn content(mut h: ResolvedHost) -> ResolvedHost {
    h.identity.clear();
    h.source_file.clear();
    h.group.clear();
    h.source_line = 0;
    h
}

#[test]
fn bastion_resolution_matches_ssh_g() {
    if !ssh_available() {
        return eprintln!("ssh not installed; skipped");
    }
    let d = tree();
    let cfg = SshConfig::discover(d.path(), &Limits::default());
    assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
    let hosts = cfg.hosts();
    assert_eq!(hosts.len(), 5);
    for h in &hosts {
        assert_agrees(&d.path().join("config"), h);
    }
}

#[test]
fn export_gives_the_same_effective_config_under_ssh_g() {
    if !ssh_available() {
        return eprintln!("ssh not installed; skipped");
    }
    let d = tree();
    let hosts = SshConfig::discover(d.path(), &Limits::default()).hosts();
    let exported = d.path().join("exported");
    fs::write(&exported, export_hosts(&hosts).unwrap()).unwrap();
    for h in &hosts {
        assert_eq!(ssh_g(&exported, &h.alias), ssh_g(&d.path().join("config"), &h.alias), "{}", h.alias);
    }
}

#[test]
fn export_then_parse_round_trips_every_field() {
    let d = tree();
    let hosts = SshConfig::discover(d.path(), &Limits::default()).hosts();
    let text = export_hosts(&hosts).unwrap();
    let back = SshConfig::parse_str(&text, "exported");
    assert!(back.warnings.is_empty(), "{:?}", back.warnings);
    let back: Vec<_> = back.hosts().into_iter().map(content).collect();
    let want: Vec<_> = hosts.into_iter().map(content).collect();
    assert_eq!(back, want);
    // A second export is byte-identical: export is deterministic.
    assert_eq!(export_hosts(&back).unwrap(), text);
}

#[test]
fn connection_round_trips_through_ssh_config() {
    let d = tree();
    for h in SshConfig::discover(d.path(), &Limits::default()).hosts() {
        let c = h.to_connection();
        let block = host_block(&from_connection(&c).unwrap()).unwrap();
        let again = SshConfig::parse_str(&block, "x").resolve(&h.alias).to_connection();
        assert_eq!((&again.name, &again.host, &again.settings.username, &again.settings.port), (&c.name, &c.host, &c.settings.username, &c.settings.port));
        assert_eq!(again.settings.ssh_algorithms, c.settings.ssh_algorithms, "{}", h.alias);
        assert_eq!(again.settings.keepalive_secs, c.settings.keepalive_secs);
        let inert = |c: &bastion_core::model::Connection| {
            c.metadata.iter().filter(|(k, _)| !matches!(k.as_str(), "SshConfigIdentity" | "SourceFile" | "Group")).map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>()
        };
        assert_eq!(inert(&again), inert(&c), "{}", h.alias);
    }
}

#[test]
fn export_refuses_values_that_could_inject_directives() {
    let base = ResolvedHost { alias: "web".into(), hostname: "web.example".into(), ..Default::default() };
    let hostile = [
        ResolvedHost { alias: "web\n  ProxyCommand evil".into(), ..base.clone() },
        ResolvedHost { alias: "web *".into(), ..base.clone() },
        ResolvedHost { alias: "-oProxyCommand=evil".into(), ..base.clone() },
        ResolvedHost { alias: "*".into(), ..base.clone() },
        ResolvedHost { hostname: "x\nProxyCommand evil".into(), ..base.clone() },
        ResolvedHost { user: Some("a\" ProxyCommand evil \"".into()), ..base.clone() },
        ResolvedHost { proxy_command: Some("nc %h %p\nLocalCommand evil".into()), ..base.clone() },
        ResolvedHost { remote_command: Some("ls\rPermitLocalCommand yes".into()), ..base.clone() },
        ResolvedHost { local_forwards: vec!["8080 \"x\":80".into()], ..base.clone() },
        ResolvedHost { set_env: vec!["A=\u{0}".into()], ..base.clone() },
        ResolvedHost { user: Some("   ".into()), ..base.clone() },
    ];
    for h in &hostile {
        assert!(host_block(h).is_err(), "accepted {h:?}");
    }
    // Whitespace is quoted, not refused, and parses back to the same value.
    let spaced = ResolvedHost { identity_files: vec!["/keys/my key".into()], ..base.clone() };
    let back = SshConfig::parse_str(&host_block(&spaced).unwrap(), "x").resolve("web");
    assert_eq!(back.identity_files, ["/keys/my key"]);
}

#[test]
fn export_connections_skips_unsafe_and_non_ssh_entries() {
    let mut ok = ResolvedHost { alias: "web".into(), hostname: "web.example".into(), ..Default::default() }.to_connection();
    ok.settings.username = Some("alice".into());
    let mut evil = ok.clone();
    evil.name = "evil\nHost *\n  ProxyCommand touch /tmp/pwned".into();
    let mut rdp = ok.clone();
    rdp.protocol = bastion_core::model::Protocol::Rdp;
    rdp.name = "desk".into();
    let (text, skipped) = export_connections(&[ok, evil, rdp]);
    assert!(text.contains("Host web\n") && !text.contains("pwned") && !text.contains("desk"));
    assert_eq!(skipped.len(), 2);
    assert!(SshConfig::parse_str(&text, "x").warnings.is_empty());
}

#[test]
fn hostile_trees_fail_safely_with_a_reason() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    // Self include, mutual loop, a glob that matches its own file, traversal, an absolute path
    // outside the root, bad UTF-8, CRLF, and an escaping symlink.
    write(r, "config", "Include config\nInclude a\nInclude config.d/*\nHost ok\n  HostName ok.example\n");
    write(r, "a", "Include b\nHost a\n  HostName a.example\n");
    // Enough `..` to leave any temp folder (on Windows four only reach the user's profile), and an
    // absolute file that exists outside the root on each platform.
    let outside = if cfg!(windows) { format!("{}/win.ini", std::env::var("SystemRoot").unwrap().replace('\\', "/")) } else { "/etc/ssh/ssh_config".into() };
    write(r, "b", &format!("Include a\nInclude {}etc/passwd\nInclude {outside}\n", "../".repeat(16)));
    write(r, "config.d/glob", "Include config.d/*\nHost g\n  HostName g.example\n");
    fs::write(r.join("config.d/crlf"), "Host crlf\r\n  HostName crlf.example\r\n  Port 2200\r\n").unwrap();
    fs::write(r.join("config.d/latin1"), b"Host caf\xe9\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/hosts", r.join("config.d/escape")).unwrap();
    let cfg = SshConfig::discover(r, &Limits::default());
    let mut names: Vec<_> = cfg.hosts().into_iter().map(|h| (h.alias, h.hostname, h.port)).collect();
    names.sort();
    assert_eq!(names, [
        ("a".into(), "a.example".into(), None),
        ("crlf".into(), "crlf.example".into(), Some(2200)),
        ("g".into(), "g.example".into(), None),
        ("ok".into(), "ok.example".into(), None),
    ]);
    let says = |needle: &str| cfg.warnings.iter().any(|w| w.message.contains(needle));
    assert!(says("cycle"), "{:?}", cfg.warnings);
    assert!(says("escapes the config directory"), "{:?}", cfg.warnings);
    assert!(says("outside the allowed"), "{:?}", cfg.warnings);
    assert!(says("not valid UTF-8"), "{:?}", cfg.warnings);
}

#[test]
fn file_count_and_size_limits_hold_under_a_flood() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    for i in 0..300 {
        write(r, &format!("config.d/f{i:03}"), &format!("Host h{i}\n  HostName h{i}.example\n"));
    }
    write(r, "config", &"Host big\n  HostName big.example\n".repeat(60_000));
    let start = std::time::Instant::now();
    let cfg = SshConfig::discover(r, &Limits::default());
    assert!(start.elapsed().as_secs() < 5, "took {:?}", start.elapsed());
    assert!(cfg.warnings.iter().any(|w| w.message.contains("byte limit")), "{:?}", cfg.warnings);
    assert!(cfg.warnings.iter().any(|w| w.message.contains("too many config files")));
    assert_eq!(cfg.files.len(), Limits::default().max_files);
}

#[test]
fn ten_thousand_hosts_export_and_reparse_quickly() {
    let hosts: Vec<_> = (0..10_000)
        .map(|i| ResolvedHost { alias: format!("h{i}"), hostname: format!("10.0.{}.{}", i / 256, i % 256), user: Some("ops".into()), ..Default::default() })
        .collect();
    let start = std::time::Instant::now();
    let text = export_hosts(&hosts).unwrap();
    let back = SshConfig::parse_str(&text, "x").hosts();
    assert_eq!(back.len(), 10_000);
    assert!(start.elapsed().as_secs() < 5, "took {:?}", start.elapsed());
}

fn connections(doc: &Document) -> Vec<String> {
    fn walk(f: &Folder, out: &mut Vec<String>) {
        for n in &f.children {
            match n {
                Node::Folder(f) => walk(f, out),
                Node::Connection(c) => out.push(format!("{}/{}", c.name, c.host)),
            }
        }
    }
    let mut out = Vec::new();
    walk(&doc.root, &mut out);
    out.sort();
    out
}

#[test]
fn config_d_reimport_after_edits_never_duplicates() {
    let d = tree();
    let scan = || SshConfig::discover(d.path(), &Limits::default()).hosts();
    let mut doc = Document::new("Library");
    let first = reimport_hosts(&mut doc, &scan()).unwrap();
    assert_eq!((first.added, first.updated), (5, 0));
    for _ in 0..3 {
        let again = reimport_hosts(&mut doc, &scan()).unwrap();
        assert_eq!((again.added, again.updated), (0, 5));
    }
    // Edit a host, switch the file to CRLF, add a customer file: only the new host is added.
    let acme = fs::read_to_string(d.path().join("config.d/acme")).unwrap();
    fs::write(d.path().join("config.d/acme"), acme.replace("%h.acme.example", "%h.acme.test").replace('\n', "\r\n")).unwrap();
    write(d.path(), "config.d/initech", "Host initech-app\n  HostName app.initech.example\n");
    let r = reimport_hosts(&mut doc, &scan()).unwrap();
    assert_eq!((r.added, r.updated), (1, 5));
    let all = connections(&doc);
    assert_eq!(all.len(), 6, "{all:?}");
    assert!(all.contains(&"acme-web/acme-web.acme.test".to_string()), "{all:?}");
}
