//! Export hosts back to OpenSSH `ssh_config` text.
//!
//! Each host becomes one self-contained `Host <alias>` block holding its fully resolved values,
//! so `ssh -G -F <exported> <alias>` gives the same effective config as the source tree did.
//! Values are validated before they are written: a value that could start a new directive
//! (newline, other control characters) or break quoting (`"`) is refused, never escaped, so a
//! hostile name or field can't smuggle a `ProxyCommand` into the exported file.

use crate::error::{CoreError, Result};
use crate::export::{self, Selection};
use crate::model::{Connection, Document, Protocol};
use crate::sshconfig::ResolvedHost;

/// Characters that make an alias a pattern (or a comment) instead of one host name.
const ALIAS_FORBIDDEN: &[char] = &['*', '?', '!', ',', '"', '#', '%'];

/// Render `hosts` as one `ssh_config` file. Fails on the first host that can't be written safely.
pub fn export_hosts(hosts: &[ResolvedHost]) -> Result<String> {
    let mut out = String::from("# Exported by Gantry\n");
    for h in hosts {
        out.push('\n');
        out.push_str(&host_block(h)?);
    }
    Ok(out)
}

/// Render SSH connections. Connections that can't be exported (not SSH, or a name or value that
/// isn't safe in `ssh_config`) are skipped and listed with the reason.
pub fn export_connections(conns: &[Connection]) -> (String, Vec<(String, String)>) {
    let mut out = String::from("# Exported by Gantry\n");
    let mut skipped = Vec::new();
    for c in conns {
        let block = from_connection(c).ok_or_else(|| CoreError::Invalid("not an SSH connection".into())).and_then(|h| host_block(&h));
        match block {
            Ok(b) => {
                out.push('\n');
                out.push_str(&b);
            }
            Err(e) => skipped.push((c.name.clone(), e.to_string())),
        }
    }
    (out, skipped)
}

/// Export the SSH connections in `selection` with their effective (inherited) settings. The
/// selection is scrubbed exactly as a Bastion export is, so no secret can reach the file.
pub fn export_document(doc: &Document, selection: &Selection) -> (String, Vec<(String, String)>) {
    let (picked, _) = export::prepare(doc, selection);
    let conns: Vec<Connection> = picked
        .connections()
        .into_iter()
        .map(|r| {
            let mut c = r.connection;
            c.settings = r.effective;
            // The protocol's default port is what ssh uses anyway; keep the file minimal.
            if c.settings.port == c.protocol.default_port() {
                c.settings.port = None;
            }
            c
        })
        .collect();
    let mut out = String::from("# Exported by Gantry\n");
    let mut skipped = Vec::new();
    for c in &conns {
        // Auto-start tunnels on this connection go back as forward lines (round trip of import).
        let fwd = crate::sshforwards::export_lines(doc, c.id);
        skipped.extend(fwd.skipped.iter().map(|why| (c.name.clone(), why.clone())));
        let block = from_connection(c).ok_or_else(|| CoreError::Invalid("not an SSH connection".into())).and_then(|mut h| {
            (h.local_forwards, h.remote_forwards, h.dynamic_forwards) = (fwd.local, fwd.remote, fwd.dynamic);
            host_block(&h)
        });
        match block {
            Ok(b) => {
                out.push('\n');
                out.push_str(&b);
            }
            Err(e) => skipped.push((c.name.clone(), e.to_string())),
        }
    }
    (out, skipped)
}

/// The inverse of [`ResolvedHost::to_connection`] for everything a connection keeps.
pub fn from_connection(c: &Connection) -> Option<ResolvedHost> {
    if c.protocol != Protocol::Ssh {
        return None;
    }
    let md = |k: &str| c.metadata.get(k).cloned();
    let algs = c.settings.ssh_algorithms.clone().unwrap_or_default();
    Some(ResolvedHost {
        alias: c.name.clone(),
        hostname: c.host.clone(),
        user: c.settings.username.clone(),
        port: c.settings.port,
        server_alive_interval: c.settings.keepalive_secs,
        identity_files: md("IdentityFile").into_iter().collect(),
        proxy_jump: md("ProxyJump"),
        proxy_command: md("ProxyCommand"),
        identity_agent: md("IdentityAgent"),
        host_key_alias: md("HostKeyAlias"),
        user_known_hosts_file: md("UserKnownHostsFile"),
        strict_host_key_checking: md("StrictHostKeyChecking"),
        pubkey_accepted_algorithms: md("PubkeyAcceptedAlgorithms"),
        request_tty: md("RequestTTY"),
        remote_command: md("RemoteCommand"),
        add_keys_to_agent: md("AddKeysToAgent"),
        exit_on_forward_failure: md("ExitOnForwardFailure").map(|v| v.eq_ignore_ascii_case("yes")),
        send_env: md("SendEnv").map(|v| v.split_whitespace().map(String::from).collect()).unwrap_or_default(),
        set_env: md("SetEnv").map(|v| v.lines().map(String::from).collect()).unwrap_or_default(),
        kex_algorithms: algs.kex,
        ciphers: algs.ciphers,
        macs: algs.macs,
        host_key_algorithms: algs.host_keys,
        compression: algs.compression,
        ..Default::default()
    })
}

/// One `Host` block. Every directive the parser understands is written when set.
pub fn host_block(h: &ResolvedHost) -> Result<String> {
    check_alias(&h.alias)?;
    let mut b = Block(format!("Host {}\n", h.alias));
    // `%` in a resolved host name is literal; OpenSSH would read it as a token.
    b.word("HostName", Some(&h.hostname.replace('%', "%%")))?;
    b.word("User", h.user.as_deref())?;
    b.word("Port", h.port.map(|p| p.to_string()).as_deref())?;
    for f in &h.identity_files {
        b.word("IdentityFile", Some(f))?;
    }
    for f in &h.certificate_files {
        b.word("CertificateFile", Some(f))?;
    }
    b.word("IdentitiesOnly", yes_no(h.identities_only))?;
    b.word("IdentityAgent", h.identity_agent.as_deref())?;
    b.word("ProxyJump", h.proxy_jump.as_deref())?;
    b.verbatim("ProxyCommand", h.proxy_command.as_deref())?;
    b.word("ForwardAgent", yes_no(h.forward_agent))?;
    for f in &h.local_forwards {
        b.args("LocalForward", f)?;
    }
    for f in &h.remote_forwards {
        b.args("RemoteForward", f)?;
    }
    for f in &h.dynamic_forwards {
        b.args("DynamicForward", f)?;
    }
    b.word("HostKeyAlias", h.host_key_alias.as_deref())?;
    b.word("UserKnownHostsFile", h.user_known_hosts_file.as_deref())?;
    b.word("StrictHostKeyChecking", h.strict_host_key_checking.as_deref())?;
    b.word("ServerAliveInterval", h.server_alive_interval.map(|v| v.to_string()).as_deref())?;
    b.word("ConnectTimeout", h.connect_timeout.map(|v| v.to_string()).as_deref())?;
    b.word("KexAlgorithms", h.kex_algorithms.as_deref())?;
    b.word("Ciphers", h.ciphers.as_deref())?;
    b.word("MACs", h.macs.as_deref())?;
    b.word("HostKeyAlgorithms", h.host_key_algorithms.as_deref())?;
    b.word("PubkeyAcceptedAlgorithms", h.pubkey_accepted_algorithms.as_deref())?;
    b.word("Compression", yes_no(h.compression))?;
    if !h.send_env.is_empty() {
        b.words("SendEnv", &h.send_env)?;
    }
    if !h.set_env.is_empty() {
        b.words("SetEnv", &h.set_env)?;
    }
    b.word("RequestTTY", h.request_tty.as_deref())?;
    b.verbatim("RemoteCommand", h.remote_command.as_deref())?;
    b.word("AddKeysToAgent", h.add_keys_to_agent.as_deref())?;
    b.word("ExitOnForwardFailure", yes_no(h.exit_on_forward_failure))?;
    Ok(b.0)
}

struct Block(String);

impl Block {
    /// A single argument, quoted when it holds whitespace.
    fn word(&mut self, key: &str, v: Option<&str>) -> Result<()> {
        let Some(v) = v else { return Ok(()) };
        self.line(key, &quote(key, v)?);
        Ok(())
    }

    /// Several single arguments on one line.
    fn words(&mut self, key: &str, vs: &[String]) -> Result<()> {
        let quoted: Result<Vec<String>> = vs.iter().map(|v| quote(key, v)).collect();
        self.line(key, &quoted?.join(" "));
        Ok(())
    }

    /// A value that already holds several space-separated arguments (forwards).
    fn args(&mut self, key: &str, v: &str) -> Result<()> {
        check_value(key, v)?;
        if v.contains('"') {
            return Err(refused(key, v));
        }
        self.line(key, v);
        Ok(())
    }

    /// The rest of the line, written as stored (`ProxyCommand`, `RemoteCommand`).
    fn verbatim(&mut self, key: &str, v: Option<&str>) -> Result<()> {
        let Some(v) = v else { return Ok(()) };
        check_value(key, v)?;
        self.line(key, v);
        Ok(())
    }

    fn line(&mut self, key: &str, v: &str) {
        self.0.push_str("  ");
        self.0.push_str(key);
        self.0.push(' ');
        self.0.push_str(v);
        self.0.push('\n');
    }
}

fn yes_no(v: Option<bool>) -> Option<&'static str> {
    v.map(|b| if b { "yes" } else { "no" })
}

fn quote(key: &str, v: &str) -> Result<String> {
    check_value(key, v)?;
    if v.contains('"') {
        return Err(refused(key, v));
    }
    Ok(if v.chars().any(char::is_whitespace) { format!("\"{v}\"") } else { v.to_string() })
}

fn check_value(key: &str, v: &str) -> Result<()> {
    if v.trim().is_empty() || v.chars().any(char::is_control) {
        return Err(refused(key, v));
    }
    Ok(())
}

fn check_alias(a: &str) -> Result<()> {
    let bad = a.is_empty() || a.starts_with('-') || a.chars().any(|c| c.is_whitespace() || c.is_control() || ALIAS_FORBIDDEN.contains(&c));
    if bad {
        return Err(CoreError::Invalid(format!("`{}` can't be an ssh_config host alias", a.escape_debug())));
    }
    Ok(())
}

fn refused(key: &str, v: &str) -> CoreError {
    CoreError::Invalid(format!("{key} `{}` can't be written to ssh_config safely", v.escape_debug()))
}
