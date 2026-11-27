//! OpenSSH client config discovery and resolution.
//!
//! Imported configs are untrusted input (they may come from a shared GitLab repository), so:
//! - nothing is ever executed: `ProxyCommand` is stored inert and flagged, `Match` blocks are
//!   recorded but never applied (so `Match exec` can never run);
//! - `Include` is confined to the discovery root (plus explicitly allowed roots), with a depth
//!   limit, cycle detection, a file-count limit, a per-file size limit and UTF-8 validation;
//! - problems become [`Warning`]s on the result instead of aborting the whole scan.
//!
//! Precedence follows OpenSSH: for each option the first value obtained wins, scanning the
//! config top to bottom with `Include`d files inlined where they appear.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{Connection, Protocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_file_bytes: u64,
    pub max_include_depth: usize,
    pub max_files: usize,
}

impl Default for Limits {
    fn default() -> Self {
        // OpenSSH itself stops at an include depth of 16.
        Limits { max_file_bytes: 1024 * 1024, max_include_depth: 16, max_files: 256 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warning {
    /// Source-relative file the problem was found in (or the rejected path).
    pub file: String,
    pub line: usize,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Condition {
    Always,
    Host(Vec<String>),
    /// Recorded, never evaluated.
    Match(String),
}

#[derive(Debug, Clone)]
struct Directive {
    key: String,
    value: String,
    cond: usize,
}

/// A `Match` block found in the config. It is listed for the user but has no effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchBlock {
    pub file: String,
    pub line: usize,
    pub criteria: String,
}

#[derive(Debug, Clone)]
struct HostDecl {
    alias: String,
    file: String,
    line: usize,
}

/// Per-host provenance plus every supported directive, resolved with first-match-wins.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedHost {
    pub alias: String,
    /// Stable identity: SHA-256 of the source-relative file path and the alias. Independent of
    /// where the tree lives on disk, so a GitLab clone and a local copy dedupe to one host.
    pub identity: String,
    /// File (relative to the discovery root) whose `Host` line declares the alias.
    pub source_file: String,
    /// Customer group: the declaring file's name (`config.d/acme` → `acme`).
    pub group: String,
    /// Line of the declaring `Host` (0 when the alias is not declared).
    pub source_line: usize,
    pub hostname: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_files: Vec<String>,
    pub certificate_files: Vec<String>,
    pub identities_only: Option<bool>,
    pub identity_agent: Option<String>,
    pub proxy_jump: Option<String>,
    /// Stored verbatim and never executed.
    pub proxy_command: Option<String>,
    pub forward_agent: Option<bool>,
    pub local_forwards: Vec<String>,
    pub remote_forwards: Vec<String>,
    pub dynamic_forwards: Vec<String>,
    pub host_key_alias: Option<String>,
    pub user_known_hosts_file: Option<String>,
    pub strict_host_key_checking: Option<String>,
    pub server_alive_interval: Option<u32>,
    pub connect_timeout: Option<u32>,
    /// Algorithm lists in OpenSSH syntax (`+`/`-`/`^` prefixes kept), see `algorithms`.
    #[serde(default)]
    pub kex_algorithms: Option<String>,
    #[serde(default)]
    pub ciphers: Option<String>,
    #[serde(default)]
    pub macs: Option<String>,
    #[serde(default)]
    pub host_key_algorithms: Option<String>,
    /// Client-key signature algorithms; recorded, russh picks the RSA hash itself.
    #[serde(default)]
    pub pubkey_accepted_algorithms: Option<String>,
    #[serde(default)]
    pub compression: Option<bool>,
    /// Environment variable names (patterns) to pass from the local environment.
    #[serde(default)]
    pub send_env: Vec<String>,
    /// `NAME=value` pairs to set on the remote side.
    #[serde(default)]
    pub set_env: Vec<String>,
    /// `yes`, `no`, `force` or `auto`.
    #[serde(default)]
    pub request_tty: Option<String>,
    /// Run on the server instead of a login shell. Stored verbatim; never run locally.
    #[serde(default)]
    pub remote_command: Option<String>,
    /// `yes`, `no`, `ask`, `confirm` or a lifetime.
    #[serde(default)]
    pub add_keys_to_agent: Option<String>,
    #[serde(default)]
    pub exit_on_forward_failure: Option<bool>,
    pub flags: Vec<HostFlag>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFlag {
    /// `ProxyCommand` is set; Bastion will not run it.
    ProxyCommandInert,
    /// The config contains `Match` blocks that might apply to this host but were not evaluated.
    MatchBlocksIgnored,
    /// `ForwardAgent yes` exposes the local agent to the remote host.
    ForwardAgentEnabled,
    /// The algorithm lists name weak algorithms; they stay off until allowed for this host.
    WeakAlgorithmsRequested,
    /// The algorithm lists name algorithms Bastion's SSH library cannot do.
    UnsupportedAlgorithms,
}

const MULTI: &[&str] = &["identityfile", "certificatefile", "localforward", "remoteforward", "dynamicforward", "sendenv", "setenv"];

/// What [`SshConfig::discover_opts`] reads besides `<root>/config` and its includes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discovery {
    /// Also read every file in `<root>/config.d/` (each becomes a customer group).
    pub scan_config_d: bool,
    pub extra_files: Vec<PathBuf>,
    pub extra_roots: Vec<PathBuf>,
}

/// Parsed config tree.
#[derive(Debug, Default)]
pub struct SshConfig {
    conds: Vec<Condition>,
    directives: Vec<Directive>,
    hosts: Vec<HostDecl>,
    pub match_blocks: Vec<MatchBlock>,
    pub warnings: Vec<Warning>,
    /// Source-relative paths of every file read.
    pub files: Vec<String>,
}

struct Loader<'a> {
    root: PathBuf,
    allowed: Vec<PathBuf>,
    limits: &'a Limits,
    stack: Vec<PathBuf>,
    seen: BTreeSet<PathBuf>,
    out: SshConfig,
}

impl SshConfig {
    /// Discover `<root>/config` (following its `Include`s) and every file in `<root>/config.d`
    /// not already reached through an `Include`. `root` is normally `~/.ssh`, or the matching
    /// directory of a GitLab clone.
    pub fn discover(root: &Path, limits: &Limits) -> SshConfig {
        Self::discover_with(root, &[], &[], limits)
    }

    /// Like [`discover`](Self::discover), plus custom config files and extra directories that
    /// `Include` may reach.
    pub fn discover_with(root: &Path, extra_files: &[PathBuf], extra_roots: &[PathBuf], limits: &Limits) -> SshConfig {
        Self::discover_opts(root, &Discovery { scan_config_d: true, extra_files: extra_files.to_vec(), extra_roots: extra_roots.to_vec() }, limits)
    }

    /// Discovery with every optional source switchable. `config` and whatever it `Include`s are
    /// always read (that is OpenSSH's own behaviour); scanning `config.d/` for files that are
    /// *not* included is the optional part.
    pub fn discover_opts(root: &Path, opts: &Discovery, limits: &Limits) -> SshConfig {
        let (extra_files, extra_roots) = (&opts.extra_files, &opts.extra_roots);
        let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let mut allowed = vec![root.clone()];
        allowed.extend(extra_roots.iter().filter_map(|p| p.canonicalize().ok()));
        let mut l = Loader { root: root.clone(), allowed, limits, stack: vec![], seen: BTreeSet::new(), out: SshConfig::default() };
        let main = root.join("config");
        if main.exists() {
            l.load(&main, 0, None);
        }
        let mut extra: Vec<PathBuf> = if opts.scan_config_d {
            std::fs::read_dir(root.join("config.d"))
                .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.is_file()).collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        extra.sort();
        extra.extend(extra_files.iter().cloned());
        for f in extra {
            if let Ok(c) = f.canonicalize() {
                if !l.seen.contains(&c) {
                    l.load(&f, 0, None);
                }
            }
        }
        l.out
    }

    /// Parse a single in-memory config. `Include` is not followed (reported as a warning).
    pub fn parse_str(text: &str, name: &str) -> SshConfig {
        let mut out = SshConfig::default();
        out.files.push(name.into());
        let mut cond = out.push_cond(Condition::Always);
        for (n, line) in text.lines().enumerate() {
            match out.line(line, name, n + 1, &mut cond) {
                Some(Line::Include(_)) => out.warn(name, n + 1, "Include is not followed when parsing a single file"),
                _ => {}
            }
        }
        out
    }

    fn push_cond(&mut self, c: Condition) -> usize {
        self.conds.push(c);
        self.conds.len() - 1
    }

    fn warn(&mut self, file: &str, line: usize, msg: impl Into<String>) {
        self.warnings.push(Warning { file: file.into(), line, message: msg.into() });
    }

    /// Interpret one line; returns `Some(Include)` for the caller to resolve.
    fn line(&mut self, raw: &str, file: &str, n: usize, cond: &mut usize) -> Option<Line> {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let (key, rest) = match line.find(|c: char| c.is_whitespace() || c == '=') {
            Some(i) => (&line[..i], line[i..].trim_start().trim_start_matches('=').trim()),
            None => (line, ""),
        };
        let key = key.to_ascii_lowercase();
        let args = tokenize(rest);
        match key.as_str() {
            "host" => {
                if args.is_empty() {
                    self.warn(file, n, "Host without patterns");
                }
                for a in &args {
                    if !a.starts_with('!') && !a.contains(['*', '?']) {
                        self.hosts.push(HostDecl { alias: a.clone(), file: file.into(), line: n });
                    }
                }
                *cond = self.push_cond(Condition::Host(args));
            }
            "match" => {
                self.match_blocks.push(MatchBlock { file: file.into(), line: n, criteria: rest.into() });
                *cond = self.push_cond(Condition::Match(rest.into()));
            }
            "include" => return Some(Line::Include(args)),
            _ if args.is_empty() => self.warn(file, n, format!("`{key}` has no value")),
            _ => {
                // ProxyCommand is kept byte-for-byte (it is shown to the user, never run).
                let value = if matches!(key.as_str(), "proxycommand" | "remotecommand" | "setenv") { rest.to_string() } else { args.join(" ") };
                self.directives.push(Directive { key, value, cond: *cond })
            }
        }
        None
    }

    /// Every concrete alias (wildcard and negated patterns are never listed), in config order,
    /// first declaration wins.
    pub fn hosts(&self) -> Vec<ResolvedHost> {
        let mut seen = BTreeSet::new();
        let index = self.index();
        self.hosts
            .iter()
            .filter(|h| seen.insert(h.alias.to_ascii_lowercase()))
            .map(|h| self.resolve_decl(h, &index))
            .collect()
    }

    /// Group directives by the condition they sit under, so resolving one host visits only the
    /// blocks that can apply to it instead of the whole tree (10k hosts would be quadratic).
    fn index(&self) -> DirectiveIndex {
        let mut ix = DirectiveIndex { by_cond: vec![Vec::new(); self.conds.len()], ..Default::default() };
        for (i, d) in self.directives.iter().enumerate() {
            ix.by_cond[d.cond].push(i);
        }
        for (c, cond) in self.conds.iter().enumerate() {
            match cond {
                Condition::Host(p) if p.iter().all(|p| !p.starts_with('!') && !p.contains(['*', '?'])) => {
                    for a in p {
                        ix.literal.entry(a.to_ascii_lowercase()).or_default().push(c);
                    }
                }
                _ => ix.general.push(c),
            }
        }
        ix
    }

    /// Resolve an arbitrary alias, as `ssh <alias>` would (minus `Match`).
    pub fn resolve(&self, alias: &str) -> ResolvedHost {
        let decl = self.hosts.iter().find(|h| h.alias.eq_ignore_ascii_case(alias)).cloned();
        self.resolve_decl(&decl.unwrap_or(HostDecl { alias: alias.into(), file: String::new(), line: 0 }), &self.index())
    }

    fn resolve_decl(&self, decl: &HostDecl, index: &DirectiveIndex) -> ResolvedHost {
        let alias = decl.alias.as_str();
        let mut single: BTreeMap<&str, &str> = BTreeMap::new();
        let mut multi: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut match_seen = false;
        let literal = index.literal.get(&alias.to_ascii_lowercase()).map(Vec::as_slice).unwrap_or_default();
        let mut order: Vec<usize> = index.general.iter().chain(literal).flat_map(|&c| index.by_cond[c].iter().copied()).collect();
        order.sort_unstable();
        order.dedup();
        for d in order.iter().map(|&i| &self.directives[i]) {
            match &self.conds[d.cond] {
                Condition::Always => {}
                Condition::Host(p) if host_matches(p, alias) => {}
                Condition::Match(_) => {
                    match_seen = true;
                    continue;
                }
                Condition::Host(_) => continue,
            }
            if MULTI.contains(&d.key.as_str()) {
                multi.entry(&d.key).or_default().push(&d.value);
            } else {
                single.entry(&d.key).or_insert(&d.value);
            }
        }
        let s = |k: &str| single.get(k).map(|v| v.to_string());
        let m = |k: &str| multi.get(k).map(|v| v.iter().map(|s| s.to_string()).collect()).unwrap_or_default();
        let yes = |k: &str| single.get(k).map(|v| v.eq_ignore_ascii_case("yes"));
        let hostname = s("hostname").map(|h| expand_tokens(&h, alias)).unwrap_or_else(|| alias.into());
        let mut r = ResolvedHost {
            alias: alias.into(),
            identity: stable_identity(&decl.file, alias),
            source_file: decl.file.clone(),
            group: group_name(&decl.file),
            source_line: decl.line,
            hostname,
            user: s("user"),
            port: s("port").and_then(|p| p.parse().ok()),
            identity_files: m("identityfile"),
            certificate_files: m("certificatefile"),
            identities_only: yes("identitiesonly"),
            identity_agent: s("identityagent"),
            proxy_jump: s("proxyjump").filter(|v| !v.eq_ignore_ascii_case("none")),
            proxy_command: s("proxycommand").filter(|v| !v.eq_ignore_ascii_case("none")),
            forward_agent: yes("forwardagent"),
            local_forwards: m("localforward"),
            remote_forwards: m("remoteforward"),
            dynamic_forwards: m("dynamicforward"),
            host_key_alias: s("hostkeyalias"),
            user_known_hosts_file: s("userknownhostsfile"),
            strict_host_key_checking: s("stricthostkeychecking"),
            server_alive_interval: s("serveraliveinterval").and_then(|v| v.parse().ok()),
            connect_timeout: s("connecttimeout").and_then(|v| v.parse().ok()),
            kex_algorithms: s("kexalgorithms"),
            ciphers: s("ciphers"),
            macs: s("macs"),
            host_key_algorithms: s("hostkeyalgorithms"),
            pubkey_accepted_algorithms: s("pubkeyacceptedalgorithms").or_else(|| s("pubkeyacceptedkeytypes")),
            compression: yes("compression"),
            send_env: m("sendenv").iter().flat_map(|v: &String| v.split_whitespace().map(String::from).collect::<Vec<_>>()).collect(),
            set_env: m("setenv").iter().flat_map(|v: &String| tokenize(v)).collect(),
            request_tty: s("requesttty"),
            remote_command: s("remotecommand").filter(|v| !v.eq_ignore_ascii_case("none")),
            add_keys_to_agent: s("addkeystoagent"),
            exit_on_forward_failure: yes("exitonforwardfailure"),
            flags: vec![],
        };
        if let Some(a) = r.algorithm_settings() {
            let warnings = a.resolve(false).map(|x| x.warnings).unwrap_or_else(|e| vec![e.to_string()]);
            if warnings.iter().any(|w| w.contains("weak")) {
                r.flags.push(HostFlag::WeakAlgorithmsRequested);
            }
            if warnings.iter().any(|w| w.contains("not implemented")) {
                r.flags.push(HostFlag::UnsupportedAlgorithms);
            }
        }
        if r.proxy_command.is_some() {
            r.flags.push(HostFlag::ProxyCommandInert);
        }
        if match_seen {
            r.flags.push(HostFlag::MatchBlocksIgnored);
        }
        if r.forward_agent == Some(true) {
            r.flags.push(HostFlag::ForwardAgentEnabled);
        }
        r
    }
}

enum Line {
    Include(Vec<String>),
}

#[derive(Default)]
struct DirectiveIndex {
    /// Directive indices per condition, in config order.
    by_cond: Vec<Vec<usize>>,
    /// Conditions that must be evaluated for every host (`Always`, `Match`, wildcard or negated `Host`).
    general: Vec<usize>,
    /// Literal-only `Host` conditions by lowercase alias.
    literal: std::collections::HashMap<String, Vec<usize>>,
}

impl Loader<'_> {
    fn rel(&self, p: &Path) -> String {
        p.strip_prefix(&self.root).unwrap_or(p).to_string_lossy().replace('\\', "/")
    }

    fn load(&mut self, path: &Path, depth: usize, inherited: Option<usize>) {
        let name = self.rel(path);
        let Ok(canon) = path.canonicalize() else {
            return self.out.warn(&name, 0, "file not found");
        };
        if !self.allowed.iter().any(|r| canon.starts_with(r)) {
            return self.out.warn(&name, 0, "path is outside the allowed config directories; not read");
        }
        if self.stack.contains(&canon) {
            return self.out.warn(&name, 0, "Include cycle detected; not read again");
        }
        if depth > self.limits.max_include_depth {
            return self.out.warn(&name, 0, "Include depth limit exceeded");
        }
        if self.seen.len() >= self.limits.max_files {
            return self.out.warn(&name, 0, "too many config files; remaining files skipped");
        }
        let text = match read_limited(&canon, self.limits.max_file_bytes) {
            Ok(t) => t,
            Err(msg) => return self.out.warn(&name, 0, msg),
        };
        self.seen.insert(canon.clone());
        self.stack.push(canon);
        self.out.files.push(name.clone());
        let mut cond = match inherited {
            Some(c) => c,
            None => self.out.push_cond(Condition::Always),
        };
        for (n, line) in text.lines().enumerate() {
            if let Some(Line::Include(args)) = self.out.line(line, &name, n + 1, &mut cond) {
                for pattern in args {
                    for target in self.expand_include(&pattern, &name, n + 1) {
                        self.load(&target, depth + 1, Some(cond));
                    }
                }
            }
        }
        self.stack.pop();
    }

    /// Resolve an `Include` argument to files. Relative paths are relative to the root, as
    /// OpenSSH resolves them relative to `~/.ssh`; `~/.ssh/` maps to the root. Wildcards are
    /// supported in the final path component only.
    fn expand_include(&mut self, pattern: &str, file: &str, line: usize) -> Vec<PathBuf> {
        let p = if let Some(rest) = pattern.strip_prefix("~/.ssh/") {
            self.root.join(rest)
        } else if let Some(rest) = pattern.strip_prefix("~/") {
            home_dir().map(|h| h.join(rest)).unwrap_or_else(|| PathBuf::from(pattern))
        } else {
            self.root.join(pattern)
        };
        // On Windows the canonical root is a `\\?\` verbatim path, where `/` is not a separator
        // and `..` is not resolved: `config.d/*` would never match and `../` would slip past the
        // escape check below. OpenSSH accepts both separators, so use the native one.
        #[cfg(windows)]
        let p = PathBuf::from(p.to_string_lossy().replace('/', "\\"));
        // Look for `..` in the pattern itself: joining onto a verbatim root on Windows already
        // folds `..` away, so the joined path no longer shows it.
        let climbs = pattern.split(['/', '\\']).any(|seg| seg == "..") || p.components().any(|c| c == Component::ParentDir);
        if climbs && !self.allowed.iter().any(|r| normalize(&p).starts_with(r)) {
            self.out.warn(file, line, format!("Include `{pattern}` escapes the config directory; ignored"));
            return vec![];
        }
        let (Some(dir), Some(last)) = (p.parent(), p.file_name().map(|s| s.to_string_lossy().into_owned())) else {
            return vec![];
        };
        // Check the pattern's own directory part, not the resolved path: on Windows the root (or an
        // absolute Include) can carry a `\\?\` verbatim prefix whose `?` is not a wildcard.
        let dir_part = pattern.strip_prefix(r"\\?\").unwrap_or(pattern);
        if dir_part.rsplit_once(['/', '\\']).is_some_and(|(d, _)| d.contains(['*', '?'])) {
            self.out.warn(file, line, format!("Include `{pattern}`: wildcards are only supported in the file name"));
            return vec![];
        }
        if !last.contains(['*', '?']) {
            if !p.exists() {
                self.out.warn(file, line, format!("Include `{pattern}` not found"));
                return vec![];
            }
            return vec![p];
        }
        let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| glob(&last, &e.file_name().to_string_lossy()))
                    .map(|e| e.path())
                    .filter(|p| p.is_file())
                    .collect()
            })
            .unwrap_or_default();
        found.sort();
        found
    }
}

fn read_limited(path: &Path, max: u64) -> std::result::Result<String, String> {
    let len = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    if len > max {
        return Err(format!("file is {len} bytes, over the {max}-byte limit; not read"));
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    if bytes.contains(&0) {
        return Err("file contains NUL bytes; not a text config".into());
    }
    let text = String::from_utf8(bytes).map_err(|_| "file is not valid UTF-8; not read".to_string())?;
    Ok(text.trim_start_matches('\u{feff}').to_string())
}

/// Lexical normalisation (no filesystem access) for traversal checks.
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}

/// The user's home: `HOME`, else `USERPROFILE` (Windows sets only the latter).
pub(crate) fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from)
}

/// Split arguments, honouring double quotes.
fn tokenize(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted) = (Vec::new(), String::new(), false);
    for ch in s.chars() {
        match ch {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// OpenSSH pattern-list semantics: matches if any positive pattern matches and no negated
/// pattern does. Comparison is case-insensitive.
pub fn host_matches(patterns: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let mut positive = false;
    for p in patterns {
        let p = p.to_ascii_lowercase();
        match p.strip_prefix('!') {
            Some(neg) if glob(neg, &host) => return false,
            Some(_) => {}
            None if glob(&p, &host) => positive = true,
            None => {}
        }
    }
    positive
}

/// `*` and `?` wildcard match (iterative, no backtracking blow-up).
fn glob(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

fn expand_tokens(v: &str, alias: &str) -> String {
    v.replace("%%", "\u{0}").replace("%h", alias).replace('\u{0}', "%")
}

pub fn stable_identity(source_file: &str, alias: &str) -> String {
    let mut h = Sha256::new();
    h.update(source_file.as_bytes());
    h.update([0u8]);
    h.update(alias.to_ascii_lowercase().as_bytes());
    hex::encode(h.finalize())
}

fn group_name(file: &str) -> String {
    file.rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or("config").to_string()
}

impl ResolvedHost {
    /// The algorithm settings this host's config asks for, or `None` when it sets none. Weak
    /// algorithms are never opted in by an import; the user allows them per host.
    pub fn algorithm_settings(&self) -> Option<crate::algorithms::AlgorithmSettings> {
        let a = crate::algorithms::AlgorithmSettings {
            kex: self.kex_algorithms.clone(),
            ciphers: self.ciphers.clone(),
            macs: self.macs.clone(),
            host_keys: self.host_key_algorithms.clone(),
            compression: self.compression,
            allow_weak: false,
        };
        (a != Default::default()).then_some(a)
    }

    /// Convert to a connection. Provenance and inert options go into metadata; nothing secret.
    pub fn to_connection(&self) -> Connection {
        let mut c = Connection::new(&self.alias, Protocol::Ssh, &self.hostname);
        c.settings.username = self.user.clone();
        c.settings.port = self.port;
        c.settings.keepalive_secs = self.server_alive_interval;
        c.settings.ssh_algorithms = self.algorithm_settings();
        let md = &mut c.metadata;
        md.insert("SshConfigIdentity".into(), self.identity.clone());
        md.insert("SourceFile".into(), self.source_file.clone());
        md.insert("Group".into(), self.group.clone());
        let opt = [
            ("ProxyJump", &self.proxy_jump),
            ("ProxyCommand", &self.proxy_command),
            ("IdentityAgent", &self.identity_agent),
            ("HostKeyAlias", &self.host_key_alias),
            ("UserKnownHostsFile", &self.user_known_hosts_file),
            ("StrictHostKeyChecking", &self.strict_host_key_checking),
            ("PubkeyAcceptedAlgorithms", &self.pubkey_accepted_algorithms),
            ("RequestTTY", &self.request_tty),
            ("RemoteCommand", &self.remote_command),
            ("AddKeysToAgent", &self.add_keys_to_agent),
        ];
        for (k, v) in opt {
            if let Some(v) = v {
                md.insert(k.into(), v.clone());
            }
        }
        if let Some(v) = self.exit_on_forward_failure {
            md.insert("ExitOnForwardFailure".into(), if v { "yes" } else { "no" }.into());
        }
        if !self.send_env.is_empty() {
            md.insert("SendEnv".into(), self.send_env.join(" "));
        }
        if !self.set_env.is_empty() {
            md.insert("SetEnv".into(), self.set_env.join("\n"));
        }
        if let Some(f) = self.identity_files.first() {
            md.insert("IdentityFile".into(), f.clone());
        }
        c
    }
}
