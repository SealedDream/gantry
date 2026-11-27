//! A plugin runs a declared command on its entry's host over SSH (plugin API 1.5; permission
//! `exec = "entry"`; threat review in `docs/specs/plugins.md`, section 19).
//!
//! Pure decisions only. The manifest declares every command as an argv template (`[[exec]]`);
//! a plugin names a template and gives typed arguments; the core checks each argument against
//! its kind's strict pattern, puts it in its own argv element, and quotes every element for a
//! POSIX shell. A plugin never sends a command line, a flag or a shell word of its own.
//!
//! The dispatch in `host/view_exec.rs` sends the built command to the app, which runs it over
//! the entry's own SSH login and route (gateway, jump hosts) and answers with the exit status
//! and the output. The plugin never sees the login.

use std::collections::BTreeMap;
use std::time::Duration;

use super::Failure;

/// Templates in one manifest.
pub const MAX_TEMPLATES: usize = 32;
/// Elements in one template's argv.
pub const MAX_ARGV: usize = 32;
/// Bytes in one fixed argv element.
pub const MAX_ELEMENT_BYTES: usize = 256;
/// Output kept per stream (stdout, stderr). More is cut and reported as truncated.
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
/// The longest a non-interactive command may run, and the default.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Commands one helper may have running at once.
pub const MAX_RUNNING: usize = 4;
/// Commands per helper per minute, refused ones included.
pub const MAX_PER_MINUTE: usize = 120;

/// Fixed words that change state in the CLIs plugins drive (Docker, Podman, kubectl, systemctl).
/// A template holding one must be `changes = true`.
pub const MUTATING_WORDS: &[&str] = &[
    "rm", "rmi", "stop", "kill", "restart", "start", "exec", "run", "pull", "push", "prune", "create", "update", "pause", "unpause", "rename", "delete", "apply",
    "scale", "cp", "commit", "build", "load", "import", "tag", "login", "logout", "attach", "up", "down", "remove", "patch", "replace", "drain", "cordon",
    "uncordon", "rollout", "set", "edit", "enable", "disable", "mask", "reload",
];

/// Programs a template may run with `changes = false` (security review SEC-REVIEW-01). Any
/// other program (a shell, an interpreter, sudo, curl, wget, mv, rm, chmod, dd, tee, ...) is
/// always a change.
pub const READ_ONLY_PROGRAMS: &[&str] = &["docker", "podman", "kubectl", "systemctl", "echo", "sleep"];
/// `systemctl` subcommands that only read.
pub const SYSTEMCTL_READ: &[&str] = &["status", "show", "list-units", "list-unit-files", "list-timers", "is-active", "is-enabled", "is-failed", "cat", "list-dependencies"];

/// Whether the template's program may run without `changes = true`.
fn program_read_only(argv: &[Part]) -> bool {
    let word = |i: usize| match argv.get(i) {
        Some(Part::Fixed(w)) => Some(w.as_str()),
        _ => None,
    };
    match word(0) {
        Some("systemctl") => word(1).is_some_and(|w| SYSTEMCTL_READ.contains(&w)),
        Some(p) => READ_ONLY_PROGRAMS.contains(&p),
        None => false,
    }
}

/// What one argument may hold. Fixed by the core; a manifest picks one per placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// A container, image, volume or network id or name: `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`.
    /// Never starts with `-`, so it cannot be read as a flag.
    Name,
    /// An image reference: a name with `/`, `:` and `@` too (`registry:5000/app:1.2`,
    /// `app@sha256:...`), 1 to 255 bytes, starting with a letter or digit.
    Image,
    /// A whole number from 1 to 100000 (a line count).
    Count,
}

impl ArgKind {
    pub fn parse(s: &str) -> Option<ArgKind> {
        match s {
            "name" => Some(ArgKind::Name),
            "image" => Some(ArgKind::Image),
            "count" => Some(ArgKind::Count),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ArgKind::Name => "name",
            ArgKind::Image => "image",
            ArgKind::Count => "count",
        }
    }

    /// Whether `v` is a valid value of this kind.
    pub fn accepts(self, v: &str) -> bool {
        let first_ok = v.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric());
        match self {
            ArgKind::Name => first_ok && v.len() <= 128 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
            ArgKind::Image => first_ok && v.len() <= 255 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-/:@".contains(&b)),
            ArgKind::Count => !v.is_empty() && v.len() <= 6 && v.bytes().all(|b| b.is_ascii_digit()) && !v.starts_with('0') && v.parse::<u32>().is_ok_and(|n| (1..=100_000).contains(&n)),
        }
    }
}

/// One argv element of a template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// Sent as written.
    Fixed(String),
    /// `{name}`: the argument of that name, one whole element.
    Arg(String),
}

/// One `[[exec]]` entry of the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub id: String,
    pub argv: Vec<Part>,
    /// Kind of each placeholder.
    pub args: BTreeMap<String, ArgKind>,
    /// Changes the server (start, stop, remove, a shell): needs the entry's "Allow changes" and a
    /// user action just before.
    pub changes: bool,
    /// Runs in a terminal tab with a PTY (`exec.terminal`), never through `exec.run`.
    pub interactive: bool,
}

/// The manifest's `[[exec]]` list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecSpec {
    pub templates: Vec<Template>,
}

/// A fixed element: printable ASCII without a shell-special meaning that matters once quoted, so
/// the install prompt shows exactly what runs. Quoting makes any byte safe; this keeps the
/// prompt readable and refuses control characters.
pub fn valid_fixed(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_ELEMENT_BYTES && s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// Parse one argv element: `{name}` is a placeholder (the whole element), anything else fixed.
/// A `{` or `}` inside a fixed element is allowed only as Go template text (`{{json .}}`).
pub fn parse_part(s: &str) -> Option<Part> {
    if let Some(inner) = s.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
        if !inner.starts_with('{') {
            let ok = !inner.is_empty() && inner.len() <= 32 && inner.bytes().all(|b| b.is_ascii_lowercase() || b == b'-');
            return ok.then(|| Part::Arg(inner.to_string()));
        }
    }
    valid_fixed(s).then(|| Part::Fixed(s.to_string()))
}

impl Template {
    /// Every placeholder has a kind, every kind is used, and an interactive template changes.
    pub fn check(&self) -> Result<(), &'static str> {
        if self.argv.is_empty() || self.argv.len() > MAX_ARGV {
            return Err("exec.argv");
        }
        if !matches!(self.argv.first(), Some(Part::Fixed(_))) {
            return Err("exec.argv");
        }
        let used: Vec<&String> = self.argv.iter().filter_map(|p| if let Part::Arg(n) = p { Some(n) } else { None }).collect();
        if used.iter().any(|n| !self.args.contains_key(*n)) || self.args.keys().any(|k| !used.contains(&k)) {
            return Err("exec.args");
        }
        if self.interactive && !self.changes {
            return Err("exec.changes");
        }
        // An image argument can name any registry: pulling or running one is a change.
        if self.args.values().any(|k| *k == ArgKind::Image) && !self.changes {
            return Err("exec.changes");
        }
        // The manifest marks changes, but a word that changes state must be marked (security
        // review, MEDIUM 3). Belt and braces: Official review is the main control.
        let mutating = self.argv.iter().any(|p| matches!(p, Part::Fixed(w) if MUTATING_WORDS.contains(&w.as_str())));
        if (mutating || !program_read_only(&self.argv)) && !self.changes {
            return Err("exec.changes");
        }
        Ok(())
    }

    /// The command as the install prompt shows it: `docker logs --tail <count> <name>`.
    pub fn display(&self) -> String {
        self.argv
            .iter()
            .map(|p| match p {
                Part::Fixed(s) => quote(s),
                Part::Arg(n) => format!("<{}>", self.args.get(n).map_or("?", |k| k.as_str())),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Build the argv from `given`: exactly the template's arguments, each valid for its kind.
    pub fn build(&self, given: &[(String, String)]) -> Result<Vec<String>, Failure> {
        let mut values: BTreeMap<&str, &str> = BTreeMap::new();
        for (k, v) in given {
            let Some(kind) = self.args.get(k) else {
                return Err(Failure::Invalid(format!("`{}` is not an argument of command `{}`", short(k), self.id)));
            };
            if !kind.accepts(v) {
                return Err(Failure::Invalid(format!("argument `{k}` is not a valid {}", kind.as_str())));
            }
            if values.insert(k, v).is_some() {
                return Err(Failure::Invalid(format!("argument `{k}` is given twice")));
            }
        }
        self.argv
            .iter()
            .map(|p| match p {
                Part::Fixed(s) => Ok(s.clone()),
                Part::Arg(n) => values.get(n.as_str()).map(|v| v.to_string()).ok_or_else(|| Failure::Invalid(format!("argument `{n}` is missing"))),
            })
            .collect()
    }
}

fn short(s: &str) -> String {
    s.chars().take(32).filter(|c| !c.is_control()).collect()
}

/// One element quoted for a POSIX shell: bare when it holds only safe characters, else in
/// single quotes with each `'` written as `'\''`. The SSH server hands the command line to the
/// user's login shell, so every element must arrive as one word with no expansion.
pub fn quote(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-./:@=,+%".contains(&b)) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The command line the app sends as the SSH `exec` request.
pub fn command_line(argv: &[String]) -> String {
    argv.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
}

impl ExecSpec {
    pub fn get(&self, id: &str) -> Option<&Template> {
        self.templates.iter().find(|t| t.id == id)
    }
}

/// The time limit a plugin asked for, capped.
pub fn timeout_of(ms: Option<u32>) -> Duration {
    match ms {
        None | Some(0) => DEFAULT_TIMEOUT,
        Some(ms) => Duration::from_millis(ms as u64).min(MAX_TIMEOUT),
    }
}

/// `true` when the entry's field `allow-changes` is on.
pub fn changes_allowed(fields: &[(String, String)]) -> bool {
    fields.iter().any(|(k, v)| k == ALLOW_CHANGES_FIELD && v == "true")
}

/// The entry field that turns on templates with `changes = true`. The user sets it in the
/// entry's properties; the plugin cannot.
pub const ALLOW_CHANGES_FIELD: &str = "allow-changes";

/// Cut `data` to the output cap; `true` when something was cut.
pub fn cap_output(mut data: Vec<u8>) -> (Vec<u8>, bool) {
    if data.len() > MAX_OUTPUT_BYTES {
        data.truncate(MAX_OUTPUT_BYTES);
        (data, true)
    } else {
        (data, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logs() -> Template {
        Template {
            id: "logs".into(),
            argv: ["docker", "logs", "--tail", "{lines}", "{id}"].iter().map(|s| parse_part(s).unwrap()).collect(),
            args: [("lines".to_string(), ArgKind::Count), ("id".to_string(), ArgKind::Name)].into_iter().collect(),
            changes: false,
            interactive: false,
        }
    }

    #[test]
    fn names_refuse_flags_shell_words_and_spaces() {
        for bad in ["", "-rf", "--privileged", "a b", "a;rm", "$(id)", "`id`", "a\nb", "a'b", "a|b", "../x", "é", &"a".repeat(129)] {
            assert!(!ArgKind::Name.accepts(bad), "{bad:?}");
        }
        for good in ["web", "f00dbabe1234", "my_app.1-2"] {
            assert!(ArgKind::Name.accepts(good));
        }
        assert!(ArgKind::Image.accepts("registry:5000/team/app:1.2"));
        assert!(!ArgKind::Image.accepts("-v"));
        assert!(!ArgKind::Image.accepts("app latest"));
    }

    #[test]
    fn counts_are_whole_numbers_in_range() {
        for bad in ["0", "-1", "100001", "01", "1e3", "", "9999999", " 5"] {
            assert!(!ArgKind::Count.accepts(bad), "{bad:?}");
        }
        assert!(ArgKind::Count.accepts("1") && ArgKind::Count.accepts("100000"));
    }

    #[test]
    fn a_template_builds_argv_from_typed_arguments_only() {
        let t = logs();
        t.check().unwrap();
        let argv = t.build(&[("id".into(), "web".into()), ("lines".into(), "200".into())]).unwrap();
        assert_eq!(argv, ["docker", "logs", "--tail", "200", "web"]);
        assert!(t.build(&[("id".into(), "web".into())]).is_err(), "missing");
        assert!(t.build(&[("id".into(), "web".into()), ("lines".into(), "2".into()), ("extra".into(), "x".into())]).is_err(), "unknown");
        assert!(t.build(&[("id".into(), "w;id".into()), ("lines".into(), "2".into())]).is_err(), "pattern");
        assert!(t.build(&[("id".into(), "a".into()), ("id".into(), "b".into()), ("lines".into(), "2".into())]).is_err(), "twice");
        assert_eq!(t.display(), "docker logs --tail <count> <name>");
    }

    #[test]
    fn quoting_makes_every_element_one_literal_word() {
        assert_eq!(quote("web"), "web");
        assert_eq!(quote("{{json .}}"), "'{{json .}}'");
        assert_eq!(quote("it's"), "'it'\\''s'");
        assert_eq!(quote(""), "''");
        assert_eq!(command_line(&["docker".into(), "ps".into(), "--format".into(), "{{json .}}".into()]), "docker ps --format '{{json .}}'");
        assert_eq!(quote("$(id)"), "'$(id)'");
    }

    #[test]
    fn templates_are_checked() {
        let mut t = logs();
        t.args.remove("lines");
        assert_eq!(t.check(), Err("exec.args"), "placeholder with no kind");
        let mut t = logs();
        t.args.insert("unused".into(), ArgKind::Name);
        assert_eq!(t.check(), Err("exec.args"), "kind never used");
        let mut t = logs();
        t.argv.insert(0, Part::Arg("id".into()));
        assert_eq!(t.check(), Err("exec.argv"), "the program must be fixed");
        let mut t = logs();
        t.interactive = true;
        assert_eq!(t.check(), Err("exec.changes"), "a shell always counts as a change");
        let mut t = logs();
        t.argv[1] = Part::Fixed("rm".into());
        assert_eq!(t.check(), Err("exec.changes"), "rm must be marked as a change");
        t.changes = true;
        assert_eq!(t.check(), Ok(()));
        let mut t = logs();
        t.args.insert("id".into(), ArgKind::Image);
        assert_eq!(t.check(), Err("exec.changes"), "an image argument is a change");
        for prog in ["sh", "bash", "zsh", "python", "perl", "sudo", "curl", "wget", "mv", "rm", "chmod", "dd", "tee"] {
            let mut t = logs();
            t.argv[0] = Part::Fixed(prog.into());
            assert_eq!(t.check(), Err("exec.changes"), "{prog} is always a change");
            t.changes = true;
            assert_eq!(t.check(), Ok(()));
        }
        let sys = |sub: &str| Template { argv: vec![Part::Fixed("systemctl".into()), Part::Fixed(sub.into())], args: BTreeMap::new(), ..logs() };
        assert_eq!(sys("status").check(), Ok(()));
        assert_eq!(sys("poweroff").check(), Err("exec.changes"));
        for prog in ["podman", "kubectl"] {
            let mut t = logs();
            t.argv[0] = Part::Fixed(prog.into());
            assert_eq!(t.check(), Ok(()), "{prog} logs is read-only");
        }
        assert_eq!(parse_part("{ID}"), None, "a brace word that is not a placeholder name is refused");
        assert_eq!(parse_part("{{json .}}"), Some(Part::Fixed("{{json .}}".into())));
        assert_eq!(parse_part("a\tb"), None);
    }

    #[test]
    fn limits_and_allow_changes() {
        assert_eq!(timeout_of(None), DEFAULT_TIMEOUT);
        assert_eq!(timeout_of(Some(999_999)), MAX_TIMEOUT);
        assert!(changes_allowed(&[("allow-changes".into(), "true".into())]));
        assert!(!changes_allowed(&[("allow-changes".into(), "yes".into())]));
        let (d, cut) = cap_output(vec![0; MAX_OUTPUT_BYTES + 1]);
        assert!(cut && d.len() == MAX_OUTPUT_BYTES);
    }
}
