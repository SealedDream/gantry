//! Export SSH connections as an Ansible INI inventory.
//!
//! One `[bastion]` group; each connection becomes `<name> ansible_host=… ansible_user=… …`.
//! Names and values that could break INI parsing or smuggle extra variables (whitespace, quotes,
//! `#`/`;`, `=` in a name, control characters) are skipped and listed, never escaped. Secrets
//! never reach the file: the selection is scrubbed exactly as a Bastion export is.

use crate::export::{self, Selection};
use crate::error::{CoreError, Result};
use crate::model::{Document, Protocol};
use std::path::Path;

/// Characters allowed in an inventory host name (Ansible accepts more, but these are all safe).
fn name_ok(n: &str) -> bool {
    !n.is_empty() && !n.starts_with(['-', '.']) && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn value_ok(v: &str) -> bool {
    !v.is_empty() && v.chars().all(|c| !c.is_whitespace() && !c.is_control() && !matches!(c, '"' | '\'' | '#' | ';' | '\\' | '$' | '{' | '}' | '`'))
}

/// Inventory file format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Ini,
    Yaml,
}

/// INI inventory text plus `(name, reason)` for each connection left out.
pub fn export_document(doc: &Document, selection: &Selection) -> (String, Vec<(String, String)>) {
    export_document_as(doc, selection, Format::Ini)
}

/// Inventory text in `format` plus `(name, reason)` for each connection left out.
pub fn export_document_as(doc: &Document, selection: &Selection, format: Format) -> (String, Vec<(String, String)>) {
    let (picked, _) = export::prepare(doc, selection);
    let mut hosts: Vec<(String, Vec<(&'static str, String)>)> = Vec::new();
    let mut skipped = Vec::new();
    for r in picked.connections() {
        let c = r.connection;
        let s = r.effective;
        if c.protocol != Protocol::Ssh {
            skipped.push((c.name, "not an SSH connection".to_string()));
            continue;
        }
        if !name_ok(&c.name) {
            skipped.push((c.name, "name isn't a safe inventory host name (use letters, digits, _ - .)".into()));
            continue;
        }
        let mut vars = vec![("ansible_host", c.host.clone())];
        if let Some(u) = s.username.clone() {
            vars.push(("ansible_user", u));
        }
        if let Some(p) = s.port.filter(|p| Some(*p) != c.protocol.default_port()) {
            vars.push(("ansible_port", p.to_string()));
        }
        if let Some(k) = c.metadata.get("IdentityFile") {
            vars.push(("ansible_ssh_private_key_file", k.clone()));
        }
        if let Some(j) = c.metadata.get("ProxyJump") {
            vars.push(("ansible_ssh_common_args", format!("-J{j}")));
        }
        if let Some((k, v)) = vars.iter().find(|(_, v)| !value_ok(v)) {
            skipped.push((c.name, format!("{k} `{}` can't be written to an inventory safely", v.escape_debug())));
            continue;
        }
        hosts.push((c.name, vars));
    }
    let mut out = String::from("# Exported by Gantry\n");
    match format {
        Format::Ini => {
            out.push_str("[bastion]\n");
            for (name, vars) in hosts {
                out.push_str(&name);
                for (k, v) in vars {
                    out.push_str(&format!(" {k}={v}"));
                }
                out.push('\n');
            }
        }
        Format::Yaml => {
            out.push_str("all:\n  children:\n    bastion:\n");
            if hosts.is_empty() {
                out.push_str("      hosts: {}\n");
            } else {
                out.push_str("      hosts:\n");
            }
            for (name, vars) in hosts {
                out.push_str(&format!("        {name}:\n"));
                for (k, v) in vars {
                    // Values hold no quote or backslash (value_ok), so double quotes are safe.
                    out.push_str(&format!("          {k}: \"{v}\"\n"));
                }
            }
        }
    }
    (out, skipped)
}

fn arg_ok(a: &str) -> bool {
    !a.is_empty() && !a.starts_with('-') && !a.chars().any(char::is_control)
}

/// argv for `ansible <pattern> -i <inventory> -m <module> [-a <args>]`. No shell is involved: the
/// caller passes the vector straight to a process spawn.
pub fn ad_hoc_argv(inventory: &Path, module: &str, args: Option<&str>, pattern: &str) -> Result<Vec<String>> {
    if !arg_ok(pattern) || !arg_ok(module) || args.is_some_and(|a| a.chars().any(char::is_control)) {
        return Err(CoreError::Invalid("pattern, module or arguments aren't valid for ansible".into()));
    }
    let mut v = vec!["ansible".to_string(), pattern.into(), "-i".into(), inventory.display().to_string(), "-m".into(), module.into()];
    if let Some(a) = args.filter(|a| !a.is_empty()) {
        v.push("-a".into());
        v.push(a.into());
    }
    Ok(v)
}

/// argv for `ansible-playbook -i <inventory> <playbook>`.
pub fn playbook_argv(inventory: &Path, playbook: &Path) -> Result<Vec<String>> {
    let p = playbook.display().to_string();
    if p.is_empty() || p.starts_with('-') || p.chars().any(char::is_control) {
        return Err(CoreError::Invalid("playbook path isn't valid".into()));
    }
    Ok(vec!["ansible-playbook".into(), "-i".into(), inventory.display().to_string(), p])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_values_are_validated() {
        assert!(name_ok("web-1.prod_a"));
        assert!(!name_ok("web 1"));
        assert!(!name_ok("a=b"));
        assert!(!name_ok(""));
        assert!(value_ok("10.0.0.5"));
        assert!(!value_ok("host name"));
        assert!(!value_ok("x#y"));
        assert!(!value_ok("a\nb"));
    }

    #[test]
    fn argv_builders_refuse_option_injection() {
        let inv = Path::new("/tmp/inv.ini");
        assert_eq!(ad_hoc_argv(inv, "ping", None, "all").unwrap(), ["ansible", "all", "-i", "/tmp/inv.ini", "-m", "ping"]);
        assert_eq!(ad_hoc_argv(inv, "shell", Some("uptime"), "web").unwrap().last().unwrap(), "uptime");
        assert!(ad_hoc_argv(inv, "ping", None, "--version").is_err());
        assert!(ad_hoc_argv(inv, "-m", None, "all").is_err());
        assert!(ad_hoc_argv(inv, "ping", Some("a\nb"), "all").is_err());
        assert_eq!(playbook_argv(inv, Path::new("site.yml")).unwrap(), ["ansible-playbook", "-i", "/tmp/inv.ini", "site.yml"]);
        assert!(playbook_argv(inv, Path::new("--check")).is_err());
    }
}
