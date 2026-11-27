//! mRemoteNG `confCons.xml` importer (B14-C1). The file is untrusted: a small hand-written,
//! non-validating scanner reads only `<Node>` elements. DTDs and entities are refused, so no
//! entity expansion can happen. Passwords are never imported; script fields are ignored.

use std::collections::BTreeMap;

use crate::error::{CoreError, Result};
use crate::import::{Found, Imported, MAX_TREE_DEPTH};
use crate::model::{Connection, Protocol};

/// Largest single attribute value (notes included).
pub const MAX_ATTR_BYTES: usize = 64 * 1024;
/// Most `<Node>` elements one file may hold.
pub const MAX_NODES: usize = 100_000;

/// Fields a connection may take from a parent container through `Inherit<Field>="True"`.
/// `Hostname` and `Password` are never inherited.
const INHERITABLE: [&str; 4] = ["Port", "Username", "Domain", "Protocol"];

type Attrs = BTreeMap<String, String>;

/// Parse a `confCons.xml` export into folders and connections.
pub fn mremoteng(text: &str) -> Result<Imported> {
    if text.len() > crate::export::MAX_IMPORT_BYTES {
        return Err(CoreError::Invalid(format!(
            "import file is larger than the {} MiB limit",
            crate::export::MAX_IMPORT_BYTES >> 20
        )));
    }
    if text.contains("<!DOCTYPE") || text.contains("<!ENTITY") {
        return Err(CoreError::Invalid(
            "the file has a DTD or entity declarations, which are not accepted".into(),
        ));
    }
    let mut out = Imported::default();
    let mut seen_root = false;
    // Open containers: (folder name, attributes).
    let mut stack: Vec<(String, Attrs)> = Vec::new();
    // For each open <Node>, whether it pushed a container frame.
    let mut open: Vec<bool> = Vec::new();
    let mut nodes = 0usize;
    let mut rest = text;
    while let Some(lt) = rest.find('<') {
        rest = &rest[lt..];
        if let Some(r) = rest.strip_prefix("<!--") {
            rest = r.find("-->").map_or("", |e| &r[e + 3..]);
            continue;
        }
        let end = find_tag_end(rest)
            .ok_or_else(|| CoreError::Invalid("the file ends inside a tag".into()))?;
        let tag = &rest[1..end];
        rest = &rest[end + 1..];
        if tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        if let Some(name) = tag.strip_prefix('/') {
            if element_name(name) == "Node" && open.pop() == Some(true) {
                stack.pop();
            }
            continue;
        }
        let self_closing = tag.ends_with('/');
        let body = tag.trim_end_matches('/');
        let name = element_name(body);
        if name == "Connections" || name.ends_with(":Connections") {
            let attrs = parse_attrs(body)?;
            if attrs
                .get("FullFileEncryption")
                .is_some_and(|v| v.eq_ignore_ascii_case("true"))
            {
                return Err(CoreError::Invalid(
                    "the file is fully encrypted; export it unencrypted from mRemoteNG".into(),
                ));
            }
            seen_root = true;
            continue;
        }
        if name != "Node" {
            continue;
        }
        if !seen_root {
            return Err(not_mremoteng());
        }
        nodes += 1;
        if nodes > MAX_NODES {
            return Err(CoreError::Invalid(format!(
                "the file has more than {MAX_NODES} entries"
            )));
        }
        let attrs = parse_attrs(body)?;
        if attrs.get("Type").is_some_and(|t| t == "Container") {
            if stack.len() >= MAX_TREE_DEPTH {
                return Err(CoreError::Invalid(format!(
                    "the folder tree is deeper than {MAX_TREE_DEPTH} levels"
                )));
            }
            if !self_closing {
                let label = attrs
                    .get("Name")
                    .filter(|n| !n.trim().is_empty())
                    .cloned()
                    .unwrap_or_else(|| "Folder".into());
                stack.push((label, attrs));
                open.push(true);
            }
        } else {
            connection(&attrs, &stack, &mut out);
            if !self_closing {
                open.push(false);
            }
        }
    }
    if !seen_root {
        return Err(not_mremoteng());
    }
    Ok(out)
}

fn not_mremoteng() -> CoreError {
    CoreError::Invalid("not an mRemoteNG file (no <Connections> element)".into())
}

/// The value of `key` for a connection, following `Inherit<key>` up the container stack. The
/// stack is capped at `MAX_TREE_DEPTH`, so the walk is bounded.
fn resolve(key: &str, attrs: &Attrs, stack: &[(String, Attrs)]) -> Option<String> {
    let inherits = |a: &Attrs| {
        INHERITABLE.contains(&key)
            && a.get(&format!("Inherit{key}"))
                .is_some_and(|v| v.eq_ignore_ascii_case("true"))
    };
    if !inherits(attrs) {
        return attrs.get(key).cloned();
    }
    stack
        .iter()
        .rev()
        .find(|(_, parent)| !inherits(parent))
        .and_then(|(_, parent)| parent.get(key).cloned())
}

fn map_protocol(p: &str) -> Option<(Protocol, Option<&'static str>)> {
    Some(match p {
        "RDP" => (Protocol::Rdp, None),
        "SSH1" | "SSH2" => (Protocol::Ssh, None),
        "VNC" => (Protocol::Vnc, None),
        // Rlogin and RAW are not Telnet: RAW is plain TCP and Telnet negotiation would corrupt it.
        "Telnet" => (Protocol::Telnet, None),
        "HTTP" => (Protocol::Web, Some("http")),
        "HTTPS" => (Protocol::Web, Some("https")),
        _ => return None,
    })
}

fn connection(attrs: &Attrs, stack: &[(String, Attrs)], out: &mut Imported) {
    let name = attrs
        .get("Name")
        .map(|n| n.trim())
        .filter(|n| !n.is_empty())
        .unwrap_or("Connection")
        .to_string();
    let get = |k: &str| {
        resolve(k, attrs, stack)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let raw_protocol = get("Protocol").unwrap_or_else(|| "RDP".into());
    let Some((protocol, scheme)) = map_protocol(&raw_protocol) else {
        out.skipped.push(format!(
            "{name}: {raw_protocol} connections are not supported"
        ));
        return;
    };
    let Some(host) = get("Hostname") else {
        out.skipped.push(format!("{name}: no host name"));
        return;
    };
    if let Err(e) = crate::properties::check_host(&host) {
        out.skipped.push(format!("{name}: {e}"));
        return;
    }
    let port = match get("Port")
        .map(|p| crate::properties::parse_port(&p))
        .transpose()
    {
        Ok(p) => p,
        Err(e) => {
            out.skipped.push(format!("{name}: {e}"));
            return;
        }
    };
    let (host, port) = match scheme {
        Some(s) => match port {
            Some(p) if !((s == "http" && p == 80) || (s == "https" && p == 443)) => {
                (format!("{s}://{host}:{p}"), None)
            }
            _ => (format!("{s}://{host}"), None),
        },
        None => (host, port.filter(|p| Some(*p) != protocol.default_port())),
    };
    let mut c = Connection::new(&name, protocol, host);
    c.settings.port = port;
    c.settings.username = match (get("Domain"), get("Username")) {
        (Some(d), Some(u)) if protocol == Protocol::Rdp => Some(format!("{d}\\{u}")),
        (_, u) => u,
    };
    c.notes = attrs.get("Descr").cloned().unwrap_or_default();
    if attrs.get("Password").is_some_and(|p| !p.is_empty()) {
        out.skipped
            .push(format!("{name}: password not imported (use the vault)"));
    }
    out.found.push(Found {
        path: stack.iter().map(|(n, _)| n.clone()).collect(),
        connection: c,
    });
}

/// Index of the `>` that closes the tag starting at `s[0] == '<'`, skipping quoted values.
fn find_tag_end(s: &str) -> Option<usize> {
    let mut quote: Option<u8> = None;
    for (i, b) in s.bytes().enumerate().skip(1) {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(i),
            None => {}
        }
    }
    None
}

fn element_name(tag: &str) -> &str {
    tag.split(char::is_whitespace).next().unwrap_or_default()
}

fn parse_attrs(tag: &str) -> Result<Attrs> {
    let mut attrs = Attrs::new();
    let mut rest = tag.trim_start_matches(|c: char| !c.is_whitespace());
    loop {
        rest = rest.trim_start();
        let Some(eq) = rest.find('=') else { break };
        let key = rest[..eq].trim().to_string();
        let after = rest[eq + 1..].trim_start();
        let Some(q) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            return Err(CoreError::Invalid(
                "an attribute value is not quoted".into(),
            ));
        };
        let close = after[1..]
            .find(q)
            .ok_or_else(|| CoreError::Invalid("an attribute value is not closed".into()))?;
        let value = &after[1..1 + close];
        if value.len() > MAX_ATTR_BYTES {
            return Err(CoreError::Invalid(format!(
                "the attribute {key} is larger than {} KiB",
                MAX_ATTR_BYTES >> 10
            )));
        }
        attrs.insert(key, unescape(value));
        rest = &after[close + 2..];
    }
    Ok(attrs)
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#xD;", "\r")
        .replace("&#xA;", "\n")
        .replace("&amp;", "&")
}

#[cfg(test)]
#[path = "import_mremoteng_tests.rs"]
mod tests;
