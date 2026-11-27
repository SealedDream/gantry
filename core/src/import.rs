//! Importers: OpenSSH config, CSV, Microsoft `.rdp` files, PuTTY sessions (`.reg`), Royal JSON
//! and RDCMan `.rdg`. Secrets are never imported here; skipped fields are reported.
use std::collections::BTreeMap;

use crate::error::{CoreError, Result};
use crate::model::{Connection, Protocol};

/// Parse a single OpenSSH client config (no `Include` following); delegates to
/// [`crate::sshconfig`], so options resolve with OpenSSH first-match-wins precedence.
/// Wildcard and negated patterns are never listed as hosts.
pub fn openssh_config(text: &str) -> Vec<Connection> {
    crate::sshconfig::SshConfig::parse_str(text, "config").hosts().iter().map(|h| h.to_connection()).collect()
}

/// CSV with a header row. Required columns: `name`, `host`, `protocol`. Optional: `port`,
/// `username`, `tags` (`;`-separated), `notes`. Password columns are rejected outright.
pub fn csv(text: &str) -> Result<Vec<Connection>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut records = csv_records(text)?
        .into_iter()
        .filter(|(_, r)| !(r.len() == 1 && r[0].trim().is_empty()));
    let header: Vec<String> = records
        .next()
        .ok_or_else(|| CoreError::Invalid("empty CSV".into()))?
        .1
        .into_iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    if header.iter().any(|h| h.contains("password")) {
        return Err(CoreError::Invalid(
            "CSV contains a password column; import secrets through the credential importer".into(),
        ));
    }
    let col = |n: &str| header.iter().position(|h| h == n);
    let (Some(ni), Some(hi), Some(pi)) = (col("name"), col("host"), col("protocol")) else {
        return Err(CoreError::Invalid("CSV needs name, host and protocol columns".into()));
    };
    records.map(|(row, f)| csv_row(row, &f, &col, ni, hi, pi)).collect()
}

fn csv_row(
    row: usize,
    f: &[String],
    col: &dyn Fn(&str) -> Option<usize>,
    ni: usize,
    hi: usize,
    pi: usize,
) -> Result<Connection> {
    let get = |idx: Option<usize>| {
        idx.and_then(|i| f.get(i)).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    };
    let proto_name = get(Some(pi)).unwrap_or_default().to_lowercase();
    let proto: Protocol = serde_json::from_value(serde_json::Value::String(proto_name))
        .map_err(|_| CoreError::Invalid(format!("row {row}: unknown protocol")))?;
    let host = get(Some(hi)).ok_or_else(|| CoreError::Invalid(format!("row {row}: missing host")))?;
    let mut c = Connection::new(get(Some(ni)).unwrap_or_else(|| host.clone()), proto, host);
    c.settings.port = match get(col("port")) {
        None => None,
        Some(p) => Some(
            p.parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| CoreError::Invalid(format!("row {row}: invalid port `{p}` (1-65535)")))?,
        ),
    };
    c.settings.username = get(col("username"));
    c.tags = get(col("tags"))
        .map(|t| t.split(';').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();
    c.notes = get(col("notes")).unwrap_or_default();
    Ok(c)
}

/// RFC 4180 records: quoted fields may hold commas, doubled quotes and line breaks. Returns
/// each record with the 1-based line it started on. Stray or unterminated quotes are errors.
fn csv_records(text: &str) -> Result<Vec<(usize, Vec<String>)>> {
    let (mut out, mut fields, mut cur) = (Vec::new(), Vec::new(), String::new());
    let (mut quoted, mut after_quote, mut line, mut start) = (false, false, 1usize, 1usize);
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if quoted {
            match ch {
                '"' if chars.peek() == Some(&'"') => {
                    cur.push('"');
                    chars.next();
                }
                '"' => (quoted, after_quote) = (false, true),
                '\n' => {
                    line += 1;
                    cur.push(ch);
                }
                _ => cur.push(ch),
            }
            continue;
        }
        match ch {
            ',' => {
                fields.push(std::mem::take(&mut cur));
                after_quote = false;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                fields.push(std::mem::take(&mut cur));
                out.push((start, std::mem::take(&mut fields)));
                after_quote = false;
                line += 1;
                start = line;
            }
            '"' if cur.trim().is_empty() && !after_quote => {
                cur.clear();
                quoted = true;
            }
            '"' => return Err(CoreError::Invalid(format!("line {line}: unexpected quote in CSV field"))),
            c if after_quote && !c.is_whitespace() => {
                return Err(CoreError::Invalid(format!("line {line}: text after closing quote")));
            }
            _ if after_quote => {}
            _ => cur.push(ch),
        }
    }
    if quoted {
        return Err(CoreError::Invalid(format!("line {start}: unterminated quoted CSV field")));
    }
    if !cur.is_empty() || !fields.is_empty() {
        fields.push(cur);
        out.push((start, fields));
    }
    Ok(out)
}

/// Parse a Microsoft `.rdp` file (`key:type:value` lines).
pub fn rdp_file(name: &str, text: &str) -> Result<Connection> {
    let mut c = Connection::new(name, Protocol::Rdp, "");
    for line in text.lines() {
        let mut parts = line.trim().trim_start_matches('\u{feff}').splitn(3, ':');
        let (Some(k), Some(_ty), Some(v)) = (parts.next(), parts.next(), parts.next()) else { continue };
        match k.to_lowercase().as_str() {
            "full address" => match v.rsplit_once(':') {
                Some((h, p)) if p.parse::<u16>().is_ok() => {
                    c.host = h.into();
                    c.settings.port = p.parse().ok();
                }
                _ => c.host = v.into(),
            },
            "username" => c.settings.username = Some(v.into()),
            "gatewayhostname" => {
                c.metadata.insert("RDGateway".into(), v.into());
            }
            _ => {}
        }
    }
    if c.host.is_empty() {
        return Err(CoreError::Invalid("no `full address` in .rdp file".into()));
    }
    Ok(c)
}

/// A connection found by a tree-shaped importer, with the folder path it sat in.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub path: Vec<String>,
    pub connection: Connection,
}

/// What an importer found, plus what it left out and why (secrets, unsupported types).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Imported {
    pub found: Vec<Found>,
    pub skipped: Vec<String>,
}

pub(crate) const MAX_TREE_DEPTH: usize = 32;

/// Decode an import file: UTF-8 (with or without BOM) or UTF-16LE/BE with a BOM, as
/// `reg export` and RDCMan write them.
pub fn decode_text(bytes: &[u8]) -> Result<String> {
    if bytes.len() > crate::export::MAX_IMPORT_BYTES {
        return Err(CoreError::Invalid("import file is too large".into()));
    }
    let utf16 = |le: bool| {
        // An odd byte count after the BOM is a truncated code unit: refuse it rather than drop it.
        if bytes.len() % 2 != 0 {
            return Err(CoreError::Invalid("the file is not valid UTF-16 (it ends in the middle of a character)".into()));
        }
        let units: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) }).collect();
        String::from_utf16(&units).map_err(|_| CoreError::Invalid("the file is not valid UTF-16".into()))
    };
    match bytes {
        [0xff, 0xfe, ..] => utf16(true),
        [0xfe, 0xff, ..] => utf16(false),
        _ => {
            let b = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
            String::from_utf8(b.to_vec()).map_err(|_| CoreError::Invalid("the file is not UTF-8 or UTF-16 text".into()))
        }
    }
}

/// PuTTY saved sessions from `reg export HKCU\Software\SimonTatham\PuTTY\Sessions`. SSH,
/// Telnet and serial sessions are imported; passwords are not stored by PuTTY.
pub fn putty_reg(text: &str) -> Result<Imported> {
    const KEY: &str = "\\software\\simontatham\\putty\\sessions\\";
    let mut out = Imported::default();
    let mut sections: Vec<(String, BTreeMap<String, String>)> = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let lower = section.to_lowercase();
            sections.push((lower.find(KEY).map(|i| percent_decode(&section[i + KEY.len()..])).unwrap_or_default(), BTreeMap::new()));
        } else if let (Some((_, values)), Some((k, v))) = (sections.last_mut(), line.split_once('=')) {
            values.insert(k.trim_matches('"').to_lowercase(), v.to_string());
        }
    }
    if !text.contains("Windows Registry Editor") && !text.contains("REGEDIT4") {
        return Err(CoreError::Invalid("not a registry export (.reg)".into()));
    }
    for (name, v) in sections.into_iter().filter(|(n, _)| !n.is_empty() && !n.contains('\\')) {
        let s = |k: &str| v.get(k).and_then(|x| x.strip_prefix('"')).and_then(|x| x.strip_suffix('"')).map(|x| x.replace("\\\\", "\\")).filter(|x| !x.is_empty());
        let protocol = match s("protocol").as_deref().unwrap_or("ssh") {
            "ssh" => Protocol::Ssh,
            "telnet" => Protocol::Telnet,
            "serial" => Protocol::Serial,
            other => {
                out.skipped.push(format!("{name}: {other} sessions are not supported"));
                continue;
            }
        };
        let host = if protocol == Protocol::Serial { s("serialline") } else { s("hostname") };
        let Some(host) = host else {
            if name != "Default Settings" {
                out.skipped.push(format!("{name}: no host name"));
            }
            continue;
        };
        let mut c = Connection::new(&name, protocol, host);
        c.settings.port = v.get("portnumber").and_then(|p| p.strip_prefix("dword:")).and_then(|h| u32::from_str_radix(h, 16).ok()).and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0 && protocol != Protocol::Serial);
        c.settings.username = s("username");
        out.found.push(Found { path: vec![], connection: c });
    }
    Ok(out)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (b[i], b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Royal TS / Royal TSX "Royal JSON" (dynamic folder format): `{"Objects": [...]}` with
/// `Folder` objects nesting further `Objects`. Credential fields are never read.
pub fn royal_json(text: &str) -> Result<Imported> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| CoreError::Invalid(format!("not Royal JSON: {e}")))?;
    let objects = v.get("Objects").and_then(|o| o.as_array()).ok_or_else(|| CoreError::Invalid("not Royal JSON (no \"Objects\" list)".into()))?;
    let mut out = Imported::default();
    royal_objects(objects, &mut Vec::new(), &mut out)?;
    Ok(out)
}

fn royal_objects(objects: &[serde_json::Value], path: &mut Vec<String>, out: &mut Imported) -> Result<()> {
    if path.len() > MAX_TREE_DEPTH {
        return Err(CoreError::Invalid("folders are nested too deeply".into()));
    }
    for o in objects {
        let s = |k: &str| o.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty()).map(str::to_string);
        let name = s("Name").unwrap_or_else(|| "Unnamed".into());
        let kind = s("Type").unwrap_or_default();
        if kind == "Folder" {
            path.push(name);
            royal_objects(o.get("Objects").and_then(|x| x.as_array()).map(Vec::as_slice).unwrap_or(&[]), path, out)?;
            path.pop();
            continue;
        }
        let protocol = match kind.as_str() {
            "RemoteDesktopConnection" => Protocol::Rdp,
            "VNCConnection" => Protocol::Vnc,
            "WebConnection" => Protocol::Web,
            "FileTransferConnection" => Protocol::Sftp,
            "TerminalConnection" if s("TerminalConnectionType").map_or(true, |t| t.eq_ignore_ascii_case("ssh")) => Protocol::Ssh,
            "TerminalConnection" => Protocol::Telnet,
            other => {
                out.skipped.push(format!("{name}: {} objects are not supported", if other.is_empty() { "untyped" } else { other }));
                continue;
            }
        };
        let host = if protocol == Protocol::Web { s("URL").or_else(|| s("ComputerName")) } else { s("ComputerName") };
        let Some(host) = host else {
            out.skipped.push(format!("{name}: no computer name"));
            continue;
        };
        let mut c = Connection::new(&name, protocol, host);
        c.settings.port = o.get("Port").and_then(|p| p.as_u64().or_else(|| p.as_str().and_then(|x| x.parse().ok()))).and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0);
        c.settings.username = s("Username");
        // A credential by name only; the resolver finds it in the vault at connect time.
        c.settings.credential_name = s("CredentialName");
        c.notes = s("Notes").unwrap_or_default();
        c.tags = s("Tags").map(|t| t.split([',', ';']).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default();
        if s("Password").is_some() {
            out.skipped.push(format!("{name}: password not imported (use the vault)"));
        }
        let mut full = path.clone();
        full.extend(s("Path").map(|p| p.split(['/', '\\']).map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect::<Vec<_>>()).unwrap_or_default());
        out.found.push(Found { path: full, connection: c });
    }
    Ok(())
}

/// Microsoft Remote Desktop Connection Manager `.rdg` files (schema 1–3): groups become
/// folders, servers RDP connections. Passwords (encrypted to the exporting Windows user) and
/// gateway credentials are skipped.
pub fn rdcman(text: &str) -> Result<Imported> {
    if !text.contains("<RDCMan") {
        return Err(CoreError::Invalid("not an RDCMan file (no <RDCMan> element)".into()));
    }
    let mut out = Imported::default();
    // Element stack; each group/server frame collects its own fields.
    let mut stack: Vec<String> = Vec::new();
    let mut groups: Vec<Option<String>> = Vec::new();
    let mut server: Option<BTreeMap<&'static str, String>> = None;
    let mut rest = text;
    while let Some(lt) = rest.find('<') {
        let content = xml_unescape(rest[..lt].trim());
        let after = &rest[lt..];
        let end = if after.starts_with("<!--") { after.find("-->").map(|i| i + 3) } else { after.find('>').map(|i| i + 1) };
        let Some(end) = end else { return Err(CoreError::Invalid("unterminated tag".into())) };
        let tag = &after[1..end - 1];
        rest = &after[end..];
        if tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        if let Some(name) = tag.strip_prefix('/') {
            let name = name.trim();
            let parent = stack.len().checked_sub(2).map(|i| stack[i].as_str());
            let grand = stack.len().checked_sub(3).map(|i| stack[i].as_str());
            if !content.is_empty() {
                let field = match (name, parent, grand) {
                    ("name", Some("properties"), Some("server")) | ("name", Some("server"), _) => Some("host"),
                    ("displayName", Some("properties"), Some("server")) | ("displayName", Some("server"), _) => Some("display"),
                    ("userName", Some("logonCredentials"), _) => Some("user"),
                    ("port", Some("connectionSettings"), _) => Some("port"),
                    ("name", Some("properties"), Some("group")) => {
                        if let Some(g) = groups.last_mut() {
                            *g = Some(content.clone());
                        }
                        None
                    }
                    ("password", ..) => {
                        if let Some(srv) = server.as_mut() {
                            srv.insert("password", String::new());
                        }
                        None
                    }
                    _ => None,
                };
                if let (Some(f), Some(srv)) = (field, server.as_mut()) {
                    srv.entry(f).or_insert(content);
                }
            }
            match stack.pop().as_deref() {
                Some("group") => {
                    groups.pop();
                }
                Some("server") => {
                    if let Some(srv) = server.take() {
                        rdcman_server(srv, &groups, &mut out);
                    }
                }
                _ => {}
            }
            continue;
        }
        let self_closing = tag.ends_with('/');
        let name = tag.trim_end_matches('/').split_whitespace().next().unwrap_or("").to_string();
        if self_closing {
            continue;
        }
        if stack.len() >= MAX_TREE_DEPTH * 4 {
            return Err(CoreError::Invalid("elements are nested too deeply".into()));
        }
        match name.as_str() {
            "group" => groups.push(None),
            "server" => server = Some(BTreeMap::new()),
            _ => {}
        }
        stack.push(name);
    }
    Ok(out)
}

fn rdcman_server(srv: BTreeMap<&'static str, String>, groups: &[Option<String>], out: &mut Imported) {
    let Some(host) = srv.get("host").cloned() else {
        out.skipped.push("a server without a name".into());
        return;
    };
    let name = srv.get("display").cloned().unwrap_or_else(|| host.clone());
    if srv.contains_key("password") {
        out.skipped.push(format!("{name}: password not imported (use the vault)"));
    }
    let mut c = Connection::new(&name, Protocol::Rdp, host);
    c.settings.port = srv.get("port").and_then(|p| p.parse().ok()).filter(|p| *p != 0 && *p != 3389);
    c.settings.username = srv.get("user").cloned();
    out.found.push(Found { path: groups.iter().map(|g| g.clone().unwrap_or_else(|| "Group".into())).collect(), connection: c });
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// Build a folder named `name` holding the found connections in their sub-folders.
pub fn into_folder(name: &str, found: Vec<Found>) -> crate::model::Folder {
    use crate::model::{Folder, Node};
    fn new_folder(name: &str) -> Folder {
        Folder { id: uuid::Uuid::new_v4(), name: name.into(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() }
    }
    let mut root = new_folder(name);
    for f in found {
        let mut at = &mut root;
        for seg in f.path {
            let pos = at.children.iter().position(|n| matches!(n, Node::Folder(x) if x.name == seg));
            let pos = pos.unwrap_or_else(|| {
                at.children.push(Node::Folder(new_folder(&seg)));
                at.children.len() - 1
            });
            let Node::Folder(next) = &mut at.children[pos] else { unreachable!() };
            at = next;
        }
        at.children.push(Node::Connection(f.connection));
    }
    root
}

/// Add an imported folder to `doc`, merging into an existing top-level folder of the same name
/// so importing the same file again does not duplicate hosts. Subfolders merge by name;
/// a connection already present (same name, protocol, host, port and username) is skipped.
/// Returns the id of the folder that now holds the import and how many connections were added.
pub fn merge_import(doc: &mut crate::model::Document, mut folder: crate::model::Folder) -> (uuid::Uuid, usize) {
    use crate::model::Node;
    // Whatever the file says about logins is not yet the user's choice (A1-CORE-01-FU1).
    crate::logins::mark_received(&mut folder);
    // No importer may create a dynamic folder (B15, C9).
    crate::dynfolder::strip(&mut folder);
    let existing = doc.root.children.iter_mut().find_map(|n| match n {
        Node::Folder(f) if f.name == folder.name => Some(f),
        _ => None,
    });
    match existing {
        Some(target) => {
            let id = target.id;
            (id, merge_folder(target, folder))
        }
        None => {
            let (id, added) = (folder.id, count_connections(&folder));
            doc.root.children.push(Node::Folder(folder));
            (id, added)
        }
    }
}

fn connection_key(c: &Connection) -> (String, Protocol, String, Option<u16>, Option<String>) {
    (c.name.clone(), c.protocol, c.host.to_lowercase(), c.settings.port, c.settings.username.clone())
}

fn count_connections(f: &crate::model::Folder) -> usize {
    use crate::model::Node;
    f.children.iter().map(|n| match n {
        Node::Folder(sub) => count_connections(sub),
        Node::Connection(_) => 1,
    }).sum()
}

fn merge_folder(target: &mut crate::model::Folder, incoming: crate::model::Folder) -> usize {
    use crate::model::Node;
    let mut added = 0;
    for node in incoming.children {
        match node {
            Node::Connection(c) => {
                let key = connection_key(&c);
                let dup = target.children.iter().any(|n| matches!(n, Node::Connection(e) if connection_key(e) == key));
                if !dup {
                    target.children.push(Node::Connection(c));
                    added += 1;
                }
            }
            Node::Folder(sub) => {
                let pos = target.children.iter().position(|n| matches!(n, Node::Folder(f) if f.name == sub.name));
                match pos.and_then(|i| match &mut target.children[i] { Node::Folder(f) => Some(f), _ => None }) {
                    Some(t) => added += merge_folder(t, sub),
                    None => {
                        added += count_connections(&sub);
                        target.children.push(Node::Folder(sub));
                    }
                }
            }
        }
    }
    added
}
