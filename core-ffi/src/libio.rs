//! Library data in and out, plus the small text tools, all through the core: importing CSV,
//! `.rdp`, PuTTY `.reg`, Royal JSON, RDCMan `.rdg`, mRemoteNG `.xml` and Bastion exports (`core::import`,
//! `core::export`); the secret-free `bastion-export` v1 file (previewed first, since
//! `policy::Action::ExportConfiguration` needs confirmation); the vault's password generator;
//! and `$Variable$` substitution for text sent to a terminal (`core::vars`).
use std::collections::BTreeSet;
use std::path::Path;

use bastion_core::export::{self, Selection};
use bastion_core::import::{self, Found, Imported};
use bastion_core::model::{Connection, Folder, Node};
use bastion_core::vars::Variables;
use bastion_core::CoreError;
use uuid::Uuid;

use crate::{parse_id, FfiError, FfiResult, Library};

const MAX_SELECTION: usize = 10_000;
const MAX_TEMPLATE: usize = 4096;
const MIN_GENERATED: u32 = 12;
const MAX_GENERATED: u32 = 128;
/// Secret variables: listed by name only and refused by the core's leak guard, because this app
/// never authorises secrets in sent text (their values are never loaded).
const SECRET_NAMES: &[&str] = &["Password", "Passphrase"];

fn failed(message: impl Into<String>) -> FfiError {
    FfiError::failed(message.into())
}

#[derive(uniffi::Record)]
pub struct ImportResultView {
    /// Id of the new top-level folder holding the import.
    pub folder: String,
    pub format: String,
    pub connections: u32,
    /// What the importer left out and why (secrets, unsupported types).
    pub skipped: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct ExportPreviewView {
    pub folders: u32,
    pub connections: u32,
    pub credential_refs: u32,
    pub stripped_fields: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct SshConfigExportView {
    pub exported: u32,
    /// `name: reason` for each connection left out (not SSH, or unsafe in ssh_config).
    pub skipped: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct VariableView {
    pub name: String,
    pub value: String,
}

#[derive(uniffi::Record)]
pub struct VariablesView {
    pub plain: Vec<VariableView>,
    pub secret: Vec<String>,
}

/// Give every node a new id so an import never collides with connections already in the library.
fn fresh_ids(f: &mut Folder) {
    f.id = Uuid::new_v4();
    for n in &mut f.children {
        match n {
            Node::Folder(sub) => fresh_ids(sub),
            Node::Connection(c) => c.id = Uuid::new_v4(),
        }
    }
}

fn count(f: &Folder) -> usize {
    f.children.iter().map(|n| match n {
        Node::Folder(sub) => count(sub),
        Node::Connection(_) => 1,
    }).sum()
}

/// Parse an import file by extension into a folder named `Imported <stem>`.
fn parse(ext: &str, stem: &str, text: &str) -> FfiResult<(&'static str, Folder, Vec<String>)> {
    let flat = |v: Vec<Connection>| Imported { found: v.into_iter().map(|connection| Found { path: vec![], connection }).collect(), skipped: vec![] };
    let name = format!("Imported {stem}");
    let (format, imported) = match ext {
        "csv" => ("CSV", flat(import::csv(text)?)),
        "rdp" => ("Remote Desktop file", flat(vec![import::rdp_file(stem, text)?])),
        "reg" => ("PuTTY sessions", import::putty_reg(text)?),
        "rdg" => ("RDCMan", import::rdcman(text)?),
        "xml" => ("mRemoteNG", bastion_core::import_mremoteng::mremoteng(text)?),
        "json" if text.contains(&format!("\"{}\"", export::FORMAT)) => {
            let doc = export::import(text.as_bytes())?;
            let mut root = Folder { name, ..doc.root };
            fresh_ids(&mut root);
            return Ok(("Gantry export", root, vec![]));
        }
        "json" => ("Royal JSON", import::royal_json(text)?),
        _ => return Err(failed("choose a .csv, .rdp, .reg (PuTTY), .json (Royal JSON or Gantry export) .rdg (RDCMan) or .xml (mRemoteNG) file")),
    };
    Ok((format, import::into_folder(&name, imported.found), imported.skipped))
}

pub(crate) fn selection(ids: Option<Vec<String>>) -> FfiResult<Selection> {
    match ids {
        None => Ok(Selection::All),
        Some(v) if v.len() > MAX_SELECTION => Err(failed("too many items selected")),
        Some(v) => Ok(Selection::Nodes(v.iter().map(|s| parse_id(s)).collect::<Result<BTreeSet<_>, _>>()?)),
    }
}

fn to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[uniffi::export]
impl Library {
    /// Import the file at `path` into a new top-level folder `Imported <file name>`. Nothing is
    /// added when the file holds no connections.
    pub fn import_file(&self, path: String) -> FfiResult<ImportResultView> {
        let path = Path::new(&path);
        let meta = std::fs::metadata(path).map_err(CoreError::from)?;
        if !meta.is_file() || meta.len() > export::MAX_IMPORT_BYTES as u64 {
            return Err(failed("choose a regular file under 64 MB"));
        }
        let text = import::decode_text(&std::fs::read(path).map_err(CoreError::from)?)?;
        let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("").to_ascii_lowercase();
        let stem: String = path.file_stem().and_then(|x| x.to_str()).unwrap_or("file").chars().filter(|c| !c.is_control()).take(80).collect();
        let (format, folder, skipped) = parse(&ext, &stem, &text)?;
        let connections = count(&folder);
        if connections == 0 {
            let why = if skipped.is_empty() { String::new() } else { format!(" ({})", skipped.join("; ")) };
            return Err(failed(format!("no connections found in this {format} file{why}")));
        }
        let (id, added) = self.with_doc(|d| Ok(import::merge_import(d, folder)))?;
        let mut skipped = skipped;
        if added < connections {
            skipped.push(format!("{} already in the library", connections - added));
        }
        Ok(ImportResultView { folder: id.to_string(), format: format.into(), connections: to_u32(added), skipped })
    }

    /// Write the SSH connections in `ids` (everything when `None`) to `path` as an OpenSSH
    /// `ssh_config` file (owner-only, atomic). Values that could inject directives are skipped.
    pub fn export_ssh_config(&self, path: String, ids: Option<Vec<String>>) -> FfiResult<SshConfigExportView> {
        let sel = selection(ids)?;
        let (text, skipped) = self.with_doc(|d| Ok(bastion_core::sshconfig_export::export_document(d, &sel)))?;
        let exported = text.lines().filter(|l| l.starts_with("Host ")).count();
        bastion_core::store::write_atomic(Path::new(&path), text.as_bytes())?;
        Ok(SshConfigExportView { exported: to_u32(exported), skipped: skipped.into_iter().map(|(n, r)| format!("{n}: {r}")).collect() })
    }

    /// Write the SSH connections in `ids` (everything when `None`) to `path` as an Ansible
    /// inventory (`yaml` picks YAML over INI; owner-only, atomic). Unsafe names/values are skipped.
    pub fn export_ansible_inventory(&self, path: String, ids: Option<Vec<String>>, yaml: bool) -> FfiResult<SshConfigExportView> {
        use bastion_core::ansible_inventory::{export_document_as, Format};
        let sel = selection(ids)?;
        let format = if yaml { Format::Yaml } else { Format::Ini };
        let (text, skipped) = self.with_doc(|d| Ok(export_document_as(d, &sel, format)))?;
        let exported = text.lines().filter(|l| if yaml { l.starts_with("        ") && !l.starts_with("          ") } else { !l.is_empty() && !l.starts_with(['#', '[']) }).count();
        bastion_core::store::write_atomic(Path::new(&path), text.as_bytes())?;
        Ok(SshConfigExportView { exported: to_u32(exported), skipped: skipped.into_iter().map(|(n, r)| format!("{n}: {r}")).collect() })
    }

    /// What an export of `ids` (everything when `None`) would contain; nothing is written.
    pub fn export_preview(&self, ids: Option<Vec<String>>) -> FfiResult<ExportPreviewView> {
        let sel = selection(ids)?;
        let p = self.with_doc(|d| Ok(export::preview(d, &sel)))?;
        Ok(ExportPreviewView {
            folders: to_u32(p.folders),
            connections: to_u32(p.connections),
            credential_refs: to_u32(p.credential_refs.len()),
            stripped_fields: p.stripped_fields,
        })
    }

    /// Write the confirmed, secret-free export to `path` (atomic, owner-only).
    pub fn export_to(&self, path: String, ids: Option<Vec<String>>) -> FfiResult<()> {
        let sel = selection(ids)?;
        let bytes = self.with_doc(|d| export::export(d, &sel))?;
        write_private(Path::new(&path), &bytes).map_err(CoreError::from)?;
        Ok(())
    }

    /// The variables text for connection `id` may use (secret ones by name only).
    pub fn variables(&self, id: String) -> FfiResult<VariablesView> {
        let plain = self.plain_variables(&id)?;
        Ok(VariablesView {
            plain: plain.into_iter().map(|(name, value)| VariableView { name, value }).collect(),
            secret: SECRET_NAMES.iter().map(|s| s.to_string()).collect(),
        })
    }

    /// Substitute `$Name$` variables in `template` for connection `id`; an unknown or secret
    /// variable is an error, and `$$` is a literal `$`.
    pub fn substitute(&self, id: String, template: String) -> FfiResult<String> {
        if template.len() > MAX_TEMPLATE {
            return Err(failed(format!("text is longer than {MAX_TEMPLATE} bytes")));
        }
        let mut vars = Variables::default();
        for (k, v) in self.plain_variables(&id)? {
            vars.set(&k, &v);
        }
        for k in SECRET_NAMES {
            vars.set_secret(k, "");
        }
        Ok(vars.substitute(&template, false)?)
    }
}

impl Library {
    fn plain_variables(&self, id: &str) -> FfiResult<Vec<(String, String)>> {
        let id = parse_id(id)?;
        let r = self.with_doc(|d| d.resolve(id))?;
        let c = &r.connection;
        let protocol = c.protocol.as_str().to_string();
        let mut plain = vec![
            ("Name".to_string(), c.name.clone()),
            ("Host".into(), c.host.clone()),
            ("Port".into(), r.effective.port.map(|p| p.to_string()).unwrap_or_default()),
            ("Username".into(), r.effective.username.clone().unwrap_or_default()),
            ("Protocol".into(), protocol),
            ("Folder".into(), r.path.join("/")),
        ];
        plain.extend(c.user_metadata().into_iter().map(|(k, v)| (format!("Meta.{}", k.replace(' ', "_")), v)));
        Ok(plain)
    }
}

/// Write `bytes` to `path` through a temporary file in the same directory, owner-only.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".{}.tmp", Uuid::new_v4()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        // Windows has no mode bits: replace the inherited ACL before any byte is written.
        #[cfg(windows)]
        bastion_core::winacl::restrict_path(&tmp, false)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// argv (program first) for an Ansible ad-hoc run against `inventory`; no shell is involved.
#[uniffi::export]
pub fn ansible_ad_hoc_argv(inventory: String, module: String, args: Option<String>, pattern: String) -> FfiResult<Vec<String>> {
    Ok(bastion_core::ansible_inventory::ad_hoc_argv(Path::new(&inventory), &module, args.as_deref(), &pattern)?)
}

/// argv (program first) for `ansible-playbook` against `inventory`; no shell is involved.
#[uniffi::export]
pub fn ansible_playbook_argv(inventory: String, playbook: String) -> FfiResult<Vec<String>> {
    Ok(bastion_core::ansible_inventory::playbook_argv(Path::new(&inventory), Path::new(&playbook))?)
}

/// A random password from the vault's generator, 12–128 characters.
#[uniffi::export]
pub fn generate_password(length: u32) -> FfiResult<String> {
    if !(MIN_GENERATED..=MAX_GENERATED).contains(&length) {
        return Err(failed(format!("Length must be {MIN_GENERATED}–{MAX_GENERATED} characters")));
    }
    Ok(bastion_core::vault::generate_password(length as usize).expose().to_string())
}

/// Rough strength estimate in bits, for the generator's indicator only.
#[uniffi::export]
pub fn password_strength_bits(password: String) -> f64 {
    bastion_core::vault::strength_bits(&password)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn library(dir: &tempfile::TempDir) -> Library {
        Library::open(dir.path().join("library.json").display().to_string()).unwrap()
    }

    #[test]
    fn imports_putty_sessions_and_refuses_unknown_types() {
        let dir = tempfile::tempdir().unwrap();
        let lib = library(&dir);
        let reg = dir.path().join("sessions.reg");
        std::fs::write(&reg, "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\web01]\r\n\"HostName\"=\"web01.example\"\r\n\"Protocol\"=\"ssh\"\r\n\"PortNumber\"=dword:00000016\r\n").unwrap();
        let r = lib.import_file(reg.display().to_string()).unwrap();
        assert_eq!((r.format.as_str(), r.connections), ("PuTTY sessions", 1));
        let bad = dir.path().join("x.txt");
        std::fs::write(&bad, "x").unwrap();
        assert!(lib.import_file(bad.display().to_string()).is_err());
    }

    #[test]
    fn export_round_trips_through_import() {
        let dir = tempfile::tempdir().unwrap();
        let lib = library(&dir);
        lib.add_connection(None, "db".into(), "ssh".into(), "db.example".into(), Some(22), Some("ops".into())).unwrap();
        assert_eq!(lib.export_preview(None).unwrap().connections, 1);
        let out = dir.path().join("lib.json");
        lib.export_to(out.display().to_string(), None).unwrap();
        let r = lib.import_file(out.display().to_string()).unwrap();
        assert_eq!((r.format.as_str(), r.connections), ("Gantry export", 1));
    }

    #[test]
    fn substitutes_plain_variables_and_refuses_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let lib = library(&dir);
        let id = lib.add_connection(None, "db".into(), "ssh".into(), "db.example".into(), Some(2222), Some("ops".into())).unwrap();
        assert_eq!(lib.substitute(id.clone(), "ssh $Username$@$Host$ -p $Port$ $$".into()).unwrap(), "ssh ops@db.example -p 2222 $");
        assert!(lib.substitute(id.clone(), "$Password$".into()).is_err());
        assert!(lib.substitute(id.clone(), "$Nope$".into()).is_err());
        assert!(lib.variables(id).unwrap().secret.contains(&"Password".to_string()));
    }

    #[test]
    fn generator_honours_length_bounds() {
        assert_eq!(generate_password(20).unwrap().chars().count(), 20);
        assert!(generate_password(4).is_err());
        assert!(password_strength_bits(generate_password(20).unwrap()) > 100.0);
    }
}
