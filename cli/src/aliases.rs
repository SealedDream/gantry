//! Opt-in shell shortcuts (`sshp`, `rdpp`, `vncp`, `tun`): symlinks to this binary in a folder the
//! user chooses (on Windows `name.exe` hard links, or copies when the folder is on another volume,
//! since symlinks need Developer Mode there), recorded in `cli-aliases.json` next to the library so `uninstall` removes exactly
//! what was made. A name that is already a command on `PATH` is refused: aliases never shadow or
//! intercept a shell command (no shell rc file is touched either).
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// What an alias opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Ssh,
    Rdp,
    Vnc,
    Tunnel,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        Some(match s {
            "ssh" => Role::Ssh,
            "rdp" => Role::Rdp,
            "vnc" => Role::Vnc,
            "tunnel" | "tun" => Role::Tunnel,
            _ => return None,
        })
    }

    pub fn protocol(self) -> Option<&'static str> {
        match self {
            Role::Ssh => Some("ssh"),
            Role::Rdp => Some("rdp"),
            Role::Vnc => Some("vnc"),
            Role::Tunnel => None,
        }
    }
}

pub const DEFAULTS: &[(&str, Role)] = &[("sshp", Role::Ssh), ("rdpp", Role::Rdp), ("vncp", Role::Vnc), ("tun", Role::Tunnel)];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alias {
    pub name: String,
    pub role: Role,
    pub path: PathBuf,
    /// Windows: SHA-256 of the file made, so `uninstall` removes only an unchanged alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub aliases: Vec<Alias>,
}

pub fn manifest_path(data_dir: &Path) -> PathBuf {
    data_dir.join("cli-aliases.json")
}

pub fn load(data_dir: &Path) -> Result<Manifest, String> {
    match std::fs::read(manifest_path(data_dir)) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("cli-aliases.json: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Manifest::default()),
        Err(e) => Err(e.to_string()),
    }
}

fn save(data_dir: &Path, m: &Manifest) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(m).map_err(|e| e.to_string())?;
    bastion_core::store::write_atomic(&manifest_path(data_dir), &bytes).map_err(|e| e.to_string())
}

/// A valid alias name: a short word that cannot be read as a path or an option.
fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 32 && !n.starts_with('-') && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Executable suffixes a shell tries for a bare command name (Windows PATHEXT; none on Unix).
fn command_suffixes() -> Vec<String> {
    let mut out = vec![String::new()];
    if cfg!(windows) {
        let ext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        out.extend(ext.split(';').filter(|e| !e.is_empty()).map(|e| e.to_ascii_lowercase()));
    }
    out
}

/// Where `name` already resolves on `path_var`, ignoring `dir` (where the alias would go).
fn existing_command(name: &str, path_var: &str, dir: &Path) -> Option<PathBuf> {
    let suffixes = command_suffixes();
    std::env::split_paths(path_var)
        .filter(|p| p != dir)
        .flat_map(|p| suffixes.iter().map(move |s| p.join(format!("{name}{s}"))))
        .find(|p| p.is_file())
}

/// The file an alias named `name` lives in.
pub fn alias_file(dir: &Path, name: &str) -> PathBuf {
    if cfg!(windows) { dir.join(format!("{name}.exe")) } else { dir.join(name) }
}

fn digest(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    std::fs::read(path).ok().map(|b| hex::encode(Sha256::digest(&b)))
}

/// Whether `a` is still exactly what `install` made.
fn is_ours(a: &Alias) -> bool {
    if cfg!(windows) {
        return a.digest.is_some() && digest(&a.path) == a.digest;
    }
    std::fs::read_link(&a.path).ok().and_then(|t| t.file_name().map(|f| f.to_string_lossy().starts_with("bastion"))).unwrap_or(false)
}

/// Install `wanted` (name → role) as symlinks to `exe` in `dir`.
pub fn install(data_dir: &Path, dir: &Path, exe: &Path, wanted: &[(String, Role)], path_var: &str) -> Result<Vec<Alias>, String> {
    let mut m = load(data_dir)?;
    let mut made = Vec::new();
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for (name, role) in wanted {
        if !valid_name(name) {
            return Err(format!("`{name}` is not a usable command name"));
        }
        if let Some(other) = existing_command(name, path_var, dir) {
            return Err(format!("`{name}` is already a command ({}); choose another name, Bastion never shadows shell commands", other.display()));
        }
        let link = alias_file(dir, name);
        if link.symlink_metadata().is_ok() {
            let ours = m.aliases.iter().any(|a| a.path == link && is_ours(a));
            if !ours {
                return Err(format!("{} already exists and was not made by Bastion", link.display()));
            }
            std::fs::remove_file(&link).map_err(|e| e.to_string())?;
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(exe, &link).map_err(|e| format!("{}: {e}", link.display()))?;
        #[cfg(not(unix))]
        if std::fs::hard_link(exe, &link).is_err() {
            std::fs::copy(exe, &link).map_err(|e| format!("{}: {e}", link.display()))?;
        }
        let made_digest = if cfg!(windows) { digest(&link) } else { None };
        m.aliases.retain(|a| a.name != *name);
        let a = Alias { name: name.clone(), role: *role, path: link, digest: made_digest };
        m.aliases.push(a.clone());
        made.push(a);
    }
    save(data_dir, &m)?;
    Ok(made)
}

/// Remove every alias in the manifest that is still a symlink to a `bastion` binary; anything
/// else at that path (the user replaced it) is left alone and reported.
pub fn uninstall(data_dir: &Path) -> Result<(Vec<PathBuf>, Vec<PathBuf>), String> {
    let m = load(data_dir)?;
    let (mut removed, mut kept) = (Vec::new(), Vec::new());
    for a in &m.aliases {
        if is_ours(a) {
            std::fs::remove_file(&a.path).map_err(|e| e.to_string())?;
            removed.push(a.path.clone());
        } else if a.path.symlink_metadata().is_ok() {
            kept.push(a.path.clone());
        }
    }
    save(data_dir, &Manifest::default())?;
    Ok((removed, kept))
}

/// The role of the program name `argv0` (an installed alias), if any.
pub fn role_for(data_dir: &Path, argv0: &str) -> Option<Role> {
    // Windows runs `sshp.exe` for `sshp` and does not care about case.
    let (name, fold) = if cfg!(windows) { (Path::new(argv0).file_stem()?.to_str()?, true) } else { (Path::new(argv0).file_name()?.to_str()?, false) };
    load(data_dir).ok()?.aliases.into_iter().find(|a| if fold { a.name.eq_ignore_ascii_case(name) } else { a.name == name }).map(|a| a.role)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_refuses_shadowing_and_uninstall_removes_only_ours() {
        let root = tempfile::tempdir().unwrap();
        let (data, bin, other) = (root.path().join("data"), root.path().join("bin"), root.path().join("other"));
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("ssh"), "#!/bin/sh\n").unwrap();
        let exe = root.path().join("bastion");
        std::fs::write(&exe, "binary").unwrap();
        let path_var = std::env::join_paths([other.clone(), bin.clone()]).unwrap().into_string().unwrap();
        let err = install(&data, &bin, &exe, &[("ssh".into(), Role::Ssh)], &path_var).unwrap_err();
        assert!(err.contains("never shadows"), "{err}");
        assert!(install(&data, &bin, &exe, &[("../x".into(), Role::Ssh)], &path_var).is_err());
        let made = install(&data, &bin, &exe, &[("sshp".into(), Role::Ssh), ("tun".into(), Role::Tunnel)], &path_var).unwrap();
        assert_eq!(made.len(), 2);
        assert_eq!(role_for(&data, "/some/where/sshp"), Some(Role::Ssh));
        if cfg!(windows) {
            assert_eq!(role_for(&data, r"C:\bin\SSHP.EXE"), Some(Role::Ssh));
            // A shadowing check that knows PATHEXT: `ssh.exe` blocks `ssh` too.
            std::fs::write(other.join("rdpp.exe"), "").unwrap();
            assert!(install(&data, &bin, &exe, &[("rdpp".into(), Role::Rdp)], &path_var).unwrap_err().contains("never shadows"));
        }
        assert_eq!(role_for(&data, "tun"), Some(Role::Tunnel));
        assert_eq!(role_for(&data, "bastion"), None);
        // Reinstalling our own alias is fine; a foreign file is not replaced.
        install(&data, &bin, &exe, &[("sshp".into(), Role::Ssh)], &path_var).unwrap();
        std::fs::write(alias_file(&bin, "vncp"), "user's own").unwrap();
        assert!(install(&data, &bin, &exe, &[("vncp".into(), Role::Vnc)], &path_var).unwrap_err().contains("not made by Bastion"));
        let (removed, kept) = uninstall(&data).unwrap();
        assert_eq!(removed.len(), 2);
        assert!(kept.is_empty());
        assert!(!alias_file(&bin, "sshp").exists() && alias_file(&bin, "vncp").exists());
        assert_eq!(role_for(&data, "sshp"), None);
    }
}
