//! Saved tunnels (the Tunnel Manager): named port forwards on a library connection that can be
//! started without opening a terminal. They are personal, so they live in their own file next to
//! the library (`tunnels.json`) and hold only a connection id, ports and destination names: no
//! hosts' credentials or secrets. Running them is `tunnel` / `SshSession::remote_forward`.
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::store::write_atomic;

const MAX_NAME: usize = 120;
const MAX_HOST: usize = 253;
pub const MAX_TUNNELS: usize = 256;

/// What a saved tunnel forwards. Listeners always bind loopback (`127.0.0.1`), on this computer
/// for local and SOCKS forwards and on the server for remote ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum TunnelSpec {
    /// `ssh -L 127.0.0.1:bind_port:dest_host:dest_port`
    Local { bind_port: u16, dest_host: String, dest_port: u16 },
    /// `ssh -R 127.0.0.1:remote_port:local_host:local_port`
    Remote { remote_port: u16, local_host: String, local_port: u16 },
    /// `ssh -D 127.0.0.1:bind_port`
    Socks { bind_port: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelDef {
    pub id: Uuid,
    pub name: String,
    /// The library connection whose SSH session carries the tunnel.
    pub connection: Uuid,
    pub spec: TunnelSpec,
    /// Start when the app starts.
    #[serde(default)]
    pub auto_start: bool,
}

impl TunnelDef {
    pub fn new(name: &str, connection: Uuid, spec: TunnelSpec) -> Result<Self> {
        let def = TunnelDef { id: Uuid::new_v4(), name: name.trim().to_string(), connection, spec, auto_start: false };
        def.validate()?;
        Ok(def)
    }

    /// Names and ports a saved tunnel may hold. Saved listeners need a fixed port (0 would pick a
    /// different one each start, which nothing could rely on).
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() || self.name.chars().count() > MAX_NAME {
            return Err(CoreError::Invalid(format!("tunnel name must be 1–{MAX_NAME} characters")));
        }
        match &self.spec {
            TunnelSpec::Local { bind_port, dest_host, dest_port } => {
                port(*bind_port, "local port")?;
                host(dest_host)?;
                port(*dest_port, "destination port")
            }
            TunnelSpec::Remote { remote_port, local_host, local_port } => {
                port(*remote_port, "server port")?;
                host(local_host)?;
                port(*local_port, "local port")
            }
            TunnelSpec::Socks { bind_port } => port(*bind_port, "local port"),
        }
    }

    /// The `ssh` option this tunnel corresponds to, for lists.
    pub fn summary(&self) -> String {
        match &self.spec {
            TunnelSpec::Local { bind_port, dest_host, dest_port } => format!("-L 127.0.0.1:{bind_port}:{dest_host}:{dest_port}"),
            TunnelSpec::Remote { remote_port, local_host, local_port } => format!("-R 127.0.0.1:{remote_port}:{local_host}:{local_port}"),
            TunnelSpec::Socks { bind_port } => format!("-D 127.0.0.1:{bind_port}"),
        }
    }
}

fn port(p: u16, label: &str) -> Result<()> {
    if p == 0 {
        return Err(CoreError::Invalid(format!("{label} must be 1–65535")));
    }
    Ok(())
}

/// A destination name: DNS characters or an IP literal, never something an option parser could
/// read as a flag.
fn host(h: &str) -> Result<()> {
    let ok = !h.is_empty() && h.len() <= MAX_HOST && !h.starts_with('-') && h.chars().all(|c| c.is_ascii_alphanumeric() || ".-_:".contains(c));
    if !ok {
        return Err(CoreError::Invalid(format!("`{h}` is not a valid host name")));
    }
    Ok(())
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    tunnels: Vec<TunnelDef>,
}

/// The per-user saved tunnels on disk.
pub struct TunnelRegistry {
    path: PathBuf,
    tunnels: Vec<TunnelDef>,
}

impl TunnelRegistry {
    /// Open `path`, treating a missing file as empty. Entries that fail validation (an edited
    /// file) make the whole file corrupt rather than being dropped silently.
    pub fn open(path: &Path) -> Result<Self> {
        let tunnels = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<File>(&bytes).map_err(|e| CoreError::Corrupt(e.to_string()))?.tunnels,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        for t in &tunnels {
            t.validate().map_err(|e| CoreError::Corrupt(format!("tunnel `{}`: {e}", t.name)))?;
        }
        Ok(TunnelRegistry { path: path.to_path_buf(), tunnels })
    }

    pub fn list(&self) -> &[TunnelDef] {
        &self.tunnels
    }

    pub fn get(&self, id: &Uuid) -> Option<&TunnelDef> {
        self.tunnels.iter().find(|t| &t.id == id)
    }

    /// Insert or replace (by id) and persist.
    pub fn save(&mut self, def: TunnelDef) -> Result<()> {
        def.validate()?;
        let exists = self.tunnels.iter().any(|t| t.id == def.id);
        if !exists && self.tunnels.len() >= MAX_TUNNELS {
            return Err(CoreError::Invalid(format!("at most {MAX_TUNNELS} saved tunnels")));
        }
        let mut next: Vec<TunnelDef> = self.tunnels.iter().filter(|t| t.id != def.id).cloned().collect();
        next.push(def);
        self.persist(next)
    }

    pub fn remove(&mut self, id: &Uuid) -> Result<()> {
        if self.get(id).is_none() {
            return Err(CoreError::NotFound(format!("tunnel {id}")));
        }
        let next = self.tunnels.iter().filter(|t| &t.id != id).cloned().collect();
        self.persist(next)
    }

    /// Saved tunnels whose connection is gone from the library, for the UI to flag.
    pub fn orphaned(&self, exists: impl Fn(&Uuid) -> bool) -> Vec<Uuid> {
        self.tunnels.iter().filter(|t| !exists(&t.connection)).map(|t| t.id).collect()
    }

    fn persist(&mut self, tunnels: Vec<TunnelDef>) -> Result<()> {
        let file = File { tunnels };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| CoreError::Corrupt(e.to_string()))?;
        write_atomic(&self.path, &bytes)?;
        self.tunnels = file.tunnels;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> TunnelSpec {
        TunnelSpec::Local { bind_port: 15432, dest_host: "db.internal".into(), dest_port: 5432 }
    }

    #[test]
    fn saved_tunnels_survive_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tunnels.json");
        let conn = Uuid::new_v4();
        let mut reg = TunnelRegistry::open(&path).unwrap();
        assert!(reg.list().is_empty());
        let def = TunnelDef::new("db", conn, local()).unwrap();
        reg.save(def.clone()).unwrap();
        reg.save(TunnelDef::new("proxy", conn, TunnelSpec::Socks { bind_port: 1080 }).unwrap()).unwrap();
        let again = TunnelRegistry::open(&path).unwrap();
        assert_eq!(again.list().len(), 2);
        assert_eq!(again.get(&def.id), Some(&def));
    }

    #[test]
    fn save_replaces_by_id_and_remove_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = TunnelRegistry::open(&dir.path().join("t.json")).unwrap();
        let mut def = TunnelDef::new("db", Uuid::new_v4(), local()).unwrap();
        reg.save(def.clone()).unwrap();
        def.auto_start = true;
        reg.save(def.clone()).unwrap();
        assert_eq!(reg.list(), &[def.clone()]);
        reg.remove(&def.id).unwrap();
        assert!(reg.list().is_empty());
        assert!(matches!(reg.remove(&def.id), Err(CoreError::NotFound(_))));
    }

    #[test]
    fn invalid_definitions_are_refused() {
        let c = Uuid::new_v4();
        assert!(TunnelDef::new(" ", c, local()).is_err());
        assert!(TunnelDef::new("x", c, TunnelSpec::Socks { bind_port: 0 }).is_err());
        assert!(TunnelDef::new("x", c, TunnelSpec::Local { bind_port: 1, dest_host: "-oProxyCommand=x".into(), dest_port: 1 }).is_err());
        assert!(TunnelDef::new("x", c, TunnelSpec::Remote { remote_port: 9000, local_host: "a b".into(), local_port: 22 }).is_err());
    }

    #[test]
    fn a_hand_edited_invalid_entry_makes_the_file_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.json");
        let bad = format!(r#"{{"tunnels":[{{"id":"{}","name":"x","connection":"{}","spec":{{"kind":"socks","bindPort":0}}}}]}}"#, Uuid::new_v4(), Uuid::new_v4());
        fs::write(&path, bad).unwrap();
        assert!(matches!(TunnelRegistry::open(&path), Err(CoreError::Corrupt(_))));
    }

    #[test]
    fn summary_matches_the_ssh_option() {
        let def = TunnelDef::new("db", Uuid::new_v4(), local()).unwrap();
        assert_eq!(def.summary(), "-L 127.0.0.1:15432:db.internal:5432");
    }

    #[test]
    fn orphaned_lists_tunnels_whose_connection_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = TunnelRegistry::open(&dir.path().join("t.json")).unwrap();
        let (kept, gone) = (Uuid::new_v4(), Uuid::new_v4());
        reg.save(TunnelDef::new("a", kept, local()).unwrap()).unwrap();
        let orphan = TunnelDef::new("b", gone, local()).unwrap();
        reg.save(orphan.clone()).unwrap();
        assert_eq!(reg.orphaned(|c| *c == kept), vec![orphan.id]);
    }
}
