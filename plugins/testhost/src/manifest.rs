//! The part of `plugin.toml` the test host needs: the permissions. The full manifest check is
//! the core's (`core/src/plugin/manifest.rs`).

/// What the manifest grants.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Permissions {
    pub network: bool,
    pub credentials: bool,
    pub storage: bool,
    pub clipboard: bool,
    pub files_save: bool,
    pub files_open: bool,
    /// `http = "entry"` (API 1.1).
    pub http: bool,
    /// `open` lists these (API 1.2).
    pub open_ssh: bool,
    pub open_rdp: bool,
    pub open_vnc: bool,
    /// `exec = "entry"` (API 1.5).
    pub exec: bool,
    /// `library = "propose"` (API 1.6).
    pub library: bool,
}

impl Permissions {
    /// Every permission, for tests that are not about permissions.
    pub fn all() -> Permissions {
        Permissions { network: true, credentials: true, storage: true, clipboard: true, files_save: true, files_open: true, http: true, open_ssh: true, open_rdp: true, open_vnc: true, exec: true, library: true }
    }

    /// Reads `[permissions]` from a manifest. Unknown keys and values are refused.
    pub fn from_manifest(text: &str) -> Result<Permissions, String> {
        let table: toml::Table = text.parse().map_err(|e| format!("plugin.toml: {e}"))?;
        let mut p = Permissions::default();
        let Some(perms) = table.get("permissions") else { return Ok(p) };
        let perms = perms.as_table().ok_or("plugin.toml: [permissions] is not a table")?;
        for (key, value) in perms {
            match (key.as_str(), value) {
                ("network", toml::Value::String(v)) if v == "entry" => p.network = true,
                ("credentials", toml::Value::String(v)) if v == "entry" => p.credentials = true,
                ("storage", toml::Value::Boolean(v)) => p.storage = *v,
                ("clipboard", toml::Value::String(v)) if v == "write" => p.clipboard = true,
                ("http", toml::Value::String(v)) if v == "entry" => p.http = true,
                ("exec", toml::Value::String(v)) if v == "entry" => p.exec = true,
                ("library", toml::Value::String(v)) if v == "propose" => p.library = true,
                ("open", toml::Value::Array(items)) if !items.is_empty() => {
                    for item in items {
                        match item.as_str() {
                            Some("ssh") => p.open_ssh = true,
                            Some("rdp") => p.open_rdp = true,
                            Some("vnc") => p.open_vnc = true,
                            _ => return Err("plugin.toml: open takes \"ssh\", \"rdp\" and \"vnc\"".into()),
                        }
                    }
                }
                ("files", toml::Value::Array(items)) => {
                    for item in items {
                        match item.as_str() {
                            Some("save") => p.files_save = true,
                            Some("open") => p.files_open = true,
                            _ => return Err("plugin.toml: files takes \"save\" and \"open\"".into()),
                        }
                    }
                }
                _ => return Err(format!("plugin.toml: unknown permission or value `{key}`")),
            }
        }
        Ok(p)
    }

    /// Whether the `bastion:plugin` interface `name` (without version) may be imported.
    pub fn allows(&self, interface: &str) -> bool {
        match interface {
            "types" | "host" | "log" | "ui" | "events" => true,
            "net" => self.network,
            "credentials" => self.credentials,
            "storage" => self.storage,
            "clipboard" => self.clipboard,
            "files" => self.files_save || self.files_open,
            "http" => self.http,
            "open" => self.open_ssh || self.open_rdp || self.open_vnc,
            "exec" => self.exec,
            "library" => self.library,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_permissions() {
        let p = Permissions::from_manifest(
            "[permissions]\nnetwork = \"entry\"\nstorage = true\nfiles = [\"save\"]\n",
        )
        .unwrap();
        assert_eq!(p, Permissions { network: true, storage: true, files_save: true, ..Default::default() });
        assert!(p.allows("net") && p.allows("files") && !p.allows("credentials") && !p.allows("clipboard"));
    }

    #[test]
    fn no_permissions_table_grants_nothing() {
        assert_eq!(Permissions::from_manifest("schema = 1\n").unwrap(), Permissions::default());
    }

    #[test]
    fn unknown_permission_is_refused() {
        assert!(Permissions::from_manifest("[permissions]\nshell = true\n").is_err());
        assert!(Permissions::from_manifest("[permissions]\nnetwork = \"any\"\n").is_err());
    }
}
