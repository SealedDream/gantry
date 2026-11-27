//! Installing, updating, rolling back and removing plugins on disk (PLUG-04b, sections 6, 9
//! and 10).
//!
//! Layout, under the app's data folder:
//!
//! ```text
//! plugins/.lock                         held while a change is made (several running apps)
//! plugins/trust.json                    the stored catalogue state (trust.rs)
//! plugins/<id>/installed.json           the current version and the kept previous one
//! plugins/<id>/<version>.bastionplugin  the package exactly as verified, never unpacked
//! plugins/<id>/<version>.sig            its release record, when it had one
//! plugin-data/<id>/                     the plugin's own data, kept on remove unless asked
//! ```
//!
//! The package stays a single file: the core reads it into memory each time (section 6), and
//! [`load_installed`] checks it against the SHA-256 recorded at install, so a file changed on
//! disk is refused rather than run. Nothing here fetches or runs anything.
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::broker::audit::PluginAudit;
use super::error::{Excerpt, PluginError};
use super::imports::check_imports;
use super::manifest::{is_plugin_id, Version};
use super::package::{read_package, Package};
use super::record::{check_package_against_record, Tier, VerifiedRecord};
use super::trust::TrustState;
use crate::audit::{Category, Outcome};

const SCHEMA: u32 = 1;
const INSTALLED_FILE: &str = "installed.json";
const LOCK_FILE: &str = ".lock";

pub(super) fn io(e: impl std::fmt::Display) -> PluginError {
    PluginError::Io(Excerpt::new(e.to_string().as_bytes()))
}

/// Where plugins live under the app's data folder.
#[derive(Debug, Clone)]
pub struct PluginFolders {
    data_dir: PathBuf,
}

impl PluginFolders {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        PluginFolders { data_dir: data_dir.into() }
    }

    pub fn plugins_dir(&self) -> PathBuf {
        self.data_dir.join("plugins")
    }

    /// The stored catalogue state ([`TrustState`]).
    pub fn trust_path(&self) -> PathBuf {
        self.plugins_dir().join("trust.json")
    }

    /// One plugin's folder. The id is checked first, so it can never leave `plugins/`.
    fn plugin_dir(&self, id: &str) -> Result<PathBuf, PluginError> {
        if !is_plugin_id(id) {
            return Err(PluginError::NotInstalled(Excerpt::new(id.as_bytes())));
        }
        Ok(self.plugins_dir().join(id))
    }

    /// The plugin's own data folder.
    pub fn data_dir_of(&self, id: &str) -> Result<PathBuf, PluginError> {
        if !is_plugin_id(id) {
            return Err(PluginError::NotInstalled(Excerpt::new(id.as_bytes())));
        }
        Ok(self.data_dir.join("plugin-data").join(id))
    }
}

/// Held while the plugins folder changes: an OS advisory lock on `plugins/.lock` (`flock` on
/// Unix, `LockFileEx` on Windows). The file itself is never deleted; the OS releases the lock
/// when the handle closes, also when the app stops mid-change, so there is no stale-lock rule
/// and no takeover race. Two handles conflict even inside one process.
pub(super) struct FolderLock {
    _file: std::fs::File,
}

impl FolderLock {
    pub(super) fn acquire(folders: &PluginFolders) -> Result<FolderLock, PluginError> {
        let dir = folders.plugins_dir();
        std::fs::create_dir_all(&dir).map_err(io)?;
        let file = OpenOptions::new().write(true).create(true).truncate(false).open(dir.join(LOCK_FILE)).map_err(io)?;
        match file.try_lock() {
            Ok(()) => Ok(FolderLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(PluginError::FolderBusy),
            Err(std::fs::TryLockError::Error(e)) => Err(io(e)),
        }
    }
}

/// One installed version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledVersion {
    pub version: String,
    /// "official", "external" or "unverified": from the signatures at install, never the manifest.
    pub tier: String,
    /// SHA-256 of the package file, lower-case hex.
    pub sha256: String,
    pub size: u64,
}

impl InstalledVersion {
    pub fn tier(&self) -> Tier {
        tier_from(&self.tier)
    }
}

/// `plugins/<id>/installed.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installed {
    schema: u32,
    pub id: String,
    pub current: InstalledVersion,
    /// The version before the last update, kept for one rollback (section 9, Updates).
    pub previous: Option<InstalledVersion>,
}

fn tier_name(tier: Tier) -> &'static str {
    match tier {
        Tier::Official => "official",
        Tier::External => "external",
        Tier::Unverified => "unverified",
    }
}

/// An unknown name reads as Unverified, the least trusted tier.
fn tier_from(name: &str) -> Tier {
    match name {
        "official" => Tier::Official,
        "external" => Tier::External,
        _ => Tier::Unverified,
    }
}

fn package_name(version: &str) -> String {
    format!("{version}.bastionplugin")
}

fn sig_name(version: &str) -> String {
    format!("{version}.sig")
}

fn read_installed(dir: &Path) -> Result<Option<Installed>, PluginError> {
    let path = dir.join(INSTALLED_FILE);
    let bytes = match std::fs::read(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e)),
        Ok(bytes) => bytes,
    };
    let installed: Installed = serde_json::from_slice(&bytes).map_err(io)?;
    if installed.schema != SCHEMA {
        return Err(io("installed.json has an unknown schema"));
    }
    check_installed(dir, &installed)?;
    Ok(Some(installed))
}

/// A damaged or hand-edited `installed.json` is refused before any of its values names a file:
/// the id must be the folder's own, each version must parse (file names are built from them),
/// each tier and hash must be well formed.
fn check_installed(dir: &Path, installed: &Installed) -> Result<(), PluginError> {
    let folder = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let damaged = || PluginError::InstalledCopyChanged(Excerpt::new(folder.as_bytes()));
    if !is_plugin_id(&installed.id) || installed.id != folder {
        return Err(damaged());
    }
    for version in std::iter::once(&installed.current).chain(installed.previous.as_ref()) {
        let canonical = Version::parse(&version.version).map(|v| v.to_string());
        let hex_ok = version.sha256.len() == 64 && version.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if canonical.as_deref() != Some(version.version.as_str()) || !matches!(version.tier.as_str(), "official" | "external" | "unverified") || !hex_ok {
            return Err(damaged());
        }
    }
    Ok(())
}

/// Run [`accept_index`](super::trust::accept_index) on the stored state and save it, under the
/// folder lock, re-reading the state file first. This is the only way the state file is
/// written, so two running apps cannot overwrite a newer floor or revocation with an older one.
pub fn accept_and_store(folders: &PluginFolders, bytes: &[u8], keys: &super::sign::TrustedKeys, now: u64) -> Result<super::trust::IndexDecision, PluginError> {
    let _lock = FolderLock::acquire(folders)?;
    let mut state = TrustState::load(&folders.trust_path())?;
    let decision = super::trust::accept_index(&mut state, bytes, keys, now)?;
    if matches!(decision, super::trust::IndexDecision::Accepted { .. }) {
        state.save(&folders.trust_path())?;
    }
    Ok(decision)
}

fn write_installed(dir: &Path, installed: &Installed) -> Result<(), PluginError> {
    let bytes = serde_json::to_vec_pretty(installed).map_err(io)?;
    crate::store::write_atomic(&dir.join(INSTALLED_FILE), &bytes).map_err(io)
}

/// What [`install`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallKind {
    Installed,
    Updated { from: String },
    RolledBack { from: String },
    /// The same package was already the current version; nothing changed.
    AlreadyInstalled,
}

/// The result of [`install`], with the audit record to write (T18.26).
#[derive(Debug, Clone)]
pub struct InstallResult {
    pub id: String,
    pub version: Version,
    pub tier: Tier,
    pub kind: InstallKind,
    pub audit: Option<PluginAudit>,
}

/// One install, from the catalogue or from a file.
#[derive(Debug, Clone, Copy)]
pub struct InstallRequest<'a> {
    /// The `.bastionplugin` bytes.
    pub package: &'a [u8],
    /// Its verified release record, if it has one (from the index or its `.sig` file).
    pub record: Option<&'a VerifiedRecord>,
    /// The record's signed bytes, kept next to the package so a later check works offline.
    pub record_bytes: Option<&'a [u8]>,
    /// The setting "Allow unverified plugins" (off by default; policy can lock it off).
    pub allow_unverified: bool,
}

fn audit(action: &'static str, id: &str, version: &str, tier: Tier, extra: &[(&str, String)]) -> PluginAudit {
    let mut details = std::collections::BTreeMap::new();
    details.insert("plugin".to_string(), id.to_string());
    details.insert("plugin_version".to_string(), version.to_string());
    details.insert("tier".to_string(), tier_name(tier).to_string());
    for (key, value) in extra {
        details.insert((*key).to_string(), value.clone());
    }
    PluginAudit { category: Category::Plugin, action, target: None, outcome: Outcome::Success, details }
}

/// `plugin.install.refused`: an install, update or rollback was refused. The reason is the
/// error's text, which holds no untrusted bytes beyond an [`Excerpt`].
pub fn refused_audit(package: &[u8], error: &PluginError) -> PluginAudit {
    let mut details = std::collections::BTreeMap::new();
    details.insert("package_sha256".to_string(), hex::encode(<sha2::Sha256 as sha2::Digest>::digest(package)));
    details.insert("reason".to_string(), error.to_string());
    PluginAudit { category: Category::Plugin, action: "plugin.install.refused", target: None, outcome: Outcome::Denied, details }
}

/// `plugin.revoked`: a revocation switched an installed plugin off.
pub fn revoked_audit(id: &str, version: &str, reason: &str) -> PluginAudit {
    let mut details = std::collections::BTreeMap::new();
    details.insert("plugin".to_string(), id.to_string());
    details.insert("plugin_version".to_string(), version.to_string());
    details.insert("reason".to_string(), reason.to_string());
    PluginAudit { category: Category::Plugin, action: "plugin.revoked", target: None, outcome: Outcome::Success, details }
}

/// Install, update or roll back one plugin.
///
/// Checks, in order: the package reading rules and manifest checks ([`read_package`]); the
/// record (hash, size, id, version, permissions, API range, reserved id, "Bastion" names); the
/// Unverified setting; the stored revocations; the tier of what is installed (a file cannot
/// replace a higher tier); and the version (older versions are refused, except the kept
/// previous one). Only then is anything written, under the folder lock.
pub fn install(folders: &PluginFolders, request: InstallRequest<'_>) -> Result<InstallResult, PluginError> {
    let package = read_package(request.package)?;
    let tier = check_package_against_record(&package, request.record)?;
    // The component may import only what its permissions allow (section 6).
    check_imports(&package.wasm, &package.manifest.permissions)?;
    if tier == Tier::Unverified && !request.allow_unverified {
        return Err(PluginError::UnverifiedNotAllowed);
    }
    let id = package.manifest.id.clone();
    let version = package.manifest.version;
    let version_text = version.to_string();
    let sha256 = hex::encode(package.sha256);

    let _lock = FolderLock::acquire(folders)?;
    // The stored revocations, read under the lock: a revocation another app stored a moment ago
    // applies, whatever copy of the state the caller holds.
    let trust = TrustState::load(&folders.trust_path())?;
    if let Some(revocation) = trust.revocation_for(&id, &version) {
        return Err(PluginError::Revoked { id, version: version_text, reason: revocation.reason.clone() });
    }
    let dir = folders.plugin_dir(&id)?;
    let existing = read_installed(&dir)?;
    let entry = InstalledVersion { version: version_text.clone(), tier: tier_name(tier).to_string(), sha256: sha256.clone(), size: package.size };

    let (kind, installed) = match existing {
        None => (InstallKind::Installed, Installed { schema: SCHEMA, id: id.clone(), current: entry, previous: None }),
        Some(existing) => {
            if existing.current.tier() > tier {
                return Err(PluginError::HigherTierInstalled);
            }
            let current = Version::parse(&existing.current.version).ok_or_else(|| io("installed.json has a bad version"))?;
            if version == current {
                if existing.current.sha256 == sha256 {
                    return Ok(InstallResult { id, version, tier, kind: InstallKind::AlreadyInstalled, audit: None });
                }
                return Err(PluginError::SameVersionDifferentPackage { version: version_text });
            }
            if version < current {
                let is_previous = existing.previous.as_ref().is_some_and(|p| p.version == version_text && p.sha256 == sha256);
                if !is_previous {
                    return Err(PluginError::OlderVersion { offered: version_text, installed: existing.current.version });
                }
                let from = existing.current.version.clone();
                (InstallKind::RolledBack { from }, Installed { schema: SCHEMA, id: id.clone(), current: entry, previous: Some(existing.current) })
            } else {
                let from = existing.current.version.clone();
                // Only one previous version is kept: the one before this update.
                if let Some(old) = &existing.previous {
                    if old.version != version_text {
                        let _ = std::fs::remove_file(dir.join(package_name(&old.version)));
                        let _ = std::fs::remove_file(dir.join(sig_name(&old.version)));
                    }
                }
                (InstallKind::Updated { from }, Installed { schema: SCHEMA, id: id.clone(), current: entry, previous: Some(existing.current) })
            }
        }
    };

    std::fs::create_dir_all(&dir).map_err(io)?;
    crate::store::write_atomic(&dir.join(package_name(&version_text)), request.package).map_err(io)?;
    match request.record_bytes {
        Some(bytes) => crate::store::write_atomic(&dir.join(sig_name(&version_text)), bytes).map_err(io)?,
        None => {
            let _ = std::fs::remove_file(dir.join(sig_name(&version_text)));
        }
    }
    // installed.json last: until it is written, the old state is still the installed one.
    write_installed(&dir, &installed)?;
    // The renamed official pack supersedes its pre-rename install (`dev.bastion.x` -> `dev.gantry.x`).
    if let Some(rest) = id.strip_prefix(super::manifest::RESERVED_ID).filter(|r| r.starts_with('.')) {
        let legacy = format!("{}{rest}", super::manifest::LEGACY_RESERVED_ID);
        if let Ok(old) = folders.plugin_dir(&legacy) {
            if old.is_dir() {
                let _ = std::fs::remove_dir_all(&old);
            }
        }
    }
    let audit_record = match &kind {
        InstallKind::Installed => audit("plugin.install", &id, &version_text, tier, &[]),
        InstallKind::Updated { from } => audit("plugin.update", &id, &version_text, tier, &[("from_version", from.clone())]),
        InstallKind::RolledBack { from } => audit("plugin.rollback", &id, &version_text, tier, &[("from_version", from.clone())]),
        InstallKind::AlreadyInstalled => unreachable!("returned above"),
    };
    Ok(InstallResult { id, version, tier, kind, audit: Some(audit_record) })
}

/// Remove a plugin: its packages and records always, its data only when asked (section 10).
pub fn remove(folders: &PluginFolders, id: &str, delete_data: bool) -> Result<PluginAudit, PluginError> {
    let _lock = FolderLock::acquire(folders)?;
    let dir = folders.plugin_dir(id)?;
    let installed = read_installed(&dir)?.ok_or_else(|| PluginError::NotInstalled(Excerpt::new(id.as_bytes())))?;
    std::fs::remove_dir_all(&dir).map_err(io)?;
    if delete_data {
        let data = folders.data_dir_of(id)?;
        if data.exists() {
            std::fs::remove_dir_all(&data).map_err(io)?;
        }
    }
    Ok(audit("plugin.remove", id, &installed.current.version, installed.current.tier(), &[("data_deleted", delete_data.to_string())]))
}

/// Every installed plugin, sorted by id. A folder whose `installed.json` is missing (an install
/// stopped before its last step) is skipped.
pub fn list_installed(folders: &PluginFolders) -> Result<Vec<Installed>, PluginError> {
    let dir = folders.plugins_dir();
    let entries = match std::fs::read_dir(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io(e)),
        Ok(entries) => entries,
    };
    let mut all = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_plugin_id(&name) || !entry.file_type().map_err(io)?.is_dir() {
            continue;
        }
        if let Some(installed) = read_installed(&entry.path())? {
            if installed.id == name {
                all.push(installed);
            }
        }
    }
    all.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(all)
}

/// Read the current version of `id` back into memory, checked against the hash recorded at
/// install, and refused if a stored revocation covers it. The tier is re-derived from the
/// stored signed release record against the app's pinned keys (SEC-5).
pub fn load_installed(folders: &PluginFolders, id: &str) -> Result<(Package, Tier), PluginError> {
    load_installed_with(folders, id, &super::catalogue::pinned_keys())
}

/// [`load_installed`] with the given trusted keys (tests and key rotation).
///
/// SEC-5: `installed.json` is not signed, so its `tier` is never trusted to raise a plugin. The
/// tier is the one the stored `<version>.sig` verifies to, re-checked against the package on
/// every load, and never higher than the tier `installed.json` records (a hand edit can only
/// lower it). A missing, unreadable or no-longer-valid record makes the plugin Unverified; a
/// reserved id then fails as at install. Symbolic links in place of the package, record or
/// `installed.json` are refused.
pub fn load_installed_with(folders: &PluginFolders, id: &str, keys: &super::sign::TrustedKeys) -> Result<(Package, Tier), PluginError> {
    let dir = folders.plugin_dir(id)?;
    let changed = || PluginError::InstalledCopyChanged(Excerpt::new(id.as_bytes()));
    if is_symlink(&dir.join(INSTALLED_FILE)) {
        return Err(changed());
    }
    let installed = read_installed(&dir)?.ok_or_else(|| PluginError::NotInstalled(Excerpt::new(id.as_bytes())))?;
    let package_path = dir.join(package_name(&installed.current.version));
    let sig_path = dir.join(sig_name(&installed.current.version));
    if is_symlink(&package_path) || is_symlink(&sig_path) {
        return Err(changed());
    }
    let bytes = std::fs::read(&package_path).map_err(io)?;
    let package = read_package(&bytes)?;
    if hex::encode(package.sha256) != installed.current.sha256 || package.manifest.id != id || package.manifest.version.to_string() != installed.current.version {
        return Err(changed());
    }
    // Read from disk on every load, so a revocation stored by any running app applies.
    let trust = TrustState::load(&folders.trust_path())?;
    if let Some(revocation) = trust.revocation_for(id, &package.manifest.version) {
        return Err(PluginError::Revoked { id: id.to_string(), version: installed.current.version, reason: revocation.reason.clone() });
    }
    let record = match std::fs::read(&sig_path) {
        Ok(record_bytes) => super::record::verify_release_record(&record_bytes, keys, &trust.revoked_index_keys()).ok(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(io(e)),
    };
    let verified = match record.as_ref().map(|r| check_package_against_record(&package, Some(r))) {
        Some(Ok(tier)) => tier,
        // No record, or one that no longer verifies or matches: the package is Unverified
        // (and a reserved id or a "Bastion" name is refused, as at install).
        _ => check_package_against_record(&package, None)?,
    };
    Ok((package, verified.min(installed.current.tier())))
}

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false)
}
