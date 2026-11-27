//! Installing a `.bastionplugin` the user picked, with its release record when one lies next to
//! it (PLUG-12; `docs/specs/plugins.md`, section 10, "Install from a file").
//!
//! The record is looked for beside the package as `<file stem>.sig`, then `<id>-<version>.sig`
//! (the name the catalogue ships). A record that is there but does not verify, or does not match
//! the package, refuses the install: it never falls back to Unverified. With no record the
//! package is Unverified and installs only with the "Allow unverified plugins" setting.
use std::io::Read;
use std::path::{Path, PathBuf};

use super::error::PluginError;
use super::install::{install, io, InstallRequest, InstallResult, PluginFolders};
use super::package::{read_package, MAX_PACKAGE_FILE_BYTES};
use super::record::{verify_release_record, MAX_RECORD_BYTES};
use super::sign::TrustedKeys;
use super::trust::TrustState;

/// Read at most `limit` bytes of `path`; a longer file is refused, not cut.
fn read_capped(path: &Path, limit: usize) -> Result<Vec<u8>, PluginError> {
    let file = std::fs::File::open(path).map_err(io)?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(io)?;
    if bytes.len() > limit {
        return Err(PluginError::RecordTooLarge);
    }
    Ok(bytes)
}

/// The release record files that may belong to the package at `path`, in the order tried.
fn record_candidates(path: &Path, id: &str, version: &str) -> Vec<PathBuf> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut out = Vec::with_capacity(2);
    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
        out.push(dir.join(format!("{stem}.sig")));
    }
    let named = dir.join(format!("{id}-{version}.sig"));
    if !out.contains(&named) {
        out.push(named);
    }
    out
}

/// A plain file, not followed through a link: a link, FIFO or device beside the package is never
/// read as its record.
fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

/// Install the package file at `path`, verifying a release record found beside it with `keys`
/// and the index keys the stored state has revoked.
pub fn install_file(folders: &PluginFolders, path: &Path, keys: &TrustedKeys, allow_unverified: bool) -> Result<InstallResult, PluginError> {
    let package_bytes = std::fs::File::open(path).map_err(io).and_then(|file| {
        let mut bytes = Vec::new();
        file.take(MAX_PACKAGE_FILE_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(io)?;
        Ok(bytes)
    })?;
    // Read once here to learn the id and version that name the record file.
    let package = read_package(&package_bytes)?;
    let version = package.manifest.version.to_string();
    let record_path = record_candidates(path, &package.manifest.id, &version).into_iter().find(|p| is_regular_file(p));
    let Some(record_path) = record_path else {
        return install(folders, InstallRequest { package: &package_bytes, record: None, record_bytes: None, allow_unverified });
    };
    let record_bytes = read_capped(&record_path, MAX_RECORD_BYTES)?;
    let revoked = TrustState::load(&folders.trust_path())?.revoked_index_keys();
    let record = verify_release_record(&record_bytes, keys, &revoked)?;
    install(folders, InstallRequest { package: &package_bytes, record: Some(&record), record_bytes: Some(&record_bytes), allow_unverified })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stem_record_is_tried_before_the_catalogue_name() {
        let c = record_candidates(Path::new("/d/proxmox.bastionplugin"), "dev.bastion.proxmox", "0.1.0");
        assert_eq!(c, [PathBuf::from("/d/proxmox.sig"), PathBuf::from("/d/dev.bastion.proxmox-0.1.0.sig")]);
        let same = record_candidates(Path::new("/d/a.b-1.0.0.bastionplugin"), "a.b", "1.0.0");
        assert_eq!(same, [PathBuf::from("/d/a.b-1.0.0.sig")]);
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_record_is_not_a_record() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.sig");
        std::fs::write(&real, b"{}").unwrap();
        let link = dir.path().join("link.sig");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(is_regular_file(&real) && !is_regular_file(&link) && !is_regular_file(dir.path()));
    }
}
