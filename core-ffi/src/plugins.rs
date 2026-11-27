//! PLUG-04b part 2: installed plugins, install from a file, remove, refreshing the catalogue
//! and the update plan, over `bastion_core::plugin`. `data_dir` is the app's data folder.
//!
//! The pinned keys are `bastion_core::plugin::pinned_keys()` (PLUG-12): an Official package
//! installs from a file when its signed `.sig` record lies beside it.
use std::path::PathBuf;

use bastion_core::plugin::{
    install_file, list_installed, load_cached, pinned_keys, plan_updates, refresh, remove, FolderCatalogue, HttpCatalogue, IndexDecision, IndexOutcome, InstallKind,
    PluginError, PluginFolders, RefreshOutcome, TrustState,
};

use crate::{FfiError, FfiResult};

/// `unverified` marks the one refusal the apps answer with a question (install it unverified?);
/// every other plugin error is `plugin`.
fn fail(e: PluginError) -> FfiError {
    let code = if matches!(e, PluginError::UnverifiedNotAllowed) { "unverified" } else { "plugin" };
    FfiError::Failed { message: e.to_string(), code: code.into() }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn folders(data_dir: &str) -> PluginFolders {
    PluginFolders::new(PathBuf::from(data_dir))
}

/// One installed plugin.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct InstalledPluginView {
    pub id: String,
    pub version: String,
    /// `official`, `external` or `unverified`.
    pub tier: String,
    /// The kept previous version, if any (restore).
    pub previous_version: Option<String>,
}

/// The installed plugins, by id.
#[uniffi::export]
pub fn plugins_installed(data_dir: String) -> FfiResult<Vec<InstalledPluginView>> {
    let list = list_installed(&folders(&data_dir)).map_err(fail)?;
    Ok(list
        .into_iter()
        .map(|p| InstalledPluginView { id: p.id, version: p.current.version, tier: p.current.tier, previous_version: p.previous.map(|v| v.version) })
        .collect())
}

/// Install a `.bastionplugin` file the user picked, with its release record when a `.sig` lies
/// beside it (`<stem>.sig` or `<id>-<version>.sig`); a record that does not verify refuses the
/// install. Without one the package is Unverified, so it installs only with `allow_unverified` (the setting "Allow unverified plugins").
/// Returns `installed`, `updated`, `restored` or `unchanged`.
#[uniffi::export]
pub fn plugin_install_file(data_dir: String, path: String, allow_unverified: bool) -> FfiResult<String> {
    let result = install_file(&folders(&data_dir), std::path::Path::new(&path), &pinned_keys(), allow_unverified).map_err(fail)?;
    Ok(match result.kind {
        InstallKind::Installed => "installed",
        InstallKind::Updated { .. } => "updated",
        InstallKind::RolledBack { .. } => "restored",
        InstallKind::AlreadyInstalled => "unchanged",
    }
    .into())
}

/// Remove plugin `id`; `delete_data` also deletes its data folder.
#[uniffi::export]
pub fn plugin_remove(data_dir: String, id: String, delete_data: bool) -> FfiResult<()> {
    remove(&folders(&data_dir), &id, delete_data).map(|_| ()).map_err(fail)
}

/// Fetch the catalogue index: the official catalogue, or the mirror folder `mirror` when set.
/// Returns `accepted`, `expired`, `clock-wrong`, `refused: <why>` or `unreachable: <why>`.
/// Nothing is changed unless it is accepted.
#[uniffi::export]
pub fn plugins_refresh(data_dir: String, mirror: Option<String>) -> FfiResult<String> {
    let folders = folders(&data_dir);
    let keys = pinned_keys();
    let outcome = match mirror {
        Some(dir) => refresh(&folders, &keys, &FolderCatalogue(dir.into()), now()),
        None => refresh(&folders, &keys, &HttpCatalogue::official(), now()),
    }
    .map_err(fail)?;
    Ok(match outcome {
        RefreshOutcome::Unreachable(why) => format!("unreachable: {why}"),
        RefreshOutcome::Checked(IndexDecision::Refused(why)) => format!("refused: {why:?}"),
        RefreshOutcome::Checked(IndexDecision::Accepted { clock_looks_wrong: true, .. }) => "clock-wrong".into(),
        RefreshOutcome::Checked(IndexDecision::Accepted { outcome: IndexOutcome::Usable(_), .. }) => "accepted".into(),
        RefreshOutcome::Checked(IndexDecision::Accepted { outcome: IndexOutcome::Expired(_), .. }) => "expired".into(),
        RefreshOutcome::Checked(IndexDecision::Accepted { .. }) => "clock-wrong".into(),
    })
}

/// One update the cached catalogue offers.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PluginUpdateView {
    pub id: String,
    pub from: String,
    pub to: String,
    pub tier: String,
    /// The update asks for new permissions: ask the user first.
    pub needs_consent: bool,
}

/// The updates the cached, usable index offers. Empty when there is no usable index.
#[uniffi::export]
pub fn plugins_updates(data_dir: String) -> FfiResult<Vec<PluginUpdateView>> {
    let folders = folders(&data_dir);
    let keys = pinned_keys();
    let Some(IndexOutcome::Usable(index)) = load_cached(&folders, &keys, now()) else { return Ok(Vec::new()) };
    let trust = TrustState::load(&folders.trust_path()).map_err(fail)?;
    let installed = list_installed(&folders).map_err(fail)?;
    let permissions_of = |p: &bastion_core::plugin::Installed| bastion_core::plugin::load_installed(&folders, &p.id).ok().map(|(package, _)| package.manifest.permissions);
    Ok(plan_updates(&installed, &index, &trust, permissions_of)
        .into_iter()
        .map(|u| PluginUpdateView { id: u.id, from: u.from, to: u.record.version.to_string(), tier: format!("{:?}", u.record.tier).to_lowercase(), needs_consent: u.needs_consent })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_folder_lists_nothing_and_offers_no_update() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().display().to_string();
        assert!(plugins_installed(d.clone()).unwrap().is_empty());
        assert!(plugins_updates(d.clone()).unwrap().is_empty());
        // No mirror index: unreachable, and nothing is written.
        let mirror = tempfile::tempdir().unwrap();
        assert!(plugins_refresh(d.clone(), Some(mirror.path().display().to_string())).unwrap().starts_with("unreachable"));
        assert!(plugin_remove(d.clone(), "com.example.none".into(), false).is_err());
        assert!(plugin_install_file(d, dir.path().join("missing.bastionplugin").display().to_string(), true).is_err());
    }

    #[test]
    fn an_unverified_refusal_has_its_own_code() {
        assert_eq!(fail(PluginError::UnverifiedNotAllowed).code(), "unverified");
        assert_eq!(fail(PluginError::RecordTooLarge).code(), "plugin");
    }
}
