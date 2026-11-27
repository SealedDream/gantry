//! PLUG-04b part 2: fetching and storing the index from a mirror folder, fail-safe refresh,
//! fetching a package and the update plan.
#[path = "fixtures/plugin/support.rs"]
mod support;

use bastion_core::plugin::{
    fetch_package, install, list_installed, load_cached, plan_updates, refresh, CatalogueSource, FolderCatalogue, IndexDecision, IndexOutcome, InstallRequest, PluginError,
    PluginFolders, RefreshOutcome, TrustState, TrustedKeys, INDEX_FILE,
};
use support::*;

const DAY: u64 = 24 * 3600;

struct Setup {
    _dir: tempfile::TempDir,
    folders: PluginFolders,
    mirror: tempfile::TempDir,
    key: ed25519_dalek::SigningKey,
    public: [[u8; 32]; 1],
}

impl Setup {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let folders = PluginFolders::new(dir.path());
        let key = new_key();
        let public = [public(&key)];
        Setup { _dir: dir, folders, mirror: tempfile::tempdir().unwrap(), key, public }
    }
    fn keys(&self) -> TrustedKeys<'_> {
        TrustedKeys { index: &self.public, official: &[] }
    }
    fn source(&self) -> FolderCatalogue {
        FolderCatalogue(self.mirror.path().into())
    }
    /// Publish an index with `versions` of the example plugin, and their packages.
    fn publish(&self, sequence: u64, versions: &[&str]) {
        let mut records = Vec::new();
        for version in versions {
            let package = package_for(EXTERNAL_ID, version);
            std::fs::write(self.mirror.path().join(format!("{EXTERNAL_ID}-{version}.gantryplugin")), &package).unwrap();
            records.push(external_record(&self.key, EXTERNAL_ID, version, &package));
        }
        let index = signed_index(&self.key, &index_value(sequence, NOW - DAY, NOW + 20 * DAY, &records));
        std::fs::write(self.mirror.path().join(INDEX_FILE), index).unwrap();
    }
    fn usable(&self) -> bastion_core::plugin::Index {
        match load_cached(&self.folders, &self.keys(), NOW) {
            Some(IndexOutcome::Usable(index)) => index,
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn an_unreachable_catalogue_changes_nothing() {
    let s = Setup::new();
    assert!(matches!(refresh(&s.folders, &s.keys(), &s.source(), NOW).unwrap(), RefreshOutcome::Unreachable(_)));
    assert!(!s.folders.trust_path().exists());
    s.publish(5, &["1.0.0"]);
    refresh(&s.folders, &s.keys(), &s.source(), NOW).unwrap();
    let before = std::fs::read(s.folders.trust_path()).unwrap();
    std::fs::remove_file(s.mirror.path().join(INDEX_FILE)).unwrap();
    assert!(matches!(refresh(&s.folders, &s.keys(), &s.source(), NOW).unwrap(), RefreshOutcome::Unreachable(_)));
    assert_eq!(std::fs::read(s.folders.trust_path()).unwrap(), before);
    assert_eq!(s.usable().sequence, 5);
}

#[test]
fn an_accepted_index_is_cached_and_a_rollback_is_not() {
    let s = Setup::new();
    s.publish(5, &["1.0.0"]);
    assert!(matches!(refresh(&s.folders, &s.keys(), &s.source(), NOW).unwrap(), RefreshOutcome::Checked(IndexDecision::Accepted { .. })));
    s.publish(4, &["1.0.0", "1.1.0"]);
    assert!(matches!(refresh(&s.folders, &s.keys(), &s.source(), NOW).unwrap(), RefreshOutcome::Checked(IndexDecision::Refused(_))));
    assert_eq!(s.usable().sequence, 5);
}

#[test]
fn with_no_pinned_key_nothing_is_accepted() {
    let s = Setup::new();
    s.publish(5, &["1.0.0"]);
    let none = TrustedKeys { index: &[], official: &[] };
    assert!(matches!(refresh(&s.folders, &none, &s.source(), NOW).unwrap(), RefreshOutcome::Checked(IndexDecision::Refused(_))));
    assert!(load_cached(&s.folders, &none, NOW).is_none());
}

#[test]
fn a_package_larger_than_its_record_is_not_read() {
    let s = Setup::new();
    s.publish(5, &["1.0.0"]);
    refresh(&s.folders, &s.keys(), &s.source(), NOW).unwrap();
    let index = s.usable();
    let record = &index.records[0];
    assert_eq!(fetch_package(&s.source(), record).unwrap().len() as u64, record.size);
    let path = s.mirror.path().join(format!("{EXTERNAL_ID}-1.0.0.gantryplugin"));
    let mut bigger = std::fs::read(&path).unwrap();
    bigger.push(0);
    std::fs::write(&path, bigger).unwrap();
    assert!(matches!(s.source().package(record), Err(PluginError::Unreachable(_))));
}

#[test]
fn the_update_plan_offers_the_highest_newer_version() {
    let s = Setup::new();
    s.publish(5, &["1.0.0"]);
    refresh(&s.folders, &s.keys(), &s.source(), NOW).unwrap();
    let index = s.usable();
    let package = fetch_package(&s.source(), &index.records[0]).unwrap();
    let trust = TrustState::load(&s.folders.trust_path()).unwrap();
    install(&s.folders, InstallRequest { package: &package, record: Some(&index.records[0]), record_bytes: None, allow_unverified: false }).unwrap();
    let installed = list_installed(&s.folders).unwrap();
    assert!(plan_updates(&installed, &index, &trust, |_| None).is_empty());

    s.publish(6, &["1.0.0", "1.1.0", "1.2.0"]);
    refresh(&s.folders, &s.keys(), &s.source(), NOW).unwrap();
    let index = s.usable();
    let trust = TrustState::load(&s.folders.trust_path()).unwrap();
    let same = index.records[0].permissions;
    let plans = plan_updates(&installed, &index, &trust, |_| Some(same));
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].record.version.to_string(), "1.2.0");
    assert!(!plans[0].needs_consent);
    assert!(plan_updates(&installed, &index, &trust, |_| None)[0].needs_consent);
}
