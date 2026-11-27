//! PLUG-15: the revocation drill, app side. Run by `scripts/plugin-revocation-drill.sh` with
//! throwaway keys; runbook `docs/plugins/OPERATIONS.md`, "Revocation drill".
//!
//! Two scenarios, each through the same calls the apps make (`accept_and_store`, `install`,
//! `load_installed_with`):
//! 1. A bad plugin version: the maintainer signs an index with a revocation; an installed copy
//!    stops loading, the version cannot be installed again, and a later index that leaves the
//!    revocation out does not bring it back.
//! 2. A stolen index key: the thief signs a very high sequence; the spare key revokes the stolen
//!    key, the floor resets, and every later index from the stolen key is refused.
#[path = "fixtures/plugin/support.rs"]
mod support;

use bastion_core::plugin::{
    accept_and_store, install, load_installed_with, verify_release_record, IndexDecision, IndexRefusal, InstallKind, InstallRequest, PluginError, PluginFolders, Tier, TrustedKeys,
};
use ed25519_dalek::SigningKey;
use support::*;

const DAY: u64 = 24 * 3600;
const ISSUED: u64 = NOW - DAY;
const EXPIRES: u64 = ISSUED + 30 * DAY;

struct Drill {
    active: SigningKey,
    spare: SigningKey,
    index_public: [[u8; 32]; 2],
    official_public: [[u8; 32]; 1],
    dir: std::path::PathBuf,
    folders: PluginFolders,
}

impl Drill {
    fn new() -> Self {
        let (active, spare, official) = (new_key(), new_key(), new_key());
        let dir = std::env::temp_dir().join(format!("bastion-plug15-drill-{}", uuid::Uuid::new_v4()));
        Drill { index_public: [public(&active), public(&spare)], official_public: [public(&official)], active, spare, folders: PluginFolders::new(&dir), dir }
    }
    fn keys(&self) -> TrustedKeys<'_> {
        TrustedKeys { index: &self.index_public, official: &self.official_public }
    }
    fn store(&self, index: &[u8]) -> IndexDecision {
        accept_and_store(&self.folders, index, &self.keys(), NOW).unwrap()
    }
    fn install(&self, version: &str) -> Result<InstallKind, PluginError> {
        let package = package_for(EXTERNAL_ID, version);
        let record_bytes = external_record(&self.active, EXTERNAL_ID, version, &package);
        let record = verify_release_record(&record_bytes, &self.keys(), &[]).unwrap();
        install(&self.folders, InstallRequest { package: &package, record: Some(&record), record_bytes: Some(&record_bytes), allow_unverified: false }).map(|r| r.kind)
    }
}

impl Drop for Drill {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn index(key: &SigningKey, sequence: u64, revocations: serde_json::Value, revoked_keys: &[&SigningKey]) -> Vec<u8> {
    let mut value = index_value(sequence, ISSUED, EXPIRES, &[]);
    value["revocations"] = revocations;
    value["revoked_keys"] = serde_json::json!(revoked_keys.iter().map(|k| hex::encode(public(k))).collect::<Vec<_>>());
    signed_index(key, &value)
}

fn is_accepted(decision: &IndexDecision) -> bool {
    matches!(decision, IndexDecision::Accepted { .. })
}

#[test]
fn drill_1_a_revoked_version_stops_loading_and_stays_revoked() {
    let drill = Drill::new();
    assert!(is_accepted(&drill.store(&index(&drill.active, 10, serde_json::json!([]), &[]))));
    assert_eq!(drill.install("1.0.0").unwrap(), InstallKind::Installed);
    assert_eq!(load_installed_with(&drill.folders, EXTERNAL_ID, &drill.keys()).unwrap().1, Tier::External);

    let revocation = serde_json::json!([{ "id": EXTERNAL_ID, "from": "1.0.0", "to": "1.0.9", "reason": "Drill: unsafe query handling." }]);
    assert!(is_accepted(&drill.store(&index(&drill.active, 11, revocation, &[]))));
    match load_installed_with(&drill.folders, EXTERNAL_ID, &drill.keys()).unwrap_err() {
        PluginError::Revoked { reason, .. } => assert_eq!(reason, "Drill: unsafe query handling."),
        other => panic!("expected Revoked, got {other:?}"),
    }
    assert!(matches!(drill.install("1.0.0").unwrap_err(), PluginError::Revoked { .. }));

    // A later index that leaves the revocation out does not lift it (union).
    assert!(is_accepted(&drill.store(&index(&drill.active, 12, serde_json::json!([]), &[]))));
    assert!(matches!(load_installed_with(&drill.folders, EXTERNAL_ID, &drill.keys()).unwrap_err(), PluginError::Revoked { .. }));

    // The fixed version installs and loads.
    assert_eq!(drill.install("1.1.0").unwrap(), InstallKind::Updated { from: "1.0.0".into() });
    assert_eq!(load_installed_with(&drill.folders, EXTERNAL_ID, &drill.keys()).unwrap().1, Tier::External);
    eprintln!("DRILL 1 PASS: revoked version refused at load and install, revocation kept, fixed version loads");
}

#[test]
fn drill_2_the_spare_key_revokes_a_stolen_index_key() {
    let drill = Drill::new();
    assert!(is_accepted(&drill.store(&index(&drill.active, 10, serde_json::json!([]), &[]))));
    // The thief, holding the active key, pushes the floor very high.
    assert!(is_accepted(&drill.store(&index(&drill.active, 1_000_000, serde_json::json!([]), &[]))));

    // The maintainer signs with the offline spare: revoke the active key, at a sequence above
    // everything the spare has signed (it has signed nothing yet).
    match drill.store(&index(&drill.spare, 20, serde_json::json!([]), &[&drill.active])) {
        IndexDecision::Accepted { floor_reset, .. } => assert!(floor_reset, "the floor must reset to the spare's index"),
        other => panic!("the revoking index was refused: {other:?}"),
    }
    // Anything the thief signs from now on is refused, however high.
    assert_eq!(drill.store(&index(&drill.active, 2_000_000, serde_json::json!([]), &[])), IndexDecision::Refused(IndexRefusal::RevokedKey));
    // A replay of an older spare index is a rollback.
    assert!(matches!(drill.store(&index(&drill.spare, 19, serde_json::json!([]), &[])), IndexDecision::Refused(IndexRefusal::RolledBack { .. })));
    // The spare carries on.
    assert!(is_accepted(&drill.store(&index(&drill.spare, 21, serde_json::json!([]), &[]))));
    // A release record signed by the stolen key no longer verifies once its revocation is stored.
    let package = package_for(EXTERNAL_ID, "3.0.0");
    let record = external_record(&drill.active, EXTERNAL_ID, "3.0.0", &package);
    let revoked = bastion_core::plugin::TrustState::load(&drill.folders.trust_path()).unwrap().revoked_index_keys();
    assert!(verify_release_record(&record, &drill.keys(), &revoked).is_err());
    eprintln!("DRILL 2 PASS: stolen key revoked by the spare, floor reset, stolen-key indexes and records refused");
}
