//! PLUG-04b part 1: the stored index state (sequence floor, reset, clock, revocation union),
//! the extra manifest and name checks, and installing into the plugins folder.
//! Spec: docs/specs/plugins.md, sections 6, 9 and 10; A1-C10, A1-C11, A1-C12 in THREAT_MODEL.
#[path = "fixtures/plugin/support.rs"]
mod support;

use bastion_core::plugin::{
    accept_and_store, accept_index, check_package_against_record, install, list_installed, load_installed, load_installed_with, parse_manifest, read_package, remove, verify_index, verify_release_record, IndexDecision,
    IndexOutcome, IndexRefusal, InstallKind, InstallRequest, PluginError, PluginFolders, Purpose, Tier, TrustState, TrustedKeys, Version, MAX_INDEX_RECORDS,
};
use ed25519_dalek::SigningKey;
use support::*;

const DAY: u64 = 24 * 3600;
const ISSUED: u64 = NOW - DAY;
const EXPIRES: u64 = ISSUED + 30 * DAY;

struct Keys {
    index: SigningKey,
    spare: SigningKey,
    official: SigningKey,
    index_public: [[u8; 32]; 2],
    official_public: [[u8; 32]; 1],
}

impl Keys {
    fn new() -> Self {
        let (index, spare, official) = (new_key(), new_key(), new_key());
        let index_public = [public(&index), public(&spare)];
        let official_public = [public(&official)];
        Keys { index, spare, official, index_public, official_public }
    }
    fn trusted(&self) -> TrustedKeys<'_> {
        TrustedKeys { index: &self.index_public, official: &self.official_public }
    }
}

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn plain_index(key: &SigningKey, sequence: u64) -> Vec<u8> {
    signed_index(key, &index_value(sequence, ISSUED, EXPIRES, &[]))
}

fn revoking(key: &SigningKey, sequence: u64, revoked: &SigningKey) -> Vec<u8> {
    let mut value = index_value(sequence, ISSUED, EXPIRES, &[]);
    value["revoked_keys"] = serde_json::json!([hex::encode(public(revoked))]);
    signed_index(key, &value)
}

fn accepted(decision: IndexDecision) -> (IndexOutcome, bool, bool) {
    match decision {
        IndexDecision::Accepted { outcome, floor_reset, clock_looks_wrong } => (outcome, floor_reset, clock_looks_wrong),
        other => panic!("expected the index to be accepted, got {other:?}"),
    }
}

fn refused(decision: IndexDecision) -> IndexRefusal {
    match decision {
        IndexDecision::Refused(refusal) => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ---- the sequence floor (section 9, Rollback; A1-C12.2) ----

#[test]
fn the_first_index_sets_the_floor_and_an_older_one_is_refused() {
    let keys = Keys::new();
    let mut state = TrustState::default();
    let (outcome, reset, wrong) = accepted(accept_index(&mut state, &plain_index(&keys.index, 7), &keys.trusted(), NOW).unwrap());
    assert!(matches!(outcome, IndexOutcome::Usable(_)) && !reset && !wrong);
    let floor = state.floor().unwrap();
    assert_eq!((floor.sequence, floor.issued, floor.signer.as_str()), (7, ISSUED, hex::encode(public(&keys.index)).as_str()));
    assert_eq!(refused(accept_index(&mut state, &plain_index(&keys.index, 6), &keys.trusted(), NOW).unwrap()), IndexRefusal::RolledBack { sequence: 6, floor: 7 });
    assert_eq!(state.floor().unwrap().sequence, 7, "a refused index changes nothing");
}

#[test]
fn an_equal_sequence_is_accepted_only_for_the_same_index() {
    let keys = Keys::new();
    let mut state = TrustState::default();
    let first = plain_index(&keys.index, 7);
    accepted(accept_index(&mut state, &first, &keys.trusted(), NOW).unwrap());
    accepted(accept_index(&mut state, &first, &keys.trusted(), NOW).unwrap());
    let mut other = index_value(7, ISSUED, EXPIRES, &[]);
    other["revocations"] = serde_json::json!([{ "id": EXTERNAL_ID, "from": "1.0.0", "to": "1.0.0", "reason": "different" }]);
    let other = signed_index(&keys.index, &other);
    assert_eq!(refused(accept_index(&mut state, &other, &keys.trusted(), NOW).unwrap()), IndexRefusal::SameSequenceDifferentIndex { sequence: 7 });
    assert!(state.revocation_for(EXTERNAL_ID, &v("1.0.0")).is_none(), "the refused index's revocation was not taken");
}

#[test]
fn the_state_survives_a_restart() {
    let keys = Keys::new();
    let dir = std::env::temp_dir().join(format!("bastion-plug04b-{}", uuid::Uuid::new_v4()));
    let folders = PluginFolders::new(&dir);
    accepted(accept_and_store(&folders, &plain_index(&keys.index, 9), &keys.trusted(), NOW).unwrap());
    let mut again = TrustState::load(&folders.trust_path()).unwrap();
    assert_eq!(again.floor().unwrap().issued, ISSUED, "the stored issue time survives a restart");
    assert_eq!(refused(accept_index(&mut again, &plain_index(&keys.index, 8), &keys.trusted(), NOW).unwrap()), IndexRefusal::RolledBack { sequence: 8, floor: 9 });
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_index_with_more_than_4096_records_or_two_index_signatures_is_refused() {
    let keys = Keys::new();
    let record = external_record(&keys.index, EXTERNAL_ID, "1.0.0", &good_package());
    let many = vec![record; MAX_INDEX_RECORDS + 1];
    let bytes = signed_index(&keys.index, &index_value(7, ISSUED, EXPIRES, &many));
    assert_eq!(verify_index(&bytes, &keys.trusted(), &[], 0, NOW).unwrap_err(), PluginError::IndexTooManyRecords);
    let value = index_value(7, ISSUED, EXPIRES, &[]);
    let twice = envelope(&to_bytes(&value), &[sig(&keys.index, Purpose::Index), sig(&keys.spare, Purpose::Index)]);
    assert!(matches!(verify_index(&twice, &keys.trusted(), &[], 0, NOW).unwrap_err(), PluginError::IndexMalformed(_)));
}

// ---- recovery from a stolen index key (A1-C12.5) ----

#[test]
fn an_index_that_revokes_the_floor_signer_resets_the_floor() {
    let keys = Keys::new();
    let mut state = TrustState::default();
    // The thief signs a very high sequence with key A.
    accepted(accept_index(&mut state, &plain_index(&keys.index, 1_000_000), &keys.trusted(), NOW).unwrap());
    // Key B revokes A at a sequence below the floor but above anything B signed before.
    let (outcome, reset, _) = accepted(accept_index(&mut state, &revoking(&keys.spare, 50, &keys.index), &keys.trusted(), NOW).unwrap());
    assert!(reset && matches!(outcome, IndexOutcome::Usable(_)));
    assert_eq!(state.floor().unwrap().sequence, 50);
    assert_eq!(state.floor().unwrap().signer, hex::encode(public(&keys.spare)));
    // From then on A is refused whatever its sequence...
    assert_eq!(refused(accept_index(&mut state, &plain_index(&keys.index, 2_000_000), &keys.trusted(), NOW).unwrap()), IndexRefusal::RevokedKey);
    // ...and an older B index is a rollback below the new floor.
    assert_eq!(refused(accept_index(&mut state, &plain_index(&keys.spare, 40), &keys.trusted(), NOW).unwrap()), IndexRefusal::RolledBack { sequence: 40, floor: 50 });
}

#[test]
fn a_reset_must_beat_every_sequence_accepted_from_the_remaining_key() {
    let keys = Keys::new();
    let mut state = TrustState::default();
    accepted(accept_index(&mut state, &plain_index(&keys.spare, 60), &keys.trusted(), NOW).unwrap());
    accepted(accept_index(&mut state, &plain_index(&keys.index, 1_000), &keys.trusted(), NOW).unwrap());
    assert_eq!(state.highest_from(&public(&keys.spare)), 60);
    // At or below B's highest: refused, the floor stays.
    assert_eq!(refused(accept_index(&mut state, &revoking(&keys.spare, 60, &keys.index), &keys.trusted(), NOW).unwrap()), IndexRefusal::RolledBack { sequence: 60, floor: 1_000 });
    assert_eq!(state.floor().unwrap().sequence, 1_000);
    // Above it: accepted and reset.
    let (_, reset, _) = accepted(accept_index(&mut state, &revoking(&keys.spare, 61, &keys.index), &keys.trusted(), NOW).unwrap());
    assert!(reset);
}

#[test]
fn an_index_below_the_floor_that_does_not_revoke_the_floor_signer_is_a_rollback() {
    let keys = Keys::new();
    let mut state = TrustState::default();
    accepted(accept_index(&mut state, &plain_index(&keys.index, 100), &keys.trusted(), NOW).unwrap());
    // B revokes nothing: no reset, however high above B's own history.
    assert!(matches!(refused(accept_index(&mut state, &plain_index(&keys.spare, 99), &keys.trusted(), NOW).unwrap()), IndexRefusal::RolledBack { .. }));
}

// ---- revocations are a union (A1-C12.7) ----

#[test]
fn a_release_revocation_is_never_dropped_by_a_later_index() {
    let keys = Keys::new();
    let mut state = TrustState::default();
    let mut first = index_value(7, ISSUED, EXPIRES, &[]);
    first["revocations"] = serde_json::json!([{ "id": EXTERNAL_ID, "from": "1.0.0", "to": "1.4.3", "reason": "Sends data to an unknown host." }]);
    accepted(accept_index(&mut state, &signed_index(&keys.index, &first), &keys.trusted(), NOW).unwrap());
    accepted(accept_index(&mut state, &plain_index(&keys.index, 8), &keys.trusted(), NOW).unwrap());
    let revocation = state.revocation_for(EXTERNAL_ID, &v("1.2.0")).expect("still revoked after an index that leaves it out");
    assert_eq!(revocation.reason, "Sends data to an unknown host.");
    // A reset does not remove it either.
    accepted(accept_index(&mut state, &revoking(&keys.spare, 5, &keys.index), &keys.trusted(), NOW).unwrap());
    assert!(state.revocation_for(EXTERNAL_ID, &v("1.2.0")).is_some());
    assert!(state.revocation_for(EXTERNAL_ID, &v("1.4.4")).is_none());
}

// ---- the clock (A1-C10) ----

#[test]
fn a_clock_a_year_back_is_reported_and_expiry_uses_the_stored_issue_time() {
    let keys = Keys::new();
    let mut state = TrustState::default();
    let bytes = plain_index(&keys.index, 7);
    accepted(accept_index(&mut state, &bytes, &keys.trusted(), NOW).unwrap());
    let (outcome, _, wrong) = accepted(accept_index(&mut state, &bytes, &keys.trusted(), NOW - 365 * DAY).unwrap());
    assert!(wrong && matches!(outcome, IndexOutcome::ClockBeforeIssue(_)));
    assert!(state.clock_looks_wrong(NOW - 365 * DAY) && !state.clock_looks_wrong(NOW));
    // After expiry the index is reported expired, and its revocations still apply.
    let (outcome, _, _) = accepted(accept_index(&mut state, &bytes, &keys.trusted(), EXPIRES).unwrap());
    assert!(matches!(outcome, IndexOutcome::Expired(_)));
}

#[test]
fn a_far_future_index_followed_by_a_correct_higher_one_leaves_a_working_catalogue() {
    let keys = Keys::new();
    let mut state = TrustState::default();
    let future = NOW + 365 * DAY;
    let far = signed_index(&keys.index, &index_value(7, future, future + 30 * DAY, &[]));
    let (outcome, _, wrong) = accepted(accept_index(&mut state, &far, &keys.trusted(), NOW).unwrap());
    assert!(wrong && matches!(outcome, IndexOutcome::ClockBeforeIssue(_)));
    let (outcome, _, wrong) = accepted(accept_index(&mut state, &plain_index(&keys.index, 8), &keys.trusted(), NOW).unwrap());
    assert!(!wrong && matches!(outcome, IndexOutcome::Usable(_)), "{outcome:?}");
}

#[test]
fn an_index_valid_for_60_days_is_refused() {
    let keys = Keys::new();
    let mut state = TrustState::default();
    let long = signed_index(&keys.index, &index_value(7, ISSUED, ISSUED + 60 * DAY, &[]));
    assert!(matches!(accept_index(&mut state, &long, &keys.trusted(), NOW).unwrap_err(), PluginError::IndexMalformed(_)));
    assert!(state.floor().is_none());
}

// ---- manifest checks (section 6; A1-C1.5, A1-03a2.2, A1-03a4.3) ----

fn with_field(key: &str, label: &str) -> String {
    manifest(EXTERNAL_ID, "1.0.0").replace("key = \"database\"\nlabel = \"Database\"", &format!("key = \"{key}\"\nlabel = \"{label}\""))
}

#[test]
fn a_field_that_looks_like_a_secret_is_refused() {
    // Keys are local ids (lower case, digits, hyphens), so the spec's `api_token` is tried as a label.
    for (key, label) in [("api-token", "API"), ("conn", "api_token"), ("phrase", "Pass Phrase"), ("key", "Private-Key"), ("pwd", "Login"), ("dsn", "DSN")] {
        let error = parse_manifest(with_field(key, label).as_bytes()).unwrap_err();
        assert!(matches!(error, PluginError::SecretLikeField(_)), "{key} / {label}: {error:?}");
    }
    for (key, label) in [("database", "Database"), ("security", "Security mode")] {
        parse_manifest(with_field(key, label).as_bytes()).unwrap_or_else(|e| panic!("{key} / {label}: {e}"));
    }
}

#[test]
fn unknown_keys_in_connection_types_and_number_ranges_are_refused() {
    let kind = manifest(EXTERNAL_ID, "1.0.0").replace("default_port = 5432", "default_port = 5432\ncredential_kind = \"cert\"");
    assert!(matches!(parse_manifest(kind.as_bytes()).unwrap_err(), PluginError::ManifestUnknownKey(_)));
    let big = manifest(EXTERNAL_ID, "1.0.0").replace("kind = \"text\"", "kind = \"number\"\nmax = 1152921504606846976");
    assert!(matches!(parse_manifest(big.as_bytes()).unwrap_err(), PluginError::ManifestUnknownKey(_)));
}

#[test]
fn a_bastion_name_needs_the_official_signature() {
    let keys = Keys::new();
    let named = |name: &str, publisher: &str| {
        let text = manifest(EXTERNAL_ID, "1.0.0").replace("name = \"PostgreSQL\"\nversion", &format!("name = \"{name}\"\nversion")).replace("publisher = \"Example Tools\"", &format!("publisher = \"{publisher}\""));
        zip(&entries_for(&text))
    };
    // Unverified "Bastion Security" is refused.
    let unverified = read_package(&named("Bastion Security", "Example Tools")).unwrap();
    assert_eq!(check_package_against_record(&unverified, None).unwrap_err(), PluginError::BastionNameNeedsOfficial);
    // An External record with publisher "bastion" (any case) is refused.
    let bytes = named("Tool", "The BASTION team");
    let record = verify_release_record(&external_record(&keys.index, EXTERNAL_ID, "1.0.0", &bytes), &keys.trusted(), &[]).unwrap();
    assert_eq!(check_package_against_record(&read_package(&bytes).unwrap(), Some(&record)).unwrap_err(), PluginError::BastionNameNeedsOfficial);
    // The Official package of section 6 (publisher "Bastion") is fine.
    let official = package_for(OFFICIAL_ID, "2.1.0");
    let record = verify_release_record(&official_record(&keys.index, &keys.official, OFFICIAL_ID, "2.1.0", &official), &keys.trusted(), &[]).unwrap();
    assert_eq!(check_package_against_record(&read_package(&official).unwrap(), Some(&record)).unwrap(), Tier::Official);
}

#[test]
fn an_http_prefix_of_slash_alone_needs_the_official_signature() {
    // Plugin API 1.1 (`docs/specs/plugins-amendment-2.md`, section 3).
    let with_paths = |paths: &str| {
        manifest(EXTERNAL_ID, "1.0.0").replace("api = \"1.0\"", "api = \"1.1\"").replace("[permissions]", &format!("[http]\npaths = {paths}\n\n[permissions]\nhttp = \"entry\""))
    };
    let root = with_paths("[\"/\"]");
    let unverified = read_package(&zip(&entries_for(&root))).unwrap();
    assert_eq!(check_package_against_record(&unverified, None).unwrap_err(), PluginError::BadValue("http.paths"));
    let narrow = with_paths("[\"/api/\"]");
    assert_eq!(check_package_against_record(&read_package(&zip(&entries_for(&narrow))).unwrap(), None).unwrap(), Tier::Unverified);
}

// ---- the plugins folder (sections 9 and 10) ----

struct Folder {
    dir: std::path::PathBuf,
    folders: PluginFolders,
}

impl Folder {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("bastion-plug04b-{}", uuid::Uuid::new_v4()));
        Folder { folders: PluginFolders::new(&dir), dir }
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn external(keys: &Keys, version: &str) -> (Vec<u8>, Vec<u8>) {
    let package = package_for(EXTERNAL_ID, version);
    let record = external_record(&keys.index, EXTERNAL_ID, version, &package);
    (package, record)
}

fn install_external(keys: &Keys, folder: &Folder, version: &str) -> Result<InstallKind, PluginError> {
    let (package, record_bytes) = external(keys, version);
    let record = verify_release_record(&record_bytes, &keys.trusted(), &[]).unwrap();
    let request = InstallRequest { package: &package, record: Some(&record), record_bytes: Some(&record_bytes), allow_unverified: false };
    install(&folder.folders, request).map(|result| result.kind)
}

#[test]
fn install_update_rollback_and_remove() {
    let keys = Keys::new();
    let folder = Folder::new();
    assert_eq!(install_external(&keys, &folder, "1.0.0").unwrap(), InstallKind::Installed);
    assert_eq!(install_external(&keys, &folder, "1.0.0").unwrap(), InstallKind::AlreadyInstalled);
    assert_eq!(install_external(&keys, &folder, "1.1.0").unwrap(), InstallKind::Updated { from: "1.0.0".into() });
    // The kept previous version can be restored; any other older version is refused.
    assert_eq!(install_external(&keys, &folder, "1.0.0").unwrap(), InstallKind::RolledBack { from: "1.1.0".into() });
    assert_eq!(install_external(&keys, &folder, "1.1.0").unwrap(), InstallKind::Updated { from: "1.0.0".into() });
    assert_eq!(install_external(&keys, &folder, "1.2.0").unwrap(), InstallKind::Updated { from: "1.1.0".into() });
    assert!(matches!(install_external(&keys, &folder, "1.0.0").unwrap_err(), PluginError::OlderVersion { .. }));
    let listed = list_installed(&folder.folders).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!((listed[0].current.version.as_str(), listed[0].previous.as_ref().unwrap().version.as_str()), ("1.2.0", "1.1.0"));
    // Only the current and the previous package stay on disk.
    let files: Vec<String> = std::fs::read_dir(folder.folders.plugins_dir().join(EXTERNAL_ID)).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert!(!files.iter().any(|f| f.starts_with("1.0.0")), "{files:?}");
    let (package, tier) = load_installed_with(&folder.folders, EXTERNAL_ID, &keys.trusted()).unwrap();
    assert_eq!((package.manifest.version, tier), (v("1.2.0"), Tier::External));
    // Remove keeps the plugin's data unless asked.
    let data = folder.folders.data_dir_of(EXTERNAL_ID).unwrap();
    std::fs::create_dir_all(&data).unwrap();
    let audit = remove(&folder.folders, EXTERNAL_ID, false).unwrap();
    assert_eq!(audit.action, "plugin.remove");
    assert!(data.exists() && list_installed(&folder.folders).unwrap().is_empty());
    assert!(matches!(remove(&folder.folders, EXTERNAL_ID, true).unwrap_err(), PluginError::NotInstalled(_)));
}

#[test]
fn unverified_needs_the_setting_and_cannot_replace_a_higher_tier() {
    let keys = Keys::new();
    let folder = Folder::new();
    let package = package_for(EXTERNAL_ID, "2.0.0");
    let request = InstallRequest { package: &package, record: None, record_bytes: None, allow_unverified: false };
    assert_eq!(install(&folder.folders, request).unwrap_err(), PluginError::UnverifiedNotAllowed);
    install_external(&keys, &folder, "1.0.0").unwrap();
    let request = InstallRequest { allow_unverified: true, ..request };
    assert_eq!(install(&folder.folders, request).unwrap_err(), PluginError::HigherTierInstalled);
}

#[test]
fn a_revoked_version_is_not_installed_and_not_loaded() {
    let keys = Keys::new();
    let folder = Folder::new();
    install_external(&keys, &folder, "1.0.0").unwrap();
    let mut value = index_value(7, ISSUED, EXPIRES, &[]);
    value["revocations"] = serde_json::json!([{ "id": EXTERNAL_ID, "from": "1.0.0", "to": "1.1.0", "reason": "Unsafe." }]);
    // Stored by "another app": install and load read it from disk, not from a caller's copy.
    accepted(accept_and_store(&folder.folders, &signed_index(&keys.index, &value), &keys.trusted(), NOW).unwrap());
    assert!(matches!(load_installed_with(&folder.folders, EXTERNAL_ID, &keys.trusted()).unwrap_err(), PluginError::Revoked { .. }));
    assert!(matches!(install_external(&keys, &folder, "1.1.0").unwrap_err(), PluginError::Revoked { .. }));
    assert_eq!(install_external(&keys, &folder, "1.2.0").unwrap(), InstallKind::Updated { from: "1.0.0".into() });
}

#[test]
fn a_package_changed_on_disk_is_refused_at_load() {
    let keys = Keys::new();
    let folder = Folder::new();
    install_external(&keys, &folder, "1.0.0").unwrap();
    // Replace the stored package with another valid package of the same id and version.
    let other = zip(&entries_for(&manifest(EXTERNAL_ID, "1.0.0").replace("New Query", "New Query 2")));
    std::fs::write(folder.folders.plugins_dir().join(EXTERNAL_ID).join("1.0.0.bastionplugin"), other).unwrap();
    assert!(matches!(load_installed_with(&folder.folders, EXTERNAL_ID, &keys.trusted()).unwrap_err(), PluginError::InstalledCopyChanged(_)));
}

#[test]
fn a_held_lock_refuses_a_second_change_at_once() {
    let keys = Keys::new();
    let folder = Folder::new();
    std::fs::create_dir_all(folder.folders.plugins_dir()).unwrap();
    // A lock file left by an app that stopped is not a lock: only a held OS lock is.
    std::fs::write(folder.folders.plugins_dir().join(".lock"), b"left over").unwrap();
    install_external(&keys, &folder, "1.0.0").unwrap();
    let held = std::fs::OpenOptions::new().write(true).open(folder.folders.plugins_dir().join(".lock")).unwrap();
    held.lock().unwrap();
    assert_eq!(install_external(&keys, &folder, "1.1.0").unwrap_err(), PluginError::FolderBusy);
    drop(held);
    install_external(&keys, &folder, "1.1.0").unwrap();
}

#[test]
fn racing_threads_never_hold_the_folder_lock_together() {
    let keys = Keys::new();
    let folder = Folder::new();
    // Eight threads store indexes 1..=80 in mixed order; each store is serialised, so the floor
    // ends at the highest sequence any of them stored and no write is lost.
    let stored = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for t in 0..8u64 {
            let (keys, folder, stored) = (&keys, &folder, &stored);
            scope.spawn(move || {
                for i in 0..10u64 {
                    let sequence = 1 + (i * 8 + (t * 3 + i) % 8);
                    loop {
                        match accept_and_store(&folder.folders, &plain_index(&keys.index, sequence), &keys.trusted(), NOW) {
                            Err(PluginError::FolderBusy) => std::thread::yield_now(),
                            Ok(IndexDecision::Accepted { .. }) => break stored.lock().unwrap().push(sequence),
                            Ok(IndexDecision::Refused(_)) => break,
                            Err(e) => panic!("{e}"),
                        }
                    }
                }
            });
        }
    });
    let highest = *stored.lock().unwrap().iter().max().unwrap();
    assert_eq!(TrustState::load(&folder.folders.trust_path()).unwrap().floor().unwrap().sequence, highest);
    // Two handles on the lock file conflict, also inside one process.
    let a = std::fs::OpenOptions::new().write(true).open(folder.folders.plugins_dir().join(".lock")).unwrap();
    a.lock().unwrap();
    assert_eq!(install_external(&keys, &folder, "1.0.0").unwrap_err(), PluginError::FolderBusy);
}

#[test]
fn the_same_version_from_a_different_package_has_its_own_refusal() {
    let keys = Keys::new();
    let folder = Folder::new();
    install_external(&keys, &folder, "1.0.0").unwrap();
    // Same id and version, different bytes: a TOML comment changes the hash only.
    let other = zip(&entries_for(&format!("{}\n# rebuilt\n", manifest(EXTERNAL_ID, "1.0.0"))));
    let record_bytes = external_record(&keys.index, EXTERNAL_ID, "1.0.0", &other);
    let record = verify_release_record(&record_bytes, &keys.trusted(), &[]).unwrap();
    let request = InstallRequest { package: &other, record: Some(&record), record_bytes: Some(&record_bytes), allow_unverified: false };
    assert!(matches!(install(&folder.folders, request).unwrap_err(), PluginError::SameVersionDifferentPackage { .. }));
}

#[test]
fn a_stale_app_cannot_lower_the_floor_or_drop_a_revocation() {
    let keys = Keys::new();
    let folder = Folder::new();
    // App B read the state when the floor was 8, then app A stored index 10 with a revocation.
    accepted(accept_and_store(&folder.folders, &plain_index(&keys.index, 8), &keys.trusted(), NOW).unwrap());
    let revoking = signed_index(&keys.index, &{
        let mut v = index_value(10, ISSUED, EXPIRES, &[]);
        v["revocations"] = serde_json::json!([{ "id": EXTERNAL_ID, "from": "1.0.0", "to": "1.0.0", "reason": "bad build" }]);
        v
    });
    accepted(accept_and_store(&folder.folders, &revoking, &keys.trusted(), NOW).unwrap());
    // B now offers index 9, valid against its old view: the store re-reads the file and refuses it.
    assert_eq!(refused(accept_and_store(&folder.folders, &plain_index(&keys.index, 9), &keys.trusted(), NOW).unwrap()), IndexRefusal::RolledBack { sequence: 9, floor: 10 });
    let state = TrustState::load(&folder.folders.trust_path()).unwrap();
    assert_eq!(state.floor().unwrap().sequence, 10);
    assert!(state.revocation_for(EXTERNAL_ID, &v("1.0.0")).is_some());
}

#[test]
fn a_damaged_stored_entry_is_damage_not_skipped() {
    let keys = Keys::new();
    let folder = Folder::new();
    accepted(accept_and_store(&folder.folders, &plain_index(&keys.index, 8), &keys.trusted(), NOW).unwrap());
    let path = folder.folders.trust_path();
    let good: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let bad_edits: Vec<(&str, serde_json::Value)> = vec![
        ("revoked_index_keys", serde_json::json!(["zz"])),
        ("revocations", serde_json::json!([{ "id": EXTERNAL_ID, "from": "x", "to": "1.0.0", "reason": "r" }])),
        ("revocations", serde_json::json!([{ "id": EXTERNAL_ID, "from": "2.0.0", "to": "1.0.0", "reason": "r" }])),
        ("revocations", serde_json::json!([{ "id": "../x", "from": "1.0.0", "to": "1.0.0", "reason": "r" }])),
        ("highest_by_key", serde_json::json!({ "nothex": 3 })),
    ];
    for (field, value) in bad_edits {
        let mut edited = good.clone();
        edited[field] = value;
        std::fs::write(&path, serde_json::to_vec(&edited).unwrap()).unwrap();
        assert!(matches!(TrustState::load(&path), Err(PluginError::TrustStateDamaged(_))), "{field}");
    }
    let mut edited = good.clone();
    edited["floor"]["signer"] = serde_json::json!("short");
    std::fs::write(&path, serde_json::to_vec(&edited).unwrap()).unwrap();
    assert!(matches!(TrustState::load(&path), Err(PluginError::TrustStateDamaged(_))));
}

#[test]
fn a_damaged_installed_file_never_names_a_file_outside_the_plugin() {
    let keys = Keys::new();
    let folder = Folder::new();
    install_external(&keys, &folder, "1.0.0").unwrap();
    let path = folder.folders.plugins_dir().join(EXTERNAL_ID).join("installed.json");
    let good: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for (pointer, value) in [("/current/version", "../../x"), ("/current/version", "01.0.0"), ("/id", "com.example.other"), ("/current/tier", "gold"), ("/current/sha256", "ABC")] {
        let mut edited = good.clone();
        *edited.pointer_mut(pointer).unwrap() = serde_json::json!(value);
        std::fs::write(&path, serde_json::to_vec(&edited).unwrap()).unwrap();
        assert!(matches!(install_external(&keys, &folder, "1.1.0"), Err(PluginError::InstalledCopyChanged(_))), "{pointer}={value}");
        assert!(matches!(list_installed(&folder.folders), Err(PluginError::InstalledCopyChanged(_))), "{pointer}");
    }
}

// ---- SEC-5: the tier comes from the stored signed record, never from installed.json ----

fn edit_tier(folder: &Folder, tier: &str) {
    let path = folder.folders.plugins_dir().join(EXTERNAL_ID).join("installed.json");
    let mut value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["current"]["tier"] = serde_json::json!(tier);
    std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

#[test]
fn sec5_a_tampered_installed_json_cannot_raise_the_tier() {
    let keys = Keys::new();
    let folder = Folder::new();
    install_external(&keys, &folder, "1.0.0").unwrap();
    edit_tier(&folder, "official");
    let (_, tier) = load_installed_with(&folder.folders, EXTERNAL_ID, &keys.trusted()).unwrap();
    assert_eq!(tier, Tier::External, "an edited installed.json must not make a plugin Official");
}

#[test]
fn sec5_an_unverified_install_stays_unverified_after_an_edit() {
    let keys = Keys::new();
    let folder = Folder::new();
    let package = package_for(EXTERNAL_ID, "1.0.0");
    install(&folder.folders, InstallRequest { package: &package, record: None, record_bytes: None, allow_unverified: true }).unwrap();
    edit_tier(&folder, "official");
    assert_eq!(load_installed_with(&folder.folders, EXTERNAL_ID, &keys.trusted()).unwrap().1, Tier::Unverified);
    edit_tier(&folder, "external");
    assert_eq!(load_installed_with(&folder.folders, EXTERNAL_ID, &keys.trusted()).unwrap().1, Tier::Unverified);
}

#[test]
fn sec5_a_record_planted_after_install_cannot_raise_the_tier() {
    // A valid Official record for this exact package, dropped in by hand: the tier is never
    // higher than installed.json records, so it stays Unverified.
    let keys = Keys::new();
    let folder = Folder::new();
    let package = package_for(EXTERNAL_ID, "1.0.0");
    install(&folder.folders, InstallRequest { package: &package, record: None, record_bytes: None, allow_unverified: true }).unwrap();
    let record = external_record(&keys.index, EXTERNAL_ID, "1.0.0", &package);
    std::fs::write(folder.folders.plugins_dir().join(EXTERNAL_ID).join("1.0.0.sig"), record).unwrap();
    assert_eq!(load_installed_with(&folder.folders, EXTERNAL_ID, &keys.trusted()).unwrap().1, Tier::Unverified);
}

#[test]
fn sec5_a_record_that_no_longer_verifies_drops_to_unverified() {
    let keys = Keys::new();
    let folder = Folder::new();
    install_external(&keys, &folder, "1.0.0").unwrap();
    // Removed, damaged, or signed by a key the app no longer trusts: Unverified.
    let sig = folder.folders.plugins_dir().join(EXTERNAL_ID).join("1.0.0.sig");
    let good = std::fs::read(&sig).unwrap();
    let other = Keys::new();
    assert_eq!(load_installed_with(&folder.folders, EXTERNAL_ID, &other.trusted()).unwrap().1, Tier::Unverified);
    let mut bad = good.clone();
    let last = bad.len() - 3;
    bad[last] ^= 1;
    std::fs::write(&sig, &bad).unwrap();
    assert_eq!(load_installed_with(&folder.folders, EXTERNAL_ID, &keys.trusted()).unwrap().1, Tier::Unverified);
    std::fs::remove_file(&sig).unwrap();
    assert_eq!(load_installed_with(&folder.folders, EXTERNAL_ID, &keys.trusted()).unwrap().1, Tier::Unverified);
    // The production entry point has no pinned keys yet (PLUG-15): nothing loads above Unverified.
    std::fs::write(&sig, &good).unwrap();
    assert_eq!(load_installed(&folder.folders, EXTERNAL_ID).unwrap().1, Tier::Unverified);
}

#[cfg(unix)]
#[test]
fn sec5_symlinks_in_the_plugin_folder_are_refused() {
    let keys = Keys::new();
    let folder = Folder::new();
    install_external(&keys, &folder, "1.0.0").unwrap();
    let dir = folder.folders.plugins_dir().join(EXTERNAL_ID);
    for name in ["1.0.0.sig", "1.0.0.bastionplugin", "installed.json"] {
        let real = dir.join(format!("{name}.real"));
        std::fs::rename(dir.join(name), &real).unwrap();
        std::os::unix::fs::symlink(&real, dir.join(name)).unwrap();
        assert!(matches!(load_installed_with(&folder.folders, EXTERNAL_ID, &keys.trusted()).unwrap_err(), PluginError::InstalledCopyChanged(_)), "{name}");
        std::fs::remove_file(dir.join(name)).unwrap();
        std::fs::rename(&real, dir.join(name)).unwrap();
    }
    assert_eq!(load_installed_with(&folder.folders, EXTERNAL_ID, &keys.trusted()).unwrap().1, Tier::External);
}
