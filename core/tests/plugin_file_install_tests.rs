//! PLUG-12: installing a package file with the signed release record beside it.
//! Valid Official and External records, a tampered package, a tampered record, a record signed
//! by keys that are not pinned, and a record from a revoked index key.
#[path = "fixtures/plugin/support.rs"]
mod support;

use std::path::{Path, PathBuf};

use bastion_core::plugin::{accept_and_store, install_file, list_installed, pinned_keys, PluginError, PluginFolders, Tier, TrustedKeys};
use ed25519_dalek::SigningKey;
use support::*;

struct Setup {
    _dir: tempfile::TempDir,
    folders: PluginFolders,
    drop: PathBuf,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let folders = PluginFolders::new(dir.path().join("data"));
    let drop = dir.path().join("downloads");
    std::fs::create_dir_all(&drop).unwrap();
    Setup { _dir: dir, folders, drop }
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

struct Keys {
    index: SigningKey,
    official: SigningKey,
    index_public: [[u8; 32]; 1],
    official_public: [[u8; 32]; 1],
}

impl Keys {
    fn new() -> Self {
        let (index, official) = (new_key(), new_key());
        let (index_public, official_public) = ([public(&index)], [public(&official)]);
        Keys { index, official, index_public, official_public }
    }
    fn trusted(&self) -> TrustedKeys<'_> {
        TrustedKeys { index: &self.index_public, official: &self.official_public }
    }
}

fn tier_of(s: &Setup, id: &str) -> String {
    list_installed(&s.folders).unwrap().into_iter().find(|p| p.id == id).unwrap().current.tier
}

#[test]
fn a_signed_official_pack_installs_as_official_with_the_unverified_setting_off() {
    let (s, k) = (setup(), Keys::new());
    let package = package_for(OFFICIAL_ID, "1.0.0");
    let path = write(&s.drop, "postgres.bastionplugin", &package);
    write(&s.drop, "postgres.sig", &official_record(&k.index, &k.official, OFFICIAL_ID, "1.0.0", &package));
    let result = install_file(&s.folders, &path, &k.trusted(), false).unwrap();
    assert_eq!(result.tier, Tier::Official);
    assert_eq!(tier_of(&s, OFFICIAL_ID), "official");
}

#[test]
fn the_catalogue_record_name_is_found_too() {
    let (s, k) = (setup(), Keys::new());
    let package = package_for(EXTERNAL_ID, "1.0.0");
    let path = write(&s.drop, "tool.bastionplugin", &package);
    write(&s.drop, &format!("{EXTERNAL_ID}-1.0.0.sig"), &external_record(&k.index, EXTERNAL_ID, "1.0.0", &package));
    assert_eq!(install_file(&s.folders, &path, &k.trusted(), false).unwrap().tier, Tier::External);
}

#[test]
fn an_unsigned_official_id_is_refused_whatever_the_setting() {
    let (s, k) = (setup(), Keys::new());
    let path = write(&s.drop, "postgres.bastionplugin", &package_for(OFFICIAL_ID, "1.0.0"));
    assert!(matches!(install_file(&s.folders, &path, &k.trusted(), true), Err(PluginError::ReservedIdNeedsOfficial)));
    assert!(list_installed(&s.folders).unwrap().is_empty());
}

#[test]
fn an_unsigned_external_pack_needs_the_unverified_setting() {
    let (s, k) = (setup(), Keys::new());
    let path = write(&s.drop, "tool.bastionplugin", &package_for(EXTERNAL_ID, "1.0.0"));
    assert!(matches!(install_file(&s.folders, &path, &k.trusted(), false), Err(PluginError::UnverifiedNotAllowed)));
    assert_eq!(install_file(&s.folders, &path, &k.trusted(), true).unwrap().tier, Tier::Unverified);
}

#[test]
fn a_tampered_package_is_refused_and_never_falls_back_to_unverified() {
    let (s, k) = (setup(), Keys::new());
    let package = package_for(EXTERNAL_ID, "1.0.0");
    write(&s.drop, "tool.sig", &external_record(&k.index, EXTERNAL_ID, "1.0.0", &package));
    // The same id and version, one changed word in the manifest: other bytes.
    let changed = manifest(EXTERNAL_ID, "1.0.0").replacen("Query", "Probe", 1);
    let tampered = zip(&entries_for(&changed));
    assert_ne!(tampered, package);
    let path = write(&s.drop, "tool.bastionplugin", &tampered);
    let err = install_file(&s.folders, &path, &k.trusted(), true).unwrap_err();
    assert!(matches!(err, PluginError::PackageHashMismatch | PluginError::PackageSizeMismatch), "{err:?}");
    assert!(list_installed(&s.folders).unwrap().is_empty());
}

#[test]
fn a_tampered_record_is_refused() {
    let (s, k) = (setup(), Keys::new());
    let package = package_for(OFFICIAL_ID, "1.0.0");
    let path = write(&s.drop, "postgres.bastionplugin", &package);
    let good = official_record(&k.index, &k.official, OFFICIAL_ID, "1.0.0", &package);
    let mut value: serde_json::Value = serde_json::from_slice(&good).unwrap();
    // Flip one bit of the signed payload.
    let payload = value["payload"].as_str().unwrap().to_string();
    let mut raw = base64_decode(&payload);
    raw[10] ^= 1;
    value["payload"] = serde_json::Value::String(base64_encode(&raw));
    write(&s.drop, "postgres.sig", &serde_json::to_vec(&value).unwrap());
    assert!(matches!(install_file(&s.folders, &path, &k.trusted(), true), Err(PluginError::SignatureInvalid(_))));
    assert!(list_installed(&s.folders).unwrap().is_empty());
}

#[test]
fn a_record_signed_by_other_keys_is_refused() {
    let (s, k, stranger) = (setup(), Keys::new(), Keys::new());
    let package = package_for(OFFICIAL_ID, "1.0.0");
    let path = write(&s.drop, "postgres.bastionplugin", &package);
    write(&s.drop, "postgres.sig", &official_record(&stranger.index, &stranger.official, OFFICIAL_ID, "1.0.0", &package));
    assert!(matches!(install_file(&s.folders, &path, &k.trusted(), true), Err(PluginError::SignatureUntrustedKey(_))));
}

#[test]
fn an_official_claim_without_the_official_key_is_refused() {
    let (s, k, stranger) = (setup(), Keys::new(), Keys::new());
    let package = package_for(OFFICIAL_ID, "1.0.0");
    let path = write(&s.drop, "postgres.bastionplugin", &package);
    // A real index key, but the official signature comes from an unpinned key.
    write(&s.drop, "postgres.sig", &official_record(&k.index, &stranger.official, OFFICIAL_ID, "1.0.0", &package));
    assert!(install_file(&s.folders, &path, &k.trusted(), true).is_err());
    assert!(list_installed(&s.folders).unwrap().is_empty());
}

#[test]
fn a_record_from_a_revoked_index_key_is_refused() {
    let (s, k) = (setup(), Keys::new());
    let spare = new_key();
    let index_keys = [public(&k.index), public(&spare)];
    let trusted = TrustedKeys { index: &index_keys, official: &k.official_public };
    // The spare key's index revokes the active key.
    let mut value = index_value(1, NOW - 60, NOW + 86_400, &[]);
    value["revoked_keys"] = serde_json::json!([hex::encode(public(&k.index))]);
    accept_and_store(&s.folders, &signed_index(&spare, &value), &trusted, NOW).unwrap();
    let package = package_for(EXTERNAL_ID, "1.0.0");
    let path = write(&s.drop, "tool.bastionplugin", &package);
    write(&s.drop, "tool.sig", &external_record(&k.index, EXTERNAL_ID, "1.0.0", &package));
    assert!(matches!(install_file(&s.folders, &path, &trusted, true), Err(PluginError::SignatureRevokedKey(_))));
}

#[test]
fn an_oversized_record_is_refused_unread() {
    let (s, k) = (setup(), Keys::new());
    let path = write(&s.drop, "tool.bastionplugin", &package_for(EXTERNAL_ID, "1.0.0"));
    write(&s.drop, "tool.sig", &vec![b' '; 64 * 1024]);
    assert!(matches!(install_file(&s.folders, &path, &k.trusted(), true), Err(PluginError::RecordTooLarge)));
}

#[test]
fn the_pinned_keys_refuse_a_record_made_with_test_keys() {
    let (s, k) = (setup(), Keys::new());
    let package = package_for(OFFICIAL_ID, "1.0.0");
    let path = write(&s.drop, "postgres.bastionplugin", &package);
    write(&s.drop, "postgres.sig", &official_record(&k.index, &k.official, OFFICIAL_ID, "1.0.0", &package));
    assert!(install_file(&s.folders, &path, &pinned_keys(), true).is_err());
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).unwrap()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
