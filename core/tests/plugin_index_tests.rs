//! PLUG-04a: release records, tiers and the signed index.
//! Spec: docs/specs/plugins.md, sections 7 and 9.
#[path = "fixtures/plugin/support.rs"]
mod support;

use std::time::{Duration, Instant};

use bastion_core::plugin::{is_revoked, verify_index, verify_release_record, IndexOutcome, PluginError, Purpose, Tier, TrustedKeys, Version, MAX_INDEX_BYTES, MAX_RECORD_BYTES};
use ed25519_dalek::SigningKey;
use support::*;

const DAY: u64 = 24 * 3600;
const ISSUED: u64 = NOW - DAY;
const EXPIRES: u64 = ISSUED + 30 * DAY;

/// One index key, one spare index key and the official key, as section 9 pins them.
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

fn version(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ---- release record ----

#[test]
fn a_good_official_record_needs_both_signatures_and_gets_the_official_tier() {
    let keys = Keys::new();
    let package = package_for(OFFICIAL_ID, "1.0.0");
    let record = verify_release_record(&official_record(&keys.index, &keys.official, OFFICIAL_ID, "1.0.0", &package), &keys.trusted(), &[]).unwrap();
    assert_eq!(record.tier, Tier::Official);
    assert_eq!(record.id, OFFICIAL_ID);
    assert_eq!(record.version, version("1.0.0"));
    assert_eq!(record.size, package.len() as u64);
    assert_eq!(record.source_commit, "0123456789abcdef0123456789abcdef01234567");
    // The spare index key signs as well as the active one.
    assert!(verify_release_record(&official_record(&keys.spare, &keys.official, OFFICIAL_ID, "1.0.0", &package), &keys.trusted(), &[]).is_ok());
}

#[test]
fn a_good_external_record_needs_the_index_key_alone() {
    let keys = Keys::new();
    let package = good_package();
    let record = verify_release_record(&external_record(&keys.index, EXTERNAL_ID, "1.0.0", &package), &keys.trusted(), &[]).unwrap();
    assert_eq!(record.tier, Tier::External);
    assert!(record.permissions.network_entry && record.permissions.files_save && !record.permissions.files_open);
}

#[test]
fn an_official_record_without_the_official_signature_is_refused() {
    let keys = Keys::new();
    let payload = to_bytes(&record_value(EXTERNAL_ID, "1.0.0", "official", &good_package()));
    let bytes = envelope(&payload, &[sig(&keys.index, Purpose::ReleaseRecord)]);
    assert_eq!(verify_release_record(&bytes, &keys.trusted(), &[]).unwrap_err(), PluginError::SignatureMissing(Purpose::Official));
    // Two index keys do not add up to the official key.
    let bytes = envelope(&payload, &[sig(&keys.index, Purpose::ReleaseRecord), sig(&keys.spare, Purpose::ReleaseRecord)]);
    assert_eq!(verify_release_record(&bytes, &keys.trusted(), &[]).unwrap_err(), PluginError::SignatureMissing(Purpose::Official));
    // Nor does an index key signing with the official tag.
    let bytes = envelope(&payload, &[sig(&keys.index, Purpose::ReleaseRecord), sig(&keys.index, Purpose::Official)]);
    assert_eq!(verify_release_record(&bytes, &keys.trusted(), &[]).unwrap_err(), PluginError::SignatureUntrustedKey(Purpose::Official));
}

#[test]
fn an_official_signature_alone_is_not_enough() {
    let keys = Keys::new();
    let payload = to_bytes(&record_value(OFFICIAL_ID, "1.0.0", "official", &good_package()));
    let bytes = envelope(&payload, &[sig(&keys.official, Purpose::Official)]);
    assert_eq!(verify_release_record(&bytes, &keys.trusted(), &[]).unwrap_err(), PluginError::SignatureMissing(Purpose::ReleaseRecord));
    // The official key is not an index key, whatever tag it signs with.
    let bytes = envelope(&payload, &[sig(&keys.official, Purpose::ReleaseRecord), sig(&keys.official, Purpose::Official)]);
    assert_eq!(verify_release_record(&bytes, &keys.trusted(), &[]).unwrap_err(), PluginError::SignatureUntrustedKey(Purpose::ReleaseRecord));
}

#[test]
fn a_signature_made_for_another_purpose_is_refused() {
    let keys = Keys::new();
    let payload = to_bytes(&record_value(EXTERNAL_ID, "1.0.0", "external", &good_package()));
    // Made with the index tag, presented as a release-record signature.
    let relabelled = Sig { key: &keys.index, signed_for: Purpose::Index, label: Purpose::ReleaseRecord.label() };
    assert_eq!(verify_release_record(&envelope(&payload, &[relabelled]), &keys.trusted(), &[]).unwrap_err(), PluginError::SignatureWrongPurpose(Purpose::ReleaseRecord));
    // Made with the index tag and honestly labelled: still not a release-record signature.
    assert_eq!(verify_release_record(&envelope(&payload, &[sig(&keys.index, Purpose::Index)]), &keys.trusted(), &[]).unwrap_err(), PluginError::SignatureWrongPurpose(Purpose::ReleaseRecord));
    // A real release-record signature under the wrong label does not count either.
    let mislabelled = Sig { key: &keys.index, signed_for: Purpose::ReleaseRecord, label: "index" };
    assert_eq!(verify_release_record(&envelope(&payload, &[mislabelled]), &keys.trusted(), &[]).unwrap_err(), PluginError::SignatureWrongPurpose(Purpose::ReleaseRecord));
    // The official key's signature, made with the release-record tag, cannot serve as the official one.
    let official_payload = to_bytes(&record_value(EXTERNAL_ID, "1.0.0", "official", &good_package()));
    let wrong_tag = Sig { key: &keys.official, signed_for: Purpose::ReleaseRecord, label: Purpose::Official.label() };
    let bytes = envelope(&official_payload, &[sig(&keys.index, Purpose::ReleaseRecord), wrong_tag]);
    assert_eq!(verify_release_record(&bytes, &keys.trusted(), &[]).unwrap_err(), PluginError::SignatureWrongPurpose(Purpose::Official));
    // An unknown label is refused as a malformed envelope.
    let unknown = Sig { key: &keys.index, signed_for: Purpose::ReleaseRecord, label: "anything" };
    assert!(matches!(verify_release_record(&envelope(&payload, &[unknown]), &keys.trusted(), &[]).unwrap_err(), PluginError::EnvelopeMalformed(_)));
}

#[test]
fn a_record_changed_after_signing_is_refused() {
    let keys = Keys::new();
    let package = good_package();
    let good = envelope_value(&to_bytes(&record_value(EXTERNAL_ID, "1.0.0", "external", &package)), &[sig(&keys.index, Purpose::ReleaseRecord)]);
    // Keep the signature, swap the payload for one with more permissions.
    let mut other = record_value(EXTERNAL_ID, "1.0.0", "external", &package);
    other["permissions"]["files"] = serde_json::json!(["save", "open"]);
    let mut tampered = good.clone();
    tampered["payload"] = base64_of(&to_bytes(&other)).into();
    assert_eq!(verify_release_record(&to_bytes(&tampered), &keys.trusted(), &[]).unwrap_err(), PluginError::SignatureInvalid(Purpose::ReleaseRecord));
    // One byte of white space added to the payload is a change too: the signature is over exact bytes.
    let mut spaced = to_bytes(&record_value(EXTERNAL_ID, "1.0.0", "external", &package));
    spaced.push(b' ');
    let mut padded = good;
    padded["payload"] = base64_of(&spaced).into();
    assert_eq!(verify_release_record(&to_bytes(&padded), &keys.trusted(), &[]).unwrap_err(), PluginError::SignatureInvalid(Purpose::ReleaseRecord));
}

#[test]
fn a_signature_by_an_untrusted_key_is_refused() {
    let keys = Keys::new();
    let stranger = new_key();
    let payload = to_bytes(&record_value(EXTERNAL_ID, "1.0.0", "external", &good_package()));
    let bytes = envelope(&payload, &[sig(&stranger, Purpose::ReleaseRecord)]);
    assert_eq!(verify_release_record(&bytes, &keys.trusted(), &[]).unwrap_err(), PluginError::SignatureUntrustedKey(Purpose::ReleaseRecord));
    // Claiming a trusted key's id does not help.
    let mut forged = envelope_value(&payload, &[sig(&stranger, Purpose::ReleaseRecord)]);
    forged["signatures"][0]["keyid"] = bastion_core::plugin::key_id(&public(&keys.index)).into();
    assert_eq!(verify_release_record(&to_bytes(&forged), &keys.trusted(), &[]).unwrap_err(), PluginError::SignatureInvalid(Purpose::ReleaseRecord));
    // With no trusted keys at all, nothing verifies.
    let good = external_record(&keys.index, EXTERNAL_ID, "1.0.0", &good_package());
    assert!(verify_release_record(&good, &TrustedKeys { index: &[], official: &[] }, &[]).is_err());
}

#[test]
fn a_reserved_id_signed_only_by_the_index_key_is_refused() {
    let keys = Keys::new();
    let package = package_for(OFFICIAL_ID, "1.0.0");
    assert_eq!(verify_release_record(&external_record(&keys.index, OFFICIAL_ID, "1.0.0", &package), &keys.trusted(), &[]).unwrap_err(), PluginError::ReservedIdNeedsOfficial);
    // Claiming the official tier in the record changes nothing: the tier comes from signatures.
    let claimed = envelope(&to_bytes(&record_value(OFFICIAL_ID, "1.0.0", "official", &package)), &[sig(&keys.index, Purpose::ReleaseRecord)]);
    assert_eq!(verify_release_record(&claimed, &keys.trusted(), &[]).unwrap_err(), PluginError::ReservedIdNeedsOfficial);
    for id in ["dev.bastion.x", "dev.bastion"] {
        let bytes = external_record(&keys.index, id, "1.0.0", &package);
        assert_eq!(verify_release_record(&bytes, &keys.trusted(), &[]).unwrap_err(), PluginError::ReservedIdNeedsOfficial, "{id}");
    }
    // A look-alike outside the reserved name is an ordinary External id.
    assert!(verify_release_record(&external_record(&keys.index, "dev.bastionx.tool", "1.0.0", &package), &keys.trusted(), &[]).is_ok());
}

#[test]
fn the_tier_a_record_states_must_agree_with_its_signatures() {
    let keys = Keys::new();
    let payload = to_bytes(&record_value(EXTERNAL_ID, "1.0.0", "external", &good_package()));
    let bytes = envelope(&payload, &[sig(&keys.index, Purpose::ReleaseRecord), sig(&keys.official, Purpose::Official)]);
    assert_eq!(verify_release_record(&bytes, &keys.trusted(), &[]).unwrap_err(), PluginError::RecordTierMismatch);
    let unverified = to_bytes(&record_value(EXTERNAL_ID, "1.0.0", "unverified", &good_package()));
    assert!(matches!(verify_release_record(&envelope(&unverified, &[sig(&keys.index, Purpose::ReleaseRecord)]), &keys.trusted(), &[]).unwrap_err(), PluginError::RecordMalformed(_)));
}

#[test]
fn a_record_signed_by_a_revoked_index_key_is_refused() {
    let keys = Keys::new();
    let bytes = external_record(&keys.index, EXTERNAL_ID, "1.0.0", &good_package());
    assert_eq!(verify_release_record(&bytes, &keys.trusted(), &[public(&keys.index)]).unwrap_err(), PluginError::SignatureRevokedKey(Purpose::ReleaseRecord));
    assert!(verify_release_record(&bytes, &keys.trusted(), &[public(&keys.spare)]).is_ok());
}

#[test]
fn a_malformed_or_oversized_record_is_refused() {
    let keys = Keys::new();
    let package = good_package();
    let signed = |value: &serde_json::Value| envelope(&to_bytes(value), &[sig(&keys.index, Purpose::ReleaseRecord)]);
    let error = |value: &serde_json::Value| verify_release_record(&signed(value), &keys.trusted(), &[]).unwrap_err();

    let mut value = record_value(EXTERNAL_ID, "1.0.0", "external", &package);
    value["extra"] = 1.into();
    assert!(matches!(error(&value), PluginError::RecordMalformed(_)), "an unknown key");
    for (key, bad) in [
        ("schema", serde_json::json!(2)),
        ("id", serde_json::json!("Not.An.Id")),
        ("version", serde_json::json!("1.0")),
        ("sha256", serde_json::json!("abc")),
        ("sha256", serde_json::json!("G".repeat(64))),
        ("size", serde_json::json!(0)),
        ("size", serde_json::json!(1u64 << 40)),
        ("api", serde_json::json!({ "min": "1.2", "max": "1.1" })),
        ("permissions", serde_json::json!({ "network": "any" })),
        ("source", serde_json::json!({ "repository": "http://example.test/x", "commit": "0123456789abcdef0123456789abcdef01234567" })),
        ("source", serde_json::json!({ "repository": "https://example.test/x", "commit": "main" })),
    ] {
        let mut value = record_value(EXTERNAL_ID, "1.0.0", "external", &package);
        value[key] = bad.clone();
        assert!(matches!(error(&value), PluginError::RecordMalformed(_)), "{key} = {bad}");
    }

    assert!(matches!(verify_release_record(b"{}", &keys.trusted(), &[]).unwrap_err(), PluginError::EnvelopeMalformed(_)));
    assert!(matches!(verify_release_record(b"", &keys.trusted(), &[]).unwrap_err(), PluginError::EnvelopeMalformed(_)));
    assert_eq!(verify_release_record(&vec![b' '; MAX_RECORD_BYTES + 1], &keys.trusted(), &[]).unwrap_err(), PluginError::RecordTooLarge);
    // Errors about a record do not echo it at length.
    let mut value = record_value(EXTERNAL_ID, "1.0.0", "external", &package);
    value["z".repeat(400)] = 1.into();
    let message = error(&value).to_string();
    assert!(!message.contains(&"z".repeat(65)), "{message}");
}

// ---- index ----

fn index_with_records(keys: &Keys) -> serde_json::Value {
    let external = external_record(&keys.index, EXTERNAL_ID, "1.0.0", &good_package());
    let official = official_record(&keys.index, &keys.official, OFFICIAL_ID, "2.1.0", &package_for(OFFICIAL_ID, "2.1.0"));
    index_value(7, ISSUED, EXPIRES, &[external, official])
}

fn outcome(keys: &Keys, bytes: &[u8], highest_seen: u64, now: u64) -> IndexOutcome {
    verify_index(bytes, &keys.trusted(), &[], highest_seen, now).unwrap()
}

#[test]
fn a_good_index_is_usable_and_holds_verified_records() {
    let keys = Keys::new();
    let bytes = signed_index(&keys.index, &index_with_records(&keys));
    let IndexOutcome::Usable(index) = outcome(&keys, &bytes, 0, NOW) else { panic!("expected a usable index") };
    assert_eq!((index.sequence, index.issued, index.expires), (7, ISSUED, EXPIRES));
    assert_eq!(index.records.len(), 2);
    assert_eq!(index.record(EXTERNAL_ID, &version("1.0.0")).unwrap().tier, Tier::External);
    assert_eq!(index.record(OFFICIAL_ID, &version("2.1.0")).unwrap().tier, Tier::Official);
    assert!(index.record(OFFICIAL_ID, &version("2.1.1")).is_none());
    assert!(index.revoked_index_keys.is_empty());
    // The spare index key signs an index as well.
    assert!(matches!(outcome(&keys, &signed_index(&keys.spare, &index_with_records(&keys)), 0, NOW), IndexOutcome::Usable(_)));
}

#[test]
fn an_index_over_4_mib_is_refused_before_parsing() {
    let keys = Keys::new();
    assert_eq!(verify_index(&vec![b'['; MAX_INDEX_BYTES + 1], &keys.trusted(), &[], 0, NOW).unwrap_err(), PluginError::IndexTooLarge);
    assert!(verify_index(&vec![b' '; MAX_INDEX_BYTES], &keys.trusted(), &[], 0, NOW).unwrap_err() != PluginError::IndexTooLarge);
}

#[test]
fn an_expired_index_is_reported_as_expired_and_keeps_its_revocations() {
    let keys = Keys::new();
    let mut value = index_with_records(&keys);
    value["revocations"] = serde_json::json!([{ "id": EXTERNAL_ID, "from": "1.0.0", "to": "1.0.0", "reason": "malware" }]);
    let bytes = signed_index(&keys.index, &value);
    assert!(matches!(outcome(&keys, &bytes, 0, EXPIRES - 1), IndexOutcome::Usable(_)), "the last second before expiry");
    for now in [EXPIRES, EXPIRES + 1, EXPIRES + 400 * DAY] {
        let IndexOutcome::Expired(index) = outcome(&keys, &bytes, 0, now) else { panic!("expected an expired index at {now}") };
        assert!(is_revoked(&index, EXTERNAL_ID, &version("1.0.0")).is_some(), "revocations still apply");
        assert_eq!(index.records.len(), 2, "installed plugins can still be checked against their records");
    }
}

#[test]
fn a_sequence_below_the_highest_seen_is_a_rollback_and_an_equal_one_is_accepted() {
    let keys = Keys::new();
    let bytes = signed_index(&keys.index, &index_with_records(&keys));
    assert_eq!(outcome(&keys, &bytes, 8, NOW), IndexOutcome::RolledBack { sequence: 7, highest_seen: 8 });
    assert_eq!(outcome(&keys, &bytes, u64::MAX, NOW), IndexOutcome::RolledBack { sequence: 7, highest_seen: u64::MAX });
    assert!(matches!(outcome(&keys, &bytes, 7, NOW), IndexOutcome::Usable(_)), "the same index again");
    assert!(matches!(outcome(&keys, &bytes, 6, NOW), IndexOutcome::Usable(_)));
    // A rolled-back index is refused even when it has also expired.
    assert!(matches!(outcome(&keys, &bytes, 8, EXPIRES + 1), IndexOutcome::RolledBack { .. }));
}

#[test]
fn a_clock_before_the_issue_time_is_reported_as_a_wrong_clock() {
    let keys = Keys::new();
    let bytes = signed_index(&keys.index, &index_with_records(&keys));
    assert!(matches!(outcome(&keys, &bytes, 0, ISSUED), IndexOutcome::Usable(_)), "the issue second itself");
    let IndexOutcome::ClockBeforeIssue(index) = outcome(&keys, &bytes, 0, ISSUED - 1) else { panic!("expected a clock warning") };
    assert_eq!(index.sequence, 7);
    assert!(matches!(outcome(&keys, &bytes, 0, 0), IndexOutcome::ClockBeforeIssue(_)));
}

#[test]
fn an_index_with_a_bad_signature_is_refused() {
    let keys = Keys::new();
    let value = index_with_records(&keys);
    // Changed after signing.
    let mut tampered = envelope_value(&to_bytes(&value), &[sig(&keys.index, Purpose::Index)]);
    let mut newer = value.clone();
    newer["sequence"] = 9.into();
    tampered["payload"] = base64_of(&to_bytes(&newer)).into();
    assert_eq!(outcome(&keys, &to_bytes(&tampered), 0, NOW), IndexOutcome::BadSignature);
    // Signed by a key that is not pinned.
    assert_eq!(outcome(&keys, &signed_index(&new_key(), &value), 0, NOW), IndexOutcome::BadSignature);
    // Signed by the official key: it is not an index key.
    assert_eq!(outcome(&keys, &signed_index(&keys.official, &value), 0, NOW), IndexOutcome::BadSignature);
    // Signed by the index key, but for the release-record purpose.
    let wrong_purpose = envelope(&to_bytes(&value), &[Sig { key: &keys.index, signed_for: Purpose::ReleaseRecord, label: "index" }]);
    assert_eq!(outcome(&keys, &wrong_purpose, 0, NOW), IndexOutcome::BadSignature);
    // No signatures at all.
    assert_eq!(outcome(&keys, &envelope(&to_bytes(&value), &[]), 0, NOW), IndexOutcome::BadSignature);
    // A bad signature is reported before anything inside the payload is looked at.
    assert_eq!(outcome(&keys, &envelope(b"not json", &[sig(&new_key(), Purpose::Index)]), 0, NOW), IndexOutcome::BadSignature);
}

#[test]
fn an_index_signed_by_a_revoked_index_key_is_refused() {
    let keys = Keys::new();
    let value = index_value(7, ISSUED, EXPIRES, &[]);
    let by_spare = signed_index(&keys.spare, &value);
    let revoked = [public(&keys.spare)];
    assert_eq!(verify_index(&by_spare, &keys.trusted(), &revoked, 0, NOW).unwrap(), IndexOutcome::RevokedKey);
    // The other key still works. An index signed by both is refused: an index carries exactly
    // one index-key signature, so the floor has one signer (A1-C12.5, PLUG-04b).
    assert!(matches!(verify_index(&signed_index(&keys.index, &value), &keys.trusted(), &revoked, 0, NOW).unwrap(), IndexOutcome::Usable(_)));
    let both = envelope(&to_bytes(&value), &[sig(&keys.spare, Purpose::Index), sig(&keys.index, Purpose::Index)]);
    assert!(matches!(verify_index(&both, &keys.trusted(), &revoked, 0, NOW).unwrap_err(), PluginError::IndexMalformed(_)));
}

#[test]
fn one_index_key_can_revoke_the_other() {
    let keys = Keys::new();
    let mut value = index_value(8, ISSUED, EXPIRES, &[]);
    value["revoked_keys"] = serde_json::json!([hex::encode(public(&keys.index))]);
    let IndexOutcome::Usable(index) = outcome(&keys, &signed_index(&keys.spare, &value), 7, NOW) else { panic!("expected a usable index") };
    assert_eq!(index.revoked_index_keys, vec![public(&keys.index)]);
    // The caller stores that list. From then on the revoked key is refused: for an index...
    let later = signed_index(&keys.index, &index_value(9, ISSUED, EXPIRES, &[]));
    assert_eq!(verify_index(&later, &keys.trusted(), &index.revoked_index_keys, 8, NOW).unwrap(), IndexOutcome::RevokedKey);
    // ...and for a release record.
    let record = external_record(&keys.index, EXTERNAL_ID, "1.0.0", &good_package());
    assert_eq!(verify_release_record(&record, &keys.trusted(), &index.revoked_index_keys).unwrap_err(), PluginError::SignatureRevokedKey(Purpose::ReleaseRecord));
    // An index cannot revoke the only key that signed it.
    let mut own = index_value(8, ISSUED, EXPIRES, &[]);
    own["revoked_keys"] = serde_json::json!([hex::encode(public(&keys.spare))]);
    assert!(matches!(verify_index(&signed_index(&keys.spare, &own), &keys.trusted(), &[], 7, NOW).unwrap_err(), PluginError::IndexMalformed(_)));
    // Records signed by the key an index revokes may not ride along in that index.
    let mut carries = index_value(8, ISSUED, EXPIRES, &[record]);
    carries["revoked_keys"] = serde_json::json!([hex::encode(public(&keys.index))]);
    let error = verify_index(&signed_index(&keys.spare, &carries), &keys.trusted(), &[], 7, NOW).unwrap_err();
    assert_eq!(error, PluginError::IndexRecordInvalid { position: 0, error: Box::new(PluginError::SignatureRevokedKey(Purpose::ReleaseRecord)) });
    // Only an index key can be revoked this way, and only by its full public key.
    for bad in [serde_json::json!(["abcd"]), serde_json::json!([hex::encode(public(&keys.official))]), serde_json::json!([hex::encode([1u8; 32])])] {
        let mut value = index_value(8, ISSUED, EXPIRES, &[]);
        value["revoked_keys"] = bad.clone();
        assert!(matches!(verify_index(&signed_index(&keys.spare, &value), &keys.trusted(), &[], 7, NOW).unwrap_err(), PluginError::IndexMalformed(_)), "{bad}");
    }
}

#[test]
fn a_revocation_covers_its_version_range_and_nothing_outside_it() {
    let keys = Keys::new();
    let mut value = index_value(7, ISSUED, EXPIRES, &[]);
    value["revocations"] = serde_json::json!([
        { "id": EXTERNAL_ID, "from": "1.2.0", "to": "1.4.3", "reason": "Sends data to another host" },
        { "id": "com.example.other", "from": "0.0.0", "to": "0.9.9", "reason": "Withdrawn by its author" },
    ]);
    let IndexOutcome::Usable(index) = outcome(&keys, &signed_index(&keys.index, &value), 0, NOW) else { panic!("expected a usable index") };
    for inside in ["1.2.0", "1.3.7", "1.4.3", "1.2.1", "1.4.2", "1.3.99999"] {
        let hit = is_revoked(&index, EXTERNAL_ID, &version(inside)).unwrap_or_else(|| panic!("{inside} is in the range"));
        assert_eq!(hit.reason, "Sends data to another host");
        assert_eq!(index.revocation_for(EXTERNAL_ID, &version(inside)), Some(hit));
    }
    for outside in ["1.1.99", "1.4.4", "1.5.0", "2.0.0", "0.9.0", "1.10.0"] {
        assert!(is_revoked(&index, EXTERNAL_ID, &version(outside)).is_none(), "{outside} is outside the range");
    }
    assert!(is_revoked(&index, "com.example.other", &version("0.5.0")).is_some());
    assert!(is_revoked(&index, "com.example.other", &version("1.3.0")).is_none(), "another plugin's range does not apply");
    assert!(is_revoked(&index, "com.example.third", &version("1.3.0")).is_none());
}

#[test]
fn a_malformed_index_is_refused() {
    let keys = Keys::new();
    let error = |value: &serde_json::Value| verify_index(&signed_index(&keys.index, value), &keys.trusted(), &[], 0, NOW).unwrap_err();
    let base = || index_value(7, ISSUED, EXPIRES, &[]);

    let mut value = base();
    value["schema"] = 2.into();
    assert!(matches!(error(&value), PluginError::IndexMalformed(_)));
    let mut value = base();
    value["extra"] = 1.into();
    assert!(matches!(error(&value), PluginError::IndexMalformed(_)), "an unknown key");
    let mut value = base();
    value.as_object_mut().unwrap().remove("revocations");
    assert!(matches!(error(&value), PluginError::IndexMalformed(_)), "a missing key");
    // Expiry at or before the issue time, and a validity far beyond the 30 days of section 9.
    assert!(matches!(error(&index_value(7, ISSUED, ISSUED, &[])), PluginError::IndexMalformed(_)));
    assert!(matches!(error(&index_value(7, ISSUED, ISSUED + 32 * DAY, &[])), PluginError::IndexMalformed(_)));
    assert!(verify_index(&signed_index(&keys.index, &index_value(7, ISSUED, ISSUED + 31 * DAY, &[])), &keys.trusted(), &[], 0, NOW).is_ok());
    // Revocations: a bad id, a bad version, a range the wrong way round, an over-long reason.
    for bad in [
        serde_json::json!({ "id": "Bad", "from": "1.0.0", "to": "1.0.0", "reason": "x" }),
        serde_json::json!({ "id": EXTERNAL_ID, "from": "1.0", "to": "1.0.0", "reason": "x" }),
        serde_json::json!({ "id": EXTERNAL_ID, "from": "1.0.1", "to": "1.0.0", "reason": "x" }),
        serde_json::json!({ "id": EXTERNAL_ID, "from": "1.0.0", "to": "1.0.0", "reason": "x".repeat(121) }),
        serde_json::json!({ "id": EXTERNAL_ID, "from": "1.0.0", "to": "1.0.0", "reason": "bad\u{1b}[31m" }),
        serde_json::json!({ "id": EXTERNAL_ID, "from": "1.0.0", "to": "1.0.0" }),
    ] {
        let mut value = base();
        value["revocations"] = serde_json::json!([bad]);
        assert!(matches!(error(&value), PluginError::IndexMalformed(_)), "{bad}");
    }
    // A record inside the index that does not verify spoils the whole index.
    let stranger = new_key();
    let bad_record = external_record(&stranger, EXTERNAL_ID, "1.0.0", &good_package());
    let good_record = external_record(&keys.index, "com.example.first", "1.0.0", &good_package());
    assert_eq!(error(&index_value(7, ISSUED, EXPIRES, &[good_record, bad_record])), PluginError::IndexRecordInvalid { position: 1, error: Box::new(PluginError::SignatureUntrustedKey(Purpose::ReleaseRecord)) });
    // So does the same id and version twice.
    let record = external_record(&keys.index, EXTERNAL_ID, "1.0.0", &good_package());
    assert!(matches!(error(&index_value(7, ISSUED, EXPIRES, &[record.clone(), record])), PluginError::IndexMalformed(_)));
    // An Official record in the index still needs the official key, although the index key signed the index.
    let claimed = envelope(&to_bytes(&record_value(EXTERNAL_ID, "1.0.0", "official", &good_package())), &[sig(&keys.index, Purpose::ReleaseRecord)]);
    assert_eq!(error(&index_value(7, ISSUED, EXPIRES, &[claimed])), PluginError::IndexRecordInvalid { position: 0, error: Box::new(PluginError::SignatureMissing(Purpose::Official)) });

    assert!(matches!(verify_index(b"", &keys.trusted(), &[], 0, NOW).unwrap_err(), PluginError::EnvelopeMalformed(_)));
    assert!(matches!(verify_index(b"[1, 2]", &keys.trusted(), &[], 0, NOW).unwrap_err(), PluginError::EnvelopeMalformed(_)));
}

// ---- robustness ----

const PER_CALL: Duration = Duration::from_secs(2);

#[test]
fn mutated_indexes_and_records_never_panic_and_never_take_long() {
    let keys = Keys::new();
    let mut value = index_with_records(&keys);
    value["revocations"] = serde_json::json!([{ "id": EXTERNAL_ID, "from": "1.0.0", "to": "1.0.0", "reason": "malware" }]);
    let good_index = signed_index(&keys.index, &value);
    let good_payload = to_bytes(&value);
    let good_record = external_record(&keys.index, EXTERNAL_ID, "1.0.0", &good_package());
    let mut mutator = Mutator(0x5EED_0003);
    for round in 0..3000 {
        // Mutate the signed file, then mutate the payload and sign it again, so the parser
        // behind the signature check is reached as well.
        let resigned = envelope(&mutator.mutate(&good_payload), &[sig(&keys.index, Purpose::Index)]);
        for bytes in [mutator.mutate(&good_index), resigned] {
            let started = Instant::now();
            if let Err(error) = verify_index(&bytes, &keys.trusted(), &[], 0, NOW) {
                assert!(error.to_string().len() < 300, "round {round}: {error}");
            }
            assert!(started.elapsed() < PER_CALL, "round {round} took {:?}", started.elapsed());
        }
        let started = Instant::now();
        if let Err(error) = verify_release_record(&mutator.mutate(&good_record), &keys.trusted(), &[]) {
            assert!(error.to_string().len() < 300, "round {round}: {error}");
        }
        assert!(started.elapsed() < PER_CALL, "round {round} took {:?}", started.elapsed());
    }
}

#[test]
fn a_deeply_nested_index_does_not_overflow_the_stack() {
    let keys = Keys::new();
    let nested = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    assert!(verify_index(nested.as_bytes(), &keys.trusted(), &[], 0, NOW).is_err());
    let signed = envelope(nested.as_bytes(), &[sig(&keys.index, Purpose::Index)]);
    assert!(matches!(verify_index(&signed, &keys.trusted(), &[], 0, NOW).unwrap_err(), PluginError::IndexMalformed(_)));
}

/// The Speed section of docs/evidence/PLUG-04a.md: run with
/// `cargo test --release --test plugin_index_tests -- --ignored --nocapture speed`.
#[test]
#[ignore = "a measurement, not a check"]
fn speed_of_verifying_a_4_mib_index() {
    let keys = Keys::new();
    let package = good_package();
    // Fill the index to just under 4 MiB with External records, then with Official ones.
    for (label, official) in [("External records", false), ("Official records", true)] {
        let mut records = Vec::new();
        let mut size = 0;
        let mut n = 0u32;
        loop {
            let id = format!("com.example.tool{n}");
            let record = if official { official_record(&keys.index, &keys.official, &id, "1.0.0", &package) } else { external_record(&keys.index, &id, "1.0.0", &package) };
            // Base64 of the index payload grows each record by a third.
            if (size + record.len() + 1) * 4 / 3 + 600 > MAX_INDEX_BYTES {
                break;
            }
            size += record.len() + 1;
            records.push(record);
            n += 1;
        }
        let bytes = signed_index(&keys.index, &index_value(7, ISSUED, EXPIRES, &records));
        assert!(bytes.len() <= MAX_INDEX_BYTES && bytes.len() > MAX_INDEX_BYTES - 8192, "{}", bytes.len());
        let mut times = Vec::new();
        for _ in 0..5 {
            let started = Instant::now();
            assert!(matches!(verify_index(&bytes, &keys.trusted(), &[], 0, NOW).unwrap(), IndexOutcome::Usable(_)));
            times.push(started.elapsed());
        }
        times.sort();
        println!("4 MiB index ({} bytes, {} {label}): median {:?}, slowest {:?}", bytes.len(), records.len(), times[2], times[4]);
    }
    // A realistic catalogue for comparison.
    let records: Vec<Vec<u8>> = (0..50).map(|n| official_record(&keys.index, &keys.official, &format!("com.example.tool{n}"), "1.0.0", &package)).collect();
    let bytes = signed_index(&keys.index, &index_value(7, ISSUED, EXPIRES, &records));
    let started = Instant::now();
    for _ in 0..20 {
        verify_index(&bytes, &keys.trusted(), &[], 0, NOW).unwrap();
    }
    println!("50-record index ({} bytes): mean {:?}", bytes.len(), started.elapsed() / 20);
}
