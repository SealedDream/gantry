//! The signed index (section 9): the catalogue's release records, the revocation list, a
//! sequence number, an issue time and an expiry.
//!
//! The index is a signed envelope (purpose `index`, an index key) whose payload is JSON:
//!
//! ```json
//! {"schema": 1, "sequence": 7, "issued": 1800000000, "expires": 1802592000,
//!  "records": [<release-record envelope>, ...],
//!  "revocations": [{"id": "com.example.tool", "from": "1.0.0", "to": "1.4.3", "reason": "..."}],
//!  "revoked_keys": ["<64 hex: an index public key>"]}
//! ```
//!
//! Times are Unix seconds. Each record is a full release-record envelope and is verified like a
//! record that arrives on its own, so an index key alone can never place an Official record in
//! the catalogue. This module keeps nothing: the caller stores the highest sequence seen and
//! the revoked index keys, and passes them back in.
use serde::Deserialize;

use super::error::{Excerpt, PluginError};
use super::manifest::{check_text, is_plugin_id, Version};
use super::record::{verify_envelope, VerifiedRecord};
use super::sign::{Envelope, Purpose, RawEnvelope, TrustedKeys};

pub const MAX_INDEX_BYTES: usize = 4 * 1024 * 1024;
/// The index expires 30 days after it is issued (section 9); one more day is allowed so that a
/// signing script rounding to a day is not refused. A longer validity is refused: it would
/// lengthen the time a frozen catalogue stays usable.
pub const MAX_INDEX_VALIDITY_SECS: u64 = 31 * 24 * 3600;
/// At most 4,096 release records (A1-C12.3): the index is verified off the main thread, and the
/// cap bounds that work as well as the 4 MiB size does.
pub const MAX_INDEX_RECORDS: usize = 4096;
const MAX_REASON_CHARS: usize = 120;
const SCHEMA: u32 = 1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIndex {
    schema: u32,
    sequence: u64,
    issued: u64,
    expires: u64,
    records: Vec<RawEnvelope>,
    revocations: Vec<RawRevocation>,
    revoked_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRevocation {
    id: String,
    from: String,
    to: String,
    reason: String,
}

/// Versions `from` to `to` of plugin `id`, both ends included, are switched off.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Revocation {
    pub id: String,
    pub from: Version,
    pub to: Version,
    /// Plain text, at most 120 characters, shown to the user.
    pub reason: String,
}

/// An index whose signature and every record were verified. It can only be built by
/// [`verify_index`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Index {
    pub sequence: u64,
    /// Unix seconds.
    pub issued: u64,
    /// Unix seconds; the index is expired from this second on.
    pub expires: u64,
    pub records: Vec<VerifiedRecord>,
    pub revocations: Vec<Revocation>,
    /// Index keys this index revokes. The caller stores them and passes them to every later
    /// call as `revoked_index_keys`.
    pub revoked_index_keys: Vec<[u8; 32]>,
    /// The one index key that signed this index (section 9: exactly one index-key signature).
    /// The stored state keeps it for the floor index (A1-C12.5).
    pub signer: [u8; 32],
}

impl Index {
    /// The release record for exactly this id and version, if the catalogue has one.
    pub fn record(&self, id: &str, version: &Version) -> Option<&VerifiedRecord> {
        self.records.iter().find(|record| record.id == id && record.version == *version)
    }

    /// The revocation that covers this id and version, if there is one.
    pub fn revocation_for(&self, id: &str, version: &Version) -> Option<&Revocation> {
        self.revocations.iter().find(|revocation| revocation.id == id && revocation.from <= *version && *version <= revocation.to)
    }
}

/// "Is this id and version revoked", for any loaded index: usable, expired, or loaded while
/// the clock looked wrong. Revocations apply whenever an index is loaded (section 9).
pub fn is_revoked<'a>(index: &'a Index, id: &str, version: &Version) -> Option<&'a Revocation> {
    index.revocation_for(id, version)
}

/// What [`verify_index`] found. The first three carry the index, because its revocation list
/// applies in all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexOutcome {
    /// Current and authentic: installs and updates may use it.
    Usable(Index),
    /// Authentic but past its expiry: installed plugins keep working, there are no new
    /// installs or updates, and the catalogue is reported as out of date.
    Expired(Index),
    /// Authentic, but the clock is earlier than the index's issue time: say the clock looks
    /// wrong. No new installs or updates.
    ClockBeforeIssue(Index),
    /// Authentic, but older than an index already seen. Refused.
    RolledBack { sequence: u64, highest_seen: u64 },
    /// Not signed for the index purpose by a trusted index key. Refused.
    BadSignature,
    /// Signed only by an index key that has been revoked. Refused.
    RevokedKey,
}

fn malformed(reason: &str) -> PluginError {
    PluginError::IndexMalformed(Excerpt::new(reason.as_bytes()))
}

/// The index keys this index revokes. Each must be the full public key of a trusted index key,
/// and the index must still be signed by a key it does not revoke.
fn revoked_keys(raw: &[String], keys: &TrustedKeys, signers: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, PluginError> {
    let mut revoked: Vec<[u8; 32]> = Vec::with_capacity(raw.len().min(keys.index.len()));
    for text in raw {
        let key = Some(text).filter(|text| text.len() == 64).and_then(|text| hex::decode(text).ok()).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
        let key = key.filter(|key| keys.index.contains(key)).ok_or_else(|| malformed("`revoked_keys` names something that is not an index key"))?;
        if revoked.contains(&key) {
            return Err(malformed("`revoked_keys` names a key twice"));
        }
        revoked.push(key);
    }
    if signers.iter().all(|signer| revoked.contains(signer)) {
        return Err(malformed("the index revokes the only key that signed it"));
    }
    Ok(revoked)
}

fn revocation(raw: RawRevocation) -> Result<Revocation, PluginError> {
    if !is_plugin_id(&raw.id) {
        return Err(malformed("a revocation has an id that is not a plugin id"));
    }
    let from = Version::parse(&raw.from).ok_or_else(|| malformed("a revocation has a `from` that is not a version"))?;
    let to = Version::parse(&raw.to).ok_or_else(|| malformed("a revocation has a `to` that is not a version"))?;
    if from > to {
        return Err(malformed("a revocation has `from` above `to`"));
    }
    if check_text(&raw.reason, MAX_REASON_CHARS).is_err() {
        return Err(malformed("a revocation reason must be 1 to 120 plain characters"));
    }
    Ok(Revocation { id: raw.id, from, to, reason: raw.reason })
}

/// Verify the index and say whether it can be used.
///
/// - `keys`: the pinned index and official keys.
/// - `revoked_index_keys`: index keys that an earlier index revoked.
/// - `highest_seen`: the highest sequence number the app has accepted so far (0 if none). An
///   index with the same number is accepted: it is the same index again.
/// - `now`: Unix seconds.
///
/// `Err` means the file is too large or, although correctly signed, not a valid index. The
/// checks run in this order: size, signature, payload, rollback, records, clock, expiry.
pub fn verify_index(bytes: &[u8], keys: &TrustedKeys, revoked_index_keys: &[[u8; 32]], highest_seen: u64, now: u64) -> Result<IndexOutcome, PluginError> {
    if bytes.len() > MAX_INDEX_BYTES {
        return Err(PluginError::IndexTooLarge);
    }
    let envelope = Envelope::parse(bytes)?;
    // Nothing in the payload is read before an index key has vouched for its exact bytes.
    let signers = match envelope.require(Purpose::Index, keys, revoked_index_keys) {
        Ok(signers) => signers,
        Err(PluginError::SignatureRevokedKey(_)) => return Ok(IndexOutcome::RevokedKey),
        Err(_) => return Ok(IndexOutcome::BadSignature),
    };
    // Exactly one index-key signature, so the floor index has one signer to store (A1-C12.5).
    if envelope.count(Purpose::Index) != 1 || signers.len() != 1 {
        return Err(malformed("an index carries exactly one index-key signature"));
    }
    let signer = signers[0];
    let raw: RawIndex = serde_json::from_slice(envelope.payload()).map_err(|e| malformed(&e.to_string()))?;
    if raw.schema != SCHEMA {
        return Err(malformed("`schema` must be 1"));
    }
    if raw.expires <= raw.issued {
        return Err(malformed("`expires` is not after `issued`"));
    }
    if raw.expires - raw.issued > MAX_INDEX_VALIDITY_SECS {
        return Err(malformed("the index is valid for more than 31 days"));
    }
    if raw.sequence < highest_seen {
        return Ok(IndexOutcome::RolledBack { sequence: raw.sequence, highest_seen });
    }

    if raw.records.len() > MAX_INDEX_RECORDS {
        return Err(PluginError::IndexTooManyRecords);
    }
    let revoked_here = revoked_keys(&raw.revoked_keys, keys, &signers)?;
    // A key this index revokes is revoked for the records it carries as well.
    let all_revoked: Vec<[u8; 32]> = revoked_index_keys.iter().chain(&revoked_here).copied().collect();
    let mut records: Vec<VerifiedRecord> = Vec::with_capacity(raw.records.len());
    for (position, raw_record) in raw.records.into_iter().enumerate() {
        let record = Envelope::from_raw(raw_record).and_then(|envelope| verify_envelope(&envelope, keys, &all_revoked)).map_err(|error| PluginError::IndexRecordInvalid { position, error: Box::new(error) })?;
        records.push(record);
    }
    let mut seen: Vec<(&str, Version)> = records.iter().map(|record| (record.id.as_str(), record.version)).collect();
    seen.sort_unstable();
    if seen.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(malformed("the same id and version appears twice"));
    }
    let revocations = raw.revocations.into_iter().map(revocation).collect::<Result<Vec<_>, _>>()?;

    let index = Index { sequence: raw.sequence, issued: raw.issued, expires: raw.expires, records, revocations, revoked_index_keys: revoked_here, signer };
    Ok(if now < index.issued {
        IndexOutcome::ClockBeforeIssue(index)
    } else if now >= index.expires {
        IndexOutcome::Expired(index)
    } else {
        IndexOutcome::Usable(index)
    })
}
