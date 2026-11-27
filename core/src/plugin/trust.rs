//! The stored catalogue state (PLUG-04b, section 9 and A1-C12): the sequence floor, the
//! highest sequence accepted from each index key, the revoked index keys and the union of every
//! release revocation the app has accepted.
//!
//! [`accept_index`] is the one way an index changes this state. It runs [`verify_index`] and
//! then the rules that need memory:
//!
//! - **Floor.** An index below the floor is a rollback and is refused. An index with the same
//!   sequence is accepted only if it is the same index (same SHA-256).
//! - **Reset (A1-C12.5).** An index that revokes the key which signed the floor index is
//!   accepted below the floor if its sequence is above the highest sequence accepted from every
//!   index key that stays unrevoked. It resets the floor to itself.
//! - **Clock (A1-C10).** Expiry uses the later of the clock and the stored issue time, and a
//!   clock before the stored issue time is reported as a wrong clock.
//! - **Revocations.** Release revocations are kept as a union: no later index, reset or replay
//!   removes one. Revoked index keys are kept the same way.
//!
//! The state is a small JSON file. A damaged file is an error, never an empty state: an empty
//! state would drop the floor and the revocations, which is exactly what an attacker wants.
use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::error::{Excerpt, PluginError};
use super::index::{verify_index, Index, IndexOutcome, Revocation};
use super::manifest::Version;
use super::sign::TrustedKeys;

const SCHEMA: u32 = 1;
/// The state file never grows past this: the revocation union is bounded by what signed indexes
/// can carry, and anything larger is damage.
const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;

/// The index holding the sequence floor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Floor {
    pub sequence: u64,
    /// Unix seconds: the issue time of the highest-sequence index accepted.
    pub issued: u64,
    /// SHA-256 of that index file, lower-case hex.
    pub sha256: String,
    /// The index key that signed it, lower-case hex.
    pub signer: String,
}

/// A release revocation as stored.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredRevocation {
    pub id: String,
    pub from: String,
    pub to: String,
    pub reason: String,
}

/// What the app remembers between runs about the signed index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustState {
    schema: u32,
    floor: Option<Floor>,
    /// Index key (hex) to the highest sequence accepted from it.
    highest_by_key: BTreeMap<String, u64>,
    /// Index keys (hex) that some accepted index revoked. Never shrinks.
    revoked_index_keys: Vec<String>,
    /// Every release revocation accepted. Never shrinks.
    revocations: Vec<StoredRevocation>,
}

impl Default for TrustState {
    fn default() -> Self {
        TrustState { schema: SCHEMA, floor: None, highest_by_key: BTreeMap::new(), revoked_index_keys: Vec::new(), revocations: Vec::new() }
    }
}

/// Why [`accept_index`] refused an index that was otherwise readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexRefusal {
    /// Below the floor, and not a valid reset.
    RolledBack { sequence: u64, floor: u64 },
    /// The floor's sequence, but not the floor's file.
    SameSequenceDifferentIndex { sequence: u64 },
    /// Not signed for the index purpose by a trusted index key.
    BadSignature,
    /// Signed only by an index key that has been revoked.
    RevokedKey,
}

/// What [`accept_index`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexDecision {
    /// Accepted. `outcome` is `Usable`, `Expired` or `ClockBeforeIssue`, judged with the later
    /// of the clock and the stored issue time.
    Accepted {
        outcome: IndexOutcome,
        /// This index revoked the floor's signer and reset the floor (A1-C12.5).
        floor_reset: bool,
        /// The clock is before the stored issue time: say the clock looks wrong, and show
        /// External plugins as "Revocation status unknown".
        clock_looks_wrong: bool,
    },
    Refused(IndexRefusal),
}

fn hex32(key: &[u8; 32]) -> String {
    hex::encode(key)
}

fn damaged(reason: &str) -> PluginError {
    PluginError::TrustStateDamaged(Excerpt::new(reason.as_bytes()))
}

impl TrustState {
    /// Read the state file. A missing file is a fresh state; a damaged one is an error.
    pub fn load(path: &Path) -> Result<TrustState, PluginError> {
        let bytes = match std::fs::metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(TrustState::default()),
            Err(e) => return Err(PluginError::Io(Excerpt::new(e.to_string().as_bytes()))),
            Ok(meta) if meta.len() > MAX_STATE_BYTES => return Err(damaged("the file is too large")),
            Ok(_) => std::fs::read(path).map_err(|e| PluginError::Io(Excerpt::new(e.to_string().as_bytes())))?,
        };
        let state: TrustState = serde_json::from_slice(&bytes).map_err(|e| damaged(&e.to_string()))?;
        if state.schema != SCHEMA {
            return Err(damaged("unknown schema"));
        }
        state.check()?;
        Ok(state)
    }

    /// Every stored value must parse. A value that does not is damage, never skipped: a
    /// skipped key or revocation would quietly un-revoke it.
    fn check(&self) -> Result<(), PluginError> {
        let hex64 = |text: &str| text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if let Some(floor) = &self.floor {
            if !hex64(&floor.sha256) || !hex64(&floor.signer) {
                return Err(damaged("the floor has a bad hash or signer"));
            }
        }
        if !self.highest_by_key.keys().all(|k| hex64(k)) || !self.revoked_index_keys.iter().all(|k| hex64(k)) {
            return Err(damaged("a stored index key is not 64 hex digits"));
        }
        for r in &self.revocations {
            let ok = super::manifest::is_plugin_id(&r.id)
                && matches!((Version::parse(&r.from), Version::parse(&r.to)), (Some(from), Some(to)) if from <= to && from.to_string() == r.from && to.to_string() == r.to);
            if !ok {
                return Err(damaged("a stored revocation has a bad id or version range"));
            }
        }
        Ok(())
    }

    /// Write the state file atomically (temp file, then rename), readable by this user only.
    /// Only [`accept_and_store`](super::install::accept_and_store) calls it, under the folder lock.
    pub(crate) fn save(&self, path: &Path) -> Result<(), PluginError> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| PluginError::Io(Excerpt::new(e.to_string().as_bytes())))?;
        crate::store::write_atomic(path, &bytes).map_err(|e| PluginError::Io(Excerpt::new(e.to_string().as_bytes())))
    }

    pub fn floor(&self) -> Option<&Floor> {
        self.floor.as_ref()
    }

    /// The index keys an accepted index revoked.
    pub fn revoked_index_keys(&self) -> Vec<[u8; 32]> {
        self.revoked_index_keys.iter().filter_map(|text| hex::decode(text).ok()).filter_map(|bytes| <[u8; 32]>::try_from(bytes).ok()).collect()
    }

    /// The highest sequence accepted from `key`, or 0.
    pub fn highest_from(&self, key: &[u8; 32]) -> u64 {
        self.highest_by_key.get(&hex32(key)).copied().unwrap_or(0)
    }

    /// The stored revocation covering this id and version, if any. It applies whether or not
    /// an index is currently usable (section 9).
    pub fn revocation_for(&self, id: &str, version: &Version) -> Option<&StoredRevocation> {
        self.revocations.iter().find(|r| {
            r.id == id && matches!((Version::parse(&r.from), Version::parse(&r.to)), (Some(from), Some(to)) if from <= *version && *version <= to)
        })
    }

    /// The clock looks wrong: it is before the issue time of the floor index.
    pub fn clock_looks_wrong(&self, now: u64) -> bool {
        self.floor.as_ref().is_some_and(|floor| now < floor.issued)
    }

    /// Fold an accepted index's revocations and revoked keys into the unions.
    fn merge(&mut self, index: &Index) {
        for key in &index.revoked_index_keys {
            let key = hex32(key);
            if !self.revoked_index_keys.contains(&key) {
                self.revoked_index_keys.push(key);
            }
        }
        for revocation in &index.revocations {
            let stored = stored(revocation);
            if !self.revocations.contains(&stored) {
                self.revocations.push(stored);
            }
        }
        self.revocations.sort();
        self.revoked_index_keys.sort();
    }
}

fn stored(revocation: &Revocation) -> StoredRevocation {
    StoredRevocation { id: revocation.id.clone(), from: revocation.from.to_string(), to: revocation.to.to_string(), reason: revocation.reason.clone() }
}

/// Verify `bytes` as an index against the stored state and, if it is accepted, update the
/// state. The caller saves the state afterwards. `Err` means the file is not a valid index (as
/// [`verify_index`]); a refusal by the floor rules is `Ok(IndexDecision::Refused(..))`.
///
/// `now` is Unix seconds. Nothing changes in `state` unless the index is accepted.
pub fn accept_index(state: &mut TrustState, bytes: &[u8], keys: &TrustedKeys, now: u64) -> Result<IndexDecision, PluginError> {
    let revoked = state.revoked_index_keys();
    // The floor rules and the clock rule are applied here, so the verifier is asked with no
    // floor of its own; its time judgement is replaced below.
    let index = match verify_index(bytes, keys, &revoked, 0, now)? {
        IndexOutcome::Usable(index) | IndexOutcome::Expired(index) | IndexOutcome::ClockBeforeIssue(index) => index,
        IndexOutcome::BadSignature => return Ok(IndexDecision::Refused(IndexRefusal::BadSignature)),
        IndexOutcome::RevokedKey => return Ok(IndexDecision::Refused(IndexRefusal::RevokedKey)),
        IndexOutcome::RolledBack { sequence, highest_seen } => return Ok(IndexDecision::Refused(IndexRefusal::RolledBack { sequence, floor: highest_seen })),
    };
    let sha256 = hex::encode(Sha256::digest(bytes));
    let mut floor_reset = false;
    if let Some(floor) = &state.floor {
        if index.sequence == floor.sequence {
            if sha256 != floor.sha256 {
                return Ok(IndexDecision::Refused(IndexRefusal::SameSequenceDifferentIndex { sequence: index.sequence }));
            }
        } else if index.sequence < floor.sequence {
            // A1-C12.5: a reset needs this index to revoke the floor's signer and to beat every
            // sequence accepted from the keys that stay trusted.
            let floor_signer_revoked_here = index.revoked_index_keys.iter().any(|key| hex32(key) == floor.signer);
            let mut still_trusted = keys.index.iter().filter(|key| !revoked.contains(key) && !index.revoked_index_keys.contains(key));
            let beats_every_trusted_key = still_trusted.all(|key| index.sequence > state.highest_from(key));
            if !(floor_signer_revoked_here && beats_every_trusted_key) {
                return Ok(IndexDecision::Refused(IndexRefusal::RolledBack { sequence: index.sequence, floor: floor.sequence }));
            }
            floor_reset = true;
        }
    }
    if state.floor.as_ref().is_none_or(|floor| index.sequence != floor.sequence) {
        state.floor = Some(Floor { sequence: index.sequence, issued: index.issued, sha256, signer: hex32(&index.signer) });
    }
    let highest = state.highest_by_key.entry(hex32(&index.signer)).or_insert(0);
    *highest = (*highest).max(index.sequence);
    state.merge(&index);

    // A1-C10: expiry uses the later of the clock and the issue time of the floor index (which
    // may be this one), and a clock before that issue time is reported, not trusted.
    let stored_issued = state.floor.as_ref().map_or(index.issued, |floor| floor.issued);
    let clock_looks_wrong = now < stored_issued;
    let effective_now = now.max(stored_issued);
    let outcome = if clock_looks_wrong {
        IndexOutcome::ClockBeforeIssue(index)
    } else if effective_now >= index.expires {
        IndexOutcome::Expired(index)
    } else {
        IndexOutcome::Usable(index)
    };
    Ok(IndexDecision::Accepted { outcome, floor_reset, clock_looks_wrong })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_is_a_fresh_state_and_a_damaged_one_is_an_error() {
        let dir = std::env::temp_dir().join(format!("bastion-trust-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trust.json");
        assert_eq!(TrustState::load(&path).unwrap(), TrustState::default());
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(TrustState::load(&path), Err(PluginError::TrustStateDamaged(_))));
        std::fs::write(&path, br#"{"schema":2,"floor":null,"highest_by_key":{},"revoked_index_keys":[],"revocations":[]}"#).unwrap();
        assert!(matches!(TrustState::load(&path), Err(PluginError::TrustStateDamaged(_))));
        let mut state = TrustState::default();
        state.revocations.push(StoredRevocation { id: "com.example.tool".into(), from: "1.0.0".into(), to: "1.2.0".into(), reason: "bad".into() });
        state.save(&path).unwrap();
        assert_eq!(TrustState::load(&path).unwrap(), state);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_stored_revocation_covers_its_range_only() {
        let mut state = TrustState::default();
        state.revocations.push(StoredRevocation { id: "com.example.tool".into(), from: "1.0.0".into(), to: "1.2.0".into(), reason: "bad".into() });
        let v = |t: &str| Version::parse(t).unwrap();
        assert!(state.revocation_for("com.example.tool", &v("1.1.0")).is_some());
        assert!(state.revocation_for("com.example.tool", &v("1.2.1")).is_none());
        assert!(state.revocation_for("com.example.other", &v("1.1.0")).is_none());
    }
}
