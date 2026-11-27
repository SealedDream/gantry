//! Signed envelopes and purpose tags (section 9, "Keys").
//!
//! An envelope is `{"payload": base64, "signatures": [{"keyid", "purpose", "sig"}]}`, the shape
//! `crate::update` uses, with one addition: every signature has a purpose. The Ed25519 signature
//! covers a fixed tag for that purpose followed by the exact payload bytes, so a signature made
//! for one purpose never verifies for another, and no JSON canonicalisation is involved.
use std::fmt;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::error::PluginError;

/// More signatures than this in one envelope is refused: it bounds the work per file.
pub const MAX_SIGNATURES: usize = 8;

/// What a signature is for. The index key signs with `Index` and `ReleaseRecord`; the official
/// key signs with `Official`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// The index key over the index.
    Index,
    /// The index key over a release record.
    ReleaseRecord,
    /// The official key over a release record.
    Official,
}

impl Purpose {
    const ALL: [Purpose; 3] = [Purpose::Index, Purpose::ReleaseRecord, Purpose::Official];

    /// The name the envelope carries next to the signature.
    pub fn label(self) -> &'static str {
        match self {
            Purpose::Index => "index",
            Purpose::ReleaseRecord => "release-record",
            Purpose::Official => "official",
        }
    }

    /// The bytes signed in front of the payload. No tag is a prefix of another: each ends in a
    /// zero byte that appears nowhere else in it.
    fn tag(self) -> &'static [u8] {
        match self {
            Purpose::Index => b"bastion-plugin-index-v1\0",
            Purpose::ReleaseRecord => b"bastion-plugin-release-record-v1\0",
            Purpose::Official => b"bastion-plugin-official-v1\0",
        }
    }

    fn from_label(label: &str) -> Option<Purpose> {
        Purpose::ALL.into_iter().find(|p| p.label() == label)
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The exact bytes a signer signs and a verifier checks: the purpose tag, then the payload.
pub fn signed_message(purpose: Purpose, payload: &[u8]) -> Vec<u8> {
    let tag = purpose.tag();
    let mut message = Vec::with_capacity(tag.len() + payload.len());
    message.extend_from_slice(tag);
    message.extend_from_slice(payload);
    message
}

/// Key id: the first 8 bytes of SHA-256 of the public key, in hex (as `crate::update::key_id`).
/// It only helps to say which signature failed; trust never depends on it.
pub fn key_id(public_key: &[u8; 32]) -> String {
    hex::encode(&Sha256::digest(public_key)[..8])
}

/// The pinned public keys, by role. A key trusted in one role is not trusted in the other.
#[derive(Debug, Clone, Copy)]
pub struct TrustedKeys<'a> {
    /// Index keys: they sign the index and release records.
    pub index: &'a [[u8; 32]],
    /// Official keys: they co-sign Official release records.
    pub official: &'a [[u8; 32]],
}

impl<'a> TrustedKeys<'a> {
    fn for_purpose(&self, purpose: Purpose) -> &'a [[u8; 32]] {
        match purpose {
            Purpose::Index | Purpose::ReleaseRecord => self.index,
            Purpose::Official => self.official,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawEnvelope {
    payload: String,
    signatures: Vec<RawSignature>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignature {
    keyid: String,
    purpose: String,
    sig: String,
}

struct EnvelopeSignature {
    keyid: String,
    purpose: Purpose,
    sig: [u8; 64],
}

/// A parsed envelope. Nothing in it is trusted until [`Envelope::require`] has passed.
pub(super) struct Envelope {
    payload: Vec<u8>,
    signatures: Vec<EnvelopeSignature>,
}

/// What one signature really is, found by trying every trusted key with every purpose tag.
struct Truth {
    key: [u8; 32],
    purpose: Purpose,
}

fn verifies(key: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|vk| vk.verify_strict(message, &Signature::from_bytes(sig)).is_ok())
}

impl Envelope {
    pub(super) fn parse(bytes: &[u8]) -> Result<Envelope, PluginError> {
        let raw: RawEnvelope = serde_json::from_slice(bytes).map_err(|_| PluginError::EnvelopeMalformed("not JSON with `payload` and `signatures`"))?;
        Envelope::from_raw(raw)
    }

    pub(super) fn from_raw(raw: RawEnvelope) -> Result<Envelope, PluginError> {
        if raw.signatures.len() > MAX_SIGNATURES {
            return Err(PluginError::EnvelopeMalformed("too many signatures"));
        }
        let payload = B64.decode(&raw.payload).map_err(|_| PluginError::EnvelopeMalformed("the payload is not base64"))?;
        let mut signatures = Vec::with_capacity(raw.signatures.len());
        for s in raw.signatures {
            let purpose = Purpose::from_label(&s.purpose).ok_or(PluginError::EnvelopeMalformed("a signature has an unknown purpose"))?;
            let sig = B64.decode(&s.sig).ok().and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok()).ok_or(PluginError::EnvelopeMalformed("a signature is not 64 bytes of base64"))?;
            signatures.push(EnvelopeSignature { keyid: s.keyid, purpose, sig });
        }
        Ok(Envelope { payload, signatures })
    }

    /// The signed bytes. Parse them only after [`Envelope::require`] has passed.
    pub(super) fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The keys of `keys`' role for `purpose` that signed the payload for exactly that purpose,
    /// revoked ones left out. An error says why there is none.
    ///
    /// A signature counts only when its label is `purpose`, it verifies (`verify_strict`) over
    /// the tag of `purpose` followed by the payload, and the key is trusted in that role.
    /// `revoked_index_keys` applies to index keys only.
    pub(super) fn require(&self, purpose: Purpose, keys: &TrustedKeys, revoked_index_keys: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, PluginError> {
        let (signers, revoked) = self.signers(purpose, keys, revoked_index_keys);
        if !signers.is_empty() {
            return Ok(signers);
        }
        if revoked {
            return Err(PluginError::SignatureRevokedKey(purpose));
        }
        Err(self.why_not(purpose, keys))
    }

    /// How many signatures are labelled `purpose`, valid or not.
    pub(super) fn count(&self, purpose: Purpose) -> usize {
        self.signatures.iter().filter(|s| s.purpose == purpose).count()
    }

    /// True when a key trusted for `purpose` signed the payload for exactly that purpose. The
    /// same rule as [`Envelope::require`], without the work of explaining a refusal: with no
    /// signature labelled `purpose` it verifies nothing.
    pub(super) fn is_signed_for(&self, purpose: Purpose, keys: &TrustedKeys, revoked_index_keys: &[[u8; 32]]) -> bool {
        !self.signers(purpose, keys, revoked_index_keys).0.is_empty()
    }

    /// The keys that count for `purpose`, and whether a revoked key also signed.
    fn signers(&self, purpose: Purpose, keys: &TrustedKeys, revoked_index_keys: &[[u8; 32]]) -> (Vec<[u8; 32]>, bool) {
        let mut signers = Vec::new();
        let mut revoked = false;
        let mut labelled = self.signatures.iter().filter(|s| s.purpose == purpose).peekable();
        if labelled.peek().is_none() {
            return (signers, revoked);
        }
        let role = keys.for_purpose(purpose);
        let message = signed_message(purpose, &self.payload);
        for s in labelled {
            for key in role.iter().filter(|key| verifies(key, &message, &s.sig)) {
                if purpose != Purpose::Official && revoked_index_keys.contains(key) {
                    revoked = true;
                } else if !signers.contains(key) {
                    signers.push(*key);
                }
            }
        }
        (signers, revoked)
    }

    /// Only reached when no signature counted: say which rule failed. This tries every trusted
    /// key with every tag, which is at most `MAX_SIGNATURES` x keys x 3 verifications.
    fn why_not(&self, purpose: Purpose, keys: &TrustedKeys) -> PluginError {
        let role = keys.for_purpose(purpose);
        let truths: Vec<Option<Truth>> = self.signatures.iter().map(|s| self.truth_of(s, keys)).collect();
        // A key of the right role signed, but for another purpose or under another label.
        let wrong_purpose = self.signatures.iter().zip(&truths).any(|(s, truth)| truth.as_ref().is_some_and(|t| role.contains(&t.key) && (t.purpose != purpose || s.purpose != purpose)));
        if wrong_purpose {
            return PluginError::SignatureWrongPurpose(purpose);
        }
        let mut labelled = self.signatures.iter().zip(&truths).filter(|(s, _)| s.purpose == purpose).peekable();
        if labelled.peek().is_none() {
            return PluginError::SignatureMissing(purpose);
        }
        // It names a key of the right role but verifies under no trusted key: the bytes changed.
        let names_a_trusted_key = labelled.any(|(s, truth)| truth.is_none() && role.iter().any(|key| key_id(key) == s.keyid));
        if names_a_trusted_key {
            PluginError::SignatureInvalid(purpose)
        } else {
            PluginError::SignatureUntrustedKey(purpose)
        }
    }

    fn truth_of(&self, s: &EnvelopeSignature, keys: &TrustedKeys) -> Option<Truth> {
        for purpose in Purpose::ALL {
            let message = signed_message(purpose, &self.payload);
            if let Some(key) = keys.index.iter().chain(keys.official).find(|key| verifies(key, &message, &s.sig)) {
                return Some(Truth { key: *key, purpose });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purpose_tags_are_distinct_and_none_is_a_prefix_of_another() {
        for a in Purpose::ALL {
            assert_eq!(Purpose::from_label(a.label()), Some(a));
            assert_eq!(a.tag().iter().filter(|&&b| b == 0).count(), 1);
            assert_eq!(a.tag().last(), Some(&0));
            for b in Purpose::ALL {
                if a != b {
                    assert!(!a.tag().starts_with(b.tag()) && a.label() != b.label());
                }
            }
        }
        assert_eq!(Purpose::from_label("Index"), None);
        assert_eq!(signed_message(Purpose::Index, b"x"), b"bastion-plugin-index-v1\0x");
    }

    #[test]
    fn malformed_envelopes_are_refused() {
        let bad = |text: &str| Envelope::parse(text.as_bytes()).err();
        assert!(bad("").is_some() && bad("{}").is_some() && bad("[]").is_some());
        assert!(bad(r#"{"payload":"!!","signatures":[]}"#).is_some(), "payload is not base64");
        assert!(bad(r#"{"payload":"","signatures":[],"extra":1}"#).is_some(), "unknown key");
        assert!(bad(r#"{"payload":"","signatures":[{"keyid":"k","purpose":"index","sig":"AAAA"}]}"#).is_some(), "short signature");
        assert!(bad(r#"{"payload":"","signatures":[{"keyid":"k","purpose":"index","sig":"AAAA","x":1}]}"#).is_some());
        let sig = B64.encode([0u8; 64]);
        let one = format!(r#"{{"keyid":"k","purpose":"index","sig":"{sig}"}}"#);
        let many = vec![one.clone(); MAX_SIGNATURES + 1].join(",");
        assert!(bad(&format!(r#"{{"payload":"","signatures":[{many}]}}"#)).is_some(), "too many signatures");
        let most = vec![one; MAX_SIGNATURES].join(",");
        assert!(bad(&format!(r#"{{"payload":"","signatures":[{most}]}}"#)).is_none());
    }
}
