//! Signed update manifests (the first, smallest piece of a TUF-style update channel).
//!
//! A manifest is an envelope `{"payload": base64(JSON), "signatures": [{"keyid", "sig"}]}`. The
//! Ed25519 signature covers the exact payload bytes, so no JSON canonicalisation is involved.
//! Verification refuses, in this order: oversized input, no valid signature from a trusted
//! (compiled-in) key, a payload that does not parse, another channel, an expired manifest
//! (freeze attack: a mirror serving an old, still-signed manifest forever) and a version lower
//! than the installed one (rollback). Files listed carry SHA-256 and size; `verify_file` checks a
//! download against them.
//!
//! Not covered yet (see SECURITY.md): role separation and key rotation (one root key signs
//! everything), threshold signatures, persisting the newest manifest seen (so a replayed older
//! but unexpired manifest is only caught by the version check). Installing is done by the hosts:
//! apps/macos Updates.swift (replace the .app) and apps/windows MainWindow.Updates.cs (silent Inno
//! setup, or the update-apply.cmd file swap for the portable zip).
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{CoreError, Result};

pub mod github;

/// Manifests are small; anything larger is refused before parsing.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// A manifest may not claim to stay valid for more than this (limits the freeze window).
pub const MAX_VALIDITY_SECS: u64 = 400 * 24 * 3600;
const SCHEMA: u32 = 1;

#[derive(Deserialize)]
struct Envelope {
    payload: String,
    signatures: Vec<EnvelopeSignature>,
}

#[derive(Deserialize)]
struct EnvelopeSignature {
    keyid: String,
    sig: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct UpdateFile {
    pub name: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    pub channel: String,
    pub version: String,
    /// Unix seconds after which the manifest must not be trusted.
    pub expires: u64,
    #[serde(default)]
    pub notes: String,
    pub files: Vec<UpdateFile>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UpdateCheck {
    UpToDate { latest: String },
    Available(Manifest),
}

/// Key id: first 8 bytes of SHA-256 of the public key, hex. Lets a manifest name its signer.
pub fn key_id(public_key: &[u8; 32]) -> String {
    hex::encode(&Sha256::digest(public_key)[..8])
}

/// `major.minor.patch` (optionally `-suffix`, ignored for ordering). No new dependency.
pub fn parse_version(v: &str) -> Result<(u64, u64, u64)> {
    let core = v.trim().split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    let [a, b, c] = parts.as_slice() else { return Err(CoreError::Invalid(format!("not a version: `{v}`"))) };
    let n = |s: &str| s.parse::<u64>().map_err(|_| CoreError::Invalid(format!("not a version: `{v}`")));
    Ok((n(a)?, n(b)?, n(c)?))
}

fn signed_by_trusted_key(payload: &[u8], sigs: &[EnvelopeSignature], trusted: &[[u8; 32]]) -> bool {
    sigs.iter().any(|s| {
        let Some(sig) = B64.decode(&s.sig).ok().and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok()) else { return false };
        trusted.iter().filter(|k| key_id(k) == s.keyid).any(|k| {
            VerifyingKey::from_bytes(k).is_ok_and(|vk| vk.verify_strict(payload, &Signature::from_bytes(&sig)).is_ok())
        })
    })
}

/// Verify an envelope against the trusted keys and decide whether it offers an update.
pub fn verify_manifest(bytes: &[u8], trusted: &[[u8; 32]], channel: &str, installed: &str, now: u64) -> Result<UpdateCheck> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(CoreError::Invalid("update manifest is too large".into()));
    }
    let env: Envelope = serde_json::from_slice(bytes).map_err(|_| CoreError::Corrupt("update manifest is not a signed envelope".into()))?;
    let payload = B64.decode(&env.payload).map_err(|_| CoreError::Corrupt("update manifest payload is not base64".into()))?;
    if !signed_by_trusted_key(&payload, &env.signatures, trusted) {
        return Err(CoreError::PolicyDenied("update manifest is not signed by a trusted key".into()));
    }
    let m: Manifest = serde_json::from_slice(&payload).map_err(|e| CoreError::Corrupt(format!("update manifest payload: {e}")))?;
    if m.schema != SCHEMA {
        return Err(CoreError::Invalid(format!("unsupported update manifest schema {}", m.schema)));
    }
    if m.channel != channel {
        return Err(CoreError::PolicyDenied(format!("manifest is for channel `{}`, not `{channel}`", m.channel)));
    }
    if m.expires <= now {
        return Err(CoreError::PolicyDenied("update manifest has expired (a mirror may be serving stale data)".into()));
    }
    if m.expires > now.saturating_add(MAX_VALIDITY_SECS) {
        return Err(CoreError::PolicyDenied("update manifest claims an implausibly long validity".into()));
    }
    for f in &m.files {
        if f.sha256.len() != 64 || !f.sha256.chars().all(|c| c.is_ascii_hexdigit()) || !f.url.starts_with("https://") {
            return Err(CoreError::Invalid(format!("update file `{}` needs an https URL and a SHA-256", f.name)));
        }
    }
    let (latest, current) = (parse_version(&m.version)?, parse_version(installed)?);
    if latest < current {
        return Err(CoreError::PolicyDenied(format!("manifest offers {} but {installed} is installed (rollback refused)", m.version)));
    }
    Ok(if latest == current { UpdateCheck::UpToDate { latest: m.version } } else { UpdateCheck::Available(m) })
}

/// Check downloaded bytes against a manifest entry (size first, then SHA-256).
pub fn verify_file(bytes: &[u8], file: &UpdateFile) -> Result<()> {
    if bytes.len() as u64 != file.size {
        return Err(CoreError::PolicyDenied(format!("`{}` has the wrong size", file.name)));
    }
    if !hex::encode(Sha256::digest(bytes)).eq_ignore_ascii_case(&file.sha256) {
        return Err(CoreError::PolicyDenied(format!("`{}` does not match its SHA-256", file.name)));
    }
    Ok(())
}

/// Fetch `url` (https, or http on loopback for testing) and verify it. Blocking.
pub fn check(url: &str, trusted: &[[u8; 32]], channel: &str, installed: &str, now: u64) -> Result<UpdateCheck> {
    let ok_scheme = url.starts_with("https://") || url.starts_with("http://127.0.0.1:") || url.starts_with("http://localhost:");
    if !ok_scheme {
        return Err(CoreError::Invalid("update URL must be https (http only on loopback)".into()));
    }
    crate::offline::check_url(url)?;
    let resp = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(20))
        .timeout_connect(crate::offline::CONNECT_TIMEOUT)
        .resolver(crate::offline::resolve)
        .redirects(0)
        .build()
        .get(url)
        .call()
        .map_err(|e| CoreError::Invalid(format!("could not fetch the update manifest: {e}")))?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(resp.into_reader(), MAX_MANIFEST_BYTES as u64 + 1), &mut bytes)?;
    verify_manifest(&bytes, trusted, channel, installed, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign(key: &SigningKey, payload: &[u8]) -> Vec<u8> {
        let pk = key.verifying_key().to_bytes();
        serde_json::to_vec(&serde_json::json!({
            "payload": B64.encode(payload),
            "signatures": [{ "keyid": key_id(&pk), "sig": B64.encode(key.sign(payload).to_bytes()) }],
        }))
        .unwrap()
    }

    fn payload(version: &str, expires: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": 1, "channel": "stable", "version": version, "expires": expires, "notes": "fixes",
            "files": [{ "name": "Bastion.zip", "url": "https://example.test/Bastion.zip",
                        "sha256": hex::encode(Sha256::digest(b"app")), "size": 3 }],
        }))
        .unwrap()
    }

    const NOW: u64 = 1_800_000_000;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    #[test]
    fn valid_manifest_offers_newer_version_and_reports_up_to_date() {
        let k = key(1);
        let trusted = [k.verifying_key().to_bytes()];
        let m = sign(&k, &payload("0.2.0", NOW + 3600));
        match verify_manifest(&m, &trusted, "stable", "0.1.0", NOW).unwrap() {
            UpdateCheck::Available(m) => {
                assert_eq!(m.version, "0.2.0");
                verify_file(b"app", &m.files[0]).unwrap();
                assert!(verify_file(b"apq", &m.files[0]).is_err(), "changed bytes refused");
                assert!(verify_file(b"apps", &m.files[0]).is_err(), "wrong size refused");
            }
            other => panic!("expected an update, got {other:?}"),
        }
        assert_eq!(verify_manifest(&m, &trusted, "stable", "0.2.0", NOW).unwrap(), UpdateCheck::UpToDate { latest: "0.2.0".into() });
    }

    #[test]
    fn tampered_wrong_key_expired_and_downgrade_are_refused() {
        let k = key(1);
        let trusted = [k.verifying_key().to_bytes()];
        let good = sign(&k, &payload("0.2.0", NOW + 3600));
        // Tampered: swap the payload for another one, keep the signature.
        let mut env: serde_json::Value = serde_json::from_slice(&good).unwrap();
        env["payload"] = B64.encode(payload("9.9.9", NOW + 3600)).into();
        assert!(matches!(verify_manifest(&serde_json::to_vec(&env).unwrap(), &trusted, "stable", "0.1.0", NOW), Err(CoreError::PolicyDenied(_))));
        // Wrong key, also when it claims the trusted key's id.
        let other = sign(&key(2), &payload("0.2.0", NOW + 3600));
        assert!(matches!(verify_manifest(&other, &trusted, "stable", "0.1.0", NOW), Err(CoreError::PolicyDenied(_))));
        let mut forged: serde_json::Value = serde_json::from_slice(&other).unwrap();
        forged["signatures"][0]["keyid"] = key_id(&trusted[0]).into();
        assert!(verify_manifest(&serde_json::to_vec(&forged).unwrap(), &trusted, "stable", "0.1.0", NOW).is_err());
        assert!(verify_manifest(&good, &[], "stable", "0.1.0", NOW).is_err(), "no trusted keys, no updates");
        // Expired (freeze) and implausibly long-lived manifests.
        assert!(verify_manifest(&sign(&k, &payload("0.2.0", NOW)), &trusted, "stable", "0.1.0", NOW).is_err());
        assert!(verify_manifest(&sign(&k, &payload("0.2.0", NOW + MAX_VALIDITY_SECS + 1)), &trusted, "stable", "0.1.0", NOW).is_err());
        // Rollback: an older version than installed.
        let err = verify_manifest(&sign(&k, &payload("0.1.0", NOW + 3600)), &trusted, "stable", "0.2.0", NOW).unwrap_err();
        assert!(err.to_string().contains("rollback"));
        // Other channel, garbage, oversized.
        assert!(verify_manifest(&good, &trusted, "beta", "0.1.0", NOW).is_err());
        assert!(verify_manifest(b"{}", &trusted, "stable", "0.1.0", NOW).is_err());
        assert!(verify_manifest(&vec![b' '; MAX_MANIFEST_BYTES + 1], &trusted, "stable", "0.1.0", NOW).is_err());
    }

    #[test]
    fn versions_compare_numerically_and_files_need_https() {
        assert!(parse_version("0.10.0").unwrap() > parse_version("0.9.9").unwrap());
        assert_eq!(parse_version("1.2.3-beta").unwrap(), (1, 2, 3));
        assert!(parse_version("1.2").is_err() && parse_version("a.b.c").is_err());
        let k = key(1);
        let mut p: serde_json::Value = serde_json::from_slice(&payload("0.2.0", NOW + 60)).unwrap();
        p["files"][0]["url"] = "http://example.test/x".into();
        let m = sign(&k, &serde_json::to_vec(&p).unwrap());
        assert!(verify_manifest(&m, &[k.verifying_key().to_bytes()], "stable", "0.1.0", NOW).is_err());
        assert!(check("http://example.test/m.json", &[], "stable", "0.1.0", NOW).is_err(), "plain http off loopback refused");
    }
}
