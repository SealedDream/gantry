//! Release records and tiers (sections 7 and 9).
//!
//! A release record is a signed envelope whose payload is JSON:
//!
//! ```json
//! {"schema": 1, "id": "com.example.tool", "version": "1.0.0", "tier": "external",
//!  "sha256": "<64 hex>", "size": 12345, "api": {"min": "1.0", "max": "1.0"},
//!  "permissions": {"network": "entry", "files": ["save"]},
//!  "source": {"repository": "https://...", "commit": "<40 hex>"}}
//! ```
//!
//! The tier comes only from signatures. Official needs an index key (purpose `release-record`)
//! and the official key (purpose `official`); External needs an index key alone; with no valid
//! record a package is Unverified. The `tier` the record states must agree with its signatures,
//! and is never what grants the tier.
use serde::Deserialize;

use super::error::{Excerpt, PluginError};
use super::manifest::{is_https_address, is_plugin_id, is_reserved_id, names_bastion, ApiVersion, Permissions, Version};
use super::package::{Package, MAX_PACKAGE_FILE_BYTES};
use super::sign::{Envelope, Purpose, TrustedKeys};

/// A record is small (it ships as `<id>-<version>.sig`); anything larger is refused unparsed.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;
const SCHEMA: u32 = 1;

/// Ordered from least to most trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// No valid release record.
    Unverified,
    /// Signed by an index key.
    External,
    /// Signed by an index key and the official key.
    Official,
}

/// A release record whose signatures were checked. It can only be built by
/// [`verify_release_record`] or by `verify_index`, so holding one is proof of its tier.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedRecord {
    pub id: String,
    pub version: Version,
    /// From the signatures; never `Unverified`.
    pub tier: Tier,
    pub sha256: [u8; 32],
    pub size: u64,
    pub api_min: ApiVersion,
    pub api_max: ApiVersion,
    pub permissions: Permissions,
    pub source_repository: String,
    pub source_commit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecord {
    schema: u32,
    id: String,
    version: String,
    tier: String,
    sha256: String,
    size: u64,
    api: RawApi,
    permissions: RawPermissions,
    source: RawSource,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApi {
    min: String,
    max: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPermissions {
    network: Option<String>,
    credentials: Option<String>,
    storage: Option<bool>,
    clipboard: Option<String>,
    files: Option<Vec<String>>,
    http: Option<String>,
    open: Option<Vec<String>>,
    #[serde(default)]
    exec: Option<String>,
    library: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSource {
    repository: String,
    commit: String,
}

fn malformed(reason: &str) -> PluginError {
    PluginError::RecordMalformed(Excerpt::new(reason.as_bytes()))
}

fn lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The payload, checked field by field. `stated_tier` is what the record says, not yet what
/// its signatures give.
fn parse(payload: &[u8]) -> Result<(VerifiedRecord, Tier), PluginError> {
    let raw: RawRecord = serde_json::from_slice(payload).map_err(|e| malformed(&e.to_string()))?;
    if raw.schema != SCHEMA {
        return Err(malformed("`schema` must be 1"));
    }
    if !is_plugin_id(&raw.id) {
        return Err(malformed("`id` is not a valid plugin id"));
    }
    let version = Version::parse(&raw.version).ok_or_else(|| malformed("`version` is not a valid version"))?;
    let stated_tier = match raw.tier.as_str() {
        "official" => Tier::Official,
        "external" => Tier::External,
        _ => return Err(malformed("`tier` must be `official` or `external`")),
    };
    let sha256 = Some(&raw.sha256).filter(|text| lower_hex(text, 64)).and_then(|text| hex::decode(text).ok()).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
    let sha256 = sha256.ok_or_else(|| malformed("`sha256` must be 64 lower-case hex digits"))?;
    if raw.size == 0 || raw.size > MAX_PACKAGE_FILE_BYTES as u64 {
        return Err(malformed("`size` is not a size a package can have"));
    }
    let api_min = ApiVersion::parse(&raw.api.min).ok_or_else(|| malformed("`api.min` is not a valid API version"))?;
    let api_max = ApiVersion::parse(&raw.api.max).ok_or_else(|| malformed("`api.max` is not a valid API version"))?;
    if api_min > api_max {
        return Err(malformed("`api.min` is above `api.max`"));
    }
    let p = &raw.permissions;
    let files: Option<Vec<&str>> = p.files.as_ref().map(|files| files.iter().map(String::as_str).collect());
    let open: Option<Vec<&str>> = p.open.as_ref().map(|open| open.iter().map(String::as_str).collect());
    let mut permissions = Permissions::from_parts(p.network.as_deref(), p.credentials.as_deref(), p.storage, p.clipboard.as_deref(), files.as_deref(), p.http.as_deref(), open.as_deref(), p.library.as_deref()).map_err(|_| malformed("a permission has a value that is not allowed"))?;
    permissions.exec_entry = Permissions::exec_word(p.exec.as_deref()).map_err(|_| malformed("a permission has a value that is not allowed"))?;
    if !is_https_address(&raw.source.repository) {
        return Err(malformed("`source.repository` must be an https address"));
    }
    if !lower_hex(&raw.source.commit, 40) {
        return Err(malformed("`source.commit` must be a full 40-digit commit hash"));
    }
    let record = VerifiedRecord { id: raw.id, version, tier: stated_tier, sha256, size: raw.size, api_min, api_max, permissions, source_repository: raw.source.repository, source_commit: raw.source.commit };
    Ok((record, stated_tier))
}

/// Check the signatures of a parsed envelope, then its payload, and derive the tier.
pub(super) fn verify_envelope(envelope: &Envelope, keys: &TrustedKeys, revoked_index_keys: &[[u8; 32]]) -> Result<VerifiedRecord, PluginError> {
    if envelope.payload().len() > MAX_RECORD_BYTES {
        return Err(PluginError::RecordTooLarge);
    }
    // Nothing in the payload is read before an index key has vouched for its exact bytes.
    envelope.require(Purpose::ReleaseRecord, keys, revoked_index_keys)?;
    let (mut record, stated_tier) = parse(envelope.payload())?;
    let official = envelope.is_signed_for(Purpose::Official, keys, revoked_index_keys);
    record.tier = match (stated_tier, official) {
        (_, false) if is_reserved_id(&record.id) => return Err(PluginError::ReservedIdNeedsOfficial),
        (Tier::Official, true) => Tier::Official,
        // Ask again only to learn which rule the official signature broke.
        (Tier::Official, false) => return Err(envelope.require(Purpose::Official, keys, revoked_index_keys).err().unwrap_or(PluginError::SignatureMissing(Purpose::Official))),
        (_, true) => return Err(PluginError::RecordTierMismatch),
        (_, false) => Tier::External,
    };
    Ok(record)
}

/// Verify a release record (`<id>-<version>.sig`) over its exact bytes with `verify_strict`.
///
/// `revoked_index_keys` are index keys an earlier index revoked; a record signed only by one of
/// them is refused. No valid record means the package is Unverified: pass `None` to
/// [`check_package_against_record`].
pub fn verify_release_record(bytes: &[u8], keys: &TrustedKeys, revoked_index_keys: &[[u8; 32]]) -> Result<VerifiedRecord, PluginError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(PluginError::RecordTooLarge);
    }
    verify_envelope(&Envelope::parse(bytes)?, keys, revoked_index_keys)
}

/// Check a package against its verified record and return the tier it may be installed at.
///
/// With a record: the package's SHA-256 and size, and the manifest's id, version and
/// permissions, must all match it, and the manifest's API version must lie in its API range. Without one the package is Unverified, unless its id is
/// under `dev.bastion`, which is refused without the official signature.
pub fn check_package_against_record(package: &Package, record: Option<&VerifiedRecord>) -> Result<Tier, PluginError> {
    let manifest = &package.manifest;
    // A name or publisher with "Bastion" in it claims to be ours: only the official signature
    // may carry it (A1-C11).
    let claims_bastion = names_bastion(&manifest.name) || names_bastion(&manifest.publisher);
    // `http.paths = ["/"]` reaches the whole server: Official plugins only (plugin API 1.1,
    // `docs/specs/plugins-amendment-2.md` section 3 and its review).
    let root_http = manifest.http.as_ref().is_some_and(|h| h.has_root_prefix());
    let Some(record) = record else {
        return if is_reserved_id(&manifest.id) {
            Err(PluginError::ReservedIdNeedsOfficial)
        } else if root_http {
            Err(PluginError::BadValue("http.paths"))
        } else if claims_bastion {
            Err(PluginError::BastionNameNeedsOfficial)
        } else {
            Ok(Tier::Unverified)
        };
    };
    if package.size != record.size {
        return Err(PluginError::PackageSizeMismatch);
    }
    if package.sha256 != record.sha256 {
        return Err(PluginError::PackageHashMismatch);
    }
    if manifest.id != record.id {
        return Err(PluginError::ManifestRecordMismatch("id"));
    }
    if manifest.version != record.version {
        return Err(PluginError::ManifestRecordMismatch("version"));
    }
    if manifest.permissions != record.permissions {
        return Err(PluginError::ManifestRecordMismatch("permissions"));
    }
    // The manifest names the lowest API version it needs; the record names the range the
    // reviewed build was made for.
    if manifest.api < record.api_min || manifest.api > record.api_max {
        return Err(PluginError::ManifestRecordMismatch("api"));
    }
    // `verify_envelope` already refuses this; it is repeated so the rule holds on its own here.
    if is_reserved_id(&manifest.id) && record.tier != Tier::Official {
        return Err(PluginError::ReservedIdNeedsOfficial);
    }
    if claims_bastion && record.tier != Tier::Official {
        return Err(PluginError::BastionNameNeedsOfficial);
    }
    if root_http && record.tier != Tier::Official {
        return Err(PluginError::BadValue("http.paths"));
    }
    Ok(record.tier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_are_ordered_by_trust() {
        assert!(Tier::Official > Tier::External && Tier::External > Tier::Unverified);
    }

    #[test]
    fn hashes_must_be_lower_case_hex_of_the_exact_length() {
        assert!(lower_hex(&"0123456789abcdef".repeat(4), 64));
        assert!(!lower_hex(&"0123456789ABCDEF".repeat(4), 64));
        assert!(!lower_hex(&"a".repeat(63), 64) && !lower_hex(&"a".repeat(65), 64) && !lower_hex(&"g".repeat(64), 64));
    }
}
