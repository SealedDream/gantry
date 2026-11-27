//! Errors of the plugin verifier. Each one names the rule that failed. They are safe to show:
//! untrusted text only ever appears as an [`Excerpt`], which is at most 64 bytes of printable
//! ASCII.
use std::fmt;

use thiserror::Error;

use super::sign::Purpose;
use crate::error::CoreError;

/// At most [`Excerpt::MAX_BYTES`] bytes of untrusted input, with everything that is not printable
/// ASCII replaced by `?`, so an error can be logged or shown without carrying markup, control
/// characters or a large part of a hostile file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Excerpt(String);

impl Excerpt {
    pub const MAX_BYTES: usize = 64;

    pub fn new(untrusted: &[u8]) -> Self {
        let shown = untrusted.iter().take(Self::MAX_BYTES).map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '?' });
        let mut text: String = shown.collect();
        if untrusted.len() > Self::MAX_BYTES {
            text.push_str("...");
        }
        Excerpt(text)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Excerpt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PluginError {
    // ---- package (section 6, "Reading rules") ----
    #[error("plugin package: the file is larger than a package can be")]
    PackageTooLarge,
    #[error("plugin package: not a complete zip file (the end record is missing or cut short)")]
    ZipTruncated,
    #[error("plugin package: there is data after the end of the zip")]
    ZipTrailingData,
    #[error("plugin package: the zip uses a feature that packages may not use ({0})")]
    ZipUnsupported(&'static str),
    #[error("plugin package: the zip is damaged ({0})")]
    ZipMalformed(&'static str),
    #[error("plugin package: more than 16 entries")]
    TooManyEntries,
    #[error("plugin package: an entry name is not ASCII")]
    NameNotAscii,
    #[error("plugin package: entry `{0}` has an absolute path")]
    NameAbsolute(Excerpt),
    #[error("plugin package: entry `{0}` has `..` in its path")]
    NameParent(Excerpt),
    #[error("plugin package: entry `{0}` is a folder or is inside one")]
    EntryIsFolder(Excerpt),
    #[error("plugin package: entry `{0}` is a link")]
    EntryIsLink(Excerpt),
    #[error("plugin package: entry `{0}` differs from another entry only by case")]
    NameCaseDuplicate(Excerpt),
    #[error("plugin package: entry `{0}` appears twice")]
    NameDuplicate(Excerpt),
    #[error("plugin package: entry `{0}` is not one of the files a package may hold")]
    EntryNotAllowed(Excerpt),
    #[error("plugin package: `{0}` is missing")]
    MissingFile(&'static str),
    #[error("plugin package: more than 50 MiB uncompressed")]
    UncompressedTooLarge,
    #[error("plugin package: `{0}` is compressed by more than 100 to 1")]
    RatioTooHigh(&'static str),
    #[error("plugin package: `{0}` is not the size its header states")]
    SizeMismatch(&'static str),
    #[error("plugin package: `{0}` does not match its checksum")]
    ChecksumMismatch(&'static str),
    #[error("plugin package: `{0}` is empty")]
    FileEmpty(&'static str),
    #[error("plugin package: `{0}` is not plain UTF-8 text")]
    FileNotText(&'static str),
    #[error("plugin package: `icon.png` is larger than 64 KiB")]
    IconTooLarge,
    #[error("plugin package: `icon.png` is not a PNG image")]
    IconNotPng,
    #[error("plugin package: `plugin.wasm` could not be read as a component ({0})")]
    WasmMalformed(&'static str),
    #[error("plugin package: `plugin.wasm` imports `{import}`, which is not allowed: {why}")]
    WasmImportNotAllowed { import: Excerpt, why: &'static str },

    // ---- manifest (section 6, limits of section 5) ----
    #[error("plugin manifest: larger than 64 KiB")]
    ManifestTooLarge,
    #[error("plugin manifest: not valid TOML ({0})")]
    ManifestSyntax(Excerpt),
    #[error("plugin manifest: unknown key `{0}`")]
    ManifestUnknownKey(Excerpt),
    #[error("plugin manifest: `{0}` is missing")]
    ManifestMissingKey(&'static str),
    #[error("plugin manifest: `{0}` has the wrong type")]
    ManifestWrongType(&'static str),
    #[error("plugin manifest: `schema` must be 1")]
    ManifestSchema,
    #[error("plugin manifest: `{0}` is not a valid id (lower-case letters, digits and hyphens; a plugin id is reverse DNS)")]
    BadId(&'static str),
    #[error("plugin manifest: `{0}` is not a valid version")]
    BadVersion(&'static str),
    #[error("plugin manifest: `{field}` is longer than {max} characters")]
    TextTooLong { field: &'static str, max: usize },
    #[error("plugin manifest: `{0}` contains a control character")]
    TextControlChar(&'static str),
    #[error("plugin manifest: `{0}` is empty")]
    TextEmpty(&'static str),
    #[error("plugin manifest: permission `{0}` has a value that is not allowed")]
    BadPermission(&'static str),
    #[error("plugin manifest: `{0}` has a value that is not allowed")]
    BadValue(&'static str),
    #[error("plugin manifest: `{0}` is used twice")]
    DuplicateId(&'static str),
    #[error("plugin manifest: connection-type field `{0}` looks like a secret; a plugin that needs one asks for `credentials = \"entry\"`")]
    SecretLikeField(Excerpt),

    // ---- signatures, release records and tiers (sections 7 and 9) ----
    #[error("plugin release record: larger than 16 KiB")]
    RecordTooLarge,
    #[error("signed plugin file: not a signed envelope ({0})")]
    EnvelopeMalformed(&'static str),
    #[error("signed plugin file: no {0} signature")]
    SignatureMissing(Purpose),
    #[error("signed plugin file: the {0} signature is not by a trusted key")]
    SignatureUntrustedKey(Purpose),
    #[error("signed plugin file: the {0} signature does not match the signed bytes")]
    SignatureInvalid(Purpose),
    #[error("signed plugin file: a signature made for another purpose was offered as the {0} signature")]
    SignatureWrongPurpose(Purpose),
    #[error("signed plugin file: the {0} signature is by an index key that has been revoked")]
    SignatureRevokedKey(Purpose),
    #[error("plugin release record: not a valid record ({0})")]
    RecordMalformed(Excerpt),
    #[error("plugin release record: the tier it states does not match its signatures")]
    RecordTierMismatch,
    #[error("plugin id under `dev.bastion` needs the official signature")]
    ReservedIdNeedsOfficial,
    #[error("plugin package does not match the SHA-256 in its release record")]
    PackageHashMismatch,
    #[error("plugin package does not match the size in its release record")]
    PackageSizeMismatch,
    #[error("plugin manifest and release record disagree on `{0}`")]
    ManifestRecordMismatch(&'static str),
    #[error("a plugin whose name or publisher contains \"Gantry\" needs the official signature")]
    BastionNameNeedsOfficial,

    // ---- index (section 9) ----
    #[error("plugin index: larger than 4 MiB")]
    IndexTooLarge,
    #[error("plugin index: not a valid index ({0})")]
    IndexMalformed(Excerpt),
    #[error("plugin index: record {position} is not valid: {error}")]
    IndexRecordInvalid { position: usize, error: Box<PluginError> },
    #[error("plugin index: more than 4,096 release records")]
    IndexTooManyRecords,

    // ---- install and the stored index state (PLUG-04b) ----
    #[error("plugin: the stored catalogue state is damaged ({0}); it is kept as it is and no index is accepted until it is repaired")]
    TrustStateDamaged(Excerpt),
    #[error("plugin: unverified plugins are not allowed (the setting \"Allow unverified plugins\" is off)")]
    UnverifiedNotAllowed,
    #[error("plugin {id} {version} is revoked: {reason}")]
    Revoked { id: String, version: String, reason: String },
    #[error("plugin: the same id is installed at a higher tier, so this package cannot replace it")]
    HigherTierInstalled,
    #[error("plugin: version {offered} is older than the installed {installed}; only the kept previous version can be restored")]
    OlderVersion { offered: String, installed: String },
    #[error("plugin {0} is not installed")]
    NotInstalled(Excerpt),
    #[error("plugin: the installed copy of {0} does not match what was installed")]
    InstalledCopyChanged(Excerpt),
    #[error("plugin: version {version} is already installed from a different package; the offered package is not the one installed")]
    SameVersionDifferentPackage { version: String },
    #[error("plugin: another Gantry is changing the plugins folder; try again in a moment")]
    FolderBusy,
    #[error("plugin: the plugins folder could not be written ({0})")]
    Io(Excerpt),
    #[error("plugin: the catalogue could not be reached ({0}); nothing was changed")]
    Unreachable(Excerpt),
}

impl PluginError {
    /// True when a signature, a tier or a signed value did not hold, as opposed to a file that
    /// is malformed.
    fn is_trust_failure(&self) -> bool {
        use PluginError::*;
        match self {
            IndexRecordInvalid { error, .. } => error.is_trust_failure(),
            SignatureMissing(_) | SignatureUntrustedKey(_) | SignatureInvalid(_) | SignatureWrongPurpose(_) | SignatureRevokedKey(_) => true,
            RecordTierMismatch | ReservedIdNeedsOfficial | BastionNameNeedsOfficial | PackageHashMismatch | PackageSizeMismatch | ManifestRecordMismatch(_) => true,
            WasmImportNotAllowed { .. } | UnverifiedNotAllowed | Revoked { .. } | HigherTierInstalled | OlderVersion { .. } | InstalledCopyChanged(_) | SameVersionDifferentPackage { .. } => true,
            _ => false,
        }
    }
}

impl From<PluginError> for CoreError {
    fn from(error: PluginError) -> Self {
        if error.is_trust_failure() {
            CoreError::PolicyDenied(error.to_string())
        } else {
            CoreError::Invalid(error.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_excerpt_is_short_printable_ascii() {
        assert_eq!(Excerpt::new(b"plugin.toml").as_str(), "plugin.toml");
        assert_eq!(Excerpt::new(b"a\x1b[31m\n\xff").as_str(), "a?[31m??");
        let long = Excerpt::new(&[b'x'; 200]);
        assert_eq!(long.as_str(), format!("{}...", "x".repeat(64)));
        assert_eq!(Excerpt::new(&[b'x'; 64]).as_str(), "x".repeat(64));
    }

    #[test]
    fn trust_failures_map_to_policy_denied_and_the_rest_to_invalid() {
        assert_eq!(CoreError::from(PluginError::PackageHashMismatch).code(), "policy");
        assert_eq!(CoreError::from(PluginError::SignatureMissing(Purpose::Official)).code(), "policy");
        let nested = PluginError::IndexRecordInvalid { position: 3, error: Box::new(PluginError::ReservedIdNeedsOfficial) };
        assert_eq!(CoreError::from(nested).code(), "policy");
        assert_eq!(CoreError::from(PluginError::ZipTruncated).code(), "invalid");
        assert_eq!(CoreError::from(PluginError::ManifestSchema).code(), "invalid");
    }
}
