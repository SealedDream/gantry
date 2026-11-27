//! Plugin packages, manifests, release records and the signed index: the verifying half
//! (PLUG-04a; design in `docs/specs/plugins.md`, sections 5, 6, 7 and 9).
//!
//! Everything here is a pure function over untrusted bytes. There is no state, no disk access,
//! no network and no clock: the time, the trusted keys, the revoked index keys and the highest
//! index sequence seen are passed in, as in `crate::update::verify_manifest`. Nothing is wired
//! to these functions yet. The production keys are pinned in `catalogue::pinned_keys` (PLUG-12).
//!
//! - [`parse_manifest`]: `plugin.toml`, typed, unknown keys refused.
//! - [`read_package`]: a `.bastionplugin` from a byte slice into memory, never to disk.
//! - [`verify_release_record`]: a signed release record, and the tier its signatures give.
//! - [`check_package_against_record`]: hash, size, id, version and permissions.
//! - [`verify_index`] and [`is_revoked`]: the signed index and its revocation list.
//!
//! PLUG-04b part 1 adds the state and the disk:
//!
//! - [`accept_index`] and [`TrustState`]: the stored sequence floor, its reset when the floor's
//!   signer is revoked, the clock rule and the union of revocations (A1-C12).
//! - [`install`], [`remove`], [`list_installed`] and [`load_installed`]: the plugins folder.
//!
//! PLUG-04b part 2 adds [`check_imports`] (the import list of `plugin.wasm`), fetching and
//! caching the index ([`refresh`], [`load_cached`], [`fetch_package`]) and [`plan_updates`].

mod error;
pub mod broker;
mod catalogue;
mod file_install;
pub mod highlight;
pub mod host;
mod imports;
mod index;
mod install;
pub mod library_save;
mod manifest;
mod package;
mod record;
mod sign;
mod trust;

pub use error::{Excerpt, PluginError};
pub(crate) use manifest::{check_text, is_label, is_plugin_id, TextFault};
pub use highlight::{tokenize_line, tokenize_text, LineState, LineTokens, TextTokens, Token, TokenKind};
pub use index::{is_revoked, verify_index, Index, IndexOutcome, Revocation, MAX_INDEX_BYTES, MAX_INDEX_RECORDS, MAX_INDEX_VALIDITY_SECS};
pub use manifest::{SIDEBAR_VIEW, 
    canonical_plugin_id, is_reserved_id, parse_manifest, ApiVersion, Command, ConnectionType, Field, FieldKind, Manifest, Permissions, Version, MAX_COMMAND_TITLE_CHARS, MAX_DESCRIPTION_CHARS,
    MAX_FIELD_LABEL_CHARS, MAX_MANIFEST_BYTES, MAX_NAME_CHARS,
};
pub use package::{read_package, read_package_counted, Package, ReadCount, MAX_ENTRIES, MAX_ICON_BYTES, MAX_PACKAGE_FILE_BYTES, MAX_RATIO, MAX_UNCOMPRESSED_BYTES};
pub use record::{check_package_against_record, verify_release_record, Tier, VerifiedRecord, MAX_RECORD_BYTES};
pub use catalogue::{fetch_package, load_cached, package_file_name, pinned_keys, plan_updates, refresh, CatalogueSource, FolderCatalogue, HttpCatalogue, PlannedUpdate, RefreshOutcome, APP_API, INDEX_FILE};
pub use file_install::install_file;
pub use imports::{check_imports, component_imports};
pub use install::{accept_and_store, install, list_installed, load_installed, load_installed_with, refused_audit, remove, revoked_audit, InstallKind, InstallRequest, InstallResult, Installed, InstalledVersion, PluginFolders};
pub use trust::{accept_index, Floor, IndexDecision, IndexRefusal, StoredRevocation, TrustState};
pub use sign::{key_id, signed_message, Purpose, TrustedKeys, MAX_SIGNATURES};
