//! Fetching the signed index and packages, the stored copy of the index, and the update plan
//! (PLUG-04b part 2; `docs/specs/plugins.md`, sections 8 and 9).
//!
//! Everything fetched is untrusted until [`accept_index`] or [`install`](super::install) has
//! checked it. A fetch that fails changes nothing (fail safe): the stored floor, revocations
//! and cached index stay as they are. Network fetches go through [`ReleaseFetcher`] (https only,
//! allowed hosts, redirects checked, size caps, the offline guard).
use std::path::{Path, PathBuf};

use super::error::{Excerpt, PluginError};
use super::index::{verify_index, Index, IndexOutcome, MAX_INDEX_BYTES};
use super::install::{io, FolderLock, Installed, PluginFolders};
use super::manifest::{ApiVersion, Permissions, Version};
use super::package::MAX_PACKAGE_FILE_BYTES;
use super::record::{Tier, VerifiedRecord};
use super::sign::TrustedKeys;
use super::trust::{accept_index, IndexDecision, TrustState};
use crate::update::github::ReleaseFetcher;

/// The plugin API this build of the app provides.
/// 1.1 adds the `http` interface (`docs/specs/plugins-amendment-2.md`); 1.2 adds `open`
/// (`docs/specs/plugins-amendment-3.md`).
pub const APP_API: ApiVersion = ApiVersion { major: 1, minor: 6 };
/// The index file's name, in the catalogue and in the plugins folder (the cached copy).
pub const INDEX_FILE: &str = "plugin-index.json";

/// Index keys (key ceremony 2026-11-20, PLUG-12): A, the active key (key id 83ac7bd28c260b05),
/// then B, the offline spare (key id ece1ba7bebf86c48). Runbook: `docs/plugins/OPERATIONS.md`.
const INDEX_KEYS: [[u8; 32]; 2] = [
    hex32("927a245f9d94ec233922a9fb8bf5894de3d5cb26c8a0b79fadd1119768e53eb8"),
    hex32("3eccfc88267a8d71341f8b2d5096182cb84dcb2e3b4cfb4ece77022daa42e23e"),
];
/// The official key (2026-11-20, key id 3d4f5284a2353382). It co-signs Official release records.
const OFFICIAL_KEYS: [[u8; 32]; 1] = [hex32("993cc0a1b52650a5f6a452a2b3eddf9ffbd2dc72f7bbe9dafab1c681b82f62d9")];

/// 64 hex digits to 32 bytes, at compile time: a typo in a pinned key fails the build.
const fn hex32(text: &str) -> [u8; 32] {
    const fn digit(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("a pinned key is lower-case hex"),
        }
    }
    let bytes = text.as_bytes();
    assert!(bytes.len() == 64, "a pinned key is 64 hex digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = digit(bytes[2 * i]) << 4 | digit(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

/// The pinned production keys, shared by all four apps. Keys rotate only through an app update.
pub fn pinned_keys() -> TrustedKeys<'static> {
    TrustedKeys { index: &INDEX_KEYS, official: &OFFICIAL_KEYS }
}

/// The package file name of a record, in a catalogue or a mirror folder.
pub fn package_file_name(record: &VerifiedRecord) -> String {
    format!("{}-{}.gantryplugin", record.id, record.version)
}

/// Where the index and packages come from.
pub trait CatalogueSource {
    /// The index bytes, at most [`MAX_INDEX_BYTES`].
    fn index(&self) -> Result<Vec<u8>, PluginError>;
    /// The package bytes of `record`, at most `record.size`.
    fn package(&self, record: &VerifiedRecord) -> Result<Vec<u8>, PluginError>;
}

fn unreachable(e: impl std::fmt::Display) -> PluginError {
    PluginError::Unreachable(Excerpt::new(e.to_string().as_bytes()))
}

fn package_limit(record: &VerifiedRecord) -> u64 {
    record.size.min(MAX_PACKAGE_FILE_BYTES as u64)
}

/// A catalogue on the web: `<base>/plugin-index.json` and `<base>/<id>-<version>.gantryplugin`.
pub struct HttpCatalogue {
    fetcher: ReleaseFetcher,
    base: String,
}

impl HttpCatalogue {
    /// The official catalogue: the `plugin-catalogue` release of the Bastion repository.
    pub fn official() -> Self {
        Self::at("https://github.com/SealedDream/gantry/releases/download/plugin-catalogue", crate::update::github::ALLOWED_HOSTS)
            .expect("the official address is valid")
    }

    /// A catalogue at an https `base`, fetched only from `hosts` (redirects included).
    pub fn at(base: &str, hosts: &[&str]) -> Result<Self, PluginError> {
        let base = base.trim_end_matches('/');
        if !base.starts_with("https://") || hosts.is_empty() {
            return Err(unreachable("a catalogue address must be https and name its hosts"));
        }
        Ok(Self { fetcher: ReleaseFetcher::for_hosts(base, hosts), base: base.to_string() })
    }
}

impl CatalogueSource for HttpCatalogue {
    fn index(&self) -> Result<Vec<u8>, PluginError> {
        self.fetcher.get(&format!("{}/{INDEX_FILE}", self.base), MAX_INDEX_BYTES as u64).map_err(unreachable)
    }

    fn package(&self, record: &VerifiedRecord) -> Result<Vec<u8>, PluginError> {
        self.fetcher.get(&format!("{}/{}", self.base, package_file_name(record)), package_limit(record)).map_err(unreachable)
    }
}

/// A mirror folder holding the same files (offline use).
pub struct FolderCatalogue(pub PathBuf);

fn read_capped(path: &Path, limit: u64) -> Result<Vec<u8>, PluginError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(unreachable)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).map_err(unreachable)?;
    if bytes.len() as u64 > limit {
        return Err(unreachable("the file is larger than its limit"));
    }
    Ok(bytes)
}

impl CatalogueSource for FolderCatalogue {
    fn index(&self) -> Result<Vec<u8>, PluginError> {
        read_capped(&self.0.join(INDEX_FILE), MAX_INDEX_BYTES as u64)
    }

    fn package(&self, record: &VerifiedRecord) -> Result<Vec<u8>, PluginError> {
        read_capped(&self.0.join(package_file_name(record)), package_limit(record))
    }
}

/// What [`refresh`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// The index was checked; `decision` says whether it was accepted. An accepted index is
    /// stored as the cached copy and its floor and revocations are saved.
    Checked(IndexDecision),
    /// The catalogue could not be reached or read. Nothing was changed.
    Unreachable(String),
}

/// Fetch the index from `source`, check it against the stored state and store it.
pub fn refresh(folders: &PluginFolders, keys: &TrustedKeys, source: &dyn CatalogueSource, now: u64) -> Result<RefreshOutcome, PluginError> {
    let bytes = match source.index() {
        Ok(bytes) => bytes,
        Err(e) => return Ok(RefreshOutcome::Unreachable(e.to_string())),
    };
    let _lock = FolderLock::acquire(folders)?;
    let mut state = TrustState::load(&folders.trust_path())?;
    let decision = accept_index(&mut state, &bytes, keys, now)?;
    if matches!(decision, IndexDecision::Accepted { .. }) {
        state.save(&folders.trust_path())?;
        crate::store::write_atomic(&folders.plugins_dir().join(INDEX_FILE), &bytes).map_err(io)?;
    }
    Ok(RefreshOutcome::Checked(decision))
}

/// The cached index, checked again. `None` when there is none or it no longer verifies.
pub fn load_cached(folders: &PluginFolders, keys: &TrustedKeys, now: u64) -> Option<IndexOutcome> {
    let state = TrustState::load(&folders.trust_path()).ok()?;
    let bytes = read_capped(&folders.plugins_dir().join(INDEX_FILE), MAX_INDEX_BYTES as u64).ok()?;
    let outcome = verify_index(&bytes, keys, &state.revoked_index_keys(), 0, now).ok()?;
    // Only the floor's own index is used; an older cached file is ignored.
    match &outcome {
        IndexOutcome::Usable(i) | IndexOutcome::Expired(i) | IndexOutcome::ClockBeforeIssue(i) if state.floor().is_some_and(|f| f.sequence == i.sequence) => Some(outcome),
        _ => None,
    }
}

/// Fetch the package of `record`. Its hash and size are checked at install.
pub fn fetch_package(source: &dyn CatalogueSource, record: &VerifiedRecord) -> Result<Vec<u8>, PluginError> {
    source.package(record)
}

/// One update the catalogue offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedUpdate {
    pub id: String,
    pub from: String,
    pub record: VerifiedRecord,
    /// The new version asks for permissions the installed one did not have: ask first.
    pub needs_consent: bool,
}

fn adds_permissions(old: &Permissions, new: &Permissions) -> bool {
    // Destructured without `..`: a new permission flag does not compile until it is listed here.
    let flags = |p: &Permissions| {
        let Permissions { network_entry, credentials_entry, storage, clipboard_write, files_save, files_open, http_entry, open_ssh, open_rdp, open_vnc, exec_entry, library_propose } = *p;
        [network_entry, credentials_entry, storage, clipboard_write, files_save, files_open, http_entry, open_ssh, open_rdp, open_vnc, exec_entry, library_propose]
    };
    flags(old).iter().zip(flags(new).iter()).any(|(o, n)| *n && !*o)
}

/// Whether this app runs a release built for `min..=max` (spec section 5, "API versions"):
/// it needs nothing newer than [`APP_API`], and it was built for the app's major version or
/// the one before. Minor versions only add, so a 1.0 build runs on a 1.1 app.
pub fn app_runs(min: ApiVersion, max: ApiVersion) -> bool {
    min <= APP_API && APP_API.major <= max.major.saturating_add(1)
}

/// The updates `index` offers for `installed`: for each verified plugin, the highest version
/// above the installed one that is not revoked (in the index or the stored state), supports
/// [`APP_API`] and is at least the installed tier. `permissions_of` gives an installed
/// plugin's current permissions. Unverified plugins are never updated from the catalogue.
pub fn plan_updates(installed: &[Installed], index: &Index, trust: &TrustState, permissions_of: impl Fn(&Installed) -> Option<Permissions>) -> Vec<PlannedUpdate> {
    let mut plans = Vec::new();
    for plugin in installed {
        let tier = plugin.current.tier();
        if tier == Tier::Unverified {
            continue;
        }
        let Some(current) = Version::parse(&plugin.current.version) else { continue };
        let best = index
            .records
            .iter()
            .filter(|r| r.id == plugin.id && r.version > current && r.tier >= tier)
            .filter(|r| app_runs(r.api_min, r.api_max))
            .filter(|r| index.revocation_for(&r.id, &r.version).is_none() && trust.revocation_for(&r.id, &r.version).is_none())
            .max_by_key(|r| r.version);
        if let Some(record) = best {
            let needs_consent = permissions_of(plugin).is_none_or(|old| adds_permissions(&old, &record.permissions));
            plans.push(PlannedUpdate { id: plugin.id.clone(), from: plugin.current.version.clone(), record: record.clone(), needs_consent });
        }
    }
    plans
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_app_runs_older_minor_builds_and_the_previous_major() {
        let v = |major, minor| ApiVersion { major, minor };
        assert!(app_runs(v(1, 0), v(1, 0)), "a 1.0 build on a 1.1 app");
        assert!(app_runs(v(1, 1), v(1, 1)));
        assert!(app_runs(v(1, 2), v(1, 2)));
        assert!(app_runs(v(1, 3), v(1, 3)));
        assert!(app_runs(v(1, 4), v(1, 4)));
        assert!(app_runs(v(1, 5), v(1, 5)));
        assert!(app_runs(v(1, 6), v(1, 6)), "1.6: stat tiles and status/meter cells; library.propose");
        assert!(!app_runs(v(1, 7), v(1, 7)), "needs a newer app");
        assert!(!app_runs(v(2, 0), v(2, 0)));
        assert!(app_runs(v(0, 9), v(0, 9)), "the previous major");
    }

    #[test]
    fn the_ceremony_keys_are_pinned_in_their_roles() {
        let keys = pinned_keys();
        let ids = |k: &[[u8; 32]]| k.iter().map(super::super::sign::key_id).collect::<Vec<_>>();
        assert_eq!(ids(keys.index), ["83ac7bd28c260b05", "ece1ba7bebf86c48"]);
        assert_eq!(ids(keys.official), ["3d4f5284a2353382"]);
        assert!(keys.official.iter().all(|k| !keys.index.contains(k)), "no key in both roles");
    }

    #[test]
    fn only_https_addresses_with_hosts_are_accepted() {
        assert!(HttpCatalogue::at("http://example.org/c", &["example.org"]).is_err());
        assert!(HttpCatalogue::at("https://example.org/c", &[]).is_err());
        assert!(HttpCatalogue::at("https://example.org/c/", &["example.org"]).is_ok());
        let _ = HttpCatalogue::official();
    }

    #[test]
    fn new_permissions_need_consent() {
        let none = Permissions::default();
        let net = Permissions { network_entry: true, ..none };
        assert!(adds_permissions(&none, &net));
        assert!(!adds_permissions(&net, &none));
        assert!(!adds_permissions(&net, &net));
        assert!(adds_permissions(&none, &Permissions { http_entry: true, ..none }), "http needs consent too");
        assert!(adds_permissions(&Permissions { open_ssh: true, ..none }, &Permissions { open_ssh: true, open_rdp: true, ..none }), "a new protocol needs consent");
    }

    #[test]
    fn a_missing_or_oversized_mirror_file_is_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(FolderCatalogue(dir.path().into()).index(), Err(PluginError::Unreachable(_))));
        std::fs::write(dir.path().join("big"), vec![0u8; 11]).unwrap();
        assert!(read_capped(&dir.path().join("big"), 10).is_err());
        assert_eq!(read_capped(&dir.path().join("big"), 11).unwrap().len(), 11);
    }
}
