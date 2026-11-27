//! "Check for Updates": fetch the signed manifest from the latest GitHub release and report, then
//! (on request) download one of its files, verified. Installing is left to the host app.
use bastion_core::update::{self, github::{ReleaseFetcher, RELEASE_REPO}, UpdateCheck};

use crate::{FfiError, FfiResult};

/// Ed25519 public keys trusted to sign update manifests.
///
/// Release key (2026-11-03, key id d3691b950e725573). Its secret half is kept outside the repo, on
/// the release machine at `~/.config/bastion/release-signing.key` (mode 0600); `scripts/release.sh`
/// signs with it. To rotate: ship a build trusting both keys, then drop the old one.
const UPDATE_KEYS: [[u8; 32]; 1] = [hex32("3fbefcb27d3ed4970d4c41cec9e6d414f4e89250581033a63e101e97ea251a2d")];
const CHANNEL: &str = "stable";

/// Updates come from GitHub releases of `bastion_core::update::github::RELEASE_REPO`, so every
/// build has a channel. `BASTION_UPDATE_URL` still points a check (not a download) at another
/// manifest for testing; the signature is required either way.
#[uniffi::export]
pub fn update_channel_configured() -> bool {
    true
}

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("UPDATE_KEYS must be lowercase hex"),
    }
}

#[derive(uniffi::Record)]
pub struct UpdateFileView {
    pub name: String,
    pub size: u64,
}

#[derive(uniffi::Record)]
pub struct UpdateStatusView {
    pub installed: String,
    pub latest: String,
    pub available: bool,
    pub notes: String,
    /// Download page or file for the new version (https), when available.
    pub url: Option<String>,
    /// Unix seconds until which the manifest is valid.
    pub manifest_expires: Option<u64>,
    /// The release's signed files; pass one's `name` to [`download_update`].
    pub files: Vec<UpdateFileView>,
}

/// The version this build reports: `BASTION_VERSION` at build time (the release scripts set it from
/// the tag, and the same value goes into Info.plist and Gantry.exe), else the crate version.
pub const APP_VERSION: &str = match option_env!("BASTION_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[uniffi::export]
pub fn app_version() -> String {
    APP_VERSION.to_string()
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Where updates come from, and the keys trusted for them. Release builds: GitHub and
/// [`UPDATE_KEYS`] only. Test-hooks builds also honour `BASTION_UPDATE_BASE` (a local fake GitHub,
/// https), `BASTION_UPDATE_CA` (its DER certificate) and `BASTION_UPDATE_TEST_KEY` (one extra
/// trusted public key, hex), so the whole check, download and install path can be run end to end.
fn source() -> bastion_core::Result<(ReleaseFetcher, Vec<[u8; 32]>)> {
    #[cfg(feature = "test-hooks")]
    if let Ok(base) = std::env::var("BASTION_UPDATE_BASE") {
        let ca = std::fs::read(std::env::var("BASTION_UPDATE_CA").unwrap_or_default())?;
        let mut keys = UPDATE_KEYS.to_vec();
        if let Ok(hex) = std::env::var("BASTION_UPDATE_TEST_KEY") {
            keys.push(parse_key(&hex)?);
        }
        return Ok((ReleaseFetcher::test_server(&base, &ca)?, keys));
    }
    Ok((ReleaseFetcher::github(), UPDATE_KEYS.to_vec()))
}

#[cfg(feature = "test-hooks")]
fn parse_key(hex: &str) -> bastion_core::Result<[u8; 32]> {
    let bad = || bastion_core::CoreError::Invalid("BASTION_UPDATE_TEST_KEY must be 64 hex digits".into());
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

fn latest() -> bastion_core::Result<UpdateCheck> {
    if let Ok(url) = std::env::var("BASTION_UPDATE_URL") {
        return update::check(&url, &UPDATE_KEYS, CHANNEL, &app_version(), now());
    }
    let (fetcher, keys) = source()?;
    fetcher.check_latest(RELEASE_REPO, &keys, CHANNEL, &app_version(), now())
}

/// Fetch and verify the latest release's manifest (blocking: call off the main thread).
#[uniffi::export]
pub fn check_for_updates() -> FfiResult<UpdateStatusView> {
    let installed = app_version();
    Ok(match latest()? {
        UpdateCheck::UpToDate { latest } => {
            UpdateStatusView { installed, latest, available: false, notes: String::new(), url: None, manifest_expires: None, files: vec![] }
        }
        UpdateCheck::Available(m) => UpdateStatusView {
            installed,
            latest: m.version,
            available: true,
            notes: m.notes,
            url: m.files.first().map(|f| f.url.clone()),
            manifest_expires: Some(m.expires),
            files: m.files.into_iter().map(|f| UpdateFileView { name: f.name, size: f.size }).collect(),
        },
    })
}

/// Re-check the latest GitHub release and download its file `file_name` into the existing
/// directory `dest_dir`, verified against the signed size and SHA-256; returns the file's path.
/// Blocking. Fails when no newer release offers that file.
#[uniffi::export]
pub fn download_update(file_name: String, dest_dir: String) -> FfiResult<String> {
    let (fetcher, keys) = source()?;
    let UpdateCheck::Available(m) = fetcher.check_latest(RELEASE_REPO, &keys, CHANNEL, &app_version(), now())? else {
        return Err(FfiError::failed("Gantry is already up to date.".into()));
    };
    let file = m.files.iter().find(|f| f.name == file_name).ok_or_else(|| FfiError::failed(format!("Release {} has no file `{file_name}`.", m.version)))?;
    Ok(fetcher.download(file, std::path::Path::new(&dest_dir))?.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    #[test]
    fn compiled_key_parses_and_version_is_semver() {
        assert_eq!(bastion_core::update::key_id(&super::UPDATE_KEYS[0]), "d3691b950e725573");
        assert!(bastion_core::update::parse_version(&super::app_version()).is_ok());
    }

    /// A release build ignores the fake-server settings: updates come only from GitHub with the
    /// compiled-in key. A test-hooks build uses them (and fails here on the unreadable CA).
    #[test]
    fn update_base_is_honoured_only_in_test_hooks_builds() {
        std::env::set_var("BASTION_UPDATE_BASE", "https://127.0.0.1:9/");
        std::env::set_var("BASTION_UPDATE_CA", "/nonexistent/bastion-test-ca.der");
        std::env::set_var("BASTION_UPDATE_TEST_KEY", "00".repeat(32));
        let source = super::source();
        if cfg!(feature = "test-hooks") {
            assert!(source.is_err(), "a test-hooks build must read BASTION_UPDATE_CA");
        } else {
            let (fetcher, keys) = source.expect("release source");
            assert!(fetcher.latest_manifest_url(super::RELEASE_REPO).unwrap().starts_with("https://github.com/"));
            assert_eq!(keys, super::UPDATE_KEYS.to_vec());
        }
        for v in ["BASTION_UPDATE_BASE", "BASTION_UPDATE_CA", "BASTION_UPDATE_TEST_KEY"] {
            std::env::remove_var(v);
        }
    }
}
