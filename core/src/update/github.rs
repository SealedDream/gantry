//! Updates from GitHub releases: the latest release of a repository carries the signed manifest
//! as the asset [`MANIFEST_ASSET`], and the files it lists as further assets.
//!
//! Every request is https and every hop (GitHub redirects asset downloads to a CDN) must land on
//! one of [`ALLOWED_HOSTS`]; redirects are followed by hand so each `Location` is checked before
//! it is fetched. Bodies are capped: the manifest at `MAX_MANIFEST_BYTES`, a file at its signed
//! size (and never above [`MAX_DOWNLOAD_BYTES`]). The manifest then goes through
//! [`verify_manifest`] unchanged, and a download through [`verify_file`].
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::{verify_file, verify_manifest, UpdateCheck, UpdateFile, MAX_MANIFEST_BYTES};
use crate::error::{CoreError, Result};

/// The repository whose releases Gantry updates from: `BASTION_RELEASE_REPO` at build time
/// (`owner/name`), else the project's repository. Checked by [`ReleaseFetcher::latest_manifest_url`].
pub const RELEASE_REPO: &str = match option_env!("BASTION_RELEASE_REPO") {
    Some(r) => r,
    None => "SealedDream/gantry",
};
/// Name of the signed manifest asset on every release.
pub const MANIFEST_ASSET: &str = "update-manifest.json";
/// Hosts a request or redirect may reach. GitHub serves release assets from
/// `release-assets.githubusercontent.com` (since 2025) and formerly `objects.githubusercontent.com`.
pub const ALLOWED_HOSTS: &[&str] = &["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"];
/// Largest update file accepted, whatever the manifest says.
pub const MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const TIMEOUT: Duration = Duration::from_secs(60);

pub struct ReleaseFetcher {
    agent: ureq::Agent,
    allowed_hosts: Vec<String>,
    /// `https://github.com`, or a test server.
    base: String,
}

impl ReleaseFetcher {
    /// The production fetcher: GitHub, system web PKI roots, [`ALLOWED_HOSTS`].
    pub fn github() -> Self {
        Self::new(agent(None), "https://github.com", ALLOWED_HOSTS)
    }

    /// A fetcher limited to `hosts`, for another signed feed (the plugin catalogue, PLUG-04b).
    pub(crate) fn for_hosts(base: &str, hosts: &[&str]) -> Self {
        Self::new(agent(None), base, hosts)
    }

    /// Test-hooks builds only: a fetcher for a local fake GitHub at `base` (https), trusting the
    /// DER certificate `ca_der` instead of web PKI and allowing only `base`'s host.
    #[cfg(feature = "test-hooks")]
    pub fn test_server(base: &str, ca_der: &[u8]) -> Result<Self> {
        let host = base
            .strip_prefix("https://")
            .and_then(|r| r.split(['/', ':']).next())
            .filter(|h| !h.is_empty())
            .ok_or_else(|| CoreError::Invalid(format!("test update server `{base}` is not https")))?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(ca_der.to_vec()))
            .map_err(|e| CoreError::Invalid(format!("test update CA: {e}")))?;
        Ok(Self::new(agent(Some(roots)), base.trim_end_matches('/'), &[host]))
    }

    fn new(agent: ureq::Agent, base: &str, hosts: &[&str]) -> Self {
        Self { agent, base: base.into(), allowed_hosts: hosts.iter().map(|h| h.to_ascii_lowercase()).collect() }
    }

    /// Download URL of the manifest asset on `repo`'s latest release (GitHub redirects it).
    pub fn latest_manifest_url(&self, repo: &str) -> Result<String> {
        let valid = |s: &str| !s.is_empty() && s != "." && s != ".." && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
        match repo.split_once('/') {
            Some((owner, name)) if valid(owner) && valid(name) => Ok(format!("{}/{repo}/releases/latest/download/{MANIFEST_ASSET}", self.base)),
            _ => Err(CoreError::Invalid(format!("not a GitHub repository: `{repo}`"))),
        }
    }

    /// Fetch and verify the latest release's manifest; its files must also be on allowed hosts.
    pub fn check_latest(&self, repo: &str, trusted: &[[u8; 32]], channel: &str, installed: &str, now: u64) -> Result<UpdateCheck> {
        let bytes = self.get(&self.latest_manifest_url(repo)?, MAX_MANIFEST_BYTES as u64).map_err(|e| match e {
            CoreError::NotFound(_) => CoreError::NotFound(format!("{repo} has no published release with update information yet")),
            e => e,
        })?;
        let check = verify_manifest(&bytes, trusted, channel, installed, now)?;
        if let UpdateCheck::Available(m) = &check {
            for f in &m.files {
                self.allowed(&f.url)?;
            }
        }
        Ok(check)
    }

    /// Download `file` into `dir`, verify size and SHA-256, and return its path. The file appears
    /// under its final name only once verified; `name` may not contain a path.
    pub fn download(&self, file: &UpdateFile, dir: &Path) -> Result<PathBuf> {
        let name_ok = !file.name.is_empty() && !file.name.starts_with('.') && !file.name.contains(['/', '\\', ':']);
        if !name_ok {
            return Err(CoreError::Invalid(format!("unsafe update file name `{}`", file.name)));
        }
        if file.size > MAX_DOWNLOAD_BYTES {
            return Err(CoreError::PolicyDenied(format!("`{}` is larger than an update may be", file.name)));
        }
        let bytes = self.get(&file.url, file.size)?;
        verify_file(&bytes, file)?;
        let path = dir.join(&file.name);
        let partial = dir.join(format!(".{}.partial", file.name));
        std::fs::write(&partial, &bytes)?;
        std::fs::rename(&partial, &path)?;
        Ok(path)
    }

    /// Refuses anything but https to an allowed host (no userinfo).
    fn allowed(&self, url: &str) -> Result<()> {
        let refuse = || CoreError::PolicyDenied(format!("update URL `{url}` is not https on an allowed GitHub host"));
        let rest = url.strip_prefix("https://").ok_or_else(refuse)?;
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.contains('@') {
            return Err(refuse());
        }
        let host = authority.rsplit_once(':').map_or(authority, |(h, port)| if port.chars().all(|c| c.is_ascii_digit()) { h } else { authority });
        if self.allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) { Ok(()) } else { Err(refuse()) }
    }

    /// GET with hand-checked redirects; refuses a body longer than `limit`.
    pub(crate) fn get(&self, url: &str, limit: u64) -> Result<Vec<u8>> {
        let too_large = || CoreError::PolicyDenied("update download is larger than allowed".into());
        let mut url = url.to_string();
        for _ in 0..=MAX_REDIRECTS {
            self.allowed(&url)?;
            crate::offline::check_url(&url)?;
            let resp = match self.agent.get(&url).call() {
                Ok(r) => r,
                Err(ureq::Error::Status(404, _)) => return Err(CoreError::NotFound(url)),
                Err(ureq::Error::Status(code, _)) => return Err(CoreError::Invalid(format!("update server answered {code} for {url}"))),
                Err(e) => return Err(CoreError::Invalid(format!("could not reach the update server: {e}"))),
            };
            if (300..400).contains(&resp.status()) {
                url = resp.header("location").ok_or_else(|| CoreError::Invalid("update redirect without a location".into()))?.to_string();
                continue;
            }
            if resp.header("content-length").and_then(|l| l.parse::<u64>().ok()).is_some_and(|l| l > limit) {
                return Err(too_large());
            }
            let mut bytes = Vec::new();
            resp.into_reader().take(limit + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > limit {
                return Err(too_large());
            }
            return Ok(bytes);
        }
        Err(CoreError::Invalid("too many update redirects".into()))
    }
}

/// An agent that follows no redirects itself; `roots` replaces web PKI (tests only).
fn agent(roots: Option<rustls::RootCertStore>) -> ureq::Agent {
    let roots = roots.unwrap_or_else(|| rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() });
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    ureq::AgentBuilder::new().timeout(TIMEOUT).timeout_connect(crate::offline::CONNECT_TIMEOUT).resolver(crate::offline::resolve).redirects(0).tls_config(Arc::new(tls)).build()
}

#[cfg(test)]
#[path = "github_tests.rs"]
mod tests;
