//! Fetches Cisco's prebuilt OpenH264 library for shells that do not download it themselves
//! (Windows over the C ABI, the Tauri helper). Cisco's licence covers the binary only when the
//! user gets it from Cisco, so it is fetched from ciscobinary.openh264.org, never bundled.
//! The macOS app has its own downloader (OpenH264.swift) and uses the same file names.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ironrdp_egfx::decode::OpenH264Decoder;

pub const OPENH264_VERSION: &str = "2.6.0";

/// Cisco's archives are a few hundred KB to ~1.5 MB.
const MAX_ARCHIVE: u64 = 16 * 1024 * 1024;
/// Decoded-size budget: the real library is a few MiB; a bz2 bomb is refused before it grows.
const MAX_LIBRARY: u64 = 32 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(60);
/// An unreachable network fails in this time, not the OS default.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Cisco's file name for this platform, or None where Cisco publishes no binary.
pub fn file_name() -> Option<String> {
    let v = OPENH264_VERSION;
    let name = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => format!("libopenh264-{v}-mac-arm64.dylib"),
        ("macos", "x86_64") => format!("libopenh264-{v}-mac-x64.dylib"),
        ("windows", "x86_64") => format!("openh264-{v}-win64.dll"),
        ("windows", "aarch64") => format!("openh264-{v}-win-arm64.dll"),
        ("linux", "x86_64") => format!("libopenh264-{v}-linux64.7.so"),
        ("linux", "aarch64") => format!("libopenh264-{v}-linux-arm64.7.so"),
        _ => return None,
    };
    Some(name)
}

/// The library in `codecs_dir`, downloaded from Cisco first if it is not there. Blocking; a
/// file that fails the SHA-256 check against Cisco's release list is deleted, never loaded.
pub fn install(codecs_dir: &Path) -> Result<PathBuf, String> {
    install_with(codecs_dir, offline())
}

fn install_with(codecs_dir: &Path, offline: bool) -> Result<PathBuf, String> {
    let name = file_name().ok_or("Cisco publishes no OpenH264 binary for this platform")?;
    let dest = codecs_dir.join(&name);
    if dest.is_file() {
        return Ok(dest);
    }
    // Offline (BASTION_OFFLINE=1, the internet-blocked test run): fail at once; RDP then uses
    // its other codecs, exactly as when Cisco's server cannot be reached.
    if offline {
        return Err("offline: OpenH264 is not downloaded".into());
    }
    std::fs::create_dir_all(codecs_dir).map_err(|e| format!("codecs folder: {e}"))?;
    let archive = download(&format!("http://ciscobinary.openh264.org/{name}.bz2"))?;
    let lib = decompress_bounded(&archive, MAX_LIBRARY)?;
    // Unique per process, so two sessions downloading at once never share a partial file.
    let partial = codecs_dir.join(format!("{name}.{}.partial", std::process::id()));
    std::fs::write(&partial, &lib).map_err(|e| format!("write: {e}"))?;
    if let Err(e) = OpenH264Decoder::from_library_path(&partial) {
        let _ = std::fs::remove_file(&partial);
        return Err(format!("downloaded library refused: {e}"));
    }
    if let Err(e) = std::fs::rename(&partial, &dest) {
        let _ = std::fs::remove_file(&partial);
        if !dest.is_file() {
            return Err(format!("install: {e}"));
        }
    }
    Ok(dest)
}

fn offline() -> bool {
    std::env::var("BASTION_OFFLINE").is_ok_and(|v| v == "1")
}

fn download(url: &str) -> Result<Vec<u8>, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(TIMEOUT)).timeout_connect(Some(CONNECT_TIMEOUT)).build().into();
    let mut resp = agent.get(url).call().map_err(|e| format!("download: {e}"))?;
    resp.body_mut().with_config().limit(MAX_ARCHIVE).read_to_vec().map_err(|e| format!("download: {e}"))
}

fn decompress_bounded(archive: &[u8], limit: u64) -> Result<Vec<u8>, String> {
    let mut lib = Vec::new();
    bzip2::read::BzDecoder::new(archive).take(limit + 1).read_to_end(&mut lib).map_err(|e| format!("bad archive: {e}"))?;
    if lib.len() as u64 > limit {
        return Err("bad archive: decoded library is too large".into());
    }
    Ok(lib)
}

#[cfg(test)]
mod tests {
    #[test]
    fn decompression_is_bounded() {
        use std::io::Write;
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
        enc.write_all(&vec![0u8; 4 * 1024 * 1024]).unwrap();
        let bomb = enc.finish().unwrap();
        assert!(super::decompress_bounded(&bomb, 1024 * 1024).is_err());
        assert_eq!(super::decompress_bounded(&bomb, 4 * 1024 * 1024).unwrap().len(), 4 * 1024 * 1024);
    }

    use super::*;

    #[test]
    fn offline_install_fails_at_once_but_reuses_an_installed_library() {
        let path = std::env::temp_dir().join(format!("bastion-openh264-offline-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        let t = std::time::Instant::now();
        let e = install_with(&path, true).unwrap_err();
        assert!(e.starts_with("offline"), "{e}");
        assert!(t.elapsed() < Duration::from_millis(50));
        assert!(std::fs::read_dir(&path).unwrap().next().is_none(), "nothing written");
        if let Some(name) = file_name() {
            std::fs::write(path.join(&name), b"x").unwrap();
            assert_eq!(install_with(&path, true).unwrap(), path.join(name));
        }
        std::fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn file_name_is_pinned_version() {
        let name = file_name().expect("supported platform");
        assert!(name.contains(OPENH264_VERSION));
    }

    /// Downloads from Cisco: `cargo test --lib openh264_install -- --ignored`.
    #[test]
    #[ignore]
    fn openh264_install_downloads_verifies_and_reuses() {
        let dir = std::env::temp_dir().join(format!("bastion-codecs-{}", std::process::id()));
        let path = install(&dir).expect("install");
        assert!(OpenH264Decoder::from_library_path(&path).is_ok());
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(install(&dir).unwrap(), path);
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), modified);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
