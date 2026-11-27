//! Local files that SFTP, SCP and FTPS downloads write. Remote file names are untrusted, so
//! one validator decides which names may become a local file. Each download writes to an
//! unpredictable, owner-only temporary file created exclusively (a planted file or symlink is
//! never opened). It then commits with a rename that refuses to replace an existing file unless
//! the caller allowed overwriting.
use std::path::{Component, Path, PathBuf};

use crate::error::{CoreError, Result};

/// Windows device names, which open the device whatever the extension (`nul.txt`, `COM1.log`).
const RESERVED_WINDOWS: [&str; 26] = [
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Longest file name accepted (the common file system limit).
const MAX_NAME_BYTES: usize = 255;

/// Whether a server-supplied `name` is safe to use as one local file name on this platform:
/// a single component that cannot climb out of, or point outside, the folder it is joined to.
pub fn safe_file_name(name: &str) -> bool {
    safe_file_name_for(name, cfg!(windows))
}

/// [`safe_file_name`] with the Windows rules switched on or off (so both are testable anywhere).
pub fn safe_file_name_for(name: &str, windows: bool) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name == "." || name == ".." {
        return false;
    }
    if name.contains('/') || name.chars().any(char::is_control) {
        return false;
    }
    if !windows {
        return true;
    }
    // `\` separates, `:` is a drive prefix or an alternate data stream, the rest are refused by
    // Windows. A trailing dot or space is stripped by Windows, so `..` + space would alias `..`.
    if name.contains(['\\', ':', '<', '>', '"', '|', '?', '*']) || name.ends_with(['.', ' ']) {
        return false;
    }
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let stem = stem.replace(['¹', '²', '³'], "1");
    !RESERVED_WINDOWS.iter().any(|r| r.eq_ignore_ascii_case(&stem))
}

/// `dir/name` for downloading a remote entry called `name` into `dir`; refused when the name is
/// not a safe single file name, so the result is always directly inside `dir`.
pub fn download_target(dir: &Path, name: &str) -> Result<PathBuf> {
    if !safe_file_name(name) {
        return Err(CoreError::Invalid(format!("{name:?} is not a safe local file name")));
    }
    let path = dir.join(name);
    if path.parent() != Some(dir) {
        return Err(CoreError::Invalid(format!("{name:?} is not a safe local file name")));
    }
    Ok(path)
}

/// Refuses a download target whose file name is unsafe or whose path climbs with `..`.
pub fn check_download_target(local: &Path) -> Result<()> {
    let bad = || CoreError::Invalid(format!("{} is not a safe download target", local.display()));
    let name = local.file_name().and_then(|n| n.to_str()).ok_or_else(bad)?;
    if !safe_file_name(name) || local.components().any(|c| c == Component::ParentDir) {
        return Err(bad());
    }
    Ok(())
}

/// An owner-only temporary file next to a download target. It is removed on drop unless
/// [`PartFile::commit`] moved it into place.
pub struct PartFile {
    path: PathBuf,
    pub file: tokio::fs::File,
    committed: bool,
}

impl PartFile {
    /// Creates `.<name>.<random>.bastion-part` beside `local`: exclusive creation (an existing
    /// file or symlink of that name fails instead of being followed), mode 0600 on Unix,
    /// owner-only ACL on Windows before any byte is written.
    pub async fn create(local: &Path) -> Result<PartFile> {
        check_download_target(local)?;
        let name = local.file_name().and_then(|n| n.to_str()).unwrap_or("download");
        let random = uuid::Uuid::new_v4().simple().to_string();
        let path = local.with_file_name(format!(".{name}.{random}{}", crate::scp::PART_SUFFIX));
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let file = opts.open(&path).await?;
        let part = PartFile { path, file, committed: false };
        #[cfg(windows)]
        crate::winacl::restrict_path(&part.path, false)?;
        Ok(part)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Flushes and syncs the data, then moves it to `local`. Without `overwrite` the move is
    /// atomic and refuses an existing `local`, even one created during the transfer.
    pub async fn commit(mut self, local: &Path, overwrite: bool) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        self.file.flush().await?;
        self.file.sync_all().await?;
        let moved = if overwrite { std::fs::rename(&self.path, local) } else { rename_noreplace(&self.path, local) };
        match moved {
            Ok(()) => {
                self.committed = true;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(CoreError::Invalid(format!("{} already exists", local.display()))),
            Err(e) => Err(CoreError::Io(e)),
        }
    }
}

impl Drop for PartFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Renames `from` to `to`, failing with `AlreadyExists` instead of replacing `to`.
pub fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    imp::rename_noreplace(from, to)
}

#[cfg(target_vendor = "apple")]
mod imp {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    pub fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
        let (f, t) = (CString::new(from.as_os_str().as_bytes())?, CString::new(to.as_os_str().as_bytes())?);
        // SAFETY: both are valid NUL-terminated paths that outlive the call.
        if unsafe { libc::renamex_np(f.as_ptr(), t.as_ptr(), libc::RENAME_EXCL) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        // File systems without RENAME_EXCL (some network volumes) fall back to link + unlink.
        if e.raw_os_error() == Some(libc::ENOTSUP) {
            return super::link_then_unlink(from, to);
        }
        Err(e)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    pub fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
        let (f, t) = (CString::new(from.as_os_str().as_bytes())?, CString::new(to.as_os_str().as_bytes())?);
        // SAFETY: both are valid NUL-terminated paths that outlive the call.
        if unsafe { libc::renameat2(libc::AT_FDCWD, f.as_ptr(), libc::AT_FDCWD, t.as_ptr(), libc::RENAME_NOREPLACE) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOSYS)) {
            return super::link_then_unlink(from, to);
        }
        Err(e)
    }
}

#[cfg(windows)]
mod imp {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    pub fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
        let wide = |p: &Path| p.as_os_str().encode_wide().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let (f, t) = (wide(from), wide(to));
        // Without MOVEFILE_REPLACE_EXISTING the move fails if `to` exists (ERROR_ALREADY_EXISTS).
        // SAFETY: both are valid NUL-terminated wide strings that outlive the call.
        let ok = unsafe { windows_sys::Win32::Storage::FileSystem::MoveFileExW(f.as_ptr(), t.as_ptr(), windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH) };
        if ok != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android", windows)))]
mod imp {
    pub use super::link_then_unlink as rename_noreplace;
}

/// No-replace move through a hard link: `link` fails if `to` exists.
#[allow(dead_code)]
fn link_then_unlink(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::hard_link(from, to)?;
    std::fs::remove_file(from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_rules_refuse_traversal_drives_streams_and_devices() {
        for bad in [
            "..\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.cmd",
            "C:\\Users\\victim\\evil.cmd",
            "C:evil.cmd",
            "report.txt:hidden",
            "\\\\server\\share\\x",
            "CON",
            "nul.txt",
            "Com1.log",
            "LPT9",
            "COM¹",
            "CONOUT$",
            "trailing.",
            "trailing ",
            ".. ",
            "a<b",
            "a|b",
            "a?b",
            "a*b",
            "a\"b",
        ] {
            assert!(!safe_file_name_for(bad, true), "{bad:?} must be refused on Windows");
        }
        for ok in ["report.txt", ".bashrc", "a..b", "console.log", "COM10", "my file (1).tar.gz", "été.txt"] {
            assert!(safe_file_name_for(ok, true), "{ok:?} must be allowed on Windows");
        }
    }

    #[test]
    fn every_platform_refuses_separators_dots_and_control_characters() {
        for windows in [false, true] {
            for bad in ["", ".", "..", "a/b", "../x", "/etc/passwd", "a\0b", "line\nbreak", "esc\u{1b}[2J", &"x".repeat(256)] {
                assert!(!safe_file_name_for(bad, windows), "{bad:?} must be refused (windows={windows})");
            }
        }
        assert!(safe_file_name_for("a:b", false), "colons are ordinary on Unix");
    }

    #[test]
    fn download_target_stays_in_the_folder() {
        let dir = Path::new("/home/me/Downloads");
        assert_eq!(download_target(dir, "a.txt").unwrap(), dir.join("a.txt"));
        for bad in ["..", "../a", "/etc/x", "", "a/b"] {
            assert!(download_target(dir, bad).is_err(), "{bad:?}");
        }
        assert!(check_download_target(&dir.join("..").join("x")).is_err());
        assert!(check_download_target(&dir.join("ok.bin")).is_ok());
    }

    #[tokio::test]
    async fn part_file_ignores_a_planted_symlink_at_the_old_predictable_name() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, b"keep me").unwrap();
        let local = dir.path().join("download.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&victim, dir.path().join(format!("download.txt{}", crate::scp::PART_SUFFIX))).unwrap();
        let mut part = PartFile::create(&local).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut part.file, b"downloaded").await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(part.path()).unwrap().permissions().mode() & 0o777, 0o600);
        }
        part.commit(&local, false).await.unwrap();
        assert_eq!(std::fs::read(&local).unwrap(), b"downloaded");
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
    }

    #[tokio::test]
    async fn commit_without_overwrite_refuses_a_file_created_during_the_transfer() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("big.iso");
        let part = PartFile::create(&local).await.unwrap();
        let part_path = part.path().to_path_buf();
        std::fs::write(&local, b"someone else's").unwrap();
        assert!(part.commit(&local, false).await.unwrap_err().to_string().contains("already exists"));
        assert_eq!(std::fs::read(&local).unwrap(), b"someone else's");
        assert!(!part_path.exists(), "the temporary file is cleaned up");
    }

    #[tokio::test]
    async fn commit_with_overwrite_replaces_and_drop_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("f");
        std::fs::write(&local, b"old").unwrap();
        let mut part = PartFile::create(&local).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut part.file, b"new").await.unwrap();
        part.commit(&local, true).await.unwrap();
        assert_eq!(std::fs::read(&local).unwrap(), b"new");
        let abandoned = PartFile::create(&local).await.unwrap();
        let p = abandoned.path().to_path_buf();
        drop(abandoned);
        assert!(!p.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
