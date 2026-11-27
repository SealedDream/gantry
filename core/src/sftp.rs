//! SFTP over an authenticated `SshSession` (russh-sftp). Covers browsing, upload, download,
//! rename, mkdir and delete. Transfers never overwrite unless asked, and both directions write
//! to a temporary name first and rename into place, so an interrupted transfer never leaves a
//! truncated file under the real name.
use std::path::Path;

use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{CoreError, Result};
use crate::ssh::SshSession;

const CHUNK: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone)]
pub struct RemoteEntry {
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    /// Unix seconds, when the server reports it.
    pub modified: Option<u32>,
    pub permissions: Option<u32>,
}

pub struct Sftp {
    session: SftpSession,
    peer: String,
}

/// Upload temp files that could not be removed because the link died, per `user@host:port`.
/// Only exact names this process created are ever listed here.
static PENDING_TEMPS: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());

fn pending_add(peer: &str, path: &str) {
    let mut g = PENDING_TEMPS.lock().unwrap_or_else(|e| e.into_inner());
    if !g.iter().any(|(p, f)| p == peer && f == path) {
        g.push((peer.to_string(), path.to_string()));
    }
}

fn pending_take(peer: &str) -> Vec<String> {
    let mut g = PENDING_TEMPS.lock().unwrap_or_else(|e| e.into_inner());
    let (mine, rest): (Vec<_>, Vec<_>) = g.drain(..).partition(|(p, _)| p == peer);
    *g = rest;
    mine.into_iter().map(|(_, f)| f).collect()
}

fn pending_take_for(peer: &str, remote: &str) -> Vec<String> {
    let mut g = PENDING_TEMPS.lock().unwrap_or_else(|e| e.into_inner());
    let prefix = format!("{remote}.bastion-part-");
    let (mine, rest): (Vec<_>, Vec<_>) = g.drain(..).partition(|(p, f)| p == peer && f.starts_with(&prefix));
    *g = rest;
    mine.into_iter().map(|(_, f)| f).collect()
}

fn sftp_err(e: russh_sftp::client::error::Error) -> CoreError {
    CoreError::Ssh(format!("sftp: {e}"))
}


fn temp_suffix() -> String {
    format!(".bastion-part-{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
}

impl SshSession {
    /// Open the `sftp` subsystem on a new channel of this session.
    pub async fn open_sftp(&self) -> Result<Sftp> {
        let channel = self.channel_session().await?;
        channel.request_subsystem(true, "sftp").await.map_err(|e| CoreError::Ssh(format!("sftp subsystem refused: {e}")))?;
        let session = SftpSession::new(channel.into_stream()).await.map_err(sftp_err)?;
        let sftp = Sftp { session, peer: self.peer.clone() };
        sftp.sweep_pending(pending_take(&sftp.peer)).await;
        Ok(sftp)
    }
}

/// Most entries one delete removes, so a wrong click on a huge tree stops early.
pub const MAX_REMOVE_ENTRIES: u64 = 100_000;

/// Refuses deleting the root, an empty path or a path ending in `.`/`..`.
pub fn check_removable(path: &str) -> Result<()> {
    let trimmed = path.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or("");
    if trimmed.is_empty() || last.is_empty() || last == "." || last == ".." || trimmed == "~" {
        return Err(CoreError::Invalid(format!("refusing to delete {path:?}")));
    }
    Ok(())
}

impl Sftp {
    /// Removes remembered temp files; any that still cannot be removed stay remembered.
    async fn sweep_pending(&self, paths: Vec<String>) {
        for path in paths {
            match self.session.remove_file(&path).await {
                Ok(()) => {}
                // Already gone: nothing left to clean.
                Err(russh_sftp::client::error::Error::Status(s)) if s.status_code == russh_sftp::protocol::StatusCode::NoSuchFile => {}
                Err(_) => pending_add(&self.peer, &path),
            }
        }
    }

    /// Removes `tmp`; if the link is dead, remembers it for the next connection.
    async fn remove_or_remember(&self, tmp: &str) {
        if self.session.remove_file(tmp).await.is_err() {
            pending_add(&self.peer, tmp);
        }
    }

    /// Absolute form of `path` on the server (`"."` gives the login directory).
    pub async fn canonicalize(&self, path: &str) -> Result<String> {
        self.session.canonicalize(path).await.map_err(sftp_err)
    }

    /// Directory listing sorted directories first, then by name. `.`/`..` and names that are not
    /// a single path component are dropped.
    pub async fn list(&self, path: &str) -> Result<Vec<RemoteEntry>> {
        let mut out: Vec<RemoteEntry> = self
            .session
            .read_dir(path)
            .await
            .map_err(sftp_err)?
            .filter(|e| crate::localfile::safe_file_name(&e.file_name()))
            .map(|e| {
                let m = e.metadata();
                let kind = if m.is_dir() {
                    EntryKind::Dir
                } else if m.is_symlink() {
                    EntryKind::Symlink
                } else if m.is_regular() {
                    EntryKind::File
                } else {
                    EntryKind::Other
                };
                RemoteEntry { name: e.file_name(), kind, size: m.size.unwrap_or(0), modified: m.mtime, permissions: m.permissions }
            })
            .collect();
        out.sort_by(|a, b| (b.kind == EntryKind::Dir).cmp(&(a.kind == EntryKind::Dir)).then_with(|| a.name.cmp(&b.name)));
        Ok(out)
    }

    pub async fn exists(&self, path: &str) -> Result<bool> {
        self.session.try_exists(path).await.map_err(sftp_err)
    }

    /// Upload a local file to `remote`. Returns bytes sent.
    pub async fn upload(&self, local: &Path, remote: &str, overwrite: bool) -> Result<u64> {
        self.upload_with_progress(local, remote, overwrite, &|_| {}).await
    }

    /// `upload`, calling `progress` with the bytes sent so far after each chunk.
    pub async fn upload_with_progress(&self, local: &Path, remote: &str, overwrite: bool, progress: &(dyn Fn(u64) + Sync)) -> Result<u64> {
        if !overwrite && self.exists(remote).await? {
            return Err(CoreError::Invalid(format!("{remote} already exists on the server")));
        }
        self.sweep_pending(pending_take_for(&self.peer, remote)).await;
        let mut src = tokio::fs::File::open(local).await?;
        let tmp = format!("{remote}{}", temp_suffix());
        let mut dst = self
            .session
            .open_with_flags(&tmp, OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE)
            .await
            .map_err(sftp_err)?;
        let copied = copy(&mut src, &mut dst, progress).await;
        let closed = dst.shutdown().await;
        let sent = match (copied, closed) {
            (Ok(n), Ok(())) => n,
            (Err(e), _) | (_, Err(e)) => {
                self.remove_or_remember(&tmp).await;
                return Err(CoreError::Io(e));
            }
        };
        // SFTP v3 rename never replaces, so a no-overwrite upload commits atomically here: a
        // file created at `remote` during the transfer makes this fail instead of being lost.
        let Err(first) = self.session.rename(&tmp, remote).await else {
            return Ok(sent);
        };
        let target = self.stat_path(remote).await?;
        let target_exists = target.is_some();
        if overwrite && target.as_ref().is_some_and(|t| !t.is_file) {
            self.remove_or_remember(&tmp).await;
            return Err(CoreError::Invalid(format!("{remote} is not a file; it was not replaced")));
        }
        if !overwrite || !target_exists {
            self.remove_or_remember(&tmp).await;
            return Err(if target_exists { CoreError::Invalid(format!("{remote} already exists on the server")) } else { sftp_err(first) });
        }
        self.replace_keeping_original(&tmp, remote).await?;
        Ok(sent)
    }

    /// Installs the finished `tmp` at the existing `remote` without ever leaving `remote`
    /// missing: the original moves to a recovery name, `tmp` moves into place, and only then is
    /// the original removed. If installing fails the original is moved back; if that fails too,
    /// the error names both files so nothing is lost.
    async fn replace_keeping_original(&self, tmp: &str, remote: &str) -> Result<()> {
        let backup = format!("{remote}{}", temp_suffix().replace("-part-", "-old-"));
        self.session.rename(remote, &backup).await.map_err(|e| {
            CoreError::Ssh(format!("sftp: could not set {remote} aside to replace it ({e}); the upload is kept at {tmp}"))
        })?;
        match self.session.rename(tmp, remote).await {
            Ok(()) => {
                let _ = self.session.remove_file(&backup).await;
                Ok(())
            }
            Err(e) => match self.session.rename(&backup, remote).await {
                Ok(()) => {
                    let _ = self.session.remove_file(tmp).await;
                    Err(sftp_err(e))
                }
                Err(restore) => Err(CoreError::Ssh(format!(
                    "sftp: replacing {remote} failed ({e}) and restoring it failed ({restore}); the original is at {backup}, the upload at {tmp}"
                ))),
            },
        }
    }

    /// Download `remote` to a local file (created 0600 on Unix). Returns bytes received.
    pub async fn download(&self, remote: &str, local: &Path, overwrite: bool) -> Result<u64> {
        self.download_with_progress(remote, local, overwrite, &|_| {}).await
    }

    /// `download`, calling `progress` with the bytes received so far after each chunk.
    pub async fn download_with_progress(&self, remote: &str, local: &Path, overwrite: bool, progress: &(dyn Fn(u64) + Sync)) -> Result<u64> {
        crate::localfile::check_download_target(local)?;
        if !overwrite && local.exists() {
            return Err(CoreError::Invalid(format!("{} already exists", local.display())));
        }
        let mut src = self.session.open(remote).await.map_err(sftp_err)?;
        let mut part = crate::localfile::PartFile::create(local).await?;
        let n = copy(&mut src, &mut part.file, progress).await?;
        part.commit(local, overwrite).await?;
        Ok(n)
    }

    /// Rename or move on the server. Refuses to replace an existing target.
    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        if self.exists(to).await? {
            return Err(CoreError::Invalid(format!("{to} already exists on the server")));
        }
        self.session.rename(from, to).await.map_err(sftp_err)
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        self.session.create_dir(path).await.map_err(sftp_err)
    }

    pub async fn remove_file(&self, path: &str) -> Result<()> {
        self.session.remove_file(path).await.map_err(sftp_err)
    }

    /// Removes an empty directory.
    pub async fn remove_dir(&self, path: &str) -> Result<()> {
        self.session.remove_dir(path).await.map_err(sftp_err)
    }

    /// Removes `path`: a file or link (never followed), or a folder with everything in it.
    /// Refuses the root and paths ending in `.`/`..`. Stops at the first error and after
    /// [`MAX_REMOVE_ENTRIES`] entries. Returns how many entries were removed.
    pub async fn remove_tree(&self, path: &str, is_dir: bool) -> Result<u64> {
        check_removable(path)?;
        if !is_dir {
            self.remove_file(path).await?;
            return Ok(1);
        }
        let mut removed = 0u64;
        // Depth-first without recursion: (folder, listed yet?).
        let mut stack = vec![(path.trim_end_matches('/').to_string(), false)];
        while let Some((dir, listed)) = stack.pop() {
            if listed {
                self.remove_dir(&dir).await?;
                removed += 1;
                continue;
            }
            stack.push((dir.clone(), true));
            for e in self.list(&dir).await? {
                let child = format!("{dir}/{}", e.name);
                if removed >= MAX_REMOVE_ENTRIES {
                    return Err(CoreError::Invalid(format!("{path} holds more than {MAX_REMOVE_ENTRIES} entries; nothing more was deleted")));
                }
                if e.kind == EntryKind::Dir {
                    stack.push((child, false));
                } else {
                    self.remove_file(&child).await?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    /// Size, mtime, permission bits and whether it is a regular file; `None` when missing.
    pub async fn stat_path(&self, path: &str) -> Result<Option<crate::remoteedit::RemoteStat>> {
        if !self.exists(path).await? {
            return Ok(None);
        }
        let m = self.session.metadata(path).await.map_err(sftp_err)?;
        Ok(Some(crate::remoteedit::RemoteStat { size: m.size.unwrap_or(0), mtime: m.mtime, permissions: m.permissions.map(|p| p & 0o7777), is_file: m.is_regular() }))
    }

    /// Whole file into memory; refused once it passes `max` bytes.
    pub async fn read_capped(&self, path: &str, max: u64) -> Result<Vec<u8>> {
        let f = self.session.open(path).await.map_err(sftp_err)?;
        let mut out = Vec::new();
        f.take(max + 1).read_to_end(&mut out).await?;
        if out.len() as u64 > max {
            return Err(CoreError::Invalid(format!("{path} is larger than {max} bytes")));
        }
        Ok(out)
    }

    /// Create `path` (refused if it exists) holding `bytes`, then apply `permissions`.
    pub async fn write_new(&self, path: &str, bytes: &[u8], permissions: Option<u32>) -> Result<()> {
        let mut f = self.session.open_with_flags(path, OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE).await.map_err(sftp_err)?;
        let written = async {
            f.write_all(bytes).await?;
            f.shutdown().await
        }
        .await;
        if let Err(e) = written {
            let _ = self.session.remove_file(path).await;
            return Err(CoreError::Io(e));
        }
        if let Some(mode) = permissions {
            let attrs = russh_sftp::protocol::FileAttributes { permissions: Some(mode), ..Default::default() };
            if let Err(e) = self.session.set_metadata(path, attrs).await {
                let _ = self.session.remove_file(path).await;
                return Err(sftp_err(e));
            }
        }
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        self.session.close().await.map_err(sftp_err)
    }
}

async fn copy<R, W>(src: &mut R, dst: &mut W, progress: &(dyn Fn(u64) + Sync)) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await?;
        total += n as u64;
        progress(total);
    }
    dst.flush().await?;
    Ok(total)
}

#[cfg(test)]
mod remove_tests {
    use super::check_removable;

    #[test]
    fn refuses_root_dots_and_empty_paths() {
        for bad in ["", "/", "//", ".", "..", "/home/a/..", "/home/a/.", "/home/a/../", "~"] {
            assert!(check_removable(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn allows_ordinary_files_and_folders() {
        for ok in ["/home/a/file.txt", "/home/a/dir/", "relative/x", "a..b", ".hidden"] {
            assert!(check_removable(ok).is_ok(), "{ok:?} must be allowed");
        }
    }
}

#[cfg(test)]
mod pending_tests {
    use super::*;

    #[test]
    fn remembers_only_exact_names_per_peer_without_duplicates() {
        let peer = "t1@pending-test-a:22";
        pending_add(peer, "/d/f.bin.bastion-part-aaaaaaaa");
        pending_add(peer, "/d/f.bin.bastion-part-aaaaaaaa");
        pending_add("t1@pending-test-b:22", "/d/f.bin.bastion-part-bbbbbbbb");
        assert_eq!(pending_take(peer), vec!["/d/f.bin.bastion-part-aaaaaaaa".to_string()]);
        assert!(pending_take(peer).is_empty());
        assert_eq!(pending_take("t1@pending-test-b:22").len(), 1);
    }

    #[test]
    fn retry_takes_only_temps_of_the_same_target() {
        let peer = "t2@pending-test-c:22";
        pending_add(peer, "/d/a.bin.bastion-part-11111111");
        pending_add(peer, "/d/ab.bin.bastion-part-22222222");
        pending_add(peer, "/d/a.bin.bastion-part-33333333");
        let mut got = pending_take_for(peer, "/d/a.bin");
        got.sort();
        assert_eq!(got, vec!["/d/a.bin.bastion-part-11111111", "/d/a.bin.bastion-part-33333333"]);
        assert_eq!(pending_take(peer), vec!["/d/ab.bin.bastion-part-22222222".to_string()]);
    }
}
