//! SCP over an authenticated `SshSession`, for servers without the SFTP subsystem. Transfers
//! speak the classic SCP protocol (`scp -t` / `scp -f`) over an exec channel; browsing, rename
//! and new folder run plain POSIX commands (`ls -la`, `mv`, `mkdir`) with every path quoted.
//! Like SFTP, transfers never overwrite unless asked and go through a temporary name, so an
//! interrupted transfer never leaves a truncated file under the real name.
use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::error::{CoreError, Result};
use crate::sftp::{EntryKind, RemoteEntry};
use crate::ssh::SshSession;

const CHUNK: usize = 64 * 1024;
/// Longest SCP control line accepted from the server (`C0644 <size> <name>`).
const MAX_HEADER: usize = 4096;
/// Suffix of the temporary name a transfer writes before renaming into place.
pub const PART_SUFFIX: &str = ".bastion-part";

/// One argument for a POSIX shell: single-quoted, with embedded quotes closed and escaped.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Entries from `ls -la` output (the same parser FTP uses for UNIX listings); `.`, `..` and
/// lines that are not entries (`total 12`) are skipped.
pub fn parse_listing(output: &str) -> Vec<RemoteEntry> {
    output
        .lines()
        .filter_map(|line| suppaftp::list::ListParser::parse_posix(line).ok())
        .filter(|f| f.name() != "." && f.name() != "..")
        .map(|f| {
            let kind = if f.is_directory() {
                EntryKind::Dir
            } else if f.is_symlink() {
                EntryKind::Symlink
            } else if f.is_file() {
                EntryKind::File
            } else {
                EntryKind::Other
            };
            let modified = f.modified().duration_since(std::time::UNIX_EPOCH).ok().and_then(|d| u32::try_from(d.as_secs()).ok());
            // `ls -la` shows "name -> target" for links; the entry is the name.
            let name = match kind {
                EntryKind::Symlink => f.name().split(" -> ").next().unwrap_or(f.name()).to_string(),
                _ => f.name().to_string(),
            };
            RemoteEntry { name, kind, size: f.size() as u64, modified, permissions: None }
        })
        .collect()
}

/// The file header the sender writes before the data (`C0644 <size> <name>\n`).
pub fn file_header(size: u64, name: &str) -> Result<String> {
    if name.is_empty() || name.contains(['/', '\n', '\r']) {
        return Err(CoreError::Invalid(format!("SCP: `{name}` is not a file name")));
    }
    Ok(format!("C0644 {size} {name}\n"))
}

/// Reads a `C<mode> <size> <name>` header; anything else (directories, errors) is refused.
pub fn parse_file_header(line: &str) -> Result<(u64, String)> {
    let bad = || CoreError::Invalid(format!("SCP: unexpected reply `{}`", line.trim_end()));
    let rest = line.strip_prefix('C').ok_or_else(bad)?.trim_end_matches('\n');
    let mut parts = rest.splitn(3, ' ');
    let (mode, size, name) = (parts.next().ok_or_else(bad)?, parts.next().ok_or_else(bad)?, parts.next().ok_or_else(bad)?);
    if mode.len() != 4 || !mode.chars().all(|c| c.is_digit(8)) {
        return Err(bad());
    }
    let size = size.parse().map_err(|_| bad())?;
    if !crate::localfile::safe_file_name(name) {
        return Err(bad());
    }
    Ok((size, name.to_string()))
}

pub struct Scp<'a> {
    ssh: &'a SshSession,
}

impl<'a> Scp<'a> {
    pub fn new(ssh: &'a SshSession) -> Self {
        Self { ssh }
    }

    /// Runs a command; a non-zero exit is an error carrying its stderr.
    async fn run(&self, command: &str) -> Result<String> {
        let out = self.ssh.exec(command).await?;
        if out.exit_status != Some(0) {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(CoreError::Ssh(if err.is_empty() { format!("`{command}` failed") } else { err }));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    pub async fn home(&self) -> Result<String> {
        Ok(self.run("pwd").await?.trim().to_string())
    }

    pub async fn list(&self, dir: &str) -> Result<Vec<RemoteEntry>> {
        let out = self.run(&format!("LC_ALL=C ls -la -- {}", shell_quote(dir))).await?;
        Ok(parse_listing(&out))
    }

    pub async fn exists(&self, path: &str) -> Result<bool> {
        Ok(self.ssh.exec(&format!("test -e {}", shell_quote(path))).await?.exit_status == Some(0))
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        if self.exists(to).await? {
            return Err(CoreError::Invalid(format!("{to} already exists")));
        }
        self.run(&format!("mv -- {} {}", shell_quote(from), shell_quote(to))).await.map(|_| ())
    }

    /// Removes a file, or a folder with everything in it (`rm -r`). Same refusals as SFTP.
    pub async fn remove(&self, path: &str, is_dir: bool) -> Result<()> {
        crate::sftp::check_removable(path)?;
        let flag = if is_dir { "-r " } else { "" };
        self.run(&format!("rm {flag}-- {}", shell_quote(path))).await.map(|_| ())
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        self.run(&format!("mkdir -- {}", shell_quote(path))).await.map(|_| ())
    }

    /// Sends `local` to `remote` (a file path): `scp -t` into an unpredictable `.bastion-part`
    /// name, then commits it. With `overwrite` the commit is `mv -f` (an atomic replace);
    /// without it the commit is `ln` (which refuses an existing target, even one created during
    /// the transfer) followed by removing the temporary name.
    pub async fn upload(&self, local: &Path, remote: &str, overwrite: bool) -> Result<u64> {
        if !overwrite && self.exists(remote).await? {
            return Err(CoreError::Invalid(format!("{remote} already exists")));
        }
        let mut file = tokio::fs::File::open(local).await?;
        let size = file.metadata().await?.len();
        let (dir, name) = remote.rsplit_once('/').unwrap_or((".", remote));
        let dir = if dir.is_empty() { "/" } else { dir };
        let part = format!(".{name}.{}{PART_SUFFIX}", uuid::Uuid::new_v4().simple());
        let channel = self.ssh.open_exec(&format!("scp -t -- {}", shell_quote(dir))).await?;
        let mut stream = channel.into_stream();
        expect_ack(&mut stream).await?;
        stream.write_all(file_header(size, &part)?.as_bytes()).await?;
        expect_ack(&mut stream).await?;
        let mut buf = vec![0u8; CHUNK];
        let mut sent = 0u64;
        while sent < size {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                return Err(CoreError::Invalid(format!("{} changed size while it was sent", local.display())));
            }
            stream.write_all(&buf[..n]).await?;
            sent += n as u64;
        }
        stream.write_all(&[0]).await?;
        expect_ack(&mut stream).await?;
        stream.shutdown().await?;
        let part_path = format!("{}/{part}", dir.trim_end_matches('/'));
        let (part_q, remote_q) = (shell_quote(&part_path), shell_quote(remote));
        let commit = if overwrite { format!("mv -f -- {part_q} {remote_q}") } else { format!("ln -- {part_q} {remote_q} && rm -f -- {part_q}") };
        if let Err(e) = self.run(&commit).await {
            let _ = self.ssh.exec(&format!("rm -f -- {part_q}")).await;
            if !overwrite && self.exists(remote).await.unwrap_or(false) {
                return Err(CoreError::Invalid(format!("{remote} already exists")));
            }
            return Err(e);
        }
        Ok(sent)
    }

    /// Fetches `remote` (a file) into `local` through an owner-only temporary file.
    pub async fn download(&self, remote: &str, local: &Path, overwrite: bool) -> Result<u64> {
        crate::localfile::check_download_target(local)?;
        if !overwrite && local.exists() {
            return Err(CoreError::Invalid(format!("{} already exists", local.display())));
        }
        let channel = self.ssh.open_exec(&format!("scp -f -- {}", shell_quote(remote))).await?;
        let mut stream = BufReader::new(channel.into_stream());
        stream.get_mut().write_all(&[0]).await?;
        let header = read_control(&mut stream).await?;
        let (size, _) = parse_file_header(&header)?;
        stream.get_mut().write_all(&[0]).await?;
        let mut part = crate::localfile::PartFile::create(local).await?;
        let mut left = size;
        let mut buf = vec![0u8; CHUNK];
        while left > 0 {
            let want = buf.len().min(left as usize);
            let n = stream.read(&mut buf[..want]).await?;
            if n == 0 {
                return Err(CoreError::Ssh("SCP: the connection ended during the transfer".into()));
            }
            part.file.write_all(&buf[..n]).await?;
            left -= n as u64;
        }
        let mut status = [0u8; 1];
        stream.read_exact(&mut status).await?;
        if status[0] != 0 {
            return Err(CoreError::Ssh("SCP: the server reported an error after the data".into()));
        }
        stream.get_mut().write_all(&[0]).await?;
        part.commit(local, overwrite).await?;
        Ok(size)
    }
}

/// One status byte: 0 = ok, 1 = warning, 2 = fatal (followed by a message line).
async fn expect_ack<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<()> {
    let mut b = [0u8; 1];
    stream.read_exact(&mut b).await.map_err(|_| CoreError::Ssh("SCP: the server closed the channel (is scp installed there?)".into()))?;
    if b[0] == 0 {
        return Ok(());
    }
    let mut msg = Vec::new();
    let mut c = [0u8; 1];
    while msg.len() < MAX_HEADER && stream.read_exact(&mut c).await.is_ok() && c[0] != b'\n' {
        msg.push(c[0]);
    }
    Err(CoreError::Ssh(format!("SCP: {}", String::from_utf8_lossy(&msg).trim())))
}

/// The sender's next control line; a status byte 1/2 is turned into the server's message.
async fn read_control<S: tokio::io::AsyncBufRead + Unpin>(stream: &mut S) -> Result<String> {
    let mut line = Vec::new();
    let n = (&mut *stream).take(MAX_HEADER as u64).read_until(b'\n', &mut line).await?;
    if n == 0 {
        return Err(CoreError::Ssh("SCP: the server closed the channel (is scp installed there?)".into()));
    }
    match line.first() {
        Some(1) | Some(2) => Err(CoreError::Ssh(format!("SCP: {}", String::from_utf8_lossy(&line[1..]).trim()))),
        _ => Ok(String::from_utf8_lossy(&line).into_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_survives_quotes_spaces_and_dashes() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("-rf $(x)"), "'-rf $(x)'");
    }

    #[test]
    fn ls_output_becomes_entries() {
        let out = "total 12\n\
drwxr-xr-x    2 1000 1000  4096 Nov  3 07:21 .\n\
drwxr-xr-x    3 0    0     4096 Nov  1 21:15 ..\n\
drwx------    2 1000 1000  4096 Nov  1 21:15 .ssh\n\
-rw-r--r--    1 1000 1000    48 Nov  1 22:54 notes file.txt\n\
lrwxrwxrwx    1 1000 1000     4 Nov  1 22:54 link -> notes\n";
        let e = parse_listing(out);
        let names: Vec<_> = e.iter().map(|x| (x.name.as_str(), &x.kind, x.size)).collect();
        assert_eq!(names, [(".ssh", &EntryKind::Dir, 4096), ("notes file.txt", &EntryKind::File, 48), ("link", &EntryKind::Symlink, 4)]);
    }

    #[test]
    fn headers_round_trip_and_hostile_ones_are_refused() {
        assert_eq!(parse_file_header(&file_header(42, "a b.txt").unwrap()).unwrap(), (42, "a b.txt".into()));
        assert!(file_header(1, "../x").is_err());
        assert!(file_header(1, "a\nC0644 1 b").is_err());
        for bad in ["D0755 0 dir\n", "C0644 1 ../etc\n", "C0644 1 a/b\n", "C064 1 a\n", "C0999 1 a\n", "C0644 x a\n", "T1 0 1 0\n"] {
            assert!(parse_file_header(bad).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn acks_and_server_errors() {
        let mut ok: &[u8] = &[0];
        assert!(expect_ack(&mut ok).await.is_ok());
        let mut err: &[u8] = b"\x01scp: /x: Permission denied\n";
        let e = expect_ack(&mut err).await.unwrap_err().to_string();
        assert!(e.contains("Permission denied"), "{e}");
        let mut closed: &[u8] = &[];
        assert!(expect_ack(&mut closed).await.is_err());
        let mut fatal: &[u8] = b"\x02scp: /nope: No such file or directory\n";
        assert!(read_control(&mut fatal).await.unwrap_err().to_string().contains("No such file"));
    }
}
