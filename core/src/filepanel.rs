//! File-panel helpers: follow the terminal's folder (OSC 7) and edit-locally auto-upload.
//!
//! Follow folder: shells that emit `ESC ] 7 ; file://host/path BEL|ST` tell us the working
//! directory; [`parse_osc7`] turns the payload into a remote path. [`follow_cd_command`] is the
//! optional one-line hook a user may paste into a shell that does not emit OSC 7.
//!
//! Edit locally: a downloaded copy lives in an owner-only folder; [`EditWatcher::poll`] reports
//! copies whose content changed so the host queues an upload. Change is decided by size and a
//! SHA-256 of the content, never by mtime alone (editors that save in place keep or fake mtimes).
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{CoreError, Result};

/// Longest remote path accepted from an OSC 7 sequence.
const MAX_OSC7_PATH: usize = 4096;
/// Files above this size are not offered for edit-locally (a text editor, not a transfer).
pub const MAX_EDIT_BYTES: u64 = 64 * 1024 * 1024;

/// Remote working directory from an OSC 7 payload (`file://host/path`, percent-encoded).
/// `None` for anything that is not a plain absolute path: other schemes, bad escapes, bad UTF-8,
/// control characters, `..` segments, or an over-long path.
pub fn parse_osc7(payload: &str) -> Option<String> {
    let rest = payload.strip_prefix("file://")?;
    let path = &rest[rest.find('/')?..];
    if path.len() > MAX_OSC7_PATH {
        return None;
    }
    let decoded = percent_decode(path)?;
    if decoded.chars().any(|c| c.is_control()) || decoded.split('/').any(|s| s == "..") {
        return None;
    }
    Some(decoded)
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Finds OSC 7 sequences in a terminal byte stream, across chunk boundaries, with a bounded buffer.
#[derive(Debug, Default)]
pub struct Osc7Scanner {
    state: ScanState,
    buf: Vec<u8>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum ScanState {
    #[default]
    Ground,
    Esc,
    /// After `ESC ]`: collecting the OSC number.
    Number,
    /// Inside an OSC 7 payload.
    Payload,
    /// Saw ESC inside the payload (maybe the `ESC \` terminator).
    PayloadEsc,
    /// Inside some other OSC, or an over-long OSC 7: skip to its end.
    Skip,
    SkipEsc,
}

impl Osc7Scanner {
    /// Feed output bytes; returns the last valid directory announced in them, if any.
    pub fn feed(&mut self, bytes: &[u8]) -> Option<String> {
        let mut found = None;
        for &b in bytes {
            self.state = match (self.state, b) {
                (ScanState::Ground, 0x1b) => ScanState::Esc,
                (ScanState::Ground, _) => ScanState::Ground,
                (ScanState::Esc, b']') => {
                    self.buf.clear();
                    ScanState::Number
                }
                (ScanState::Esc, 0x1b) => ScanState::Esc,
                (ScanState::Esc, _) => ScanState::Ground,
                (ScanState::Number, b'0'..=b'9') if self.buf.len() < 4 => {
                    self.buf.push(b);
                    ScanState::Number
                }
                (ScanState::Number, b';') if self.buf == b"7" => {
                    self.buf.clear();
                    ScanState::Payload
                }
                (ScanState::Number, 0x07) => ScanState::Ground,
                (ScanState::Number, 0x1b) => ScanState::SkipEsc,
                (ScanState::Number, _) => ScanState::Skip,
                (ScanState::Payload, 0x07) => {
                    found = self.take().or(found);
                    ScanState::Ground
                }
                (ScanState::Payload, 0x1b) => ScanState::PayloadEsc,
                (ScanState::Payload, _) if self.buf.len() < MAX_OSC7_PATH + 256 => {
                    self.buf.push(b);
                    ScanState::Payload
                }
                (ScanState::Payload, _) => ScanState::Skip,
                (ScanState::PayloadEsc, b'\\') => {
                    found = self.take().or(found);
                    ScanState::Ground
                }
                (ScanState::PayloadEsc, b']') => {
                    self.buf.clear();
                    ScanState::Number
                }
                (ScanState::PayloadEsc, _) => ScanState::Ground,
                (ScanState::Skip, 0x07) => ScanState::Ground,
                (ScanState::Skip, 0x1b) => ScanState::SkipEsc,
                (ScanState::Skip, _) => ScanState::Skip,
                (ScanState::SkipEsc, b'\\') => ScanState::Ground,
                (ScanState::SkipEsc, b']') => {
                    self.buf.clear();
                    ScanState::Number
                }
                (ScanState::SkipEsc, _) => ScanState::Skip,
            };
        }
        found
    }

    fn take(&mut self) -> Option<String> {
        let payload = std::mem::take(&mut self.buf);
        parse_osc7(std::str::from_utf8(&payload).ok()?)
    }
}

/// Shell hook that makes bash/zsh emit OSC 7 after each prompt, for servers that do not already.
pub fn follow_cd_command(shell: &str) -> Option<&'static str> {
    match shell {
        "bash" => Some(r#"PROMPT_COMMAND='printf "\e]7;file://%s%s\a" "$HOSTNAME" "$PWD"'"#),
        "zsh" => Some(r#"precmd() { printf "\e]7;file://%s%s\a" "$HOST" "$PWD" }"#),
        _ => None,
    }
}

/// One file opened with "Edit locally".
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EditCopy {
    pub local: PathBuf,
    pub remote: String,
    #[serde(skip)]
    size: u64,
    #[serde(skip)]
    digest: [u8; 32],
}

/// Tracks edit-locally copies and reports the ones saved since the last poll.
#[derive(Debug, Default)]
pub struct EditWatcher {
    copies: HashMap<PathBuf, EditCopy>,
}

impl EditWatcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start watching `local` (just downloaded from `remote`). Large files are refused.
    pub fn watch(&mut self, local: &Path, remote: &str) -> Result<()> {
        let (size, digest) = fingerprint(local)?;
        self.copies.insert(local.to_path_buf(), EditCopy { local: local.to_path_buf(), remote: remote.to_string(), size, digest });
        Ok(())
    }

    pub fn unwatch(&mut self, local: &Path) -> bool {
        self.copies.remove(local).is_some()
    }

    pub fn watched(&self) -> impl Iterator<Item = &EditCopy> {
        self.copies.values()
    }

    /// Copies whose content changed since they were watched or last reported. A copy that was
    /// deleted or became unreadable stops being watched and is returned in the second list.
    pub fn poll(&mut self) -> (Vec<EditCopy>, Vec<EditCopy>) {
        let (mut changed, mut gone) = (Vec::new(), Vec::new());
        for copy in self.copies.values_mut() {
            match fingerprint(&copy.local) {
                Ok((size, digest)) if size != copy.size || digest != copy.digest => {
                    copy.size = size;
                    copy.digest = digest;
                    changed.push(copy.clone());
                }
                Ok(_) => {}
                Err(_) => gone.push(copy.clone()),
            }
        }
        for g in &gone {
            self.copies.remove(&g.local);
        }
        (changed, gone)
    }
}

fn fingerprint(path: &Path) -> Result<(u64, [u8; 32])> {
    let meta = fs::metadata(path)?;
    if !meta.is_file() {
        return Err(CoreError::Invalid(format!("{} is not a file", path.display())));
    }
    if meta.len() > MAX_EDIT_BYTES {
        return Err(CoreError::Invalid(format!("{} is too large to edit locally", path.display())));
    }
    let mut hasher = Sha256::new();
    let mut file = fs::File::open(path)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok((size, hasher.finalize().into()))
}

/// Owner-only folder for edit-locally copies of one session, under `base`.
pub fn edit_dir(base: &Path, session: &str) -> Result<PathBuf> {
    if session.is_empty() || !session.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(CoreError::Invalid("bad session id".into()));
    }
    let dir = base.join("edit-locally").join(session);
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    crate::winacl::restrict_path(&dir, true)?;
    Ok(dir)
}

/// Local path for a remote file inside an edit folder: the remote file name only, so a hostile
/// name can never escape the folder.
pub fn edit_path(dir: &Path, remote: &str) -> Result<PathBuf> {
    let name = remote.rsplit('/').next().unwrap_or_default();
    if !crate::localfile::safe_file_name(name) || name.contains(['\\', ':']) {
        return Err(CoreError::Invalid(format!("cannot edit {remote} locally")));
    }
    Ok(dir.join(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc7_parses_paths_and_refuses_hostile_input() {
        assert_eq!(parse_osc7("file://web1/home/me").as_deref(), Some("/home/me"));
        assert_eq!(parse_osc7("file:///srv/my%20dir").as_deref(), Some("/srv/my dir"));
        assert_eq!(parse_osc7("file://h/%C3%A9t%C3%A9").as_deref(), Some("/été"));
        assert_eq!(parse_osc7("http://h/x"), None);
        assert_eq!(parse_osc7("file://h"), None);
        assert_eq!(parse_osc7("file://h/a%2"), None);
        assert_eq!(parse_osc7("file://h/a%FF"), None, "bad UTF-8");
        assert_eq!(parse_osc7("file://h/a%0Ab"), None, "control char");
        assert_eq!(parse_osc7("file://h/a/../etc"), None);
        assert_eq!(parse_osc7(&format!("file://h/{}", "a".repeat(MAX_OSC7_PATH + 1))), None);
    }

    #[test]
    fn scanner_finds_osc7_across_chunks_and_ignores_other_oscs() {
        let mut s = Osc7Scanner::default();
        assert_eq!(s.feed(b"ls\r\n\x1b]0;title\x07\x1b]7;file://h/ho"), None);
        assert_eq!(s.feed(b"me/me\x07$ ").as_deref(), Some("/home/me"));
        assert_eq!(s.feed(b"\x1b]7;file://h/srv\x1b\\").as_deref(), Some("/srv"), "ST terminator");
        assert_eq!(s.feed(b"\x1b]7;file://h/a/../b\x07"), None, "invalid payload dropped");
        assert_eq!(s.feed(b"\x1b]77;file://h/x\x07"), None, "OSC 77 is not OSC 7");
        let long = [b"\x1b]7;file://h/".as_slice(), &vec![b'a'; MAX_OSC7_PATH + 1000], b"\x07"].concat();
        assert_eq!(s.feed(&long), None, "over-long payload skipped, buffer bounded");
        assert!(s.buf.len() <= MAX_OSC7_PATH + 256);
        assert_eq!(s.feed(b"\x1b]7;file://h/ok\x07").as_deref(), Some("/ok"), "recovers");
    }

    #[test]
    fn hook_exists_for_bash_and_zsh_only() {
        assert!(follow_cd_command("bash").unwrap().contains("]7;"));
        assert!(follow_cd_command("zsh").is_some());
        assert!(follow_cd_command("fish").is_none());
    }

    #[test]
    fn watcher_reports_content_changes_once() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.conf");
        fs::write(&f, "one").unwrap();
        let mut w = EditWatcher::new();
        w.watch(&f, "/etc/a.conf").unwrap();
        assert!(w.poll().0.is_empty());
        fs::write(&f, "two").unwrap(); // same size, different content
        let (changed, _) = w.poll();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].remote, "/etc/a.conf");
        assert!(w.poll().0.is_empty(), "reported once");
        fs::remove_file(&f).unwrap();
        let (_, gone) = w.poll();
        assert_eq!(gone.len(), 1);
        assert_eq!(w.watched().count(), 0);
    }

    #[test]
    fn watcher_refuses_dirs_and_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = EditWatcher::new();
        assert!(w.watch(dir.path(), "/x").is_err());
        assert!(w.watch(&dir.path().join("nope"), "/x").is_err());
        assert!(!w.unwatch(&dir.path().join("nope")));
    }

    #[test]
    fn edit_dir_is_owner_only_and_paths_stay_inside() {
        let base = tempfile::tempdir().unwrap();
        let d = edit_dir(base.path(), "abc-123").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        }
        assert!(edit_dir(base.path(), "../x").is_err());
        assert_eq!(edit_path(&d, "/etc/nginx/nginx.conf").unwrap(), d.join("nginx.conf"));
        assert!(edit_path(&d, "/etc/..").is_err());
        assert!(edit_path(&d, "/etc/").is_err());
        assert!(edit_path(&d, "/x/a\\..\\b").is_err());
    }
}
