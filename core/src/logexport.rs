//! Log snippet export: the lines a user selected in a terminal, cleaned and written to a new
//! owner-only file. Escape sequences and control bytes are removed so the file is plain text
//! that is safe to open in any editor.
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{CoreError, Result};

/// Largest snippet accepted (bytes of cleaned text plus header).
pub const MAX_SNIPPET_BYTES: usize = 16 * 1024 * 1024;
/// Longest file stem kept from a caller's name hint.
const MAX_STEM_CHARS: usize = 80;
/// How many `-N` suffixes are tried before giving up on a free file name.
const MAX_NAME_ATTEMPTS: u32 = 1000;

/// Plain text of `text`: CRLF/CR become LF, ANSI escapes are removed (when `strip_ansi`), other
/// control characters except tab are dropped, trailing blanks on each line and trailing empty
/// lines are trimmed.
pub fn clean_snippet(text: &str, strip_ansi: bool) -> String {
    let text = if strip_ansi { strip_escapes(text) } else { text.to_string() };
    let normalised = text.replace("\r\n", "\n").replace('\r', "\n");
    let keep = |c: &char| *c == '\t' || !c.is_control() || (!strip_ansi && *c == '\x1b');
    let lines: Vec<String> = normalised.split('\n').map(|l| l.chars().filter(keep).collect::<String>().trim_end().to_string()).collect();
    let end = lines.iter().rposition(|l| !l.is_empty()).map_or(0, |i| i + 1);
    lines[..end].join("\n")
}

/// Remove ESC-introduced sequences: CSI (`ESC [ … final`), OSC/DCS/APC/PM/SOS (up to BEL or
/// `ESC \`), and two-character escapes. Also the 8-bit CSI (U+009B), OSC (U+009D) and DCS (U+0090).
pub fn strip_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let is_csi = match c {
            '\x1b' => match chars.next() {
                Some('[') => true,
                Some(']' | 'P' | '_' | '^' | 'X') => false,
                Some(_) | None => continue,
            },
            '\u{9b}' => true,
            '\u{9d}' | '\u{90}' => false,
            _ => {
                out.push(c);
                continue;
            }
        };
        if is_csi {
            // Parameters and intermediates, then one final character in @..~.
            for n in chars.by_ref() {
                if ('@'..='~').contains(&n) {
                    break;
                }
            }
        } else {
            while let Some(n) = chars.next() {
                if n == '\x07' || n == '\u{9c}' {
                    break;
                }
                if n == '\x1b' && chars.peek() == Some(&'\\') {
                    chars.next();
                    break;
                }
            }
        }
    }
    out
}

/// A safe file stem from a hint (a host or tab name): letters, digits, `-`, `_`, `.` only, no
/// leading or trailing dot or dash, at most 80 characters; "snippet" when nothing is left.
pub fn safe_stem(hint: &str) -> String {
    let s: String = hint.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '-' }).take(MAX_STEM_CHARS).collect();
    let s = s.trim_matches(|c| c == '.' || c == '-');
    if s.is_empty() { "snippet".into() } else { s.to_string() }
}

/// Write `header` (if not empty) and the cleaned `text` to a new owner-only `<stem>.log` in
/// `dir`, picking `<stem>-2.log`, `-3` … when the name is taken. Never overwrites. Returns the
/// path written.
pub fn export_snippet(dir: &Path, name_hint: &str, header: &str, text: &str, strip_ansi: bool) -> Result<PathBuf> {
    let body = clean_snippet(text, strip_ansi);
    if body.is_empty() {
        return Err(CoreError::Invalid("nothing to export: the selection is empty".into()));
    }
    let header = clean_snippet(header, true);
    if body.len() + header.len() > MAX_SNIPPET_BYTES {
        return Err(CoreError::Invalid("the selection is too large to export (16 MB limit)".into()));
    }
    if !dir.is_dir() {
        return Err(CoreError::Invalid(format!("not a folder: {}", dir.display())));
    }
    let stem = safe_stem(name_hint);
    for n in 1..=MAX_NAME_ATTEMPTS {
        let path = dir.join(if n == 1 { format!("{stem}.log") } else { format!("{stem}-{n}.log") });
        let mut f = match create_owner_only(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        };
        if !header.is_empty() {
            writeln!(f, "{header}")?;
        }
        writeln!(f, "{body}")?;
        f.sync_all()?;
        return Ok(path);
    }
    Err(CoreError::Invalid("no free file name for the snippet".into()))
}

/// Create a new file readable and writable only by the current user (refused if it exists).
pub fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts.open(path)?;
    #[cfg(windows)]
    crate::winacl::restrict_path(path, false)?;
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_csi_osc_and_controls() {
        let raw = "\x1b[1;31mred\x1b[0m ok\r\n\x1b]0;title\x07next\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\\x08\n\n\n";
        assert_eq!(clean_snippet(raw, true), "red ok\nnextlink");
    }

    #[test]
    fn keeps_tabs_and_trims_trailing_blanks() {
        assert_eq!(clean_snippet("a\tb   \n  c  \n", true), "a\tb\n  c");
    }

    #[test]
    fn keeps_escapes_when_asked() {
        assert_eq!(clean_snippet("\x1b[1mbold\x1b[0m\x07", false), "\x1b[1mbold\x1b[0m");
    }

    #[test]
    fn eight_bit_csi_is_removed() {
        assert_eq!(clean_snippet("x\u{9b}2Ky", true), "xy");
    }

    #[test]
    fn unterminated_sequences_do_not_panic() {
        assert_eq!(clean_snippet("ok\x1b[12", true), "ok");
        assert_eq!(clean_snippet("ok\x1b]0;never", true), "ok");
        assert_eq!(clean_snippet("ok\x1b", true), "ok");
    }

    #[test]
    fn safe_stem_refuses_traversal() {
        assert_eq!(safe_stem("../../etc/passwd"), "etc-passwd");
        assert_eq!(safe_stem("..."), "snippet");
        assert_eq!(safe_stem("web 01:22"), "web-01-22");
        assert_eq!(safe_stem(&"x".repeat(500)).len(), MAX_STEM_CHARS);
    }
}
