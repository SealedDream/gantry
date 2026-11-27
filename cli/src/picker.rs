//! fzf-style picker on the terminal: type to filter (the core's palette ranking), arrows or
//! Ctrl-P/Ctrl-N to move, Return to choose, Esc or Ctrl-C to cancel. Draws on the terminal itself
//! (/dev/tty on Unix, CONIN$/CONOUT$ on Windows), so it works inside pipes; the chosen item is
//! returned, never printed by the picker itself.
use std::io::{Read, Write};

use bastion_core::palette::{Entry, EntryKind, Index};

const ROWS: usize = 10;

pub struct Item {
    pub title: String,
    pub detail: String,
}

#[cfg(unix)]
pub fn pick(prompt: &str, items: &[Item]) -> Result<Option<usize>, String> {
    use std::os::fd::AsRawFd;
    if items.is_empty() {
        return Err("nothing to choose from".into());
    }
    let mut tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").map_err(|e| format!("no terminal for the picker: {e}"))?;
    let fd = tty.as_raw_fd();
    // SAFETY: tcgetattr/tcsetattr on a valid fd with a zeroed termios we own.
    let saved = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) != 0 {
            return Err("cannot read terminal settings".into());
        }
        let saved = t;
        t.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
        t.c_cc[libc::VMIN] = 1;
        t.c_cc[libc::VTIME] = 0;
        libc::tcsetattr(fd, libc::TCSANOW, &t);
        saved
    };
    let mut out = tty.try_clone().map_err(|e| format!("no terminal for the picker: {e}"))?;
    let result = run(&mut tty, &mut out, prompt, items);
    // SAFETY: restoring the settings read above.
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
    let _ = write!(tty, "\r\x1b[J");
    result
}

/// Windows: the console's own input and output (CONIN$ / CONOUT$, also when stdin or stdout is
/// redirected), switched to raw VT input (no line editing, echo or Ctrl-C signal; arrows arrive
/// as ESC [ A/B) and VT output for the duration, then restored.
#[cfg(windows)]
pub fn pick(prompt: &str, items: &[Item]) -> Result<Option<usize>, String> {
    use std::os::windows::io::AsRawHandle;
    if items.is_empty() {
        return Err("nothing to choose from".into());
    }
    let open = |name: &str| std::fs::OpenOptions::new().read(true).write(true).open(name).map_err(|e| format!("no console for the picker: {e}"));
    let mut input = open("CONIN$")?;
    let mut output = open("CONOUT$")?;
    let (hin, hout) = (input.as_raw_handle(), output.as_raw_handle());
    let (mut in_mode, mut out_mode) = (0u32, 0u32);
    // SAFETY: Get/SetConsoleMode on console handles we just opened and own for this call.
    unsafe {
        if win::GetConsoleMode(hin, &mut in_mode) == 0 || win::GetConsoleMode(hout, &mut out_mode) == 0 {
            return Err("cannot read console settings".into());
        }
        let raw = (in_mode & !(win::ENABLE_PROCESSED_INPUT | win::ENABLE_LINE_INPUT | win::ENABLE_ECHO_INPUT)) | win::ENABLE_VIRTUAL_TERMINAL_INPUT;
        if win::SetConsoleMode(hin, raw) == 0 || win::SetConsoleMode(hout, out_mode | win::ENABLE_PROCESSED_OUTPUT | win::ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0 {
            win::SetConsoleMode(hin, in_mode);
            return Err("this console does not support the picker (no VT mode); pass a name".into());
        }
    }
    let result = run(&mut input, &mut output, prompt, items);
    let _ = write!(output, "\r\x1b[J");
    let _ = output.flush();
    // SAFETY: restoring the modes read above.
    unsafe {
        win::SetConsoleMode(hin, in_mode);
        win::SetConsoleMode(hout, out_mode);
    }
    result
}

#[cfg(windows)]
mod win {
    use std::os::windows::io::RawHandle;
    pub const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
    pub const ENABLE_LINE_INPUT: u32 = 0x0002;
    pub const ENABLE_ECHO_INPUT: u32 = 0x0004;
    pub const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
    pub const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
    pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn GetConsoleMode(handle: RawHandle, mode: *mut u32) -> i32;
        pub fn SetConsoleMode(handle: RawHandle, mode: u32) -> i32;
    }
}

#[cfg(not(any(unix, windows)))]
pub fn pick(_: &str, _: &[Item]) -> Result<Option<usize>, String> {
    Err("the picker is not available on this platform yet; pass a name".into())
}

/// Matches for `query` in palette order (all items for an empty query).
pub fn filter(index: &Index, count: usize, query: &str) -> Vec<usize> {
    if query.trim().is_empty() {
        (0..count).collect()
    } else {
        index.rank(query, count)
    }
}

pub fn index(items: &[Item]) -> Index {
    let entries: Vec<Entry> = items.iter().map(|i| Entry { kind: EntryKind::Connection, title: i.title.clone(), detail: i.detail.clone(), keywords: String::new() }).collect();
    Index::new(&entries)
}

/// The picker loop over any byte input and output (the terminal, or a script in tests).
fn run(tty: &mut impl Read, out: &mut impl Write, prompt: &str, items: &[Item]) -> Result<Option<usize>, String> {
    let idx = index(items);
    let mut query = String::new();
    let mut cursor = 0usize;
    let mut drawn = 0usize;
    loop {
        let hits = filter(&idx, items.len(), &query);
        cursor = cursor.min(hits.len().saturating_sub(1));
        // Redraw below the cursor line: query line, then up to ROWS matches.
        let mut frame = String::from("\r\x1b[J");
        frame.push_str(&format!("{prompt}> {query}  ({}/{})", hits.len(), items.len()));
        for (row, &i) in hits.iter().take(ROWS).enumerate() {
            let marker = if row == cursor { "\x1b[7m>" } else { " " };
            frame.push_str(&format!("\r\n{marker} {:<32} {}\x1b[0m", items[i].title, items[i].detail));
        }
        let shown = hits.len().min(ROWS);
        if shown > 0 {
            frame.push_str(&format!("\x1b[{shown}A"));
        }
        frame.push_str(&format!("\r\x1b[{}C", prompt.len() + 2 + query.chars().count()));
        out.write_all(frame.as_bytes()).and_then(|()| out.flush()).map_err(|e| e.to_string())?;
        drawn = drawn.max(shown);
        let mut b = [0u8; 1];
        if tty.read(&mut b).map_err(|e| e.to_string())? == 0 {
            return Ok(None);
        }
        match b[0] {
            b'\r' | b'\n' => return Ok(hits.get(cursor).copied()),
            3 => return Ok(None),
            0x1b => {
                let mut seq = [0u8; 2];
                // Arrow keys arrive as ESC [ A/B; a lone Esc cancels.
                if tty.read(&mut seq[..1]).ok() == Some(1) && seq[0] == b'[' && tty.read(&mut seq[1..]).ok() == Some(1) {
                    match seq[1] {
                        b'A' => cursor = cursor.saturating_sub(1),
                        b'B' => cursor = (cursor + 1).min(hits.len().min(ROWS).saturating_sub(1)),
                        _ => {}
                    }
                } else {
                    return Ok(None);
                }
            }
            16 => cursor = cursor.saturating_sub(1),
            14 => cursor = (cursor + 1).min(hits.len().min(ROWS).saturating_sub(1)),
            127 | 8 => {
                query.pop();
                cursor = 0;
            }
            c if c >= 0x20 && c < 0x7f => {
                query.push(c as char);
                cursor = 0;
            }
            _ => {}
        }
        let _ = drawn;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_uses_palette_ranking() {
        let items: Vec<Item> = ["acme-web-01", "acme-db-01", "globex-jump"].iter().map(|t| Item { title: t.to_string(), detail: String::new() }).collect();
        let idx = index(&items);
        assert_eq!(filter(&idx, 3, "").len(), 3);
        assert_eq!(filter(&idx, 3, "db").into_iter().map(|i| items[i].title.as_str()).collect::<Vec<_>>(), ["acme-db-01"]);
        assert_eq!(filter(&idx, 3, "acme").len(), 2);
    }

    fn items() -> Vec<Item> {
        ["acme-web-01", "acme-db-01", "globex-jump"].iter().map(|t| Item { title: t.to_string(), detail: String::new() }).collect()
    }

    fn script(keys: &[u8]) -> (Result<Option<usize>, String>, String) {
        let mut out = Vec::new();
        let r = run(&mut std::io::Cursor::new(keys.to_vec()), &mut out, "ssh", &items());
        (r, String::from_utf8_lossy(&out).into_owned())
    }

    #[test]
    fn typing_filters_and_return_chooses() {
        let (r, screen) = script(b"globex\r");
        assert_eq!(r, Ok(Some(2)));
        assert!(screen.contains("ssh> globex  (1/3)"), "{screen}");
    }

    #[test]
    fn arrows_and_ctrl_keys_move_and_stop_at_the_ends() {
        assert_eq!(script(b"\x1b[B\x1b[B\x1b[B\r").0, Ok(Some(2)));
        assert_eq!(script(b"\x0e\x10\x10\r").0, Ok(Some(0)));
    }

    #[test]
    fn backspace_widens_and_escape_or_ctrl_c_cancel() {
        assert_eq!(script(b"db\x7f\x7f\x08\r").0, Ok(Some(0)));
        assert_eq!(script(b"\x1bx").0, Ok(None));
        assert_eq!(script(b"acme\x03").0, Ok(None));
        assert_eq!(script(b"").0, Ok(None));
    }
}
