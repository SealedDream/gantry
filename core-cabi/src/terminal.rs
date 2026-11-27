//! Terminal sessions over the C ABI: a local shell in a PTY (ConPTY on Windows), rendered by the
//! host from flat snapshots.
//!
//! Snapshot layout (`BastionScreen`): `cells` points at `cell_count == cols * rows` fixed-size
//! [`BastionCell`]s in row-major order; each cell's text is `text[ch_offset .. ch_offset + ch_len]`
//! (UTF-8, empty for the trailing half of a wide character). Packed straight from the core grid (no
//! intermediate UniFFI cell vector) into one owned block per snapshot, freed with
//! [`bastion_screen_free`]. Hosts should poll [`bastion_terminal_generation`] and only take a new
//! snapshot when it moves.
//!
//! Thread safety: every call except `bastion_terminal_free` may be made from any thread, including
//! concurrently; the core serialises access internally. The host must not free a handle while
//! another thread is still using it.
use std::ffi::c_char;
use std::sync::Arc;

use bastion_ffi::Terminal;

use crate::{guarded, optional_text, required, set_ok, to_c};

/// Opaque handle for one terminal session.
pub struct BastionTerminal(Arc<Terminal>);

impl BastionTerminal {
    /// A shared reference to the terminal, for calls that take one (themes).
    pub(crate) fn arc(&self) -> Arc<Terminal> {
        Arc::clone(&self.0)
    }

    /// Wrap a terminal opened elsewhere in the crate (an SSH shell; see `session.rs`), so it works
    /// with every `bastion_terminal_*` function below.
    pub(crate) fn new(t: Arc<Terminal>) -> Self {
        BastionTerminal(t)
    }

    /// The shared terminal behind this handle (the session supervisor keeps its own reference).
    pub(crate) fn shared(&self) -> &Arc<Terminal> {
        &self.0
    }
}

pub const CELL_BOLD: u8 = 1;
pub const CELL_ITALIC: u8 = 2;
pub const CELL_UNDERLINE: u8 = 4;
pub const CELL_SELECTED: u8 = 8;
pub const CELL_MATCHED: u8 = 16;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BastionCell {
    /// 0xRRGGBB.
    pub fg: u32,
    pub bg: u32,
    pub ch_offset: u32,
    pub ch_len: u16,
    /// `CELL_*` bits.
    pub flags: u8,
    pub _reserved: u8,
}

#[repr(C)]
#[derive(Debug)]
pub struct BastionScreen {
    pub cols: u16,
    pub rows: u16,
    pub cursor_row: u16,
    pub cursor_col: u16,
    pub cursor_visible: u8,
    /// Application cursor-key mode (DECCKM): arrows send `ESC O x` instead of `ESC [ x`.
    pub app_cursor: u8,
    /// 0 once the program has exited.
    pub alive: u8,
    pub _reserved: u8,
    pub generation: u64,
    pub cells: *const BastionCell,
    pub cell_count: u32,
    pub text_len: u32,
    pub text: *const u8,
    /// Window title set by the program, or NULL.
    pub title: *mut c_char,
}

/// Owns the buffers a `BastionScreen` points into; the screen is its first field so the host's
/// pointer is also the pointer to free.
#[repr(C)]
struct ScreenAlloc {
    screen: BastionScreen,
    cells: Vec<BastionCell>,
    text: Vec<u8>,
}

pub(crate) unsafe fn term<'a>(t: *const BastionTerminal) -> Result<&'a Terminal, String> {
    t.as_ref().map(|t| &*t.0).ok_or_else(|| "terminal handle is NULL".to_string())
}

fn size(cols: u16, rows: u16) -> Result<(), String> {
    if cols == 0 || rows == 0 || cols > 1000 || rows > 1000 {
        return Err(format!("terminal size {cols}x{rows} out of range"));
    }
    Ok(())
}

/// Start the user's default shell (`%COMSPEC%` on Windows, the login shell on Unix) in a PTY of
/// `cols` x `rows`. Returns NULL and sets `*err` on failure.
///
/// # Safety
/// `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_local_shell(cols: u16, rows: u16, err: *mut *mut c_char) -> *mut BastionTerminal {
    guarded(err, std::ptr::null_mut(), || {
        size(cols, rows)?;
        let t = Terminal::local_shell(cols, rows).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionTerminal(t))))
    })
}

/// Start `program` directly (no shell in between) in a PTY. `args_json` is a JSON array of strings
/// or NULL for none. The program is resolved through `PATH` like any process start.
///
/// # Safety
/// `program` valid NUL-terminated UTF-8; `args_json` NULL or valid; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_spawn(program: *const c_char, args_json: *const c_char, cols: u16, rows: u16, err: *mut *mut c_char) -> *mut BastionTerminal {
    guarded(err, std::ptr::null_mut(), || {
        size(cols, rows)?;
        let program = required(program, "program")?;
        if program.trim().is_empty() {
            return Err("program is required".into());
        }
        let args: Vec<String> = if args_json.is_null() {
            Vec::new()
        } else {
            serde_json::from_str(&required(args_json, "args_json")?).map_err(|_| "args_json must be a JSON array of strings".to_string())?
        };
        let t = Terminal::local_program(program, args, cols, rows).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionTerminal(t))))
    })
}

/// Installed WSL distributions as a JSON array of names, default first; `[]` when WSL is missing.
///
/// # Safety
/// `err` NULL or writable. Free the result with [`crate::bastion_string_free`].
#[no_mangle]
pub unsafe extern "C" fn bastion_wsl_distros_json(err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let names = bastion_core::wsl::list_distros().map_err(|e| e.to_string())?;
        Ok(to_c(serde_json::to_string(&names).map_err(|e| e.to_string())?))
    })
}

/// Installed WSL distributions with details, default first, as a JSON array of
/// `{"name","version","is_default","state","hidden"}`: `version` 1, 2 or 0 (unknown); `state`
/// `running`, `stopped`, `busy` or `unknown`; `hidden` for helper distributions such as
/// `docker-desktop*` that pickers leave out unless asked. `[]` when WSL is missing.
///
/// # Safety
/// `err` NULL or writable. Free the result with [`crate::bastion_string_free`].
#[no_mangle]
pub unsafe extern "C" fn bastion_wsl_distros_detail_json(err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let list: Vec<serde_json::Value> = bastion_core::wsl::distros()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|d| {
                let hidden = bastion_core::wsl::is_hidden_by_default(&d.name);
                let mut v = serde_json::to_value(d).unwrap_or_default();
                v["hidden"] = hidden.into();
                v
            })
            .collect();
        Ok(to_c(serde_json::to_string(&list).map_err(|e| e.to_string())?))
    })
}

/// What opening a saved WSL connection to `distro` would find, as JSON tagged by `kind`:
/// `{"kind":"ready","state":…}`, `{"kind":"wsl_missing"}`, `{"kind":"removed","installed":[…]}`
/// or `{"kind":"busy"}`.
///
/// # Safety
/// `distro` valid NUL-terminated UTF-8; `err` NULL or writable. Free the result with
/// [`crate::bastion_string_free`].
#[no_mangle]
pub unsafe extern "C" fn bastion_wsl_availability_json(distro: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let a = bastion_core::wsl::availability(&required(distro, "distro")?).map_err(|e| e.to_string())?;
        Ok(to_c(serde_json::to_string(&a).map_err(|e| e.to_string())?))
    })
}

/// Open the saved local terminal connection `connection_id` (`Protocol::Local`): the shell,
/// arguments and start folder from its properties, started directly (no shell string).
///
/// # Safety
/// `lib` a live library handle; `connection_id` valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_open_local(lib: *const crate::BastionLibrary, connection_id: *const c_char, cols: u16, rows: u16, err: *mut *mut c_char) -> *mut BastionTerminal {
    guarded(err, std::ptr::null_mut(), || {
        size(cols, rows)?;
        let lib = crate::library(lib)?;
        let t = Terminal::local_connection(lib, required(connection_id, "connection_id")?, cols, rows).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionTerminal(t))))
    })
}

/// Open the saved SSH connection `connection_id` over Mosh (its `ssh.transport` is `mosh`): the
/// local `mosh` client in a PTY, attaching the connection's tmux session when `ssh.tmux` is
/// `attach`. Fails with a message when Mosh is not installed or the connection needs a gateway or
/// jump host. Plain SSH connections attach tmux inside `bastion_terminal_connect` already.
/// Additive in ABI 67.
///
/// # Safety
/// `lib` a live library handle; `connection_id` valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_open_mosh(lib: *const crate::BastionLibrary, connection_id: *const c_char, cols: u16, rows: u16, err: *mut *mut c_char) -> *mut BastionTerminal {
    guarded(err, std::ptr::null_mut(), || {
        size(cols, rows)?;
        let lib = crate::library(lib)?;
        let t = Terminal::mosh_connection(lib, required(connection_id, "connection_id")?, cols, rows).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionTerminal(t))))
    })
}

/// Open `distro` (a name from [`bastion_wsl_distros_json`]) in a PTY as `wsl.exe -d <distro>`.
/// Names that WSL would not accept, including ones starting with `-`, are refused.
///
/// # Safety
/// `distro` valid NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_wsl(distro: *const c_char, cols: u16, rows: u16, err: *mut *mut c_char) -> *mut BastionTerminal {
    guarded(err, std::ptr::null_mut(), || {
        size(cols, rows)?;
        let args = bastion_core::wsl::launch_args(&required(distro, "distro")?).map_err(|e| e.to_string())?;
        let t = Terminal::local_program("wsl.exe".into(), args, cols, rows).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionTerminal(t))))
    })
}

/// A new shell beside `t`, for a split pane: a second shell channel on the same SSH connection (no
/// new login, no secret kept), or a new local shell (`%COMSPEC%`) when `t` is local. The new handle
/// is independent: free it with [`bastion_terminal_free`]; it ends when the SSH connection does.
/// Returns NULL and sets `*err` on failure.
///
/// # Safety
/// `t` a live handle; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_open_sibling(t: *const BastionTerminal, cols: u16, rows: u16, err: *mut *mut c_char) -> *mut BastionTerminal {
    guarded(err, std::ptr::null_mut(), || {
        size(cols, rows)?;
        let s = term(t)?.open_sibling(cols, rows).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionTerminal(s))))
    })
}

/// Close the session (the child process is ended) and release the handle. NULL is ignored.
///
/// # Safety
/// `t` NULL or a live handle not in use by another thread; not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_free(t: *mut BastionTerminal) {
    if t.is_null() {
        return;
    }
    let b = Box::from_raw(t);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| b.0.close()));
}

/// Increases whenever the screen may have changed. 0 for a NULL handle.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_generation(t: *const BastionTerminal) -> u64 {
    guarded(std::ptr::null_mut(), 0, || Ok(term(t)?.generation()))
}

/// Block until the screen generation differs from `after` or `timeout_ms` passes, and return the
/// current generation (`after` for a NULL handle). For a host thread that wakes its UI once per
/// change instead of polling (Native Mac `TerminalWake`). Call it off the UI thread; keep
/// `timeout_ms` short, because the handle must not be freed while this call is in flight.
///
/// # Safety
/// `t` must be NULL or a live handle from this library that no other thread frees during the call.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_wait_change(t: *const BastionTerminal, after: u64, timeout_ms: u32) -> u64 {
    guarded(std::ptr::null_mut(), after, || Ok(term(t)?.wait_change(after, timeout_ms)))
}

/// 1 while the program runs, 0 after it exited (or for a NULL handle).
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_is_alive(t: *const BastionTerminal) -> i32 {
    guarded(std::ptr::null_mut(), 0, || Ok(term(t)?.is_alive() as i32))
}

/// A snapshot of the visible grid. Free with [`bastion_screen_free`].
///
/// # Safety
/// `t` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_screen(t: *const BastionTerminal, err: *mut *mut c_char) -> *mut BastionScreen {
    guarded(err, std::ptr::null_mut(), || {
        let (generation, alive, s) = term(t)?.core_screen();
        let mut cells = Vec::with_capacity(s.cells.len());
        let mut text = Vec::with_capacity(s.cells.len());
        for c in &s.cells {
            let bytes = c.text.as_bytes();
            let len = bytes.len().min(u16::MAX as usize);
            let st = &c.style;
            let flags = (st.bold as u8 * CELL_BOLD)
                | (st.italic as u8 * CELL_ITALIC)
                | (st.underline as u8 * CELL_UNDERLINE)
                | (c.selected as u8 * CELL_SELECTED)
                | (c.matched as u8 * CELL_MATCHED);
            cells.push(BastionCell { fg: st.fg, bg: st.bg, ch_offset: text.len() as u32, ch_len: len as u16, flags, _reserved: 0 });
            text.extend_from_slice(&bytes[..len]);
        }
        let mut alloc = Box::new(ScreenAlloc {
            screen: BastionScreen {
                cols: s.cols,
                rows: s.rows,
                cursor_row: s.cursor_row,
                cursor_col: s.cursor_col,
                cursor_visible: s.cursor_visible as u8,
                app_cursor: s.app_cursor as u8,
                alive: alive as u8,
                _reserved: 0,
                generation,
                cells: std::ptr::null(),
                cell_count: cells.len() as u32,
                text_len: text.len() as u32,
                text: std::ptr::null(),
                title: s.title.map(to_c).unwrap_or(std::ptr::null_mut()),
            },
            cells,
            text,
        });
        alloc.screen.cells = alloc.cells.as_ptr();
        alloc.screen.text = alloc.text.as_ptr();
        Ok(Box::into_raw(alloc) as *mut BastionScreen)
    })
}

/// Free a snapshot. NULL is ignored.
///
/// # Safety
/// `s` NULL or a pointer from [`bastion_terminal_screen`], not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_screen_free(s: *mut BastionScreen) {
    if s.is_null() {
        return;
    }
    let alloc = Box::from_raw(s as *mut ScreenAlloc);
    crate::bastion_string_free(alloc.screen.title);
}

/// Send keyboard input (already encoded as terminal bytes). 0 on success, -1 on failure.
///
/// # Safety
/// `bytes` valid for `len` bytes (may be NULL when `len` is 0); `t` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_write(t: *const BastionTerminal, bytes: *const u8, len: usize, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let data = if len == 0 {
            Vec::new()
        } else if bytes.is_null() {
            return Err("bytes is NULL".into());
        } else {
            std::slice::from_raw_parts(bytes, len).to_vec()
        };
        term(t)?.write(data).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Paste text: wrapped in bracketed-paste markers when the program enabled them, with any markers
/// inside the text stripped. 0 / -1.
///
/// # Safety
/// `text` valid NUL-terminated UTF-8; `t` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_paste(t: *const BastionTerminal, text: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let text = required(text, "text")?;
        term(t)?.paste(text).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// OSC 52 copy requests: `policy` is "off", "ask" or "allow" (the `terminal.osc52` setting; hosts pass
/// "off" when the managed policy forbids clipboard writes). Programs can never read the clipboard. 0 / -1.
/// Additive in ABI 25.
///
/// # Safety
/// `t` live; `policy` NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_set_clipboard_policy(t: *const BastionTerminal, policy: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let policy = required(policy, "policy")?;
        if !matches!(policy.as_str(), "off" | "ask" | "allow") {
            return Err(format!("unknown clipboard policy {policy:?}"));
        }
        term(t)?.set_clipboard_policy(policy);
        set_ok()
    })
}

/// The program's latest OSC 52 copy, taken once, as `{text, ask}` (`ask`: show it and copy only on
/// Allow), or NULL when there is none or the policy is "off". Free the result.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_take_clipboard_json(t: *const BastionTerminal) -> *mut c_char {
    guarded(std::ptr::null_mut(), std::ptr::null_mut(), || {
        Ok(match term(t)?.take_clipboard_request() {
            Some(r) => to_c(serde_json::json!({ "text": r.text, "ask": r.ask }).to_string()),
            None => std::ptr::null_mut(),
        })
    })
}

/// Whether the program rang the bell (BEL) since the last call: 1 / 0. Several rings between calls count once.
/// Additive in ABI 27.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_take_bell(t: *const BastionTerminal) -> i32 {
    guarded(std::ptr::null_mut(), 0, || Ok(term(t)?.take_bell() as i32))
}

/// The shell's working directory from its latest OSC 7 (`file://host/path`), or NULL when the
/// shell sends none. Free with [`crate::bastion_string_free`]. Additive in ABI 45.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_cwd(t: *const BastionTerminal) -> *mut c_char {
    guarded(std::ptr::null_mut(), std::ptr::null_mut(), || Ok(crate::optional_text(term(t)?.cwd())))
}

/// The foreground process of a local terminal: `{"pid":N,"name":"vim"|null,"busy":true|false}`, or
/// NULL when it cannot be told (SSH, Telnet, serial, exited). On Windows a shell is busy while it has
/// a child process. Free with [`crate::bastion_string_free`]. Additive in ABI 133.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_foreground_json(t: *const BastionTerminal) -> *mut c_char {
    guarded(std::ptr::null_mut(), std::ptr::null_mut(), || {
        Ok(match term(t)?.foreground_process() {
            Some(f) => crate::to_c(serde_json::json!({ "pid": f.pid, "name": f.name, "busy": f.busy }).to_string()),
            None => std::ptr::null_mut(),
        })
    })
}

/// Reconnect: keep `old`'s scrollback and screen text above `t`'s new prompt, with a dim
/// `[Reconnected]` line between. Does nothing for a second carry, the same terminal, an empty old
/// terminal, or a new terminal past its 256 KiB early-output cap. Additive in ABI 134.
///
/// # Safety
/// `t` and `old` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_carry_over(t: *const BastionTerminal, old: *const BastionTerminal) {
    guarded(std::ptr::null_mut(), (), || {
        let old = old.as_ref().map(|o| o.0.clone()).ok_or_else(|| "terminal handle is NULL".to_string())?;
        term(t)?.carry_over(old);
        Ok(())
    })
}

/// Drop the scrollback; the visible screen stays. Additive in ABI 27.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_clear_scrollback(t: *const BastionTerminal) {
    guarded(std::ptr::null_mut(), (), || Ok(term(t)?.clear_scrollback()))
}

/// Lines of history kept above the screen (`terminal.scrollback`), at most 100 000; shrinking drops
/// the oldest lines. Returns 0, or -1 with `*err` set (NULL handle, or 0 lines). Additive in ABI 74.
///
/// # Safety
/// `t` NULL or live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_set_scrollback(t: *const BastionTerminal, lines: u32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        if lines == 0 {
            return Err("scrollback must be at least 1 line".into());
        }
        term(t)?.set_scrollback(lines);
        Ok(0)
    })
}

/// Switch to a built-in theme by id ("bastion-dark", "bastion-light", "solarized-dark",
/// "high-contrast"). 0 / -1 (unknown id). Additive in ABI v2: older hosts never call it.
///
/// # Safety
/// `t` live; `id` NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_set_theme(t: *const BastionTerminal, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let id = required(id, "id")?;
        term(t)?.set_theme(id).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// The current theme background as 0xRRGGBB, for painting margins. 0 for a NULL handle.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_background(t: *const BastionTerminal) -> u32 {
    guarded(std::ptr::null_mut(), 0, || Ok(term(t)?.background()))
}

/// Whether the program asked for bracketed paste (so a multi-line paste is safe to send as is).
/// 1 / 0. Hosts should confirm multi-line pastes when this is 0.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_bracketed_paste(t: *const BastionTerminal) -> i32 {
    guarded(std::ptr::null_mut(), 0, || Ok(term(t)?.bracketed_paste() as i32))
}

/// Resize the grid and the PTY. 0 / -1.
///
/// # Safety
/// `t` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_resize(t: *const BastionTerminal, cols: u16, rows: u16, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        size(cols, rows)?;
        term(t)?.resize(cols, rows).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Scroll the viewport through scrollback; positive goes up.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_scroll(t: *const BastionTerminal, lines: i32) {
    guarded(std::ptr::null_mut(), (), || Ok(term(t)?.scroll(lines)))
}

/// Select the whole scrollback and screen (Select All); copy it with `bastion_terminal_selection_text`.
/// Additive in ABI 75.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_select_all(t: *const BastionTerminal) {
    guarded(std::ptr::null_mut(), (), || Ok(term(t)?.select_all()))
}

/// Start a selection at a visible cell. `clicks`: 1 cell, 2 word, 3 line.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_select_start(t: *const BastionTerminal, row: u16, col: u16, clicks: u8) {
    guarded(std::ptr::null_mut(), (), || Ok(term(t)?.select_start(row, col, clicks)))
}

/// Extend the selection to a visible cell (mouse drag).
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_select_extend(t: *const BastionTerminal, row: u16, col: u16) {
    guarded(std::ptr::null_mut(), (), || Ok(term(t)?.select_extend(row, col)))
}

/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_clear_selection(t: *const BastionTerminal) {
    guarded(std::ptr::null_mut(), (), || Ok(term(t)?.clear_selection()))
}

/// The selected text, or NULL when nothing is selected. Free with `bastion_string_free`.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_selection_text(t: *const BastionTerminal) -> *mut c_char {
    guarded(std::ptr::null_mut(), std::ptr::null_mut(), || Ok(optional_text(term(t)?.selection_text())))
}

/// Regex search through screen and scrollback (`forward` 0 searches upwards), scrolling the match
/// into view. 1 found, 0 not found, -1 error (invalid pattern).
///
/// # Safety
/// `pattern` valid NUL-terminated UTF-8; `t` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_search(t: *const BastionTerminal, pattern: *const c_char, forward: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let pattern = required(pattern, "pattern")?;
        Ok(term(t)?.search(pattern, forward != 0).map_err(|e| e.to_string())? as i32)
    })
}

/// Find-bar search: `query` is plain text unless `regex` is non-zero, case is ignored unless
/// `match_case` is non-zero. Returns `{"index","total","capped"}` JSON (`index` 1-based, both 0
/// when nothing matched), NULL with `err` set on an invalid regex. An empty query clears the search.
///
/// # Safety
/// `query` valid NUL-terminated UTF-8; `t` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_find_json(t: *const BastionTerminal, query: *const c_char, forward: i32, match_case: i32, regex: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let query = required(query, "query")?;
        let r = term(t)?.find(query, forward != 0, match_case != 0, regex != 0).map_err(|e| e.to_string())?;
        Ok(to_c(serde_json::json!({ "index": r.index, "total": r.total, "capped": r.capped }).to_string()))
    })
}

/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_clear_search(t: *const BastionTerminal) {
    guarded(std::ptr::null_mut(), (), || Ok(term(t)?.clear_search()))
}

/// End the program; the handle stays valid (and reports not alive) until freed.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_close(t: *const BastionTerminal) {
    guarded(std::ptr::null_mut(), (), || Ok(term(t)?.close()))
}

/// 1 when the program enabled mouse reporting (DECSET 1000/1002/1003), so the UI should send
/// clicks, drags and wheel to it instead of selecting or scrolling; 0 otherwise or on NULL.
/// Additive in ABI 79.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_mouse_reporting(t: *const BastionTerminal) -> i32 {
    guarded(std::ptr::null_mut(), 0, || Ok(term(t)?.mouse_reporting() as i32))
}

/// Send one mouse event at a 0-based `row`/`col` to the program when its mouse mode wants it
/// (core `termmouse::encode`: X10 or SGR 1006). `button`: 0 left, 1 middle, 2 right, 3 wheel up,
/// 4 wheel down, 5 none (motion only). `action`: 0 press, 1 release, 2 motion. `mods` bits:
/// 1 shift, 2 alt, 4 ctrl. Returns 1 when sent, 0 when the mode did not want it, -1 on error
/// (message in `err`, free with [`crate::bastion_string_free`]). Additive in ABI 79.
///
/// # Safety
/// `t` NULL or live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_mouse(t: *const BastionTerminal, button: u32, action: u32, row: u16, col: u16, mods: u32, err: *mut *mut c_char) -> i32 {
    use bastion_ffi::{MouseActionView as A, MouseButtonView as B};
    guarded(err, -1, || {
        let button = match button {
            0 => B::Left,
            1 => B::Middle,
            2 => B::Right,
            3 => B::WheelUp,
            4 => B::WheelDown,
            5 => B::None,
            other => return Err(format!("unknown mouse button {other}")),
        };
        let action = match action {
            0 => A::Press,
            1 => A::Release,
            2 => A::Motion,
            other => return Err(format!("unknown mouse action {other}")),
        };
        let sent = term(t)?
            .mouse(button, action, row, col, mods & 1 != 0, mods & 2 != 0, mods & 4 != 0)
            .map_err(|e| e.to_string())?;
        Ok(sent as i32)
    })
}

/// Events since the last call, taken once, as JSON:
/// `{activity, finished: {exit_code, duration_ms} | null, notification: {title, body} | null,
/// typed_ssh: {host, user, port} | null}`. Remote text is already sanitized. Free the result.
/// Additive in ABI 132.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_take_events_json(t: *const BastionTerminal) -> *mut c_char {
    guarded(std::ptr::null_mut(), std::ptr::null_mut(), || {
        let e = term(t)?.take_events();
        Ok(to_c(
            serde_json::json!({
                "activity": e.activity,
                "finished": e.finished.then(|| serde_json::json!({ "exit_code": e.finished_exit_code, "duration_ms": e.finished_duration_ms })),
                "notification": e.notification_body.as_ref().map(|body| serde_json::json!({ "title": e.notification_title, "body": body })),
                "typed_ssh": e.typed_ssh_host.as_ref().map(|host| serde_json::json!({ "host": host, "user": e.typed_ssh_user, "port": e.typed_ssh_port })),
            })
            .to_string(),
        ))
    })
}

/// Scroll to the previous (`forward` 0) or next (1) shell prompt (OSC 133 marks): 1 moved, 0 no
/// prompt there. Additive in ABI 132.
///
/// # Safety
/// `t` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_jump_prompt(t: *const BastionTerminal, forward: i32) -> i32 {
    guarded(std::ptr::null_mut(), 0, || Ok(term(t)?.jump_prompt(forward != 0) as i32))
}

/// 1 when the JSON string array of tags marks a production connection (`production`/`prod`, any
/// case), else 0. Additive in ABI 132.
///
/// # Safety
/// `tags_json` NULL or a valid C string.
#[no_mangle]
pub unsafe extern "C" fn bastion_tags_is_production(tags_json: *const c_char) -> i32 {
    guarded(std::ptr::null_mut(), 0, || {
        if tags_json.is_null() {
            return Ok(0);
        }
        let Ok(text) = std::ffi::CStr::from_ptr(tags_json).to_str() else { return Ok(0) };
        let tags: Vec<String> = serde_json::from_str(text).unwrap_or_default();
        Ok(bastion_core::shellmarks::is_production(&tags) as i32)
    })
}
