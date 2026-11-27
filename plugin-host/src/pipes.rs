//! The helper's two pipe ends. macOS: descriptors 0 (from the core) and 1 (to the core), placed
//! there by `posix_spawn`. Windows: with `--handles-from-stdin`, standard input is a one-shot
//! pipe with the two handle values the core duplicated into this suspended process.

use std::fs::File;
use std::io;

#[cfg(unix)]
pub fn open(handles_from_stdin: bool) -> io::Result<(File, File)> {
    use std::os::fd::FromRawFd;
    if handles_from_stdin {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: the core placed our two pipe ends on descriptors 0 and 1 and nothing else in this
    // process owns them.
    Ok(unsafe { (File::from_raw_fd(0), File::from_raw_fd(1)) })
}

#[cfg(windows)]
pub fn open(handles_from_stdin: bool) -> io::Result<(File, File)> {
    use std::io::Read;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    if !handles_from_stdin {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bootstrap = io::stdin().lock();
    let mut message = [0u8; 16];
    bootstrap.read_exact(&mut message)?;
    drop(bootstrap);
    let input = u64::from_le_bytes(message[..8].try_into().expect("8 bytes")) as usize as RawHandle;
    let output = u64::from_le_bytes(message[8..].try_into().expect("8 bytes")) as usize as RawHandle;
    if input.is_null() || output.is_null() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // SAFETY: the core duplicated exactly these two handles into this process before resuming
    // it; nothing else here owns them.
    Ok(unsafe { (File::from_raw_handle(input), File::from_raw_handle(output)) })
}
